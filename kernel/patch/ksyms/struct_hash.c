
#include "baselib.h"
#include "symbol.h"
#include <linux/kernel.h>

#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include "uapi/linux/btf.h"
#include "linux/jhash.h"
#include "linux/hashtable.h"

#include "struct_hash.h"

// /* 哈希表条目：存储结构体成员名到偏移量的映射 */
// struct struct_member_entry {
//     struct hlist_node node;
//     char struct_name[64];      /* 结构体名称，如 "task_struct" */
//     char member_name[128];       /* 成员名称，如 "pid" 或 "tasks.next" */
//     uint32_t offset;            /* 成员偏移量 */
//     uint32_t type_id;           /* 成员类型 ID */
// };

/* 哈希表：使用 10 位，即 1024 个桶 */
#define STRUCT_MEMBER_HASH_BITS 10
DEFINE_HASHTABLE(struct_member_hash, STRUCT_MEMBER_HASH_BITS);
static bool struct_member_hash_initialized = false;
static btf_t g_btf;
static bool g_btf_initialized = false;

/* 确保全局 BTF 只解析一次 */
static int ensure_btf_ready(void)
{
    if (g_btf_initialized) return 0;

    if (btf_parse(&g_btf) != 0) {
        logke("Failed to parse BTF\n");
        return -1;
    }

    g_btf_initialized = true;
    return 0;
}

/* 确保哈希表已初始化 */
static inline void ensure_hash_ready(void)
{
    if (!struct_member_hash_initialized) {
        hash_init(struct_member_hash);
        struct_member_hash_initialized = true;
    }
}

/* 计算字符串的哈希值（用于哈希表键） */
uint32_t member_hash_key(const char *struct_name, const char *member_name)
{
    char key[192];
    int n;

    /* 使用snprintf安全地拼接字符串，自动处理截断和null终止 */
    n = snprintf(key, sizeof(key), "%s.%s", struct_name, member_name);
    if (n < 0 || n >= (int)sizeof(key)) {
        /* 如果字符串被截断或出错，使用截断后的字符串计算哈希 */
        key[sizeof(key) - 1] = '\0';
        n = sizeof(key) - 1;
    }

    return jhash(key, (u32)n, JHASH_INITVAL);
}

/* 查找哈希表条目 */
struct struct_member_entry *find_member_entry(const char *struct_name, const char *member_name)
{
    if (!struct_name || !member_name) {
        return NULL;
    }

    uint32_t key = member_hash_key(struct_name, member_name);
    struct struct_member_entry *entry;

    hash_for_each_possible(struct_member_hash, entry, node, key)
    {
        if (strcmp(entry->struct_name, struct_name) == 0 && strcmp(entry->member_name, member_name) == 0) {
            return entry;
        }
    }

    return NULL;
}
KP_EXPORT_SYMBOL(find_member_entry);

/* 添加成员到哈希表 */
int add_member_to_hash(const char *struct_name, const char *member_name, uint32_t offset, uint32_t type_id)
{
    struct struct_member_entry *entry;

    /* 参数检查 */
    if (!struct_name || !member_name) {
        logke("add_member_to_hash: invalid parameters\n");
        return -1;
    }

    /* 检查是否已存在 */
    entry = find_member_entry(struct_name, member_name);
    if (entry) {
        /* 更新现有条目 */
        entry->offset = offset;
        entry->type_id = type_id;
        return 0;
    }

    /* 分配新条目 */
    entry = vmalloc(sizeof(*entry));
    if (!entry) {
        logke("Failed to allocate struct_member_entry\n");
        return -1;
    }

    lib_memset(entry, 0, sizeof(*entry));
    /* 使用snprintf安全地复制字符串，自动处理null终止 */
    snprintf(entry->struct_name, sizeof(entry->struct_name), "%s", struct_name);
    snprintf(entry->member_name, sizeof(entry->member_name), "%s", member_name);
    entry->offset = offset;
    entry->type_id = type_id;

    /* 添加到哈希表 */
    uint32_t key = member_hash_key(struct_name, member_name);
    hash_add(struct_member_hash, &entry->node, key);

    return 0;
}

const char *btf_type_name_by_id(const btf_t *btf, uint32_t type_id)
{
    const struct btf_type *t = btf_type_by_id(btf, type_id);
    if (!t) return NULL;
    return btf_name_by_offset(btf, t->name_off);
}

/* 为结构体/联合分配成员缓冲区，容量按 vlen 决定，最大限制 4096 */
int32_t alloc_struct_members(const btf_t *btf, uint32_t type_id, btf_member_info_t **out_members,
                             uint32_t *out_capacity)
{
    if (!btf || !out_members) return -1;

    const struct btf_type *t = btf_type_by_id(btf, type_id);
    if (!t) {
        *out_members = NULL;
        return -1;
    }

    uint32_t vlen = BTF_INFO_VLEN(t->info);
    /* 默认 256，若 vlen 更大则扩到 vlen，设上限 4096 防御 */
    uint32_t cap = vlen ? vlen : 256;
    if (cap > 4096) cap = 4096;

    //btf_member_info_t *buf = kcalloc(cap, sizeof(*buf), GFP_KERNEL);
    btf_member_info_t *buf = vmalloc(cap * sizeof(*buf));
    if (!buf) {
        *out_members = NULL;
        return -1;
    }
    lib_memset(buf, 0, cap * sizeof(*buf));

    int32_t count = btf_get_struct_members(btf, type_id, buf, cap);
    if (count <= 0) {
        vfree(buf);
        *out_members = NULL;
        return -1;
    }

    *out_members = buf;
    if (out_capacity) *out_capacity = cap;
    return count;
}

/* 跳过 typedef/const/volatile/restrict，获取真实类型 ID；遇到指针直接返回 false */
bool resolve_struct_or_union_type_id(const btf_t *btf, uint32_t type_id, uint32_t *resolved_id)
{
    uint32_t depth = 0;
    const uint32_t MAX_DEPTH = 6; /* 防止循环引用导致的无限循环 */

    while (depth < MAX_DEPTH) {
        const struct btf_type *t = btf_type_by_id(btf, type_id);
        if (!t) return false;

        uint32_t kind = BTF_INFO_KIND(t->info);
        switch (kind) {
        case BTF_KIND_TYPEDEF:
        case BTF_KIND_VOLATILE:
        case BTF_KIND_CONST:
        case BTF_KIND_RESTRICT:
            type_id = *(uint32_t *)(t + 1);
            depth++;
            continue;
        case BTF_KIND_PTR:
            return false;
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
            if (resolved_id) *resolved_id = type_id;
            return true;
        default:
            return false;
        }
    }

    /* 超过最大深度，可能存在循环引用 */
    logkw("resolve_struct_or_union_type_id: exceeded max depth %u\n", MAX_DEPTH);
    return false;
}

/* 解析一层嵌套结构体成员（member_name.nested），并写入哈希表 */
void add_nested_members(const btf_t *btf, const char *struct_name, const btf_member_info_t *parent_member)
{
    if (!parent_member) return;

    uint32_t nested_type_id;
    if (!resolve_struct_or_union_type_id(btf, parent_member->type_id, &nested_type_id)) return;

    btf_member_info_t *nested = NULL;
    int32_t nested_cnt = alloc_struct_members(btf, nested_type_id, &nested, NULL);
    if (nested_cnt <= 0 || !nested) {
        /* alloc_struct_members 失败时会自动释放内存并设置 nested = NULL */
        return;
    }

    const char *parent_name = parent_member->name;
    const char *fallback_parent = btf_type_name_by_id(btf, nested_type_id);

    for (int32_t j = 0; j < nested_cnt; j++) {
        const char *nested_name = nested[j].name ? nested[j].name : "anon";
        char full_name[128];

        /* 处理匿名嵌套：优先用父成员名；如无，则用嵌套类型名；再不行则直接扁平化子成员名 */
        if (parent_name && parent_name[0]) {
            int n = snprintf(full_name, sizeof(full_name), "%s.%s", parent_name, nested_name);
            if (n <= 0 || n >= (int)sizeof(full_name)) {
                logkw("Nested member name too long: %s.%s\n", parent_name, nested_name);
                continue;
            }
        } else if (fallback_parent && fallback_parent[0]) {
            int n = snprintf(full_name, sizeof(full_name), "%s.%s", fallback_parent, nested_name);
            if (n <= 0 || n >= (int)sizeof(full_name)) {
                logkw("Nested member name too long: %s.%s\n", fallback_parent, nested_name);
                continue;
            }
        } else {
            /* 直接使用子成员名进行扁平化 */
            int n = snprintf(full_name, sizeof(full_name), "%s", nested_name);
            if (n <= 0 || n >= (int)sizeof(full_name)) {
                logkw("Nested member name too long: %s\n", nested_name);
                continue;
            }
        }

        uint32_t combined_offset = parent_member->offset + nested[j].offset;
        // if (add_member_to_hash(struct_name, full_name, combined_offset, nested[j].type_id) != 0) {
        //     logke("Failed to add nested member '%s.%s'\n", struct_name, full_name);
        //     continue;
        // }

        logki("  Added nested: %s.%s offset=0x%x type_id=%u\n",
              struct_name, full_name, combined_offset, nested[j].type_id);
    }
    vfree(nested);
}

/* 供外部调用：将指定结构体的成员添加到哈希表 */
int btf_add_struct_to_hash(const char *struct_name)
{
    if (!struct_name || !struct_name[0]) {
        logke("Invalid struct name\n");
        return -1;
    }

    if (ensure_btf_ready() != 0) return -1;

    ensure_hash_ready();
    return parse_struct_with_btf(&g_btf, struct_name);
}
KP_EXPORT_SYMBOL(btf_add_struct_to_hash);

/* 批量添加结构体到哈希表 */
int btf_add_structs_to_hash(const char *const *struct_names, size_t count)
{
    int ret = 0;
    int success_count = 0;
    int fail_count = 0;

    if (!struct_names) return -1;
    if (count == 0) return 0; /* 空列表不是错误 */

    for (size_t i = 0; i < count; i++) {
        const char *name = struct_names[i];

        if (!name || !name[0]) continue;

        if (btf_add_struct_to_hash(name) != 0) {
            ret = -1;
            fail_count++;
        } else {
            success_count++;
        }
    }

    if (fail_count > 0) {
        logkw("btf_add_structs_to_hash: %d succeeded, %d failed\n", success_count, fail_count);
    }

    return ret;
}
KP_EXPORT_SYMBOL(btf_add_structs_to_hash);

/* 使用 BTF 解析结构体并填充哈希表 */
__noinline int parse_struct_with_btf(const btf_t *btf, const char *struct_name)
{
    int32_t type_id = btf_find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
    if (type_id < 0) {
        /* 尝试查找 TYPEDEF */
        type_id = btf_find_by_name(btf, struct_name);
        if (type_id < 0) {
            logkw("Struct '%s' not found in BTF\n", struct_name);
            return -1;
        }
    }

    /* 获取结构体成员 */
    btf_member_info_t *members = NULL;
    int32_t member_count = alloc_struct_members(btf, (uint32_t)type_id, &members, NULL);
    if (member_count <= 0 || !members) {
        logkw("Struct '%s' has no members or failed to get members\n", struct_name);
        return -1;
    }

    log_boot("Parsing struct '%s' (%d members)\n", struct_name, member_count);

    /* 将每个成员添加到哈希表 */
    for (int32_t i = 0; i < member_count; i++) {
        const char *member_name = members[i].name ? members[i].name : "anon";

        uint32_t offset = members[i].offset;
        uint32_t member_type_id = members[i].type_id;

        // if (add_member_to_hash(struct_name, member_name, offset, member_type_id) != 0) {
        //     logke("Failed to add member '%s.%s' to hash table\n", struct_name, member_name);
        //     continue;
        // }

        logki("  Added: %s.%s offset=0x%x type_id=%u\n",
              struct_name, member_name, offset, member_type_id);

        /* 支持二级结构体：对嵌套的 struct/union 再解析一层 */
        add_nested_members(btf, struct_name, &members[i]);
    }

    vfree(members);
    return 0;
}

/* 
 * 使用 BTF 解析所有结构体并建立哈希表
 * 
 * 此函数会：
 * 1. 解析内核 BTF 数据
 * 2. 提取 task_struct、cred、mm_struct 等结构体的成员信息
 * 3. 将成员名和偏移量存储到哈希表中，供后续快速查询
 * 
 * 返回 0 表示成功，负数表示失败
 */
int resolve_struct_with_btf_hash(void)
{
    int ret = 0;

    log_boot("Resolving struct offsets using BTF hash table\n");

    /* 初始化 BTF 和哈希表 */
    if (ensure_btf_ready() != 0) {
        logke("Failed to initialize BTF\n");
        return -1;
    }

    ensure_hash_ready();

    /* 解析主要结构体 */
    const char *structs_to_parse[] = {
        "task_struct", "mm_struct", "cred", "mount", "vm_area_struct", "file",
        "inode",       "dentry",    "path", "page",  "super_block",    "input_dev"

    };

    if (btf_add_structs_to_hash(structs_to_parse, ARRAY_SIZE(structs_to_parse)) != 0) {
        logkw("Some structs failed to parse\n");
        ret = -1;
    }

    log_boot("BTF hash table initialized\n");
    return ret;
}

/* 
 * 查询结构体成员偏移量
 * 
 * @struct_name: 结构体名称，如 "task_struct"
 * @member_name: 成员名称，如 "pid"
 * 
 * 返回成员的字节偏移量，失败返回 -1
 */
int32_t btf_get_member_offset(const char *struct_name, const char *member_name)
{
    struct struct_member_entry *entry;

    if (!struct_member_hash_initialized) {
        logke("Struct member hash table not initialized\n");
        return -1;
    }

    entry = find_member_entry(struct_name, member_name);
    if (!entry) {
        return -1;
    }

    return (int32_t)entry->offset;
}
KP_EXPORT_SYMBOL(btf_get_member_offset);

/* 
 * 查询结构体成员类型 ID
 * 
 * @struct_name: 结构体名称，如 "task_struct"
 * @member_name: 成员名称，如 "pid"
 * 
 * 返回成员的 BTF 类型 ID，失败返回 -1
 */
int32_t btf_get_member_type_id(const char *struct_name, const char *member_name)
{
    struct struct_member_entry *entry;

    if (!struct_member_hash_initialized) {
        logke("Struct member hash table not initialized\n");
        return -1;
    }

    entry = find_member_entry(struct_name, member_name);
    if (!entry) {
        return -1;
    }

    return (int32_t)entry->type_id;
}
KP_EXPORT_SYMBOL(btf_get_member_type_id);

/* 遍历并打印哈希表内容，便于调试 */
void btf_dump_struct_hash(void)
{
    if (!struct_member_hash_initialized) {
        logkw("Struct member hash table not initialized\n");
        return;
    }

    struct struct_member_entry *entry;
    int bkt;
    log_boot("Dumping struct member hash table:\n");
    hash_for_each(struct_member_hash, bkt, entry, node)
    {
        log_boot("  %s.%s => offset=0x%x type_id=%u\n", entry->struct_name, entry->member_name, entry->offset,
              entry->type_id);
    }
}
KP_EXPORT_SYMBOL(btf_dump_struct_hash);
/* 
 * 清理哈希表
 * 
 * 释放所有哈希表条目占用的内存
 */
void btf_cleanup_struct_hash(void)
{
    struct struct_member_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    if (!struct_member_hash_initialized) {
        return;
    }

    hash_for_each_safe(struct_member_hash, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        vfree(entry);
    }

    if (g_btf_initialized) {
        btf_free(&g_btf);
        g_btf_initialized = false;
    }

    struct_member_hash_initialized = false;
    logki("BTF struct hash table cleaned up\n");
}

// struct member_test_case {
//     const char *struct_name;
//     const char *member_name;
// };

// static const struct member_test_case member_tests[] = {
//     { "task_struct", "pid" },
//     { "task_struct", "comm" },
//     { "task_struct", "tasks.next" },
//     { "cred", "uid" },
//     { "mm_struct", "pgd" },
// };

// static int run_struct_query_tests(void)
// {
//     int ret = 0;

//     for (size_t i = 0; i < ARRAY_SIZE(member_tests); i++) {
//         const struct member_test_case *test = &member_tests[i];
//         int32_t offset;
//         int32_t type_id;

//         /* 直接从已构建的哈希表查询 */
//         offset = btf_get_member_offset(test->struct_name, test->member_name);
//         if (offset < 0) {
//             logke("Hash lookup offset failed for %s.%s (not found)\n", test->struct_name, test->member_name);
//             ret = -1;
//             continue;
//         }

//         type_id = btf_get_member_type_id(test->struct_name, test->member_name);
//         if (type_id < 0) {
//             logke("Hash lookup type_id failed for %s.%s (not found)\n", test->struct_name, test->member_name);
//             ret = -1;
//             continue;
//         }

//         logki("Hash query passed for %s.%s (offset=0x%x, type_id=%d)\n",
//               test->struct_name, test->member_name, offset, type_id);
//     }

//     return ret;
// }

// static int __init test_init(void)
// {
//     int ret;

//     logki("Test module init start\n");

//     ret = resolve_struct_with_btf_hash();
//     if (ret != 0) {
//         logke("Failed to build struct member hash\n");
//         return ret;
//     }

//     ret = run_struct_query_tests();
//     if (ret != 0) {
//         logke("Query tests failed\n");
//         btf_cleanup_struct_hash();
//         return ret;
//     }

//     logki("All query tests passed\n");
//     return 0;
// }

// static void __exit test_exit(void)
// {
//    btf_dump_struct_hash();
//     btf_cleanup_struct_hash();
//     logki("Test module exited\n");
// }
