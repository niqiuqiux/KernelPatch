#ifndef __STRUCT_HASH_H__
#define __STRUCT_HASH_H__

#include <linux/kernel.h>

#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "uapi/linux/btf.h"
#include "linux/hashtable.h"

/* 哈希表条目：存储结构体成员名到偏移量的映射 */
struct struct_member_entry {
    struct hlist_node node;
    char struct_name[64];      /* 结构体名称，如 "task_struct" */
    char member_name[128];       /* 成员名称，如 "pid" 或 "tasks.next" */
    uint32_t offset;            /* 成员偏移量 */
    uint32_t type_id;           /* 成员类型 ID */
};




/* 计算字符串的哈希值（用于哈希表键） */
 uint32_t member_hash_key(const char *struct_name, const char *member_name);

/* 查找哈希表条目 */
 struct struct_member_entry *find_member_entry(const char *struct_name, const char *member_name);

/* 添加成员到哈希表 */
 int add_member_to_hash(const char *struct_name, const char *member_name, 
                              uint32_t offset, uint32_t type_id);

 const char *btf_type_name_by_id(const btf_t *btf, uint32_t type_id);

/* 为结构体/联合分配成员缓冲区，容量按 vlen 决定，最大限制 4096 */
 int32_t alloc_struct_members(const btf_t *btf, uint32_t type_id,
                                    btf_member_info_t **out_members,
                                    uint32_t *out_capacity);

/* 跳过 typedef/const/volatile/restrict，获取真实类型 ID；遇到指针直接返回 false */
 bool resolve_struct_or_union_type_id(const btf_t *btf, uint32_t type_id, uint32_t *resolved_id);

/* 解析一层嵌套结构体成员（member_name.nested），并写入哈希表 */
 void add_nested_members(const btf_t *btf,
                               const char *struct_name,
                               const btf_member_info_t *parent_member);

/* 将结构体添加到哈希表（全局 BTF 单例） */
int btf_add_struct_to_hash(const char *struct_name);

/* 批量添加结构体到哈希表 */
int btf_add_structs_to_hash(const char *struct_names[], size_t count);

/* 使用 BTF 解析结构体并填充哈希表 */
__noinline
 int parse_struct_with_btf(const btf_t *btf, const char *struct_name);

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
int resolve_struct_with_btf_hash(void);

/* 
 * 查询结构体成员偏移量
 * 
 * @struct_name: 结构体名称，如 "task_struct"
 * @member_name: 成员名称，如 "pid"
 * 
 * 返回成员的字节偏移量，失败返回 -1
 */
int32_t btf_get_member_offset(const char *struct_name, const char *member_name);

/* 
 * 查询结构体成员类型 ID
 * 
 * @struct_name: 结构体名称，如 "task_struct"
 * @member_name: 成员名称，如 "pid"
 * 
 * 返回成员的 BTF 类型 ID，失败返回 -1
 */
int32_t btf_get_member_type_id(const char *struct_name, const char *member_name);

/* 遍历并打印哈希表内容，便于调试 */
void btf_dump_struct_hash(void);

/* 
 * 清理哈希表
 * 
 * 释放所有哈希表条目占用的内存
 */
void btf_cleanup_struct_hash(void);

#endif