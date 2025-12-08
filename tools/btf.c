/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 niqiuqiux. All Rights Reserved.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "btf.h"
 #include "common.h"
 #include "order.h"
 
 #include <string.h>
 #include <stdlib.h>
 #include <stdio.h>
 
#ifdef _WIN32
#include <string.h>
static void *memmem(const void *haystack, size_t haystack_len, const void *const needle, const size_t needle_len)
{
    if (haystack == NULL) return NULL; // or assert(haystack != NULL);
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL; // or assert(needle != NULL);
    if (needle_len == 0) return NULL;

    for (const char *h = (const char *)haystack; haystack_len >= needle_len; ++h, --haystack_len) {
        if (!memcmp(h, needle, needle_len)) {
            return (void *)h;
        }
    }
    return NULL;
}
/* Windows使用strtok_s */
#define btf_strtok_r(str, delim, saveptr) strtok_s(str, delim, saveptr)
#else
/* POSIX系统使用strtok_r */
#define btf_strtok_r(str, delim, saveptr) strtok_r(str, delim, saveptr)
#endif
 
 #define BTF_ALIGN(x) align_ceil(x, 4)

/* 前置声明，避免早期调用产生隐式声明 */
static int parse_btf_header(const char *data, uint32_t data_size, struct btf_header **hdr, bool is_be);
static int parse_btf_types(const btf_t *btf, const struct btf_type ***types, uint32_t *nr_types);
 
 /* 在kernel镜像中搜索BTF magic number */
 static const char *search_btf_magic(const char *img, int32_t imglen, uint32_t *btf_size, bool *is_be)
 {
     /* BTF magic: 0xeB9F
      * 在little-endian内存中存储为: 9F EB
      * 在big-endian内存中存储为: EB 9F
      */
     const uint8_t magic_le_bytes[] = { 0x9F, 0xEB };
     const uint8_t magic_be_bytes[] = { 0xEB, 0x9F };
 
     /* 搜索BTF magic number */
    int32_t max_off = imglen - (int32_t)sizeof(struct btf_header);
    if (max_off < 0) return NULL;

    for (int32_t offset = 0; offset <= max_off; offset += 4) {
         /* 检查little-endian magic (9F EB) */
         if (memcmp(img + offset, magic_le_bytes, 2) == 0) {
             struct btf_header *hdr = (struct btf_header *)(img + offset);
             /* 验证header - 字段已经是little-endian格式 */
             uint16_t magic = u16le(hdr->magic);
             uint8_t version = hdr->version;
             uint32_t hdr_len = u32le(hdr->hdr_len);
             
             if (magic == BTF_MAGIC && version == BTF_VERSION && hdr_len >= sizeof(struct btf_header)) {
                 uint32_t type_len = u32le(hdr->type_len);
                 uint32_t str_len = u32le(hdr->str_len);
                 uint32_t total_size = hdr_len + type_len + str_len;
                 
                 if (offset + total_size <= (uint32_t)imglen) {
                     *btf_size = total_size;
                     *is_be = false;
                     tools_logi("found BTF data at offset 0x%x (little-endian), size 0x%x\n", offset, total_size);
                     return img + offset;
                 }
             }
         }
         /* 检查big-endian magic (EB 9F) */
         if (memcmp(img + offset, magic_be_bytes, 2) == 0) {
             struct btf_header *hdr = (struct btf_header *)(img + offset);
             /* 验证header - 字段是big-endian格式，需要转换 */
             uint16_t magic = u16be(hdr->magic);
             uint8_t version = hdr->version;
             uint32_t hdr_len = u32be(hdr->hdr_len);
             
             if (magic == BTF_MAGIC && version == BTF_VERSION && hdr_len >= sizeof(struct btf_header)) {
                 uint32_t type_len = u32be(hdr->type_len);
                 uint32_t str_len = u32be(hdr->str_len);
                 uint32_t total_size = hdr_len + type_len + str_len;
                 
                 if (offset + total_size <= (uint32_t)imglen) {
                     *btf_size = total_size;
                     *is_be = true;
                     tools_logi("found BTF data at offset 0x%x (big-endian), size 0x%x\n", offset, total_size);
                     return img + offset;
                 }
             }
         }
     }
 
     return NULL;
 }
 
 /* 查找ELF section中的BTF */
 static int find_btf_in_elf(const char *img, int32_t imglen, const char **btf_data, uint32_t *btf_size)
 {
     Elf64_Ehdr *ehdr = (Elf64_Ehdr *)img;
 
     /* 检查ELF magic */
    if (imglen < (int32_t)sizeof(Elf64_Ehdr) || memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
         return -1;
     }
 
     /* 检查是否为64位ELF */
     if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
         return -1;
     }
 
     /* 检查section header table */
     if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
         return -1;
     }
 
     if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > (uint64_t)imglen) {
         return -1;
     }
 
     /* 获取section header table */
     Elf64_Shdr *shdrs = (Elf64_Shdr *)(img + ehdr->e_shoff);
 
     /* 获取section name string table */
     if (ehdr->e_shstrndx >= ehdr->e_shnum) {
         return -1;
     }
 
     Elf64_Shdr *shstrtab = &shdrs[ehdr->e_shstrndx];
     if (shstrtab->sh_offset + shstrtab->sh_size > (uint64_t)imglen) {
         return -1;
     }
     const char *shstrtab_data = img + shstrtab->sh_offset;
 
     /* 查找.BTF section */
     for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
         Elf64_Shdr *shdr = &shdrs[i];
         if (shdr->sh_name >= shstrtab->sh_size) continue;
 
         const char *sec_name = shstrtab_data + shdr->sh_name;
         if (strcmp(sec_name, ".BTF") == 0) {
             if (shdr->sh_offset + shdr->sh_size > (uint64_t)imglen) {
                 return -1;
             }
             *btf_data = img + shdr->sh_offset;
             *btf_size = (uint32_t)shdr->sh_size;
             tools_logi("found .BTF section in ELF at offset 0x%lx, size 0x%lx\n", shdr->sh_offset, shdr->sh_size);
             return 0;
         }
     }
 
     return -1;
 }
 
 /* 查找BTF section - 支持ELF格式和kernel镜像格式 */
 static int find_btf_section(const char *img, int32_t imglen, const char **btf_data, uint32_t *btf_size, bool *is_be)
 {
     /* 方法1: 尝试作为标准ELF文件解析 */
     if (find_btf_in_elf(img, imglen, btf_data, btf_size) == 0) {
         /* ELF文件通常是little-endian */
         *is_be = false;
         return 0;
     }
 
     /* 方法2: 在kernel镜像中搜索BTF magic number */
     tools_logi("not a standard ELF file, searching for BTF magic in kernel image...\n");
     const char *btf_magic_pos = search_btf_magic(img, imglen, btf_size, is_be);
     if (btf_magic_pos) {
         *btf_data = btf_magic_pos;
         return 0;
     }
 
     tools_logw("BTF section not found in kernel image\n");
     return -1;
 }

/* 校验指定偏移处的BTF块，并返回端序和总长度 */
static int validate_btf_at_offset(const char *img, int32_t imglen, uint32_t btf_offset,
                                  const char **btf_data, uint32_t *btf_size, bool *is_be)
{
    if (!img) {
        tools_loge("invalid kernel image\n");
        return -1;
    }
    if (btf_offset + sizeof(struct btf_header) > (uint32_t)imglen) {
        tools_loge("btf offset 0x%x out of image range (size 0x%x)\n", btf_offset, imglen);
        return -1;
    }

    const struct btf_header *hdr = (const struct btf_header *)(img + btf_offset);
    uint16_t magic_le = u16le(hdr->magic);
    uint16_t magic_be = u16be(hdr->magic);

    if (magic_le == BTF_MAGIC) {
        *is_be = false;
    } else if (magic_be == BTF_MAGIC) {
        *is_be = true;
    } else {
        tools_loge("btf magic mismatch at offset 0x%x\n", btf_offset);
        return -1;
    }

    uint32_t hdr_len = *is_be ? u32be(hdr->hdr_len) : u32le(hdr->hdr_len);
    uint32_t type_len = *is_be ? u32be(hdr->type_len) : u32le(hdr->type_len);
    uint32_t str_len = *is_be ? u32be(hdr->str_len) : u32le(hdr->str_len);
    uint32_t total_size = hdr_len + type_len + str_len;

    if (hdr_len < sizeof(struct btf_header) || hdr_len > total_size) {
        tools_loge("btf header len invalid: 0x%x\n", hdr_len);
        return -1;
    }
    if (btf_offset + total_size > (uint32_t)imglen) {
        tools_loge("btf size overflow: offset 0x%x size 0x%x img 0x%x\n", btf_offset, total_size, imglen);
        return -1;
    }

    *btf_data = img + btf_offset;
    *btf_size = total_size;
    return 0;
}

/* 统一的数据解析入口 */
static int btf_parse_from_data(const char *btf_data, uint32_t btf_size, bool is_be, btf_t *btf)
{
    btf->data = btf_data;
    btf->data_size = btf_size;
    btf->is_be = is_be;

    if (parse_btf_header(btf_data, btf_size, &btf->hdr, is_be) != 0) {
        return -1;
    }

    /* 根据字节序读取header字段 */
    uint32_t hdr_len, type_off, str_off;
    if (is_be) {
        hdr_len = u32be(btf->hdr->hdr_len);
        type_off = u32be(btf->hdr->type_off);
        str_off = u32be(btf->hdr->str_off);
    } else {
        hdr_len = u32le(btf->hdr->hdr_len);
        type_off = u32le(btf->hdr->type_off);
        str_off = u32le(btf->hdr->str_off);
    }

    /* 验证字符串表偏移和大小 */
    uint32_t str_len = is_be ? u32be(btf->hdr->str_len) : u32le(btf->hdr->str_len);
    if (hdr_len + str_off + str_len > btf_size) {
        tools_loge("string table extends beyond BTF data: hdr_len=%u, str_off=%u, str_len=%u, btf_size=%u\n",
                   hdr_len, str_off, str_len, btf_size);
        return -1;
    }

    btf->strings = btf_data + hdr_len + str_off;
    if (str_len > 0 && btf->strings[0] != '\0') {
        tools_logw("string table does not start with null character\n");
    }

    /* 解析类型表 */
    if (parse_btf_types(btf, &btf->types, &btf->nr_types) != 0) {
        return -1;
    }

    tools_logi("parsed BTF successfully\n");
    return 0;
}
 
 /* 解析BTF头部 - 根据字节序正确读取字段 */
 static int parse_btf_header(const char *data, uint32_t data_size, struct btf_header **hdr, bool is_be)
 {
     if (data_size < sizeof(struct btf_header)) {
         tools_loge("BTF data too small for header\n");
         return -1;
     }
 
     *hdr = (struct btf_header *)data;
 
     /* 根据字节序读取magic number */
     uint16_t magic;
     if (is_be) {
         magic = u16be((*hdr)->magic);
     } else {
         magic = u16le((*hdr)->magic);
     }
 
     if (magic != BTF_MAGIC) {
         tools_loge("invalid BTF magic: 0x%04x\n", magic);
         return -1;
     }
 
     /* 检查版本 */
     uint8_t version = (*hdr)->version;
     if (version != BTF_VERSION) {
         tools_logw("unsupported BTF version: %d\n", version);
     }
 
     /* 根据字节序读取字段 */
     uint32_t hdr_len, type_len, str_len;
     if (is_be) {
         hdr_len = u32be((*hdr)->hdr_len);
         type_len = u32be((*hdr)->type_len);
         str_len = u32be((*hdr)->str_len);
     } else {
         hdr_len = u32le((*hdr)->hdr_len);
         type_len = u32le((*hdr)->type_len);
         str_len = u32le((*hdr)->str_len);
     }
 
     /* 检查数据大小 */
     uint32_t total_size = hdr_len + type_len + str_len;
     if (data_size < total_size) {
         tools_loge("BTF data size mismatch: expected %u, got %u\n", total_size, data_size);
         return -1;
     }
 
     tools_logi("BTF header: magic=0x%04x, version=%d, type_len=%u, str_len=%u, endian=%s\n", 
                magic, version, type_len, str_len, is_be ? "big" : "little");
 
     return 0;
 }
 
 /* 解析BTF类型表 - 根据字节序正确读取字段 */
 static int parse_btf_types(const btf_t *btf, const struct btf_type ***types, uint32_t *nr_types)
 {
     const struct btf_header *hdr = btf->hdr;
     bool is_be = btf->is_be;
     
     /* 根据字节序读取header字段 */
     uint32_t hdr_len, type_off, type_len;
     if (is_be) {
         hdr_len = u32be(hdr->hdr_len);
         type_off = u32be(hdr->type_off);
         type_len = u32be(hdr->type_len);
     } else {
         hdr_len = u32le(hdr->hdr_len);
         type_off = u32le(hdr->type_off);
         type_len = u32le(hdr->type_len);
     }
     
     const char *type_data = btf->data + hdr_len + type_off;
     uint32_t type_count = 0;
     uint32_t offset = 0;
 
     tools_logi("parsing BTF types: hdr_len=%u, type_off=%u, type_len=%u\n", hdr_len, type_off, type_len);
 
    /* 第一遍：计算类型数量 */
    while (offset < type_len) {
        /* 检查是否有足够的空间读取一个btf_type结构 */
        if (offset + sizeof(struct btf_type) > type_len) {
            /* 如果剩余字节不足以读取完整结构，说明类型表已结束 */
            /* 这可能是正常的，因为类型表可能不是完全对齐的 */
            if (type_len - offset > 0) {
                tools_logi("type table ends with %u trailing bytes at offset %u\n", type_len - offset, offset);
            }
            break;
        }
         
         const struct btf_type *t = (const struct btf_type *)(type_data + offset);
         
         /* 根据字节序读取info字段 */
         uint32_t info;
         if (is_be) {
             info = u32be(t->info);
         } else {
             info = u32le(t->info);
         }
         
         uint32_t kind = BTF_INFO_KIND(info);
         uint32_t vlen = BTF_INFO_VLEN(info);
 
         /* 调试：打印前几个类型的信息 */
         if (type_count < 5) {
             uint32_t name_off = is_be ? u32be(t->name_off) : u32le(t->name_off);
             tools_logi("type[%u]: kind=%u, vlen=%u, name_off=%u, offset=%u\n", 
                        type_count, kind, vlen, name_off, offset);
         }
 
         /* kind == 0 是void类型，仍然是有效类型，不应该break */
         /* 类型表的结束应该通过offset >= type_len来判断 */
 
         offset += sizeof(struct btf_type);
         uint32_t old_offset = offset;
 
         /* 根据类型添加额外数据大小 */
         switch (kind) {
         case BTF_KIND_INT:
             if (offset + sizeof(uint32_t) <= type_len) {
                 offset += sizeof(uint32_t); /* encoding */
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_ARRAY:
             if (offset + sizeof(struct btf_array) <= type_len) {
                 offset += sizeof(struct btf_array);
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_STRUCT:
         case BTF_KIND_UNION:
             if (offset + vlen * sizeof(struct btf_member) <= type_len) {
                 offset += vlen * sizeof(struct btf_member);
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_ENUM:
             if (offset + vlen * sizeof(struct btf_enum) <= type_len) {
                 offset += vlen * sizeof(struct btf_enum);
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_ENUM64:
             if (offset + vlen * sizeof(struct btf_enum) + vlen * sizeof(uint32_t) <= type_len) {
                 offset += vlen * sizeof(struct btf_enum) + vlen * sizeof(uint32_t); /* 额外的32位值 */
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_FUNC_PROTO:
             if (offset + vlen * sizeof(struct btf_param) <= type_len) {
                 offset += vlen * sizeof(struct btf_param);
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_VAR:
             if (offset + sizeof(uint32_t) <= type_len) {
                 offset += sizeof(uint32_t); /* linkage */
             } else {
                 goto type_parse_done;
             }
             break;
         case BTF_KIND_DATASEC:
             if (offset + vlen * sizeof(struct btf_var_secinfo) <= type_len) {
                 offset += vlen * sizeof(struct btf_var_secinfo);
             } else {
                 goto type_parse_done;
             }
             break;
         default:
             /* 未知类型，只跳过基本结构 */
             break;
         }
 
         /* 如果offset超出范围，说明数据有问题 */
         if (offset > type_len) {
             tools_logw("type record extends beyond type_len at offset %u (kind=%u, vlen=%u)\n", 
                        old_offset, kind, vlen);
             goto type_parse_done;
         }
 
        /* 对齐offset，但要确保不超过type_len */
        uint32_t aligned_offset = BTF_ALIGN(offset);
        if (aligned_offset > type_len) {
            /* 对齐后的offset超出范围，说明这是最后一个类型 */
            aligned_offset = type_len;
        }
        offset = aligned_offset;
        type_count++;
        
        /* 防止无限循环 */
        if (type_count > 1000000) {
            tools_loge("too many types, possible infinite loop\n");
            break;
        }
        
        /* 每10000个类型打印一次进度 */
        if (type_count % 10000 == 0) {
           // tools_logi("parsed %u types, offset=%u/%u\n", type_count, offset, type_len);
        }
        
        /* 如果offset已经达到或超过type_len，结束解析 */
        if (offset >= type_len) {
            break;
        }
    }
type_parse_done:
    /* label needs a statement; use empty statement to keep following declarations valid */
    ;

    uint32_t expected_type_count = type_count;
     *nr_types = type_count;
     if (type_count == 0) {
         *types = NULL;
         return 0;
     }

     /* 分配类型指针数组 */
     *types = (const struct btf_type **)calloc(type_count + 1, sizeof(struct btf_type *));
     if (!*types) {
         tools_loge_exit("failed to allocate type array\n");
     }

    /* 第二遍：填充类型指针 */
    offset = 0;
    type_count = 0;
    while (offset < type_len) {
        /* 检查是否有足够的空间读取一个btf_type结构 */
        if (offset + sizeof(struct btf_type) > type_len) {
            /* 类型表结束 */
            break;
        }
         
         const struct btf_type *t = (const struct btf_type *)(type_data + offset);
         
         /* 根据字节序读取info字段 */
         uint32_t info;
         if (is_be) {
             info = u32be(t->info);
         } else {
             info = u32le(t->info);
         }
         
         uint32_t kind = BTF_INFO_KIND(info);
         uint32_t vlen = BTF_INFO_VLEN(info);
 
         /* kind == 0 是void类型，仍然是有效类型 */
         (*types)[++type_count] = t; /* 类型ID从1开始 */
 
         offset += sizeof(struct btf_type);
 
         /* 根据类型添加额外数据大小 */
         switch (kind) {
         case BTF_KIND_INT:
             if (offset + sizeof(uint32_t) > type_len) goto done;
             offset += sizeof(uint32_t);
             break;
         case BTF_KIND_ARRAY:
             if (offset + sizeof(struct btf_array) > type_len) goto done;
             offset += sizeof(struct btf_array);
             break;
         case BTF_KIND_STRUCT:
         case BTF_KIND_UNION:
             if (offset + vlen * sizeof(struct btf_member) > type_len) goto done;
             offset += vlen * sizeof(struct btf_member);
             break;
         case BTF_KIND_ENUM:
             if (offset + vlen * sizeof(struct btf_enum) > type_len) goto done;
             offset += vlen * sizeof(struct btf_enum);
             break;
         case BTF_KIND_ENUM64:
             if (offset + vlen * sizeof(struct btf_enum) + vlen * sizeof(uint32_t) > type_len) goto done;
             offset += vlen * sizeof(struct btf_enum) + vlen * sizeof(uint32_t);
             break;
         case BTF_KIND_FUNC_PROTO:
             if (offset + vlen * sizeof(struct btf_param) > type_len) goto done;
             offset += vlen * sizeof(struct btf_param);
             break;
         case BTF_KIND_VAR:
             if (offset + sizeof(uint32_t) > type_len) goto done;
             offset += sizeof(uint32_t);
             break;
         case BTF_KIND_DATASEC:
             if (offset + vlen * sizeof(struct btf_var_secinfo) > type_len) goto done;
             offset += vlen * sizeof(struct btf_var_secinfo);
             break;
         default:
             /* 未知类型，只跳过基本结构 */
             break;
         }
 
          /* 如果offset超出范围，说明数据有问题 */
          if (offset > type_len) {
              tools_logw("type record extends beyond type_len at offset %u\n", offset);
              break;
          }

          /* 对齐offset，但要确保不超过type_len */
          uint32_t aligned_offset = BTF_ALIGN(offset);
          if (aligned_offset > type_len) {
              aligned_offset = type_len;
          }
          offset = aligned_offset;
          
          /* 防止无限循环 */
          if (type_count > 1000000) {
              tools_loge("too many types, possible infinite loop\n");
              break;
          }
          
          /* 如果offset已经达到或超过type_len，结束解析 */
          if (offset >= type_len) {
              break;
          }
      }
done:
 
     /* 验证第二遍解析的类型数量与第一遍一致 */
     if (type_count != expected_type_count) {
         tools_loge("type count mismatch: first pass=%u, second pass=%u\n", expected_type_count, type_count);
         /* 使用实际解析的类型数量 */
         *nr_types = type_count;
     }
     
     tools_logi("parsed %u BTF types (validated %u types in second pass)\n", *nr_types, type_count);
     return 0;
 }
 
 /* 解析BTF */
 int32_t btf_parse(const char *img, int32_t imglen, btf_t *btf)
 {
     /* 保存allocated_data字段（如果已设置） */
     char *saved_allocated_data = btf->allocated_data;
     memset(btf, 0, sizeof(btf_t));
     btf->allocated_data = saved_allocated_data;
 
     /* 查找BTF section并检测字节序 */
     const char *btf_data = NULL;
     uint32_t btf_size = 0;
     bool btf_is_be = false;
     if (find_btf_section(img, imglen, &btf_data, &btf_size, &btf_is_be) != 0) {
         return -1;
     }
    return btf_parse_from_data(btf_data, btf_size, btf_is_be, btf);
}

/* 通过已知偏移解析BTF，避免遍历 */
int32_t btf_parse_at(const char *img, int32_t imglen, uint32_t btf_offset, btf_t *btf)
{
    char *saved_allocated_data = btf->allocated_data;
    memset(btf, 0, sizeof(btf_t));
    btf->allocated_data = saved_allocated_data;

    const char *btf_data = NULL;
    uint32_t btf_size = 0;
    bool btf_is_be = false;

    if (validate_btf_at_offset(img, imglen, btf_offset, &btf_data, &btf_size, &btf_is_be) != 0) {
        return -1;
    }

    tools_logi("using BTF at offset 0x%x, size 0x%x\n", btf_offset, btf_size);
    return btf_parse_from_data(btf_data, btf_size, btf_is_be, btf);
}
 
 /* 释放BTF资源 */
 void btf_free(btf_t *btf)
 {
     if (btf->types) {
         free((void *)btf->types);
         btf->types = NULL;
     }
     /* 释放由btf_parse_kernel_file分配的内存 */
     if (btf->allocated_data) {
         free(btf->allocated_data);
         btf->allocated_data = NULL;
     }
     memset(btf, 0, sizeof(btf_t));
 }
 
 /* 根据类型ID获取类型 */
 const struct btf_type *btf_type_by_id(const btf_t *btf, uint32_t type_id)
 {
     if (!btf || !btf->types || type_id == 0 || type_id > btf->nr_types) {
         return NULL;
     }
     return btf->types[type_id];
 }
 
 /* 根据偏移获取名称 */
 const char *btf_name_by_offset(const btf_t *btf, uint32_t name_off)
 {
     if (!btf || !btf->strings) {
         return NULL;
     }
     
     /* 根据字节序读取str_len */
     uint32_t str_len = btf->is_be ? u32be(btf->hdr->str_len) : u32le(btf->hdr->str_len);
     
     /* 边界检查 */
     if (name_off >= str_len) {
         return NULL;
     }
     
     /* 如果偏移为0，返回NULL（BTF规范：偏移0表示无名称） */
     if (name_off == 0) {
         return NULL;
     }
     
     /* 验证字符串不会超出字符串表边界 */
     const char *name = btf->strings + name_off;
     const char *str_end = btf->strings + str_len;
     
     /* 确保name指针在有效范围内 */
     if (name >= str_end) {
         return NULL;
     }
     
     /* 检查字符串是否为空 */
     if (name[0] == '\0') {
         return NULL;
     }
     
     /* 检查字符串是否以null结尾（查找null终止符），限制最大搜索长度避免无限循环 */
     const char *p = name;
     uint32_t max_len = str_end - name;
     uint32_t searched = 0;
     while (searched < max_len && p < str_end) {
         if (*p == '\0') {
             /* 找到null终止符，字符串有效 */
             return name;
         }
         p++;
         searched++;
     }
     
     /* 如果没有找到null终止符，说明字符串无效 */
     return NULL;
 }
 
 /* 获取类型种类 - 注意：需要根据BTF的字节序读取 */
 uint32_t btf_kind(const struct btf_type *t)
 {
     if (!t) return BTF_KIND_UNKN;
     /* 注意：这里假设info字段已经是正确字节序的，因为parse_btf_types已经解析过了 */
     /* 但实际上BTF数据在内存中可能还是原始字节序，所以需要从btf_t获取字节序信息 */
     /* 为了简化，这里直接读取，调用者应该确保传入的btf_t是正确的 */
     return BTF_INFO_KIND(t->info);
 }
 
 /* 获取可变长度字段数量 - 注意：需要根据BTF的字节序读取 */
 uint32_t btf_vlen(const struct btf_type *t)
 {
     if (!t) return 0;
     return BTF_INFO_VLEN(t->info);
 }
 
 /* 根据BTF对象和字节序获取类型种类 */
 static uint32_t btf_kind_with_endian(const struct btf_type *t, bool is_be)
 {
     if (!t) return BTF_KIND_UNKN;
     uint32_t info = is_be ? u32be(t->info) : u32le(t->info);
     return BTF_INFO_KIND(info);
 }
 
 /* 根据BTF对象和字节序获取可变长度字段数量 */
 static uint32_t btf_vlen_with_endian(const struct btf_type *t, bool is_be)
 {
     if (!t) return 0;
     uint32_t info = is_be ? u32be(t->info) : u32le(t->info);
     return BTF_INFO_VLEN(info);
 }
 
 /* 获取类型信息 */
 int32_t btf_get_type_info(const btf_t *btf, uint32_t type_id, btf_type_info_t *info)
 {
     if (!btf || !info) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, type_id);
     if (!t) return -1;
 
     /* 根据字节序读取字段 */
     uint32_t name_off, size_val;
     if (btf->is_be) {
         name_off = u32be(t->name_off);
         size_val = u32be(t->size);
     } else {
         name_off = u32le(t->name_off);
         size_val = u32le(t->size);
     }
 
     info->type_id = type_id;
     info->kind = btf_kind_with_endian(t, btf->is_be);
     info->name = btf_name_by_offset(btf, name_off);
     info->size = size_val;
     info->type_data = (void *)t;
 
     return 0;
 }
 
/* 内部通用实现：可选检查 kind，避免重复代码，同时避免过多调试输出 */
static int32_t btf_find_by_name_internal(const btf_t *btf,
                                         const char *name,
                                         uint32_t expected_kind,
                                         bool check_kind)
{
    if (!btf || !name || !btf->types || !btf->strings || btf->nr_types == 0)
        return -1;

    uint32_t str_len = btf->is_be ? u32be(btf->hdr->str_len) : u32le(btf->hdr->str_len);
    if (str_len == 0)
        return -1;

    for (uint32_t i = 1; i <= btf->nr_types; i++) {
        const struct btf_type *t = btf_type_by_id(btf, i);
        if (!t)
            continue;

        if (check_kind) {
            uint32_t kind = btf_kind_with_endian(t, btf->is_be);
            if (kind != expected_kind)
                continue;
        }

        uint32_t name_off = btf->is_be ? u32be(t->name_off) : u32le(t->name_off);
        if (name_off == 0 || name_off >= str_len)
            continue;

        const char *tname = btf_name_by_offset(btf, name_off);
        if (!tname)
            continue;

        if (strcmp(tname, name) == 0)
            return (int32_t)i;
    }

    return -1;
}

/* 根据名称查找类型（不限制 kind） */
int32_t btf_find_by_name(const btf_t *btf, const char *name)
{
    return btf_find_by_name_internal(btf, name, 0, false);
}

/* 根据名称 + kind 查找类型，kind 取值为 BTF_KIND_xxx */
int32_t btf_find_by_name_kind(const btf_t *btf, const char *name, uint32_t kind)
{
    return btf_find_by_name_internal(btf, name, kind, true);
}
 
 /* 获取结构体成员 */
 int32_t btf_get_struct_members(const btf_t *btf, uint32_t struct_type_id, btf_member_info_t *members, int32_t max_members)
 {
    //  printf("[DEBUG] btf_get_struct_members: struct_type_id=%u\n", struct_type_id);
    //  fflush(stdout);
     
     if (!btf || !members || max_members <= 0) {
         printf("[ERROR] btf_get_struct_members: invalid parameters\n");
         fflush(stdout);
         return -1;
     }

     const struct btf_type *t = btf_type_by_id(btf, struct_type_id);
     if (!t) {
         printf("[ERROR] btf_get_struct_members: type %u not found\n", struct_type_id);
         fflush(stdout);
         return -1;
     }

     uint32_t kind = btf_kind_with_endian(t, btf->is_be);
    //  printf("[DEBUG] btf_get_struct_members: type_id=%u, kind=%u (STRUCT=%u, UNION=%u)\n", 
    //         struct_type_id, kind, BTF_KIND_STRUCT, BTF_KIND_UNION);
    //  fflush(stdout);
     
     if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION) {
         /* 可能是TYPEDEF，需要解析到实际的STRUCT类型 */
         if (kind == BTF_KIND_TYPEDEF) {
             uint32_t *type_ptr = (uint32_t *)(t + 1);
             uint32_t target_type_id = btf->is_be ? u32be(*type_ptr) : u32le(*type_ptr);
            //  printf("[DEBUG] type_id %u is TYPEDEF, following to type_id %u\n", struct_type_id, target_type_id);
            //  fflush(stdout);
             return btf_get_struct_members(btf, target_type_id, members, max_members);
         }
         /* 可能是FWD（前向声明），需要查找完整的STRUCT定义 */
         if (kind == BTF_KIND_FWD) {
             uint32_t name_off = btf->is_be ? u32be(t->name_off) : u32le(t->name_off);
             const char *fwd_name = btf_name_by_offset(btf, name_off);
            //  printf("[DEBUG] type_id %u is FWD declaration for '%s', searching for full definition...\n", 
            //         struct_type_id, fwd_name ? fwd_name : "(null)");
            //  fflush(stdout);
             
             /* 搜索完整的STRUCT定义 */
             for (uint32_t i = 1; i <= btf->nr_types; i++) {
                 if (i == struct_type_id) continue;
                 
                 const struct btf_type *candidate = btf_type_by_id(btf, i);
                 if (!candidate) continue;
                 
                 uint32_t candidate_kind = btf_kind_with_endian(candidate, btf->is_be);
                 if (candidate_kind != BTF_KIND_STRUCT) continue;
                 
                 uint32_t candidate_name_off = btf->is_be ? u32be(candidate->name_off) : u32le(candidate->name_off);
                 const char *candidate_name = btf_name_by_offset(btf, candidate_name_off);
                 
                 if (fwd_name && candidate_name && strcmp(fwd_name, candidate_name) == 0) {
                     uint32_t candidate_size = btf->is_be ? u32be(candidate->size) : u32le(candidate->size);
                     uint32_t candidate_vlen = btf_vlen_with_endian(candidate, btf->is_be);
                     
                     if (candidate_size > 0 && candidate_vlen > 0) {
                        //  printf("[DEBUG] Found full STRUCT definition at type_id %u (size=%u, vlen=%u)\n", 
                        //         i, candidate_size, candidate_vlen);
                        //  fflush(stdout);
                         return btf_get_struct_members(btf, i, members, max_members);
                     }
                 }
             }
             printf("[ERROR] Full STRUCT definition not found for FWD '%s'\n", fwd_name ? fwd_name : "(null)");
             fflush(stdout);
             return -1;
         }
         printf("[ERROR] btf_get_struct_members: type %u is not STRUCT or UNION (kind=%u)\n", struct_type_id, kind);
         fflush(stdout);
         return -1;
     }

     /* 读取size字段用于调试 */
     uint32_t size_val = btf->is_be ? u32be(t->size) : u32le(t->size);
     uint32_t name_off = btf->is_be ? u32be(t->name_off) : u32le(t->name_off);
     const char *type_name = btf_name_by_offset(btf, name_off);
     
     /* 读取原始info字段 */
     uint32_t info_raw = btf->is_be ? u32be(t->info) : u32le(t->info);
     uint32_t info_direct = t->info;  /* 直接读取，不做字节序转换 */
     
     /* 根据新的BTF规范解析vlen */
     /* 新的BTF格式：info字段布局
      * bits  0-15: vlen (低16位)
      * bits 16-23: unused
      * bits 24-28: kind (5位)
      * bits 29-30: unused
      * bit     31: kind_flag
      */
     uint32_t vlen = btf_vlen_with_endian(t, btf->is_be);
     
     /* 验证vlen是否正确解析 */
     uint32_t vlen_from_info_raw = BTF_INFO_VLEN(info_raw);
     uint32_t kind_from_info_raw = BTF_INFO_KIND(info_raw);
     
     uint8_t *info_bytes = (uint8_t*)&t->info;
     
    //  printf("[DEBUG] btf_get_struct_members: type_id=%u, name='%s', kind=%u\n", 
    //         struct_type_id, type_name ? type_name : "(null)", kind);
    //  printf("[DEBUG]   size=%u, info_raw=0x%08x, info_direct=0x%08x\n", 
    //         size_val, info_raw, info_direct);
     /* 尝试多种方式解析vlen，包括从原始字节 */
     /* 如果info bytes是 [02 00 00 04]，在不同的字节序下表示不同的值 */
     uint32_t info_as_le = info_bytes[0] | (info_bytes[1] << 8) | (info_bytes[2] << 16) | (info_bytes[3] << 24);
     uint32_t info_as_be = (info_bytes[0] << 24) | (info_bytes[1] << 16) | (info_bytes[2] << 8) | info_bytes[3];
     uint32_t vlen_from_info_as_le = BTF_INFO_VLEN(info_as_le);
     uint32_t vlen_from_info_as_be = BTF_INFO_VLEN(info_as_be);
     
    //  printf("[DEBUG]   vlen (with endian)=%u, vlen_from_info_raw=%u\n", vlen, vlen_from_info_raw);
    //  printf("[DEBUG]   kind_from_info_raw=%u, info bytes: %02x %02x %02x %02x\n",
    //         kind_from_info_raw, info_bytes[0], info_bytes[1], info_bytes[2], info_bytes[3]);
    //  printf("[DEBUG]   Analyzing info field: info_raw=0x%08x, info_direct=0x%08x\n", 
    //         info_raw, info_direct);
    //  printf("[DEBUG]   According to new BTF format: vlen should be in low 16 bits (bits 0-15)\n");
    //  fflush(stdout);
     
     /* 如果size > 0但vlen=0，尝试使用info_raw直接解析 */
     if (size_val > 0 && vlen == 0) {
         if (vlen_from_info_raw > 0) {
            //  printf("[DEBUG] vlen was 0, but vlen_from_info_raw=%u, using it\n", vlen_from_info_raw);
            //  fflush(stdout);
             vlen = vlen_from_info_raw;
         } else {
             /* 如果vlen_from_info_raw也是0，说明info_raw的字节序转换可能有问题 */
             /* 尝试直接从原始字节解析（在little-endian系统中，vlen在byte[0]和byte[1]） */
             uint32_t vlen_from_bytes = info_bytes[0] | (info_bytes[1] << 8);
             if (vlen_from_bytes > 0 && vlen_from_bytes < 65535 && kind_from_info_raw == kind) {
                //  printf("[DEBUG] Trying vlen from raw bytes (little-endian): %u\n", vlen_from_bytes);
                //  fflush(stdout);
                 vlen = vlen_from_bytes;
             }
         }
     }
     
     if (vlen > (uint32_t)max_members) {
         vlen = max_members;
     }
     
     if (vlen == 0 && size_val > 0) {
         /* 如果size>0但vlen=0，这很不正常。可能vlen字段解析错误，或者这是特殊的结构体 */
         /* 检查类型后面是否有成员数据 */
         const struct btf_member *m = (const struct btf_member *)(t + 1);
        //  printf("[DEBUG] Checking if members exist after type structure...\n");
        //  printf("[DEBUG] Type structure ends at %p, checking next %u bytes...\n", 
        //         (void *)t, (unsigned int)sizeof(struct btf_type));
        //  fflush(stdout);
         
         /* 尝试读取第一个成员，看是否存在 */
         uint32_t raw_test_name_off = m[0].name_off;
         uint32_t raw_test_type = m[0].type;
         uint32_t raw_test_offset = m[0].offset;
         
         uint32_t test_name_off, test_type, test_offset;
         if (btf->is_be) {
             test_name_off = u32be(raw_test_name_off);
             test_type = u32be(raw_test_type);
             test_offset = u32be(raw_test_offset);
         } else {
             test_name_off = u32le(raw_test_name_off);
             test_type = u32le(raw_test_type);
             test_offset = u32le(raw_test_offset);
         }
         const char *test_name = btf_name_by_offset(btf, test_name_off);
        //  printf("[DEBUG] First potential member name_off=%u, name=%s, type_id=%u, offset=%u\n", 
        //         test_name_off, test_name ? test_name : "(null)", test_type, test_offset);
        //  fflush(stdout);
         
        //  /* 如果size>0，应该尝试手动计数，即使第一个成员看起来无效 */
        //  /* 因为vlen解析可能错误，或者第一个成员确实是匿名成员 */
        //  printf("[DEBUG] size>0 but vlen=0, attempting manual member counting...\n");
        //  fflush(stdout);
         
         /* 手动计算成员数量：遍历直到遇到无效数据或超出合理范围 */
         uint32_t manual_vlen = 0;
         uint32_t max_iterations = size_val > 0 ? (size_val / 4) : 1000;  /* 根据size估算最大成员数 */
         if (max_iterations > 1000) max_iterations = 1000;  /* 限制最大1000个成员 */
         
         for (uint32_t i = 0; i < max_iterations; i++) {
             /* 根据BTF字节序读取成员字段 */
             uint32_t raw_name_off = m[i].name_off;
             uint32_t raw_type = m[i].type;
             uint32_t raw_offset = m[i].offset;
             
             /* 输出原始字节值用于调试 */
             if (i < 3) {
                 uint8_t *type_bytes = (uint8_t*)&m[i].type;
                //  printf("[DEBUG] Raw member[%u] type bytes: %02x %02x %02x %02x (raw_value=0x%08x)\n",
                //         i, type_bytes[0], type_bytes[1], type_bytes[2], type_bytes[3], raw_type);
                //  fflush(stdout);
             }
             
             uint32_t member_name_off, member_type, member_offset;
             if (btf->is_be) {
                 member_name_off = u32be(raw_name_off);
                 member_type = u32be(raw_type);
                 member_offset = u32be(raw_offset);
             } else {
                 member_name_off = u32le(raw_name_off);
                 member_type = u32le(raw_type);
                 member_offset = u32le(raw_offset);
             }
             
             if (i < 3) {
                //  printf("[DEBUG] Converted member[%u]: name_off=%u, type_id=%u, offset=%u\n",
                //         i, member_name_off, member_type, member_offset);
                //  fflush(stdout);
             }
             
             /* 检查是否是结束标记（全0） */
             if (member_name_off == 0 && member_type == 0 && member_offset == 0) {
                 printf("[DEBUG] Found end marker (all zeros) at member %u\n", i);
                 fflush(stdout);
                 break;  /* 遇到全0，可能是结束 */
             }
             
             /* 检查type_id是否有效 */
             if (member_type == 0 || member_type > btf->nr_types) {
                 /* 如果type_id无效，说明已经读取完所有成员，立即停止 */
                //  printf("[DEBUG] Member %u has invalid type_id=%u (valid range: 1-%u), stopping manual count\n", 
                //         i, member_type, btf->nr_types);
                //  fflush(stdout);
                 /* 检查是否已经计数了足够的成员（通常是2个：匿名结构体 + cpu_bitmap） */
                 if (manual_vlen >= 2) {
                     printf("[DEBUG] Already counted %u valid members, stopping\n", manual_vlen);
                     fflush(stdout);
                 }
                 break;  /* 遇到无效type_id，立即停止计数 */
             }
             
             /* name_off可以为0（匿名成员），这是合法的 */
             /* 验证name_off在字符串表范围内（如果非0） */
             if (member_name_off != 0) {
                 uint32_t str_len = btf->is_be ? u32be(btf->hdr->str_len) : u32le(btf->hdr->str_len);
                 if (member_name_off >= str_len) {
                    //  printf("[DEBUG] Member %u has invalid name_off=%u (>= str_len=%u), stopping\n", 
                    //         i, member_name_off, str_len);
                    //  fflush(stdout);
                     break;
                 }
             }
             
             manual_vlen++;
             
             /* 前10个成员每次都输出详细信息 */
             if (i < 10) {
                 const char *member_name = btf_name_by_offset(btf, member_name_off);
                //  printf("[DEBUG] Member[%u]: name_off=%u, name=%s, type_id=%u, offset=%u\n",
                //         i, member_name_off, member_name ? member_name : "(anon)", member_type, member_offset);
                //  fflush(stdout);
             }
             
             /* 每100个成员打印一次进度 */
             if ((i + 1) % 100 == 0) {
                 printf("[DEBUG] Counted %u members so far...\n", manual_vlen);
                 fflush(stdout);
             }
         }
         
         if (manual_vlen > 0) {
             printf("[DEBUG] Manually counted %u members. Using this value.\n", manual_vlen);
             fflush(stdout);
             vlen = manual_vlen;
         } else {
             printf("[WARN] Manual counting failed, no valid members found after %u iterations\n", max_iterations);
             fflush(stdout);
         }
         
         /* 如果手动计数也失败，尝试搜索完整的定义 */
         if (vlen == 0) {
             printf("[WARN] type_id %u has size=%u but vlen=0, searching for alternative definition...\n", 
                    struct_type_id, size_val);
             fflush(stdout);
             
             /* 搜索所有类型，查找同名的STRUCT类型 */
             for (uint32_t i = 1; i <= btf->nr_types; i++) {
                 if (i == struct_type_id) continue; /* 跳过自己 */
                 
                 const struct btf_type *candidate = btf_type_by_id(btf, i);
                 if (!candidate) continue;
                 
                 uint32_t candidate_kind = btf_kind_with_endian(candidate, btf->is_be);
                 if (candidate_kind != BTF_KIND_STRUCT) continue;
                 
                 uint32_t candidate_name_off = btf->is_be ? u32be(candidate->name_off) : u32le(candidate->name_off);
                 const char *candidate_name = btf_name_by_offset(btf, candidate_name_off);
                 
                 if (candidate_name && type_name && strcmp(candidate_name, type_name) == 0) {
                     uint32_t candidate_size = btf->is_be ? u32be(candidate->size) : u32le(candidate->size);
                     uint32_t candidate_vlen = btf_vlen_with_endian(candidate, btf->is_be);
                     
                     printf("[DEBUG] Found candidate: type_id=%u, size=%u, vlen=%u\n", i, candidate_size, candidate_vlen);
                     fflush(stdout);
                     
                     /* 如果找到有成员的版本，使用它 */
                     if (candidate_size > 0 && candidate_vlen > 0) {
                         printf("[DEBUG] Using full definition at type_id %u (size=%u, vlen=%u)\n", 
                                i, candidate_size, candidate_vlen);
                         fflush(stdout);
                         /* 递归调用获取完整定义的成员 */
                         return btf_get_struct_members(btf, i, members, max_members);
                     }
                 }
             }
             printf("[DEBUG] No alternative definition found for '%s'\n", type_name ? type_name : "(null)");
             fflush(stdout);
         }
     }
     
     if (vlen == 0) {
         /* 检查是否是前向声明 */
         if (size_val == 0) {
         
         /* 检查是否是前向声明 */
         if (size_val == 0) {
             printf("[DEBUG] type_id %u appears to be a forward declaration (size=0, vlen=0)\n", struct_type_id);
             printf("[DEBUG] Searching for full definition...\n");
             fflush(stdout);
             
             /* 搜索所有类型，查找同名的STRUCT类型 */
             for (uint32_t i = 1; i <= btf->nr_types; i++) {
                 if (i == struct_type_id) continue; /* 跳过自己 */
                 
                 const struct btf_type *candidate = btf_type_by_id(btf, i);
                 if (!candidate) continue;
                 
                 uint32_t candidate_kind = btf_kind_with_endian(candidate, btf->is_be);
                 if (candidate_kind != BTF_KIND_STRUCT) continue;
                 
                 uint32_t candidate_name_off = btf->is_be ? u32be(candidate->name_off) : u32le(candidate->name_off);
                 const char *candidate_name = btf_name_by_offset(btf, candidate_name_off);
                 
                 if (candidate_name && type_name && strcmp(candidate_name, type_name) == 0) {
                     uint32_t candidate_size = btf->is_be ? u32be(candidate->size) : u32le(candidate->size);
                     uint32_t candidate_vlen = btf_vlen_with_endian(candidate, btf->is_be);
                     
                     if (candidate_size > 0 && candidate_vlen > 0) {
                         printf("[DEBUG] Found full definition at type_id %u (size=%u, vlen=%u)\n", 
                                i, candidate_size, candidate_vlen);
                         fflush(stdout);
                         /* 递归调用获取完整定义的成员 */
                         return btf_get_struct_members(btf, i, members, max_members);
                     }
                 }
             }
             printf("[DEBUG] No full definition found for '%s'\n", type_name ? type_name : "(null)");
             fflush(stdout);
         }
         
         printf("[WARN] btf_get_struct_members: type_id %u has 0 members\n", struct_type_id);
         fflush(stdout);
         return 0;
     }
    }
 
     const struct btf_member *m = (const struct btf_member *)(t + 1);
    //  printf("[DEBUG] btf_get_struct_members: member array at %p\n", (void *)m);
    //  fflush(stdout);
     
     for (uint32_t i = 0; i < vlen; i++) {
         /* 根据BTF字节序读取成员字段 */
         /* 注意：BTF数据在内存中已经按照BTF的字节序存储 */
         /* 如果BTF是little-endian，数据在内存中就是little-endian格式 */
         /* 在little-endian系统上直接读取uint32_t，就已经是正确的值 */
         /* u32le/u32be函数会根据系统字节序转换，但这里我们需要根据BTF字节序转换 */
         uint32_t name_off, type_id, offset_val;
         
         /* 直接读取原始值 */
         uint32_t raw_name_off = m[i].name_off;
         uint32_t raw_type = m[i].type;
         uint32_t raw_offset = m[i].offset;
         
         /* 根据BTF字节序转换：使用u32le/u32be函数自动处理系统字节序 */
         if (btf->is_be) {
             name_off = u32be(raw_name_off);
             type_id = u32be(raw_type);
             offset_val = u32be(raw_offset);
         } else {
             name_off = u32le(raw_name_off);
             type_id = u32le(raw_type);
             offset_val = u32le(raw_offset);
         }
         
         members[i].name = btf_name_by_offset(btf, name_off);
         members[i].type_id = type_id;
         
         /* 根据新的BTF规范解析offset字段 */
         /* 如果结构体的kind_flag被设置，offset字段包含位域信息：
          * - 高8位：位域大小 (BTF_MEMBER_BITFIELD_SIZE)
          * - 低24位：位偏移 (BTF_MEMBER_BIT_OFFSET)
          * 否则，offset就是位偏移
          */
         /* 根据新的BTF规范解析offset字段 */
         /* 如果结构体的kind_flag被设置：
          *   - offset字段包含位域信息（如果bitfield_size>0）或位偏移（如果bitfield_size=0）
          * 如果kind_flag未设置：
          *   - offset字段只包含位偏移
          */
         uint32_t struct_kind_flag = BTF_INFO_KFLAG(info_raw);
         uint32_t bitfield_size = BTF_MEMBER_BITFIELD_SIZE(offset_val);
         uint32_t bit_offset = BTF_MEMBER_BIT_OFFSET(offset_val);
         
         if (struct_kind_flag) {
             /* kind_flag设置了：使用新的格式 */
             if (bitfield_size > 0) {
                 /* 位域成员 */
                 members[i].bit_offset = bit_offset;
                 members[i].offset = bit_offset / 8; /* 转换为字节偏移 */
                 members[i].bitfield_size = bitfield_size;
             } else {
                 /* 普通成员：offset是位偏移 */
                 members[i].bit_offset = offset_val;
                 members[i].offset = offset_val / 8; /* 转换为字节偏移 */
                 members[i].bitfield_size = 0;
             }
         } else {
             /* kind_flag未设置：offset只包含位偏移 */
             members[i].bit_offset = offset_val;
             members[i].offset = offset_val / 8; /* 转换为字节偏移 */
             members[i].bitfield_size = 0;
         }
         
         if (i < 5) {
            //  printf("[DEBUG] member[%u]: name_off=%u, name=%s, type_id=%u, offset=%u\n", 
            //         i, name_off, members[i].name ? members[i].name : "(null)", type_id, members[i].offset);
            //  fflush(stdout);
         }
     }

    // printf("[DEBUG] btf_get_struct_members: returning %u members\n", vlen);
    // fflush(stdout);
    return (int32_t)vlen;
}

int32_t btf_get_struct_outer_members(const btf_t *btf, uint32_t struct_type_id, char *name, btf_member_info_t *out)
{
    if (!btf || !name || !out) {
        return -1;
    }

    btf_member_info_t members[256];
    int32_t member_count = btf_get_struct_members(btf, struct_type_id, members, 256);
    if (member_count <= 0) {
        return -1;
    }

    for (int32_t i = 0; i < member_count; i++) {
        if (members[i].name) {
            if (strcmp(members[i].name, name) == 0) {
                *out = members[i];
                return 0;
            }
        }
    }

    return -1;
}

int32_t btf_get_struct_1depth_members(const btf_t *btf, uint32_t struct_type_id, char *name, btf_member_info_t *out){

    if (!btf || !name || !out) {
        return -1;
    }

    btf_member_info_t members[256];
    int32_t member_count = btf_get_struct_members(btf, struct_type_id, members, 256);
    if (member_count <= 0) {
        return -1;
    }

    for (int32_t i = 0; i < member_count; i++) {
        //const char *name = members[i].name ? members[i].name : "<anon>";
        uint32_t abs_offset = members[i].offset; 


        //printf("%s: offset=0x%04x, type_id=%u\n", name, abs_offset, members[i].type_id);

        /* 如果成员本身是结构体或联合体，递归打印其成员 */
        btf_type_info_t member_type_info = {0};
        if (btf_get_type_info(btf, members[i].type_id, &member_type_info) == 0) {
            if (member_type_info.kind == BTF_KIND_STRUCT ||
                member_type_info.kind == BTF_KIND_UNION) {
                // print_struct_members_recursive(btf, members[i].type_id, abs_offset, depth + 1);

                btf_member_info_t member_members[256];
                int32_t member_count = btf_get_struct_members(btf, members[i].type_id, member_members, 256);
             
                for (int32_t j = 0; j < member_count; j++) {
                //    printf("    member_members[%d]: %s: offset=0x%04x, type_id=%u\n", j, member_members[j].name, member_members[j].offset, member_members[j].type_id);
                  if (member_members[j].name) {
                    if (strcmp(member_members[j].name, name) == 0) {
                        *out = member_members[j];
                        return 0;
                    }
                  }
                }
            }
        }
    }
    return -1;
}

/* 根据结构体 type_id + 成员名查找成员信息（单层结构体，不递归） */
int32_t btf_find_struct_member_by_type_id(const btf_t *btf,
                                          uint32_t struct_type_id,
                                          const char *member_name,
                                          btf_member_info_t *out)
{
    if (!btf || !member_name || !out) {
        return -1;
    }

    /* 先取出该结构体的所有成员，然后在线性表中按名称搜索 */
    btf_member_info_t members[256];
    int32_t count = btf_get_struct_members(btf, struct_type_id, members,
                                           (int32_t)(sizeof(members) / sizeof(members[0])));
    if (count <= 0) {
        return -1;
    }

    for (int32_t i = 0; i < count; i++) {
        const char *name = members[i].name;
        if (name && strcmp(name, member_name) == 0) {
            *out = members[i];
            return 0;
        }
    }

    return -1;
}

/* 根据结构体名称 + 成员名查找成员信息（内部先通过名称找到结构体，再复用上面的接口） */
int32_t btf_find_struct_member(const btf_t *btf,
                               const char *struct_name,
                               const char *member_name,
                               btf_member_info_t *out)
{
    if (!btf || !struct_name || !member_name || !out) {
        return -1;
    }

    /* 通过名称先找到一个类型 ID（可能是 STRUCT/UNION/TYPEDEF/FWD） */
    int32_t type_id = btf_find_by_name(btf, struct_name);
    if (type_id < 0) {
        return -1;
    }

    /* 让已有的 btf_get_struct_members() 去处理 TYPEDEF/FWD 等情况 */
    return btf_find_struct_member_by_type_id(btf, (uint32_t)type_id, member_name, out);
}

/* 工具函数：根据当前类型 ID，解析去掉 TYPEDEF/CONST/VOLATILE 等修饰符后的实际类型 ID */
static uint32_t btf_resolve_real_type_id(const btf_t *btf, uint32_t type_id)
{
    while (1) {
        const struct btf_type *t = btf_type_by_id(btf, type_id);
        if (!t)
            break;

        uint32_t kind = btf_kind_with_endian(t, btf->is_be);
        if (kind == BTF_KIND_TYPEDEF ||
            kind == BTF_KIND_VOLATILE ||
            kind == BTF_KIND_CONST ||
            kind == BTF_KIND_RESTRICT) {
            /* 这些类型后面紧跟着一个 u32，表示真正的 type_id */
            uint32_t *type_ptr = (uint32_t *)(t + 1);
            uint32_t raw = *type_ptr;
            uint32_t next_id = btf->is_be ? u32be(raw) : u32le(raw);
            if (next_id == 0 || next_id == type_id)
                break;
            type_id = next_id;
            continue;
        }

        break;
    }

    return type_id;
}

/* 按 type_id + 路径（形如 "a.b.c"）解析嵌套成员最终 offset/type */
int32_t btf_resolve_member_path_by_type_id(const btf_t *btf,
                                           uint32_t root_type_id,
                                           const char *path,
                                           btf_member_path_result_t *out)
{
    if (!btf || !path || !out)
        return -1;

    /* 为了简单，限制路径段数量和单段长度 */
    enum { MAX_SEG = 32, MAX_SEG_LEN = 128 };
    char buf[1024];

    size_t path_len = strlen(path);
    if (path_len == 0 || path_len >= sizeof(buf))
        return -1;

    memcpy(buf, path, path_len + 1);

    char *segs[MAX_SEG];
    int seg_cnt = 0;

    char *saveptr = NULL;
    char *token = btf_strtok_r(buf, ".", &saveptr);
    while (token && seg_cnt < MAX_SEG) {
        if (strlen(token) == 0 || strlen(token) >= MAX_SEG_LEN)
            return -1;
        segs[seg_cnt++] = token;
        token = btf_strtok_r(NULL, ".", &saveptr);
    }

    if (seg_cnt == 0)
        return -1;

    uint32_t cur_type_id = btf_resolve_real_type_id(btf, root_type_id);
    uint32_t total_off = 0;

    for (int i = 0; i < seg_cnt; i++) {
        const struct btf_type *t = btf_type_by_id(btf, cur_type_id);
        if (!t)
            return -1;

        uint32_t kind = btf_kind_with_endian(t, btf->is_be);
        if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION)
            return -1;

        btf_member_info_t mi;
        if (btf_find_struct_member_by_type_id(btf, cur_type_id, segs[i], &mi) != 0)
            return -1;

        total_off += mi.offset;
        cur_type_id = btf_resolve_real_type_id(btf, mi.type_id);
    }

    out->final_type_id = cur_type_id;
    out->final_offset = total_off;
    return 0;
}

/* 按结构体名 + 路径解析嵌套成员最终 offset/type */
int32_t btf_resolve_member_path(const btf_t *btf,
                                const char *struct_name,
                                const char *path,
                                btf_member_path_result_t *out)
{
    if (!btf || !struct_name || !path || !out)
        return -1;

    int32_t type_id = btf_find_by_name(btf, struct_name);
    if (type_id < 0)
        return -1;

    return btf_resolve_member_path_by_type_id(btf, (uint32_t)type_id, path, out);
}

/* 根据类型 ID 获取最终类型大小（自动跳过 typedef/修饰符） */
int32_t btf_get_type_size_by_id(const btf_t *btf, uint32_t type_id, uint32_t *size_out)
{
    if (!btf || !size_out)
        return -1;

    uint32_t real_id = btf_resolve_real_type_id(btf, type_id);
    const struct btf_type *t = btf_type_by_id(btf, real_id);
    if (!t)
        return -1;

    uint32_t kind = btf_kind_with_endian(t, btf->is_be);

    /* 只有部分 kind 的类型才有 size 含义 */
    switch (kind) {
    case BTF_KIND_INT:
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
    case BTF_KIND_ENUM:
    case BTF_KIND_DATASEC:
    case BTF_KIND_FLOAT:
    case BTF_KIND_ENUM64:
        break;
    default:
        return -1;
    }

    uint32_t size_val = btf->is_be ? u32be(t->size) : u32le(t->size);
    *size_out = size_val;
    return 0;
}

/* 根据结构体名称获取结构体大小（支持 typedef 包装的结构体） */
int32_t btf_get_struct_size(const btf_t *btf, const char *struct_name, uint32_t *size_out)
{
    if (!btf || !struct_name || !size_out)
        return -1;

    /* 优先按 struct kind 查，避免同名的 enum/union 干扰 */
    int32_t type_id = btf_find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
    if (type_id < 0) {
        /* 退一步：不限定 kind，交给 size 解析逻辑去做判断（兼容 typedef 等情况） */
        type_id = btf_find_by_name(btf, struct_name);
        if (type_id < 0)
            return -1;
    }

    return btf_get_type_size_by_id(btf, (uint32_t)type_id, size_out);
}

/* 根据 VAR 类型 ID 获取内核变量信息（名称 / 类型 / 大小 / linkage） */
int32_t btf_get_var_info_by_id(const btf_t *btf, uint32_t var_type_id, btf_var_info_t *info)
{
    if (!btf || !info)
        return -1;

    const struct btf_type *t = btf_type_by_id(btf, var_type_id);
    if (!t)
        return -1;

    uint32_t kind = btf_kind_with_endian(t, btf->is_be);
    if (kind != BTF_KIND_VAR)
        return -1;

    /* 变量名 */
    uint32_t name_off = btf->is_be ? u32be(t->name_off) : u32le(t->name_off);
    const char *name = btf_name_by_offset(btf, name_off);

    /* 变量类型 ID（注意：t->type 也是按 BTF 字节序存放的） */
    uint32_t raw_type = t->type;
    uint32_t type_id = btf->is_be ? u32be(raw_type) : u32le(raw_type);

    /* 变量 linkage 信息 */
    const struct btf_var *var = (const struct btf_var *)(t + 1);
    uint32_t raw_linkage = var->linkage;
    uint32_t linkage = btf->is_be ? u32be(raw_linkage) : u32le(raw_linkage);

    /* 变量大小 = 其类型大小 */
    uint32_t size = 0;
    if (btf_get_type_size_by_id(btf, type_id, &size) != 0) {
        size = 0;
    }

    info->name = name;
    info->type_id = type_id;
    info->size = size;
    info->linkage = linkage;
    return 0;
}

/* 根据变量名获取内核变量信息（内部自动查找 BTF_KIND_VAR） */
int32_t btf_get_var_info_by_name(const btf_t *btf, const char *var_name, btf_var_info_t *info)
{
    if (!btf || !var_name || !info)
        return -1;

    int32_t var_id = btf_find_by_name_kind(btf, var_name, BTF_KIND_VAR);
    if (var_id < 0)
        return -1;

    return btf_get_var_info_by_id(btf, (uint32_t)var_id, info);
}

/* 获取枚举值 */
int32_t btf_get_enum_values(const btf_t *btf, uint32_t enum_type_id, btf_enum_info_t *values, int32_t max_values)
{
     if (!btf || !values || max_values <= 0) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, enum_type_id);
     if (!t) return -1;
 
     uint32_t kind = btf_kind_with_endian(t, btf->is_be);
     if (kind != BTF_KIND_ENUM && kind != BTF_KIND_ENUM64) {
         return -1;
     }
 
     uint32_t vlen = btf_vlen_with_endian(t, btf->is_be);
     if (vlen > (uint32_t)max_values) {
         vlen = max_values;
     }
 
     const struct btf_enum *e = (const struct btf_enum *)(t + 1);
     for (uint32_t i = 0; i < vlen; i++) {
         /* 根据字节序读取枚举字段 */
         uint32_t name_off;
         int32_t val;
         if (btf->is_be) {
             name_off = u32be(e[i].name_off);
             val = i32be(e[i].val);
         } else {
             name_off = u32le(e[i].name_off);
             val = i32le(e[i].val);
         }
         
         values[i].name = btf_name_by_offset(btf, name_off);
         values[i].val = val;
     }
 
     return (int32_t)vlen;
}
 
/* 打印类型（递归） - 限制递归深度避免栈溢出 */
static void dump_type_recursive(const btf_t *btf, uint32_t type_id, int32_t indent, bool visited[])
{
    /* 限制递归深度 */
    if (indent > 10) {
        for (int32_t i = 0; i < indent; i++) printf("  ");
        printf("[type %u] (max depth reached)\n", type_id);
        return;
    }

    if (type_id == 0 || type_id > btf->nr_types) {
        for (int32_t i = 0; i < indent; i++) printf("  ");
        printf("[invalid type %u]\n", type_id);
        return;
    }
    
    if (visited[type_id]) {
        for (int32_t i = 0; i < indent; i++) printf("  ");
        printf("[type %u]\n", type_id);
        return;
    }
    visited[type_id] = true;
 
     const struct btf_type *t = btf->types[type_id];
     bool is_be = btf->is_be;
     uint32_t kind = btf_kind_with_endian(t, is_be);
     
     /* 根据字节序读取name_off和size */
     uint32_t name_off = is_be ? u32be(t->name_off) : u32le(t->name_off);
     uint32_t size_val = is_be ? u32be(t->size) : u32le(t->size);
     const char *name = btf_name_by_offset(btf, name_off);
 
     for (int32_t i = 0; i < indent; i++) printf("  ");
 
     switch (kind) {
     case BTF_KIND_INT: {
         /* INT类型在btf_type后面跟着一个uint32_t encoding字段 */
         uint32_t *encoding_ptr = (uint32_t *)(t + 1);
         uint32_t encoding_val_raw = *encoding_ptr;
         uint32_t encoding_val = is_be ? u32be(encoding_val_raw) : u32le(encoding_val_raw);
         uint32_t encoding = BTF_INT_ENCODING(encoding_val);
         printf("[%u] INT %s (size=%u", type_id, name ? name : "<anon>", size_val);
         if (encoding & BTF_INT_SIGNED) printf(", signed");
         if (encoding & BTF_INT_CHAR) printf(", char");
         if (encoding & BTF_INT_BOOL) printf(", bool");
         printf(")\n");
         break;
     }
     case BTF_KIND_PTR: {
         uint32_t *type_ptr = (uint32_t *)(t + 1);
         uint32_t target_type = is_be ? u32be(*type_ptr) : u32le(*type_ptr);
         printf("[%u] PTR -> ", type_id);
         dump_type_recursive(btf, target_type, indent + 1, visited);
         break;
     }
     case BTF_KIND_ARRAY: {
         const struct btf_array *arr = (const struct btf_array *)(t + 1);
         uint32_t arr_type = is_be ? u32be(arr->type) : u32le(arr->type);
         uint32_t index_type = is_be ? u32be(arr->index_type) : u32le(arr->index_type);
         uint32_t nelems = is_be ? u32be(arr->nelems) : u32le(arr->nelems);
         printf("[%u] ARRAY[%u] of ", type_id, nelems);
         dump_type_recursive(btf, arr_type, indent + 1, visited);
         break;
     }
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION: {
        printf("[%u] %s %s (size=%u", type_id, kind == BTF_KIND_STRUCT ? "STRUCT" : "UNION",
               name ? name : "<anon>", size_val);
        uint32_t vlen = btf_vlen_with_endian(t, is_be);
        printf(", %u members)\n", vlen);
        
        /* 限制显示的成员数量，避免输出过多 */
        uint32_t max_members = vlen < 20 ? vlen : 20;
        const struct btf_member *m = (const struct btf_member *)(t + 1);
        for (uint32_t i = 0; i < max_members; i++) {
            for (int32_t j = 0; j < indent + 1; j++) printf("  ");
            uint32_t raw_m_name_off = m[i].name_off;
            uint32_t raw_m_type = m[i].type;
            uint32_t raw_m_offset = m[i].offset;
            
            uint32_t m_name_off, m_type, m_offset;
            if (is_be) {
                m_name_off = u32be(raw_m_name_off);
                m_type = u32be(raw_m_type);
                m_offset = u32be(raw_m_offset);
            } else {
                m_name_off = u32le(raw_m_name_off);
                m_type = u32le(raw_m_type);
                m_offset = u32le(raw_m_offset);
            }
            const char *mname = btf_name_by_offset(btf, m_name_off);
            printf("  [%u] %s (offset=%u, type_id=%u)\n", i, mname ? mname : "<anon>", m_offset >> 3, m_type);
        }
        if (vlen > max_members) {
            for (int32_t j = 0; j < indent + 1; j++) printf("  ");
            printf("  ... (omitted %u more members)\n", vlen - max_members);
        }
        break;
    }
     case BTF_KIND_ENUM: {
         printf("[%u] ENUM %s\n", type_id, name ? name : "<anon>");
         uint32_t vlen = btf_vlen_with_endian(t, is_be);
         const struct btf_enum *e = (const struct btf_enum *)(t + 1);
         for (uint32_t i = 0; i < vlen; i++) {
             for (int32_t j = 0; j < indent + 1; j++) printf("  ");
             uint32_t e_name_off = is_be ? u32be(e[i].name_off) : u32le(e[i].name_off);
             int32_t e_val = is_be ? i32be(e[i].val) : i32le(e[i].val);
             const char *ename = btf_name_by_offset(btf, e_name_off);
             printf("  %s = %d\n", ename ? ename : "<anon>", e_val);
         }
         break;
     }
     case BTF_KIND_TYPEDEF: {
         uint32_t *type_ptr = (uint32_t *)(t + 1);
         uint32_t target_type = is_be ? u32be(*type_ptr) : u32le(*type_ptr);
         printf("[%u] TYPEDEF %s -> ", type_id, name ? name : "<anon>");
         dump_type_recursive(btf, target_type, indent + 1, visited);
         break;
     }
     case BTF_KIND_VOLATILE: {
         uint32_t *type_ptr = (uint32_t *)(t + 1);
         uint32_t target_type = is_be ? u32be(*type_ptr) : u32le(*type_ptr);
         printf("[%u] VOLATILE -> ", type_id);
         dump_type_recursive(btf, target_type, indent + 1, visited);
         break;
     }
     case BTF_KIND_CONST: {
         uint32_t *type_ptr = (uint32_t *)(t + 1);
         uint32_t target_type = is_be ? u32be(*type_ptr) : u32le(*type_ptr);
         printf("[%u] CONST -> ", type_id);
         dump_type_recursive(btf, target_type, indent + 1, visited);
         break;
     }
     case BTF_KIND_FWD:
         printf("[%u] FWD %s\n", type_id, name ? name : "<anon>");
         break;
     default:
         printf("[%u] KIND_%u %s\n", type_id, kind, name ? name : "<anon>");
         break;
     }
 }
 
 /* 转储类型 */
 int32_t btf_dump_type(const btf_t *btf, uint32_t type_id, int32_t indent)
 {
     if (!btf) return -1;
 
     bool *visited = (bool *)calloc(btf->nr_types + 1, sizeof(bool));
     if (!visited) {
         tools_loge_exit("failed to allocate visited array\n");
     }
 
     dump_type_recursive(btf, type_id, indent, visited);
     free(visited);
 
     return 0;
 }
 
/* 转储所有类型 - 限制输出以避免过多信息 */
int32_t btf_dump_all_types(const btf_t *btf)
{
    if (!btf) return -1;

    printf("BTF Types (total: %u):\n", btf->nr_types);
    printf("========================================\n");
    printf("Note: Only showing first 100 types. Use btf_dump_type() for specific types.\n");
    printf("========================================\n");

    bool *visited = (bool *)calloc(btf->nr_types + 1, sizeof(bool));
    if (!visited) {
        tools_loge_exit("failed to allocate visited array\n");
    }

    /* 限制输出前100个类型，避免输出过多 */
    uint32_t max_dump = btf->nr_types < 100 ? btf->nr_types : 100;
    for (uint32_t i = 1; i <= max_dump; i++) {
        dump_type_recursive(btf, i, 0, visited);
        memset(visited, 0, (btf->nr_types + 1) * sizeof(bool));
    }

    if (btf->nr_types > max_dump) {
        printf("... (omitted %u more types)\n", btf->nr_types - max_dump);
    }

    printf("============end===================\n");
    free(visited);
    return 0;
}
 
 /* 从内核文件解析BTF */
 int32_t btf_parse_kernel_file(const char *kimg_path, btf_t *btf)
 {
     char *img = NULL;
     int len = 0;

     read_file(kimg_path, &img, &len);
     
     /* 保存分配的内存指针，以便btf_free释放 */
     btf->allocated_data = img;
     
     int32_t ret = btf_parse(img, len, btf);
     
     /* 如果解析失败，释放内存 */
     if (ret != 0) {
         free(img);
         btf->allocated_data = NULL;
     }

     return ret;
 }
 
 /* 转储BTF信息 */
 int32_t dump_btf(const char *kimg_path)
 {
     btf_t btf = { 0 };
     int32_t ret = btf_parse_kernel_file(kimg_path, &btf);
     if (ret != 0) {
         tools_loge("failed to parse BTF from %s\n", kimg_path);
         return ret;
     }
 
     printf("BTF Information:\n");
     printf("================\n");
     printf("Magic: 0x%04x\n", btf.hdr->magic);
     printf("Version: %d\n", btf.hdr->version);
     printf("Type section size: %u bytes\n", btf.hdr->type_len);
     printf("String section size: %u bytes\n", btf.hdr->str_len);
     printf("Total types: %u\n", btf.nr_types);
     printf("\n");
 
     btf_dump_all_types(&btf);
     btf_free(&btf);
 
     return 0;
 }
 
 /* 根据名称转储特定类型 */
 int32_t dump_btf_type_by_name(const char *kimg_path, const char *type_name)
 {
     btf_t btf = { 0 };
     int32_t ret = btf_parse_kernel_file(kimg_path, &btf);
     if (ret != 0) {
         tools_loge("failed to parse BTF from %s\n", kimg_path);
         return ret;
     }
 
     int32_t type_id = btf_find_by_name(&btf, type_name);
     if (type_id < 0) {
         tools_loge("type '%s' not found\n", type_name);
         btf_free(&btf);
         return -1;
     }
 
     printf("Type: %s (ID: %d)\n", type_name, type_id);
     printf("================\n");
     btf_dump_type(&btf, (uint32_t)type_id, 0);
 
     /* 如果是结构体，打印成员详细信息 */
     btf_type_info_t info = { 0 };
     if (btf_get_type_info(&btf, (uint32_t)type_id, &info) == 0) {
         if (info.kind == BTF_KIND_STRUCT || info.kind == BTF_KIND_UNION) {
             btf_member_info_t members[256];
             int32_t member_count = btf_get_struct_members(&btf, (uint32_t)type_id, members, 256);
             if (member_count > 0) {
                 printf("\nMembers:\n");
                 for (int32_t i = 0; i < member_count; i++) {
                     printf("  [%d] %s (offset: %u bytes, type_id: %u)\n", i, members[i].name ? members[i].name : "<anon>",
                            members[i].offset, members[i].type_id);
                 }
             }
         } else if (info.kind == BTF_KIND_ENUM) {
             btf_enum_info_t values[256];
             int32_t value_count = btf_get_enum_values(&btf, (uint32_t)type_id, values, 256);
             if (value_count > 0) {
                 printf("\nEnum values:\n");
                 for (int32_t i = 0; i < value_count; i++) {
                     printf("  %s = %d\n", values[i].name ? values[i].name : "<anon>", values[i].val);
                 }
             }
         }
     }
 
     btf_free(&btf);
     return 0;
 }
 
 