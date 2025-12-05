/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PRESET_H_
#define _KP_PRESET_H_

#ifndef __ASSEMBLY__
#include <stdint.h>
#endif

#define KP_MAGIC "KP1158"
#define MAGIC_LEN 0x8
#define KP_HEADER_SIZE 0x40
#define SUPER_KEY_LEN 0x40
#define ROOT_SUPER_KEY_HASH_LEN 0x20
#define SETUP_PRESERVE_LEN 0x40
#define HDR_BACKUP_SIZE 0x8
#define COMPILE_TIME_LEN 0x18
#define MAP_MAX_SIZE 0xa00
#define HOOK_ALLOC_SIZE (1 << 20)
#define MEMORY_ROX_SIZE (4 << 20)
#define MEMORY_RW_SIZE (2 << 20)
#define MAP_ALIGN 0x10

#define CONFIG_DEBUG (1 << 0)
#define CONFIG_ANDROID (1 << 1)

#define MAP_SYMBOL_NUM (5)
#define MAP_SYMBOL_SIZE (MAP_SYMBOL_NUM * 8)

#define PATCH_CONFIG_LEN (512)

#define ADDITIONAL_LEN (512)

#define PATCH_EXTRA_ITEM_LEN (128)

#define STRUCT_OFFSETS_LEN (512)

#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

#ifndef __ASSEMBLY__
typedef struct version_t
{
    uint8_t _;
    uint8_t patch;
    uint8_t minor;
    uint8_t major;
} version_t;
#endif

#ifndef __ASSEMBLY__

typedef uint64_t config_t;

typedef struct _setup_header_t // 64-bytes
{
    union
    {
        struct
        {
            char magic[MAGIC_LEN]; //
            version_t kp_version;
            uint32_t _;
            config_t config_flags;
            char compile_time[COMPILE_TIME_LEN];
        };
        char _cap[64];
    };
} setup_header_t;

_Static_assert(sizeof(setup_header_t) == KP_HEADER_SIZE, "sizeof setup_header_t mismatch");

#else
/* Assembly offsets for setup_header_t (64 bytes total)
 * Structure layout:
 *   offset 0-7:   magic[8] (MAGIC_LEN)
 *   offset 8-11:  kp_version (version_t, 4 bytes)
 *   offset 12-15: _ (uint32_t, 4 bytes)
 *   offset 16-23: config_flags (config_t = uint64_t, 8 bytes)
 *   offset 24-47: compile_time[24] (COMPILE_TIME_LEN)
 *   offset 48-63: padding/reserved
 */
#define header_magic_offset 0
#define header_kp_version_offset (MAGIC_LEN)                              /* offset: 8 */
#define header_config_flags_offset (header_kp_version_offset + 4 + 4)       /* offset: 16 */
#define header_compile_time_offset (header_config_flags_offset + 8)          /* offset: 24 */
#endif

#ifndef __ASSEMBLY__
struct map_symbol
{
    union
    {
        struct
        {
            uint64_t memblock_reserve_relo;
            uint64_t memblock_free_relo;
            uint64_t memblock_phys_alloc_relo;
            uint64_t memblock_virt_alloc_relo;
            uint64_t memblock_mark_nomap_relo;
        };
        char _cap[MAP_SYMBOL_SIZE];
    };
};
typedef struct map_symbol map_symbol_t;
_Static_assert(sizeof(map_symbol_t) == MAP_SYMBOL_SIZE, "sizeof map_symbol_t mismatch");
#endif

#ifndef __ASSEMBLY__

#define PATCH_CONFIG_SU_ENABLE 0x1
#define PATCH_CONFIG_SU_HOOK_NO_WRAP 0x2
#define PATCH_CONFIG_SU_ENABLE32 0x2

struct patch_config
{
    union
    {
        struct
        {
            uint64_t kallsyms_lookup_name;
            uint64_t printk;

            uint64_t panic;
            uint64_t rest_init;
            uint64_t cgroup_init;
            uint64_t kernel_init;
            uint64_t report_cfi_failure;
            uint64_t __cfi_slowpath_diag;
            uint64_t __cfi_slowpath;
            uint64_t copy_process;
            uint64_t cgroup_post_fork;
            uint64_t avc_denied;
            uint64_t slow_avc_audit;
            uint64_t input_handle_event;

            uint8_t patch_su_config;
        };
        char _cap[PATCH_CONFIG_LEN];
    };
};
typedef struct patch_config patch_config_t;
_Static_assert(sizeof(patch_config_t) == PATCH_CONFIG_LEN, "sizeof patch_config_t mismatch");
#endif

#ifndef __ASSEMBLY__

#define EXTRA_ALIGN 0x10
#define EXTRA_NAME_LEN 0x20
#define EXTRA_EVENT_LEN 0x20

#define EXTRA_HDR_MAGIC "kpe"

typedef int32_t extra_item_type;

#define EXTRA_TYPE_NONE 0
#define EXTRA_TYPE_KPM 1
#define EXTRA_TYPE_SHELL 2
#define EXTRA_TYPE_EXEC 3
#define EXTRA_TYPE_RAW 4
#define EXTRA_TYPE_ANDROID_RC 5

#define EXTRA_TYPE_NONE_STR "none"
#define EXTRA_TYPE_KPM_STR "kpm"
#define EXTRA_TYPE_SHELL_STR "shell"
#define EXTRA_TYPE_EXEC_STR "exec"
#define EXTRA_TYPE_RAW_STR "raw"
#define EXTRA_TYPE_ANDROID_RC_STR "android_rc"

// todo
#define EXTRA_EVENT_PAGING_INIT "paging-init"

#define EXTRA_EVENT_PRE_KERNEL_INIT "pre-kernel-init"
#define EXTRA_EVENT_KPM_DEFAULT EXTRA_EVENT_PRE_KERNEL_INIT
#define EXTRA_EVENT_POST_KERNEL_INIT "post-kernel-init"

#define EXTRA_EVENT_PRE_FIRST_STAGE "pre-init-first-stage"
#define EXTRA_EVENT_POST_FIRST_STAGE "post-init-first-stage"

#define EXTRA_EVENT_PRE_EXEC_INIT "pre-exec-init"
#define EXTRA_EVENT_POST_EXEC_INIT "post-exec-init"

#define EXTRA_EVENT_PRE_SECOND_STAGE "pre-init-second-stage"
#define EXTRA_EVENT_POST_SECOND_STAGE "post-init-second-stage"

struct _patch_extra_item
{
    union
    {
        struct
        {
            char magic[4];
            int32_t priority;
            int32_t args_size;
            int32_t con_size;
            extra_item_type type;
            char name[EXTRA_NAME_LEN];
            char event[EXTRA_EVENT_LEN];
        };
        char _cap[PATCH_EXTRA_ITEM_LEN];
    };
};
typedef struct _patch_extra_item patch_extra_item_t;
_Static_assert(sizeof(patch_extra_item_t) == PATCH_EXTRA_ITEM_LEN, "sizeof patch_extra_item_t mismatch");
#endif

#ifndef __ASSEMBLY__

/* 结构体偏移量配置结构 - 从BTF提取的结构体成员偏移量 */
typedef struct
{
    union
    {
        struct
        {
            /* task_struct偏移量 */
            int32_t task_struct_pid_offset;
            int32_t task_struct_tgid_offset;
            int32_t task_struct_thread_pid_offset;
            int32_t task_struct_ptracer_cred_offset;
            int32_t task_struct_real_cred_offset;
            int32_t task_struct_cred_offset;
            int32_t task_struct_fs_offset;
            int32_t task_struct_files_offset;
            int32_t task_struct_loginuid_offset;
            int32_t task_struct_sessionid_offset;
            int32_t task_struct_comm_offset;
            int32_t task_struct_seccomp_offset;
            int32_t task_struct_security_offset;
            int32_t task_struct_stack_offset;
            int32_t task_struct_tasks_offset;
            int32_t task_struct_mm_offset;
            int32_t task_struct_active_mm_offset;
            
            /* cred偏移量 */
            int32_t cred_usage_offset;
            int32_t cred_subscribers_offset;
            int32_t cred_magic_offset;
            int32_t cred_uid_offset;
            int32_t cred_gid_offset;
            int32_t cred_suid_offset;
            int32_t cred_sgid_offset;
            int32_t cred_euid_offset;
            int32_t cred_egid_offset;
            int32_t cred_fsuid_offset;
            int32_t cred_fsgid_offset;
            int32_t cred_securebits_offset;
            int32_t cred_cap_inheritable_offset;
            int32_t cred_cap_permitted_offset;
            int32_t cred_cap_effective_offset;
            int32_t cred_cap_bset_offset;
            int32_t cred_cap_ambient_offset;
            int32_t cred_user_offset;
            int32_t cred_user_ns_offset;
            int32_t cred_ucounts_offset;
            int32_t cred_group_info_offset;
            int32_t cred_session_keyring_offset;
            int32_t cred_process_keyring_offset;
            int32_t cred_thread_keyring_offset;
            int32_t cred_request_key_auth_offset;
            int32_t cred_security_offset;
            int32_t cred_rcu_offset;
            
            /* mm_struct偏移量 */
            int32_t mm_struct_mmap_base_offset;
            int32_t mm_struct_task_size_offset;
            int32_t mm_struct_pgd_offset;
            int32_t mm_struct_map_count_offset;
            int32_t mm_struct_total_vm_offset;
            int32_t mm_struct_locked_vm_offset;
            int32_t mm_struct_pinned_vm_offset;
            int32_t mm_struct_data_vm_offset;
            int32_t mm_struct_exec_vm_offset;
            int32_t mm_struct_stack_vm_offset;
            int32_t mm_struct_start_code_offset;
            int32_t mm_struct_end_code_offset;
            int32_t mm_struct_start_data_offset;
            int32_t mm_struct_end_data_offset;
            int32_t mm_struct_start_brk_offset;
            int32_t mm_struct_brk_offset;
            int32_t mm_struct_start_stack_offset;
            int32_t mm_struct_arg_start_offset;
            int32_t mm_struct_arg_end_offset;
            int32_t mm_struct_env_start_offset;
            int32_t mm_struct_env_end_offset;
            
        };
        char _cap[STRUCT_OFFSETS_LEN];
    };
} struct_offsets_t;
_Static_assert(sizeof(struct_offsets_t) == STRUCT_OFFSETS_LEN, "sizeof struct_offsets_t mismatch");

#endif

#ifndef __ASSEMBLY__

// TODO: remove
typedef struct
{
    version_t kernel_version;
    int32_t _;
    int64_t kimg_size; // must aligned
    int64_t kpimg_size; // must aligned
    int64_t kernel_size; // must aligned
    int64_t page_shift;
    int64_t setup_offset; // must aligned
    int64_t start_offset; // must aligned
    int64_t extra_size; // must aligned
    int64_t map_offset; // must aligned MAP_ALIGN
    int64_t map_max_size;
    int64_t kallsyms_lookup_name_offset;
    int64_t paging_init_offset;
    int64_t printk_offset;
    map_symbol_t map_symbol;
    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
    patch_config_t patch_config;
    char additional[ADDITIONAL_LEN];
} setup_preset_be_000a04_t;

typedef struct _setup_preset_t
{
    version_t kernel_version;
    int32_t _;
    int64_t kimg_size; // must aligned
    int64_t kpimg_size; // must aligned
    int64_t kernel_size; // must aligned
    int64_t page_shift;
    int64_t setup_offset; // must aligned
    int64_t start_offset; // must aligned
    int64_t extra_size; // must aligned
    int64_t map_offset; // must aligned MAP_ALIGN
    int64_t map_max_size;
    int64_t kallsyms_lookup_name_offset;
    int64_t paging_init_offset;
    int64_t printk_offset;
    map_symbol_t map_symbol;
    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
    uint8_t root_superkey[ROOT_SUPER_KEY_HASH_LEN];
    uint8_t __[SETUP_PRESERVE_LEN];
    patch_config_t patch_config;
    struct_offsets_t struct_offsets;
    char additional[ADDITIONAL_LEN];
} setup_preset_t;
#else
/* Assembly offsets for setup_preset_t structure
 * Structure layout (ARM64 alignment: 8-byte aligned):
 *   offset 0-3:   kernel_version (version_t, 4 bytes)
 *   offset 4-7:   _ (int32_t, 4 bytes)
 *   offset 8-15:  kimg_size (int64_t, 8 bytes)
 *   offset 16-23: kpimg_size (int64_t, 8 bytes)
 *   offset 24-31: kernel_size (int64_t, 8 bytes)
 *   offset 32-39: page_shift (int64_t, 8 bytes)
 *   offset 40-47: setup_offset (int64_t, 8 bytes)
 *   offset 48-55: start_offset (int64_t, 8 bytes)
 *   offset 56-63: extra_size (int64_t, 8 bytes)
 *   offset 64-71: map_offset (int64_t, 8 bytes)
 *   offset 72-79: map_max_size (int64_t, 8 bytes)
 *   offset 80-87: kallsyms_lookup_name_offset (int64_t, 8 bytes)
 *   offset 88-95: paging_init_offset (int64_t, 8 bytes)
 *   offset 96-103: printk_offset (int64_t, 8 bytes)
 *   offset 104-143: map_symbol (map_symbol_t, MAP_SYMBOL_SIZE = 40 bytes)
 *   offset 144-151: header_backup (uint8_t[HDR_BACKUP_SIZE], 8 bytes)
 *   offset 152-215: superkey (uint8_t[SUPER_KEY_LEN], 64 bytes)
 *   offset 216-247: root_superkey (uint8_t[ROOT_SUPER_KEY_HASH_LEN], 32 bytes)
 *   offset 248-311: __ (uint8_t[SETUP_PRESERVE_LEN], 64 bytes)
 *   offset 312-823: patch_config (patch_config_t, PATCH_CONFIG_LEN = 512 bytes)
 *   offset 824-1335: struct_offsets (struct_offsets_t, STRUCT_OFFSETS_LEN = 512 bytes)
 *   offset 1336-1847: additional (char[ADDITIONAL_LEN], 512 bytes)
 *   Total size: 1848 bytes
 */
#define setup_kernel_version_offset 0
#define setup_kimg_size_offset (setup_kernel_version_offset + 8)          /* offset: 8 */
#define setup_kpimg_size_offset (setup_kimg_size_offset + 8)              /* offset: 16 */
#define setup_kernel_size_offset (setup_kpimg_size_offset + 8)             /* offset: 24 */
#define setup_page_shift_offset (setup_kernel_size_offset + 8)             /* offset: 32 */
#define setup_setup_offset_offset (setup_page_shift_offset + 8)             /* offset: 40 */
#define setup_start_offset_offset (setup_setup_offset_offset + 8)           /* offset: 48 */
#define setup_extra_size_offset (setup_start_offset_offset + 8)           /* offset: 56 */
#define setup_map_offset_offset (setup_extra_size_offset + 8)              /* offset: 64 */
#define setup_map_max_size_offset (setup_map_offset_offset + 8)            /* offset: 72 */
#define setup_kallsyms_lookup_name_offset_offset (setup_map_max_size_offset + 8) /* offset: 80 */
#define setup_paging_init_offset_offset (setup_kallsyms_lookup_name_offset_offset + 8) /* offset: 88 */
#define setup_printk_offset_offset (setup_paging_init_offset_offset + 8)   /* offset: 96 */
#define setup_map_symbol_offset (setup_printk_offset_offset + 8)           /* offset: 104 */
#define setup_header_backup_offset (setup_map_symbol_offset + MAP_SYMBOL_SIZE) /* offset: 144 */
#define setup_superkey_offset (setup_header_backup_offset + HDR_BACKUP_SIZE) /* offset: 152 */
#define setup_root_superkey_offset (setup_superkey_offset + SUPER_KEY_LEN) /* offset: 216 */
#define setup_patch_config_offset (setup_root_superkey_offset + ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN) /* offset: 312 */
#define setup_struct_offsets_offset (setup_patch_config_offset + PATCH_CONFIG_LEN) /* offset: 824 */
#define setup_additional_offset (setup_struct_offsets_offset + STRUCT_OFFSETS_LEN) /* offset: 1336 */
#define setup_end (setup_additional_offset + ADDITIONAL_LEN)             /* offset: 1848 */
#endif

#ifndef __ASSEMBLY__
typedef struct
{
    setup_header_t header;
    setup_preset_t setup;
} preset_t;
#endif

#endif // _KP_PRESET_H_