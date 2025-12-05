/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

 #ifndef _KP_START_H_
 #define _KP_START_H_
 
 #include <preset.h>

 #ifndef __ASSEMBLY__
 typedef struct
 {
     setup_header_t header;
     version_t kernel_version;
     uint32_t _;
     int64_t kallsyms_lookup_name_offset;
     int64_t kernel_size;
     int64_t start_offset;
     int64_t extra_size;
     uint64_t kernel_pa;
     int64_t map_offset;
     int64_t map_backup_len;
     uint8_t map_backup[MAP_MAX_SIZE];
     uint8_t superkey[SUPER_KEY_LEN];
     uint8_t root_superkey[ROOT_SUPER_KEY_HASH_LEN];
     patch_config_t patch_config;
     struct_offsets_t struct_offsets;
 } start_preset_t;
 #else
 /* Assembly offsets for start_preset_t structure
  * Structure layout (ARM64 alignment: 8-byte aligned):
  *   offset 0-63:    header (setup_header_t, KP_HEADER_SIZE = 64 bytes)
  *   offset 64-67:   kernel_version (version_t, 4 bytes)
  *   offset 68-71:   _ (uint32_t, 4 bytes)
  *                    Note: kernel_version + _ = 8 bytes, next field aligns to 8-byte boundary
  *   offset 72-79:   kallsyms_lookup_name_offset (int64_t, 8 bytes)
  *   offset 80-87:   kernel_size (int64_t, 8 bytes)
  *   offset 88-95:   start_offset (int64_t, 8 bytes)
  *   offset 96-103:  extra_size (int64_t, 8 bytes)
  *   offset 104-111: kernel_pa (uint64_t, 8 bytes)
  *   offset 112-119: map_offset (int64_t, 8 bytes)
  *   offset 120-127: map_backup_len (int64_t, 8 bytes)
  *   offset 128-2687: map_backup (uint8_t[MAP_MAX_SIZE], MAP_MAX_SIZE = 0xa00 = 2560 bytes)
  *   offset 2688-2751: superkey (uint8_t[SUPER_KEY_LEN], 64 bytes)
  *   offset 2752-2783: root_superkey (uint8_t[ROOT_SUPER_KEY_HASH_LEN], 32 bytes)
 *   offset 2784-3295: patch_config (patch_config_t, PATCH_CONFIG_LEN = 512 bytes)
 *   offset 3296-3431: struct_offsets (struct_offsets_t, STRUCT_OFFSETS_LEN)
  */
 #define start_header_offset 0
 #define start_kernel_version_offset (start_header_offset + KP_HEADER_SIZE)                    /* offset: 64 */
 #define start_kallsyms_lookup_name_offset_offset (start_kernel_version_offset + 8)            /* offset: 72 (kernel_version 4 + _ 4 = 8) */
 #define start_kernel_size_offset (start_kallsyms_lookup_name_offset_offset + 8)              /* offset: 80 */
 #define start_start_offset_offset (start_kernel_size_offset + 8)                              /* offset: 88 */
 #define start_extra_size_offset (start_start_offset_offset + 8)                               /* offset: 96 */
 #define start_kernel_pa_offset (start_extra_size_offset + 8)                                 /* offset: 104 */
 #define start_map_offset_offset (start_kernel_pa_offset + 8)                                  /* offset: 112 */
 #define start_map_backup_len_offset (start_map_offset_offset + 8)                             /* offset: 120 */
 #define start_map_backup_offset (start_map_backup_len_offset + 8)                            /* offset: 128 */
 #define start_superkey_offset (start_map_backup_offset + MAP_MAX_SIZE)                        /* offset: 2688 */
 #define start_root_superkey_offset (start_superkey_offset + SUPER_KEY_LEN)                    /* offset: 2752 */
 #define start_patch_config_offset (start_root_superkey_offset + ROOT_SUPER_KEY_HASH_LEN)      /* offset: 2784 */
 #define start_struct_offsets_offset (start_patch_config_offset + PATCH_CONFIG_LEN)            /* offset: 3296 */
 #define start_end (start_struct_offsets_offset + STRUCT_OFFSETS_LEN)                          
 #endif
 
 #endif // _KP_START_H_