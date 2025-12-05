/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"
#include "preset.h"
#include "symbol.h"
#include "kpm.h"
#include "sha256.h"
#include "btf.h"

void read_kernel_file(const char *path, kernel_file_t *kernel_file)
{
    int img_offset = 0;
    read_file(path, &kernel_file->kfile, &kernel_file->kfile_len);
    kernel_file->is_uncompressed_img = kernel_file->kfile_len >= 20 &&
                                       !strncmp("UNCOMPRESSED_IMG", kernel_file->kfile, 16);
    if (kernel_file->is_uncompressed_img) img_offset = 20;
    kernel_file->kimg = kernel_file->kfile + img_offset;
    kernel_file->kimg_len = kernel_file->kfile_len - img_offset;
}

void update_kernel_file_img_len(kernel_file_t *kernel_file, int kimg_len, bool is_different_endian)
{
    kernel_file->kimg_len = kimg_len;
    if (kernel_file->is_uncompressed_img) {
        *(uint32_t *)(kernel_file->kfile + 16) = (uint32_t)(is_different_endian ? i32swp(kimg_len) : kimg_len);
        kernel_file->kfile_len = kimg_len + 20;
    } else {
        kernel_file->kfile_len = kimg_len;
    }
}

void new_kernel_file(kernel_file_t *kernel_file, kernel_file_t *old, int kimg_len, bool is_different_endian)
{
    int prefix_len = old->kimg - old->kfile;
    int new_len = kimg_len + prefix_len;
    kernel_file->kfile = (char *)malloc(new_len);
    kernel_file->kimg = kernel_file->kfile + prefix_len;
    memcpy(kernel_file->kfile, old->kfile, prefix_len);
    kernel_file->is_uncompressed_img = old->is_uncompressed_img;
    update_kernel_file_img_len(kernel_file, kimg_len, is_different_endian);
}

void write_kernel_file(kernel_file_t *kernel_file, const char *path)
{
    write_file(path, kernel_file->kfile, kernel_file->kfile_len, false);
}

void free_kernel_file(kernel_file_t *kernel_file)
{
    free(kernel_file->kfile);
    kernel_file->kfile = NULL;
    kernel_file->kimg = NULL;
}

preset_t *get_preset(const char *kimg, int kimg_len)
{
    char magic[MAGIC_LEN] = KP_MAGIC;
    return (preset_t *)memmem(kimg, kimg_len, magic, sizeof(magic));
}

uint32_t get_kpimg_version(const char *kpimg_path)
{
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file(kpimg_path, &kpimg, &kpimg_len);
    preset_t *preset = get_preset(kpimg, kpimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");
    version_t ver = preset->header.kp_version;
    uint32_t version = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    return version;
}

int extra_str_type(const char *extra_str)
{
    int extra_type = EXTRA_TYPE_NONE;
    if (!strcmp(extra_str, EXTRA_TYPE_KPM_STR)) {
        extra_type = EXTRA_TYPE_KPM;
    } else if (!strcmp(extra_str, EXTRA_TYPE_EXEC_STR)) {
        extra_type = EXTRA_TYPE_EXEC;
    } else if (!strcmp(extra_str, EXTRA_TYPE_SHELL_STR)) {
        extra_type = EXTRA_TYPE_SHELL;
    } else if (!strcmp(extra_str, EXTRA_TYPE_RAW_STR)) {
        extra_type = EXTRA_TYPE_RAW;
    } else if (!strcmp(extra_str, EXTRA_TYPE_ANDROID_RC_STR)) {
        extra_type = EXTRA_TYPE_ANDROID_RC;
    } else {
    }
    return extra_type;
}

const char *extra_type_str(extra_item_type extra_type)
{
    switch (extra_type) {
    case EXTRA_TYPE_KPM:
        return EXTRA_TYPE_KPM_STR;
    case EXTRA_TYPE_EXEC:
        return EXTRA_TYPE_EXEC_STR;
    case EXTRA_TYPE_SHELL:
        return EXTRA_TYPE_SHELL_STR;
    case EXTRA_TYPE_RAW:
        return EXTRA_TYPE_RAW_STR;
    case EXTRA_TYPE_ANDROID_RC:
        return EXTRA_TYPE_ANDROID_RC_STR;
    default:
        return EXTRA_TYPE_NONE_STR;
    }
}

static char *bytes_to_hexstr(const unsigned char *data, int len)
{
    char *buf = (char *)malloc(2 * len + 1);
    buf[2 * len] = '\0';
    for (int i = 0; i < len; i++) {
        sprintf(&buf[2 * i], "%02x", data[i]);
    }
    return buf;
}

void print_preset_info(preset_t *preset)
{
    setup_header_t *header = &preset->header;
    setup_preset_t *setup = &preset->setup;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;

    fprintf(stdout, INFO_KP_IMG_SESSION "\n");
    fprintf(stdout, "version=0x%x\n", ver_num);
    fprintf(stdout, "compile_time=%s\n", header->compile_time);
    fprintf(stdout, "config=%s,%s\n", is_android ? "android" : "linux", is_debug ? "debug" : "release");
    fprintf(stdout, "superkey=%s\n", setup->superkey);

    // todo: remove compat version
    if (ver_num > 0xa04) {
        char *hexstr = bytes_to_hexstr(setup->root_superkey, ROOT_SUPER_KEY_HASH_LEN);
        fprintf(stdout, "root_superkey=%s\n", hexstr);
        free(hexstr);
    }

    fprintf(stdout, INFO_ADDITIONAL_SESSION "\n");
    char *addition = setup->additional;
    // todo: remove compat version
    if (ver_num <= 0xa04) {
        addition -= (ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN);
    }
    char *pos = addition;
    while (pos < addition + ADDITIONAL_LEN) {
        int len = *pos;
        if (!len) break;
        pos++;
        char backup = *(pos + len);
        *(pos + len) = 0;
        fprintf(stdout, "%s\n", pos);
        *(pos + len) = backup;
        pos += len;
    }
}

int print_kp_image_info_path(const char *kpimg_path)
{
    int rc = 0;
    char *kpimg;
    int len = 0;
    read_file(kpimg_path, &kpimg, &len);
    preset_t *preset = (preset_t *)kpimg;
    if (get_preset(kpimg, len) != preset) {
        rc = -ENOENT;
    } else {
        print_preset_info(preset);
        fprintf(stdout, "\n");
        free(kpimg);
    }
    return rc;
}

int parse_image_patch_info(const char *kimg, int kimg_len, patched_kimg_t *pimg)
{
    pimg->kimg = kimg;
    pimg->kimg_len = kimg_len;

    // kernel image infomation
    kernel_info_t *kinfo = &pimg->kinfo;
    if (get_kernel_info(kinfo, kimg, kimg_len)) tools_loge_exit("get_kernel_info error\n");

    // find banner
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);
    const char *imgend = pimg->kimg + pimg->kimg_len;
    const char *banner = (char *)pimg->kimg;
    while ((banner = (char *)memmem(banner + 1, imgend - banner, linux_banner_prefix, prefix_len)) != NULL) {
        if (isdigit(*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            pimg->banner = banner;
            break;
        }
    }
    if (!pimg->banner) tools_loge_exit("can't find linux banner\n");

    // patched or new
    preset_t *old_preset = get_preset(kimg, kimg_len);
    pimg->preset = old_preset;

    if (!old_preset) {
        tools_logi("new kernel image ...\n");
        pimg->ori_kimg_len = pimg->kimg_len;
        return 0;
    }

    tools_logi("patched kernel image ...\n");
    int32_t saved_kimg_len = old_preset->setup.kimg_size;
    if (is_be() ^ kinfo->is_be) saved_kimg_len = i32swp(saved_kimg_len);

    int align_kimg_len = (char *)old_preset - kimg;
    if (align_kimg_len != (int)align_ceil(saved_kimg_len, SZ_4K)) tools_loge_exit("saved kernel image size error\n");
    pimg->ori_kimg_len = saved_kimg_len;

    memcpy((char *)kimg, old_preset->setup.header_backup, sizeof(old_preset->setup.header_backup));

    // extra
    int extra_offset = align_kimg_len + old_preset->setup.kpimg_size;
    if (extra_offset > kimg_len) tools_loge_exit("kpimg length mismatch\n");
    if (extra_offset == kimg_len) return 0;

    int32_t extra_size = old_preset->setup.extra_size;
    if (is_be() ^ kinfo->is_be) extra_size = i32swp(extra_size);
    const char *item_pos = kimg + extra_offset;

    while (item_pos < kimg + extra_offset + extra_size) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_pos;
        if (strcmp(EXTRA_HDR_MAGIC, item->magic)) break;
        if (item->type == EXTRA_TYPE_NONE) break;
        pimg->embed_item[pimg->embed_item_num++] = item;
        item_pos += sizeof(patch_extra_item_t);
        item_pos += item->args_size;
        item_pos += item->con_size;
    }

    return 0;
}

int parse_image_patch_info_path(const char *kimg_path, patched_kimg_t *pimg)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

int print_image_patch_info(patched_kimg_t *pimg)
{
    int rc = 0;

    preset_t *preset = pimg->preset;

    fprintf(stdout, INFO_KERNEL_IMG_SESSION "\n");
    fprintf(stdout, "banner=%s", pimg->banner);

    if (pimg->banner[strlen(pimg->banner) - 1] != '\n') fprintf(stdout, "\n");
    fprintf(stdout, "patched=%s\n", preset ? "true" : "false");

    if (preset) {
        print_preset_info(preset);

        fprintf(stdout, INFO_EXTRA_SESSION "\n");
        fprintf(stdout, "num=%d\n", pimg->embed_item_num);

        for (int i = 0; i < pimg->embed_item_num; i++) {
            patch_extra_item_t *item = pimg->embed_item[i];
            const char *type = extra_type_str(item->type);
            fprintf(stdout, INFO_EXTRA_SESSION_N "\n", i);
            fprintf(stdout, "index=%d\n", i);
            fprintf(stdout, "type=%s\n", type);
            fprintf(stdout, "name=%s\n", item->name);
            fprintf(stdout, "event=%s\n", item->event);
            fprintf(stdout, "priority=%d\n", item->priority);
            fprintf(stdout, "args_size=0x%x\n", item->args_size);
            fprintf(stdout, "args=%s\n", item->args_size > 0 ? (char *)item + sizeof(*item) : "");
            fprintf(stdout, "con_size=0x%x\n", item->con_size);

            if (item->type == EXTRA_TYPE_KPM) {
                kpm_info_t kpm_info = { 0 };
                void *kpm = (kpm_info_t *)((uintptr_t)item + sizeof(patch_extra_item_t) + item->args_size);
                rc = get_kpm_info(kpm, item->con_size, &kpm_info);
                if (rc) tools_loge_exit("get kpm infomation error: %d\n", rc);
                fprintf(stdout, "version=%s\n", kpm_info.version);
                fprintf(stdout, "license=%s\n", kpm_info.license);
                fprintf(stdout, "author=%s\n", kpm_info.author);
                fprintf(stdout, "description=%s\n", kpm_info.description);
            }
        }
    }
    return rc;
}

int print_image_patch_info_path(const char *kimg_path)
{
    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, &pimg);
    print_image_patch_info(&pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

static int extra_compare(const void *a, const void *b)
{
    extra_config_t *pa = (extra_config_t *)a;
    extra_config_t *pb = (extra_config_t *)b;
    return -(pa->priority - pb->priority);
}

static void extra_append(char *kimg, const void *data, int len, int *offset)
{
    memcpy(kimg + *offset, data, len);
    *offset += len;
}

static void disable_pi_map(char *img, int32_t imglen)
{
    
    const unsigned char pattern[] = {
        0xE6, 0x03, 0x16, 0xAA,
        0xE7, 0x03, 0x1F, 0x2A,
        0x34, 0x11, 0x88, 0x9A
    };
    const size_t pattern_len = sizeof(pattern);

    const unsigned char replace[] = {
        0xE6, 0x03, 0x16, 0xAA,
        0xE7, 0x03, 0x1F, 0x2A,
        0xF4, 0x03, 0x09, 0xAA
    };

    unsigned char *p = memmem(img, imglen, pattern, pattern_len);
    if (p) {
        memcpy(p, replace, pattern_len);
    }

}

/* 从BTF提取结构体偏移量 */
static int extract_struct_offsets_from_btf(const char *kimg, int kimg_len, struct_offsets_t *offsets)
{
    btf_t btf = { 0 };

    // 初始化所有偏移量为-1（表示未找到）
    memset(offsets, -1, sizeof(*offsets));

    // 解析BTF
    if (btf_parse(kimg, kimg_len, &btf) != 0) {
        tools_loge("BTF not found or parse failed\n");
        return -1;
    }

    tools_logi("Extracting struct offsets from BTF...\n");

    btf_member_info_t member;

    int32_t task_type_id = btf_find_by_name(&btf, "task_struct");
    if (task_type_id < 0) {
        tools_loge("task_struct not found\n");
        return -1;
    }

    int32_t cred_type_id = btf_find_by_name(&btf, "cred");
    if (cred_type_id < 0) {
        tools_loge("cred not found\n");
        return -1;
    }

    int32_t mm_type_id = btf_find_by_name(&btf, "mm_struct");
    if (mm_type_id < 0) {
        tools_loge("mm_struct not found\n");
        return -1;
    }
    uint32_t struct_size = 0;
    tools_logi("parse task_struct members\n");
    btf_get_type_size_by_id(&btf, (uint32_t)task_type_id, &struct_size);
    tools_logi("task_struct members (including nested structs): size=0x%04x\n", struct_size);

    {
        btf_member_info_t task_struct_members = { 0 };

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "stack", &task_struct_members) != 0) {
            tools_loge("stack not found\n");
            return -1;
        }
        offsets->task_struct_stack_offset = task_struct_members.offset;
        tools_logi("task stack off 0x%02x\n",offsets->task_struct_stack_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "pid", &task_struct_members) != 0) {
            tools_loge("pid not found\n");
            return -1;
        }
        offsets->task_struct_pid_offset = task_struct_members.offset;
        tools_logi("task pid off 0x%02x\n",offsets->task_struct_pid_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "tgid", &task_struct_members) != 0) {
            tools_loge("tgid not found\n");
            return -1;
        }
        offsets->task_struct_tgid_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "thread_pid", &task_struct_members) != 0) {
            tools_loge("thread_pid not found\n");
            return -1;
        }
        offsets->task_struct_thread_pid_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "ptracer_cred", &task_struct_members) != 0) {
            tools_loge("ptracer_cred not found\n");
            return -1;
        }
        offsets->task_struct_ptracer_cred_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "real_cred", &task_struct_members) != 0) {
            tools_loge("real_cred not found\n");
            return -1;
        }
        offsets->task_struct_real_cred_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "cred", &task_struct_members) != 0) {
            tools_loge("cred not found\n");
            return -1;
        }
        offsets->task_struct_cred_offset = task_struct_members.offset;
        tools_logi("task cred off 0x%02x\n",offsets->task_struct_cred_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "fs", &task_struct_members) != 0) {
            tools_loge("fs not found\n");
            return -1;
        }
        offsets->task_struct_fs_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "files", &task_struct_members) != 0) {
            tools_loge("files not found\n");
            return -1;
        }
        offsets->task_struct_files_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "loginuid", &task_struct_members) != 0) {
            tools_loge("loginuid not found\n");
            return -1;
        }
        offsets->task_struct_loginuid_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "sessionid", &task_struct_members) != 0) {
            tools_loge("sessionid not found\n");
            return -1;
        }
        offsets->task_struct_sessionid_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "comm", &task_struct_members) != 0) {
            tools_loge("comm not found\n");
            return -1;
        }
        offsets->task_struct_comm_offset = task_struct_members.offset;
        tools_logi("task comm off 0x%02x\n",offsets->task_struct_comm_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "seccomp", &task_struct_members) != 0) {
            tools_loge("seccomp not found\n");
            return -1;
        }
        offsets->task_struct_seccomp_offset = task_struct_members.offset;
        tools_logi("task seccomp off 0x%02x\n",offsets->task_struct_seccomp_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "security", &task_struct_members) != 0) {
            tools_loge("security not found\n");
            return -1;
        }
        offsets->task_struct_security_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "tasks", &task_struct_members) != 0) {
            tools_loge("tasks not found\n");
            return -1;
        }
        offsets->task_struct_tasks_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "mm", &task_struct_members) != 0) {
            tools_loge("mm not found\n");
            return -1;
        }
        offsets->task_struct_mm_offset = task_struct_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)task_type_id, "active_mm", &task_struct_members) != 0) {
            tools_loge("active_mm not found\n");
            return -1;
        }
    }

    // 解析cred结构体成员
    tools_logi("parse cred members\n");
    btf_get_type_size_by_id(&btf, (uint32_t)cred_type_id, &struct_size);
    tools_logi("cred members (including nested structs): size=0x%04x\n", struct_size);

    {
        btf_member_info_t cred_members = { 0 };

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "usage", &cred_members) != 0) {
            tools_loge("usage not found\n");
            return -1;
        }
        offsets->cred_usage_offset = cred_members.offset;

        // if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "subscribers", &cred_members) != 0) {
        //     tools_loge("subscribers not found\n");
        //     return -1;
        // }
        // offsets->cred_subscribers_offset = cred_members.offset;

        // if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "magic", &cred_members) != 0) {
        //     tools_loge("magic not found\n");
        //     return -1;
        // }
        // offsets->cred_magic_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "uid", &cred_members) != 0) {
            tools_loge("uid not found\n");
            return -1;
        }
        offsets->cred_uid_offset = cred_members.offset;
        tools_logi("cred uid off 0x%02x\n",offsets->cred_uid_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "gid", &cred_members) != 0) {
            tools_loge("gid not found\n");
            return -1;
        }
        offsets->cred_gid_offset = cred_members.offset;
        tools_logi("cred gid off 0x%02x\n",offsets->cred_gid_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "suid", &cred_members) != 0) {
            tools_loge("suid not found\n");
            return -1;
        }
        offsets->cred_suid_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "sgid", &cred_members) != 0) {
            tools_loge("sgid not found\n");
            return -1;
        }
        offsets->cred_sgid_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "euid", &cred_members) != 0) {
            tools_loge("euid not found\n");
            return -1;
        }
        offsets->cred_euid_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "egid", &cred_members) != 0) {
            tools_loge("egid not found\n");
            return -1;
        }
        offsets->cred_egid_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "fsuid", &cred_members) != 0) {
            tools_loge("fsuid not found\n");
            return -1;
        }
        offsets->cred_fsuid_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "fsgid", &cred_members) != 0) {
            tools_loge("fsgid not found\n");
            return -1;
        }
        offsets->cred_fsgid_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "securebits", &cred_members) != 0) {
            tools_loge("securebits not found\n");
            return -1;
        }
        offsets->cred_securebits_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "cap_inheritable", &cred_members) != 0) {
            tools_loge("cap_inheritable not found\n");
            return -1;
        }
        offsets->cred_cap_inheritable_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "cap_permitted", &cred_members) != 0) {
            tools_loge("cap_permitted not found\n");
            return -1;
        }
        offsets->cred_cap_permitted_offset = cred_members.offset;
        tools_logi("cred cap_permitted off 0x%02x\n",offsets->cred_cap_permitted_offset);

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "cap_effective", &cred_members) != 0) {
            tools_loge("cap_effective not found\n");
            return -1;
        }
        offsets->cred_cap_effective_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "cap_bset", &cred_members) != 0) {
            tools_loge("cap_bset not found\n");
            return -1;
        }
        offsets->cred_cap_bset_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "cap_ambient", &cred_members) != 0) {
            tools_loge("cap_ambient not found\n");
            return -1;
        }
        offsets->cred_cap_ambient_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "user", &cred_members) != 0) {
            tools_loge("user not found\n");
            return -1;
        }
        offsets->cred_user_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "user_ns", &cred_members) != 0) {
            tools_loge("user_ns not found\n");
            return -1;
        }
        offsets->cred_user_ns_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "ucounts", &cred_members) != 0) {
            tools_loge("ucounts not found\n");
            return -1;
        }
        offsets->cred_ucounts_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "group_info", &cred_members) != 0) {
            tools_loge("group_info not found\n");
            return -1;
        }
        offsets->cred_group_info_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "session_keyring", &cred_members) != 0) {
            tools_loge("session_keyring not found\n");
            return -1;
        }
        offsets->cred_session_keyring_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "process_keyring", &cred_members) != 0) {
            tools_loge("process_keyring not found\n");
            return -1;
        }
        offsets->cred_process_keyring_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "thread_keyring", &cred_members) != 0) {
            tools_loge("thread_keyring not found\n");
            return -1;
        }
        offsets->cred_thread_keyring_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "request_key_auth", &cred_members) != 0) {
            tools_loge("request_key_auth not found\n");
            return -1;
        }
        offsets->cred_request_key_auth_offset = cred_members.offset;

        if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "security", &cred_members) != 0) {
            tools_loge("security not found\n");
            return -1;
        }
        offsets->cred_security_offset = cred_members.offset;

        // if (btf_get_struct_outer_members(&btf, (uint32_t)cred_type_id, "rcu", &cred_members) != 0) {
        //     tools_loge("rcu not found\n");
        //     return -1;
        // }
        // offsets->cred_rcu_offset = cred_members.offset;
    }

    // 解析mm_struct成员 mm这里需要多解析一层，因为mm的成员是嵌套在一个结构体中的
    tools_logi("parse mm_struct members\n");
    btf_get_type_size_by_id(&btf, (uint32_t)mm_type_id, &struct_size);
    tools_logi("mm_struct members (including nested structs): size=0x%04x\n", struct_size);

    {
        btf_member_info_t mm_struct_members = { 0 };

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "mmap_base", &mm_struct_members) != 0) {
            tools_loge("mmap_base not found\n");
            return -1;
        }
        offsets->mm_struct_mmap_base_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "task_size", &mm_struct_members) != 0) {
            tools_loge("task_size not found\n");
            return -1;
        }
        offsets->mm_struct_task_size_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "pgd", &mm_struct_members) != 0) {
            tools_loge("pgd not found\n");
            return -1;
        }
        offsets->mm_struct_pgd_offset = mm_struct_members.offset;
        tools_logi("mm_struct_pgd_offset: %02x\n", offsets->mm_struct_pgd_offset);

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "map_count", &mm_struct_members) != 0) {
            tools_loge("map_count not found\n");
            return -1;
        }
        offsets->mm_struct_map_count_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "total_vm", &mm_struct_members) != 0) {
            tools_loge("total_vm not found\n");
            return -1;
        }
        offsets->mm_struct_total_vm_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "locked_vm", &mm_struct_members) != 0) {
            tools_loge("locked_vm not found\n");
            return -1;
        }
        offsets->mm_struct_locked_vm_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "pinned_vm", &mm_struct_members) != 0) {
            tools_loge("pinned_vm not found\n");
            return -1;
        }
        offsets->mm_struct_pinned_vm_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "data_vm", &mm_struct_members) != 0) {
            tools_loge("data_vm not found\n");
            return -1;
        }
        offsets->mm_struct_data_vm_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "exec_vm", &mm_struct_members) != 0) {
            tools_loge("exec_vm not found\n");
            return -1;
        }
        offsets->mm_struct_exec_vm_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "stack_vm", &mm_struct_members) != 0) {
            tools_loge("stack_vm not found\n");
            return -1;
        }
        offsets->mm_struct_stack_vm_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "start_code", &mm_struct_members) != 0) {
            tools_loge("start_code not found\n");
            return -1;
        }
        offsets->mm_struct_start_code_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "end_code", &mm_struct_members) != 0) {
            tools_loge("end_code not found\n");
            return -1;
        }
        offsets->mm_struct_end_code_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "start_data", &mm_struct_members) != 0) {
            tools_loge("start_data not found\n");
            return -1;
        }
        offsets->mm_struct_start_data_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "end_data", &mm_struct_members) != 0) {
            tools_loge("end_data not found\n");
            return -1;
        }
        offsets->mm_struct_end_data_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "start_brk", &mm_struct_members) != 0) {
            tools_loge("start_brk not found\n");
            return -1;
        }
        offsets->mm_struct_start_brk_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "brk", &mm_struct_members) != 0) {
            tools_loge("brk not found\n");
            return -1;
        }
        offsets->mm_struct_brk_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "start_stack", &mm_struct_members) != 0) {
            tools_loge("start_stack not found\n");
            return -1;
        }
        offsets->mm_struct_start_stack_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "arg_start", &mm_struct_members) != 0) {
            tools_loge("arg_start not found\n");
            return -1;
        }
        offsets->mm_struct_arg_start_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "arg_end", &mm_struct_members) != 0) {
            tools_loge("arg_end not found\n");
            return -1;
        }
        offsets->mm_struct_arg_end_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "env_start", &mm_struct_members) != 0) {
            tools_loge("env_start not found\n");
            return -1;
        }
        offsets->mm_struct_env_start_offset = mm_struct_members.offset;

        if (btf_get_struct_1depth_members(&btf, (uint32_t)mm_type_id, "env_end", &mm_struct_members) != 0) {
            tools_loge("env_end not found\n");
            return -1;
        }
        offsets->mm_struct_env_end_offset = mm_struct_members.offset;
    }

    btf_free(&btf);
    tools_logi("BTF struct offsets extraction completed\n");
    return 0;
}

int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     bool root_key, const char **additional, extra_config_t *extra_configs, int extra_config_num)
{
    set_log_enable(true);

    if (!kpimg_path) tools_loge_exit("empty kpimg\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey) tools_loge_exit("empty superkey\n");

    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    if (kernel_file.is_uncompressed_img) tools_logw("kernel image with UNCOMPRESSED_IMG header\n");

    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, &pimg);
    if (rc) tools_loge_exit("parse kernel image error\n");
    // print_image_patch_info(&pimg);

    // kimg base info
    kernel_info_t *kinfo = &pimg.kinfo;
    int align_kernel_size = align_ceil(kinfo->kernel_size, SZ_4K);

    // kimg kallsym
    char *kallsym_kimg = (char *)malloc(pimg.ori_kimg_len);
    memcpy(kallsym_kimg, pimg.kimg, pimg.ori_kimg_len);
    kallsym_t kallsym = { 0 };

    if (kernel_if_need_patch(&kallsym, kallsym_kimg ,pimg.ori_kimg_len))disable_pi_map(kernel_file.kimg, kernel_file.kimg_len);
    
    if (analyze_kallsym_info(&kallsym, kallsym_kimg, pimg.ori_kimg_len, ARM64, 1)) {
        tools_loge_exit("analyze_kallsym_info error\n");
    }

    // kpimg
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file_align(kpimg_path, &kpimg, &kpimg_len, 0x10);

    // extra
    int extra_size = 0;
    int extra_num = 0;

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        if (config->is_path && config->extra_type == EXTRA_TYPE_NONE) {
            tools_loge_exit("extra type none\n");
        }
        if (config->set_event && strnlen(config->set_event, EXTRA_EVENT_LEN) >= EXTRA_EVENT_LEN) {
            tools_loge_exit("extra event too long: %s\n", config->set_event);
        }
        if (config->set_name && strnlen(config->set_name, EXTRA_NAME_LEN) >= EXTRA_NAME_LEN) {
            tools_loge_exit("extra name too long: %s\n", config->set_event);
        }

        patch_extra_item_t *item = NULL;
        if (config->is_path) {
            // todo: free
            item = (patch_extra_item_t *)malloc(sizeof(patch_extra_item_t));
            memset(item, 0, sizeof(patch_extra_item_t));
            const char *path = config->path;
            char *data;
            int len = 0;
            read_file_align(path, &data, &len, EXTRA_ALIGN);
            config->data = data;
            item->con_size = len;
            // if name not set
            if (!config->set_name) {
                if (config->extra_type == EXTRA_TYPE_KPM) {
                    kpm_info_t kpm_info = { 0 };
                    int rc = get_kpm_info(data, len, &kpm_info);
                    if (rc) tools_loge_exit("can get infomation of kpm, path: %s\n", path);
                    strcpy(item->name, kpm_info.name);
                } else {
                    char *rsp = strrchr(path, '/');
                    strncpy(item->name, rsp ? rsp + 1 : path, EXTRA_NAME_LEN - 1);
                }
            }
        } else {
            const char *name = config->name;
            for (int j = 0; j < pimg.embed_item_num; j++) {
                item = pimg.embed_item[j];
                if (strcmp(name, item->name)) continue;
                if (is_be() ^ kinfo->is_be) {
                    item->type = i32swp(item->type);
                    item->priority = i32swp(item->priority);
                    item->con_size = i32swp(item->con_size);
                    item->args_size = i32swp(item->args_size);
                }
                if (!config->set_args && item->args_size > 0) {
                    config->set_args = (char *)item + sizeof(*item);
                }
                config->extra_type = item->type;
                config->data = (char *)item + sizeof(*item) + item->args_size;
                break;
            }
        }
        if (!item) tools_loge_exit("empty extra item\n");
        strcpy(item->magic, EXTRA_HDR_MAGIC);
        config->item = item;
        item->type = config->extra_type;
        if (config->set_args) item->args_size = align_ceil(strlen(config->set_args), EXTRA_ALIGN);
        if (config->set_name) strcpy(item->name, config->set_name);
        if (config->set_event) strcpy(item->event, config->set_event);
        if (config->priority) item->priority = config->priority;
    }

    qsort(extra_configs, extra_config_num, sizeof(extra_config_t), extra_compare);

    extra_size += sizeof(patch_extra_item_t); // ending with empty item

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        extra_num++;
        extra_size += sizeof(patch_extra_item_t);
        extra_size += config->item->args_size;
        extra_size += config->item->con_size;
    }

    // copy to out image
    int ori_kimg_len = pimg.ori_kimg_len;
    int align_kimg_len = align_ceil(ori_kimg_len, SZ_4K);
    int out_img_len = align_kimg_len + kpimg_len;
    int out_all_len = out_img_len + extra_size;

    int start_offset = align_kernel_size;
    if (out_all_len > start_offset) {
        start_offset = align_ceil(out_all_len, SZ_4K);
        tools_logi("patch overlap, move start from 0x%x to 0x%x\n", align_kernel_size, start_offset);
    }
    tools_logi("layout kimg: 0x0,0x%x, kpimg: 0x%x,0x%x, extra: 0x%x,0x%x, end: 0x%x, start: 0x%x\n", ori_kimg_len,
               align_kimg_len, kpimg_len, out_img_len, extra_size, out_all_len, start_offset);

    kernel_file_t out_kernel_file;
    new_kernel_file(&out_kernel_file, &kernel_file, out_all_len, (bool)(is_be() ^ kinfo->is_be));
    memcpy(out_kernel_file.kimg, pimg.kimg, ori_kimg_len);
    memset(out_kernel_file.kimg + ori_kimg_len, 0, align_kimg_len - ori_kimg_len);
    memcpy(out_kernel_file.kimg + align_kimg_len, kpimg, kpimg_len);

    // set preset
    preset_t *preset = (preset_t *)(out_kernel_file.kimg + align_kimg_len);

    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;
    tools_logi("kpimg version: %x\n", ver_num);
    tools_logi("kpimg compile time: %s\n", header->compile_time);
    tools_logi("kpimg config: %s, %s\n", is_android ? "android" : "linux", is_debug ? "debug" : "release");

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(preset->setup));

    setup->kernel_version.major = kallsym.version.major;
    setup->kernel_version.minor = kallsym.version.minor;
    setup->kernel_version.patch = kallsym.version.patch;
    setup->kimg_size = ori_kimg_len;
    setup->kpimg_size = kpimg_len;

    setup->kernel_size = kinfo->kernel_size;
    setup->page_shift = kinfo->page_shift;
    setup->setup_offset = align_kimg_len;
    setup->start_offset = start_offset;
    setup->extra_size = extra_size;

    int map_start, map_max_size;
    select_map_area(&kallsym, kallsym_kimg, &map_start, &map_max_size);
    setup->map_offset = map_start;
    setup->map_max_size = map_max_size;
    tools_logi("map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    // 将kallsym_kimg中被NOP修改的部分同步到输出文件
    // select_map_area在max_size*2范围内修改了PAC指令，需要同步这些修改
    int tcp_init_sock_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "tcp_init_sock");
    int sync_start = tcp_init_sock_offset;
    int sync_size = map_max_size * 2;  // 覆盖可能被修改的最大范围
    if (sync_start + sync_size > ori_kimg_len) {
        sync_size = ori_kimg_len - sync_start;
    }
    if (sync_size > 0) {
        memcpy(out_kernel_file.kimg + sync_start, kallsym_kimg + sync_start, sync_size);
        tools_logi("Synced NOP modifications from kallsym_kimg to output file (offset: 0x%x, size: 0x%x)\n", 
                   sync_start, sync_size);
    }

    setup->kallsyms_lookup_name_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "kallsyms_lookup_name");

    setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "printk");
    if (!setup->printk_offset) setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_printk");
    if (!setup->printk_offset) tools_loge_exit("no symbol printk\n");

    if ((is_be() ^ kinfo->is_be)) {
        setup->kimg_size = i64swp(setup->kimg_size);
        setup->kernel_size = i64swp(setup->kernel_size);
        setup->page_shift = i64swp(setup->page_shift);
        setup->setup_offset = i64swp(setup->setup_offset);
        setup->start_offset = i64swp(setup->start_offset);
        setup->extra_size = i64swp(setup->extra_size);
        setup->map_offset = i64swp(setup->map_offset);
        setup->map_max_size = i64swp(setup->map_max_size);
        setup->kallsyms_lookup_name_offset = i64swp(setup->kallsyms_lookup_name_offset);
        setup->paging_init_offset = i64swp(setup->paging_init_offset);
        setup->printk_offset = i64swp(setup->printk_offset);
    }

    // map symbol
    fillin_map_symbol(&kallsym, kallsym_kimg, &setup->map_symbol, kinfo->is_be);

    // header backup
    memcpy(setup->header_backup, kallsym_kimg, sizeof(setup->header_backup));

    // start symbol
    fillin_patch_config(&kallsym, kallsym_kimg, ori_kimg_len, &setup->patch_config, kinfo->is_be, 0);

    // 从BTF提取结构体偏移量
    if (extract_struct_offsets_from_btf(kernel_file.kimg, kernel_file.kimg_len, &setup->struct_offsets) != 0) {
        tools_loge_exit("Failed to extract struct offsets from BTF. BTF is required for this branch.\n");
    }

    // 字节序转换（如果需要）
    if ((is_be() ^ kinfo->is_be)) {
        // struct_offsets中的所有int32_t字段需要字节序转换
        // 遍历struct_offsets_t中的所有int32_t字段进行字节序转换
        int32_t *fields = (int32_t *)&setup->struct_offsets;
        size_t field_count = STRUCT_OFFSETS_LEN / sizeof(int32_t);
        for (size_t i = 0; i < field_count; i++) {
            fields[i] = i32swp(fields[i]);
        }
    }

    // superkey
    if (!root_key) {
        tools_logi("superkey: %s\n", superkey);
        strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    } else {
        int len = SHA256_BLOCK_SIZE > ROOT_SUPER_KEY_HASH_LEN ? ROOT_SUPER_KEY_HASH_LEN : SHA256_BLOCK_SIZE;
        BYTE buf[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));
        sha256_final(&ctx, buf);
        memcpy(setup->root_superkey, buf, len);
        char *hexstr = bytes_to_hexstr(setup->root_superkey, len);
        tools_logi("root superkey hash: %s\n", hexstr);
        free(hexstr);
    }

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "paging_init");

    uint32_t nop_insn = 0xD503201F;
    for (uint32_t i = 0; i < 0x500; i += sizeof(uint32_t)) {
        uint32_t insn = *(uint32_t *)(kallsym_kimg + paging_init_offset + i);
        if ((insn & 0xFFFFFD1F) == 0xD503211F) {
            //*(uint32_t *)(kallsym_kimg + paging_init_offset + i) = 0xD503201F;
            memcpy(out_kernel_file.kimg + paging_init_offset + i, &nop_insn, sizeof(uint32_t));
            tools_logi("ori insn: %08x at %08x\n", insn, paging_init_offset + i);
        }
        if (insn == 0xD65F03C0) {
           break;//RET
        }
    }

    setup->paging_init_offset = relo_branch_func(kallsym_kimg, paging_init_offset);
    int text_offset = align_kimg_len + SZ_4K;
    b((uint32_t *)(out_kernel_file.kimg + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset, text_offset);

    // additional [len key=value] set
    char *addition_pos = setup->additional;
    for (int i = 0;; i++) {
        const char *kv = additional[i];
        if (!kv) break;
        if (!strchr(kv, '=')) tools_loge_exit("addition must be format of key=value\n");

        int kvlen = strlen(kv);
        if (kvlen > 127) tools_loge_exit("addition %s too long\n", kv);
        if (addition_pos + kvlen + 1 > setup->additional + ADDITIONAL_LEN) tools_loge_exit("no memory for addition\n");

        *addition_pos = (char)kvlen;
        addition_pos++;

        tools_logi("adding addition: %s\n", kv);
        strcpy(addition_pos, kv);
        addition_pos += kvlen;
    }

    // append extra
    int current_offset = out_img_len;
    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        patch_extra_item_t *item = config->item;
        const char *type = extra_type_str(item->type);
        tools_logi("embedding %s, name: %s, priority: %d, event: %s, args: %s, size: 0x%x+0x%x+0x%x\n", type,
                   item->name, item->priority, item->event, config->set_args ?: "", (int)sizeof(*item), item->args_size,
                   item->con_size);

        int args_len = item->args_size;
        int con_len = item->con_size;

        if (is_be() ^ kinfo->is_be) {
            item->type = i32swp(item->type);
            item->priority = i32swp(item->priority);
            item->con_size = i32swp(item->con_size);
            item->args_size = i32swp(item->args_size);
        }

        extra_append(out_kernel_file.kimg, (void *)item, sizeof(*item), &current_offset);
        if (args_len > 0) extra_append(out_kernel_file.kimg, (void *)config->set_args, args_len, &current_offset);
        extra_append(out_kernel_file.kimg, (void *)config->data, con_len, &current_offset);
    }

    // guard extra
    patch_extra_item_t empty_item = { 0 };
    extra_append(out_kernel_file.kimg, (void *)&empty_item, sizeof(empty_item), &current_offset);

    write_kernel_file(&out_kernel_file, out_path);

    // free
    free(kallsym_kimg);
    free(kpimg);
    free_kernel_file(&out_kernel_file);
    free_kernel_file(&kernel_file);

    tools_logi("patch done: %s\n", out_path);

    set_log_enable(false);
    return 0;
}

int unpatch_img(const char *kimg_path, const char *out_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    // todo: check whether the endian is different or not
    memcpy(kernel_file.kimg, preset->setup.header_backup, sizeof(preset->setup.header_backup));
    int kimg_size = preset->setup.kimg_size ?: ((char *)preset - kernel_file.kimg);
    update_kernel_file_img_len(&kernel_file, kimg_size, false);

    write_kernel_file(&kernel_file, out_path);
    free_kernel_file(&kernel_file);
    return 0;
}

int reset_key(const char *kimg_path, const char *out_path, const char *superkey)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey) tools_loge_exit("empty superkey\n");

    if (strlen(superkey) <= 0) tools_loge_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_loge_exit("too long superkey\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    char *origin_key = strdup((char *)preset->setup.superkey);
    strcpy((char *)preset->setup.superkey, superkey);
    tools_logi("reset superkey: %s -> %s\n", origin_key, preset->setup.superkey);

    write_kernel_file(&kernel_file, out_path);

    free(origin_key);
    free_kernel_file(&kernel_file);

    return 0;
}

int dump_kallsym(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);
    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, kernel_file.kimg, kernel_file.kimg_len, ARM64, 1)) {
        fprintf(stdout, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, kernel_file.kimg);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
int dump_ikconfig(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);
    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    
    dump_all_ikconfig(kernel_file.kimg,kernel_file.kimg_len);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}