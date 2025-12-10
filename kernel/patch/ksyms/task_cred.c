/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <stdbool.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/vmalloc.h>
#include <baselib.h>
#include <linux/pid.h>
#include <asm/current.h>
#include <linux/security.h>
#include <syscall.h>
#include <uapi/linux/prctl.h>
#include <uapi/linux/magic.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <linux/sched/mm.h>
#include <ksyms.h>
#include <pgtable.h>
#include <symbol.h>
#include <linux/mm_types.h>
#include <asm/processor.h>
#include <predata.h>

#include "struct_hash.h"
#define TASK_COMM_LEN 16



#define TASK_STRUCT_MAX_SIZE 0x1800
#define THREAD_INFO_MAX_SIZE 0x90
#define CRED_MAX_SIZE 0x100
#define MM_STRUCT_MAX_SIZE 0xb0

struct mm_struct_offset mm_struct_offset = {
    .mmap_base_offset = -1,
    .task_size_offset = -1,
    .pgd_offset = -1,
    .map_count_offset = -1,
    .total_vm_offset = -1,
    .locked_vm_offset = -1,
    .pinned_vm_offset = -1,
    .data_vm_offset = -1,
    .exec_vm_offset = -1,
    .stack_vm_offset = -1,
    .start_code_offset = -1,
    .end_code_offset = -1,
    .start_data_offset = -1,
    .end_data_offset = -1,
    .start_brk_offset = -1,
    .brk_offset = -1,
    .start_stack_offset = -1,
    .arg_start_offset = -1,
    .arg_end_offset = -1,
    .env_start_offset = -1,
    .env_end_offset = -1,
};
KP_EXPORT_SYMBOL(mm_struct_offset);

struct task_struct_offset task_struct_offset = {
    .pid_offset = -1,
    .tgid_offset = -1,
    .thread_pid_offset = -1,
    .ptracer_cred_offset = -1,
    .real_cred_offset = -1,
    .cred_offset = -1,
    .fs_offset = -1,
    .files_offset = -1,
    .loginuid_offset = -1,
    .sessionid_offset = -1,
    .comm_offset = -1,
    .seccomp_offset = -1,
    .security_offset = -1,
    .stack_offset = -1,
    .tasks_offset = -1,
    .mm_offset = -1,
    .active_mm_offset = -1,
};
KP_EXPORT_SYMBOL(task_struct_offset);

struct cred_offset cred_offset = {
    .usage_offset = -1,
    .subscribers_offset = -1,
    .magic_offset = -1,
    .uid_offset = -1,
    .gid_offset = -1,
    .suid_offset = -1,
    .sgid_offset = -1,
    .euid_offset = -1,
    .egid_offset = -1,
    .fsuid_offset = -1,
    .fsgid_offset = -1,
    .securebits_offset = -1,
    .cap_inheritable_offset = -1,
    .cap_permitted_offset = -1,
    .cap_effective_offset = -1,
    .cap_bset_offset = -1,
    .cap_ambient_offset = -1,

    .user_offset = -1,
    .user_ns_offset = -1,
    .ucounts_offset = -1,
    .group_info_offset = -1,

    .session_keyring_offset = -1,
    .process_keyring_offset = -1,
    .thread_keyring_offset = -1,
    .request_key_auth_offset = -1,

    .security_offset = -1,

    .rcu_offset = -1,
};
KP_EXPORT_SYMBOL(cred_offset);

struct task_struct *init_task = 0;
const struct cred *init_cred = 0;
const struct mm_struct *init_mm = 0;

int thread_size = 0;
KP_EXPORT_SYMBOL(thread_size);

// int thread_info_in_task = 0;
// KP_EXPORT_SYMBOL(thread_info_in_task);

// int sp_el0_is_current = 0;
// KP_EXPORT_SYMBOL(sp_el0_is_current);

// int sp_el0_is_thread_info = 0;
// KP_EXPORT_SYMBOL(sp_el0_is_thread_info);

// int task_in_thread_info_offset = -1;
// KP_EXPORT_SYMBOL(task_in_thread_info_offset);

int stack_in_task_offset = -1;
KP_EXPORT_SYMBOL(stack_in_task_offset);

// int stack_end_offset = 0x90;
// KP_EXPORT_SYMBOL(stack_end_offset);



int resolve_cred_offset()
{
    log_boot("struct cred: using BTF offsets\n");

    if (!struct_offsets_config) {
        logke("struct_offsets_config not initialized\n");
        return -1;
    }

    // 直接从BTF配置中复制偏移量
    cred_offset.usage_offset = struct_offsets_config->cred_usage_offset;
    cred_offset.subscribers_offset = struct_offsets_config->cred_subscribers_offset;
    cred_offset.magic_offset = struct_offsets_config->cred_magic_offset;
    cred_offset.uid_offset = struct_offsets_config->cred_uid_offset;
    cred_offset.gid_offset = struct_offsets_config->cred_gid_offset;
    cred_offset.suid_offset = struct_offsets_config->cred_suid_offset;
    cred_offset.sgid_offset = struct_offsets_config->cred_sgid_offset;
    cred_offset.euid_offset = struct_offsets_config->cred_euid_offset;
    cred_offset.egid_offset = struct_offsets_config->cred_egid_offset;
    cred_offset.fsuid_offset = struct_offsets_config->cred_fsuid_offset;
    cred_offset.fsgid_offset = struct_offsets_config->cred_fsgid_offset;
    cred_offset.securebits_offset = struct_offsets_config->cred_securebits_offset;
    cred_offset.cap_inheritable_offset = struct_offsets_config->cred_cap_inheritable_offset;
    cred_offset.cap_permitted_offset = struct_offsets_config->cred_cap_permitted_offset;
    cred_offset.cap_effective_offset = struct_offsets_config->cred_cap_effective_offset;
    cred_offset.cap_bset_offset = struct_offsets_config->cred_cap_bset_offset;
    cred_offset.cap_ambient_offset = struct_offsets_config->cred_cap_ambient_offset;
    cred_offset.user_offset = struct_offsets_config->cred_user_offset;
    cred_offset.user_ns_offset = struct_offsets_config->cred_user_ns_offset;
    cred_offset.ucounts_offset = struct_offsets_config->cred_ucounts_offset;
    cred_offset.group_info_offset = struct_offsets_config->cred_group_info_offset;
    cred_offset.session_keyring_offset = struct_offsets_config->cred_session_keyring_offset;
    cred_offset.process_keyring_offset = struct_offsets_config->cred_process_keyring_offset;
    cred_offset.thread_keyring_offset = struct_offsets_config->cred_thread_keyring_offset;
    cred_offset.request_key_auth_offset = struct_offsets_config->cred_request_key_auth_offset;
    cred_offset.security_offset = struct_offsets_config->cred_security_offset;
    cred_offset.rcu_offset = struct_offsets_config->cred_rcu_offset;

    log_boot("    uid offset: %x\n", cred_offset.uid_offset);
    log_boot("    euid offset: %x\n", cred_offset.euid_offset);
    log_boot("    gid offset: %x\n", cred_offset.gid_offset);
    log_boot("    egid offset: %x\n", cred_offset.egid_offset);
    log_boot("    cap_effective offset: %x\n", cred_offset.cap_effective_offset);
    log_boot("    cap_permitted offset: %x\n", cred_offset.cap_permitted_offset);
    log_boot("    cap_inheritable offset: %x\n", cred_offset.cap_inheritable_offset);

    return 0;
}

static int find_swapper_comm_offset(uint64_t start, int size)
{
    if (!is_kimg_range(start) || !is_kimg_range(start + size)) return -1;
    char swapper_comm[TASK_COMM_LEN] = "swapper";
    char swapper_comm_1[TASK_COMM_LEN] = "swapper/0";
    for (uint64_t i = start; i < start + size; i += sizeof(uint32_t)) {
        if (!lib_strcmp(swapper_comm, (char *)i) || !lib_strcmp(swapper_comm_1, (char *)i)) {
            return i - start;
        }
    }
    return -1;
}

int resolve_task_offset()
{
    log_boot("struct task_struct: using BTF offsets\n");

    if (!struct_offsets_config) {
        logke("struct_offsets_config not initialized\n");
        return -1;
    }

    // 直接从BTF配置中复制偏移量
    task_struct_offset.pid_offset = struct_offsets_config->task_struct_pid_offset;
    task_struct_offset.tgid_offset = struct_offsets_config->task_struct_tgid_offset;
    task_struct_offset.thread_pid_offset = struct_offsets_config->task_struct_thread_pid_offset;
    task_struct_offset.ptracer_cred_offset = struct_offsets_config->task_struct_ptracer_cred_offset;
    task_struct_offset.real_cred_offset = struct_offsets_config->task_struct_real_cred_offset;
    task_struct_offset.cred_offset = struct_offsets_config->task_struct_cred_offset;
    task_struct_offset.fs_offset = struct_offsets_config->task_struct_fs_offset;
    task_struct_offset.files_offset = struct_offsets_config->task_struct_files_offset;
    task_struct_offset.loginuid_offset = struct_offsets_config->task_struct_loginuid_offset;
    task_struct_offset.sessionid_offset = struct_offsets_config->task_struct_sessionid_offset;
    task_struct_offset.comm_offset = struct_offsets_config->task_struct_comm_offset;
    task_struct_offset.seccomp_offset = struct_offsets_config->task_struct_seccomp_offset;
    task_struct_offset.security_offset = struct_offsets_config->task_struct_security_offset;
    task_struct_offset.stack_offset = struct_offsets_config->task_struct_stack_offset;
    task_struct_offset.tasks_offset = struct_offsets_config->task_struct_tasks_offset;
    task_struct_offset.mm_offset = struct_offsets_config->task_struct_mm_offset;
    task_struct_offset.active_mm_offset = struct_offsets_config->task_struct_active_mm_offset;

    log_boot("    cred offset: %x\n", task_struct_offset.cred_offset);
    log_boot("    real_cred offset: %x\n", task_struct_offset.real_cred_offset);
    log_boot("    pid offset: %x\n", task_struct_offset.pid_offset);
    log_boot("    comm offset: %x\n", task_struct_offset.comm_offset);

    return 0;
}

int resolve_current()
{
    log_boot("resolve_current\n");
/*
每个 task 的内核栈都是 THREAD_SIZE 大小并按 THREAD_SIZE 对齐，
我们拿到任意一个当前 task 的栈指针（sp）后，
就能依据对齐关系找到对应的栈底，再结合“栈结束哨兵”位置得出 THREAD_SIZE
*/
uint64_t sp_el0, sp;
asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
asm volatile("mov %0, sp" : "=r"(sp));

init_task = (struct task_struct *)kallsyms_lookup_name("init_task");

    if (!struct_offsets_config) {
        logke("struct_offsets_config not initialized in resolve_current\n");
        return -1;
    }

    stack_in_task_offset = struct_offsets_config->task_struct_stack_offset;



    // THREAD_SIZE and end_of_stack and CONFIG_THREAD_INFO_IN_TASK
    // don't worry, we use little stack until here
    int thread_shift_cand[] = { 14, 15, 16 };
    for (int i = 0; i < sizeof(thread_shift_cand) / sizeof(thread_shift_cand[0]); i++) {
        int tsz = 1 << thread_shift_cand[i];
        uint64_t sp_low = sp & ~(tsz - 1);
        // uint64_t sp_high = sp_low + tsz; // user_stack_pointer
        uint64_t psp = sp_low;
        for (; psp < sp_low + THREAD_INFO_MAX_SIZE; psp += sizeof(uint32_t)) {
            if (*(uint64_t *)psp == STACK_END_MAGIC) { //如果栈底是STACK_END_MAGIC，则认为栈底是正确的
                if (psp == sp_low) {
                    thread_size = tsz;
                }
                break;
            }
        }
        if (thread_size > 0) {
            //log_boot("    init stack end: %llx\n", psp);
            break;
        }
    }

    log_boot("    thread_size: %x\n", thread_size);
    log_boot("    stack_in_task_offset: %x\n", stack_in_task_offset);

    return 0;
}

int resolve_mm_struct_offset()
{
    log_boot("struct mm_struct: using BTF offsets\n");

    if (!struct_offsets_config) {
        logke("struct_offsets_config not initialized\n");
        return -1;
    }

    // 直接从BTF配置中复制偏移量
    mm_struct_offset.mmap_base_offset = struct_offsets_config->mm_struct_mmap_base_offset;
    mm_struct_offset.task_size_offset = struct_offsets_config->mm_struct_task_size_offset;
    mm_struct_offset.pgd_offset = struct_offsets_config->mm_struct_pgd_offset;
    mm_struct_offset.map_count_offset = struct_offsets_config->mm_struct_map_count_offset;
    mm_struct_offset.total_vm_offset = struct_offsets_config->mm_struct_total_vm_offset;
    mm_struct_offset.locked_vm_offset = struct_offsets_config->mm_struct_locked_vm_offset;
    mm_struct_offset.pinned_vm_offset = struct_offsets_config->mm_struct_pinned_vm_offset;
    mm_struct_offset.data_vm_offset = struct_offsets_config->mm_struct_data_vm_offset;
    mm_struct_offset.exec_vm_offset = struct_offsets_config->mm_struct_exec_vm_offset;
    mm_struct_offset.stack_vm_offset = struct_offsets_config->mm_struct_stack_vm_offset;
    mm_struct_offset.start_code_offset = struct_offsets_config->mm_struct_start_code_offset;
    mm_struct_offset.end_code_offset = struct_offsets_config->mm_struct_end_code_offset;
    mm_struct_offset.start_data_offset = struct_offsets_config->mm_struct_start_data_offset;
    mm_struct_offset.end_data_offset = struct_offsets_config->mm_struct_end_data_offset;
    mm_struct_offset.start_brk_offset = struct_offsets_config->mm_struct_start_brk_offset;
    mm_struct_offset.brk_offset = struct_offsets_config->mm_struct_brk_offset;
    mm_struct_offset.start_stack_offset = struct_offsets_config->mm_struct_start_stack_offset;
    mm_struct_offset.arg_start_offset = struct_offsets_config->mm_struct_arg_start_offset;
    mm_struct_offset.arg_end_offset = struct_offsets_config->mm_struct_arg_end_offset;
    mm_struct_offset.env_start_offset = struct_offsets_config->mm_struct_env_start_offset;
    mm_struct_offset.env_end_offset = struct_offsets_config->mm_struct_env_end_offset;

    log_boot("    pgd offset: %x\n", mm_struct_offset.pgd_offset);
    return 0;
}

int resolve_struct()
{
    full_cap = CAP_FULL_SET;

    int err = 0;

    if ((err = resolve_current())) goto out;

    if ((err = resolve_task_offset())) goto out;

    if ((err = resolve_cred_offset())) goto out;

    resolve_mm_struct_offset();

    if (resolve_struct_with_btf_hash() != 0) {
        logke("resolve_struct_with_btf_hash failed\n");
        goto out;
    }
    btf_dump_struct_hash();
out:
    return err;
}
