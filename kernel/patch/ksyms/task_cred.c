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
#include <stdint.h>
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
 
    int32_t offset;
    //cred
    {
        offset = btf_get_member_offset("cred", "usage");
        logkd("cred.usage offset: %x\n", offset);
        cred_offset.usage_offset = offset;
        offset = btf_get_member_offset("cred", "subscribers");
        logkd("cred.subscribers offset: %x\n", offset);
        cred_offset.subscribers_offset = offset;
        offset = btf_get_member_offset("cred", "magic");
        logkd("cred.magic offset: %x\n", offset);
        cred_offset.magic_offset = offset;
        offset = btf_get_member_offset("cred", "uid");
        logkd("cred.uid offset: %x\n", offset);
        cred_offset.uid_offset = offset;
        offset = btf_get_member_offset("cred", "gid");
        logkd("cred.gid offset: %x\n", offset);
        cred_offset.gid_offset = offset;
        offset = btf_get_member_offset("cred", "suid");
        logkd("cred.suid offset: %x\n", offset);
        cred_offset.suid_offset = offset;
        offset = btf_get_member_offset("cred", "sgid");
        logkd("cred.sgid offset: %x\n", offset);
        cred_offset.sgid_offset = offset;
        offset = btf_get_member_offset("cred", "euid");
        logkd("cred.euid offset: %x\n", offset);
        cred_offset.euid_offset = offset;
        offset = btf_get_member_offset("cred", "egid");
        logkd("cred.egid offset: %x\n", offset);
        cred_offset.egid_offset = offset;
        offset = btf_get_member_offset("cred", "fsuid");
        logkd("cred.fsuid offset: %x\n", offset);
        cred_offset.fsuid_offset = offset;
        offset = btf_get_member_offset("cred", "fsgid");
        logkd("cred.fsgid offset: %x\n", offset);
        cred_offset.fsgid_offset = offset;
        offset = btf_get_member_offset("cred", "securebits");
        logkd("cred.securebits offset: %x\n", offset);
        cred_offset.securebits_offset = offset;
        offset = btf_get_member_offset("cred", "cap_inheritable");
        logkd("cred.cap_inheritable offset: %x\n", offset);
        cred_offset.cap_inheritable_offset = offset;
        offset = btf_get_member_offset("cred", "cap_permitted");
        logkd("cred.cap_permitted offset: %x\n", offset);
        cred_offset.cap_permitted_offset = offset;
        offset = btf_get_member_offset("cred", "cap_effective");
        logkd("cred.cap_effective offset: %x\n", offset);
        cred_offset.cap_effective_offset = offset;
        offset = btf_get_member_offset("cred", "cap_bset");
        logkd("cred.cap_bset offset: %x\n", offset);
        cred_offset.cap_bset_offset = offset;
        offset = btf_get_member_offset("cred", "cap_ambient");
        logkd("cred.cap_ambient offset: %x\n", offset);
        cred_offset.cap_ambient_offset = offset;
        offset = btf_get_member_offset("cred", "user");
        logkd("cred.user offset: %x\n", offset);
        cred_offset.user_offset = offset;
        offset = btf_get_member_offset("cred", "user_ns");
        logkd("cred.user_ns offset: %x\n", offset);
        cred_offset.user_ns_offset = offset;
        offset = btf_get_member_offset("cred", "ucounts");
        logkd("cred.ucounts offset: %x\n", offset);
        cred_offset.ucounts_offset = offset;
        offset = btf_get_member_offset("cred", "group_info");
        logkd("cred.group_info offset: %x\n", offset);
        cred_offset.group_info_offset = offset;
        offset = btf_get_member_offset("cred", "session_keyring");
        logkd("cred.session_keyring offset: %x\n", offset);
        cred_offset.session_keyring_offset = offset;
        offset = btf_get_member_offset("cred", "process_keyring");
        logkd("cred.process_keyring offset: %x\n", offset);
        cred_offset.process_keyring_offset = offset;
        offset = btf_get_member_offset("cred", "thread_keyring");
        logkd("cred.thread_keyring offset: %x\n", offset);
        cred_offset.thread_keyring_offset = offset;
        offset = btf_get_member_offset("cred", "request_key_auth");
        logkd("cred.request_key_auth offset: %x\n", offset);
        cred_offset.request_key_auth_offset = offset;
        offset = btf_get_member_offset("cred", "security");
        logkd("cred.security offset: %x\n", offset);
        cred_offset.security_offset = offset;
        offset = btf_get_member_offset("cred", "rcu");
        logkd("cred.rcu offset: %x\n", offset);
        cred_offset.rcu_offset = offset;
    }
 

    return 0;
}


int resolve_task_offset()
{
    log_boot("struct task_struct: using BTF offsets\n");

    int32_t offset;
    //task_struct
    {
        offset = btf_get_member_offset("task_struct", "pid");
        logkd("task_struct.pid offset: %x\n", offset);
        task_struct_offset.pid_offset = offset;
        offset = btf_get_member_offset("task_struct", "tgid");
        logkd("task_struct.tgid offset: %x\n", offset);
        task_struct_offset.tgid_offset = offset;
        offset = btf_get_member_offset("task_struct", "thread_pid");
        logkd("task_struct.thread_pid offset: %x\n", offset);
        task_struct_offset.thread_pid_offset = offset;
        offset = btf_get_member_offset("task_struct", "ptracer_cred");
        logkd("task_struct.ptracer_cred offset: %x\n", offset);
        task_struct_offset.ptracer_cred_offset = offset;
        offset = btf_get_member_offset("task_struct", "real_cred");
        logkd("task_struct.real_cred offset: %x\n", offset);
        task_struct_offset.real_cred_offset = offset;
        offset = btf_get_member_offset("task_struct", "cred");
        logkd("task_struct.cred offset: %x\n", offset);
        task_struct_offset.cred_offset = offset;
        offset = btf_get_member_offset("task_struct", "fs");
        logkd("task_struct.fs offset: %x\n", offset);
        task_struct_offset.fs_offset = offset;
        offset = btf_get_member_offset("task_struct", "files");
        logkd("task_struct.files offset: %x\n", offset);
        task_struct_offset.files_offset = offset;
        offset = btf_get_member_offset("task_struct", "loginuid");
        logkd("task_struct.loginuid offset: %x\n", offset);
        task_struct_offset.loginuid_offset = offset;
        offset = btf_get_member_offset("task_struct", "sessionid");
        logkd("task_struct.sessionid offset: %x\n", offset);
        task_struct_offset.sessionid_offset = offset;
        offset = btf_get_member_offset("task_struct", "comm");
        logkd("task_struct.comm offset: %x\n", offset);
        task_struct_offset.comm_offset = offset;
        offset = btf_get_member_offset("task_struct", "seccomp");
        logkd("task_struct.seccomp offset: %x\n", offset);
        task_struct_offset.seccomp_offset = offset;
        offset = btf_get_member_offset("task_struct", "security");
        logkd("task_struct.security offset: %x\n", offset);
        task_struct_offset.security_offset = offset;
        offset = btf_get_member_offset("task_struct", "stack");
        logkd("task_struct.stack offset: %x\n", offset);
        task_struct_offset.stack_offset = offset;
        offset = btf_get_member_offset("task_struct", "tasks");
        logkd("task_struct.tasks offset: %x\n", offset);
        task_struct_offset.tasks_offset = offset;
        offset = btf_get_member_offset("task_struct", "mm");
        logkd("task_struct.mm offset: %x\n", offset);
        task_struct_offset.mm_offset = offset;
        offset = btf_get_member_offset("task_struct", "active_mm");
        logkd("task_struct.active_mm offset: %x\n", offset);
        task_struct_offset.active_mm_offset = offset;
    }

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

    stack_in_task_offset = task_struct_offset.stack_offset;

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

    int32_t offset;
    //mm_struct
    {
        offset = btf_get_member_offset("mm_struct", "mmap_base");
        logkd("mm_struct.mmap_base offset: %x\n", offset);
        mm_struct_offset.mmap_base_offset = offset;
        offset = btf_get_member_offset("mm_struct", "task_size");
        logkd("mm_struct.task_size offset: %x\n", offset);
        mm_struct_offset.task_size_offset = offset;
        offset = btf_get_member_offset("mm_struct", "pgd");
        logkd("mm_struct.pgd offset: %x\n", offset);
        mm_struct_offset.pgd_offset = offset;
        offset = btf_get_member_offset("mm_struct", "map_count");
        logkd("mm_struct.map_count offset: %x\n", offset);
        mm_struct_offset.map_count_offset = offset;
        offset = btf_get_member_offset("mm_struct", "total_vm");
        logkd("mm_struct.total_vm offset: %x\n", offset);
        mm_struct_offset.total_vm_offset = offset;
        offset = btf_get_member_offset("mm_struct", "locked_vm");
        logkd("mm_struct.locked_vm offset: %x\n", offset);
        mm_struct_offset.locked_vm_offset = offset;
        offset = btf_get_member_offset("mm_struct", "pinned_vm");
        logkd("mm_struct.pinned_vm offset: %x\n", offset);
        mm_struct_offset.pinned_vm_offset = offset;
        offset = btf_get_member_offset("mm_struct", "data_vm");
        logkd("mm_struct.data_vm offset: %x\n", offset);
        mm_struct_offset.data_vm_offset = offset;
        offset = btf_get_member_offset("mm_struct", "exec_vm");
        logkd("mm_struct.exec_vm offset: %x\n", offset);
        mm_struct_offset.exec_vm_offset = offset;
        offset = btf_get_member_offset("mm_struct", "stack_vm");
        logkd("mm_struct.stack_vm offset: %x\n", offset);
        mm_struct_offset.stack_vm_offset = offset;
        offset = btf_get_member_offset("mm_struct", "start_code");
        logkd("mm_struct.start_code offset: %x\n", offset);
        mm_struct_offset.start_code_offset = offset;
        offset = btf_get_member_offset("mm_struct", "end_code");
        logkd("mm_struct.end_code offset: %x\n", offset);
        mm_struct_offset.end_code_offset = offset;
        offset = btf_get_member_offset("mm_struct", "start_data");
        logkd("mm_struct.start_data offset: %x\n", offset);
        mm_struct_offset.start_data_offset = offset;
        offset = btf_get_member_offset("mm_struct", "end_data");
        logkd("mm_struct.end_data offset: %x\n", offset);
        mm_struct_offset.end_data_offset = offset;
        offset = btf_get_member_offset("mm_struct", "start_brk");
        logkd("mm_struct.start_brk offset: %x\n", offset);
        mm_struct_offset.start_brk_offset = offset;
        offset = btf_get_member_offset("mm_struct", "brk");
        logkd("mm_struct.brk offset: %x\n", offset);
        mm_struct_offset.brk_offset = offset;
        offset = btf_get_member_offset("mm_struct", "start_stack");
        logkd("mm_struct.start_stack offset: %x\n", offset);
        mm_struct_offset.start_stack_offset = offset;
        offset = btf_get_member_offset("mm_struct", "arg_start");
        logkd("mm_struct.arg_start offset: %x\n", offset);
        mm_struct_offset.arg_start_offset = offset;
        offset = btf_get_member_offset("mm_struct", "arg_end");
        logkd("mm_struct.arg_end offset: %x\n", offset);
        mm_struct_offset.arg_end_offset = offset;
        offset = btf_get_member_offset("mm_struct", "env_start");
        logkd("mm_struct.env_start offset: %x\n", offset);
        mm_struct_offset.env_start_offset = offset;
        offset = btf_get_member_offset("mm_struct", "env_end");
        mm_struct_offset.env_end_offset = offset;
        logkd("mm_struct.env_end offset: %x\n", offset);
    }
    return 0;
}



int resolve_struct()
{
    full_cap = CAP_FULL_SET;

    int err = 0;

    if (resolve_struct_with_btf_hash() != 0) {
        logke("resolve_struct_with_btf_hash failed\n");
        goto out;
    }
//    btf_dump_struct_hash();

    resolve_current();

    resolve_task_offset();

    resolve_cred_offset();

    resolve_mm_struct_offset();


out:
    return err;
}
