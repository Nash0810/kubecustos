//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define ARGS_BUF_SIZE 4096
#define MAX_ARG_SIZE 256
#define MAX_ARGS 16

struct event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char args_buf[ARGS_BUF_SIZE];
    int args_count;
    u64 cgroup_id; // capture kernel cgroup inode id
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    struct task_struct *task;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    /* Do not call memset helpers (toolchain portability). Instead initialize
       only the fields we will rely on. This avoids implicit/unsupported helper calls. */

    e->pid = 0;
    e->ppid = 0;
    e->comm[0] = '\0';
    e->args_buf[0] = '\0';
    e->args_count = 0;
    e->cgroup_id = 0;

    e->pid = pid;
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* Safe read of comm: bpf_get_current_comm writes null-terminated string */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Save cgroup id for userspace pod resolution (stable across short-lived PIDs) */
    e->cgroup_id = bpf_get_current_cgroup_id();

    /* Read argv[0] */
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->args_buf[0], MAX_ARG_SIZE, filename);
    e->args_count = 1;

    const void *argv_base = (const void *)ctx->args[1];
    const char *argp = NULL;

    #pragma unroll
    for (int i = 1; i < MAX_ARGS; i++) {
        unsigned int offset = i * MAX_ARG_SIZE;
        if (offset >= ARGS_BUF_SIZE)
            break;

        bpf_probe_read_user(&argp, sizeof(argp),
                            (void *)(argv_base + (i * sizeof(char *))));
        if (!argp)
            break;

        bpf_probe_read_user_str(&e->args_buf[offset], MAX_ARG_SIZE, argp);
        e->args_count++;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
