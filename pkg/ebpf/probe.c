//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define ARGS_BUF_SIZE 4096 
#define MAX_ARG_SIZE 256

struct event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char args_buf[ARGS_BUF_SIZE];
    int args_count;
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
    if (!e) {
        return 0;
    }

    e->pid = pid;
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    int ret;
    int offset = 0;
    
    // 1. Read the first argument (program name)
    const char *filename = (const char *)ctx->args[0];
    ret = bpf_probe_read_user_str(&e->args_buf[0], ARGS_BUF_SIZE, filename);
    if (ret <= 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    if (ret >= ARGS_BUF_SIZE) {
        ret = ARGS_BUF_SIZE - 1;
    }
    offset += ret;
    
    // Ensure offset is within bounds (verifier hint)
    if (offset >= ARGS_BUF_SIZE) {
        offset = ARGS_BUF_SIZE - 1;
    }
    
    e->args_count = 1;

    // 2. Read argv[]
    const char *argp;
    const void *argv_base = (const void *)ctx->args[1];
    
    #pragma unroll
    for (int i = 1; i < 10; i++) {
        if (offset >= ARGS_BUF_SIZE - MAX_ARG_SIZE - 2) {
            break; // Not enough space left
        }
        
        // Read pointer to i-th argument
        ret = bpf_probe_read_user(&argp, sizeof(argp),
                            (void *)(argv_base + (i * sizeof(char *))));
        if (ret != 0 || !argp) {
            break; // end of argv array or read failed
        }
        
        if (offset <= 0 || offset >= ARGS_BUF_SIZE) {
            break;
        }
        
        // Add space separator
        e->args_buf[offset - 1] = ' ';
        
        // Calculate remaining space with explicit bounds
        int remaining_size = ARGS_BUF_SIZE - offset;
        
        // Clamp remaining size to MAX_ARG_SIZE
        if (remaining_size > MAX_ARG_SIZE) {
            remaining_size = MAX_ARG_SIZE;
        }
        
        // Additional safety check
        if (remaining_size <= 0) {
            break;
        }
        
        // Read argument string
        ret = bpf_probe_read_user_str(&e->args_buf[offset],
                                      remaining_size, argp);
        if (ret <= 0) {
            break; // failed to read
        }
        
        if (ret > remaining_size) {
            ret = remaining_size;
        }
        
        e->args_count++;
        offset += ret;
        
        if (offset >= ARGS_BUF_SIZE) {
            offset = ARGS_BUF_SIZE - 1;
            break;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}