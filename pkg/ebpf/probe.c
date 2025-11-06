//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
// We need a larger buffer to hold all the arguments
#define ARGS_BUF_SIZE 4096 

struct event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char args_buf[ARGS_BUF_SIZE];
    // Add a field to store the *number* of arguments
    int args_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

// Helper function to read a single argument
static __inline int read_arg(struct trace_event_raw_sys_enter *ctx, int arg_index, char *buf, int buf_size) {
    const char *argp = NULL;
    // Read the pointer to the argument string from argv
    bpf_probe_read_user(&argp, sizeof(argp), &ctx->args[arg_index]);
    if (argp) {
        // Read the argument string itself
        return bpf_probe_read_user_str(buf, buf_size, argp);
    }
    return -1;
}

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

    // Basic PID/PPID/Comm info
    e->pid = pid;
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // --- NEW ARGUMENT READING LOGIC ---
    int ret;
    int offset = 0;
    
    // Read the first argument (program name)
    // We still use args[0] for the filename, as it's the most reliable.
    const char* filename = (const char*)BPF_CORE_READ(ctx, args[0]);
    ret = bpf_probe_read_user_str(&e->args_buf[0], ARGS_BUF_SIZE, filename);
    if (ret <= 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    offset += ret; // 'ret' includes the null terminator

    // Read argv (from args[1])
    // We will loop and read up to 10 arguments, or until we fill the buffer
    e->args_count = 1; // We already have one argument (the filename)

    #pragma unroll
    for (int i = 1; i < 10; i++) {
        if (offset >= ARGS_BUF_SIZE - 1) {
            break; // Buffer is full
        }

        const char *argp = NULL;
        // Read the *pointer* to the i-th argument string
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->args[1][i]);
        if (!argp) {
            break; // End of argv array
        }

        // Read the argument string into our buffer, separated by a space
        e->args_buf[offset-1] = ' '; // Replace null terminator with space
        
        // Read the next argument
        ret = bpf_probe_read_user_str(&e->args_buf[offset], ARGS_BUF_SIZE - offset, argp);
        if (ret <= 0) {
            break; // Failed to read or empty string
        }

        e->args_count++;
        offset += ret; // 'ret' includes the null terminator
    }
    // --- END NEW LOGIC ---

    bpf_ringbuf_submit(e, 0);
    return 0;
}