#include "pipe_event.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PIPEMON_CLONE_THREAD 0x00010000

struct syscall_enter_ctx {
    __u64 common;
    long syscall_nr;
    unsigned long args[6];
};

struct syscall_exit_ctx {
    __u64 common;
    long syscall_nr;
    long ret;
};

struct pending_call {
    unsigned long arg1;
    unsigned long arg2;
    __u32 flags;
    __u32 call;
};

/* Syscall entry and exit run separately, so preserve arguments by thread ID. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct pending_call);
} pending_calls SEC(".maps");

/* One shared stream preserves event ordering across CPUs for userspace correlation. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Per-CPU counters avoid contention in hot tracepoint paths. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PIPE_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void increment_stat(__u32 stat)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &stat);

    if (count)
        *count += 1;
}

static __always_inline int remember_call(unsigned long arg1,
                                         unsigned long arg2, __u32 flags,
                                         __u32 call)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_call pending = {
        .arg1 = arg1,
        .arg2 = arg2,
        .flags = flags,
        .call = call,
    };

    if (bpf_map_update_elem(&pending_calls, &pid_tgid, &pending, BPF_ANY))
        increment_stat(PIPE_STAT_PENDING_UPDATE_FAILURES);

    return 0;
}

static __always_inline int emit_event(__u32 type, __s32 fd, __s32 fd2,
                                      __u32 flags, __u32 call,
                                      __u32 child_pid)
{
    char comm[PIPEMON_COMM_LEN];
    int comm_error = bpf_get_current_comm(comm, sizeof(comm));
    if (comm_error) {
        comm[0] = '\0';
        increment_stat(PIPE_STAT_COMM_READ_FAILURES);
    }

    struct pipe_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(PIPE_STAT_RINGBUF_FAILURES);
        return 0;
    }

    __u64 current = bpf_get_current_pid_tgid();
    /* Bump this whenever the shared struct layout or interpretation changes. */
    event->version = 2;
    event->type = type;
    event->pid = current >> 32;
    event->tid = (__u32)current;
    event->child_pid = child_pid;
    event->fd = fd;
    event->fd2 = fd2;
    event->flags = flags;
    event->call = call;
    __builtin_memcpy(event->comm, comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int finish_call(long ret, __u32 expected_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_call *pending = bpf_map_lookup_elem(&pending_calls, &pid_tgid);

    if (!pending)
        return 0;

    struct pending_call saved = *pending;
    if (bpf_map_delete_elem(&pending_calls, &pid_tgid))
        increment_stat(PIPE_STAT_PENDING_DELETE_FAILURES);

    /* Linux syscall tracepoint returns are negative errno values on failure. */
    if (ret < 0)
        return 0;

    if (expected_type == PIPE_EVENT_CREATED) {
        int fds[2];
        /* pipe()/pipe2() write their two process-local descriptors to user memory. */
        if (bpf_probe_read_user(fds, sizeof(fds), (void *)saved.arg1)) {
            increment_stat(PIPE_STAT_FD_READ_FAILURES);
            return 0;
        }

        return emit_event(PIPE_EVENT_CREATED, fds[0], fds[1], saved.flags,
                          saved.call, 0);
    }

    if (expected_type == PIPE_EVENT_FD_DUP) {
        /* dup() chooses its target; dup2/dup3/fcntl carry or imply it. */
        __s32 target_fd = saved.call == PIPE_CALL_DUP ? (__s32)ret :
                                                       (__s32)saved.arg2;
        return emit_event(PIPE_EVENT_FD_DUP, (__s32)saved.arg1, target_fd,
                          saved.flags, saved.call, 0);
    }

    if (expected_type == PIPE_EVENT_FD_CLOSE)
        return emit_event(PIPE_EVENT_FD_CLOSE, (__s32)saved.arg1, -1, 0, 0, 0);

    if (expected_type == PIPE_EVENT_CLOSE_RANGE)
        return emit_event(PIPE_EVENT_CLOSE_RANGE, (__s32)saved.arg1,
                          (__s32)saved.arg2, saved.flags,
                          PIPE_CALL_CLOSE_RANGE, 0);

    if (expected_type == PIPE_EVENT_FORK && ret > 0) {
        /* Threads share an address space and are not separate process records here. */
        if ((saved.call == PIPE_CALL_CLONE ||
             saved.call == PIPE_CALL_CLONE3) &&
            (saved.flags & PIPEMON_CLONE_THREAD))
            return 0;
        return emit_event(PIPE_EVENT_FORK, -1, -1, saved.flags, saved.call,
                          (__u32)ret);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int enter_pipe(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], 0, 0, PIPE_CALL_PIPE);
}

SEC("tracepoint/syscalls/sys_exit_pipe")
int exit_pipe(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_CREATED);
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int enter_pipe2(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], 0, (__u32)ctx->args[1], PIPE_CALL_PIPE2);
}

SEC("tracepoint/syscalls/sys_exit_pipe2")
int exit_pipe2(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_CREATED);
}

SEC("tracepoint/syscalls/sys_enter_dup")
int enter_dup(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], 0, 0, PIPE_CALL_DUP);
}

SEC("tracepoint/syscalls/sys_exit_dup")
int exit_dup(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FD_DUP);
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int enter_dup2(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], ctx->args[1], 0, PIPE_CALL_DUP2);
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int exit_dup2(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FD_DUP);
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int enter_dup3(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], ctx->args[1], (__u32)ctx->args[2],
                         PIPE_CALL_DUP3);
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int exit_dup3(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FD_DUP);
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int enter_fcntl(struct syscall_enter_ctx *ctx)
{
    __u32 command = (__u32)ctx->args[1];

    /* Linux F_DUPFD and F_DUPFD_CLOEXEC command values from fcntl.h. */
    if (command == 0)
        return remember_call(ctx->args[0], 0, 0, PIPE_CALL_FCNTL_DUPFD);
    if (command == 1030)
        return remember_call(ctx->args[0], 0, 1, PIPE_CALL_FCNTL_DUPFD_CLOEXEC);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int exit_fcntl(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FD_DUP);
}

SEC("tracepoint/syscalls/sys_enter_close")
int enter_close(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_close")
int exit_close(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FD_CLOSE);
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int enter_close_range(struct syscall_enter_ctx *ctx)
{
    return remember_call(ctx->args[0], ctx->args[1], (__u32)ctx->args[2],
                         PIPE_CALL_CLOSE_RANGE);
}

SEC("tracepoint/syscalls/sys_exit_close_range")
int exit_close_range(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_CLOSE_RANGE);
}

SEC("tracepoint/syscalls/sys_enter_fork")
int enter_fork(struct syscall_enter_ctx *ctx)
{
    (void)ctx;
    return remember_call(0, 0, 0, PIPE_CALL_FORK);
}

SEC("tracepoint/syscalls/sys_exit_fork")
int exit_fork(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FORK);
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int enter_vfork(struct syscall_enter_ctx *ctx)
{
    (void)ctx;
    return remember_call(0, 0, 0, PIPE_CALL_VFORK);
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int exit_vfork(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FORK);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int enter_clone(struct syscall_enter_ctx *ctx)
{
    return remember_call(0, 0, (__u32)ctx->args[0], PIPE_CALL_CLONE);
}

SEC("tracepoint/syscalls/sys_exit_clone")
int exit_clone(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FORK);
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int enter_clone3(struct syscall_enter_ctx *ctx)
{
    __u64 clone_flags = 0;
    /* clone3() receives flags in the first field of its user-space args struct. */
    if (bpf_probe_read_user(&clone_flags, sizeof(clone_flags),
                            (void *)ctx->args[0]))
        increment_stat(PIPE_STAT_CLONE_FLAGS_READ_FAILURES);
    return remember_call(0, 0, (__u32)clone_flags, PIPE_CALL_CLONE3);
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int exit_clone3(struct syscall_exit_ctx *ctx)
{
    return finish_call(ctx->ret, PIPE_EVENT_FORK);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int execve_exit(struct syscall_exit_ctx *ctx)
{
    /* Successful exec replaces the image and returns to the tracepoint as 0. */
    if (ctx->ret)
        return 0;
    return emit_event(PIPE_EVENT_EXEC, -1, -1, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int execveat_exit(struct syscall_exit_ctx *ctx)
{
    if (ctx->ret)
        return 0;
    return emit_event(PIPE_EVENT_EXEC, -1, -1, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_exit")
int exit_syscall(struct syscall_enter_ctx *ctx)
{
    (void)ctx;
    __u64 current = bpf_get_current_pid_tgid();
    /* Only emit one process-exit record, not one per terminating thread. */
    if ((__u32)(current >> 32) != (__u32)current)
        return 0;
    return emit_event(PIPE_EVENT_EXIT, -1, -1, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int exit_group_syscall(struct syscall_enter_ctx *ctx)
{
    (void)ctx;
    return emit_event(PIPE_EVENT_EXIT, -1, -1, 0, 0, 0);
}

char LICENSE[] SEC("license") = "GPL";
