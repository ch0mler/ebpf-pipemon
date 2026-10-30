#ifndef PIPE_EVENT_H
#define PIPE_EVENT_H

#include <linux/types.h>

/* Linux TASK_COMM_LEN includes the trailing NUL byte. */
#define PIPEMON_COMM_LEN 16

/* Keep event IDs stable: they are shared by the BPF object and loader. */
enum pipe_event_type {
    PIPE_EVENT_CREATED = 1,
    PIPE_EVENT_FORK,
    PIPE_EVENT_FD_DUP,
    PIPE_EVENT_FD_CLOSE,
    /* Event ID 5 is reserved for removed close_range tracking. */
    PIPE_EVENT_EXEC = 6,
    PIPE_EVENT_EXIT = 7,
};

/* Identifies the syscall that caused a creation, duplication, or fork event. */
enum pipe_call {
    PIPE_CALL_PIPE = 1,
    PIPE_CALL_PIPE2,
    PIPE_CALL_DUP,
    PIPE_CALL_DUP2,
    PIPE_CALL_DUP3,
    PIPE_CALL_FCNTL_DUPFD,
    PIPE_CALL_FCNTL_DUPFD_CLOEXEC,
    PIPE_CALL_FORK,
    PIPE_CALL_VFORK,
    PIPE_CALL_CLONE,
    PIPE_CALL_CLONE3,
};

/* Per-CPU counters for failures that can otherwise make correlation incomplete. */
enum pipe_stat {
    PIPE_STAT_PENDING_UPDATE_FAILURES,
    PIPE_STAT_PENDING_DELETE_FAILURES,
    PIPE_STAT_FD_READ_FAILURES,
    PIPE_STAT_CLONE_FLAGS_READ_FAILURES,
    PIPE_STAT_COMM_READ_FAILURES,
    PIPE_STAT_RINGBUF_FAILURES,
    PIPE_STAT_COUNT,
};

/*
 * Versioned ring-buffer ABI. fd/fd2 are syscall-specific; unused values are -1
 * where practical. pid is the process ID (TGID), tid is the syscall thread ID,
 * and child_pid is set only for PIPE_EVENT_FORK.
 */
struct pipe_event {
    __u32 version;
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 child_pid;
    __s32 fd;
    __s32 fd2;
    __u32 flags;
    __u32 call;
    char comm[PIPEMON_COMM_LEN];
};

#endif
