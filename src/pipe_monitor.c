#define _GNU_SOURCE

#include "pipe_event.h"
#include "pipe_monitor.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PIPEMON_CLOSE_RANGE_UNSHARE 0x00000002
#define PIPEMON_CLOSE_RANGE_CLOEXEC 0x00000004
#define PIPEMON_CLONE_FILES 0x00000400

struct proc_metadata {
    char comm[PIPEMON_COMM_LEN];
    char exe[PATH_MAX];
    char cmdline[4096];
    int uid;
    int ppid;
};

/* Descriptor state is keyed by an emulated fd table, not just by process ID. */
struct tracked_fd {
    __u64 fd_space;
    int fd;
    __u64 pipe_id;
    bool is_read_end;
    bool close_on_exec;
    struct tracked_fd *next;
};

struct tracked_process {
    __u32 pid;
    __u64 instance_id;
    __u64 fd_space;
    bool exec_seen;
    char comm[PIPEMON_COMM_LEN];
    struct proc_metadata metadata;
    struct tracked_process *next;
};

/* Keep one connection per process instance and pipe direction, not per fd. */
struct tracked_connection {
    __u64 process_instance;
    __u32 pid;
    bool is_read_end;
    struct proc_metadata process;
    struct tracked_connection *next;
};

struct tracked_pipe {
    __u64 pipe_id;
    __u32 creator_pid;
    struct proc_metadata creator;
    struct proc_metadata parent;
    size_t connection_count;
    struct tracked_connection *connections;
    struct tracked_pipe *next;
};

static volatile sig_atomic_t exiting;
static struct tracked_fd *tracked_fds;
static struct tracked_process *tracked_processes;
static struct tracked_pipe *tracked_pipes;
static __u64 next_pipe_id = 1;
static __u64 next_fd_space = 1;
static __u64 next_process_instance = 1;
static FILE *event_output;

static void handle_signal(int signal)
{
    (void)signal;
    exiting = 1;
}

static struct tracked_process *find_process(__u32 pid)
{
    for (struct tracked_process *process = tracked_processes; process;
         process = process->next) {
        if (process->pid == pid)
            return process;
    }
    return NULL;
}

static struct tracked_process *get_process(__u32 pid)
{
    struct tracked_process *process = find_process(pid);
    if (process)
        return process;

    process = calloc(1, sizeof(*process));
    if (!process)
        return NULL;
    process->pid = pid;
    process->instance_id = next_process_instance++;
    process->metadata.uid = -1;
    process->metadata.ppid = -1;
    /* A new process starts with its own fd table unless a clone event says otherwise. */
    process->fd_space = next_fd_space++;
    process->next = tracked_processes;
    tracked_processes = process;
    return process;
}

static struct tracked_fd *find_fd_in_space(__u64 fd_space, int fd)
{
    for (struct tracked_fd *entry = tracked_fds; entry; entry = entry->next) {
        if (entry->fd_space == fd_space && entry->fd == fd)
            return entry;
    }
    return NULL;
}

static struct tracked_fd *find_fd(__u32 pid, int fd)
{
    struct tracked_process *process = get_process(pid);
    return process ? find_fd_in_space(process->fd_space, fd) : NULL;
}

static void remove_fd_from_space(__u64 fd_space, int fd)
{
    struct tracked_fd **entry = &tracked_fds;
    while (*entry) {
        if ((*entry)->fd_space == fd_space && (*entry)->fd == fd) {
            struct tracked_fd *removed = *entry;
            *entry = removed->next;
            free(removed);
            return;
        }
        entry = &(*entry)->next;
    }
}

static void remove_fd(__u32 pid, int fd)
{
    struct tracked_process *process = get_process(pid);
    if (process)
        remove_fd_from_space(process->fd_space, fd);
}

static int set_fd_in_space(__u64 fd_space, int fd, __u64 pipe_id,
                           bool is_read_end, bool close_on_exec)
{
    struct tracked_fd *entry = find_fd_in_space(fd_space, fd);
    if (!entry) {
        entry = calloc(1, sizeof(*entry));
        if (!entry)
            return -1;
        entry->fd_space = fd_space;
        entry->fd = fd;
        entry->next = tracked_fds;
        tracked_fds = entry;
    }

    entry->pipe_id = pipe_id;
    entry->is_read_end = is_read_end;
    entry->close_on_exec = close_on_exec;
    return 0;
}

static int set_fd(__u32 pid, int fd, __u64 pipe_id, bool is_read_end,
                  bool close_on_exec)
{
    struct tracked_process *process = get_process(pid);
    return process ? set_fd_in_space(process->fd_space, fd, pipe_id,
                                     is_read_end, close_on_exec) : -1;
}

static void print_escaped(const char *value)
{
    fputc('"', event_output);
    for (const unsigned char *ch = (const unsigned char *)value; *ch; ch++) {
        if (isprint(*ch) && *ch != '"' && *ch != '\\')
            fputc(*ch, event_output);
        else
            fprintf(event_output, "\\x%02x", *ch);
    }
    fputc('"', event_output);
}

static void read_proc_metadata(__u32 pid, struct proc_metadata *metadata)
{
    char proc_path[64];
    metadata->comm[0] = '\0';
    metadata->exe[0] = '\0';
    metadata->cmdline[0] = '\0';
    metadata->uid = -1;
    metadata->ppid = -1;

    int path_len = snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", pid);
    if (path_len > 0 && (size_t)path_len < sizeof(proc_path)) {
        ssize_t exe_len = readlink(proc_path, metadata->exe,
                                   sizeof(metadata->exe) - 1);
        if (exe_len >= 0)
            metadata->exe[exe_len] = '\0';
    }

    path_len = snprintf(proc_path, sizeof(proc_path), "/proc/%u/cmdline", pid);
    if (path_len > 0 && (size_t)path_len < sizeof(proc_path)) {
        FILE *file = fopen(proc_path, "rb");
        if (file) {
            ssize_t cmdline_len = (ssize_t)fread(metadata->cmdline, 1,
                                                 sizeof(metadata->cmdline) - 1,
                                                 file);
            if (ferror(file))
                cmdline_len = -1;
            fclose(file);
            if (cmdline_len > 0) {
                /* proc cmdline is NUL-separated argv; render it as a readable line. */
                while (cmdline_len > 0 &&
                       metadata->cmdline[cmdline_len - 1] == '\0')
                    cmdline_len--;
                for (ssize_t i = 0; i < cmdline_len; i++) {
                    if (metadata->cmdline[i] == '\0')
                        metadata->cmdline[i] = ' ';
                }
                metadata->cmdline[cmdline_len] = '\0';
            }
        }
    }

    path_len = snprintf(proc_path, sizeof(proc_path), "/proc/%u/status", pid);
    if (path_len > 0 && (size_t)path_len < sizeof(proc_path)) {
        FILE *file = fopen(proc_path, "r");
        if (file) {
            char line[256];
            while (fgets(line, sizeof(line), file)) {
                unsigned int value;
                if (!strncmp(line, "Name:", 5)) {
                    char *name = line + 5;
                    while (*name == '\t' || *name == ' ')
                        name++;
                    name[strcspn(name, "\n")] = '\0';
                    size_t name_len = strnlen(name,
                                              sizeof(metadata->comm) - 1);
                    memcpy(metadata->comm, name, name_len);
                    metadata->comm[name_len] = '\0';
                } else if (sscanf(line, "Uid:%u", &value) == 1)
                    metadata->uid = (int)value;
                else if (sscanf(line, "PPid:%u", &value) == 1)
                    metadata->ppid = (int)value;
            }
            fclose(file);
        }
    }
}

static void print_metadata_value(const char *value)
{
    print_escaped(value[0] ? value : "(unavailable)");
}

/* Keep earlier snapshots when procfs no longer exposes a short-lived process. */
static void copy_available_metadata(struct proc_metadata *destination,
                                    const struct proc_metadata *source)
{
    if (source->comm[0])
        memcpy(destination->comm, source->comm, sizeof(destination->comm));
    if (source->exe[0])
        memcpy(destination->exe, source->exe, sizeof(destination->exe));
    if (source->cmdline[0])
        memcpy(destination->cmdline, source->cmdline,
               sizeof(destination->cmdline));
    if (source->uid >= 0)
        destination->uid = source->uid;
    if (source->ppid >= 0)
        destination->ppid = source->ppid;
}

static void refresh_process_metadata(struct tracked_process *process)
{
    struct proc_metadata metadata = {};
    metadata.uid = -1;
    metadata.ppid = -1;
    read_proc_metadata(process->pid, &metadata);
    copy_available_metadata(&process->metadata, &metadata);
}

static bool process_has_pipe_on_standard_fd(const struct tracked_process *process,
                                            __u64 pipe_id,
                                            const struct tracked_connection *connection)
{
    const int standard_fds[] = {STDIN_FILENO, STDOUT_FILENO};
    for (size_t i = 0; i < sizeof(standard_fds) / sizeof(standard_fds[0]); i++) {
        struct tracked_fd *entry = find_fd(process->pid, standard_fds[i]);
        if (entry && entry->pipe_id == pipe_id &&
            entry->is_read_end == connection->is_read_end)
            return true;
    }
    return false;
}

static struct tracked_pipe *find_pipe(__u64 pipe_id)
{
    for (struct tracked_pipe *pipe = tracked_pipes; pipe; pipe = pipe->next) {
        if (pipe->pipe_id == pipe_id)
            return pipe;
    }
    return NULL;
}

static struct tracked_pipe *create_pipe_summary(__u64 pipe_id, __u32 creator_pid,
                                                const char *creator_comm)
{
    struct tracked_pipe *pipe = calloc(1, sizeof(*pipe));
    if (!pipe)
        return NULL;

    pipe->pipe_id = pipe_id;
    pipe->creator_pid = creator_pid;
    pipe->creator.uid = -1;
    pipe->creator.ppid = -1;
    pipe->parent.uid = -1;
    pipe->parent.ppid = -1;

    struct proc_metadata creator = {};
    read_proc_metadata(creator_pid, &creator);
    if (!creator.comm[0] && creator_comm)
        snprintf(creator.comm, sizeof(creator.comm), "%s", creator_comm);
    copy_available_metadata(&pipe->creator, &creator);

    if (pipe->creator.ppid > 0)
        read_proc_metadata((__u32)pipe->creator.ppid, &pipe->parent);

    pipe->next = tracked_pipes;
    tracked_pipes = pipe;
    return pipe;
}

static int remember_connection(const struct tracked_fd *entry, __u32 pid,
                               const char *comm)
{
    struct tracked_pipe *pipe = find_pipe(entry->pipe_id);
    struct tracked_process *process = find_process(pid);
    if (!pipe || !process)
        return -1;

    struct tracked_connection *connection = pipe->connections;
    while (connection) {
        if (connection->process_instance == process->instance_id &&
            connection->is_read_end == entry->is_read_end)
            break;
        connection = connection->next;
    }

    if (!connection) {
        connection = calloc(1, sizeof(*connection));
        if (!connection)
            return -1;
        connection->process_instance = process->instance_id;
        connection->pid = pid;
        connection->is_read_end = entry->is_read_end;
        connection->process.uid = -1;
        connection->process.ppid = -1;
        connection->next = pipe->connections;
        pipe->connections = connection;
        pipe->connection_count++;
    }

    refresh_process_metadata(process);
    if (!process->metadata.comm[0] && comm)
        snprintf(process->metadata.comm, sizeof(process->metadata.comm), "%s",
                 comm);
    copy_available_metadata(&connection->process, &process->metadata);
    return 0;
}

static void update_connections_after_exec(struct tracked_process *process,
                                          const char *comm)
{
    /* Replace pre-exec shell metadata and discard ends closed by exec. */
    process->metadata.comm[0] = '\0';
    process->metadata.exe[0] = '\0';
    process->metadata.cmdline[0] = '\0';
    if (comm)
        snprintf(process->metadata.comm, sizeof(process->metadata.comm), "%s",
                 comm);
    refresh_process_metadata(process);

    for (struct tracked_pipe *pipe = tracked_pipes; pipe; pipe = pipe->next) {
        struct tracked_connection **connection = &pipe->connections;
        while (*connection) {
            struct tracked_connection *current = *connection;
            if (current->process_instance != process->instance_id) {
                connection = &current->next;
                continue;
            }

            if (!process_has_pipe_on_standard_fd(process, pipe->pipe_id,
                                                 current)) {
                *connection = current->next;
                free(current);
                pipe->connection_count--;
                continue;
            }

            current->process.comm[0] = '\0';
            current->process.exe[0] = '\0';
            current->process.cmdline[0] = '\0';
            copy_available_metadata(&current->process, &process->metadata);
            connection = &current->next;
        }
    }
}

static int print_pipe_summary(const struct tracked_pipe *pipe)
{
    fprintf(event_output, "pipe_summary pipe_id=%llu creator_pid=%u",
            (unsigned long long)pipe->pipe_id, pipe->creator_pid);
    fprintf(event_output, " creator_comm=");
    print_metadata_value(pipe->creator.comm);
    fprintf(event_output, " creator_exe=");
    print_metadata_value(pipe->creator.exe);
    fprintf(event_output, " creator_cmdline=");
    print_metadata_value(pipe->creator.cmdline);
    fprintf(event_output, " parent_pid=%d parent_comm=", pipe->creator.ppid);
    print_metadata_value(pipe->parent.comm);
    fprintf(event_output, " parent_exe=");
    print_metadata_value(pipe->parent.exe);
    fprintf(event_output, " parent_cmdline=");
    print_metadata_value(pipe->parent.cmdline);
    fprintf(event_output, " connections=%zu\n", pipe->connection_count);

    for (const struct tracked_connection *connection = pipe->connections;
         connection; connection = connection->next) {
        fprintf(event_output, "pipe_connection pipe_id=%llu side=%s pid=%u comm=",
                (unsigned long long)pipe->pipe_id,
                connection->is_read_end ? "reader" : "writer",
                connection->pid);
        print_metadata_value(connection->process.comm);
        fprintf(event_output, " exe=");
        print_metadata_value(connection->process.exe);
        fprintf(event_output, " cmdline=");
        print_metadata_value(connection->process.cmdline);
        fprintf(event_output, "\n");
    }

    return ferror(event_output) ? -1 : 0;
}

static bool pipe_has_tracked_descriptors(__u64 pipe_id)
{
    for (const struct tracked_fd *entry = tracked_fds; entry; entry = entry->next) {
        if (entry->pipe_id == pipe_id)
            return true;
    }
    return false;
}

static int flush_pipe_summaries(bool all)
{
    /* Keep summaries until descriptor tracking can no longer add endpoints. */
    struct tracked_pipe **pipe = &tracked_pipes;
    while (*pipe) {
        struct tracked_pipe *current = *pipe;
        if (!all && pipe_has_tracked_descriptors(current->pipe_id)) {
            pipe = &current->next;
            continue;
        }

        if (print_pipe_summary(current))
            return -1;
        *pipe = current->next;
        while (current->connections) {
            struct tracked_connection *next = current->connections->next;
            free(current->connections);
            current->connections = next;
        }
        free(current);
    }
    return 0;
}

static int report_standard_fds(__u32 pid, const char *comm)
{
    const int standard_fds[] = {STDIN_FILENO, STDOUT_FILENO};
    for (size_t i = 0; i < sizeof(standard_fds) / sizeof(standard_fds[0]); i++) {
        struct tracked_fd *entry = find_fd(pid, standard_fds[i]);
        if (entry && remember_connection(entry, pid, comm))
            return -1;
    }
    return 0;
}

static int report_fd_space_endpoints(__u64 fd_space)
{
    /* CLONE_FILES makes one descriptor update visible to every member process. */
    for (struct tracked_process *process = tracked_processes; process;
         process = process->next) {
        if (process->fd_space == fd_space &&
            report_standard_fds(process->pid,
                                process->comm[0] ? process->comm : NULL))
            return -1;
    }
    return 0;
}

static void remove_fd_space(__u64 fd_space)
{
    struct tracked_fd **entry = &tracked_fds;
    while (*entry) {
        if ((*entry)->fd_space == fd_space) {
            struct tracked_fd *removed = *entry;
            *entry = removed->next;
            free(removed);
        } else {
            entry = &(*entry)->next;
        }
    }
}

static void remove_process(__u32 pid)
{
    struct tracked_process **process = &tracked_processes;
    while (*process) {
        if ((*process)->pid == pid) {
            struct tracked_process *removed = *process;
            *process = removed->next;
            __u64 fd_space = removed->fd_space;
            free(removed);
            bool still_referenced = false;
            for (struct tracked_process *other = tracked_processes; other;
                 other = other->next) {
                if (other->fd_space == fd_space) {
                    still_referenced = true;
                    break;
                }
            }
            if (!still_referenced)
                /* Keep shared descriptor entries until their last process exits. */
                remove_fd_space(fd_space);
            return;
        }
        process = &(*process)->next;
    }
}

static int copy_fd_space(__u64 source_space, __u64 target_space)
{
    /* Copy through a temporary list so allocation failure leaves target intact. */
    struct tracked_fd *copies = NULL;
    for (struct tracked_fd *entry = tracked_fds; entry; entry = entry->next) {
        if (entry->fd_space != source_space)
            continue;

        struct tracked_fd *copy = malloc(sizeof(*copy));
        if (!copy) {
            while (copies) {
                struct tracked_fd *next = copies->next;
                free(copies);
                copies = next;
            }
            return -1;
        }
        *copy = *entry;
        copy->fd_space = target_space;
        copy->next = copies;
        copies = copy;
    }

    while (copies) {
        struct tracked_fd *copy = copies;
        copies = copies->next;
        copy->next = tracked_fds;
        tracked_fds = copy;
    }
    return 0;
}

static size_t fd_space_references(__u64 fd_space)
{
    size_t references = 0;
    for (struct tracked_process *process = tracked_processes; process;
         process = process->next) {
        if (process->fd_space == fd_space)
            references++;
    }
    return references;
}

static int unshare_fd_space(struct tracked_process *process)
{
    if (fd_space_references(process->fd_space) < 2)
        return 0;

    __u64 new_space = next_fd_space++;
    /* exec and close_range(UNSHARE) split only this process from shared state. */
    if (copy_fd_space(process->fd_space, new_space))
        return -1;
    process->fd_space = new_space;
    return 0;
}

static int inherit_fds(__u32 parent_pid, __u32 child_pid, __u32 flags)
{
    struct tracked_process *parent = get_process(parent_pid);
    struct tracked_process *child = get_process(child_pid);
    if (!parent || !child)
        return -1;
    child->exec_seen = false;
    memcpy(child->comm, parent->comm, sizeof(child->comm));
    child->metadata = parent->metadata;
    child->metadata.ppid = (int)parent_pid;

    /* CLONE_FILES shares mutations; ordinary fork/clone gets an independent copy. */
    if (flags & PIPEMON_CLONE_FILES) {
        child->fd_space = parent->fd_space;
        return 0;
    }

    return copy_fd_space(parent->fd_space, child->fd_space);
}

static int apply_close_range(__u32 pid, __u32 first, __u32 last, __u32 flags)
{
    struct tracked_process *process = get_process(pid);
    if (!process)
        return -1;

    /* UNSHARE changes this task's fd table before applying the requested range. */
    if ((flags & PIPEMON_CLOSE_RANGE_UNSHARE) &&
        unshare_fd_space(process))
        return -1;

    struct tracked_fd **entry = &tracked_fds;
    while (*entry) {
        struct tracked_fd *current = *entry;
        __u32 fd = (unsigned int)current->fd;
        if (current->fd_space != process->fd_space ||
            fd < first || fd > last) {
            entry = &current->next;
            continue;
        }

        if (flags & PIPEMON_CLOSE_RANGE_CLOEXEC) {
            /* CLOSE_RANGE_CLOEXEC defers dropping these descriptors until exec. */
            current->close_on_exec = true;
            entry = &current->next;
        } else {
            *entry = current->next;
            free(current);
        }
    }
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_size)
{
    (void)ctx;

    if (data_size != sizeof(struct pipe_event)) {
        fprintf(stderr, "Ignoring malformed pipe event (%zu bytes)\n", data_size);
        return 0;
    }

    const struct pipe_event *event = data;
    if (event->version != 2) {
        fprintf(stderr, "Ignoring unsupported pipe event version %u\n",
                event->version);
        return 0;
    }

    const char *comm = event->comm[0] ? event->comm : "(unavailable)";
    struct tracked_process *event_process = get_process(event->pid);
    if (!event_process) {
        fprintf(stderr, "Could not track process %u\n", event->pid);
        return -ENOMEM;
    }
    if (event->comm[0]) {
        memcpy(event_process->comm, event->comm, sizeof(event_process->comm));
        if (!event_process->metadata.comm[0])
            memcpy(event_process->metadata.comm, event->comm,
                   sizeof(event_process->metadata.comm));
    }
    if (event->type == PIPE_EVENT_CREATED ||
        event->type == PIPE_EVENT_FORK)
        refresh_process_metadata(event_process);

    switch (event->type) {
    case PIPE_EVENT_CREATED: {
        /* IDs are local to this monitor run; track both returned pipe ends. */
        __u64 pipe_id = next_pipe_id++;
        if (!create_pipe_summary(pipe_id, event->pid, comm)) {
            fprintf(stderr, "Could not allocate summary for pipe %llu\n",
                    (unsigned long long)pipe_id);
            return -ENOMEM;
        }
        if (get_process(event->pid) == NULL ||
            set_fd(event->pid, event->fd, pipe_id, true,
                   (event->flags & O_CLOEXEC) != 0) ||
            set_fd(event->pid, event->fd2, pipe_id, false,
                   (event->flags & O_CLOEXEC) != 0)) {
            fprintf(stderr, "Could not track pipe descriptors for pid %u\n",
                    event->pid);
            return -ENOMEM;
        }
        struct tracked_process *process = find_process(event->pid);
        if (report_fd_space_endpoints(process->fd_space)) {
            fprintf(stderr, "Could not record pipe endpoint connections\n");
            return -ENOMEM;
        }
        break;
    }
    case PIPE_EVENT_FORK:
        if (inherit_fds(event->pid, event->child_pid, event->flags)) {
            fprintf(stderr, "Could not inherit tracked descriptors from pid %u "
                    "to pid %u\n", event->pid, event->child_pid);
            return -ENOMEM;
        }
        break;
    case PIPE_EVENT_FD_DUP: {
        /* dup2/dup3 atomically replace the destination, so discard stale tracking. */
        struct tracked_fd *source = find_fd(event->pid, event->fd);
        if (event->fd != event->fd2) {
            remove_fd(event->pid, event->fd2);
            if (source) {
                bool close_on_exec = event->call == PIPE_CALL_DUP3 ?
                    (event->flags & O_CLOEXEC) != 0 :
                    event->call == PIPE_CALL_FCNTL_DUPFD_CLOEXEC;
                if (set_fd(event->pid, event->fd2, source->pipe_id,
                           source->is_read_end, close_on_exec)) {
                    fprintf(stderr, "Could not track duplicated descriptor for "
                            "pid %u\n", event->pid);
                    return -ENOMEM;
                }
            }
        }
        if (event->fd2 == STDIN_FILENO || event->fd2 == STDOUT_FILENO) {
            struct tracked_process *process = find_process(event->pid);
            if (report_fd_space_endpoints(process->fd_space)) {
                fprintf(stderr, "Could not record pipe endpoint connections\n");
                return -ENOMEM;
            }
        }
        break;
    }
    case PIPE_EVENT_FD_CLOSE:
        remove_fd(event->pid, event->fd);
        break;
    case PIPE_EVENT_CLOSE_RANGE:
        if (apply_close_range(event->pid, (unsigned int)event->fd,
                              (unsigned int)event->fd2, event->flags)) {
            fprintf(stderr, "Could not apply close_range for pid %u\n",
                    event->pid);
            return -ENOMEM;
        }
        break;
    case PIPE_EVENT_EXEC: {
        struct tracked_process *process = get_process(event->pid);
        if (!process) {
            fprintf(stderr, "Could not track exec state for pid %u\n", event->pid);
            return -ENOMEM;
        }
        if (unshare_fd_space(process)) {
            fprintf(stderr, "Could not unshare descriptors at exec for pid %u\n",
                    event->pid);
            return -ENOMEM;
        }
        /* exec closes CLOEXEC descriptors before the new image uses stdio. */
        struct tracked_fd **entry = &tracked_fds;
        while (*entry) {
            if ((*entry)->fd_space == process->fd_space &&
                (*entry)->close_on_exec) {
                struct tracked_fd *removed = *entry;
                *entry = removed->next;
                free(removed);
            } else {
                entry = &(*entry)->next;
            }
        }
        update_connections_after_exec(process, comm);
        if (report_standard_fds(event->pid, comm)) {
            fprintf(stderr, "Could not record pipe endpoint connections\n");
            return -ENOMEM;
        }
        process->exec_seen = true;
        break;
    }
    case PIPE_EVENT_EXIT: {
        struct tracked_process *process = find_process(event->pid);
        if (!process || !process->exec_seen) {
            if (report_standard_fds(event->pid, comm)) {
                fprintf(stderr, "Could not record pipe endpoint connections\n");
                return -ENOMEM;
            }
        }
        remove_process(event->pid);
        break;
    }
    default:
        fprintf(stderr, "Ignoring pipe event with unknown type %u\n", event->type);
        return 0;
    }

    if (flush_pipe_summaries(false)) {
        fprintf(stderr, "Could not write completed pipe summaries: %s\n",
                strerror(errno));
        return -EIO;
    }
    if (fflush(event_output)) {
        fprintf(stderr, "Could not write event output: %s\n", strerror(errno));
        return -EIO;
    }
    return 0;
}

static int report_stats(int stats_fd)
{
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count < 0) {
        fprintf(stderr, "Could not determine possible CPU count: %s\n",
                strerror(-cpu_count));
        return -1;
    }

    /* Per-CPU map lookup requires one value slot for every possible CPU. */
    __u64 *values = calloc((size_t)cpu_count, sizeof(*values));
    if (!values) {
        fprintf(stderr, "Could not allocate per-CPU statistics buffer\n");
        return -1;
    }

    bool failed = false;
    for (__u32 stat = 0; stat < PIPE_STAT_COUNT; stat++) {
        memset(values, 0, (size_t)cpu_count * sizeof(*values));
        if (bpf_map_lookup_elem(stats_fd, &stat, values)) {
            fprintf(stderr, "Could not read BPF statistics: %s\n",
                    strerror(errno));
            failed = true;
            break;
        }

        __u64 total = 0;
        for (int cpu = 0; cpu < cpu_count; cpu++)
            total += values[cpu];

        if (!total)
            continue;

        const char *name;
        switch (stat) {
        case PIPE_STAT_PENDING_UPDATE_FAILURES:
            name = "pending_map_update_failures";
            break;
        case PIPE_STAT_PENDING_DELETE_FAILURES:
            name = "pending_map_delete_failures";
            break;
        case PIPE_STAT_FD_READ_FAILURES:
            name = "fd_read_failures";
            break;
        case PIPE_STAT_CLONE_FLAGS_READ_FAILURES:
            name = "clone_flags_read_failures";
            break;
        case PIPE_STAT_COMM_READ_FAILURES:
            name = "comm_read_failures";
            break;
        case PIPE_STAT_RINGBUF_FAILURES:
            name = "ring_buffer_reservation_failures";
            break;
        default:
            name = "unknown";
            break;
        }
        fprintf(stderr, "monitor_stats %s=%llu\n", name,
                (unsigned long long)total);
    }

    free(values);
    return failed ? -1 : 0;
}

static void free_state(void)
{
    while (tracked_fds) {
        struct tracked_fd *next = tracked_fds->next;
        free(tracked_fds);
        tracked_fds = next;
    }
    while (tracked_processes) {
        struct tracked_process *next = tracked_processes->next;
        free(tracked_processes);
        tracked_processes = next;
    }
    while (tracked_pipes) {
        struct tracked_pipe *next_pipe = tracked_pipes->next;
        while (tracked_pipes->connections) {
            struct tracked_connection *next_connection =
                tracked_pipes->connections->next;
            free(tracked_pipes->connections);
            tracked_pipes->connections = next_connection;
        }
        free(tracked_pipes);
        tracked_pipes = next_pipe;
    }
}

static bool tracepoint_is_available(const char *name)
{
    static const char *tracefs_roots[] = {
        "/sys/kernel/tracing/events/syscalls",
        "/sys/kernel/debug/tracing/events/syscalls",
    };
    char path[PATH_MAX];

    for (size_t i = 0;
         i < sizeof(tracefs_roots) / sizeof(tracefs_roots[0]); i++) {
        int length = snprintf(path, sizeof(path), "%s/%s/id",
                              tracefs_roots[i], name);
        if (length > 0 && (size_t)length < sizeof(path) &&
            access(path, R_OK) == 0)
            return true;
    }
    return false;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [--output FILE] [--help]\n", program);
}

int main(int argc, char **argv)
{
    struct pipe_monitor_bpf *skel = NULL;
    struct ring_buffer *ring = NULL;
    int exit_code = EXIT_FAILURE;
    const char *output_path = NULL;
    event_output = stdout;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else if (!strcmp(argv[i], "--output") || !strcmp(argv[i], "-o")) {
            if (++i >= argc || argv[i][0] == '\0') {
                usage(argv[0]);
                fprintf(stderr, "Missing output file path\n");
                return EXIT_FAILURE;
            }
            output_path = argv[i];
        } else {
            usage(argv[0]);
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    struct sigaction action = {
        .sa_handler = handle_signal,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
        fprintf(stderr, "Could not install signal handlers: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    skel = pipe_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Could not open BPF object: %s\n", strerror(errno));
        goto cleanup;
    }

    if (!tracepoint_is_available("sys_enter_close_range") ||
        !tracepoint_is_available("sys_exit_close_range")) {
        /* close_range was added after the base kernel target; disable only these probes. */
        if (bpf_program__set_autoload(skel->progs.enter_close_range, false) ||
            bpf_program__set_autoload(skel->progs.exit_close_range, false)) {
            fprintf(stderr, "Could not disable unavailable close_range probes\n");
            goto cleanup;
        }
        fprintf(stderr, "close_range syscall tracepoint unavailable; "
                "close_range descriptor tracking disabled\n");
    }

    /* Skeleton owns the BPF object and links; destroy it on every exit path. */
    int err = pipe_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Could not load BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }

    err = pipe_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Could not attach syscall tracepoints: %s\n",
                strerror(-err));
        goto cleanup;
    }

    ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                            NULL);
    if (!ring) {
        fprintf(stderr, "Could not create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    if (output_path) {
        event_output = fopen(output_path, "w");
        if (!event_output) {
            fprintf(stderr, "Could not open output file %s: %s\n",
                    output_path, strerror(errno));
            goto cleanup;
        }
    }

    fprintf(stderr, "Monitoring pipe events from all processes; "
            "press Ctrl-C to stop.\n");
    exit_code = EXIT_SUCCESS;
    while (!exiting) {
        err = ring_buffer__poll(ring, 250);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer polling failed: %s\n", strerror(-err));
            exit_code = EXIT_FAILURE;
            break;
        }
    }

    /* Snapshot counters before destroying the maps and detaching their links. */
    if (report_stats(bpf_map__fd(skel->maps.stats)))
        exit_code = EXIT_FAILURE;

cleanup:
    ring_buffer__free(ring);
    pipe_monitor_bpf__destroy(skel);
    if (event_output && flush_pipe_summaries(true)) {
        fprintf(stderr, "Could not write final pipe summaries\n");
        exit_code = EXIT_FAILURE;
    }
    free_state();
    if (event_output != stdout && fclose(event_output)) {
        fprintf(stderr, "Could not close event output file: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    return exit_code;
}
