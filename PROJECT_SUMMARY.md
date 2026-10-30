# Pipe Monitor Project Summary

## Goal

Pipe Monitor is a Linux eBPF prototype for identifying anonymous pipes and
associating them with the processes that have a pipe end connected to standard
input or standard output. A motivating case is a command pipeline such as
`curl ... | bash`.

The monitor reports a connection, not proof that data was read or written.
Named FIFOs are out of scope.

## Requirements and design decisions

- Report pipe activity for all process types. There is no shell-name or other
  process-type filter.
- Identify the process that created each pipe and its parent process.
- Identify processes connected as readers or writers, including their names
  and command lines.
- Track PID and `COMM` in eBPF events; resolve richer attributes in user space
  through `/proc`.
- Track descriptor state internally to follow pipe ends across descriptor
  duplication, close, fork/clone, and exec. File descriptor numbers are omitted
  from the summary output.
- Event loss is acceptable during this prototype, though the helper reports
  available loss/error counters at shutdown.
- Develop and run privileged eBPF tests inside the disposable VM, not on the
  development host.

## Implementation

The project uses C with libbpf. The BPF side attaches to syscall tracepoints,
pairs syscall entry and exit events using a hash map keyed by thread ID, and
publishes successful operations to a ring buffer. The user-mode helper loads
the generated libbpf skeleton and correlates events.

Tracked operations include:

- `pipe()` and `pipe2()` creation
- `dup()`, `dup2()`, `dup3()`, and `fcntl(F_DUPFD*)`
- `close()`
- `fork()`, `vfork()`, `clone()`, and `clone3()`
- `execve()`, `execveat()`, and process exit

The helper reads executable path, command line, UID, and parent PID from
`/proc`. For short-lived processes, exited processes, or restricted procfs
access, some values may be unavailable. Command lines can contain sensitive
arguments; protect output files accordingly.

## Output

The helper prints plaintext summaries to stdout by default. Use
`--output FILE` or `-o FILE` to write the summaries to a file; the file is
created or truncated when monitoring starts.

Output consists of one `pipe_summary` record and zero or more
`pipe_connection` records, joined by a monitor-local `pipe_id`. A summary
contains the pipe creator and its parent. A connection identifies a process
and its side (`writer` or `reader`). Repeated observations of the same
process-instance/pipe/direction are deduplicated. Multiple readers or writers
are retained when observed.

Summaries are emitted after the helper determines that no tracked descriptors
for the pipe remain, or at shutdown if descriptors are still tracked. An
example:

```text
event=pipe_summary pipe_id=42 creator_pid=4100 creator_syscall=pipe2 creator_flags=0x00080000 creator_comm="bash" creator_exe="/usr/bin/bash" creator_cmdline="bash -c curl | bash" parent_pid=4000 parent_comm="sh" parent_exe="/usr/bin/sh" parent_cmdline="sh -c ..." connections=2
event=pipe_connection pipe_id=42 side=writer pid=4101 comm="curl" exe="/usr/bin/curl" cmdline="curl https://example[.]invalid/script"
event=pipe_connection pipe_id=42 side=reader pid=4102 comm="bash" exe="/usr/bin/bash" cmdline="bash"
```

`creator_flags` is the hexadecimal flag mask passed to `pipe2()`; it is
`0x00000000` for `pipe()`, which has no flags argument.

Processes are reported as readers when the tracked pipe read end is observed
on stdin and writers when the tracked write end is observed on stdout.
Connections to other descriptors are tracked but are not represented as
application endpoints in this output format.

## Build and run

On a Linux x86_64 development host with Clang/LLVM's BPF target, `bpftool`,
libbpf development headers/library, `pkg-config`, and a C compiler:

```sh
make
```

The build generates `build/pipe_monitor.bpf.o`, the libbpf skeleton, and
`build/pipe-monitor`. Cross-compilation is not supported.

Run the helper as root, or with suitable eBPF privileges, in a disposable
Linux VM:

```sh
sudo ./pipe-monitor
sudo ./pipe-monitor --output pipes.log
```

The documented runtime target is x86_64 Linux 5.8 or newer. Linux 5.8 is the
minimum because the implementation uses ring-buffer maps. The code does not
require target-kernel BTF.

The README and
[VM validation skill](./.github/skills/linux-ebpf-vm-validation/SKILL.md)
document prerequisites and the disposable QEMU/KVM test workflow.

## Validation history

- Clean builds with `make` succeeded during development, including after the
  summary-output changes.
- Runtime testing was performed in a disposable Ubuntu 26.04 x86_64 VM with
  kernel `7.0.0-34-generic` and BTF available. The Linux 5.8 minimum has not
  been tested.
- VM workloads exercised Python-created anonymous pipes and a Bash-to-`cat`
  pipeline. The monitor reported the Python creator and parent, and associated
  the shell pipeline with a Bash writer and `cat` reader.
- The summary-output validation exited successfully. Its output contained
  `pipe_summary` / `pipe_connection` records without raw FD or stage fields;
  a check confirmed that the Bash-to-`cat` pipe had one writer and one reader.
- `close_range()` and shared descriptor-table tracking via `CLONE_FILES` have
  been removed. The current helper does not attach to `close_range` tracepoints
  and models clone-like children as independent descriptor-table copies.
- VM tests used the bundled validation script, a copy-on-write guest overlay,
  and guest-side root privileges. Runtime behavior has not been checked on
  the development host or on Linux 5.8.

## Known limitations

- Only anonymous `pipe()` / `pipe2()` pipes are handled. Unix-domain
  `SCM_RIGHTS`, named FIFOs, and descriptor state created before the monitor
  starts are not tracked.
- `close_range()` is not monitored, and `CLONE_FILES` shared descriptor-table
  changes are not tracked; clone-like children are modeled with copied
  descriptor state.
- Endpoint identification is based on stdin/stdout wiring, not actual data
  transfer. Other file-descriptor arrangements may be tracked internally but
  are not reported as reader/writer connections.
- Procfs metadata is best-effort and can race process exit or PID reuse.
- Highly concurrent fork/clone and child descriptor activity can race
  asynchronous event consumption. Ring-buffer or pending-map exhaustion and
  user-memory read failures can also make correlation incomplete.
- PID interpretation across namespaces and compatibility with kernels older
  than Linux 5.8 have not been validated.
- The summary output is plaintext rather than JSONL and is intended as a
  first-stage representation; a graph or other visualization can be added
  later without changing the underlying pipe and connection concepts.

## Conversation history at a glance

The project began with the staged goal of detecting pipe creation, identifying
the creator, finding processes connected to both ends, and correlating the
events in user space. The implementation grew to cover descriptor duplication,
fork/clone inheritance, shared FD tables, exec, and process metadata; shared
FD-table support was later removed. A
temporary heuristic filter for process names containing `sh` and its `--all`
override were later removed at the user's request because process-name
filtering was inaccurate. The output then evolved from verbose event lines to
deduplicated per-pipe plaintext summaries, retaining FDs only in internal
tracking.
