# Pipe Monitor

Pipe Monitor is an eBPF-based Linux tool for identifying anonymous pipes (`|`)
and the processes with pipe ends connected to their standard input or output.

## Learning Process

Since this helper has been 100% vibe coded so far, I'm still understanding some of the initial design choices that Copilot has made. This section attempts to document my thought process while learning different pieces. 

### Additional hooks

I initially thought only `pipe()` would be appropriate to monitor, but `pipe2()`, `CLONE_FILES`, and `close_range()` were also chosen for inspection. Under what scenarios are each of these techniques used in setting up pipes, and why would each technique be used over each other?

#### pipe

Function Signature ([Source](www.man7.org/linux/man-pages/man2/pipe.2.html))
```
int pipe(int pipefd[2])
```

Quick Description

```
creates a pipe, a unidirectional data channel that can be
       used for interprocess communication.
```

Returns a read-end fd and a write-end fd for 2 processes to comunicate.
As opposed to named pipes (FIFO objects), these objects don't have a filesystem path even though file descriptors are created to interact with them too.

#### pipe2

Function Signature ([Source](www.man7.org/linux/man-pages/man2/pipe.2.html))
```
int pipe2(int pipefd[2], int flags)
```

It sounds like this is extremely similar to `pipe()` but with the addition of some flags. Based on the pipe manual page:

```
If flags is 0, then pipe2() is the same as pipe().
  ...
* O_CLOEXEC: close-on-exec flag w/ same behavior as open() call
* O_DIRECT: (3.4+) read/write data in pipe as packets instead of raw bitstreams
* O_NONBLOCK: opened in non-blocking mode, so no waiting for reads/writes
* O_NOTIFICATION_PIPE: (5.8+) kernel notifications added to pipes
```

#### CLONE_FILES

#### close_range()

## Open Questions

**Q**: If pipes aren't on the filesystem, where are they?

**A**: Based on [this Oracle post](https://blogs.oracle.com/linux/pipe-and-splice), it looks like pipes are basically a linked list of memory pages where head points to the location of the next write, and the tail points to the location of the next read.
Interestingly, this also covers the `splice` call, which has been a big focus for CVEs over the last year. I think this would be helpful if trying to inspect the contents of a pipe, but for our purposes - relating two processes as intending to communicate - it is likely not needed.

**Q**: Why do both `pipe()` and `pipe2()` need to be monitored?

**A**: Functionally, they are nearly identical except one modifies the attributes of the pipe or its file descriptors. Newer versions of the kernel may use `pipe2()` instead of the original `pipe()` function. TBD which one shell operations use.

**Q**: When would `CLONE_FILES` be used in a normal operation?

**A**: 

**Q**: How is `close_range()` intended to be used, and how is it related to pipes?

**A**: 

---

## Current milestone

The prototype reports summaries for successful `pipe()` and `pipe2()` calls
and tracks the resulting descriptors through fork-like process creation,
shared descriptor tables (`CLONE_FILES`), common descriptor-duplication calls,
and `close_range()`. It records a process when a tracked pipe end is connected
to stdin or stdout, and uses process-exec events to identify the program that
inherits those standard descriptors. This allows it to identify the programs
at the two ends of common shell pipelines such as `curl ... | bash`.

It does not observe actual reads or writes, so a reported endpoint means a
process has the pipe end connected to stdin/stdout, not that it transferred
data. Named FIFOs are out of scope.

The user-space helper also reads `/proc/<pid>` to report executable paths,
command lines, UIDs, and parent PIDs. Pipe-summary records include the
creator's parent name, executable, and command line; connection records
include the connected process's name, executable, and command line. These
attributes may be unavailable if a process exits before the event is handled,
or if procfs permissions restrict access. Command lines can include secrets
provided as process arguments; protect collected output accordingly.

Build on a Linux x86_64 host:

```sh
make
```

Transfer `build/pipe-monitor` to a disposable Linux VM. Inside the guest, run
the helper as root (or with the required eBPF capabilities). Pipe creation
events are reported for all processes; the helper does not filter events by
process type or name:

```sh
sudo ./pipe-monitor
```

By default, the helper prints pipe summaries to standard output. Use
`--output FILE` (or `-o FILE`) to save the plaintext summaries in a file
instead. The file is created or truncated when monitoring starts:

```sh
sudo ./pipe-monitor --output pipes.log
```

Process lifecycle and descriptor events are also observed for all processes
because they are needed to follow pipes through forks, descriptor changes, and
exec. Match `pipe_summary` and `pipe_connection` records by `pipe_id`. Each
pipe has one summary record with its creator and parent, followed by one
connection record per process and direction. Repeated observations during
descriptor setup and exec are collapsed. File descriptors remain tracked
internally but are omitted from the summary. A summary is written when all
tracked descriptors for its pipe are closed, or when the monitor exits,
whichever comes first. For example:

```text
pipe_summary pipe_id=1 creator_pid=4100 creator_comm="bash" creator_exe="/usr/bin/bash" creator_cmdline="bash -c curl | bash" parent_pid=4000 parent_comm="sh" parent_exe="/usr/bin/sh" parent_cmdline="sh -c ..." connections=2
pipe_connection pipe_id=1 side=writer pid=4101 comm="curl" exe="/usr/bin/curl" cmdline="curl https://example.invalid/script"
pipe_connection pipe_id=1 side=reader pid=4102 comm="bash" exe="/usr/bin/bash" cmdline="bash"
```

Connections describe a pipe end connected to stdin (`reader`) or stdout
(`writer`), not proof that data was transferred. A pipe still open when the
monitor exits is summarized during shutdown. The helper also reports
pending-map, user-memory-read, command-name, and ring-buffer reservation
failures to standard error when it exits.

## Runtime support

- **Target:** x86_64 Linux 5.8 or newer. The current implementation has been
  runtime-tested in a disposable Ubuntu x86_64 VM running Linux
  `7.0.0-34-generic`; the 5.8 minimum has not yet been tested. Other
  architectures and older kernels are not supported.
- **Kernel features:** syscall tracepoints for `pipe`, `pipe2`, `dup`, `dup2`,
  `dup3`, `fcntl`, `close`, `fork`, `vfork`, `clone`, `clone3`, `execve`,
  `execveat`, `exit`, and `exit_group`; BPF tracepoint programs; hash and
  per-CPU array maps; and BPF ring buffers. Linux 5.8 is the minimum because
  the implementation uses ring-buffer maps. The `close_range` syscall is
  supported when its tracepoints exist (Linux 5.9+); otherwise those optional
  probes are disabled with a startup warning.
- **BTF:** target-kernel BTF is not currently required. This prototype reads
  only the syscall tracepoint context layout and does not access kernel-internal
  types or use CO-RE relocations.
- **Privileges/configuration:** eBPF syscall access and tracepoint attachment
  must be enabled by the kernel. Run as root for the initial prototype;
  narrower capability requirements have not yet been validated across
  distributions.
- **Loss and semantics:** successful syscalls are emitted asynchronously.
  Events may be lost if the pending map fills, the user-memory read fails, or
  the ring buffer is full; these cases are counted and printed at shutdown.
  Userspace correlates the events by process ID and process-local descriptor.
- **Known limitations:** `close_range()` and `CLONE_FILES` are tracked; their
  behavior has been exercised in the disposable VM. Unusual descriptor-passing
  mechanisms such as Unix-domain `SCM_RIGHTS`, namespace-specific PID
  interpretation, and descriptor activity before the monitor starts are not
  handled. Fork events are correlated from successful fork/clone syscall
  exits; highly concurrent workloads can race event consumption and child
  descriptor operations. The helper observes fork/clone, exec, and exit
  syscall events system-wide to correlate process state. No process-name or
  process-type filter is applied.

## Build host

Build on Linux x86_64 with Clang/LLVM providing the BPF target, `bpftool`,
libbpf development headers/library, `pkg-config`, and a C compiler. The build
generates the BPF object, libbpf skeleton, and helper under `build/`; generated
files are not checked in. The first prototype has been built with Clang 18,
bpftool 7.8, and libbpf 1.3; older toolchain versions have not been tested.
Cross-compilation is not supported.

## Development and testing prerequisites

For runtime validation, build the helper on a Linux development host and run it
only inside a disposable Linux virtual machine. Do not run the eBPF helper on
the development host or use a container as a substitute for the VM; containers
share the host kernel.

### Development host

- A Linux x86_64 machine with enough disk space and memory for the toolchain,
  guest image, and test artifacts.
- The build toolchain listed above.
- Network access to obtain documented toolchain packages and a guest image,
  unless these dependencies have already been provisioned.

On Debian/Ubuntu-family hosts, install the initial host dependencies with:

```sh
bash ./install_prereqs.sh
```

The script installs the eBPF build toolchain, QEMU, and cloud-image tooling
through `apt-get`; it does not download a guest image, configure KVM
permissions, or build or install Pipe Monitor. Preview the package list first
with `bash ./install_prereqs.sh --dry-run`. Other distributions are not
currently supported by this installer.

### VM-based runtime testing

- QEMU/KVM or another supported VM manager, with hardware virtualization
  available and permission to use it. Do not install virtualization software or
  change host settings without authorization.
- A disposable x86_64 Linux guest running kernel 5.8 or newer. Kernel BTF is
  not required by the current prototype, but the guest must meet the helper's
  documented configuration and privilege requirements. The bundled VM
  validation script additionally requires BTF as an environment check.
- Permission to load and attach eBPF programs inside the guest, typically
  through guest root or the specific capabilities required by the program
  type. Host privileges are not a substitute.
- Enough disk space for the guest image, disposable VM state, and collected
  test logs.

Use the [VM validation guide](./.github/skills/linux-ebpf-vm-validation/SKILL.md)
for guest image preparation and runtime validation. It includes scripts to
create a preconfigured guest from a local Ubuntu cloud image and run the built
helper in QEMU/KVM, with monitoring, diagnostics, and teardown guidance. Do not
run eBPF helpers directly on the development host or in a container.
