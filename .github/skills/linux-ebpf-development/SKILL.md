---
name: linux-ebpf-development
description: Design, implement, build, and validate new Linux eBPF projects using modern kernel interfaces, libbpf, CO-RE, and verifier-safe patterns.
---

# Greenfield Linux eBPF development

Use this skill for new eBPF projects, not to preserve or extend legacy implementation choices. Start with modern upstream Linux eBPF interfaces and tooling. Establish the intended deployment kernel range and architecture before choosing features; do not promise compatibility with kernels that lack the project's required BTF, helpers, program types, or map types.

## Choose the modern baseline

1. Define the event or data to observe, its semantics, expected event rate, loss tolerance, target architectures, and minimum supported kernel.
2. For a general-purpose Linux application, default to C eBPF with upstream libbpf, CO-RE, BTF, and a `bpftool`-generated skeleton. Keep the loader in user space. If the project is in Rust, use `libbpf-rs` with `libbpf-cargo` rather than writing raw libbpf bindings by hand.
3. Require kernel BTF for CO-RE deployments and use `vmlinux.h` generated from BTF as the kernel type source. CO-RE relocates type and field accesses; it does not make unavailable hooks, helpers, or fields magically portable. Guard genuinely optional fields or features and set a support floor that includes every feature used.
4. Use a current Clang/LLVM BPF target and a reproducible build that produces BTF/debug information and the skeleton from the BPF object. Pin and document build dependencies; do not require compilation on the deployment host.
5. Prefer BPF links for attachment lifecycle where supported. Keep link and object ownership explicit so normal exit and error paths detach programs and release resources.

For a production application, do not start from BCC, `bpftrace`, perf-event buffers, legacy attachment mechanisms, or hand-written syscall loaders as the default. These can still be appropriate for a focused tracing script, a prototype, or a concrete requirement the modern application defaults cannot meet; document the choice and tradeoff. Do not add fallback implementations for obsolete kernels unless the user explicitly requires them.

## Specify system requirements

Before implementation, determine and document separate minimum requirements for building and running the helper. Do not report a single vague "Linux required" prerequisite:

- **Build host:** supported operating systems and architectures; required compiler/toolchain versions (including Clang/LLVM's BPF target), libbpf and bpftool or other generator versions, development headers/libraries, and any build system or language toolchain. State whether cross-compilation is supported and whether generated artifacts are checked in or produced during the build.
- **Runtime target:** minimum and tested Linux kernel versions and architectures; required kernel configuration and BTF availability; required program types, attach points, helpers, kfuncs, and map types; filesystem or mount prerequisites where applicable; and required capabilities or privileges for loading and attaching. State whether CO-RE needs target-kernel BTF and what happens when it is absent.
- **Operational constraints:** required resources or limits such as locked memory where relevant, expected permissions, container/namespace limitations, and external dependencies. Distinguish hard requirements from optional features and tested-but-not-guaranteed configurations.

Derive the minimum kernel from the least-available feature actually used, not from the newest development or test machine. Verify requirements against the target kernel range, and give users actionable checks or diagnostics for missing prerequisites. Update the README or equivalent setup documentation and the build/run instructions whenever requirements change.

## Select hooks and data paths

- Use the narrowest hook that observes the required event correctly. Prefer tracepoints when their documented event fields and semantics suffice. Use typed fentry/fexit tracing when the target kernels provide suitable BTF and the required function hook is appropriate. Treat kprobes and kernel-internal fields as less stable choices; use them only when no better supported interface works and document the kernel/version sensitivity.
- For event delivery, prefer a BPF ring buffer when the chosen kernel baseline supports it (Linux 5.8+). It provides a shared multi-producer stream and preserves reservation order across CPUs. Size it for expected bursts, handle reservation failures, and expose event-loss metrics or clear diagnostics. Use perf-event buffers only for a concrete compatibility or per-CPU delivery requirement.
- Define map key/value layouts and ownership explicitly. Use fixed-width integer types and make padding/alignment deliberate. Choose map type, capacity, per-CPU behavior, update flags, and full-map behavior based on measured semantics and workload.
- Specify whether identifiers mean task/TID, process/TGID, namespace-relative ID, or cgroup identity. Account for concurrent events, event ordering, task exit, identifier reuse, and incomplete entry/exit pairs.
- Keep the kernel/user event ABI small and versionable. Validate record size and fields in user space; make dropped, malformed, and unknown-version events observable rather than silently accepting them.

## Write verifier-safe BPF

- Keep control flow and memory access easy for the verifier to prove. Bound loops and all variable-length reads; validate pointers, lengths, and helper results before use.
- Use only helpers, kfuncs, map operations, and context fields supported by the selected program type and minimum kernel. Do not infer availability from the development machine.
- Use CO-RE access patterns for kernel types. Check optional field existence where needed, and handle failed reads explicitly. Never retain kernel pointers beyond their valid lifetime or expose kernel addresses without a compelling, reviewed need.
- Avoid blocking, unbounded work, unsupported library calls, and excessive stack use. Keep hot-path work minimal and move complex processing to user space when practical.
- Handle ring-buffer reservation/output failure and map update failure deliberately. Ensure reserved records are committed or discarded on every path.

## Build, test, and operate

1. Build the BPF object and user-space loader from a clean checkout. Verify the generated skeleton is current and that the object contains the expected BTF/CO-RE data.
2. Run formatting, static analysis, and unit tests for event decoding, filtering, and state handling. Test malformed, truncated, unknown-version, and high-volume event streams.
3. On a representative Linux target, check kernel BTF and required feature availability, load the object, inspect verifier logs on failure, attach and detach the program, and verify observable behavior and cleanup. Never claim verifier or runtime validation unless it was actually performed.
4. Exercise overload and failure cases: ring-buffer saturation, map capacity, user-space consumer interruption, attach/load errors, and shutdown while events are arriving. Report or count loss where the design can lose events.
5. Request only the privileges needed for loading and attaching the selected program type. Document capabilities and kernel configuration requirements. Prefer a disposable VM or dedicated test host for privileged integration tests; do not silently change host-wide settings or leave persistent attachments behind.

Document the separate build-host and runtime-target requirements, supported kernel range and architecture, required BTF/configuration, build dependencies and commands, required privileges, attachment points, event semantics, loss behavior, and known limitations. If runtime testing is unavailable, state exactly which build and test checks were completed and which were not.

## References

- [Linux kernel libbpf overview](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html)
- [Linux kernel BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html)
- [libbpf-bootstrap examples](https://github.com/libbpf/libbpf-bootstrap)
