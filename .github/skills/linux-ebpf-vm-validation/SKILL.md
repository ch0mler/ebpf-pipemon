---
name: linux-ebpf-vm-validation
description: Validate Linux eBPF programs in disposable test VMs with reproducible setup, teardown, kernel/verifier diagnostics, and runtime monitoring.
---

# Linux eBPF VM validation

Use this skill to build a repeatable, isolated runtime test environment for eBPF programs. Run programs inside a disposable Linux guest rather than attaching them to the developer's host. Make setup, test execution, monitoring, and teardown straightforward and explicit.

## Plan the test environment

1. Read the project build/run documentation and identify the helper's minimum and tested kernel versions, architecture, required BTF/configuration, program types, attach points, privileges, dependencies, and test workload.
2. Choose a guest kernel that represents the compatibility target. For compatibility testing, use a small matrix of kernel versions, including the minimum supported version and a current supported version; do not test only against the development host's kernel.
3. Check the host's available virtualization tools and permissions before choosing an implementation. Prefer QEMU/KVM with a reproducible, disposable guest; use libvirt or another established VM manager when already available and suitable. Do not install a hypervisor, modify host configuration, or assume nested virtualization without authorization.
4. Prefer a minimal Linux image with a known kernel, architecture, and BTF availability. Record the image source and version. Provision dependencies and test artifacts reproducibly, preferably through cloud-init or the project's existing provisioning mechanism.
5. Decide how the guest receives the program: build inside the guest when the toolchain is a test subject, otherwise build on the host and transfer the artifact. Keep build-host requirements separate from runtime guest requirements.

If a suitable VM cannot be used, report the blocker and ask how to proceed. Never substitute container-based or host-based execution for VM validation; container isolation does not provide a separate kernel, and host execution would attach the program to the developer's machine.

## Make setup and teardown easy

Provide project-appropriate, documented commands or scripts for creating/starting the test guest, running validation, collecting results, and stopping/removing the guest. Keep commands safe to repeat and make their effects visible before execution.

To create the supported preconfigured guest, obtain an Ubuntu x86_64 cloud image with cloud-init and use the bundled [guest image builder](./scripts/create_ebpf_test_image.sh):
I
```sh
bash .github/skills/linux-ebpf-vm-validation/scripts/create_ebpf_test_image.sh \
  --base-image /path/to/ubuntu-cloud-image-amd64.img \
  --output /path/to/test-guest.qcow2 \
  --guest-user ebpf-test \
  --ssh-key /path/to/private-key
```

The script copies rather than modifies the base image, provisions the named account with the matching SSH public key and passwordless sudo, installs OpenSSH and `bpftool`, boots the guest under KVM, and verifies Ubuntu, BTF, SSH, sudo, and reports the kernel's BPF feature probe before saving a standalone qcow2 image. It currently supports x86_64 hosts and expects a cloud-init-enabled Ubuntu qcow2 image. Review its `--help` for disk, memory, CPU, and port options.

- The host needs QEMU/KVM, `/dev/kvm` access, `cloud-localds` (provided by `cloud-image-utils` on Debian/Ubuntu), SSH client tools, and sufficient disk space. The script does not use host sudo, install packages, download images, or modify host settings.
- Choose an Ubuntu cloud image whose kernel meets the helper's minimum kernel and BTF requirements. The builder fails if BTF is absent; it does not change the guest kernel to make requirements pass.
- Review `guest-verification.txt` in the adjacent logs directory and confirm the BPF feature probe covers the helper's program types, maps, and helpers. The probe is diagnostic, not a substitute for loading and validating the helper in the guest.
- The guest contains passwordless sudo for the configured account and authorizes the corresponding public key. Protect the resulting image as a privileged test environment; do not distribute it casually.
- The completed image is written only to a previously unused output path. Build logs and metadata are retained in the adjacent `<output>.logs` directory. Failed builds preserve their uniquely named temporary directory for diagnosis.

For a preconfigured qcow2 guest that meets the requirements below, use the bundled [QEMU validation script](./scripts/validate_ebpf_qemu.sh) rather than writing an ad hoc launcher. Invoke it with `bash` from the project root:

```sh
bash .github/skills/linux-ebpf-vm-validation/scripts/validate_ebpf_qemu.sh \
  --image /path/to/test-guest.qcow2 \
  --ssh-key /path/to/private-key \
  --guest-user ebpf-test \
  --helper /path/to/built-helper \
  -- [helper arguments]
```

The script expects QEMU/KVM and `/dev/kvm` usable by the host user, a same-architecture qcow2 guest image with SSH server and `bpftool`, an authorized SSH key, and passwordless guest `sudo` by default. It checks for guest BTF, creates a copy-on-write overlay, forwards SSH only on host loopback, transfers and runs the helper, records guest metadata/output and periodic BPF program/map/link snapshots, captures kernel diagnostics, and stops its QEMU process on exit. `--no-sudo` is available only if the guest user already has the required BPF privileges. Review `--help` before invocation; helper arguments follow `--`.

- The script does not download, build, or configure guest images, change host settings, or install prerequisites. Prepare and trust the guest image separately.
- It requires the host and helper architectures to match and currently targets x86_64 or aarch64 hosts.
- It preserves the qcow2 overlay and results in a dedicated results directory. Inspect the output and clean up only that specific directory when no longer needed.
- Do not treat a zero helper exit status alone as proof of functional correctness; validate expected events and state using the project's workload and assertions.

- Store VM state, disk overlays, logs, and temporary artifacts in a clearly named, dedicated test directory, never in an ambiguous system or project path.
- Prefer immutable base images and disposable copy-on-write overlays or snapshots. Do not overwrite user VM images, reuse unrelated VMs, or delete paths outside the specific test environment.
- Make guest provisioning deterministic: pin image/kernel and package inputs where practical, install only needed tools, copy in the helper and tests, and report failed provisioning steps.
- Expose guest access and lifecycle details, including VM name/process or manager identifier, SSH/console method, host/guest artifact paths, and how to stop the guest.
- Ensure cleanup runs after success, failure, interruption, and partial startup. Stop/detach the test program before shutting down the guest, then remove only the explicitly created disposable state when requested. Preserve logs and test output unless the user asks to remove them.
- Do not hide setup failures with broad fallbacks. If required host capabilities, kernel support, or permissions are missing, report them and stop before destructive or privileged changes.

Do not run commands requiring host `sudo`, install system packages, alter network/firewall/boot settings, or download/run untrusted guest images without the user's authorization. Guest root privileges may be used for the test when necessary, but keep them inside the disposable guest and document why they are needed.

## Validate inside the guest

1. Record guest OS, kernel release, architecture, relevant kernel configuration, and whether `/sys/kernel/btf/vmlinux` is available. Check that required helpers, map types, program types, attach points, and capabilities are supported before the test; distinguish an unsupported environment from a program failure.
2. Run the documented helper and workload. Cover normal behavior, error paths, attach/detach lifecycle, shutdown, and cleanup. Exercise realistic event rates and overload conditions when relevant.
3. Capture compiler output, load errors, and verifier logs. On load failures, preserve the full diagnostic context and report the program type, kernel version, and relevant feature checks.
4. Check runtime behavior using the project's own observable output and, where appropriate, `bpftool` to inspect program, map, and link state. Confirm expected events and state, detect event loss or malformed records, and verify programs/links are detached after the test.
5. Monitor the guest while tests run: retain timestamped test output, guest kernel log messages relevant to BPF, resource use when material, and a clear pass/fail/skip result. Prefer guest serial/console and guest-side logs so diagnostics survive SSH loss or a crashed helper. Do not treat `bpf_printk`/trace pipe output as the production event transport.
6. Collect logs and environment metadata to a known host-side results directory before destroying the guest. Avoid collecting unrelated guest data or secrets.

Do not claim runtime or verifier validation from a successful build alone. Separate pass, fail, and skip outcomes; explain missing privileges or infrastructure, and include exact reproduction commands.

## Deliverables

Document:

- Host prerequisites (hypervisor, hardware virtualization, permissions, disk space, and network access if needed).
- Guest image and kernel versions, architecture, BTF/configuration, and required privileges/capabilities.
- Exact setup, run, monitor/log collection, and teardown commands.
- Which test cases ran and their results, including unsupported/skipped kernel configurations.
- Where artifacts and logs are stored, what cleanup removes, and any known isolation limitations.

Prefer a small, inspectable workflow over a complex VM framework. Keep tests and provisioning in the project's existing conventions when available, and do not commit VM disks, credentials, private keys, or generated test logs.
