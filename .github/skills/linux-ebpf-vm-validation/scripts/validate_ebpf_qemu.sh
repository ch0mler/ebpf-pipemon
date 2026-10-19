#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage:
  bash ./scripts/validate_ebpf_qemu.sh \
    --image GUEST.qcow2 --ssh-key PRIVATE_KEY --guest-user USER \
    --helper PATH [--results DIR] [--memory MB] [--cpus COUNT] \
    [--ssh-port PORT] [--no-sudo] [-- COMMAND_ARGS...]

Run a built eBPF helper inside a disposable QEMU/KVM guest.

The guest image must be a preconfigured qcow2 image with SSH enabled, the
provided key authorized for USER, and (unless --no-sudo is used) passwordless
sudo for the guest user. The guest needs BTF and the helper's kernel features.
The host must have usable /dev/kvm and the matching qemu-system binary.

The base image is never modified: each run uses a qcow2 overlay under RESULTS.
Guest root privileges are used only inside the guest. Results and logs are
preserved; this script does not delete the results directory.

Options:
  --image PATH       Preconfigured qcow2 guest base image (required)
  --ssh-key PATH     Private key matching an authorized guest key (required)
  --guest-user USER  Guest SSH username (required)
  --helper PATH      Built helper executable for the guest architecture (required)
  --results DIR      Results directory (default: ./ebpf-qemu-results-TIMESTAMP)
  --memory MB        Guest memory (default: 2048)
  --cpus COUNT       Guest vCPU count (default: 2)
  --ssh-port PORT    Host loopback SSH forwarding port (default: auto-select)
  --no-sudo          Run the helper as guest user without sudo
  -h, --help         Show this help
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

image=""
ssh_key=""
guest_user=""
helper=""
results=""
memory=2048
cpus=2
ssh_port=""
use_sudo=1
declare -a helper_args=()

while (($#)); do
    case "$1" in
        --image|--ssh-key|--guest-user|--helper|--results|--memory|--cpus|--ssh-port)
            (($# >= 2)) || fail "Missing value for $1"
            option="$1"
            value="$2"
            shift 2
            case "$option" in
                --image) image="$value" ;;
                --ssh-key) ssh_key="$value" ;;
                --guest-user) guest_user="$value" ;;
                --helper) helper="$value" ;;
                --results) results="$value" ;;
                --memory) memory="$value" ;;
                --cpus) cpus="$value" ;;
                --ssh-port) ssh_port="$value" ;;
            esac
            ;;
        --no-sudo)
            use_sudo=0
            shift
            ;;
        --)
            shift
            helper_args=("$@")
            break
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "Unknown option: $1"
            ;;
    esac
done

[[ -n "$image" ]] || fail "--image is required"
[[ -n "$ssh_key" ]] || fail "--ssh-key is required"
[[ -n "$guest_user" ]] || fail "--guest-user is required"
[[ -n "$helper" ]] || fail "--helper is required"
[[ -f "$image" && -r "$image" ]] || fail "Guest image is missing or unreadable: $image"
[[ -f "$ssh_key" && -r "$ssh_key" ]] || fail "SSH key is missing or unreadable: $ssh_key"
[[ -f "$helper" && -r "$helper" && -x "$helper" ]] || fail "Helper must be a readable executable: $helper"
[[ "$memory" =~ ^[1-9][0-9]*$ ]] || fail "--memory must be a positive integer"
[[ "$cpus" =~ ^[1-9][0-9]*$ ]] || fail "--cpus must be a positive integer"

if [[ -z "$results" ]]; then
    results="./ebpf-qemu-results-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p -- "$results"
results="$(cd -- "$results" && pwd -P)"

image="$(cd -- "$(dirname -- "$image")" && pwd -P)/$(basename -- "$image")"
ssh_key="$(cd -- "$(dirname -- "$ssh_key")" && pwd -P)/$(basename -- "$ssh_key")"
helper="$(cd -- "$(dirname -- "$helper")" && pwd -P)/$(basename -- "$helper")"

[[ -w "$results" ]] || fail "Results directory is not writable: $results"
command -v qemu-img >/dev/null 2>&1 || fail "qemu-img is required; run the project prerequisite installer"
command -v ssh >/dev/null 2>&1 || fail "ssh client is required"
command -v scp >/dev/null 2>&1 || fail "scp client is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] ||
    fail "/dev/kvm is missing or inaccessible; refusing to use host execution or software emulation"

case "$(uname -m)" in
    x86_64|amd64) qemu_bin="qemu-system-x86_64" ;;
    aarch64|arm64) qemu_bin="qemu-system-aarch64" ;;
    *) fail "Unsupported QEMU host architecture: $(uname -m)" ;;
esac
command -v "$qemu_bin" >/dev/null 2>&1 || fail "$qemu_bin is required"

if [[ -n "$ssh_port" ]]; then
    [[ "$ssh_port" =~ ^[0-9]+$ ]] && ((ssh_port >= 1024 && ssh_port <= 65535)) ||
        fail "--ssh-port must be an integer from 1024 to 65535"
else
    ssh_port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)" || fail "Could not select a free SSH port (python3 is required)"
fi

for file in \
    "$results/guest-overlay.qcow2" \
    "$results/qemu-img.log" \
    "$results/qemu-serial.log" \
    "$results/qemu-debug.log" \
    "$results/guest-environment.txt" \
    "$results/helper-output.log" \
    "$results/helper-exit-code.txt" \
    "$results/guest-kernel-diagnostics.log" \
    "$results/guest-monitor.log" \
    "$results/transfer.log" \
    "$results/environment.txt" \
    "$results/run-status.txt" \
    "$results/known_hosts"; do
    [[ ! -e "$file" ]] || fail "Refusing to overwrite existing test artifact: $file"
done

qemu_img_format="$(qemu-img info --output=json "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')" ||
    fail "Could not inspect guest image format"
[[ "$qemu_img_format" == "qcow2" ]] ||
    fail "Guest image must be qcow2 (found $qemu_img_format); convert or prepare a qcow2 test image first"

qemu-img create -f qcow2 -F qcow2 -b "$image" "$results/guest-overlay.qcow2" \
    >"$results/qemu-img.log" 2>&1 || fail "Could not create disposable image overlay; see $results/qemu-img.log"

guest_host="127.0.0.1"
ssh_opts=(
    -i "$ssh_key"
    -p "$ssh_port"
    -o BatchMode=yes
    -o ConnectTimeout=3
    -o StrictHostKeyChecking=accept-new
    -o UserKnownHostsFile="$results/known_hosts"
    -o LogLevel=ERROR
)
scp_opts=(
    -i "$ssh_key"
    -P "$ssh_port"
    -o BatchMode=yes
    -o ConnectTimeout=3
    -o StrictHostKeyChecking=accept-new
    -o UserKnownHostsFile="$results/known_hosts"
    -o LogLevel=ERROR
)
qemu_pid=""
helper_ssh_pid=""
guest_path="/tmp/ebpf-validation-helper"
run_status=1
started_at="$(date --iso-8601=seconds)"

qemu_cleanup() {
    local status=$?
    trap - EXIT INT TERM

    if [[ -n "$helper_ssh_pid" ]] && kill -0 "$helper_ssh_pid" 2>/dev/null; then
        kill "$helper_ssh_pid" 2>/dev/null || true
        wait "$helper_ssh_pid" 2>/dev/null || true
    fi

    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        for _ in {1..10}; do
            kill -0 "$qemu_pid" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$qemu_pid" 2>/dev/null; then
            kill -KILL "$qemu_pid" 2>/dev/null || true
        fi
        wait "$qemu_pid" 2>/dev/null || true
    fi

    printf 'Validation finished at %s (exit %s)\n' "$(date --iso-8601=seconds)" "$status" \
        >>"$results/run-status.txt"
    exit "$status"
}
trap qemu_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Started %s\n' "$started_at" >"$results/run-status.txt"
printf 'Host: %s\n' "$(uname -a)" >"$results/environment.txt"
printf 'Image: %s\nArchitecture: %s\nQEMU: %s\nSSH port: %s\n' \
    "$image" "$(uname -m)" "$qemu_bin" "$ssh_port" >>"$results/environment.txt"

"$qemu_bin" \
    -name ebpf-validation \
    -machine accel=kvm \
    -cpu host \
    -smp "$cpus" \
    -m "$memory" \
    -drive "file=$results/guest-overlay.qcow2,if=virtio,format=qcow2" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial "file:$results/qemu-serial.log" \
    -monitor none \
    -no-reboot \
    >"$results/qemu-debug.log" 2>&1 &
qemu_pid=$!
sleep 1
kill -0 "$qemu_pid" 2>/dev/null ||
    fail "QEMU failed to start; see $results/qemu-debug.log and $results/qemu-serial.log"

printf 'QEMU PID: %s\nGuest SSH: %s@%s:%s\nResults: %s\n' \
    "$qemu_pid" "$guest_user" "$guest_host" "$ssh_port" "$results"

ssh_ready=0
for _ in {1..120}; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        fail "QEMU exited during guest boot; inspect $results/qemu-debug.log and $results/qemu-serial.log"
    fi
    if ssh "${ssh_opts[@]}" "$guest_user@$guest_host" true 2>/dev/null; then
        ssh_ready=1
        break
    fi
    sleep 2
done
((ssh_ready == 1)) || fail "Guest SSH did not become ready within 240 seconds; inspect serial and QEMU logs"

if ((use_sudo)); then
    ssh "${ssh_opts[@]}" "$guest_user@$guest_host" \
        "sudo -n sh -c 'set -eu; uname -a; cat /etc/os-release 2>/dev/null || true; command -v bpftool >/dev/null; if test -r /sys/kernel/btf/vmlinux; then echo BTF=present; else echo BTF=missing; exit 20; fi'" \
        >"$results/guest-environment.txt" 2>&1 ||
        fail "Guest BTF check or passwordless sudo failed; see $results/guest-environment.txt"
else
    ssh "${ssh_opts[@]}" "$guest_user@$guest_host" \
        "sh -c 'set -eu; uname -a; cat /etc/os-release 2>/dev/null || true; command -v bpftool >/dev/null; if test -r /sys/kernel/btf/vmlinux; then echo BTF=present; else echo BTF=missing; exit 20; fi'" \
        >"$results/guest-environment.txt" 2>&1 ||
        fail "Guest BTF check failed; see $results/guest-environment.txt"
fi

scp "${scp_opts[@]}" "$helper" "$guest_user@$guest_host:$guest_path" \
    >"$results/transfer.log" 2>&1 ||
    fail "Could not transfer helper to guest; see $results/transfer.log"

printf 'Helper: %s\nArgument count: %s\n' "$helper" "${#helper_args[@]}" \
    >>"$results/environment.txt"

quote_remote_arg() {
    local escaped=${1//\'/\'\\\'\'}
    printf "'%s'" "$escaped"
}

remote_cmd="chmod 0755 $(quote_remote_arg "$guest_path") && "
if ((use_sudo)); then
    remote_cmd+="sudo -n "
fi
remote_cmd+="$(quote_remote_arg "$guest_path")"
for arg in "${helper_args[@]}"; do
    remote_cmd+=" $(quote_remote_arg "$arg")"
done

ssh "${ssh_opts[@]}" "$guest_user@$guest_host" "$remote_cmd" \
    >"$results/helper-output.log" 2>&1 &
helper_ssh_pid=$!

while kill -0 "$helper_ssh_pid" 2>/dev/null; do
    {
        printf '\n--- %s ---\n' "$(date --iso-8601=seconds)"
        if ((use_sudo)); then
            ssh "${ssh_opts[@]}" "$guest_user@$guest_host" \
                "sudo -n sh -c 'if command -v bpftool >/dev/null 2>&1; then bpftool prog show; bpftool map show; bpftool link show; fi'" \
                2>&1
        else
            ssh "${ssh_opts[@]}" "$guest_user@$guest_host" \
                "sh -c 'if command -v bpftool >/dev/null 2>&1; then bpftool prog show; bpftool map show; bpftool link show; fi'" \
                2>&1
        fi
    } >>"$results/guest-monitor.log" || true
    sleep 2
done

set +e
wait "$helper_ssh_pid"
run_status=$?
set -e
printf '%s\n' "$run_status" >"$results/helper-exit-code.txt"

if ((use_sudo)); then
    ssh "${ssh_opts[@]}" "$guest_user@$guest_host" \
        "sudo -n sh -c 'set +e; uname -a; dmesg --ctime 2>&1 | tail -n 400'" \
        >"$results/guest-kernel-diagnostics.log" 2>&1 || true
else
    ssh "${ssh_opts[@]}" "$guest_user@$guest_host" \
        "sh -c 'set +e; uname -a; dmesg --ctime 2>&1 | tail -n 400'" \
        >"$results/guest-kernel-diagnostics.log" 2>&1 || true
fi

if ((run_status == 0)); then
    printf 'PASS: helper exited successfully.\n'
    printf 'Guest environment: %s\nHelper output: %s\nKernel diagnostics: %s\n' \
        "$results/guest-environment.txt" "$results/helper-output.log" "$results/guest-kernel-diagnostics.log"
else
    printf 'FAIL: helper exited with status %s.\n' "$run_status" >&2
    printf 'Review %s and %s\n' "$results/helper-output.log" "$results/guest-kernel-diagnostics.log" >&2
fi

exit "$run_status"
