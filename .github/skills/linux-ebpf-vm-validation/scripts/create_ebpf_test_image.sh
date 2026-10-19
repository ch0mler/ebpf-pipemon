#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage:
  bash .github/skills/linux-ebpf-vm-validation/scripts/create_ebpf_test_image.sh \
    --base-image UBUNTU-CLOUD-IMAGE.qcow2 \
    --output TEST-GUEST.qcow2 --guest-user USER --ssh-key PRIVATE_KEY \
    [--memory MB] [--cpus COUNT] [--disk-size-gib SIZE] [--ssh-port PORT]

Create a standalone, preconfigured Ubuntu x86_64 qcow2 test guest. The local
base image must be an Ubuntu cloud image with cloud-init. It is never modified.
The resulting guest has OpenSSH, bpftool, the matching authorized public key, and passwordless sudo
for the specified user. It must boot with kernel BTF available.

This script uses QEMU/KVM and cloud-init but does not install host packages,
download images, change host settings, or use host sudo. It refuses to
overwrite the output image or its logs.
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

base_image=""
output=""
guest_user=""
ssh_key=""
memory=2048
cpus=2
disk_size_gib=16
ssh_port=""

while (($#)); do
    case "$1" in
        --base-image|--output|--guest-user|--ssh-key|--memory|--cpus|--disk-size-gib|--ssh-port)
            (($# >= 2)) || fail "Missing value for $1"
            option="$1"
            value="$2"
            shift 2
            case "$option" in
                --base-image) base_image="$value" ;;
                --output) output="$value" ;;
                --guest-user) guest_user="$value" ;;
                --ssh-key) ssh_key="$value" ;;
                --memory) memory="$value" ;;
                --cpus) cpus="$value" ;;
                --disk-size-gib) disk_size_gib="$value" ;;
                --ssh-port) ssh_port="$value" ;;
            esac
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

[[ -n "$base_image" ]] || fail "--base-image is required"
[[ -n "$output" ]] || fail "--output is required"
[[ -n "$guest_user" ]] || fail "--guest-user is required"
[[ -n "$ssh_key" ]] || fail "--ssh-key is required"
[[ "$guest_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "--guest-user must be a valid simple Linux username"
[[ "$memory" =~ ^[1-9][0-9]*$ ]] || fail "--memory must be a positive integer"
[[ "$cpus" =~ ^[1-9][0-9]*$ ]] || fail "--cpus must be a positive integer"
[[ "$disk_size_gib" =~ ^[1-9][0-9]*$ ]] || fail "--disk-size-gib must be a positive integer"

for tool in qemu-img cloud-localds ssh ssh-keygen python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is required; install the documented host prerequisites first"
done
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] ||
    fail "/dev/kvm is missing or inaccessible; refusing to run without KVM"
[[ "$(uname -m)" == "x86_64" ]] ||
    fail "This image builder currently supports x86_64 hosts only"
command -v qemu-system-x86_64 >/dev/null 2>&1 || fail "qemu-system-x86_64 is required"

[[ -f "$base_image" && -r "$base_image" ]] || fail "Base image is missing or unreadable: $base_image"
[[ -f "$ssh_key" && -r "$ssh_key" ]] || fail "SSH private key is missing or unreadable: $ssh_key"

ssh_key="$(cd -- "$(dirname -- "$ssh_key")" && pwd -P)/$(basename -- "$ssh_key")"
public_key_file="${ssh_key}.pub"
if [[ -r "$public_key_file" ]]; then
    read -r key_type key_data _ <"$public_key_file" || fail "Could not read SSH public key: $public_key_file"
else
    public_key="$(ssh-keygen -y -f "$ssh_key")" || fail "Could not derive public key from $ssh_key"
    read -r key_type key_data _ <<<"$public_key"
fi
[[ "$key_type" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+)$ ]] ||
    fail "Unsupported SSH public key type: ${key_type:-empty}"
[[ "$key_data" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Malformed SSH public key data"
[[ -n "$key_type" && -n "$key_data" ]] || fail "SSH public key must contain a key type and key data"

base_image="$(realpath -- "$base_image")"
output_dir="$(dirname -- "$output")"
mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
output="$output_dir/$(basename -- "$output")"
logs_dir="${output}.logs"

[[ "$output" != "$base_image" ]] || fail "Output path must differ from the base image"
[[ ! -e "$output" && ! -L "$output" ]] || fail "Refusing to overwrite existing output: $output"
[[ ! -e "$logs_dir" && ! -L "$logs_dir" ]] || fail "Refusing to overwrite existing logs directory: $logs_dir"

base_format="$(qemu-img info --output=json "$base_image" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')" ||
    fail "Could not inspect base image format"
[[ "$base_format" == "qcow2" ]] ||
    fail "Base image must be qcow2 (found $base_format)"

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
)" || fail "Could not select a free SSH port"
fi

work_dir="$(mktemp -d -- "$output_dir/.${output##*/}.build.XXXXXX")" ||
    fail "Could not create temporary build directory"
qemu_pid=""
success=0

cleanup() {
    local status=$?
    trap - EXIT INT TERM

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

    if ((success)); then
        mkdir -p -- "$logs_dir"
        cp -a -- "$work_dir/." "$logs_dir/"
        rm -rf -- "$work_dir"
        printf 'Guest image created: %s\nLogs: %s\n' "$output" "$logs_dir"
    else
        printf 'Image creation failed; temporary files and diagnostics preserved in %s\n' "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Base image: %s\n' "$base_image" >"$work_dir/build-info.txt"
printf 'Output: %s\nGuest user: %s\nArchitecture: x86_64\nSSH port: %s\n' \
    "$output" "$guest_user" "$ssh_port" >>"$work_dir/build-info.txt"

qemu-img convert -p -f qcow2 -O qcow2 "$base_image" "$work_dir/guest.qcow2" \
    >"$work_dir/convert.log" 2>&1 || fail "Could not copy base image; inspect $work_dir/convert.log"
qemu-img resize "$work_dir/guest.qcow2" "${disk_size_gib}G" \
    >"$work_dir/resize.log" 2>&1 || fail "Could not resize guest disk; inspect $work_dir/resize.log"

cat >"$work_dir/user-data" <<EOF
#cloud-config
users:
  - default
  - name: ${guest_user}
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - ${key_type} ${key_data}
ssh_pwauth: false
disable_root: true
package_update: true
packages:
  - openssh-server
  - bpftool
runcmd:
  - systemctl enable --now ssh
EOF

cat >"$work_dir/meta-data" <<EOF
instance-id: pipe-monitor-ebpf-test
local-hostname: pipe-monitor-ebpf-test
EOF

cloud-localds "$work_dir/seed.iso" "$work_dir/user-data" "$work_dir/meta-data" \
    >"$work_dir/cloud-localds.log" 2>&1 ||
    fail "Could not create cloud-init seed image; inspect $work_dir/cloud-localds.log"

qemu-system-x86_64 \
    -name pipe-monitor-ebpf-image-builder \
    -machine accel=kvm \
    -cpu host \
    -smp "$cpus" \
    -m "$memory" \
    -drive "file=$work_dir/guest.qcow2,if=virtio,format=qcow2" \
    -drive "file=$work_dir/seed.iso,media=cdrom,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -device virtio-net-pci,netdev=net0 \
    -boot order=c \
    -display none \
    -serial "file:$work_dir/serial.log" \
    -monitor none \
    -no-reboot \
    >"$work_dir/qemu.log" 2>&1 &
qemu_pid=$!

ssh_opts=(
    -i "$ssh_key"
    -p "$ssh_port"
    -o BatchMode=yes
    -o ConnectTimeout=3
    -o StrictHostKeyChecking=accept-new
    -o UserKnownHostsFile="$work_dir/known_hosts"
    -o LogLevel=ERROR
)

printf 'Waiting for cloud-init provisioning over SSH on 127.0.0.1:%s ...\n' "$ssh_port"
ssh_ready=0
for _ in {1..180}; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        fail "QEMU exited during guest provisioning; inspect $work_dir/qemu.log and $work_dir/serial.log"
    fi
    if ssh "${ssh_opts[@]}" "$guest_user@127.0.0.1" \
        "sudo -n cloud-init status --wait >/dev/null 2>&1 && sudo -n true" 2>/dev/null; then
        ssh_ready=1
        break
    fi
    sleep 2
done
((ssh_ready == 1)) ||
    fail "Guest provisioning or SSH did not complete within 360 seconds; inspect $work_dir/serial.log"

ssh "${ssh_opts[@]}" "$guest_user@127.0.0.1" \
    "sudo -n sh -c 'set -eu; grep -q \"^ID=ubuntu\" /etc/os-release; test -r /sys/kernel/btf/vmlinux; command -v bpftool; test -x /usr/sbin/sshd; uname -a; cat /etc/os-release; bpftool version; bpftool feature probe kernel; printf \"BTF=present\\n\"; sudo -n true'" \
    >"$work_dir/guest-verification.txt" 2>&1 ||
    fail "Guest is missing required BTF, bpftool, OpenSSH, or sudo; inspect $work_dir/guest-verification.txt"

ssh "${ssh_opts[@]}" "$guest_user@127.0.0.1" \
    "sudo -n cloud-init status --long; sudo -n shutdown -h now" \
    >"$work_dir/shutdown.log" 2>&1 ||
    fail "Could not request graceful guest shutdown; inspect $work_dir/shutdown.log"

for _ in {1..60}; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        wait "$qemu_pid" 2>/dev/null || true
        qemu_pid=""
        break
    fi
    sleep 1
done
if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    fail "Guest did not shut down within 60 seconds; inspect $work_dir/serial.log"
fi

mv -- "$work_dir/guest.qcow2" "$output" || fail "Could not move completed guest image to $output"
chmod 0600 -- "$output" || fail "Could not restrict permissions on completed guest image: $output"
success=1
