#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./install_prereqs.sh [--dry-run]

Install host packages needed to develop Linux eBPF programs with libbpf and
run disposable QEMU/KVM VM tests. Supports Debian/Ubuntu-family distributions.
Does not download a guest image, configure host settings, or install a project.
EOF
}

case "${1:-}" in
    "")
        ;;
    --dry-run)
        DRY_RUN=1
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

DRY_RUN="${DRY_RUN:-0}"

if [[ ! -r /etc/os-release ]]; then
    echo "Cannot identify this Linux distribution: /etc/os-release is missing." >&2
    exit 1
fi

os_id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')"
os_id_like="$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d '"')"

case " ${os_id} ${os_id_like} " in
    *" debian "*|*" ubuntu "*|*" pop "*)
        ;;
    *)
        echo "Unsupported distribution: ${os_id:-unknown}." >&2
        echo "This script supports Debian/Ubuntu-family distributions with apt-get." >&2
        exit 1
        ;;
esac

if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get was not found; cannot install prerequisites." >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64|amd64)
        qemu_package="qemu-system-x86"
        ;;
    aarch64|arm64)
        qemu_package="qemu-system-arm"
        ;;
    *)
        echo "Unsupported host architecture: $(uname -m)." >&2
        echo "Supported architectures are x86_64 and aarch64." >&2
        exit 1
        ;;
esac

packages=(
    bpftool
    build-essential
    clang
    cloud-image-utils
    libbpf-dev
    libelf-dev
    make
    openssh-client
    pkg-config
    python3
    qemu-utils
    "${qemu_package}"
    llvm
    zlib1g-dev
)

if [[ "${DRY_RUN}" == "1" ]]; then
    printf 'Would run: apt-get update\n'
    printf 'Would install these packages:\n'
    printf '  %s\n' "${packages[@]}"
    exit 0
fi

if [[ "$(id -u)" -eq 0 ]]; then
    package_manager=(apt-get)
elif command -v sudo >/dev/null 2>&1; then
    package_manager=(sudo apt-get)
else
    echo "Package installation requires root or sudo; neither is available." >&2
    exit 1
fi

printf 'Installing host prerequisites on %s (%s).\n' "${os_id}" "$(uname -m)"
"${package_manager[@]}" update
"${package_manager[@]}" install --no-install-recommends "${packages[@]}"

echo
echo "Host development prerequisites are installed."
if [[ -e /dev/kvm ]]; then
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then
        echo "KVM device is accessible to the current user."
    else
        echo "KVM device exists but is not accessible to the current user."
        echo "Configure access according to your distribution's guidance before VM testing."
    fi
else
    echo "No /dev/kvm device is present; QEMU can be installed, but KVM VM testing is not ready."
fi
echo "A guest image and project-specific build/VM automation must be provided separately."
