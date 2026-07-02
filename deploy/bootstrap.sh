#!/bin/sh
# =============================================================================
# Jinn Guard — one-command bootstrap installer
# =============================================================================
#
# Turns a bare Linux host into a running (or install-ready) Jinn Guard node with
# a single command. It detects the host, installs the right dependencies for the
# distro, fetches the source, then hands off to deploy/install.sh (which does the
# privileged build + service install). It NEVER weakens Jinn Guard's security
# posture: fail-closed defaults, no desktop lockout, safe-mode stays opt-in.
#
# Quick start:
#   curl -fsSL https://raw.githubusercontent.com/AlphaReasoning/The-Jinn-Guard/main/deploy/bootstrap.sh | sh
#   # or, from a checkout:
#   sudo sh deploy/bootstrap.sh --start-now
#
# What it does, in order:
#   1. Detect distro / package manager / kernel / arch / BTF / BPF-LSM state
#   2. Preflight: kernel >= 5.16, CO-RE BTF present, BPF LSM armed (or offer to)
#   3. Install build+runtime deps via the native package manager
#   4. Ensure a Rust toolchain (distro package or rustup)
#   5. Fetch the source (git clone) unless already run from a checkout
#   6. Hand off to deploy/install.sh to build + install + (optionally) start
#
# Flags:
#   --yes            Non-interactive; assume "yes" to prompts
#   --dry-run        Print the plan and the exact commands, run nothing
#   --no-deps        Skip dependency installation (assume already present)
#   --arm-lsm        Add lsm=...,bpf to the bootloader if missing (needs reboot)
#   --start-now      Enable AND start the service after install
#   --safe-mode      Start in audit-only mode (LSM telemetry on, deny disabled)
#   --repo <url>     Source repo (default: public The-Jinn-Guard)
#   --ref  <ref>     Branch/tag/commit to check out (default: main)
#   --dir  <path>    Where to place the source (default: /opt/jinnguard-src)
#
# Exit codes: 0 ok, 1 preflight/dependency failure, 2 usage.
# =============================================================================

set -eu

# --------------------------------------------------------------------------- #
# Output helpers (colour only on a TTY)
# --------------------------------------------------------------------------- #
if [ -t 1 ]; then
    RED=$(printf '\033[0;31m'); GREEN=$(printf '\033[0;32m')
    YEL=$(printf '\033[1;33m'); CYN=$(printf '\033[0;36m'); NC=$(printf '\033[0m')
else
    RED=''; GREEN=''; YEL=''; CYN=''; NC=''
fi
ok()   { printf '%s[ok]%s %s\n'   "$GREEN" "$NC" "$*"; }
warn() { printf '%s[!]%s %s\n'    "$YEL"  "$NC" "$*"; }
info() { printf '%s[->]%s %s\n'   "$CYN"  "$NC" "$*"; }
err()  { printf '%s[x]%s %s\n'    "$RED"  "$NC" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Args
# --------------------------------------------------------------------------- #
ASSUME_YES=false; DRY_RUN=false; NO_DEPS=false; ARM_LSM=false
START_NOW=false; SAFE_MODE=false
REPO_URL="https://github.com/AlphaReasoning/The-Jinn-Guard.git"
REF="main"; SRC_DIR="/opt/jinnguard-src"

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)     ASSUME_YES=true ;;
        --dry-run)    DRY_RUN=true ;;
        --no-deps)    NO_DEPS=true ;;
        --arm-lsm)    ARM_LSM=true ;;
        --start-now)  START_NOW=true ;;
        --safe-mode)  SAFE_MODE=true ;;
        --repo)       shift; REPO_URL="${1:-}" ;;
        --ref)        shift; REF="${1:-}" ;;
        --dir)        shift; SRC_DIR="${1:-}" ;;
        -h|--help)    sed -n '2,40p' "$0"; exit 0 ;;
        *)            err "unknown argument: $1 (see --help)" ;;
    esac
    shift
done

# Run a privileged/mutating command, honouring --dry-run.
run() {
    if $DRY_RUN; then
        printf '    %s+ %s%s\n' "$YEL" "$*" "$NC"
    else
        "$@"
    fi
}

# Elevation: prefer running privileged steps via sudo when not already root.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
    $DRY_RUN || warn "not root and no sudo found — privileged steps will fail"
fi
sudo_run() { run ${SUDO:+$SUDO} "$@"; }

confirm() {
    $ASSUME_YES && return 0
    $DRY_RUN && return 0
    printf '%s[?]%s %s [y/N] ' "$CYN" "$NC" "$*"
    read -r ans 2>/dev/null || return 1
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# --------------------------------------------------------------------------- #
# Step 1 — Detect host
# --------------------------------------------------------------------------- #
info "Detecting host..."
OS_ID="unknown"; OS_LIKE=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"; OS_LIKE="${ID_LIKE:-}"
fi
ARCH="$(uname -m)"
KREL="$(uname -r)"
KMAJ="${KREL%%.*}"; KREST="${KREL#*.}"; KMIN="${KREST%%.*}"
case "$KMIN" in ''|*[!0-9]*) KMIN=0 ;; esac

# Pick a package manager and the package-name set for this family.
PM=""; PKGS=""
if command -v apt-get >/dev/null 2>&1; then
    PM="apt"
    PKGS="build-essential clang llvm libbpf-dev libz3-dev libssl-dev keyutils pkg-config git curl ca-certificates"
elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
    PKGS="gcc make clang llvm libbpf-devel z3-devel openssl-devel keyutils pkgconf-pkg-config git curl ca-certificates"
elif command -v yum >/dev/null 2>&1; then
    PM="yum"
    PKGS="gcc make clang llvm libbpf-devel z3-devel openssl-devel keyutils pkgconfig git curl ca-certificates"
elif command -v zypper >/dev/null 2>&1; then
    PM="zypper"
    PKGS="gcc make clang llvm libbpf-devel z3-devel libopenssl-devel keyutils pkg-config git curl ca-certificates"
elif command -v pacman >/dev/null 2>&1; then
    PM="pacman"
    PKGS="base-devel clang llvm libbpf z3 keyutils openssl pkgconf git curl ca-certificates"
fi

ok  "distro=${OS_ID} like=${OS_LIKE:-none} arch=${ARCH} kernel=${KREL} pkg-mgr=${PM:-none}"

# --------------------------------------------------------------------------- #
# Step 2 — Preflight (fail-closed: refuse rather than install a broken node)
# --------------------------------------------------------------------------- #
info "Preflight checks..."

case "$ARCH" in
    x86_64|aarch64) ok "architecture ${ARCH} supported" ;;
    *) err "unsupported architecture: ${ARCH} (need x86_64 or aarch64)" ;;
esac

if [ "$KMAJ" -gt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -ge 16 ]; }; then
    ok "kernel ${KREL} meets the 5.16+ requirement"
else
    err "kernel ${KREL} too old — Jinn Guard needs Linux 5.16+ for BPF-LSM"
fi

if [ -r /sys/kernel/btf/vmlinux ]; then
    ok "kernel BTF present (/sys/kernel/btf/vmlinux) — CO-RE eBPF will load"
else
    warn "no /sys/kernel/btf/vmlinux — kernel lacks CONFIG_DEBUG_INFO_BTF."
    warn "CO-RE eBPF programs need BTF; install a kernel built with BTF or a"
    warn "matching vmlinux. Continuing, but the LSM objects may fail to load."
fi

LSM_ARMED=false
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    LSM_ARMED=true
    ok "BPF LSM is armed (bpf present in /sys/kernel/security/lsm)"
else
    warn "BPF LSM is NOT armed — 'bpf' missing from the active LSM list."
    if $ARM_LSM; then
        info "Attempting to add lsm=...,bpf to the bootloader (reboot required)..."
        if [ -w /etc/default/grub ] || [ -n "$SUDO" ]; then
            CUR="$(sed -n 's/^GRUB_CMDLINE_LINUX="\(.*\)"/\1/p' /etc/default/grub 2>/dev/null || true)"
            case "$CUR" in
                *lsm=*) warn "GRUB already sets lsm=...; edit it by hand to include bpf" ;;
                *) sudo_run sh -c 'sed -i "s/^GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf\"/" /etc/default/grub'
                   if command -v update-grub >/dev/null 2>&1; then sudo_run update-grub
                   elif command -v grub2-mkconfig >/dev/null 2>&1; then sudo_run grub2-mkconfig -o /boot/grub2/grub.cfg
                   else warn "no update-grub/grub2-mkconfig — regenerate grub.cfg manually"; fi
                   warn "REBOOT required for lsm=bpf to take effect, then re-run this script" ;;
            esac
        else
            warn "cannot edit /etc/default/grub (need root). Re-run with sudo + --arm-lsm"
        fi
    else
        warn "re-run with --arm-lsm to add it automatically (needs a reboot), or add"
        warn "  lsm=...,bpf  to your kernel cmdline and reboot. Install will refuse"
        warn "  to arm enforcement until this is set (safe-mode audit-only still works)."
    fi
fi

# --------------------------------------------------------------------------- #
# Step 3 — Dependencies
# --------------------------------------------------------------------------- #
if $NO_DEPS; then
    warn "--no-deps: skipping dependency installation"
else
    [ -n "$PM" ] || err "no supported package manager found (apt/dnf/yum/zypper/pacman)"
    info "Installing dependencies via ${PM}: ${PKGS}"
    case "$PM" in
        apt)    sudo_run apt-get update
                sudo_run env DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS ;;
        dnf)    sudo_run dnf install -y $PKGS ;;
        yum)    sudo_run yum install -y $PKGS ;;
        zypper) sudo_run zypper --non-interactive install $PKGS ;;
        pacman) sudo_run pacman -Sy --noconfirm $PKGS ;;
    esac
    ok "system dependencies installed"
fi

# --------------------------------------------------------------------------- #
# Step 4 — Rust toolchain (>= 1.75)
# --------------------------------------------------------------------------- #
need_rust=true
if command -v cargo >/dev/null 2>&1; then
    RUSTV="$(cargo --version 2>/dev/null | awk '{print $2}')"
    RMAJ="${RUSTV%%.*}"; RREST="${RUSTV#*.}"; RMIN="${RREST%%.*}"
    case "$RMIN" in ''|*[!0-9]*) RMIN=0 ;; esac
    if [ "${RMAJ:-0}" -gt 1 ] || { [ "${RMAJ:-0}" -eq 1 ] && [ "$RMIN" -ge 75 ]; }; then
        need_rust=false
        ok "cargo ${RUSTV} present (>= 1.75)"
    else
        warn "cargo ${RUSTV} is older than 1.75 — will install rustup toolchain"
    fi
fi
if $need_rust; then
    info "Installing Rust via rustup (stable, non-interactive)..."
    if $DRY_RUN; then
        printf '    %s+ curl -fsSL https://sh.rustup.rs | sh -s -- -y%s\n' "$YEL" "$NC"
    else
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1090
        . "$HOME/.cargo/env" 2>/dev/null || true
    fi
    ok "Rust toolchain ready"
fi

# --------------------------------------------------------------------------- #
# Step 5 — Fetch source (skip if we are already inside a checkout)
# --------------------------------------------------------------------------- #
HERE="$(cd "$(dirname "$0")" && pwd 2>/dev/null || echo '')"
REPO_ROOT=""
if [ -n "$HERE" ] && [ -f "$HERE/install.sh" ] && [ -f "$HERE/../Cargo.toml" ]; then
    REPO_ROOT="$(cd "$HERE/.." && pwd)"
    ok "running from an existing checkout: ${REPO_ROOT}"
else
    info "Fetching source: ${REPO_URL} @ ${REF} -> ${SRC_DIR}"
    if [ -d "$SRC_DIR/.git" ]; then
        run git -C "$SRC_DIR" fetch --depth 1 origin "$REF"
        run git -C "$SRC_DIR" checkout FETCH_HEAD
    else
        sudo_run mkdir -p "$SRC_DIR"
        [ -n "$SUDO" ] && sudo_run chown "$(id -un)" "$SRC_DIR" || true
        run git clone --depth 1 --branch "$REF" "$REPO_URL" "$SRC_DIR" \
            || run git clone --depth 1 "$REPO_URL" "$SRC_DIR"
    fi
    REPO_ROOT="$SRC_DIR"
fi

# --------------------------------------------------------------------------- #
# Step 6 — Hand off to the privileged installer
# --------------------------------------------------------------------------- #
INSTALL_ARGS=""
$START_NOW && INSTALL_ARGS="$INSTALL_ARGS --start-now"
# safe-mode is applied post-install via systemd drop-in; surface the guidance.

info "Handing off to deploy/install.sh (privileged build + service install)..."
if [ "$LSM_ARMED" = false ] && [ "$START_NOW" = true ] && [ "$SAFE_MODE" = false ]; then
    warn "BPF LSM is not armed; enforcement cannot start. Install will proceed but"
    warn "the service will only run once lsm=bpf is set (or use --safe-mode)."
fi

if $DRY_RUN; then
    printf '    %s+ %sbash %s/deploy/install.sh%s%s\n' \
        "$YEL" "${SUDO:+$SUDO }" "$REPO_ROOT" "$INSTALL_ARGS" "$NC"
    ok "dry-run complete — no changes made"
    exit 0
fi

sudo_run bash "$REPO_ROOT/deploy/install.sh" $INSTALL_ARGS

if $SAFE_MODE; then
    info "Configuring safe-mode (audit-only) systemd drop-in..."
    sudo_run mkdir -p /etc/systemd/system/jinnguard.service.d
    sudo_run sh -c 'printf "[Service]\nEnvironment=JINNGUARD_SAFE_MODE=1\n" > /etc/systemd/system/jinnguard.service.d/10-safe-mode.conf'
    sudo_run systemctl daemon-reload
    $START_NOW && sudo_run systemctl restart jinnguard || true
    ok "safe-mode drop-in installed (LSM telemetry on, deny decisions disabled)"
fi

ok "Bootstrap complete."
