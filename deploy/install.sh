#!/usr/bin/env bash
# =============================================================================
# Jinn Guard — Enterprise Installer
# =============================================================================
#
# Usage:
#   sudo ./deploy/install.sh [--no-service] [--start-now]
#
# Flags:
#   --no-service    Install files and binary but do NOT enable the service
#   --start-now     Enable and immediately start/restart the service
#
# What this script does:
#   1. Creates the 'jinnguard' system user/group
#   2. Creates all runtime directories with secure permissions
#   3. Generates a 256-bit HMAC secret and loads it into the kernel keyring
#   4. Copies policy.yaml and the systemd unit
#   5. Builds and installs the release binary
#   6. Enables the service but does NOT start it unless --start-now is passed
#
# Requirements:
#   - Rust 1.75+  (rustup or system package)
#   - libz3-dev   (apt install libz3-dev)
#   - openssl
#   - keyutils    (apt install keyutils)
# =============================================================================

set -euo pipefail

# --------------------------------------------------------------------------- #
# Colour helpers
# --------------------------------------------------------------------------- #
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Colour

ok()   { echo "${GREEN}[✓]${NC} $*"; }
warn() { echo "${YELLOW}[!]${NC} $*"; }
err()  { echo "${RED}[✗]${NC} $*" >&2; exit 1; }
info() { echo "${CYAN}[→]${NC} $*"; }

# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #
[[ $EUID -eq 0 ]] || err "This script must be run as root (sudo $0)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NO_SERVICE=false
START_NOW=false

for arg in "$@"; do
    case "$arg" in
        --no-service) NO_SERVICE=true ;;
        --start-now) START_NOW=true ;;
    esac
done

# --------------------------------------------------------------------------- #
# Step 1 — System user
# --------------------------------------------------------------------------- #
info "Creating system user 'jinnguard'..."
if getent group jinnguard &>/dev/null; then
    warn "Group 'jinnguard' already exists — skipping creation"
else
    groupadd -r jinnguard
    ok "Group 'jinnguard' created"
fi

if id jinnguard &>/dev/null; then
    warn "User 'jinnguard' already exists — skipping creation"
else
    useradd -r -g jinnguard -s /sbin/nologin -d /nonexistent -c "Jinn Guard Daemon" jinnguard
    ok "User 'jinnguard' created"
fi

# --------------------------------------------------------------------------- #
# Step 2 — Directories
# --------------------------------------------------------------------------- #
info "Creating runtime directories..."
for dir in /etc/jinnguard /var/lib/jinnguard /var/log/jinnguard /usr/lib/jinnguard; do
    install -d -m 0750 -o root -g jinnguard "$dir"
done
install -d -m 0750 -o jinnguard -g jinnguard /run/jinnguard
ok "Directories ready"

# --------------------------------------------------------------------------- #
# Step 3 — HMAC secret
# --------------------------------------------------------------------------- #
info "Generating HMAC-SHA256 secret..."
if [[ -f /etc/jinnguard/secret ]]; then
    warn "/etc/jinnguard/secret already exists — skipping generation"
else
    openssl rand -hex 32 > /etc/jinnguard/secret
    ok "Secret written to /etc/jinnguard/secret"
fi
chown root:jinnguard /etc/jinnguard/secret
chmod 0440 /etc/jinnguard/secret
ok "Secret permissions set to root:jinnguard mode 0440"

info "Loading secret into Linux kernel keyring (session keyring @s)..."
if command -v keyctl &>/dev/null; then
    keyctl add user jinnguard_hmac_key "$(cat /etc/jinnguard/secret)" @s || \
        warn "keyctl add failed — daemon will fall back to file-based secret"
    ok "Key 'jinnguard_hmac_key' loaded into @s"
else
    warn "keyutils not found — install with: apt install keyutils"
    warn "Daemon will fall back to /etc/jinnguard/secret on startup"
fi

# --------------------------------------------------------------------------- #
# Step 4 — Configuration
# --------------------------------------------------------------------------- #
info "Installing policy file..."
if [[ -f /etc/jinnguard/policy.yaml ]]; then
    warn "/etc/jinnguard/policy.yaml already exists — not overwriting"
else
    install -m 0640 -o root -g jinnguard "$REPO_ROOT/policy.yaml" \
        /etc/jinnguard/policy.yaml
    ok "policy.yaml installed"
fi

info "Installing systemd unit..."
install -m 0644 "$SCRIPT_DIR/jinnguard.service" /etc/systemd/system/jinnguard.service
ok "jinnguard.service installed"

# --------------------------------------------------------------------------- #
# Step 5 — Build & install binary
# --------------------------------------------------------------------------- #
# Kernel version check (require 5.16+)
KMAJ=$(uname -r | cut -d. -f1)
KMIN=$(uname -r | cut -d. -f2)
if [ "$KMAJ" -lt 5 ] || ([ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 16 ]); then
    echo "ERROR: Linux 5.16+ required. Found: $(uname -r)"; exit 1
fi
# BPF LSM active check
if ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "ERROR: Add lsm=bpf to kernel boot params and reboot"; exit 1
fi

BINARY="$REPO_ROOT/target/release/ts_cli"
info "Building fresh enterprise release binary (this may take a minute)..."
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    sudo -u "$SUDO_USER" env "PATH=$PATH" \
        cargo build --release --features enterprise --manifest-path "$REPO_ROOT/Cargo.toml"
else
    cargo build --release --features enterprise --manifest-path "$REPO_ROOT/Cargo.toml"
fi

[[ -x "$BINARY" ]] || err "Build failed — executable binary not found at $BINARY"

info "Verifying release binary contains safe-mode runtime support..."
grep -aFq "JINNGUARD_SAFE_MODE" "$BINARY" || \
    err "Release binary missing JINNGUARD_SAFE_MODE marker — aborting install"
grep -aFq "[safe-mode] LSM audit-only mode active; deny decisions disabled" "$BINARY" || \
    err "Release binary missing safe-mode audit-only log marker — aborting install"
ok "Release binary safe-mode markers verified"

install -m 0755 "$BINARY" /usr/sbin/jinnguard
ok "Binary installed to /usr/sbin/jinnguard"

info "Building and installing validated multi-object eBPF programs..."
if make -C "$REPO_ROOT/bpf" install; then
    ok "eBPF objects installed to /usr/lib/jinnguard"
else
    err "eBPF install failed — Enterprise release requires kernel LSM objects"
fi

# --------------------------------------------------------------------------- #
# Step 6 — Ownership pass
# --------------------------------------------------------------------------- #
chown -R jinnguard:jinnguard /var/lib/jinnguard /var/log/jinnguard /run/jinnguard
ok "Directory ownership set to jinnguard:jinnguard"

# --------------------------------------------------------------------------- #
# Step 7 — Service activation
# --------------------------------------------------------------------------- #
systemctl daemon-reload

if $NO_SERVICE; then
    warn "--no-service: skipping service enable/start"
else
    systemctl enable jinnguard
    ok "jinnguard service enabled"
    if $START_NOW; then
        systemctl restart jinnguard
        sleep 1
        if systemctl is-active --quiet jinnguard; then
            ok "jinnguard service is RUNNING"
        else
            warn "jinnguard service did not start — check: journalctl -u jinnguard -n 40"
        fi
    else
        warn "Installed but not started."
    fi
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
echo ""
echo "${GREEN}══════════════════════════════════════════════${NC}"
echo "${GREEN}  Jinn Guard installation complete!           ${NC}"
echo "${GREEN}══════════════════════════════════════════════${NC}"
echo "  Binary   : /usr/sbin/jinnguard"
echo "  Socket   : /run/jinnguard/jinnguard.sock"
echo "  Policy   : /etc/jinnguard/policy.yaml"
echo "  Audit log: /var/log/jinnguard/audit.log"
echo "  Lineage  : /var/lib/jinnguard/lineage.json"
echo "  Secret   : /etc/jinnguard/secret (mode 0440, owner root:jinnguard)"
echo ""
if ! $START_NOW; then
    echo "  Installed but not started."
fi
echo "  Validate: sudo -E env \"PATH=\$PATH\" JINNGUARD_TEST_BINARY=/usr/sbin/jinnguard cargo test -p ts_cli --features enterprise --test kernel_lsm -- --ignored --test-threads=1 --nocapture"
echo "  Start:"
echo "  Safe mode: audit-only mode keeps LSM telemetry active and disables deny decisions."
echo "  To start in safe/audit-only mode:"
echo "            sudo systemctl edit jinnguard"
echo "            add Environment=JINNGUARD_SAFE_MODE=1"
echo "            sudo systemctl daemon-reload"
echo "            sudo systemctl start jinnguard"
echo "  To start enforcement mode:"
echo "            sudo systemctl start jinnguard"
echo "  Status:   systemctl status jinnguard"
echo "  Logs:     journalctl -u jinnguard -f"
echo ""
