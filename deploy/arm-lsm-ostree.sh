#!/usr/bin/env bash
# Declaratively arm BPF-LSM on rpm-ostree booted hosts.
#
# This helper is intentionally package-mode friendly: on non-ostree hosts it is a
# no-op and exits 0. It never edits grub files and never reboots.
set -euo pipefail

OSTREE_BOOTED_PATH="${JINNGUARD_OSTREE_BOOTED_PATH:-/run/ostree-booted}"
LSM_PATH="${JINNGUARD_LSM_PATH:-/sys/kernel/security/lsm}"
RPM_OSTREE="${JINNGUARD_RPM_OSTREE:-rpm-ostree}"

info() { echo "[jinn-guard ostree] $*"; }
err() {
    echo "[jinn-guard ostree] ERROR: $*" >&2
    exit 1
}

contains_csv() {
    local csv="$1"
    local needle="$2"
    local item

    IFS=',' read -r -a items <<< "$csv"
    for item in "${items[@]}"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

append_unique() {
    local csv="$1"
    local item="$2"

    if contains_csv "$csv" "$item"; then
        printf '%s\n' "$csv"
    elif [[ -n "$csv" ]]; then
        printf '%s,%s\n' "$csv" "$item"
    else
        printf '%s\n' "$item"
    fi
}

extract_lsm_karg() {
    local token

    for token in $1; do
        case "$token" in
            lsm=*)
                printf '%s\n' "${token#lsm=}"
                return 0
                ;;
        esac
    done
}

if [[ ! -e "$OSTREE_BOOTED_PATH" ]]; then
    info "not an rpm-ostree booted host; no-op"
    exit 0
fi

[[ -r "$LSM_PATH" ]] || err "cannot read active LSM list at $LSM_PATH"
command -v "$RPM_OSTREE" >/dev/null 2>&1 || err "rpm-ostree command not found"

live_lsm="$(tr -d '[:space:]' < "$LSM_PATH")"
[[ -n "$live_lsm" ]] || err "active LSM list is empty"

current_kargs="$("$RPM_OSTREE" kargs)"
old_lsm="$(extract_lsm_karg "$current_kargs" || true)"
desired_lsm="$(append_unique "$live_lsm" "bpf")"

if [[ "$old_lsm" == "$desired_lsm" ]]; then
    info "already armed: lsm=$desired_lsm"
    info "a reboot may still be required if this is a pending rpm-ostree deployment"
    exit 0
fi

if contains_csv "$live_lsm" "bpf" && [[ -n "$old_lsm" ]] && contains_csv "$old_lsm" "bpf"; then
    info "already armed: active LSMs and rpm-ostree kargs both include bpf"
    exit 0
fi

info "active LSMs: ${live_lsm}"
if [[ -n "$old_lsm" ]]; then
    info "current rpm-ostree lsm karg: ${old_lsm}"
    info "desired rpm-ostree lsm karg: ${desired_lsm}"
    info "will run: rpm-ostree kargs --replace=lsm=${old_lsm}=${desired_lsm}"
    "$RPM_OSTREE" kargs "--replace=lsm=${old_lsm}=${desired_lsm}"
else
    info "current rpm-ostree lsm karg: <none>"
    info "desired rpm-ostree lsm karg: ${desired_lsm}"
    info "will run: rpm-ostree kargs --append=lsm=${desired_lsm}"
    "$RPM_OSTREE" kargs "--append=lsm=${desired_lsm}"
fi

info "rpm-ostree staged the updated kernel arguments."
info "A reboot is required for the pending deployment to take effect. This helper will not reboot."
info "revert: rpm-ostree kargs --delete=lsm=${desired_lsm}"
info "or drop the pending kargs deployment with: rpm-ostree rollback"
