#!/usr/bin/env bash
# ==============================================================================
# PS-028 Happy Eyeballs Measurement Lab: Teardown Script
# Safely and idempotently destroys ONLY PS-028 project-prefixed resources.
# ==============================================================================

set -euo pipefail

PROJECT_NAMESPACES=("ps028-cl" "ps028-rt" "ps028-sv")
PROJECT_INTERFACES=(
    "ps028-cl-rt" "ps028-rt-cl"
    "ps028-rt-sv4" "ps028-sv-rt4"
    "ps028-rt-sv6" "ps028-sv-rt6"
)

log_info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
log_ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
log_error(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# ------------------------------------------------------------------------------
# 1. Root / Privileges Check
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "This script requires root privileges to manage network namespaces. Please run with sudo." >&2
    exit 1
fi

log_info "Tearing down PS-028 lab resources..."

failures=()

# ------------------------------------------------------------------------------
# 2. Delete Project Namespaces
# Deleting namespaces automatically cleans up internal veth peers and qdiscs.
# Unrelated namespaces are never touched.
# ------------------------------------------------------------------------------
for ns in "${PROJECT_NAMESPACES[@]}"; do
    if ip netns list 2>/dev/null | grep -qw "$ns"; then
        log_info "Deleting namespace: $ns"
        if ! ip netns del "$ns"; then
            log_error "Failed to delete namespace: $ns"
            failures+=("namespace:$ns")
            # If namespace deletion failed, attempt cleanup of project interfaces inside it
            for iface in "${PROJECT_INTERFACES[@]}"; do
                if ip -n "$ns" link show "$iface" &>/dev/null; then
                    log_info "Deleting project interface from remaining namespace $ns: $iface"
                    if ! ip -n "$ns" link del "$iface"; then
                        log_error "Failed to delete interface $iface from namespace $ns"
                        failures+=("interface:$ns/$iface")
                    fi
                fi
            done
        fi
    fi
done

# ------------------------------------------------------------------------------
# 3. Clean Project Interfaces in Host Namespace (if interrupted mid-setup)
# Only checks explicitly designated PS-028 interface names.
# Arbitrary veth-* interfaces and eth0 are never altered.
# ------------------------------------------------------------------------------
for iface in "${PROJECT_INTERFACES[@]}"; do
    if ip link show "$iface" &>/dev/null; then
        log_info "Deleting dangling project interface from host namespace: $iface"
        if ! ip link del "$iface"; then
            log_error "Failed to delete dangling interface: $iface"
            failures+=("interface:$iface")
        fi
    fi
done

# ------------------------------------------------------------------------------
# 4. Status Evaluation & Reporting
# ------------------------------------------------------------------------------
if [[ ${#failures[@]} -ne 0 ]]; then
    log_error "PS-028 teardown incomplete. The following resources could not be removed: ${failures[*]}" >&2
    exit 1
fi

log_ok "PS-028 teardown complete. Host eth0, default routes, and unrelated resources remain untouched."
