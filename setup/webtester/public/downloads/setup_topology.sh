#!/usr/bin/env bash
# ==============================================================================
# PS-028 Happy Eyeballs Measurement Lab: Topology Setup Script
# Work Package A1: Three-Namespace Isolated Dual-Stack Topology
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEARDOWN_SCRIPT="${SCRIPT_DIR}/teardown.sh"

# ------------------------------------------------------------------------------
# Configuration & Constants (Project-Prefixed)
# ------------------------------------------------------------------------------
NS_CL="ps028-cl"
NS_RT="ps028-rt"
NS_SV="ps028-sv"

# Interface names (strictly <= 15 chars)
IF_CL_RT="ps028-cl-rt"
IF_RT_CL="ps028-rt-cl"
IF_RT_SV4="ps028-rt-sv4"
IF_SV_RT4="ps028-sv-rt4"
IF_RT_SV6="ps028-rt-sv6"
IF_SV_RT6="ps028-sv-rt6"

# Addressing
IP_CL_V4="10.0.1.2/24"
IP_RT_CL_V4="10.0.1.1/24"
IP_CL_V6="2001:db8:1::2/64"
IP_RT_CL_V6="2001:db8:1::1/64"

IP_RT_SV4="10.0.2.1/24"
IP_SV_V4="10.0.2.10/24"

IP_RT_SV6="2001:db8:2::1/64"
IP_SV_V6="2001:db8:2::10/64"

NETEM_DELAY="10ms"

# Verification thresholds
PING_COUNT=10
RTT_MIN_TOLERANCE=19.0
RTT_MAX_TOLERANCE=22.5

log_info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
log_ok()    { echo -e "\033[1;32m[OK]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# ------------------------------------------------------------------------------
# Safety & Idempotence Checks
# ------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges to manage network namespaces. Please run with sudo."
        exit 1
    fi
}

check_dependencies() {
    local deps=("ip" "tc" "sysctl" "ping" "bc" "awk" "diff")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Required command '$cmd' is not found. Please install iproute2, iputils, and bc."
            exit 1
        fi
    done
}

# Cleanup hook on unexpected setup error
cleanup_on_error() {
    local line_num="$1"
    local exit_code="$2"
    log_error "Setup encountered an error on line $line_num (exit code: $exit_code)."
    log_warn "Executing automated cleanup of PS-028 resources..."
    if [[ -x "$TEARDOWN_SCRIPT" ]]; then
        "$TEARDOWN_SCRIPT" || true
    fi
    exit "$exit_code"
}

# ------------------------------------------------------------------------------
# Host Invariance Helpers
# ------------------------------------------------------------------------------
snapshot_host_state() {
    local outfile="$1"
    log_info "Capturing host network configuration snapshot to $outfile..."
    {
        echo "=== HOST INTERFACES (eth0) ==="
        ip -d addr show dev eth0 2>/dev/null || ip addr show dev eth0
        echo "=== IPV4 ROUTES ==="
        ip -4 route show
        echo "=== IPV6 ROUTES ==="
        ip -6 route show
        echo "=== IPV4 RULES ==="
        ip -4 rule show
        echo "=== IPV6 RULES ==="
        ip -6 rule show
    } > "$outfile"
    log_ok "Host snapshot captured."
}

check_host_invariance() {
    local baseline="$1"
    local current
    current="$(mktemp /tmp/ps028_host_current.XXXXXX)"
    snapshot_host_state "$current"

    log_info "Comparing host network state against baseline ($baseline)..."
    if diff -u "$baseline" "$current"; then
        log_ok "HOST INVARIANCE VERIFIED: eth0, IPv4/IPv6 routes, and routing rules are 100% identical."
        rm -f "$current"
        return 0
    else
        log_error "HOST INVARIANCE VIOLATION DETECTED: Differences found in host network state!"
        rm -f "$current"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Core Setup Procedure
# ------------------------------------------------------------------------------
setup_topology() {
    log_info "Initializing PS-028 dual-stack lab topology..."

    # Install error trap for atomic cleanup on setup failure
    trap 'cleanup_on_error $LINENO $?' ERR

    # Ensure clean, idempotent starting state
    if [[ -x "$TEARDOWN_SCRIPT" ]]; then
        "$TEARDOWN_SCRIPT"
    fi

    # 1. Create Namespaces
    log_info "Creating project namespaces: $NS_CL, $NS_RT, $NS_SV"
    ip netns add "$NS_CL"
    ip netns add "$NS_RT"
    ip netns add "$NS_SV"

    # Bring up loopback interfaces inside namespaces only
    for ns in "$NS_CL" "$NS_RT" "$NS_SV"; do
        ip -n "$ns" link set lo up
    done

    # 2. Sysctl Configurations (inside namespaces only)
    log_info "Applying routing and neighbor sysctls..."
    ip netns exec "$NS_RT" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$NS_RT" sysctl -qw net.ipv6.conf.all.forwarding=1
    ip netns exec "$NS_RT" sysctl -qw net.ipv6.conf.default.forwarding=1

    for ns in "$NS_CL" "$NS_RT" "$NS_SV"; do
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_ra=0
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_ra=0
        ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
        ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
    done

    # 3. Create Virtual Ethernet Pairs (all names <= 15 chars)
    log_info "Creating project veth links..."
    # cl <-> rt (Dual-stack)
    ip link add "$IF_CL_RT" type veth peer name "$IF_RT_CL"
    ip link set "$IF_CL_RT" netns "$NS_CL"
    ip link set "$IF_RT_CL" netns "$NS_RT"

    # rt <-> sv (Dedicated IPv4)
    ip link add "$IF_RT_SV4" type veth peer name "$IF_SV_RT4"
    ip link set "$IF_RT_SV4" netns "$NS_RT"
    ip link set "$IF_SV_RT4" netns "$NS_SV"

    # rt <-> sv (Dedicated IPv6)
    ip link add "$IF_RT_SV6" type veth peer name "$IF_SV_RT6"
    ip link set "$IF_RT_SV6" netns "$NS_RT"
    ip link set "$IF_SV_RT6" netns "$NS_SV"

    # 4. Assign IP Addresses & Enable Interfaces
    log_info "Assigning IP addresses..."
    # cl <-> rt
    ip -n "$NS_CL" addr add "$IP_CL_V4" dev "$IF_CL_RT"
    ip -n "$NS_CL" -6 addr add "$IP_CL_V6" nodad dev "$IF_CL_RT"
    ip -n "$NS_CL" link set "$IF_CL_RT" up

    ip -n "$NS_RT" addr add "$IP_RT_CL_V4" dev "$IF_RT_CL"
    ip -n "$NS_RT" -6 addr add "$IP_RT_CL_V6" nodad dev "$IF_RT_CL"
    ip -n "$NS_RT" link set "$IF_RT_CL" up

    # rt <-> sv (IPv4 link)
    ip -n "$NS_RT" addr add "$IP_RT_SV4" dev "$IF_RT_SV4"
    ip -n "$NS_RT" link set "$IF_RT_SV4" up

    ip -n "$NS_SV" addr add "$IP_SV_V4" dev "$IF_SV_RT4"
    ip -n "$NS_SV" link set "$IF_SV_RT4" up

    # rt <-> sv (IPv6 link)
    ip -n "$NS_RT" -6 addr add "$IP_RT_SV6" nodad dev "$IF_RT_SV6"
    ip -n "$NS_RT" link set "$IF_RT_SV6" up

    ip -n "$NS_SV" -6 addr add "$IP_SV_V6" nodad dev "$IF_SV_RT6"
    ip -n "$NS_SV" link set "$IF_SV_RT6" up

    # 5. Default Routes
    log_info "Installing default routing entries..."
    ip -n "$NS_CL" route add default via "${IP_RT_CL_V4%/*}" dev "$IF_CL_RT"
    ip -n "$NS_CL" -6 route add default via "${IP_RT_CL_V6%/*}" dev "$IF_CL_RT"

    ip -n "$NS_SV" route add default via "${IP_RT_SV4%/*}" dev "$IF_SV_RT4"
    ip -n "$NS_SV" -6 route add default via "${IP_RT_SV6%/*}" dev "$IF_SV_RT6"

    # 6. Pre-populate Permanent Neighbor Entries (Eliminate cold-cache drops)
    log_info "Pre-populating static neighbor entries..."
    local mac_cl_rt mac_rt_cl mac_rt_sv4 mac_sv_rt4 mac_rt_sv6 mac_sv_rt6
    mac_cl_rt=$(ip -n "$NS_CL" -br link show "$IF_CL_RT" | awk '{print $3}')
    mac_rt_cl=$(ip -n "$NS_RT" -br link show "$IF_RT_CL" | awk '{print $3}')
    mac_rt_sv4=$(ip -n "$NS_RT" -br link show "$IF_RT_SV4" | awk '{print $3}')
    mac_sv_rt4=$(ip -n "$NS_SV" -br link show "$IF_SV_RT4" | awk '{print $3}')
    mac_rt_sv6=$(ip -n "$NS_RT" -br link show "$IF_RT_SV6" | awk '{print $3}')
    mac_sv_rt6=$(ip -n "$NS_SV" -br link show "$IF_SV_RT6" | awk '{print $3}')

    ip -n "$NS_CL" neigh add "${IP_RT_CL_V4%/*}" lladdr "$mac_rt_cl" dev "$IF_CL_RT" nud permanent
    ip -n "$NS_CL" -6 neigh add "${IP_RT_CL_V6%/*}" lladdr "$mac_rt_cl" dev "$IF_CL_RT" nud permanent

    ip -n "$NS_RT" neigh add "${IP_CL_V4%/*}" lladdr "$mac_cl_rt" dev "$IF_RT_CL" nud permanent
    ip -n "$NS_RT" -6 neigh add "${IP_CL_V6%/*}" lladdr "$mac_cl_rt" dev "$IF_RT_CL" nud permanent

    ip -n "$NS_RT" neigh add "${IP_SV_V4%/*}" lladdr "$mac_sv_rt4" dev "$IF_RT_SV4" nud permanent
    ip -n "$NS_SV" neigh add "${IP_RT_SV4%/*}" lladdr "$mac_rt_sv4" dev "$IF_SV_RT4" nud permanent

    ip -n "$NS_RT" -6 neigh add "${IP_SV_V6%/*}" lladdr "$mac_sv_rt6" dev "$IF_RT_SV6" nud permanent
    ip -n "$NS_SV" -6 neigh add "${IP_RT_SV6%/*}" lladdr "$mac_rt_sv6" dev "$IF_SV_RT6" nud permanent

    # 7. Configure 10 ms Netem Delays at Both Ends of Server Links
    log_info "Configuring 10ms netem delay on both ends of server-facing links..."
    ip netns exec "$NS_RT" tc qdisc replace dev "$IF_RT_SV4" root netem delay "$NETEM_DELAY"
    ip netns exec "$NS_SV" tc qdisc replace dev "$IF_SV_RT4" root netem delay "$NETEM_DELAY"

    ip netns exec "$NS_RT" tc qdisc replace dev "$IF_RT_SV6" root netem delay "$NETEM_DELAY"
    ip netns exec "$NS_SV" tc qdisc replace dev "$IF_SV_RT6" root netem delay "$NETEM_DELAY"

    # Remove error trap on success
    trap - ERR
    log_ok "PS-028 lab topology successfully configured."
}

# ------------------------------------------------------------------------------
# Inspection / Status Procedure
# ------------------------------------------------------------------------------
status_topology() {
    log_info "Listing PS-028 namespaces and interface states..."
    echo "--- Namespaces ---"
    ip netns list | grep -E "ps028-" || echo "No PS-028 namespaces found."

    for ns in "$NS_CL" "$NS_RT" "$NS_SV"; do
        if ip netns list | grep -qw "$ns"; then
            echo "=== Namespace: $ns ==="
            ip -n "$ns" -br addr
            echo "Routes (IPv4):" && ip -n "$ns" -4 route
            echo "Routes (IPv6):" && ip -n "$ns" -6 route
        fi
    done

    echo "=== Netem Qdiscs on Server Links ==="
    if ip netns list | grep -qw "$NS_RT"; then
        echo "Router IPv4 ($IF_RT_SV4):" && ip netns exec "$NS_RT" tc qdisc show dev "$IF_RT_SV4"
        echo "Router IPv6 ($IF_RT_SV6):" && ip netns exec "$NS_RT" tc qdisc show dev "$IF_RT_SV6"
    fi
    if ip netns list | grep -qw "$NS_SV"; then
        echo "Server IPv4 ($IF_SV_RT4):" && ip netns exec "$NS_SV" tc qdisc show dev "$IF_SV_RT4"
        echo "Server IPv6 ($IF_SV_RT6):" && ip netns exec "$NS_SV" tc qdisc show dev "$IF_SV_RT6"
    fi
}

# ------------------------------------------------------------------------------
# Verification Procedure (10-Ping Sample & Sysfs Traffic Separation)
# ------------------------------------------------------------------------------
verify_topology() {
    log_info "Executing PS-028 topology verification..."
    local target_v4="${IP_SV_V4%/*}"
    local target_v6="${IP_SV_V6%/*}"

    # 1. IPv4 Connectivity & Latency
    log_info "Testing IPv4 ($NS_CL -> $target_v4, $PING_COUNT packets)..."
    local v4_raw="" v4_rc=0
    v4_raw=$(ip netns exec "$NS_CL" ping -c "$PING_COUNT" -i 0.2 -W 2 "$target_v4" 2>&1) || v4_rc=$?
    local v4_loss v4_avg
    v4_loss=$(echo "$v4_raw" | grep -oP '\d+(?=% packet loss)' || true)
    v4_avg=$(echo "$v4_raw" | awk -F'/' '/^(rtt|round-trip)/ {print $5}')

    log_info "IPv4: Loss = ${v4_loss:-unknown}%, Mean RTT = ${v4_avg:-unknown} ms"
    if [[ "$v4_rc" -ne 0 || -z "$v4_loss" || "$v4_loss" != "0" ]]; then
        log_error "IPv4 ping failed (exit code: $v4_rc, packet loss: ${v4_loss:-unknown}%)."
        return 1
    fi
    if [[ -z "$v4_avg" ]] || ! (( $(echo "$v4_avg >= $RTT_MIN_TOLERANCE && v4_avg <= $RTT_MAX_TOLERANCE" | bc -l 2>/dev/null || echo 0) )); then
        log_error "IPv4 average RTT (${v4_avg:-unknown} ms) outside tolerance [${RTT_MIN_TOLERANCE}, ${RTT_MAX_TOLERANCE}] ms"
        return 1
    fi
    log_ok "IPv4 verification passed."

    # 2. IPv6 Connectivity & Latency
    log_info "Testing IPv6 ($NS_CL -> $target_v6, $PING_COUNT packets)..."
    local v6_raw="" v6_rc=0
    v6_raw=$(ip netns exec "$NS_CL" ping -6 -c "$PING_COUNT" -i 0.2 -W 2 "$target_v6" 2>&1) || v6_rc=$?
    local v6_loss v6_avg
    v6_loss=$(echo "$v6_raw" | grep -oP '\d+(?=% packet loss)' || true)
    v6_avg=$(echo "$v6_raw" | awk -F'/' '/^(rtt|round-trip)/ {print $5}')

    log_info "IPv6: Loss = ${v6_loss:-unknown}%, Mean RTT = ${v6_avg:-unknown} ms"
    if [[ "$v6_rc" -ne 0 || -z "$v6_loss" || "$v6_loss" != "0" ]]; then
        log_error "IPv6 ping failed (exit code: $v6_rc, packet loss: ${v6_loss:-unknown}%)."
        return 1
    fi
    if [[ -z "$v6_avg" ]] || ! (( $(echo "$v6_avg >= $RTT_MIN_TOLERANCE && v6_avg <= $RTT_MAX_TOLERANCE" | bc -l 2>/dev/null || echo 0) )); then
        log_error "IPv6 average RTT (${v6_avg:-unknown} ms) outside tolerance [${RTT_MIN_TOLERANCE}, ${RTT_MAX_TOLERANCE}] ms"
        return 1
    fi
    log_ok "IPv6 verification passed."

    # 3. Deterministic Link Separation Verification
    log_info "Testing link separation via sysfs packet counters..."
    local v4_tx_before v6_tx_before v4_tx_after v6_tx_after
    v4_tx_before=$(ip netns exec "$NS_RT" cat "/sys/class/net/$IF_RT_SV4/statistics/tx_packets" 2>/dev/null || echo "")
    v6_tx_before=$(ip netns exec "$NS_RT" cat "/sys/class/net/$IF_RT_SV6/statistics/tx_packets" 2>/dev/null || echo "")
    if [[ -z "$v4_tx_before" || -z "$v6_tx_before" ]]; then
        log_error "Failed to read initial sysfs tx_packets counters on router interfaces."
        return 1
    fi

    # Send IPv4 burst only
    local sep_raw="" sep_rc=0
    sep_raw=$(ip netns exec "$NS_CL" ping -c 3 -i 0.1 "$target_v4" 2>&1) || sep_rc=$?
    local sep_loss sep_avg
    sep_loss=$(echo "$sep_raw" | grep -oP '\d+(?=% packet loss)' || true)
    sep_avg=$(echo "$sep_raw" | awk -F'/' '/^(rtt|round-trip)/ {print $5}')

    v4_tx_after=$(ip netns exec "$NS_RT" cat "/sys/class/net/$IF_RT_SV4/statistics/tx_packets" 2>/dev/null || echo "")
    v6_tx_after=$(ip netns exec "$NS_RT" cat "/sys/class/net/$IF_RT_SV6/statistics/tx_packets" 2>/dev/null || echo "")
    if [[ -z "$v4_tx_after" || -z "$v6_tx_after" ]]; then
        log_error "Failed to read updated sysfs tx_packets counters on router interfaces."
        return 1
    fi

    local v4_delta=$((v4_tx_after - v4_tx_before))
    local v6_delta=$((v6_tx_after - v6_tx_before))

    log_info "Link-separation burst: Loss = ${sep_loss:-unknown}%, Mean RTT = ${sep_avg:-unknown} ms"
    log_info "Link separation traffic burst: IPv4 link delta = $v4_delta, IPv6 link delta = $v6_delta"

    if [[ "$sep_rc" -ne 0 || -z "$sep_loss" || "$sep_loss" != "0" ]]; then
        log_error "Link-separation ping burst failed (exit code: $sep_rc, packet loss: ${sep_loss:-unknown}%)."
        return 1
    fi

    if [[ "$v4_delta" -lt 3 || "$v6_delta" -ne 0 ]]; then
        log_error "Link separation failed: IPv4 traffic leaked onto IPv6 link or failed to traverse IPv4 link (IPv4 delta: $v4_delta, IPv6 delta: $v6_delta)."
        return 1
    fi
    log_ok "Link separation verified: IPv4 and IPv6 traffic transit isolated physical/virtual links."

    log_ok "ALL ACCEPTANCE CRITERIA MET (IPv4, IPv6, ~20ms RTT, and Link Separation)."
}

usage() {
    echo "Usage: $0 {setup|status|verify|teardown|snapshot-host <file>|check-host-invariance <file>}"
    echo ""
    echo "Commands:"
    echo "  setup                  Create namespaces, veth interfaces, routing, neighbor tables, and 10ms delays"
    echo "  status                 Inspect existing namespaces, addresses, routes, and tc qdiscs"
    echo "  verify                 Execute 10-ping samples, validate ~20ms RTT, and verify link separation"
    echo "  teardown               Delegate to lab/teardown.sh to cleanly remove PS-028 resources"
    echo "  snapshot-host <file>   Record baseline host interface, IPv4/IPv6 routes, and routing rules"
    echo "  check-host-invariance <file> Compare current host state against baseline and assert zero diff"
    exit 1
}

# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------
main() {
    local action="${1:-setup}"

    case "$action" in
        snapshot-host)
            [[ $# -lt 2 ]] && { echo "Error: Missing output file path." >&2; exit 1; }
            snapshot_host_state "$2"
            ;;
        check-host-invariance)
            [[ $# -lt 2 ]] && { echo "Error: Missing baseline file path." >&2; exit 1; }
            check_host_invariance "$2"
            ;;
        setup)
            check_root
            check_dependencies
            setup_topology
            ;;
        status)
            check_root
            check_dependencies
            status_topology
            ;;
        verify)
            check_root
            check_dependencies
            verify_topology
            ;;
        teardown)
            check_root
            if [[ -x "$TEARDOWN_SCRIPT" ]]; then
                "$TEARDOWN_SCRIPT"
            else
                log_error "Teardown script ($TEARDOWN_SCRIPT) not found or not executable."
                exit 1
            fi
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
