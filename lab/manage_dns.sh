#!/usr/bin/env bash
# ==============================================================================
# PS-028 Controlled DNS Server Management Script
# Work Package A3: Safe lifecycle, pidfd signaling, and resolver tracking.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DNS_SERVER_SCRIPT="${SCRIPT_DIR}/dns_server.py"
CONFIG_FILE="${SCRIPT_DIR}/dns_config.json"
CONFIG_BAK="${SCRIPT_DIR}/dns_config.json.bak"
LOG_FILE="${SCRIPT_DIR}/dns.log"
STDERR_LOG="${SCRIPT_DIR}/dns_stderr.log"
PID_FILE="${SCRIPT_DIR}/dns.pid"
RESOLV_CONF_SOURCE="${SCRIPT_DIR}/cl_resolv.conf"
RESOLV_MARKER="${SCRIPT_DIR}/.resolv_installed_by_ps028"
LOCK_FILE="${SCRIPT_DIR}/.verify_dns.lock"

NS_RT="ps028-rt"
NS_CL="ps028-cl"
NETNS_RESOLV_DIR="/etc/netns/${NS_CL}"
NETNS_RESOLV_FILE="${NETNS_RESOLV_DIR}/resolv.conf"
BIND_IP="10.0.1.1"
BIND_PORT="53"

log_info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
log_ok()    { echo -e "\033[1;32m[OK]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# ------------------------------------------------------------------------------
# Privilege Guard
# ------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This action requires root privileges. Please run with sudo."
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Strict Schema Validation Helper
# ------------------------------------------------------------------------------
validate_config_schema() {
    local target_file="$1"
    if [[ ! -f "$target_file" ]]; then
        log_error "Configuration file does not exist: $target_file"
        return 1
    fi

    python3 -c '
import sys, json, ipaddress

filepath = sys.argv[1]

try:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    sys.stderr.write(f"JSON decode failure in {filepath}: {e}\n")
    sys.exit(1)

try:
    if type(data) is not dict:
        raise TypeError("Root must be a JSON object")

    expected_keys = {"zone", "default_ttl", "rules", "behavior"}
    if set(data.keys()) != expected_keys:
        raise ValueError(f"Root keys mismatch: expected {expected_keys}, got {set(data.keys())}")

    # Zone
    if type(data["zone"]) is not str or data["zone"] != "he.test.":
        raise ValueError("zone must be string \"he.test.\"")

    # TTL (strictly integer, reject booleans)
    if type(data["default_ttl"]) is not int or type(data["default_ttl"]) is bool:
        raise TypeError("default_ttl must be an integer, not boolean")
    if data["default_ttl"] != 1:
        raise ValueError("default_ttl must be exactly 1")

    # Behavior
    if type(data["behavior"]) is not dict:
        raise TypeError("behavior must be an object")
    if set(data["behavior"].keys()) != {"unknown_domain_rcode", "unsupported_type_rcode"}:
        raise ValueError("behavior keys mismatch")
    if data["behavior"]["unknown_domain_rcode"] != "NXDOMAIN":
        raise ValueError("unknown_domain_rcode must be NXDOMAIN")
    if data["behavior"]["unsupported_type_rcode"] != "NOERROR":
        raise ValueError("unsupported_type_rcode must be NOERROR")

    # Rules
    rules = data["rules"]
    if type(rules) is not dict or set(rules.keys()) != {"A", "AAAA"}:
        raise ValueError("rules must contain exactly A and AAAA")

    # Rule A
    rule_a = rules["A"]
    if type(rule_a) is not dict or set(rule_a.keys()) != {"address", "delay_ms", "rcode"}:
        raise ValueError("rules.A keys mismatch")
    if type(rule_a["address"]) is not str or rule_a["address"] != "10.0.2.10":
        raise ValueError("rules.A.address must be \"10.0.2.10\"")
    ipaddress.IPv4Address(rule_a["address"])
    if type(rule_a["delay_ms"]) is not int or type(rule_a["delay_ms"]) is bool:
        raise TypeError("rules.A.delay_ms must be an integer, not boolean")
    if rule_a["delay_ms"] != 0:
        raise ValueError("rules.A.delay_ms must be 0")
    if type(rule_a["rcode"]) is not str or rule_a["rcode"] != "NOERROR":
        raise ValueError("rules.A.rcode must be \"NOERROR\"")

    # Rule AAAA
    rule_aaaa = rules["AAAA"]
    if type(rule_aaaa) is not dict or set(rule_aaaa.keys()) != {"address", "delay_ms", "rcode"}:
        raise ValueError("rules.AAAA keys mismatch")
    if type(rule_aaaa["address"]) is not str or rule_aaaa["address"] != "2001:db8:2::10":
        raise ValueError("rules.AAAA.address must be \"2001:db8:2::10\"")
    if ipaddress.IPv6Address(rule_aaaa["address"]) != ipaddress.IPv6Address("2001:db8:2::10"):
        raise ValueError("rules.AAAA.address must be canonical IPv6")
    if type(rule_aaaa["delay_ms"]) is not int or type(rule_aaaa["delay_ms"]) is bool:
        raise TypeError("rules.AAAA.delay_ms must be an integer, not boolean")
    if rule_aaaa["delay_ms"] != 0:
        raise ValueError("rules.AAAA.delay_ms must be 0")
    if type(rule_aaaa["rcode"]) is not str or rule_aaaa["rcode"] != "NOERROR":
        raise ValueError("rules.AAAA.rcode must be \"NOERROR\"")

    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"Schema validation failure in {filepath}: {e}\n")
    sys.exit(1)
' "$target_file"
}

# ------------------------------------------------------------------------------
# Confirmed Process Absence Check
# ------------------------------------------------------------------------------
confirm_process_absence() {
    local pid="$1"
    local kill_err=""

    if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
        echo "uncertain_invalid_pid"
        return 0
    fi

    if kill_err=$(kill -0 "$pid" 2>&1); then
        echo "alive"
        return 0
    fi

    if echo "$kill_err" | grep -qi "Operation not permitted"; then
        echo "alive_permission_denied"
        return 0
    fi

    if echo "$kill_err" | grep -qi "No such process"; then
        if [[ ! -d "/proc/$pid" ]]; then
            echo "confirmed_absent"
            return 0
        else
            echo "uncertain_proc_dir_exists"
            return 0
        fi
    fi

    echo "uncertain_inspection_failed"
    return 0
}

# ------------------------------------------------------------------------------
# Process Identity Verification (Read-Only)
# ------------------------------------------------------------------------------
verify_process_identity() {
    local pid="$1"
    local resolved_script
    resolved_script="$(realpath "$DNS_SERVER_SCRIPT")"

    python3 -c '
import os, sys

pid = int(sys.argv[1])
expected_script = sys.argv[2]
ns_name = sys.argv[3]

# 1. Revalidate exact NUL-separated cmdline argument
try:
    with open(f"/proc/{pid}/cmdline", "rb") as f:
        args = [a.decode("utf-8", errors="replace") for a in f.read().split(b"\x00") if a]
    if expected_script not in args:
        sys.stderr.write("cmdline_mismatch\n")
        sys.exit(3)
except (FileNotFoundError, ProcessLookupError):
    sys.stderr.write("stale\n")
    sys.exit(1)
except PermissionError:
    sys.stderr.write("permission_denied\n")
    sys.exit(2)

# 2. Revalidate network namespace identity
try:
    target_stat = os.stat(f"/run/netns/{ns_name}")
    proc_stat = os.stat(f"/proc/{pid}/ns/net")
    if target_stat.st_ino != proc_stat.st_ino:
        sys.stderr.write("netns_mismatch\n")
        sys.exit(4)
except (FileNotFoundError, ProcessLookupError):
    sys.stderr.write("stale\n")
    sys.exit(1)
except PermissionError:
    sys.stderr.write("permission_denied\n")
    sys.exit(2)

sys.stdout.write("verified\n")
sys.exit(0)
' "$pid" "$resolved_script" "$NS_RT"
}

# ------------------------------------------------------------------------------
# Verified Signal Delivery (pidfd with fail-closed fallback)
# ------------------------------------------------------------------------------
send_verified_signal() {
    local pid="$1"
    local sig_name="$2"
    local resolved_script
    resolved_script="$(realpath "$DNS_SERVER_SCRIPT")"

    python3 -c '
import os, sys, signal, errno

pid = int(sys.argv[1])
sig_name = sys.argv[2]
expected_script = sys.argv[3]
sig = getattr(signal, sig_name)

# 1. Attempt pidfd acquisition
has_pidfd_support = hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
pfd = None
fallback_to_kill = False

if has_pidfd_support:
    try:
        pfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        sys.stderr.write("stale\n")
        sys.exit(1)
    except PermissionError:
        sys.stderr.write("permission_denied\n")
        sys.exit(2)
    except OSError as e:
        if e.errno == errno.ENOSYS:
            fallback_to_kill = True
        elif e.errno in (errno.EMFILE, errno.ENFILE):
            sys.stderr.write("fd_exhaustion\n")
            sys.exit(5)
        else:
            sys.stderr.write(f"oserror_{e.errno}\n")
            sys.exit(6)
else:
    fallback_to_kill = True

# 2. Revalidate exact NUL-separated cmdline argument
try:
    with open(f"/proc/{pid}/cmdline", "rb") as f:
        args = [a.decode("utf-8", errors="replace") for a in f.read().split(b"\x00") if a]
    if expected_script not in args:
        sys.stderr.write("cmdline_mismatch\n")
        if pfd is not None: os.close(pfd)
        sys.exit(3)
except (FileNotFoundError, ProcessLookupError):
    sys.stderr.write("stale\n")
    if pfd is not None: os.close(pfd)
    sys.exit(1)
except PermissionError:
    sys.stderr.write("permission_denied\n")
    if pfd is not None: os.close(pfd)
    sys.exit(2)

# 3. Revalidate network namespace identity
try:
    target_stat = os.stat("/run/netns/ps028-rt")
    proc_stat = os.stat(f"/proc/{pid}/ns/net")
    if target_stat.st_ino != proc_stat.st_ino:
        sys.stderr.write("netns_mismatch\n")
        if pfd is not None: os.close(pfd)
        sys.exit(4)
except (FileNotFoundError, ProcessLookupError):
    sys.stderr.write("stale\n")
    if pfd is not None: os.close(pfd)
    sys.exit(1)
except PermissionError:
    sys.stderr.write("permission_denied\n")
    if pfd is not None: os.close(pfd)
    sys.exit(2)

# 4. Deliver signal
try:
    if pfd is not None:
        signal.pidfd_send_signal(pfd, sig)
        os.close(pfd)
    elif fallback_to_kill:
        os.kill(pid, sig)
    sys.stdout.write("signaled\n")
    sys.exit(0)
except ProcessLookupError:
    sys.stderr.write("stale\n")
    sys.exit(1)
except PermissionError:
    sys.stderr.write("permission_denied\n")
    sys.exit(2)
' "$pid" "$sig_name" "$resolved_script"
}

# ------------------------------------------------------------------------------
# Resolver Lifecycle Management
# ------------------------------------------------------------------------------
setup_resolver() {
    check_root
    log_info "Setting up client resolver configuration for $NS_CL..."

    if [[ -f "$NETNS_RESOLV_FILE" ]]; then
        if cmp -s "$RESOLV_CONF_SOURCE" "$NETNS_RESOLV_FILE"; then
            log_info "Resolver configuration $NETNS_RESOLV_FILE exists and matches source. No changes needed."
            return 0
        else
            log_error "Conflicting pre-existing configuration found at $NETNS_RESOLV_FILE!"
            log_error "Refusing to overwrite foreign resolver configuration. Manual review required."
            return 1
        fi
    fi

    mkdir -p "$NETNS_RESOLV_DIR"
    install -m 0644 "$RESOLV_CONF_SOURCE" "$NETNS_RESOLV_FILE"
    touch "$RESOLV_MARKER"
    log_ok "Installed $NETNS_RESOLV_FILE (ownership tracked in $RESOLV_MARKER)."
}

cleanup_resolver() {
    check_root
    log_info "Evaluating client resolver cleanup for $NS_CL..."

    if [[ ! -f "$RESOLV_MARKER" ]]; then
        log_info "Resolver configuration was not created by this project (no marker file). Leaving in place."
        return 0
    fi

    if [[ -f "$NETNS_RESOLV_FILE" ]]; then
        if cmp -s "$RESOLV_CONF_SOURCE" "$NETNS_RESOLV_FILE"; then
            log_info "Removing $NETNS_RESOLV_FILE created by PS-028..."
            rm -f "$NETNS_RESOLV_FILE"
            rmdir "$NETNS_RESOLV_DIR" 2>/dev/null || true
            rmdir "/etc/netns" 2>/dev/null || true
            rm -f "$RESOLV_MARKER"
            log_ok "Client resolver configuration cleaned up successfully."
        else
            log_warn "$NETNS_RESOLV_FILE was modified externally after installation. Leaving in place."
            rm -f "$RESOLV_MARKER"
        fi
    else
        rm -f "$RESOLV_MARKER"
    fi
}

# ------------------------------------------------------------------------------
# Transactional Recovery Routine (5-Step)
# ------------------------------------------------------------------------------
execute_transactional_recovery() {
    local orig="$CONFIG_FILE"
    local bak="$CONFIG_BAK"

    if [[ ! -f "$bak" ]]; then
        log_info "No backup file found at $bak. Configuration is clean."
        return 0
    fi

    log_info "Initiating 5-step transactional recovery from $bak..."

    # Step 1: Create unique temporary file in the same directory
    local tmp_restore
    tmp_restore=$(mktemp "${SCRIPT_DIR}/dns_config.json.tmp.XXXXXX" 2>/dev/null || true)
    if [[ -z "$tmp_restore" || ! -f "$tmp_restore" ]]; then
        log_error "Step 1 failed: Could not create unique temporary file in ${SCRIPT_DIR}! Backup retained at $bak."
        return 1
    fi

    # Step 2: Copy backup into temporary file and check status explicitly
    if ! cp -a "$bak" "$tmp_restore"; then
        log_error "Step 2 failed: Copy from $bak to $tmp_restore failed! Backup retained at $bak."
        rm -f "$tmp_restore"
        return 1
    fi

    # Step 3: Run strict schema validation on temporary file before publishing
    if ! validate_config_schema "$tmp_restore"; then
        log_error "Step 3 failed: Schema validation failed on $tmp_restore! Backup retained at $bak for manual inspection."
        rm -f "$tmp_restore"
        return 1
    fi

    # Step 4: Atomically replace dns_config.json and check status explicitly
    if ! mv -f "$tmp_restore" "$orig"; then
        log_error "Step 4 failed: Atomic rename $tmp_restore -> $orig failed! Backup retained at $bak."
        rm -f "$tmp_restore"
        return 1
    fi

    # Step 5: Reload DNS and verify NOERROR plus exact A and AAAA answers over network
    if ! reload_dns; then
        log_error "Step 5 failed: DNS reload failed! Backup retained at $bak."
        return 1
    fi

    local out_a out_aaaa status_a status_aaaa ans_a ans_aaaa
    out_a=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test A +notcp +time=1 +tries=1 2>/dev/null || true)
    out_aaaa=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test AAAA +notcp +time=1 +tries=1 2>/dev/null || true)

    status_a=$(echo "$out_a" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    status_aaaa=$(echo "$out_aaaa" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    ans_a=$(echo "$out_a" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+A\s+10\.0\.2\.10' || true)
    ans_aaaa=$(echo "$out_aaaa" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+AAAA\s+2001:db8:2::10' || true)

    if [[ "$status_a" == "NOERROR" && -n "$ans_a" && "$status_aaaa" == "NOERROR" && -n "$ans_aaaa" ]]; then
        log_ok "Step 5 passed: Verified status NOERROR and exact records (A: 10.0.2.10, AAAA: 2001:db8:2::10)."
        log_ok "Recovery completed successfully. Removing backup."
        rm -f "$bak"
        return 0
    else
        log_error "Step 5 failed: Query verification failed!"
        log_error "  Query A status: '$status_a', record found: '$ans_a'"
        log_error "  Query AAAA status: '$status_aaaa', record found: '$ans_aaaa'"
        log_error "Backup retained at $bak. Manual recovery required."
        return 1
    fi
}

recover_config() {
    check_root
    log_info "Acquiring exclusive lock on $LOCK_FILE for recovery..."

    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log_error "Cannot execute recover-config: exclusive lock $LOCK_FILE is currently held by an active test or recovery process."
        log_error "Wait for the active process to complete or verify no conflicting run exists. Zero modifications made."
        return 1
    fi

    local rc=0
    execute_transactional_recovery || rc=$?

    flock -u 200 2>/dev/null || true
    exec 200>&-
    return "$rc"
}

# ------------------------------------------------------------------------------
# Core Lifecycle: Start, Stop, Reload, Status
# ------------------------------------------------------------------------------
start_dns() {
    check_root
    log_info "Starting Controlled DNS Server inside namespace $NS_RT..."

    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file $CONFIG_FILE not found."
        return 1
    fi

    # Check for existing instance
    if [[ -f "$PID_FILE" ]]; then
        local existing_pid
        existing_pid=$(tr -d '[:space:]' < "$PID_FILE" || true)
        if [[ -n "$existing_pid" && "$existing_pid" =~ ^[0-9]+$ ]]; then
            local absence
            absence=$(confirm_process_absence "$existing_pid")
            case "$absence" in
                confirmed_absent)
                    log_info "Removing confirmed stale PID file for inactive PID $existing_pid."
                    rm -f "$PID_FILE"
                    ;;
                alive|alive_permission_denied)
                    log_error "DNS server PID file exists ($existing_pid, status: $absence). Refusing to start another instance."
                    return 1
                    ;;
                uncertain*)
                    log_error "DNS server PID file exists but process state is uncertain ($existing_pid, status: $absence). Refusing to start another instance."
                    return 1
                    ;;
                *)
                    log_error "DNS server PID file exists ($existing_pid, status: $absence). Refusing to start another instance."
                    return 1
                    ;;
            esac
        fi
    fi

    # Set up client resolver
    setup_resolver

    # Launch daemon
    log_info "Launching $DNS_SERVER_SCRIPT on $BIND_IP:$BIND_PORT..."
    ip netns exec "$NS_RT" python3 "$DNS_SERVER_SCRIPT" \
        --bind "$BIND_IP" \
        --port "$BIND_PORT" \
        --config "$CONFIG_FILE" \
        --log-file "$LOG_FILE" \
        --pid-file "$PID_FILE" >> "$STDERR_LOG" 2>&1 &

    # Poll for socket readiness
    local count=0
    local ready=false
    while [[ $count -lt 30 ]]; do
        sleep 0.1
        count=$((count + 1))
        if [[ -f "$PID_FILE" ]]; then
            local pid
            pid=$(tr -d '[:space:]' < "$PID_FILE" || true)
            if [[ -n "$pid" ]] && ip netns exec "$NS_RT" ss -luntp "( sport = :$BIND_PORT )" 2>/dev/null | grep -q "pid=$pid"; then
                ready=true
                break
            fi
        fi
    done

    if [[ "$ready" == "true" ]]; then
        log_ok "DNS server successfully started and bound to $BIND_IP:$BIND_PORT (PID $(cat "$PID_FILE"))."
        return 0
    else
        log_error "DNS server failed to start or bind within 3 seconds. Checking stderr:"
        tail -n 20 "$STDERR_LOG" 2>/dev/null || true
        rm -f "$PID_FILE" 2>/dev/null || true
        return 1
    fi
}

stop_dns() {
    check_root
    log_info "Stopping Controlled DNS Server..."

    if [[ ! -f "$PID_FILE" ]]; then
        log_info "DNS server not running (no PID file found)."
        cleanup_resolver
        return 0
    fi

    local pid
    pid=$(tr -d '[:space:]' < "$PID_FILE" || true)
    if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
        log_error "PID file $PID_FILE is corrupt. Retaining file for manual inspection."
        return 1
    fi

    # Check process absence first
    local absence
    absence=$(confirm_process_absence "$pid")
    case "$absence" in
        confirmed_absent)
            log_info "Process $pid confirmed absent. Cleaning up stale PID file."
            rm -f "$PID_FILE"
            cleanup_resolver
            return 0
            ;;
        alive)
            # Process is running; proceed with stop sequence below
            ;;
        alive_permission_denied)
            log_error "Cannot stop PID $pid: permission denied."
            return 1
            ;;
        uncertain*)
            log_error "Cannot stop PID $pid: process state is uncertain ($absence). Retaining PID file."
            return 1
            ;;
        *)
            log_error "Cannot stop PID $pid: unexpected status ($absence). Retaining PID file."
            return 1
            ;;
    esac

    # Stage 1: Graceful SIGTERM via pidfd
    log_info "Sending SIGTERM to verified DNS server (PID $pid)..."
    local sig_out
    if ! sig_out=$(send_verified_signal "$pid" "SIGTERM" 2>&1); then
        log_error "Failed to deliver SIGTERM to PID $pid (reason: $sig_out). PID file retained."
        return 1
    fi

    # Wait up to 5 seconds
    local count=0
    while kill -0 "$pid" 2>/dev/null && [[ $count -lt 50 ]]; do
        sleep 0.1
        count=$((count + 1))
    done

    # Stage 2: Forceful SIGKILL if still running
    if kill -0 "$pid" 2>/dev/null; then
        log_warn "Process $pid did not exit after SIGTERM. Revalidating before SIGKILL..."
        if ! sig_out=$(send_verified_signal "$pid" "SIGKILL" 2>&1); then
            log_error "Failed to deliver SIGKILL to PID $pid (reason: $sig_out). PID file retained."
            return 1
        fi
        sleep 0.5
    fi

    # Final Termination Verification
    absence=$(confirm_process_absence "$pid")
    case "$absence" in
        confirmed_absent)
            rm -f "$PID_FILE"
            log_ok "DNS server (PID $pid) terminated cleanly."
            cleanup_resolver
            return 0
            ;;
        alive)
            log_error "Process $pid failed to terminate (still alive)! PID file retained."
            return 1
            ;;
        alive_permission_denied)
            log_error "Process $pid termination verification failed: permission denied. PID file retained."
            return 1
            ;;
        uncertain*)
            log_error "Process $pid termination verification uncertain (status: $absence)! PID file retained."
            return 1
            ;;
        *)
            log_error "Process $pid failed to terminate (status: $absence)! PID file retained."
            return 1
            ;;
    esac
}

reload_dns() {
    check_root
    # Note: reload does NOT acquire lab/.verify_dns.lock to prevent deadlocks during recovery
    log_info "Reloading Controlled DNS Server configuration via SIGHUP..."

    if [[ ! -f "$PID_FILE" ]]; then
        log_error "Cannot reload: DNS server PID file does not exist."
        return 1
    fi

    local pid
    pid=$(tr -d '[:space:]' < "$PID_FILE" || true)
    if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
        log_error "Cannot reload: PID file $PID_FILE is corrupt. Retaining PID file."
        return 1
    fi

    local sig_out
    if ! sig_out=$(send_verified_signal "$pid" "SIGHUP" 2>&1); then
        log_error "Failed to send SIGHUP to PID $pid (reason: $sig_out)."
        return 1
    fi

    # Brief delay for server coroutine to handle reload
    sleep 0.05
    log_ok "SIGHUP delivered to verified DNS server (PID $pid)."
    return 0
}

status_dns() {
    log_info "Checking Controlled DNS Server status..."

    if [[ ! -f "$PID_FILE" ]]; then
        echo "Status: STOPPED (no PID file)."
        return 3
    fi

    local pid
    pid=$(tr -d '[:space:]' < "$PID_FILE" || true)
    if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
        echo "Status: UNKNOWN (corrupt PID file: $(cat "$PID_FILE" 2>/dev/null || true))."
        return 3
    fi

    local absence
    absence=$(confirm_process_absence "$pid")
    case "$absence" in
        confirmed_absent)
            echo "Status: STOPPED (stale PID $pid)."
            return 3
            ;;
        uncertain*)
            echo "Status: UNKNOWN (PID $pid state uncertain: $absence)."
            return 3
            ;;
        alive|alive_permission_denied)
            if [[ $EUID -ne 0 ]]; then
                echo "Status: RUNNING (PID $pid alive; detailed cmdline/namespace check requires root)."
                return 0
            fi
            ;;
        *)
            echo "Status: UNKNOWN (PID $pid unhandled status: $absence)."
            return 3
            ;;
    esac

    local ident_out
    if ident_out=$(verify_process_identity "$pid" 2>&1); then
        echo "Status: RUNNING (PID $pid verified inside $NS_RT running $DNS_SERVER_SCRIPT)."
        ip netns exec "$NS_RT" ss -luntp "( sport = :$BIND_PORT )" 2>/dev/null || true
        return 0
    else
        echo "Status: UNHEALTHY (PID $pid validation failed: $ident_out)."
        return 1
    fi
}

usage() {
    echo "Usage: $0 {start|stop|reload|status|setup-resolver|cleanup-resolver|recover-config}"
    exit 1
}

# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------
case "${1:-}" in
    start)
        start_dns
        ;;
    stop)
        stop_dns
        ;;
    reload)
        reload_dns
        ;;
    status)
        status_dns
        ;;
    setup-resolver)
        setup_resolver
        ;;
    cleanup-resolver)
        cleanup_resolver
        ;;
    recover-config)
        recover_config
        ;;
    *)
        usage
        ;;
esac
