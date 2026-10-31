#!/usr/bin/env bash
# ==============================================================================
# PS-028 Controlled DNS Server Acceptance Test Suite
# Work Package A3: Verification of DNS resolution, concurrency, fault injection,
# client resolver integration, structured logging, and transactional recovery.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DNS_SERVER_SCRIPT="${SCRIPT_DIR}/dns_server.py"
MANAGE_DNS="${SCRIPT_DIR}/manage_dns.sh"
CONFIG_FILE="${SCRIPT_DIR}/dns_config.json"
CONFIG_BAK="${SCRIPT_DIR}/dns_config.json.bak"
LOG_FILE="${SCRIPT_DIR}/dns.log"
LOCK_FILE="${SCRIPT_DIR}/.verify_dns.lock"

NS_CL="ps028-cl"
NS_RT="ps028-rt"
BIND_IP="10.0.1.1"
BIND_PORT="53"

log_info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
log_ok()    { echo -e "\033[1;32m[OK]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# ------------------------------------------------------------------------------
# Structured Query-Log Validation & Focused Testing Helper (WP A3 Test 10)
# ------------------------------------------------------------------------------
validate_query_log() {
    local target_file="${1:-$LOG_FILE}"
    if [[ ! -f "$target_file" ]]; then
        log_error "Log file does not exist: $target_file"
        return 1
    fi

    log_info "Validating structured query log: $target_file"
    python3 -c '
import datetime
import ipaddress
import os
import re
import sys
import tempfile

LINE_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"client=([^\s]+)\s+"
    r"proto=(UDP|TCP)\s+"
    r"qname=([^\s]+)\s+"
    r"qtype=([A-Z0-9]+)\s+"
    r"rcode=([A-Z0-9]+)\s+"
    r"delay_ms=([0-9\.]+)\s+"
    r"resp_timestamp_iso=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"elapsed_ms=([0-9\.]+)$"
)

VALID_RCODES = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}

def validate_entry(line):
    line = line.strip()
    if not line or line.startswith("["):
        return None

    m = LINE_PATTERN.match(line)
    if not m:
        raise ValueError(f"Log line does not match structured query schema: {line}")

    recv_iso, client, proto, qname, qtype, rcode, delay_str, resp_iso, elapsed_str = m.groups()

    # Validate ISO-8601 millisecond timestamps
    try:
        t_recv = datetime.datetime.fromisoformat(recv_iso)
    except Exception as e:
        raise ValueError(f"Invalid receive timestamp \"{recv_iso}\": {e}")

    try:
        t_resp = datetime.datetime.fromisoformat(resp_iso)
    except Exception as e:
        raise ValueError(f"Invalid response timestamp \"{resp_iso}\": {e}")

    if t_resp < t_recv:
        raise ValueError(f"Response timestamp ({resp_iso}) is earlier than receive timestamp ({recv_iso})")

    # Validate client IP and port
    if ":" not in client:
        raise ValueError(f"Client missing port separator: \"{client}\"")
    ip_str, port_str = client.rsplit(":", 1)
    ip_clean = ip_str.strip("[]")
    try:
        ipaddress.ip_address(ip_clean)
    except Exception as e:
        raise ValueError(f"Invalid client IP address \"{ip_clean}\": {e}")

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError(f"Client port {port} out of range [1, 65535]")
    except ValueError:
        raise ValueError(f"Invalid client port \"{port_str}\"")

    # Validate protocol
    if proto not in ("UDP", "TCP"):
        raise ValueError(f"Invalid protocol \"{proto}\" (must be UDP or TCP)")

    # Validate QNAME
    if not qname.endswith("."):
        raise ValueError(f"QNAME must be a fully qualified domain name ending with dot: \"{qname}\"")
    if len(qname) < 2:
        raise ValueError(f"QNAME is empty: \"{qname}\"")

    # Validate QTYPE
    if not re.match(r"^[A-Z0-9]+$", qtype):
        raise ValueError(f"Invalid QTYPE format: \"{qtype}\"")

    # Validate RCODE
    if rcode not in VALID_RCODES:
        raise ValueError(f"Unrecognized or invalid RCODE: \"{rcode}\"")

    # Validate delay_ms
    try:
        delay_ms = float(delay_str)
        if delay_ms < 0:
            raise ValueError()
    except Exception:
        raise ValueError(f"Invalid delay_ms \"{delay_str}\"")

    # Validate elapsed_ms
    try:
        elapsed_ms = float(elapsed_str)
        if elapsed_ms < 0:
            raise ValueError()
    except Exception:
        raise ValueError(f"Invalid elapsed_ms \"{elapsed_str}\"")

    # Validate elapsed duration causality against configured delay
    if elapsed_ms < (delay_ms - 20.0):
        raise ValueError(f"elapsed_ms ({elapsed_ms}) is significantly less than configured delay_ms ({delay_ms})")

    return {
        "recv_iso": recv_iso,
        "t_recv": t_recv,
        "client": client,
        "ip": ip_clean,
        "port": port,
        "proto": proto,
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,
        "delay_ms": delay_ms,
        "resp_iso": resp_iso,
        "t_resp": t_resp,
        "elapsed_ms": elapsed_ms,
    }

def validate_query_log_file(filepath):
    if not os.path.exists(filepath):
        raise ValueError(f"Log file does not exist: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    matched_records = []
    for line_no, raw_line in enumerate(lines, 1):
        try:
            entry = validate_entry(raw_line)
            if entry:
                matched_records.append((line_no, entry))
        except Exception as e:
            raise ValueError(f"Log validation error on line {line_no}: {e}")

    if not matched_records:
        raise ValueError(f"Log file \"{filepath}\" contains no valid structured query entries (empty or comments only)!")

    # Check required acceptance run evidence
    has_successful_a = any(
        e["qname"] == "he.test." and e["qtype"] == "A" and e["rcode"] == "NOERROR" and e["delay_ms"] == 0.0
        for _, e in matched_records
    )
    has_successful_aaaa = any(
        e["qname"] == "he.test." and e["qtype"] == "AAAA" and e["rcode"] == "NOERROR" and e["delay_ms"] == 0.0
        for _, e in matched_records
    )
    has_delayed_aaaa = any(
        e["qname"] == "he.test." and e["qtype"] == "AAAA" and e["rcode"] == "NOERROR"
        and e["delay_ms"] >= 1000.0 and e["elapsed_ms"] >= 900.0
        for _, e in matched_records
    )
    has_tcp = any(e["proto"] == "TCP" and e["rcode"] == "NOERROR" for _, e in matched_records)
    has_udp = any(e["proto"] == "UDP" and e["rcode"] == "NOERROR" for _, e in matched_records)

    if not has_successful_a:
        raise ValueError("Missing required acceptance evidence: no successful immediate \"A\" query for \"he.test.\" found")
    if not has_successful_aaaa:
        raise ValueError("Missing required acceptance evidence: no successful immediate \"AAAA\" query for \"he.test.\" found")
    if not has_delayed_aaaa:
        raise ValueError("Missing required acceptance evidence: no delayed-AAAA concurrency test query found (delay_ms >= 1000.0)")
    if not has_tcp:
        raise ValueError("Missing required acceptance evidence: no successful TCP queries found")
    if not has_udp:
        raise ValueError("Missing required acceptance evidence: no successful UDP queries found")

    return len(matched_records)

def run_focused_tests():
    valid_udp = "2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13"
    valid_tcp_a = "2026-10-26T18:46:31.495+00:00 client=10.0.1.2:35939 proto=TCP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.496+00:00 elapsed_ms=1.00"
    valid_tcp_aaaa = "2026-10-26T18:46:31.538+00:00 client=10.0.1.2:36315 proto=TCP qname=he.test. qtype=AAAA rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.540+00:00 elapsed_ms=1.63"
    valid_delayed = "2026-10-26T18:46:31.771+00:00 client=10.0.1.2:36322 proto=UDP qname=he.test. qtype=AAAA rcode=NOERROR delay_ms=1000.0 resp_timestamp_iso=2026-10-26T18:46:32.781+00:00 elapsed_ms=1009.78"
    valid_aaaa = "2026-10-26T18:46:31.392+00:00 client=10.0.1.2:35212 proto=UDP qname=he.test. qtype=AAAA rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.395+00:00 elapsed_ms=3.30"
    valid_z = "2026-10-26T18:46:31.309Z client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332Z elapsed_ms=24.13"
    valid_v6 = "2026-10-26T18:46:31.309+00:00 client=[2001:db8:1::2]:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13"
    comment_line = "[2026-10-26T18:19:38.504+00:00] [INFO] Initializing DNS Server on 10.0.1.1:53..."

    assert validate_entry(valid_udp) is not None
    assert validate_entry(valid_tcp_a) is not None
    assert validate_entry(valid_delayed) is not None
    assert validate_entry(valid_aaaa) is not None
    assert validate_entry(valid_z) is not None
    assert validate_entry(valid_v6) is not None
    assert validate_entry(comment_line) is None
    assert validate_entry("   ") is None

    malformed_cases = [
        ("2026-10-26T18:46:31+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "missing millis"),
        ("2026-02-30T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "invalid date"),
        ("2026-10-26T18:46:31.309+00:00 client=999.999.999.999:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "invalid IP"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:70000 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "port > 65535"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:0 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "port 0"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "missing port"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=ICMP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "invalid proto ICMP"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=udp qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "lowercase proto"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "qname without dot"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=INVALIDRCODE delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "invalid rcode"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=-1.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "negative delay"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=-10.00", "negative elapsed"),
        ("2026-10-26T18:46:35.000+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=0.0 resp_timestamp_iso=2026-10-26T18:46:31.000+00:00 elapsed_ms=1.00", "reversed timestamps"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=24.13", "missing delay_ms"),
        ("2026-10-26T18:46:31.309+00:00 client=10.0.1.2:39400 proto=UDP qname=he.test. qtype=A rcode=NOERROR delay_ms=1000.0 resp_timestamp_iso=2026-10-26T18:46:31.332+00:00 elapsed_ms=10.0", "elapsed less than delay"),
    ]

    for bad_line, desc in malformed_cases:
        try:
            validate_entry(bad_line)
            raise AssertionError(f"Expected failure for case \"{desc}\", but validation succeeded: {bad_line}")
        except ValueError:
            pass

    full_mock = f"{valid_udp}\n{valid_aaaa}\n{valid_tcp_a}\n{valid_delayed}\n"
    rejection_files = [
        ("", "Empty file"),
        ("[INFO] Comment line only\n", "Comments only"),
        (f"{valid_aaaa}\n{valid_tcp_aaaa}\n{valid_delayed}\n", "Missing immediate A"),
        (f"{valid_udp}\n{valid_tcp_a}\n{valid_delayed}\n", "Missing immediate AAAA"),
        (f"{valid_udp}\n{valid_aaaa}\n{valid_tcp_a}\n", "Missing delayed AAAA"),
        (f"{valid_udp}\n{valid_aaaa}\n{valid_delayed}\n", "Missing TCP"),
        (f"{full_mock}corrupted line\n", "Corrupted entry"),
    ]

    for content, desc in rejection_files:
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            tf.write(content)
            tf.flush()
            tname = tf.name
        try:
            validate_query_log_file(tname)
            raise AssertionError(f"Expected file failure for \"{desc}\"")
        except ValueError:
            pass
        finally:
            if os.path.exists(tname):
                os.unlink(tname)

target = sys.argv[1] if len(sys.argv) > 1 else None
run_focused_tests()
print("Focused validator tests PASSED: 22 unit & edge-case assertions verified.")
if target:
    count = validate_query_log_file(target)
    print(f"Validated {count} structured DNS query log entries in {target}.")
    print("Verified required acceptance evidence: immediate A/AAAA, TCP, UDP, and delayed-AAAA concurrency test.")
' "$target_file"
}

# ------------------------------------------------------------------------------
# Focused CLI Dispatch (Allows running T10/validator tests without root)
# ------------------------------------------------------------------------------
if [[ "${1:-}" == "--validate-log" || "${1:-}" == "--test-t10" || "${1:-}" == "--test-validator" ]]; then
    target_log="${2:-$LOG_FILE}"
    validate_query_log "$target_log"
    log_ok "Test 10 PASSED: Structured log entries verified for millisecond precision and schema."
    exit 0
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0 [--validate-log [path]] [--test-t10] [--test-validator]"
    echo "       sudo $0  # Run full acceptance test suite"
    exit 0
fi

# ------------------------------------------------------------------------------
# 1. Root & Concurrency Lock Acquisition
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "verify_dns.sh requires root privileges to execute network namespace tests and manage DNS. Please run with sudo."
    exit 1
fi

log_info "Acquiring exclusive verification lock on $LOCK_FILE..."
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log_error "Cannot execute verify_dns.sh: exclusive lock $LOCK_FILE is currently held by another test or recovery process."
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Schema Validation Helper
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
# 3. Crash-Safe Backup Creation
# ------------------------------------------------------------------------------
create_safe_backup() {
    local orig="$CONFIG_FILE"
    local bak="$CONFIG_BAK"
    local tmp_bak

    if [[ -f "$bak" ]]; then
        log_error "Leftover backup $bak detected from a previous crash/SIGKILL."
        log_error "Run 'sudo ./lab/manage_dns.sh recover-config' to inspect and restore."
        return 1
    fi

    # Step 1: Create unique temporary file in lab directory
    tmp_bak=$(mktemp "${SCRIPT_DIR}/dns_config.json.bak.tmp.XXXXXX" 2>/dev/null || true)
    if [[ -z "$tmp_bak" || ! -f "$tmp_bak" ]]; then
        log_error "Failed to create unique temporary backup file in ${SCRIPT_DIR}."
        return 1
    fi

    # Step 2: Copy baseline configuration into temporary file and check status
    if ! cp -a "$orig" "$tmp_bak"; then
        log_error "Failed to copy $orig to temporary file $tmp_bak."
        rm -f "$tmp_bak"
        return 1
    fi

    # Step 3: Validate temporary file before publishing
    if ! validate_config_schema "$tmp_bak"; then
        log_error "Active configuration $orig failed baseline schema validation! Backup not created."
        rm -f "$tmp_bak"
        return 1
    fi

    # Step 4: Atomically link temporary file to backup (guaranteed to fail if bak exists)
    if ! ln "$tmp_bak" "$bak" 2>/dev/null; then
        log_error "Failed to atomically publish $bak (target may already exist)."
        rm -f "$tmp_bak"
        return 1
    fi

    rm -f "$tmp_bak"
    log_ok "Baseline configuration verified and crash-safe backup created at $bak."
    return 0
}

# ------------------------------------------------------------------------------
# 4. In-Process 5-Step Transactional Recovery Trap
# ------------------------------------------------------------------------------
execute_transactional_recovery() {
    local orig="$CONFIG_FILE"
    local bak="$CONFIG_BAK"

    if [[ ! -f "$bak" ]]; then
        return 0
    fi

    log_info "Initiating 5-step transactional recovery from $bak..."

    # Step 1: Create unique temporary file in the same directory
    local tmp_restore
    tmp_restore=$(mktemp "${SCRIPT_DIR}/dns_config.json.tmp.XXXXXX" 2>/dev/null || true)
    if [[ -z "$tmp_restore" || ! -f "$tmp_restore" ]]; then
        log_error "Recovery Step 1 failed: Could not create unique temporary file! Backup retained at $bak."
        return 1
    fi

    # Step 2: Copy backup into temporary file and check status explicitly
    if ! cp -a "$bak" "$tmp_restore"; then
        log_error "Recovery Step 2 failed: Copy from $bak to $tmp_restore failed! Backup retained at $bak."
        rm -f "$tmp_restore"
        return 1
    fi

    # Step 3: Run strict schema validation on temporary file before publishing
    if ! validate_config_schema "$tmp_restore"; then
        log_error "Recovery Step 3 failed: Schema validation failed on $tmp_restore! Backup retained at $bak."
        rm -f "$tmp_restore"
        return 1
    fi

    # Step 4: Atomically replace dns_config.json and check status explicitly
    if ! mv -f "$tmp_restore" "$orig"; then
        log_error "Recovery Step 4 failed: Atomic rename $tmp_restore -> $orig failed! Backup retained at $bak."
        rm -f "$tmp_restore"
        return 1
    fi

    # Step 5: Reload DNS and verify NOERROR plus exact A and AAAA answers over network
    if ! "$MANAGE_DNS" reload; then
        log_error "Recovery Step 5 failed: DNS reload failed! Backup retained at $bak."
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
        log_ok "Baseline DNS configuration verified (NOERROR, correct records). Removing backup."
        rm -f "$bak"
        return 0
    else
        log_error "Recovery verification failed! A status: '$status_a', AAAA status: '$status_aaaa'."
        log_error "Backup retained at $bak. Manual recovery required."
        return 1
    fi
}

restore_configuration() {
    local target_exit="$1"
    trap - EXIT ERR INT TERM

    local rc=0
    execute_transactional_recovery || rc=$?

    flock -u 200 2>/dev/null || true
    exec 200>&-

    if [[ "$rc" -ne 0 ]]; then
        exit 1
    fi
    exit "$target_exit"
}

trap 'restore_configuration 130' INT
trap 'restore_configuration 143' TERM
trap 'restore_configuration $?' EXIT

# ------------------------------------------------------------------------------
# 5. Test Suite Execution
# ------------------------------------------------------------------------------
main() {
    log_info "================================================================="
    log_info "PS-028 Controlled DNS Server Acceptance Tests"
    log_info "================================================================="

    # Pre-test server health check
    if ! "$MANAGE_DNS" status >/dev/null 2>&1; then
        log_info "Starting Controlled DNS Server via manage_dns.sh..."
        "$MANAGE_DNS" start
    fi

    # Establish atomic verified backup
    create_safe_backup

    # --------------------------------------------------------------------------
    # Test 1: Immediate A Resolution (UDP)
    # --------------------------------------------------------------------------
    log_info "--- Test 1: Immediate A Resolution over UDP ---"
    local t1_out t1_status t1_ans
    t1_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test A +notcp +time=1 +tries=1)
    t1_status=$(echo "$t1_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t1_ans=$(echo "$t1_out" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+A\s+10\.0\.2\.10' || true)

    if [[ "$t1_status" == "NOERROR" && -n "$t1_ans" ]]; then
        log_ok "Test 1 PASSED: A record resolved to 10.0.2.10 (status: NOERROR)."
    else
        log_error "Test 1 FAILED: status: '$t1_status', answer: '$t1_ans'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 2: Immediate AAAA Resolution (UDP)
    # --------------------------------------------------------------------------
    log_info "--- Test 2: Immediate AAAA Resolution over UDP ---"
    local t2_out t2_status t2_ans
    t2_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test AAAA +notcp +time=1 +tries=1)
    t2_status=$(echo "$t2_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t2_ans=$(echo "$t2_out" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+AAAA\s+2001:db8:2::10' || true)

    if [[ "$t2_status" == "NOERROR" && -n "$t2_ans" ]]; then
        log_ok "Test 2 PASSED: AAAA record resolved to 2001:db8:2::10 (status: NOERROR)."
    else
        log_error "Test 2 FAILED: status: '$t2_status', answer: '$t2_ans'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 3a: TCP Resolution for A Record
    # --------------------------------------------------------------------------
    log_info "--- Test 3a: TCP Resolution for A Record ---"
    local t3a_out t3a_status t3a_ans
    t3a_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test A +tcp +time=2 +tries=1)
    t3a_status=$(echo "$t3a_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t3a_ans=$(echo "$t3a_out" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+A\s+10\.0\.2\.10' || true)

    if [[ "$t3a_status" == "NOERROR" && -n "$t3a_ans" ]]; then
        log_ok "Test 3a PASSED: A record resolved over TCP (status: NOERROR)."
    else
        log_error "Test 3a FAILED: status: '$t3a_status', answer: '$t3a_ans'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 3b: TCP Resolution for AAAA Record
    # --------------------------------------------------------------------------
    log_info "--- Test 3b: TCP Resolution for AAAA Record ---"
    local t3b_out t3b_status t3b_ans
    t3b_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test AAAA +tcp +time=2 +tries=1)
    t3b_status=$(echo "$t3b_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t3b_ans=$(echo "$t3b_out" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+AAAA\s+2001:db8:2::10' || true)

    if [[ "$t3b_status" == "NOERROR" && -n "$t3b_ans" ]]; then
        log_ok "Test 3b PASSED: AAAA record resolved over TCP (status: NOERROR)."
    else
        log_error "Test 3b FAILED: status: '$t3b_status', answer: '$t3b_ans'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 4: Concurrency: 1000ms Delayed AAAA vs Immediate A (< 250ms Wall-Clock)
    # --------------------------------------------------------------------------
    log_info "--- Test 4: Concurrency: Delayed AAAA vs Immediate A ---"
    python3 -c '
import json
with open("'"$CONFIG_FILE"'", "r") as f:
    d = json.load(f)
d["rules"]["AAAA"]["delay_ms"] = 1000
with open("'"$CONFIG_FILE"'", "w") as f:
    json.dump(d, f, indent=2)
'
    "$MANAGE_DNS" reload

    local aaaa_tmp="/tmp/ps028_t4_aaaa.$$"
    local a_tmp="/tmp/ps028_t4_a.$$"
    rm -f "$aaaa_tmp" "$a_tmp"

    log_info "Dispatching 1000ms delayed AAAA query in background..."
    (
        ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test AAAA +notcp +time=3 +tries=1 > "$aaaa_tmp" 2>&1
    ) &
    local bg_pid=$!

    # 50ms stagger to ensure AAAA task is sleeping on server
    sleep 0.05

    log_info "Dispatching immediate A query in foreground..."
    local t_start t_end duration_ms
    t_start=$(date +%s%3N)
    ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test A +notcp +time=1 +tries=1 > "$a_tmp" 2>&1 || true
    t_end=$(date +%s%3N)
    duration_ms=$((t_end - t_start))

    wait "$bg_pid"

    local t4_a_ans t4_aaaa_ans
    t4_a_ans=$(grep -E '^he\.test\.\s+[0-9]+\s+IN\s+A\s+10\.0\.2\.10' "$a_tmp" || true)
    t4_aaaa_ans=$(grep -E '^he\.test\.\s+[0-9]+\s+IN\s+AAAA\s+2001:db8:2::10' "$aaaa_tmp" || true)

    log_info "Query A wall-clock latency: ${duration_ms} ms (threshold: < 250 ms)."
    rm -f "$aaaa_tmp" "$a_tmp"

    if [[ "$duration_ms" -lt 250 && -n "$t4_a_ans" && -n "$t4_aaaa_ans" ]]; then
        log_ok "Test 4 PASSED: Non-blocking concurrency verified. Delayed AAAA did not block immediate A."
    else
        log_error "Test 4 FAILED: duration_ms=$duration_ms (must be < 250ms), A ans: '$t4_a_ans', AAAA ans: '$t4_aaaa_ans'."
        return 1
    fi

    # Reset config to baseline
    cp -a "$CONFIG_BAK" "$CONFIG_FILE"
    "$MANAGE_DNS" reload

    # --------------------------------------------------------------------------
    # Test 5: Dynamic Fault Injection (SERVFAIL on AAAA)
    # --------------------------------------------------------------------------
    log_info "--- Test 5: Dynamic Fault Injection (SERVFAIL on AAAA) ---"
    python3 -c '
import json
with open("'"$CONFIG_FILE"'", "r") as f:
    d = json.load(f)
d["rules"]["AAAA"]["rcode"] = "SERVFAIL"
with open("'"$CONFIG_FILE"'", "w") as f:
    json.dump(d, f, indent=2)
'
    "$MANAGE_DNS" reload

    local t5_out t5_status
    t5_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test AAAA +notcp +time=1 +tries=1)
    t5_status=$(echo "$t5_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")

    # Reset immediately
    cp -a "$CONFIG_BAK" "$CONFIG_FILE"
    "$MANAGE_DNS" reload

    if [[ "$t5_status" == "SERVFAIL" ]]; then
        log_ok "Test 5 PASSED: Injected SERVFAIL correctly returned on AAAA query."
    else
        log_error "Test 5 FAILED: Expected SERVFAIL, got '$t5_status'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 6: Malformed Config Rejection
    # --------------------------------------------------------------------------
    log_info "--- Test 6: Malformed Config Rejection ---"
    echo "{ this is invalid json syntax {" > "$CONFIG_FILE"
    "$MANAGE_DNS" reload

    local t6_out t6_status t6_ans
    t6_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test A +notcp +time=1 +tries=1)
    t6_status=$(echo "$t6_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t6_ans=$(echo "$t6_out" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+A\s+10\.0\.2\.10' || true)

    # Restore valid configuration
    cp -a "$CONFIG_BAK" "$CONFIG_FILE"
    "$MANAGE_DNS" reload

    if [[ "$t6_status" == "NOERROR" && -n "$t6_ans" ]]; then
        log_ok "Test 6 PASSED: Server rejected malformed config and retained active valid baseline rules."
    else
        log_error "Test 6 FAILED: Server failed to serve baseline after malformed reload (status: '$t6_status')."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 7: Boundary: NXDOMAIN on Unknown Domain
    # --------------------------------------------------------------------------
    log_info "--- Test 7: Boundary: NXDOMAIN on Unknown Domain ---"
    local t7_out t7_status
    t7_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" unknown.domain.test A +notcp +time=1 +tries=1)
    t7_status=$(echo "$t7_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")

    if [[ "$t7_status" == "NXDOMAIN" ]]; then
        log_ok "Test 7 PASSED: Unknown domain query returned NXDOMAIN."
    else
        log_error "Test 7 FAILED: Expected NXDOMAIN, got '$t7_status'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 8: Boundary: NODATA on Unsupported Record Type
    # --------------------------------------------------------------------------
    log_info "--- Test 8: Boundary: NODATA on Unsupported Record Type ---"
    local t8_out t8_status t8_ans_count
    t8_out=$(ip netns exec "$NS_CL" dig "@${BIND_IP}" -p "${BIND_PORT}" he.test TXT +notcp +time=1 +tries=1)
    t8_status=$(echo "$t8_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t8_ans_count=$(echo "$t8_out" | grep -oP 'ANSWER: \K[0-9]+' || echo "1")

    if [[ "$t8_status" == "NOERROR" && "$t8_ans_count" == "0" ]]; then
        log_ok "Test 8 PASSED: Unsupported record type returned NOERROR with 0 answers (NODATA)."
    else
        log_error "Test 8 FAILED: status: '$t8_status', answer count: '$t8_ans_count' (expected 0)."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 9: Default Client Resolution (No @10.0.1.1)
    # --------------------------------------------------------------------------
    log_info "--- Test 9: Default Client Resolution via /etc/netns/ps028-cl/resolv.conf ---"
    local t9_out t9_status t9_ans
    t9_out=$(ip netns exec "$NS_CL" dig he.test A +time=1 +tries=1)
    t9_status=$(echo "$t9_out" | grep -oP 'status: \K[A-Z]+' || echo "UNKNOWN")
    t9_ans=$(echo "$t9_out" | grep -E '^he\.test\.\s+[0-9]+\s+IN\s+A\s+10\.0\.2\.10' || true)

    if [[ "$t9_status" == "NOERROR" && -n "$t9_ans" ]]; then
        log_ok "Test 9 PASSED: Standard client dig resolved he.test via namespace resolv.conf."
    else
        log_error "Test 9 FAILED: status: '$t9_status', answer: '$t9_ans'."
        return 1
    fi

    # --------------------------------------------------------------------------
    # Test 10: Query-Log Validation
    # --------------------------------------------------------------------------
    log_info "--- Test 10: Structured Query-Log Validation ---"
    validate_query_log "$LOG_FILE"
    log_ok "Test 10 PASSED: Structured log entries verified for millisecond precision and schema."

    log_ok "================================================================="
    log_ok "ALL 10 ACCEPTANCE TESTS PASSED SUCCESSFULLY!"
    log_ok "================================================================="
    return 0
}

main "$@"
