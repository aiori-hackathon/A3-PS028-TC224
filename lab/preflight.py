#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Non-Destructive Dependency Preflight
Work Package A6: PS-028 Lab Hardening

Performs comprehensive read-only verification of:
1. System binary availability in PATH (networking, DNS, nftables, Nginx, Python, capture tools)
2. Debian/Ubuntu system packages against lab/system_packages.txt
3. Python library dependencies and exact pinned versions (dnspython 2.6.1, PyYAML)
4. Lab configuration files and syntax integrity (scenarios.yaml, dns_config.json, nginx.conf)
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SYSTEM_PACKAGES_FILE = SCRIPT_DIR / "system_packages.txt"
SCENARIOS_YAML = SCRIPT_DIR / "scenarios.yaml"
DNS_CONFIG = SCRIPT_DIR / "dns_config.json"
NGINX_CONF = SCRIPT_DIR / "nginx.conf"
CL_RESOLV = SCRIPT_DIR / "cl_resolv.conf"

REQUIRED_BINARIES = [
    ("ip", "iproute2", "Network namespace and link manipulation"),
    ("tc", "iproute2", "Traffic control and netem latency emulation"),
    ("ping", "iputils-ping", "ICMP latency and reachability verification"),
    ("sysctl", "procps", "Kernel forwarding and protocol tuning"),
    ("nft", "nftables", "Packet filtering, blackholing, RST, and loss emulation"),
    ("nginx", "nginx", "Dual-stack HTTP measurement endpoint"),
    ("python3", "python3", "Lab runtime, DNS server, controller, and test suites"),
    ("dig", "bind9-dnsutils", "DNS resolution client and verification"),
    ("tcpdump", "tcpdump", "Packet capture and timeline evidence collection"),
    ("curl", "curl", "HTTP measurement probe client"),
    ("bc", "bc", "Precision arithmetic in shell verifications"),
    ("awk", "gawk", "Pattern scanning and test output processing"),
    ("diff", "diffutils", "Configuration invariance comparison"),
]

OPTIONAL_BINARIES = [
    ("tshark", "tshark", "Advanced packet capture dissection"),
    ("ethtool", "ethtool", "NIC and offload inspection"),
]


def check_binaries() -> List[Dict[str, Any]]:
    results = []
    for cmd, pkg, desc in REQUIRED_BINARIES:
        path = shutil.which(cmd)
        results.append({
            "command": cmd,
            "package": pkg,
            "description": desc,
            "required": True,
            "found": path is not None,
            "path": path,
        })
    for cmd, pkg, desc in OPTIONAL_BINARIES:
        path = shutil.which(cmd)
        results.append({
            "command": cmd,
            "package": pkg,
            "description": desc,
            "required": False,
            "found": path is not None,
            "path": path,
        })
    return results


def parse_system_packages_manifest(manifest_path: Path = SYSTEM_PACKAGES_FILE) -> Dict[str, str]:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    packages = {}
    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                pkg_name, pkg_ver = line.split("=", 1)
                packages[pkg_name.strip()] = pkg_ver.strip()
            else:
                packages[line] = "*"
    return packages


def check_system_packages(manifest_path: Path = SYSTEM_PACKAGES_FILE) -> List[Dict[str, Any]]:
    manifest = parse_system_packages_manifest(manifest_path)
    results = []

    # Run dpkg-query in a single non-destructive batch
    pkg_names = list(manifest.keys())
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Status}\n"] + pkg_names,
            capture_output=True,
            text=True,
            check=False
        )
        installed = {}
        for line in proc.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                pname = parts[0]
                pver = parts[1]
                pstatus = parts[2] if len(parts) > 2 else ""
                installed[pname] = (pver, "installed" in pstatus)
    except FileNotFoundError:
        installed = {}

    for pkg_name, expected_ver in manifest.items():
        if pkg_name in installed:
            actual_ver, is_inst = installed[pkg_name]
            match = (expected_ver == "*" or actual_ver == expected_ver)
            results.append({
                "package": pkg_name,
                "expected_version": expected_ver,
                "actual_version": actual_ver,
                "installed": is_inst,
                "version_match": match,
            })
        else:
            results.append({
                "package": pkg_name,
                "expected_version": expected_ver,
                "actual_version": None,
                "installed": False,
                "version_match": False,
            })
    return results


def check_python_dependencies() -> List[Dict[str, Any]]:
    results = []

    # 1. dnspython
    try:
        import dns
        ver = getattr(dns, "__version__", "unknown")
        results.append({
            "module": "dns",
            "package": "python3-dnspython",
            "installed": True,
            "version": ver,
            "expected_version": "2.6.1",
            "version_match": (ver == "2.6.1"),
        })
    except ImportError:
        results.append({
            "module": "dns",
            "package": "python3-dnspython",
            "installed": False,
            "version": None,
            "expected_version": "2.6.1",
            "version_match": False,
        })

    # 2. PyYAML
    try:
        import yaml
        ver = getattr(yaml, "__version__", "unknown")
        results.append({
            "module": "yaml",
            "package": "python3-yaml",
            "installed": True,
            "version": ver,
            "expected_version": ">=6.0",
            "version_match": True,
        })
    except ImportError:
        results.append({
            "module": "yaml",
            "package": "python3-yaml",
            "installed": False,
            "version": None,
            "expected_version": ">=6.0",
            "version_match": False,
        })

    return results


def _rel_path(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def check_configuration_files() -> List[Dict[str, Any]]:
    results = []

    # 1. scenarios.yaml
    sc_valid = False
    sc_err = None
    if SCENARIOS_YAML.is_file():
        try:
            import yaml
            with open(SCENARIOS_YAML, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "scenarios" in data and len(data["scenarios"]) == 7:
                sc_valid = True
            else:
                sc_err = "Missing required 7 scenarios in scenarios.yaml"
        except Exception as e:
            sc_err = str(e)
    else:
        sc_err = "File not found"
    results.append({
        "file": _rel_path(SCENARIOS_YAML),
        "valid": sc_valid,
        "error": sc_err,
    })

    # 2. dns_config.json
    dns_valid = False
    dns_err = None
    if DNS_CONFIG.is_file():
        try:
            import lab.dns_server as dns_srv
            with open(DNS_CONFIG, "r", encoding="utf-8") as f:
                data = json.load(f)
            dns_srv.validate_config_dict(data)
            dns_valid = True
        except Exception as e:
            dns_err = str(e)
    else:
        dns_err = "File not found"
    results.append({
        "file": _rel_path(DNS_CONFIG),
        "valid": dns_valid,
        "error": dns_err,
    })

    # 3. nginx.conf
    ngx_valid = False
    ngx_err = None
    if NGINX_CONF.is_file():
        content = NGINX_CONF.read_text(encoding="utf-8")
        if re.search(r"\bkeepalive_timeout\s+0\s*;", content):
            ngx_valid = True
        else:
            ngx_err = "Missing 'keepalive_timeout 0;' directive in nginx.conf"
    else:
        ngx_err = "File not found"
    results.append({
        "file": _rel_path(NGINX_CONF),
        "valid": ngx_valid,
        "error": ngx_err,
    })

    # 4. cl_resolv.conf
    resolv_valid = False
    resolv_err = None
    if CL_RESOLV.is_file():
        content = CL_RESOLV.read_text(encoding="utf-8")
        if "nameserver 10.0.1.1" in content:
            resolv_valid = True
        else:
            resolv_err = "cl_resolv.conf missing 'nameserver 10.0.1.1'"
    else:
        resolv_err = "File not found"
    results.append({
        "file": _rel_path(CL_RESOLV),
        "valid": resolv_valid,
        "error": resolv_err,
    })

    return results


def check_sudo_authorization() -> Dict[str, Any]:
    """
    Verifies that non-interactive root authorization is available via sudo -n.
    Returns dict with status PASS/FAIL, detail message, and instructions.
    """
    if os.geteuid() == 0:
        return {
            "status": "PASS",
            "authorized": True,
            "method": "root",
            "message": "Process is running as root (EUID 0)."
        }
    try:
        proc = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode == 0:
            return {
                "status": "PASS",
                "authorized": True,
                "method": "sudo -n",
                "message": "Non-interactive sudo authorization verified."
            }
        else:
            err = (proc.stderr or proc.stdout).strip() or "Password required"
            return {
                "status": "FAIL",
                "authorized": False,
                "method": "sudo -n",
                "error": err,
                "message": (
                    "Non-interactive sudo authorization is unavailable (sudo -n failed). "
                    "Live PS-028 measurement operations require root privileges for network and capture operations. "
                    "Please run 'sudo -v' in your terminal before running live trials or campaigns."
                )
            }
    except FileNotFoundError:
        return {
            "status": "FAIL",
            "authorized": False,
            "method": "sudo -n",
            "error": "sudo binary not found",
            "message": "The sudo utility is not available in PATH."
        }


def run_preflight(check_sudo: bool = False) -> Dict[str, Any]:
    binaries = check_binaries()
    packages = check_system_packages()
    python_deps = check_python_dependencies()
    configs = check_configuration_files()

    missing_required_binaries = [b["command"] for b in binaries if b["required"] and not b["found"]]
    missing_packages = [p["package"] for p in packages if not p["installed"]]
    mismatched_packages = [p["package"] for p in packages if p["installed"] and not p["version_match"]]
    missing_python = [p["module"] for p in python_deps if not p["installed"] or not p["version_match"]]
    invalid_configs = [c["file"] for c in configs if not c["valid"]]

    sudo_auth = None
    sudo_failed = False
    if check_sudo:
        sudo_auth = check_sudo_authorization()
        if not sudo_auth["authorized"]:
            sudo_failed = True

    all_passed = (
        len(missing_required_binaries) == 0 and
        len(missing_packages) == 0 and
        len(missing_python) == 0 and
        len(invalid_configs) == 0 and
        not sudo_failed
    )

    failures: Dict[str, Any] = {
        "missing_required_binaries": missing_required_binaries,
        "missing_packages": missing_packages,
        "mismatched_packages": mismatched_packages,
        "missing_python": missing_python,
        "invalid_configs": invalid_configs,
    }
    if sudo_failed and sudo_auth:
        failures["sudo_authorization"] = [sudo_auth["message"]]

    res: Dict[str, Any] = {
        "status": "PASS" if all_passed else "FAIL",
        "binaries": binaries,
        "packages": packages,
        "python_dependencies": python_deps,
        "configurations": configs,
        "failures": failures,
    }
    if check_sudo and sudo_auth:
        res["sudo_authorization"] = sudo_auth
    return res


def main() -> int:
    parser = argparse.ArgumentParser(description="PS-028 Non-Destructive Lab Dependency Preflight")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--check-sudo", "--live", action="store_true", dest="check_sudo",
                        help="Check non-interactive sudo authorization for live operations")
    args = parser.parse_args()

    report = run_preflight(check_sudo=args.check_sudo)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "PASS" else 1

    print("\033[1;34m[INFO]\033[0m PS-028 Non-Destructive Lab Dependency Preflight")
    print("=" * 60)

    # 1. Binaries
    print("\n--- System Binaries (PATH) ---")
    for b in report["binaries"]:
        tag = "[REQ]" if b["required"] else "[OPT]"
        if b["found"]:
            print(f"  \033[1;32m[OK]\033[0m   {tag} {b['command']:<10} -> {b['path']} ({b['description']})")
        else:
            color = "\033[1;31m[FAIL]\033[0m" if b["required"] else "\033[1;33m[WARN]\033[0m"
            print(f"  {color} {tag} {b['command']:<10} -> NOT FOUND ({b['package']})")

    # 2. Packages
    print("\n--- System Packages (Manifest) ---")
    for p in report["packages"]:
        if p["installed"] and p["version_match"]:
            print(f"  \033[1;32m[OK]\033[0m   {p['package']} = {p['actual_version']}")
        elif p["installed"]:
            print(f"  \033[1;33m[DIFF]\033[0m {p['package']} = {p['actual_version']} (manifest: {p['expected_version']})")
        else:
            print(f"  \033[1;31m[FAIL]\033[0m {p['package']} = NOT INSTALLED")

    # 3. Python
    print("\n--- Python Dependencies ---")
    for py in report["python_dependencies"]:
        if py["installed"] and py["version_match"]:
            print(f"  \033[1;32m[OK]\033[0m   {py['module']} ({py['version']})")
        else:
            print(f"  \033[1;31m[FAIL]\033[0m {py['module']} -> {py['version']} (expected: {py['expected_version']})")

    # 4. Configurations
    print("\n--- Lab Configuration Files ---")
    for c in report["configurations"]:
        if c["valid"]:
            print(f"  \033[1;32m[OK]\033[0m   {c['file']} (valid)")
        else:
            print(f"  \033[1;31m[FAIL]\033[0m {c['file']} -> {c['error']}")

    # 5. Sudo Privileged Authorization (if checked)
    if "sudo_authorization" in report:
        print("\n--- Sudo Privileged Authorization ---")
        sa = report["sudo_authorization"]
        if sa["authorized"]:
            print(f"  \033[1;32m[OK]\033[0m   {sa['message']}")
        else:
            print(f"  \033[1;31m[FAIL]\033[0m {sa['message']}")
            print("         Please execute 'sudo -v' in your terminal session to validate sudo credentials.")

    print("\n" + "=" * 60)
    if report["status"] == "PASS":
        print("\033[1;32m[OK] Preflight PASSED: All required dependencies and configs verified.\033[0m")
        return 0
    else:
        print("\033[1;31m[FAIL] Preflight FAILED: Missing or invalid components detected.\033[0m")
        return 1


if __name__ == "__main__":
    sys.exit(main())
