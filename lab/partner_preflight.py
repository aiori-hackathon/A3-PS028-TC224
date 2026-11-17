#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Independent Partner Non-Mutating Preflight
Workstream C: Partner Replication Readiness

Performs a completely read-only, safe preflight check on an independent Linux host:
1. OS distribution, kernel version, and architecture.
2. Python runtime and pinned dependency versions (dnspython, PyYAML).
3. Required system tool availability and versions (iproute2, tc, nftables, tshark, nginx, tcpdump).
4. Browser runtime paths and version detection (Google Chrome, Mozilla Firefox).
5. System capabilities and namespace support prerequisites.
6. Available storage and disk space for 280-trial campaign evidence.
7. Privileged helper and sudoers deployment status.
8. Required lab configuration and scenario specification files.

Non-Negotiable Safety Rule:
This tool NEVER mutates network state, creates namespaces, alters routing,
installs qdiscs, injects nftables rules, modifies DNS, or launches live socket probes.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Pinned and reference versions from project specification
PINNED_CHROME_VERSION = "156.0.8078.73"
PINNED_FIREFOX_VERSION = "159.0"
MIN_PYTHON_VERSION = (3, 10)
MIN_DISK_FREE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB required for 280 trial PCAPs and logs


def get_os_and_kernel() -> Dict[str, Any]:
    """Inspects host operating system, distribution release, and kernel."""
    distro_name = "Unknown Linux"
    os_release = Path("/etc/os-release")
    if os_release.is_file():
        try:
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if line.startswith("PRETTY_NAME="):
                    distro_name = line.split("=", 1)[1].strip('"\'')
                    break
        except Exception:
            pass

    kernel_ver = platform.release()
    arch = platform.machine()
    is_linux = (platform.system() == "Linux")

    # Detect WSL2 if present
    is_wsl2 = False
    if "microsoft" in kernel_ver.lower() or "wsl" in kernel_ver.lower():
        is_wsl2 = True

    return {
        "system": platform.system(),
        "distribution": distro_name,
        "kernel_release": kernel_ver,
        "architecture": arch,
        "is_linux": is_linux,
        "is_wsl2": is_wsl2,
        "compatible": is_linux,
    }


def get_python_and_libraries() -> Dict[str, Any]:
    """Verifies Python runtime version and installed dependency libraries."""
    py_ver = sys.version_info
    py_ver_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    py_compatible = (py_ver >= MIN_PYTHON_VERSION)

    deps: Dict[str, Any] = {}

    # dnspython
    try:
        import dns
        dns_ver = getattr(dns, "__version__", "unknown")
        dns_loc = getattr(dns, "__file__", "unknown")
        deps["dnspython"] = {
            "installed": True,
            "version": dns_ver,
            "location": dns_loc,
            "compatible": (dns_ver == "2.6.1"),
            "expected": "2.6.1"
        }
    except ImportError:
        deps["dnspython"] = {
            "installed": False,
            "version": None,
            "location": None,
            "compatible": False,
            "expected": "2.6.1"
        }

    # PyYAML
    try:
        import yaml
        yaml_ver = getattr(yaml, "__version__", "unknown")
        yaml_loc = getattr(yaml, "__file__", "unknown")
        deps["pyyaml"] = {
            "installed": True,
            "version": yaml_ver,
            "location": yaml_loc,
            "compatible": True,
            "expected": ">=6.0"
        }
    except ImportError:
        deps["pyyaml"] = {
            "installed": False,
            "version": None,
            "location": None,
            "compatible": False,
            "expected": ">=6.0"
        }

    return {
        "python_version": py_ver_str,
        "sys_executable": sys.executable,
        "compatible": py_compatible and all(d["compatible"] for d in deps.values()),
        "dependencies": deps,
    }


def _query_binary_version(cmd: str, flag: str = "--version") -> Optional[str]:
    """Safely inspects binary version string without side effects."""
    path = shutil.which(cmd)
    if not path:
        return None
    try:
        proc = subprocess.run([path, flag], capture_output=True, text=True, timeout=5)
        out = (proc.stdout or proc.stderr).strip().splitlines()
        return out[0] if out else "installed (version output empty)"
    except Exception as exc:
        return f"error querying version: {exc}"


def get_system_tools() -> Dict[str, Any]:
    """Inspects required networking, firewall, web server, and capture utilities."""
    tools = [
        ("ip", "-V", True, "iproute2 network namespace manipulation"),
        ("tc", "-V", True, "traffic control and link latency emulation"),
        ("nft", "-v", True, "nftables packet filtering, RST and loss emulation"),
        ("tshark", "-v", True, "packet capture dissection and verification"),
        ("tcpdump", "--version", True, "packet capture recorder"),
        ("nginx", "-v", True, "dual-stack measurement web server endpoint"),
        ("curl", "--version", True, "HTTP endpoint testing probe"),
    ]

    results: Dict[str, Any] = {}
    all_found = True

    for bin_name, ver_flag, required, desc in tools:
        path = shutil.which(bin_name)
        ver_info = _query_binary_version(bin_name, ver_flag) if path else None
        found = (path is not None)
        if required and not found:
            all_found = False

        results[bin_name] = {
            "required": required,
            "found": found,
            "path": path,
            "version_output": ver_info,
            "description": desc,
        }

    return {
        "compatible": all_found,
        "tools": results,
    }


def get_browser_runtimes() -> Dict[str, Any]:
    """Inspects Google Chrome and Mozilla Firefox paths and versions."""
    browsers: Dict[str, Any] = {}

    chrome_candidates = ["google-chrome", "google-chrome-stable", "/usr/bin/google-chrome"]
    chrome_path = None
    for cand in chrome_candidates:
        p = shutil.which(cand) or (cand if Path(cand).is_file() and os.access(cand, os.X_OK) else None)
        if p:
            chrome_path = p
            break

    if chrome_path:
        chrome_ver_str = _query_binary_version(chrome_path, "--version")
        browsers["google-chrome"] = {
            "found": True,
            "path": chrome_path,
            "version": chrome_ver_str,
            "pinned_expected": PINNED_CHROME_VERSION,
            "matches_pinned": (chrome_ver_str is not None and PINNED_CHROME_VERSION in chrome_ver_str),
        }
    else:
        browsers["google-chrome"] = {
            "found": False,
            "path": None,
            "version": None,
            "pinned_expected": PINNED_CHROME_VERSION,
            "matches_pinned": False,
        }

    firefox_candidates = ["firefox", "/usr/bin/firefox"]
    firefox_path = None
    for cand in firefox_candidates:
        p = shutil.which(cand) or (cand if Path(cand).is_file() and os.access(cand, os.X_OK) else None)
        if p:
            firefox_path = p
            break

    if firefox_path:
        ff_ver_str = _query_binary_version(firefox_path, "--version")
        browsers["firefox"] = {
            "found": True,
            "path": firefox_path,
            "version": ff_ver_str,
            "pinned_expected": PINNED_FIREFOX_VERSION,
            "matches_pinned": (ff_ver_str is not None and PINNED_FIREFOX_VERSION in ff_ver_str),
        }
    else:
        browsers["firefox"] = {
            "found": False,
            "path": None,
            "version": None,
            "pinned_expected": PINNED_FIREFOX_VERSION,
            "matches_pinned": False,
        }

    return {
        "browsers": browsers,
        "has_chrome": browsers["google-chrome"]["found"],
        "has_firefox": browsers["firefox"]["found"],
    }


def get_system_capabilities() -> Dict[str, Any]:
    """Inspects network capabilities and permissions without modifying host state."""
    ip_forward_v4 = False
    ip_forward_v6 = False

    try:
        v4_path = Path("/proc/sys/net/ipv4/ip_forward")
        if v4_path.is_file() and v4_path.read_text().strip() == "1":
            ip_forward_v4 = True
    except Exception:
        pass

    try:
        v6_path = Path("/proc/sys/net/ipv6/conf/all/forwarding")
        if v6_path.is_file() and v6_path.read_text().strip() == "1":
            ip_forward_v6 = True
    except Exception:
        pass

    # Check network namespace support via read-only inspection of /proc/self/ns/net
    has_netns_support = Path("/proc/self/ns/net").is_file()

    # Check dedicated service account ps028-sv
    has_service_account = False
    try:
        import pwd
        pwd.getpwnam("ps028-sv")
        has_service_account = True
    except KeyError:
        pass

    return {
        "ipv4_forwarding_enabled": ip_forward_v4,
        "ipv6_forwarding_enabled": ip_forward_v6,
        "kernel_netns_support": has_netns_support,
        "dedicated_service_account_ps028_sv": has_service_account,
    }


def get_storage_status(target_path: Path = REPO_ROOT) -> Dict[str, Any]:
    """Inspects available disk storage for campaign artifacts."""
    try:
        usage = shutil.disk_usage(str(target_path))
        free_bytes = usage.free
        free_gb = free_bytes / (1024 ** 3)
        sufficient = (free_bytes >= MIN_DISK_FREE_BYTES)
        return {
            "target_path": str(target_path),
            "free_bytes": free_bytes,
            "free_gb": round(free_gb, 2),
            "sufficient_for_campaign": sufficient,
            "required_gb": round(MIN_DISK_FREE_BYTES / (1024 ** 3), 1),
        }
    except Exception as exc:
        return {
            "target_path": str(target_path),
            "error": str(exc),
            "sufficient_for_campaign": False,
        }


def get_helper_deployment_status() -> Dict[str, Any]:
    """Inspects deployment of privileged helper and sudoers drop-in."""
    helper_path = Path("/usr/local/libexec/ps028/privileged_helper.py")
    sudoers_path = Path("/etc/sudoers.d/ps028-helper")
    manifest_path = Path("/usr/local/libexec/ps028/deployment_manifest.json")

    helper_installed = helper_path.is_file()
    sudoers_installed = sudoers_path.is_file()
    manifest_installed = manifest_path.is_file()

    return {
        "helper_executable": {
            "path": str(helper_path),
            "installed": helper_installed,
            "mode": oct(helper_path.stat().st_mode & 0o777) if helper_installed else None,
        },
        "sudoers_drop_in": {
            "path": str(sudoers_path),
            "installed": sudoers_installed,
            "mode": oct(sudoers_path.stat().st_mode & 0o777) if sudoers_installed else None,
        },
        "deployment_manifest": {
            "path": str(manifest_path),
            "installed": manifest_installed,
        },
        "ready": helper_installed and sudoers_installed and manifest_installed,
    }


def get_configuration_files() -> Dict[str, Any]:
    """Inspects essential configuration and scenario files."""
    required_files = [
        SCRIPT_DIR / "scenarios.yaml",
        SCRIPT_DIR / "dns_config.json",
        SCRIPT_DIR / "nginx.conf",
        SCRIPT_DIR / "cl_resolv.conf",
        REPO_ROOT / "docs" / "phase-cd" / "partner_replication_manifest.json",
        REPO_ROOT / "docs" / "phase-cd" / "partner_replication_runbook.md",
    ]

    files_status: Dict[str, bool] = {}
    for f in required_files:
        try:
            rel = str(f.relative_to(REPO_ROOT))
        except ValueError:
            rel = str(f)
        files_status[rel] = f.is_file()

    return {
        "all_present": all(files_status.values()),
        "files": files_status,
    }


def run_partner_preflight() -> Dict[str, Any]:
    """Executes the complete non-mutating partner preflight inspection."""
    os_info = get_os_and_kernel()
    py_info = get_python_and_libraries()
    tools_info = get_system_tools()
    browsers_info = get_browser_runtimes()
    caps_info = get_system_capabilities()
    storage_info = get_storage_status()
    helper_info = get_helper_deployment_status()
    configs_info = get_configuration_files()

    overall_ready = (
        os_info["compatible"] and
        py_info["compatible"] and
        tools_info["compatible"] and
        browsers_info["has_chrome"] and
        browsers_info["has_firefox"] and
        caps_info["kernel_netns_support"] and
        storage_info.get("sufficient_for_campaign", False) and
        configs_info["all_present"]
    )

    return {
        "overall_status": "READY" if overall_ready else "ACTION_REQUIRED",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os_and_kernel": os_info,
        "python_and_libraries": py_info,
        "system_tools": tools_info,
        "browsers": browsers_info,
        "system_capabilities": caps_info,
        "storage": storage_info,
        "privileged_helper": helper_info,
        "configuration_files": configs_info,
    }


def print_human_report(report: Dict[str, Any]) -> None:
    print("=" * 78)
    print("PS-028 Happy Eyeballs Measurement Lab: Partner Host Read-Only Preflight")
    print("=" * 78)
    print(f"Overall Preflight Readiness Status: {report['overall_status']}")
    print()

    # 1. OS & Kernel
    os_info = report["os_and_kernel"]
    print("1. Platform and Kernel:")
    print(f"   Distribution : {os_info['distribution']}")
    print(f"   Kernel       : {os_info['kernel_release']} ({os_info['architecture']})")
    print(f"   WSL2 Detected: {'Yes' if os_info['is_wsl2'] else 'No (Bare Metal / VM)'}")
    print(f"   Status       : {'[OK]' if os_info['compatible'] else '[FAIL]'}")
    print()

    # 2. Python & Libraries
    py_info = report["python_and_libraries"]
    print("2. Python Environment & Pinned Libraries:")
    print(f"   Interpreter  : {py_info['sys_executable']}")
    print(f"   Python Ver   : {py_info['python_version']} (requires >= 3.10)")
    for dep_name, dep in py_info["dependencies"].items():
        status = "[OK]" if dep["compatible"] else "[FAIL]"
        print(f"   {dep_name:<12} : {dep.get('version')} (expected {dep['expected']}) {status}")
    print()

    # 3. System Tools
    tools_info = report["system_tools"]
    print("3. Required System Utilities (iproute2, tc, nftables, tshark, nginx, tcpdump):")
    for bname, tinfo in tools_info["tools"].items():
        tag = "[OK]" if tinfo["found"] else "[MISSING]"
        path_str = tinfo["path"] or "not found in PATH"
        print(f"   {bname:<10} : {path_str} {tag}")
    print()

    # 4. Browsers
    browsers = report["browsers"]["browsers"]
    print("4. Browser Runtimes:")
    for bname, binfo in browsers.items():
        tag = "[OK]" if binfo["found"] else "[NOT FOUND]"
        path_str = binfo["path"] or "absent"
        ver_str = binfo["version"] or "unknown"
        pinned_tag = " (Matches Pinned)" if binfo["matches_pinned"] else f" (Pinned: {binfo['pinned_expected']})"
        print(f"   {bname:<14} : {path_str} -> {ver_str}{pinned_tag} {tag}")
    print()

    # 5. Storage
    storage = report["storage"]
    print("5. Storage Availability:")
    if "free_gb" in storage:
        tag = "[OK]" if storage["sufficient_for_campaign"] else "[INSUFFICIENT]"
        print(f"   Available: {storage['free_gb']} GB (Required >= {storage['required_gb']} GB) {tag}")
    else:
        print(f"   Error inspecting storage: {storage.get('error')}")
    print()

    # 6. Privileged Helper Deployment
    helper = report["privileged_helper"]
    print("6. Privileged Helper Deployment Status:")
    print(f"   Helper Binary: {'Installed [OK]' if helper['helper_executable']['installed'] else 'Not Deployed [PENDING]'}")
    print(f"   Sudoers Rule : {'Installed [OK]' if helper['sudoers_drop_in']['installed'] else 'Not Deployed [PENDING]'}")
    print(f"   Manifest     : {'Installed [OK]' if helper['deployment_manifest']['installed'] else 'Not Deployed [PENDING]'}")
    print()

    # 7. Configuration Files
    configs = report["configuration_files"]
    print("7. Configuration & Manifest Files:")
    for fpath, exists in configs["files"].items():
        print(f"   {fpath:<50} : {'[OK]' if exists else '[MISSING]'}")
    print()

    print("=" * 78)
    if report["overall_status"] == "READY":
        print("[SUCCESS] Host environment satisfies read-only partner replication requirements.")
    else:
        print("[ACTION REQUIRED] One or more prerequisites require installation or attention.")
    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Non-Mutating Independent Partner Host Preflight"
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--output-file", "-o", type=Path, default=None,
                        help="Optional path to write preflight report (JSON or text)")
    args = parser.parse_args()

    report = run_partner_preflight()

    if args.json:
        json_str = json.dumps(report, indent=2)
        print(json_str)
        if args.output_file:
            args.output_file.write_text(json_str, encoding="utf-8")
    else:
        print_human_report(report)
        if args.output_file:
            args.output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return 0 if report["overall_status"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
