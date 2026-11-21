#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Independent Partner Non-Mutating Preflight
Workstream C: Partner Replication Readiness
Work Package B: Hardened Environmental & Toolchain Preflight Verification

Performs a completely read-only, safe preflight check on an independent Linux host:
1. Platform validation: Ubuntu 24.04 bare-metal or Ubuntu 24.04 under WSL2.
2. Python runtime and pinned dependency versions (dnspython, PyYAML).
3. Required system toolchain versions (iproute2, tc, nftables, tshark, tcpdump, nginx, curl).
4. Browser runtime validation: exact pinned builds for Chrome (156.0.8078.73) and Firefox (159.0),
   executable permissions, symlink resolution, Snap confinement detection, and DNS isolation support.
5. System capabilities and namespace support prerequisites.
6. Available storage and disk space for 280-trial campaign evidence.
7. Privileged helper and sudoers deployment status and integrity.
8. Required lab configuration and scenario specification files.
9. Structured 5-state readiness model:
   - ACTION_REQUIRED
   - HOST_PREREQUISITES_READY
   - BROWSER_TOOLCHAIN_READY
   - HELPER_DEPLOYMENT_READY
   - REPLICATION_READY_FOR_AUTHORIZATION

Non-Negotiable Safety Rule:
This tool NEVER mutates network state, creates namespaces, alters routing,
installs qdiscs, injects nftables rules, modifies DNS, or launches live socket probes.
"""

import argparse
from datetime import datetime, timezone
import hashlib
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

from lab.replication_contract import (
    PINNED_BROWSERS,
    REQUIRED_TOOLCHAIN,
    REQUIRED_PYTHON_DEPENDENCIES,
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    SPECIFICATION_OF_RECORD,
    TOTAL_PLANNED_TRIALS,
    REPETITIONS_PER_COHORT,
)

MIN_PYTHON_VERSION = (3, 10)
MIN_DISK_FREE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB required for 280 trial PCAPs and logs

# 5-State Readiness State Model
STATE_ACTION_REQUIRED = "ACTION_REQUIRED"
STATE_HOST_PREREQUISITES_READY = "HOST_PREREQUISITES_READY"
STATE_BROWSER_TOOLCHAIN_READY = "BROWSER_TOOLCHAIN_READY"
STATE_HELPER_DEPLOYMENT_READY = "HELPER_DEPLOYMENT_READY"
STATE_REPLICATION_READY_FOR_AUTHORIZATION = "REPLICATION_READY_FOR_AUTHORIZATION"


def parse_semver(ver_str: str) -> Tuple[int, ...]:
    """Extracts numeric version tuple from a version string (e.g. '6.1.0-1ubuntu1' -> (6, 1, 0))."""
    if not ver_str:
        return (0,)
    m = re.search(r'(\d+(?:\.\d+)+|\d+)', ver_str)
    if not m:
        return (0,)
    parts = []
    for x in m.group(1).split('.'):
        try:
            parts.append(int(x))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def compare_versions(actual: str, minimum: str) -> bool:
    """Returns True if actual version is >= minimum version."""
    act_tup = parse_semver(actual)
    min_tup = parse_semver(minimum)
    max_len = max(len(act_tup), len(min_tup))
    act_padded = act_tup + (0,) * (max_len - len(act_tup))
    min_padded = min_tup + (0,) * (max_len - len(min_tup))
    return act_padded >= min_padded


def get_os_and_kernel() -> Dict[str, Any]:
    """Inspects host operating system, distribution release, and kernel."""
    distro_name = "Unknown Linux"
    distro_id = "unknown"
    distro_version_id = "unknown"

    os_release = Path("/etc/os-release")
    if os_release.is_file():
        try:
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if line.startswith("PRETTY_NAME="):
                    distro_name = line.split("=", 1)[1].strip('"\'')
                elif line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip('"\'').lower()
                elif line.startswith("VERSION_ID="):
                    distro_version_id = line.split("=", 1)[1].strip('"\'')
        except Exception:
            pass

    kernel_ver = platform.release()
    arch = platform.machine()
    is_linux = (platform.system() == "Linux")

    # Detect WSL2 if present
    is_wsl2 = False
    if "microsoft" in kernel_ver.lower() or "wsl" in kernel_ver.lower():
        is_wsl2 = True

    # Pinned / Supported target: Ubuntu 24.04 (Noble Numbat)
    is_ubuntu_2404 = (is_linux and distro_id == "ubuntu" and distro_version_id.startswith("24.04"))
    compatible = is_ubuntu_2404

    qualification_note = "Supported Ubuntu 24.04 platform."
    if not is_linux:
        qualification_note = "Non-Linux platform is strictly incompatible with Linux network namespaces."
    elif not is_ubuntu_2404:
        qualification_note = (
            f"Unsupported Linux distribution ({distro_name} {distro_version_id}). "
            "Canonical replication target is Ubuntu 24.04 LTS (bare-metal or WSL2 with systemd)."
        )

    return {
        "system": platform.system(),
        "distribution": distro_name,
        "distro_id": distro_id,
        "distro_version_id": distro_version_id,
        "kernel_release": kernel_ver,
        "architecture": arch,
        "is_linux": is_linux,
        "is_wsl2": is_wsl2,
        "is_ubuntu_2404": is_ubuntu_2404,
        "compatible": compatible,
        "qualification_note": qualification_note,
    }


def get_python_and_libraries() -> Dict[str, Any]:
    """Verifies Python runtime version and installed dependency libraries against contract."""
    py_ver = sys.version_info
    py_ver_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    py_compatible = (py_ver >= MIN_PYTHON_VERSION)

    deps: Dict[str, Any] = {}

    # dnspython
    dns_spec = REQUIRED_PYTHON_DEPENDENCIES["dnspython"]
    try:
        import dns
        dns_ver = getattr(dns, "__version__", "unknown")
        dns_loc = getattr(dns, "__file__", "unknown")
        dns_compat = (dns_ver == dns_spec["expected"]) if dns_spec.get("exact") else compare_versions(dns_ver, dns_spec["expected"])
        deps["dnspython"] = {
            "installed": True,
            "version": dns_ver,
            "location": dns_loc,
            "compatible": dns_compat,
            "expected": dns_spec["expected"],
            "exact_required": dns_spec.get("exact", True),
        }
    except ImportError:
        deps["dnspython"] = {
            "installed": False,
            "version": None,
            "location": None,
            "compatible": False,
            "expected": dns_spec["expected"],
            "exact_required": dns_spec.get("exact", True),
        }

    # PyYAML
    yaml_spec = REQUIRED_PYTHON_DEPENDENCIES["pyyaml"]
    try:
        import yaml
        yaml_ver = getattr(yaml, "__version__", "unknown")
        yaml_loc = getattr(yaml, "__file__", "unknown")
        min_yaml = yaml_spec.get("min_version", "6.0")
        yaml_compat = compare_versions(yaml_ver, min_yaml)
        deps["pyyaml"] = {
            "installed": True,
            "version": yaml_ver,
            "location": yaml_loc,
            "compatible": yaml_compat,
            "expected": f">={min_yaml}",
            "exact_required": yaml_spec.get("exact", False),
        }
    except ImportError:
        deps["pyyaml"] = {
            "installed": False,
            "version": None,
            "location": None,
            "compatible": False,
            "expected": f">={yaml_spec.get('min_version', '6.0')}",
            "exact_required": yaml_spec.get("exact", False),
        }

    all_deps_compatible = all(d["compatible"] for d in deps.values())

    return {
        "python_version": py_ver_str,
        "sys_executable": sys.executable,
        "compatible": py_compatible and all_deps_compatible,
        "dependencies": deps,
    }


def _query_binary_version(cmd_path: str, flag: str = "--version") -> Optional[str]:
    """Safely inspects binary version string without side effects."""
    if not cmd_path or not Path(cmd_path).is_file():
        return None
    try:
        proc = subprocess.run([cmd_path, flag], capture_output=True, text=True, timeout=5)
        out = (proc.stdout or proc.stderr).strip().splitlines()
        return out[0] if out else "installed (version output empty)"
    except Exception as exc:
        return f"error querying version: {exc}"


def extract_tool_version_string(tool_name: str, raw_output: Optional[str]) -> Optional[str]:
    """Extracts normalized version number from raw tool version output."""
    if not raw_output:
        return None
    line = raw_output.strip()

    if tool_name in ("ip", "tc"):
        # e.g., 'ip utility, iproute2-6.1.0, libbpf 1.3.0' or 'tc utility, iproute2-6.1.0'
        m = re.search(r'iproute2-([\d\.]+)', line)
        if m:
            return m.group(1)
        m = re.search(r'([\d\.]+)', line)
        return m.group(1) if m else None

    if tool_name == "nft":
        # e.g., 'nftables v1.0.9 (Old Doc Yak #3)'
        m = re.search(r'nftables\s+v?([\d\.]+)', line)
        return m.group(1) if m else None

    if tool_name == "tshark":
        # e.g., 'TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)'
        m = re.search(r'TShark\s+(?:\(Wireshark\)\s+)?([\d\.]+)', line)
        return m.group(1) if m else None

    if tool_name == "tcpdump":
        # e.g., 'tcpdump version 4.99.4'
        m = re.search(r'tcpdump\s+version\s+([\d\.]+)', line)
        return m.group(1) if m else None

    if tool_name == "nginx":
        # e.g., 'nginx version: nginx/1.24.0 (Ubuntu)'
        m = re.search(r'nginx/([\d\.]+)', line)
        return m.group(1) if m else None

    if tool_name == "curl":
        # e.g., 'curl 8.5.0 (x86_64-pc-linux-gnu)...'
        m = re.search(r'curl\s+([\d\.]+)', line)
        return m.group(1) if m else None

    m = re.search(r'([\d\.]+)', line)
    return m.group(1) if m else None


def get_system_tools() -> Dict[str, Any]:
    """Inspects required networking, firewall, web server, and capture utilities against contract."""
    results: Dict[str, Any] = {}
    all_compatible = True

    tool_specs = [
        ("ip", "iproute2", "6.1.0", "-V", "iproute2 network namespace manipulation"),
        ("tc", "tc", "6.1.0", "-V", "traffic control and link latency emulation"),
        ("nft", "nftables", "1.0.0", "-v", "nftables packet filtering, RST and loss emulation"),
        ("tshark", "tshark", "4.0.0", "-v", "packet capture dissection and verification"),
        ("tcpdump", "tcpdump", "4.99.0", "--version", "packet capture recorder"),
        ("nginx", "nginx", "1.24.0", "-v", "dual-stack measurement web server endpoint"),
        ("curl", "curl", "7.80.0", "--version", "HTTP endpoint testing probe"),
    ]

    for bin_name, contract_key, min_ver, ver_flag, desc in tool_specs:
        path = shutil.which(bin_name)
        raw_output = _query_binary_version(path, ver_flag) if path else None
        extracted_ver = extract_tool_version_string(bin_name, raw_output) if raw_output else None

        found = (path is not None)
        version_compatible = False
        if found and extracted_ver:
            version_compatible = compare_versions(extracted_ver, min_ver)

        is_tool_ok = found and version_compatible
        if not is_tool_ok:
            all_compatible = False

        results[bin_name] = {
            "required": True,
            "found": found,
            "path": path,
            "min_version_required": min_ver,
            "extracted_version": extracted_ver,
            "version_compatible": version_compatible,
            "raw_version_output": raw_output,
            "description": desc,
            "status": "OK" if is_tool_ok else ("VERSION_INCOMPATIBLE" if found else "MISSING"),
        }

    return {
        "compatible": all_compatible,
        "tools": results,
    }


def _is_snap_path(path_obj: Path) -> bool:
    """Detects whether an executable path is managed under Snap confinement."""
    try:
        resolved = path_obj.resolve()
        path_str = str(path_obj)
        res_str = str(resolved)
        if "/snap/" in path_str or "/snap/" in res_str:
            return True
        if path_str.startswith("/var/lib/snapd/snap/") or res_str.startswith("/var/lib/snapd/snap/"):
            return True
    except Exception:
        pass
    return False


def get_browser_runtimes() -> Dict[str, Any]:
    """
    Rigorously inspects Google Chrome and Mozilla Firefox:
    - Absolute binary paths
    - Symlink resolution
    - Executability permissions
    - Exact pinned version matching (Chrome 156.0.8078.73, Firefox 159.0)
    - Snap confinement detection
    - DNS isolation compatibility
    """
    browsers: Dict[str, Any] = {}
    all_exact_match = True

    # Pinned targets from centralized contract
    chrome_pinned = PINNED_BROWSERS["google-chrome"]["pinned_version"]
    firefox_pinned = PINNED_BROWSERS["firefox"]["pinned_version"]

    # 1. Google Chrome inspection
    chrome_candidates = [
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ]
    chrome_path: Optional[Path] = None
    for cand in chrome_candidates:
        if cand:
            p = Path(cand)
            if p.is_file() and os.access(str(p), os.X_OK):
                chrome_path = p
                break

    if chrome_path:
        chrome_resolved = chrome_path.resolve()
        chrome_is_snap = _is_snap_path(chrome_path)
        chrome_ver_str = _query_binary_version(str(chrome_path), "--version")
        # Match exact version pin: Chrome version output e.g. "Google Chrome 156.0.8078.73"
        chrome_matches_pin = (
            chrome_ver_str is not None and
            chrome_pinned in chrome_ver_str
        )
        if not chrome_matches_pin or chrome_is_snap:
            all_exact_match = False

        browsers["google-chrome"] = {
            "canonical_name": "google-chrome",
            "found": True,
            "executable_path": str(chrome_path),
            "resolved_path": str(chrome_resolved),
            "is_executable": True,
            "raw_version_output": chrome_ver_str,
            "pinned_expected": chrome_pinned,
            "matches_pinned": chrome_matches_pin,
            "is_snap": chrome_is_snap,
            "supports_dns_isolation": not chrome_is_snap,
            "status": "READY" if (chrome_matches_pin and not chrome_is_snap) else (
                "VERSION_MISMATCH" if not chrome_matches_pin else "SNAP_CONFINED"
            ),
        }
    else:
        all_exact_match = False
        browsers["google-chrome"] = {
            "canonical_name": "google-chrome",
            "found": False,
            "executable_path": None,
            "resolved_path": None,
            "is_executable": False,
            "raw_version_output": None,
            "pinned_expected": chrome_pinned,
            "matches_pinned": False,
            "is_snap": False,
            "supports_dns_isolation": False,
            "status": "NOT_FOUND",
        }

    # 2. Mozilla Firefox inspection
    firefox_candidates = [
        shutil.which("firefox"),
        "/usr/bin/firefox",
    ]
    firefox_path: Optional[Path] = None
    for cand in firefox_candidates:
        if cand:
            p = Path(cand)
            if p.is_file() and os.access(str(p), os.X_OK):
                firefox_path = p
                break

    if firefox_path:
        firefox_resolved = firefox_path.resolve()
        firefox_is_snap = _is_snap_path(firefox_path)
        firefox_ver_str = _query_binary_version(str(firefox_path), "--version")
        # Match exact version pin: Firefox version output e.g. "Mozilla Firefox 159.0"
        firefox_matches_pin = (
            firefox_ver_str is not None and
            firefox_pinned in firefox_ver_str
        )
        if not firefox_matches_pin or firefox_is_snap:
            all_exact_match = False

        browsers["firefox"] = {
            "canonical_name": "firefox",
            "found": True,
            "executable_path": str(firefox_path),
            "resolved_path": str(firefox_resolved),
            "is_executable": True,
            "raw_version_output": firefox_ver_str,
            "pinned_expected": firefox_pinned,
            "matches_pinned": firefox_matches_pin,
            "is_snap": firefox_is_snap,
            "supports_dns_isolation": not firefox_is_snap,
            "status": "READY" if (firefox_matches_pin and not firefox_is_snap) else (
                "VERSION_MISMATCH" if not firefox_matches_pin else "SNAP_CONFINED"
            ),
        }
    else:
        all_exact_match = False
        browsers["firefox"] = {
            "canonical_name": "firefox",
            "found": False,
            "executable_path": None,
            "resolved_path": None,
            "is_executable": False,
            "raw_version_output": None,
            "pinned_expected": firefox_pinned,
            "matches_pinned": False,
            "is_snap": False,
            "supports_dns_isolation": False,
            "status": "NOT_FOUND",
        }

    has_chrome = browsers["google-chrome"]["found"]
    has_firefox = browsers["firefox"]["found"]
    chrome_ready = browsers["google-chrome"]["status"] == "READY"
    firefox_ready = browsers["firefox"]["status"] == "READY"

    return {
        "browsers": browsers,
        "has_chrome": has_chrome,
        "has_firefox": has_firefox,
        "chrome_ready": chrome_ready,
        "firefox_ready": firefox_ready,
        "all_exact_match": all_exact_match and chrome_ready and firefox_ready,
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
        "compatible": has_netns_support,
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
    """
    Inspects deployment of privileged helper, sudoers drop-in, and deployment manifest.
    Verifies helper integrity against deployment manifest SHA-256.
    """
    helper_path = Path("/usr/local/libexec/ps028/privileged_helper.py")
    sudoers_path = Path("/etc/sudoers.d/ps028-helper")
    manifest_path = Path("/usr/local/libexec/ps028/deployment_manifest.json")

    helper_installed = False
    helper_mode = None
    helper_sha256 = None
    try:
        if helper_path.is_file():
            helper_installed = True
            helper_mode = oct(helper_path.stat().st_mode & 0o777)
            h = hashlib.sha256()
            h.update(helper_path.read_bytes())
            helper_sha256 = h.hexdigest()
    except (PermissionError, OSError):
        pass

    sudoers_installed = False
    sudoers_mode = None
    try:
        if sudoers_path.is_file():
            sudoers_installed = True
            sudoers_mode = oct(sudoers_path.stat().st_mode & 0o777)
    except (PermissionError, OSError):
        pass

    manifest_installed = False
    manifest_sha_match = False
    manifest_data: Optional[Dict[str, Any]] = None
    try:
        if manifest_path.is_file():
            manifest_installed = True
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_helper_sha = manifest_data.get("helper_sha256")
            if helper_sha256 and expected_helper_sha:
                manifest_sha_match = (helper_sha256.lower() == expected_helper_sha.lower())
    except Exception:
        pass

    # Check dedicated service account ps028-sv
    has_service_account = False
    try:
        import pwd
        pwd.getpwnam("ps028-sv")
        has_service_account = True
    except KeyError:
        pass

    ready = (
        helper_installed and
        sudoers_installed and
        manifest_installed and
        manifest_sha_match and
        has_service_account
    )

    return {
        "helper_executable": {
            "path": str(helper_path),
            "installed": helper_installed,
            "mode": helper_mode,
            "sha256": helper_sha256,
        },
        "sudoers_drop_in": {
            "path": str(sudoers_path),
            "installed": sudoers_installed,
            "mode": sudoers_mode,
        },
        "deployment_manifest": {
            "path": str(manifest_path),
            "installed": manifest_installed,
            "sha_match": manifest_sha_match,
        },
        "service_account_ps028_sv": has_service_account,
        "ready": ready,
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


def compute_remediation_actions(report: Dict[str, Any]) -> List[Dict[str, str]]:
    """Generates explicit actionable remediation instructions for any failed gate."""
    actions: List[Dict[str, str]] = []

    # 1. OS & Kernel
    os_info = report["os_and_kernel"]
    if not os_info.get("compatible", False):
        actions.append({
            "category": "Platform",
            "issue": f"Unsupported OS: {os_info.get('distribution')} {os_info.get('distro_version_id')}",
            "remediation": "Replication environment must be Ubuntu 24.04 LTS (bare-metal or WSL2 with systemd enabled).",
        })

    # 2. Python & Libraries
    py_info = report["python_and_libraries"]
    if not py_info.get("compatible", False):
        for dep_name, dep in py_info.get("dependencies", {}).items():
            if not dep.get("compatible", False):
                actions.append({
                    "category": "Python Dependency",
                    "issue": f"{dep_name} version '{dep.get('version')}' does not satisfy contract '{dep.get('expected')}'",
                    "remediation": f"Install pinned dependency: python3 -m pip install {dep_name}=={dep.get('expected')}",
                })

    # 3. System Tools
    tools_info = report["system_tools"]
    if not tools_info.get("compatible", False):
        for tname, tinfo in tools_info.get("tools", {}).items():
            if not tinfo.get("found", False):
                actions.append({
                    "category": "System Tool",
                    "issue": f"Required utility '{tname}' not found in PATH",
                    "remediation": f"Install {tname} via apt-get: sudo apt-get install -y {tname}",
                })
            elif not tinfo.get("version_compatible", False):
                actions.append({
                    "category": "System Tool",
                    "issue": f"'{tname}' version '{tinfo.get('extracted_version')}' is below minimum '{tinfo.get('min_version_required')}'",
                    "remediation": f"Upgrade {tname} to >= {tinfo.get('min_version_required')}",
                })

    # 4. Browsers
    browsers_info = report["browsers"]
    if not browsers_info.get("all_exact_match", False):
        bdata = browsers_info.get("browsers", {})
        chrome = bdata.get("google-chrome", {})
        if not chrome.get("found", False):
            actions.append({
                "category": "Browser Toolchain",
                "issue": "Google Chrome binary not found",
                "remediation": f"Install Google Chrome pinned version {chrome.get('pinned_expected')} at /usr/bin/google-chrome.",
            })
        elif not chrome.get("matches_pinned", False):
            actions.append({
                "category": "Browser Toolchain",
                "issue": f"Google Chrome version mismatch: found '{chrome.get('raw_version_output')}', expected '{chrome.get('pinned_expected')}'",
                "remediation": f"Install exact pinned Google Chrome build {chrome.get('pinned_expected')} (do not substitute Chromium or alternative versions).",
            })
        elif chrome.get("is_snap", False):
            actions.append({
                "category": "Browser Toolchain",
                "issue": "Google Chrome is a Snap-confined package",
                "remediation": "Replace Snap Chrome with native deb build to allow Linux network namespace and DNS isolation.",
            })

        ff = bdata.get("firefox", {})
        if not ff.get("found", False):
            actions.append({
                "category": "Browser Toolchain",
                "issue": "Mozilla Firefox binary not found",
                "remediation": f"Install Mozilla Firefox pinned version {ff.get('pinned_expected')} at /usr/bin/firefox.",
            })
        elif not ff.get("matches_pinned", False):
            actions.append({
                "category": "Browser Toolchain",
                "issue": f"Mozilla Firefox version mismatch: found '{ff.get('raw_version_output')}', expected '{ff.get('pinned_expected')}'",
                "remediation": f"Install exact pinned Mozilla Firefox build {ff.get('pinned_expected')}.",
            })
        elif ff.get("is_snap", False):
            actions.append({
                "category": "Browser Toolchain",
                "issue": "Mozilla Firefox is a Snap-confined package",
                "remediation": "Replace Snap Firefox with native deb or tarball build to allow Linux network namespace and DNS isolation.",
            })

    # 5. Privileged Helper
    helper = report["privileged_helper"]
    if not helper.get("ready", False):
        if not helper.get("service_account_ps028_sv", False):
            actions.append({
                "category": "Security Identity",
                "issue": "Dedicated service account 'ps028-sv' does not exist",
                "remediation": "Create service account: sudo useradd -r -s /usr/sbin/nologin -d /nonexistent -M ps028-sv",
            })
        if not helper.get("helper_executable", {}).get("installed", False):
            actions.append({
                "category": "Privileged Helper",
                "issue": "Privileged helper is not deployed to /usr/local/libexec/ps028/",
                "remediation": "Perform deployment dry-run: ./lab/deploy_privileged_helper.sh --dry-run; then deploy with authorization.",
            })
        elif not helper.get("deployment_manifest", {}).get("sha_match", False):
            actions.append({
                "category": "Privileged Helper",
                "issue": "Helper executable SHA-256 does not match deployment manifest",
                "remediation": "Re-run ./lab/deploy_privileged_helper.sh with root privileges after verifying clean Git tree.",
            })

    # 6. Storage
    storage = report["storage"]
    if not storage.get("sufficient_for_campaign", False):
        actions.append({
            "category": "Storage",
            "issue": f"Available storage {storage.get('free_gb')} GB is below required {storage.get('required_gb')} GB",
            "remediation": "Free disk space to provide at least 2.0 GB for 280-trial raw packet captures and evidence.",
        })

    # 7. Configurations
    configs = report["configuration_files"]
    if not configs.get("all_present", False):
        for fpath, present in configs.get("files", {}).items():
            if not present:
                actions.append({
                    "category": "Configuration",
                    "issue": f"Required configuration file '{fpath}' is missing",
                    "remediation": f"Restore missing file '{fpath}' from repository release checkout.",
                })

    return actions


def run_partner_preflight() -> Dict[str, Any]:
    """
    Executes the complete non-mutating partner preflight inspection and
    evaluates the strict 5-state readiness model.
    """
    os_info = get_os_and_kernel()
    py_info = get_python_and_libraries()
    tools_info = get_system_tools()
    browsers_info = get_browser_runtimes()
    caps_info = get_system_capabilities()
    storage_info = get_storage_status()
    helper_info = get_helper_deployment_status()
    configs_info = get_configuration_files()

    # Core host prerequisites (non-browser, non-helper)
    host_prereqs_ok = (
        os_info["compatible"] and
        py_info["compatible"] and
        tools_info["compatible"] and
        caps_info["compatible"] and
        storage_info.get("sufficient_for_campaign", False) and
        configs_info["all_present"]
    )

    browsers_ok = browsers_info["all_exact_match"]
    helper_ok = helper_info["ready"]

    # Evaluate 5-state model
    if not host_prereqs_ok:
        readiness_state = STATE_ACTION_REQUIRED
    elif browsers_ok and helper_ok:
        readiness_state = STATE_REPLICATION_READY_FOR_AUTHORIZATION
    elif browsers_ok and not helper_ok:
        readiness_state = STATE_BROWSER_TOOLCHAIN_READY
    elif not browsers_ok and helper_ok:
        readiness_state = STATE_HELPER_DEPLOYMENT_READY
    else:
        readiness_state = STATE_HOST_PREREQUISITES_READY

    # Overall boolean status (True ONLY when replication ready for authorization)
    overall_ready = (readiness_state == STATE_REPLICATION_READY_FOR_AUTHORIZATION)

    partial_report = {
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "specification_of_record": SPECIFICATION_OF_RECORD,
        "planned_trial_count": TOTAL_PLANNED_TRIALS,
        "readiness_state": readiness_state,
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

    partial_report["remediation_actions"] = compute_remediation_actions(partial_report)

    return partial_report


def print_human_report(report: Dict[str, Any]) -> None:
    print("=" * 78)
    print("PS-028 Happy Eyeballs Measurement Lab: Independent Partner Preflight")
    print(f"Replication Protocol: v{report.get('protocol_version', '1.0.0')} | Spec: {report.get('specification_of_record')}")
    print("=" * 78)
    print(f"Readiness State:  {report['readiness_state']}")
    print(f"Overall Status :  {report['overall_status']}")
    print()

    # 1. OS & Kernel
    os_info = report["os_and_kernel"]
    print("1. Platform and Distribution:")
    print(f"   Distribution : {os_info['distribution']}")
    print(f"   Kernel       : {os_info['kernel_release']} ({os_info['architecture']})")
    print(f"   WSL2 Detected: {'Yes' if os_info['is_wsl2'] else 'No (Bare Metal / VM)'}")
    print(f"   Status       : {'[OK]' if os_info['compatible'] else '[FAIL]'}")
    if not os_info["compatible"]:
        print(f"   Note         : {os_info['qualification_note']}")
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
    print("3. Required System Utilities (iproute2, tc, nftables, tshark, tcpdump, nginx, curl):")
    for bname, tinfo in tools_info["tools"].items():
        tag = "[OK]" if tinfo["version_compatible"] else ("[OUTDATED]" if tinfo["found"] else "[MISSING]")
        path_str = tinfo["path"] or "not found in PATH"
        ver_str = tinfo.get("extracted_version") or "unknown"
        min_ver = tinfo.get("min_version_required")
        print(f"   {bname:<10} : {path_str} -> {ver_str} (min: {min_ver}) {tag}")
    print()

    # 4. Browsers
    browsers = report["browsers"]["browsers"]
    print("4. Browser Runtimes (Pinned Builds Required):")
    for bname, binfo in browsers.items():
        tag = "[OK]" if binfo["status"] == "READY" else f"[{binfo['status']}]"
        path_str = binfo["executable_path"] or "absent"
        ver_str = binfo["raw_version_output"] or "unknown"
        pinned_tag = f" (Exact Pin: {binfo['pinned_expected']})"
        snap_warn = " [SNAP-CONFINED - UNSUPPORTED]" if binfo.get("is_snap") else ""
        print(f"   {bname:<14} : {path_str} -> {ver_str}{pinned_tag}{snap_warn} {tag}")
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
    print(f"   Service Acct : {'ps028-sv [OK]' if helper['service_account_ps028_sv'] else 'ps028-sv [MISSING]'}")
    print(f"   Helper Binary: {'Installed [OK]' if helper['helper_executable']['installed'] else 'Not Deployed [PENDING]'}")
    print(f"   Sudoers Rule : {'Installed [OK]' if helper['sudoers_drop_in']['installed'] else 'Not Deployed [PENDING]'}")
    print(f"   Manifest     : {'Installed & Verified [OK]' if helper['deployment_manifest']['sha_match'] else 'Pending / Unverified [PENDING]'}")
    print()

    # 7. Configuration Files
    configs = report["configuration_files"]
    print("7. Configuration & Manifest Files:")
    for fpath, exists in configs["files"].items():
        print(f"   {fpath:<50} : {'[OK]' if exists else '[MISSING]'}")
    print()

    # 8. Actionable Remediation
    remediations = report.get("remediation_actions", [])
    if remediations:
        print("=" * 78)
        print("ACTIONABLE REMEDIATION STEPS:")
        for idx, act in enumerate(remediations, 1):
            print(f"  {idx}. [{act['category']}] {act['issue']}")
            print(f"     -> {act['remediation']}")
        print("=" * 78)

    print("=" * 78)
    if report["readiness_state"] == STATE_REPLICATION_READY_FOR_AUTHORIZATION:
        print("[SUCCESS] Host environment satisfies all partner replication requirements.")
        print("          Ready for explicit operator authorization to provision topology.")
    elif report["readiness_state"] in (STATE_HOST_PREREQUISITES_READY, STATE_BROWSER_TOOLCHAIN_READY, STATE_HELPER_DEPLOYMENT_READY):
        print(f"[{report['readiness_state']}] Host prerequisites partially met; action required before authorization.")
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

    return 0 if report["readiness_state"] == STATE_REPLICATION_READY_FOR_AUTHORIZATION else 1


if __name__ == "__main__":
    sys.exit(main())
