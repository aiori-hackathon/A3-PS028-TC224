#!/usr/bin/python3 -I
"""
PS-028 Happy Eyeballs Measurement Lab: Privileged Operations Helper
Work Package A10: Live Campaign Orchestration & Non-Interactive Privilege Separation

Narrowly scoped, non-interactive privileged helper for:
1. Applying S0-S6 network impairments (tc netem, nftables) in router/server namespaces.
2. Restoring pristine baseline state (clearing nftables, resetting 10ms delays, clearing state).
3. Verifying live network baseline (nftables absence, 10ms netem on 4 interfaces, dual-stack ping, dual-stack DNS).
4. Managing tcpdump packet capture in ps028-cl (start with immediate mode, safe graceful shutdown with SIGINT).
5. Safe lock coordination: preserves shared .lab.lock throughout trials without recursive deadlocks or silent bypass.
"""

import argparse
import concurrent.futures
import contextlib
import ctypes
import enum
import errno
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

class PrivilegedHelperError(Exception):
    """Raised when a privileged helper operation fails."""
    pass

try:
    _libc = ctypes.CDLL(None, use_errno=True)
    _renameat_fn = getattr(_libc, "renameat", None)
    if _renameat_fn:
        _renameat_fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
        _renameat_fn.restype = ctypes.c_int
except Exception:
    _renameat_fn = None

def _safe_renameat(
    old_dir_fd: int,
    old_name: str,
    new_dir_fd: int,
    new_name: str,
    fallback_old_path: Optional[Path] = None,
    fallback_new_path: Optional[Path] = None
) -> None:
    """
    Performs atomic directory-descriptor-relative rename via libc renameat.
    Prevents path traversal and parent directory substitution TOCTOU races.
    Validates single-component filenames, non-negative FDs, and rejects embedded NULs.
    """
    if not isinstance(old_name, str) or not isinstance(new_name, str):
        raise TypeError("old_name and new_name must be strings")
    if not old_name or not new_name:
        raise ValueError("old_name and new_name cannot be empty")
    if "\0" in old_name or "\0" in new_name:
        raise ValueError("Embedded NUL in filename")
    if "/" in old_name or "\\" in old_name or "/" in new_name or "\\" in new_name:
        raise ValueError("Path separators are not permitted in directory-relative filenames")
    if old_name in (".", "..") or new_name in (".", ".."):
        raise ValueError("Dot and dot-dot are not permitted as rename targets")
    if old_dir_fd < 0 or new_dir_fd < 0:
        raise ValueError("Directory file descriptors must be non-negative integers")

    if _renameat_fn is not None:
        res = _renameat_fn(
            ctypes.c_int(old_dir_fd),
            old_name.encode("utf-8"),
            ctypes.c_int(new_dir_fd),
            new_name.encode("utf-8")
        )
        if res != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
    else:
        if fallback_old_path is not None and fallback_new_path is not None:
            os.replace(fallback_old_path, fallback_new_path)
        else:
            raise OSError(errno.ENOSYS, "libc renameat is not available and no fallback path was provided")

PRIVILEGED_IMPORT_CLOSURE = [
    "lab.concurrency",
    "lab.identity",
    "lab.impair",
    "lab.run_trial",
]

def verify_privileged_import_closure(modules: Optional[List[str]] = None, allow_repo: bool = False) -> None:
    """
    Verifies the integrity of first-party modules within the privileged execution closure:
    1. Module file exists, is a regular file, and is NOT a symlink.
    2. Module file is NOT world-writable (mode & 0o002 == 0).
    3. Module file is NOT group-writable when running as root without allow_repo (mode & 0o020 == 0).
    4. If running as root (EUID 0) without allow_repo, module must be owned by root (UID 0).
    5. Parent directories up to / must not be world-writable.
    6. Corresponding .pyc bytecode files in __pycache__ (if present) are regular files,
       not symlinks, not world-writable, not group-writable, and root-owned if EUID 0.
    """
    if modules is None:
        modules = PRIVILEGED_IMPORT_CLOSURE

    for mod_name in modules:
        mod_path = None
        if mod_name in sys.modules:
            mod = sys.modules[mod_name]
            if getattr(mod, "__file__", None):
                mod_path = Path(mod.__file__)
            elif getattr(mod, "__spec__", None) and getattr(mod.__spec__, "origin", None):
                mod_path = Path(mod.__spec__.origin)

        if mod_path is None:
            try:
                spec = importlib.util.find_spec(mod_name)
                if spec is not None and spec.origin is not None:
                    mod_path = Path(spec.origin)
            except Exception as exc:
                raise PrivilegedHelperError(f"Security error: cannot inspect module spec for '{mod_name}': {exc}") from exc

        if mod_path is None:
            continue
        if not mod_path.exists():
            raise PrivilegedHelperError(f"Security error: module file '{mod_path}' for '{mod_name}' does not exist")

        if mod_path.is_symlink() or os.path.islink(str(mod_path)):
            raise PrivilegedHelperError(f"Security error: module file '{mod_path}' for '{mod_name}' is a symlink")

        st = os.lstat(str(mod_path))
        if not stat.S_ISREG(st.st_mode):
            raise PrivilegedHelperError(f"Security error: module file '{mod_path}' for '{mod_name}' is not a regular file")

        if (st.st_mode & 0o002) != 0:
            raise PrivilegedHelperError(f"Security error: module file '{mod_path}' is world-writable (mode {oct(st.st_mode)})")

        if os.geteuid() == 0 and not allow_repo and (st.st_mode & 0o020) != 0:
            raise PrivilegedHelperError(f"Security error: module file '{mod_path}' is group-writable (mode {oct(st.st_mode)})")

        if os.geteuid() == 0:
            is_repo_path = allow_repo and (mod_path == REPO_ROOT.resolve() or REPO_ROOT.resolve() in mod_path.parents)
            if not is_repo_path and st.st_uid != 0:
                raise PrivilegedHelperError(f"Security error: module file '{mod_path}' is not owned by root (UID {st.st_uid})")

        parent = mod_path.parent
        while parent != parent.parent:
            pst = parent.stat()
            if (pst.st_mode & 0o002) != 0:
                raise PrivilegedHelperError(f"Security error: directory '{parent}' in module path is world-writable")
            parent = parent.parent

        pycache_dir = mod_path.parent / "__pycache__"
        if pycache_dir.is_dir():
            for pyc in pycache_dir.glob(f"{mod_path.stem}.*.pyc"):
                if pyc.is_symlink() or os.path.islink(str(pyc)):
                    raise PrivilegedHelperError(f"Security error: bytecode file '{pyc}' is a symlink")
                pyc_st = os.lstat(str(pyc))
                if not stat.S_ISREG(pyc_st.st_mode):
                    raise PrivilegedHelperError(f"Security error: bytecode file '{pyc}' is not a regular file")
                if (pyc_st.st_mode & 0o002) != 0:
                    raise PrivilegedHelperError(f"Security error: bytecode file '{pyc}' is world-writable")
                if os.geteuid() == 0 and not allow_repo and (pyc_st.st_mode & 0o020) != 0:
                    raise PrivilegedHelperError(f"Security error: bytecode file '{pyc}' is group-writable")
                if os.geteuid() == 0 and not allow_repo and pyc_st.st_uid != 0:
                    raise PrivilegedHelperError(f"Security error: bytecode file '{pyc}' is not owned by root (UID {pyc_st.st_uid})")

def is_trusted_sys_path_dir(path: Union[str, Path], allow_repo: bool = False) -> bool:
    """
    Validates whether a directory is trusted for sys.path inclusion.
    When running as root (EUID 0), directory and all ancestors up to / must be:
    - Root-owned (UID 0) (or current user if allow_repo is True for test harnesses)
    - Not writable by group or others (mode & 0o022 == 0)
    Rejects empty, non-existent, non-directory, or world/group-writable paths.
    """
    if not path or str(path) in ("", "."):
        return False
    try:
        p = Path(path).resolve()
        if not p.is_dir():
            return False
        st = p.stat()
        if (st.st_mode & 0o002) != 0:
            return False  # World-writable is always rejected

        if os.geteuid() == 0:
            is_repo_path = allow_repo and (p == REPO_ROOT.resolve() or REPO_ROOT.resolve() in p.parents)
            if not is_repo_path and st.st_uid != 0:
                return False
            if (st.st_mode & 0o020) != 0 and not is_repo_path:
                return False  # Group-writable rejected for root execution

            # Verify parents up to root
            curr = p.parent
            while curr != curr.parent:
                pst = curr.stat()
                if (pst.st_mode & 0o002) != 0 or ((pst.st_mode & 0o020) != 0 and not is_repo_path):
                    return False
                if not is_repo_path and pst.st_uid != 0:
                    return False
                curr = curr.parent
        return True
    except (OSError, ValueError):
        return False

def sanitize_privileged_sys_path() -> None:
    """
    Sanitizes sys.path when running as root (EUID 0) to prevent arbitrary code execution
    via untrusted, user-writable directories or current working directory.
    Purges untrusted directories and ensures deployed helper path is available.
    """
    if os.geteuid() == 0:
        safe_paths = []
        is_test = bool(os.environ.get("PS028_TEST_SUITE"))
        for p in list(sys.path):
            if is_trusted_sys_path_dir(p, allow_repo=is_test):
                safe_paths.append(str(Path(p).resolve()))
        deployed_dir = Path("/usr/local/libexec/ps028")
        if deployed_dir.is_dir() and is_trusted_sys_path_dir(deployed_dir):
            dep_str = str(deployed_dir.resolve())
            if dep_str not in safe_paths:
                safe_paths.insert(0, dep_str)
        sys.path[:] = safe_paths
    else:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))

sanitize_privileged_sys_path()

import lab.concurrency as concurrency
import lab.identity as identity
import lab.impair as impair
import lab.run_trial as run_trial

verify_privileged_import_closure(allow_repo=bool(os.environ.get("PS028_TEST_SUITE")))

DEFAULT_SCENARIOS_PATH = SCRIPT_DIR / "scenarios.yaml"
STATE_FILE = SCRIPT_DIR / ".impair_state.json"
LAB_LOCK_FILE = concurrency.DEFAULT_LAB_LOCK_FILE
DNS_CONFIG_FILE = SCRIPT_DIR / "dns_config.json"
CLIENT_NETNS = "ps028-cl"
ROUTER_NETNS = "ps028-rt"
SERVER_NETNS = "ps028-sv"

CLIENT_CAPTURE_INTERFACE = "ps028-cl-rt"
DEFAULT_CAPTURE_BUFFER_KB = 8192
DEFAULT_BPF_FILTER = (
    "(host 10.0.1.1 and port 53) or "
    "(host 10.0.2.10 and tcp port 80) or "
    "(host 2001:db8:2::10 and tcp port 80)"
)

ALLOWED_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
ALLOWED_NETNS = {CLIENT_NETNS, ROUTER_NETNS, SERVER_NETNS}

DEFAULT_ALLOWED_ROOTS = [
    REPO_ROOT,
    Path("/tmp"),
    Path("/var/tmp"),
    Path(tempfile.gettempdir()),
    Path("/run"),
    Path("/var/run"),
    Path("/usr/local/libexec/ps028"),
]

ALLOWED_PS028_CLIENT_IPS = {"10.0.1.2", "2001:db8:1::2"}
ALLOWED_PS028_TARGET_IPS = {"10.0.2.10", "2001:db8:2::10"}
ALLOWED_TEST_LOOPBACK_IPS = {"127.0.0.1", "::1"}
ALLOWED_S5_IFACES = {"ps028-rt-sv6", "ps028-rt-sv4", "ps028-cl-rt", "ps028-rt-cl", "lo"}
ALLOWED_S5_NETNS = {"ps028-cl"}

class FileOperationType(str, enum.Enum):
    PID_FILE = "pid_file"
    PCAP_FILE = "pcap_file"
    LOG_FILE = "log_file"
    STATE_FILE = "state_file"
    CONFIG_FILE = "config_file"
    BACKUP_FILE = "backup_file"
    LOCK_FILE = "lock_file"
    DATA_FILE = "data_file"

OPERATION_ALLOWED_EXTENSIONS = {
    FileOperationType.PID_FILE: {".pid"},
    FileOperationType.PCAP_FILE: {".pcap", ".pcapng"},
    FileOperationType.LOG_FILE: {".log", ".txt"},
    FileOperationType.STATE_FILE: {".json", ".yaml", ".yml"},
    FileOperationType.CONFIG_FILE: {".json", ".conf", ".yaml", ".yml"},
    FileOperationType.BACKUP_FILE: {".bak", ".impair_bak", ".json"},
    FileOperationType.LOCK_FILE: {".lock"},
    FileOperationType.DATA_FILE: {".json", ".jsonl", ".csv", ".txt"},
}

OPERATION_ALLOWED_ROOTS: Dict[FileOperationType, List[Path]] = {
    FileOperationType.PID_FILE: [
        Path("/run"),
        Path("/var/run"),
        REPO_ROOT / "lab",
        REPO_ROOT / "results",
        REPO_ROOT / "captures",
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.PCAP_FILE: [
        REPO_ROOT / "results",
        REPO_ROOT / "captures",
        REPO_ROOT / "lab",
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.LOG_FILE: [
        REPO_ROOT / "results",
        REPO_ROOT / "logs",
        REPO_ROOT / "lab",
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.STATE_FILE: [
        REPO_ROOT / "lab",
        REPO_ROOT / "results",
        Path("/run"),
        Path("/var/run"),
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.CONFIG_FILE: [
        REPO_ROOT / "lab",
        Path("/usr/local/libexec/ps028"),
        Path("/etc/netns/ps028-cl"),
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.BACKUP_FILE: [
        REPO_ROOT / "lab",
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.LOCK_FILE: [
        REPO_ROOT / "lab",
        Path("/run"),
        Path("/var/run"),
        Path(tempfile.gettempdir()),
    ],
    FileOperationType.DATA_FILE: [
        REPO_ROOT / "results",
        REPO_ROOT / "lab",
        REPO_ROOT / "derived",
        Path(tempfile.gettempdir()),
    ],
}

PRIVILEGED_OPERATION_ALLOWED_ROOTS: Dict[FileOperationType, List[Path]] = {
    FileOperationType.PID_FILE: [
        Path("/run/ps028"),
        Path("/var/run/ps028"),
    ],
    FileOperationType.PCAP_FILE: [
        Path("/run/ps028"),
        Path("/var/run/ps028"),
    ],
    FileOperationType.LOG_FILE: [
        Path("/var/log/ps028"),
        Path("/run/ps028"),
        Path("/var/run/ps028"),
    ],
    FileOperationType.STATE_FILE: [
        Path("/run/ps028"),
        Path("/var/run/ps028"),
        Path("/var/lib/ps028"),
    ],
    FileOperationType.CONFIG_FILE: [
        Path("/usr/local/libexec/ps028"),
        Path("/etc/netns/ps028-cl"),
    ],
    FileOperationType.BACKUP_FILE: [
        Path("/etc/netns/ps028-cl"),
        Path("/run/ps028"),
        Path("/var/run/ps028"),
    ],
    FileOperationType.LOCK_FILE: [
        Path("/run/ps028"),
        Path("/var/run/ps028"),
    ],
    FileOperationType.DATA_FILE: [],  # Privileged writes prohibited; non-privileged streaming only
}


def validate_secure_path(
    path: Union[str, Path],
    param_name: str = "path",
    allowed_roots: Optional[List[Path]] = None,
    must_exist: bool = False,
    allow_symlinks: bool = False,
    must_be_file: bool = False
) -> Path:
    """
    Enforces strict filesystem path confinement:
    1. Rejects null bytes and invalid characters.
    2. Resolves path against explicit allowlisted roots.
    3. Rejects path traversal and symlink escapes.
    4. Validates existence and file type where required.
    5. Fails closed with PrivilegedHelperError.
    """
    if path is None:
        raise PrivilegedHelperError(f"Missing required path for parameter '{param_name}'")

    path_str = str(path)
    if "\0" in path_str:
        raise PrivilegedHelperError(f"Security error: path for '{param_name}' contains null bytes")

    roots = allowed_roots or DEFAULT_ALLOWED_ROOTS
    p = Path(path)
    norm_p = Path(os.path.abspath(path_str))

    # 1. Enforce confinement on normalized lexical path
    p_in_roots = any(
        norm_p == r or r in norm_p.parents or
        norm_p == r.resolve() or r.resolve() in norm_p.parents
        for r in roots
    )
    if not p_in_roots:
        raise PrivilegedHelperError(
            f"Security error: path '{path_str}' for parameter '{param_name}' resolves to '{norm_p}', "
            f"which is outside approved directories ({[str(r) for r in roots]}). Directory traversal rejected."
        )

    # 2. Check for direct symlink before resolution
    if not allow_symlinks:
        try:
            if p.is_symlink() or (p.exists() and os.path.islink(str(p))):
                raise PrivilegedHelperError(
                    f"Security error: symlinks are not permitted for '{param_name}': {path_str}"
                )
        except OSError as exc:
            if isinstance(exc, PrivilegedHelperError):
                raise
            pass

    # 3. Resolve the path
    try:
        resolved = p.resolve(strict=must_exist)
    except (OSError, RuntimeError) as e:
        if must_exist:
            raise PrivilegedHelperError(f"Path '{path_str}' for '{param_name}' does not exist: {e}") from e
        try:
            parent_resolved = p.parent.resolve()
            resolved = parent_resolved / p.name
        except Exception as pe:
            raise PrivilegedHelperError(f"Failed to resolve path '{path_str}' for '{param_name}': {pe}") from pe

    # 4. Check symlinks on intermediate parent components
    if not allow_symlinks:
        try:
            check_p = p.parent
            root_resolved_set = {r.resolve() for r in roots}
            root_path_set = {Path(r) for r in roots}
            while check_p != check_p.parent:
                if check_p in root_path_set or check_p.resolve() in root_resolved_set:
                    break
                if check_p.is_symlink() or os.path.islink(str(check_p)):
                    raise PrivilegedHelperError(
                        f"Security error: parent directory '{check_p}' is a symlink escaping approved roots"
                    )
                check_p = check_p.parent
        except OSError as exc:
            if isinstance(exc, PrivilegedHelperError):
                raise
            pass

    # 5. Enforce confinement within allowed_roots on resolved target
    is_confined = any(
        resolved == r.resolve() or r.resolve() in resolved.parents
        for r in roots
    )

    if not is_confined:
        raise PrivilegedHelperError(
            f"Security error: path '{path_str}' for parameter '{param_name}' resolves to '{resolved}', "
            f"which is outside approved directories ({[str(r) for r in roots]}). Directory traversal rejected."
        )

    if must_be_file and resolved.exists() and not resolved.is_file():
        raise PrivilegedHelperError(f"Path '{path_str}' for '{param_name}' must be a regular file")

    return resolved


def validate_operation_path(
    path: Union[str, Path],
    op_type: FileOperationType,
    param_name: str = "path",
    allowed_roots: Optional[List[Path]] = None,
    must_exist: bool = False,
    allow_symlinks: bool = False,
    is_test_fixture: bool = False
) -> Path:
    """
    Validates a filesystem path according to its operational role:
    1. Enforces allowed extension set for op_type.
    2. Root Execution Isolation: When running with root privileges (os.geteuid() == 0 and not is_test_fixture),
       user-owned repository paths (especially REPO_ROOT and REPO_ROOT / "lab") are strictly prohibited
       from serving as privileged configuration sources or write destinations.
    3. Enforces root confinement and symlink restrictions via validate_secure_path.
    """
    p = Path(path)
    allowed_exts = OPERATION_ALLOWED_EXTENSIONS.get(op_type)
    if allowed_exts:
        full_suffix = "".join(p.suffixes).lower()
        single_suffix = p.suffix.lower()
        if full_suffix not in allowed_exts and single_suffix not in allowed_exts:
            raise PrivilegedHelperError(
                f"Security error: path '{path}' for '{param_name}' has invalid extension for {op_type.value}. "
                f"Allowed extensions: {sorted(allowed_exts)}"
            )

    euid = os.geteuid()
    if euid == 0 and not is_test_fixture:
        if op_type == FileOperationType.DATA_FILE:
            raise PrivilegedHelperError(
                f"Security error: privileged write operations for {op_type.value} are strictly prohibited under root execution."
            )
        # Strict Root Execution Confinement:
        # Disallow any path within user-owned repository checkout (REPO_ROOT)
        try:
            norm_p = Path(os.path.abspath(str(path)))
            repo_resolved = REPO_ROOT.resolve()
            if norm_p == repo_resolved or repo_resolved in norm_p.parents:
                raise PrivilegedHelperError(
                    f"Security error: user-owned repository path '{path}' for parameter '{param_name}' "
                    f"cannot serve as privileged {op_type.value} source or destination under root execution."
                )
        except OSError:
            pass

        if allowed_roots is None:
            allowed_roots = PRIVILEGED_OPERATION_ALLOWED_ROOTS.get(op_type, [])
    else:
        if allowed_roots is None:
            allowed_roots = OPERATION_ALLOWED_ROOTS.get(op_type, DEFAULT_ALLOWED_ROOTS)

    return validate_secure_path(
        path=path,
        param_name=param_name,
        allowed_roots=allowed_roots,
        must_exist=must_exist,
        allow_symlinks=allow_symlinks
    )


def verify_trusted_parent_directory(
    dir_fd: int,
    dir_path: Union[str, Path],
    param_name: str = "directory",
    expected_uid: Optional[int] = None,
    expected_gid: Optional[int] = None,
    is_test_fixture: bool = False
) -> None:
    """
    Enforces strict directory trust boundaries for privileged and unprivileged filesystem operations:
    1. Verifies the opened descriptor is actually a directory (stat.S_ISDIR).
    2. Rejects world-writable directories unconditionally (even with sticky bit S_ISVTX):
       generic shared directories like bare /tmp or /var/tmp cannot be used directly
       as privileged write roots. A dedicated private application-owned directory is required.
    3. Root Privileged Write Policy (when os.geteuid() == 0 and not is_test_fixture):
       - Parent directory MUST be owned strictly by root (UID 0).
       - Directories owned by untrusted invoking user or target user are strictly REJECTED for root writes.
       - Parent must NOT be group-writable (group-writable directories are prohibited for root writes).
       - Safe descriptor-relative traversal verifies all ancestor path components:
         must be directories, owned by root (UID 0), not world-writable, and not group-writable.
    4. Non-privileged Harness and Test Policy (when os.geteuid() != 0 or is_test_fixture):
       - Parent must be owned by the current process EUID (or invoking UID or root).
       - Parent must not be world-writable.
       - Intermediate ancestors must not be world-writable unless a sticky-bit root owned by root (/tmp).
    """
    st = os.fstat(dir_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise PrivilegedHelperError(f"Security error: '{dir_path}' for '{param_name}' is not a directory")

    # Reject world-writable directories unconditionally for target directory
    if st.st_mode & stat.S_IWOTH:
        raise PrivilegedHelperError(
            f"Security error: parent directory '{dir_path}' is world-writable (mode {oct(st.st_mode)}). "
            f"Shared world-writable directories (including bare /tmp or /var/tmp) are prohibited for privileged writes; "
            f"a dedicated private application-owned directory is required."
        )

    euid = os.geteuid()
    if euid == 0 and not is_test_fixture:
        # STRICT ROOT PRIVILEGED WRITE POLICY
        # Output directory must be owned strictly by root (UID 0).
        if st.st_uid != 0:
            raise PrivilegedHelperError(
                f"Security error: privileged directory '{dir_path}' for '{param_name}' must be owned by root (UID 0), "
                f"but is owned by UID {st.st_uid}. Target-user or invoking-user owned directories are rejected for root writes."
            )
        if st.st_mode & stat.S_IWGRP:
            raise PrivilegedHelperError(
                f"Security error: privileged directory '{dir_path}' for '{param_name}' is group-writable (mode {oct(st.st_mode)}). "
                f"Group-writable directories are prohibited for root-privileged operations."
            )
        # Ancestor validation for root writes
        canonical_p = Path(dir_path).resolve()
        for ancestor in canonical_p.parents:
            if ancestor == Path("/"):
                break
            try:
                anc_fd = os.open(str(ancestor), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            except OSError as err:
                raise PrivilegedHelperError(f"Security error: ancestor directory '{ancestor}' cannot be safely verified: {err}")
            try:
                st_anc = os.fstat(anc_fd)
                if not stat.S_ISDIR(st_anc.st_mode):
                    raise PrivilegedHelperError(f"Security error: ancestor '{ancestor}' is not a directory")
                if st_anc.st_uid != 0:
                    raise PrivilegedHelperError(
                        f"Security error: privileged ancestor directory '{ancestor}' must be owned by root (UID 0), but is owned by UID {st_anc.st_uid}"
                    )
                if st_anc.st_mode & stat.S_IWOTH:
                    raise PrivilegedHelperError(
                        f"Security error: privileged ancestor directory '{ancestor}' is world-writable"
                    )
                if st_anc.st_mode & stat.S_IWGRP:
                    raise PrivilegedHelperError(
                        f"Security error: privileged ancestor directory '{ancestor}' is group-writable (mode {oct(st_anc.st_mode)}). "
                        f"Group-writable directories are prohibited for root-privileged operations."
                    )
            finally:
                os.close(anc_fd)
    else:
        # NON-PRIVILEGED HARNESS OR TEST FIXTURE POLICY
        allowed_uids = {0, euid}
        if is_test_fixture:
            allowed_uids.add(os.getuid())
            if expected_uid is not None:
                allowed_uids.add(expected_uid)
        if st.st_uid not in allowed_uids:
            raise PrivilegedHelperError(
                f"Security error: parent directory '{dir_path}' is owned by untrusted UID {st.st_uid} (allowed: {allowed_uids})"
            )
        if st.st_mode & stat.S_IWGRP:
            allowed_gids = {0, os.getgid()}
            if is_test_fixture and expected_gid is not None:
                allowed_gids.add(expected_gid)
            if st.st_gid not in allowed_gids:
                raise PrivilegedHelperError(
                    f"Security error: parent directory '{dir_path}' is group-writable by untrusted GID {st.st_gid}"
                )
        # Ancestor validation for unprivileged / test fixtures
        canonical_p = Path(dir_path).resolve()
        for ancestor in canonical_p.parents:
            if ancestor == Path("/"):
                break
            try:
                anc_fd = os.open(str(ancestor), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            except OSError as err:
                raise PrivilegedHelperError(f"Security error: ancestor directory '{ancestor}' cannot be safely verified: {err}")
            try:
                st_anc = os.fstat(anc_fd)
                if not stat.S_ISDIR(st_anc.st_mode):
                    raise PrivilegedHelperError(f"Security error: ancestor '{ancestor}' is not a directory")
                if st_anc.st_mode & stat.S_IWOTH:
                    if not (st_anc.st_mode & stat.S_ISVTX and st_anc.st_uid == 0):
                        raise PrivilegedHelperError(
                            f"Security error: ancestor directory '{ancestor}' is world-writable without sticky-bit root ownership"
                        )
            finally:
                os.close(anc_fd)


def safe_write_pid_file(
    pid_path: Union[str, Path],
    content: str,
    owner_user: Optional[str] = None,
    owner_group: Optional[str] = None,
    is_test_fixture: bool = False
) -> Path:
    """
    Safely writes a PID file in a symlink- and hardlink-race resistant manner:
    - Anchored by parent directory file descriptor.
    - Validates target filename is a single lexical component (no directory traversal).
    - Checks destination entry via fstatat: rejects existing symlinks, FIFOs/special files,
      and files with st_nlink > 1 (hardlink attack protection).
    - Creates a unique temporary file in the authorized directory using O_CREAT | O_EXCL | O_NOFOLLOW.
    - Validates newly created descriptor with fstat: asserts regular file and st_nlink == 1.
    - Writes content through descriptor using a loop to handle partial writes.
    - Flushes content via os.fsync(tmp_fd).
    - Sets ownership safely via os.fchown(tmp_fd, ...) when running as root.
    - Atomically replaces destination via libc renameat through the retained parent directory descriptor.
    - Flushes parent directory via os.fsync(parent_fd).
    - Cleans up temporary file descriptor and file on any failure path.
    """
    target = validate_operation_path(pid_path, FileOperationType.PID_FILE, param_name="pid_file", allow_symlinks=False, is_test_fixture=is_test_fixture)
    target_name = target.name
    if "/" in target_name or "\\" in target_name or target_name in (".", "..") or "\0" in target_name:
        raise PrivilegedHelperError(f"Security error: invalid single-component PID filename '{target_name}'")

    parent_dir = target.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    try:
        parent_fd = os.open(str(parent_dir), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as err:
        raise PrivilegedHelperError(f"Security error: cannot safely open PID parent directory '{parent_dir}': {err}")
    tmp_name = None
    tmp_fd = -1
    try:
        exp_uid = None
        exp_gid = None
        if owner_user:
            try:
                import pwd
                pw = pwd.getpwnam(str(owner_user))
                exp_uid = pw.pw_uid
                exp_gid = owner_group if isinstance(owner_group, int) else pw.pw_gid
            except Exception:
                pass
        verify_trusted_parent_directory(parent_fd, parent_dir, param_name="pid_file", expected_uid=exp_uid, expected_gid=exp_gid, is_test_fixture=is_test_fixture)

        try:
            dst_st = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(dst_st.st_mode):
                raise PrivilegedHelperError(f"Security error: PID file '{target}' is a symlink")
            if not stat.S_ISREG(dst_st.st_mode):
                raise PrivilegedHelperError(f"Security error: PID file '{target}' is not a regular file")
            if dst_st.st_nlink > 1:
                raise PrivilegedHelperError(
                    f"Security error: PID file '{target}' has multiple hard links (st_nlink={dst_st.st_nlink})"
                )
        except FileNotFoundError:
            pass

        tmp_name = f".tmp_pid_{target_name}_{secrets.token_hex(8)}"
        crea_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        tmp_fd = os.open(tmp_name, crea_flags, 0o644, dir_fd=parent_fd)

        tmp_st = os.fstat(tmp_fd)
        if not stat.S_ISREG(tmp_st.st_mode):
            raise PrivilegedHelperError(f"Security error: temporary PID file '{tmp_name}' is not a regular file")
        if tmp_st.st_nlink != 1:
            raise PrivilegedHelperError(
                f"Security error: temporary PID file '{tmp_name}' has invalid link count: {tmp_st.st_nlink}"
            )

        data = content.encode("utf-8")
        written = 0
        while written < len(data):
            n = os.write(tmp_fd, data[written:])
            if n == 0:
                raise PrivilegedHelperError("Failed to write to PID file: 0 bytes written")
            written += n

        os.fsync(tmp_fd)

        if os.geteuid() == 0 and (owner_user or owner_group):
            try:
                import pwd
                uid = pwd.getpwnam(str(owner_user)).pw_uid if owner_user else -1
                gid = owner_group if isinstance(owner_group, int) else (pwd.getpwnam(str(owner_user)).pw_gid if owner_user else -1)
                if uid > 0 and gid > 0:
                    try:
                        os.fchown(tmp_fd, uid, gid)
                    except PermissionError:
                        os.chown(str(parent_dir / tmp_name), uid, gid)
            except Exception:
                pass

        os.close(tmp_fd)
        tmp_fd = -1

        _safe_renameat(
            parent_fd,
            tmp_name,
            parent_fd,
            target_name,
            fallback_old_path=parent_dir / tmp_name,
            fallback_new_path=target
        )
        tmp_name = None

        try:
            os.fsync(parent_fd)
        except OSError:
            pass

        return target
    finally:
        if tmp_fd >= 0:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def safe_atomic_write_text(
    path: Union[str, Path],
    content: str,
    op_type: FileOperationType = FileOperationType.STATE_FILE,
    param_name: str = "path",
    owner_user: Optional[str] = None,
    owner_group: Optional[str] = None,
    is_test_fixture: bool = False
) -> Path:
    """
    Safely writes text to path using directory-descriptor-anchored atomic replacement,
    avoiding TOCTOU parent directory substitution, symlinks, and hardlink attacks.
    If the target destination file already exists, verifies it is not a symlink,
    not a special file, and does not have st_nlink > 1 before atomic replacement.
    CONFIG_FILE is strictly read-only and cannot be targeted by write operations.
    """
    if op_type == FileOperationType.CONFIG_FILE:
        raise PrivilegedHelperError("Security error: CONFIG_FILE is strictly read-only; write operations are prohibited")

    target = validate_operation_path(path, op_type, param_name=param_name, allow_symlinks=False, is_test_fixture=is_test_fixture)
    target_name = target.name
    if "/" in target_name or "\\" in target_name or target_name in (".", "..") or "\0" in target_name:
        raise PrivilegedHelperError(f"Security error: invalid single-component filename '{target_name}'")

    parent_dir = target.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    try:
        parent_fd = os.open(str(parent_dir), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as err:
        raise PrivilegedHelperError(f"Security error: cannot safely open parent directory '{parent_dir}': {err}")
    tmp_name = None
    tmp_fd = -1
    try:
        exp_uid = None
        exp_gid = None
        if owner_user:
            try:
                import pwd
                pw = pwd.getpwnam(str(owner_user))
                exp_uid = pw.pw_uid
                exp_gid = owner_group if isinstance(owner_group, int) else pw.pw_gid
            except Exception:
                pass
        verify_trusted_parent_directory(parent_fd, parent_dir, param_name=param_name, expected_uid=exp_uid, expected_gid=exp_gid, is_test_fixture=is_test_fixture)

        try:
            dst_st = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(dst_st.st_mode):
                raise PrivilegedHelperError(f"Security error: destination '{target}' is a symlink")
            if not stat.S_ISREG(dst_st.st_mode):
                raise PrivilegedHelperError(f"Security error: destination '{target}' is not a regular file")
            if dst_st.st_nlink > 1:
                raise PrivilegedHelperError(f"Security error: destination '{target}' has multiple hard links (st_nlink={dst_st.st_nlink})")
        except FileNotFoundError:
            pass

        tmp_name = f".tmp_{target_name}_{secrets.token_hex(8)}"
        crea_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        tmp_fd = os.open(tmp_name, crea_flags, 0o644, dir_fd=parent_fd)

        st = os.fstat(tmp_fd)
        if not stat.S_ISREG(st.st_mode):
            raise PrivilegedHelperError(f"Security error: temporary file '{tmp_name}' is not a regular file")
        if st.st_nlink != 1:
            raise PrivilegedHelperError(f"Security error: temporary file has invalid hardlink count: {st.st_nlink}")

        data = content.encode("utf-8")
        written = 0
        while written < len(data):
            n = os.write(tmp_fd, data[written:])
            if n == 0:
                raise PrivilegedHelperError("Failed to write to file: 0 bytes written")
            written += n

        os.fsync(tmp_fd)

        if os.geteuid() == 0 and (owner_user or owner_group):
            try:
                import pwd
                uid = pwd.getpwnam(str(owner_user)).pw_uid if owner_user else -1
                gid = owner_group if isinstance(owner_group, int) else (pwd.getpwnam(str(owner_user)).pw_gid if owner_user else -1)
                if uid > 0 and gid > 0:
                    try:
                        os.fchown(tmp_fd, uid, gid)
                    except PermissionError:
                        os.chown(str(parent_dir / tmp_name), uid, gid)
            except Exception:
                pass

        os.close(tmp_fd)
        tmp_fd = -1

        _safe_renameat(
            parent_fd,
            tmp_name,
            parent_fd,
            target_name,
            fallback_old_path=parent_dir / tmp_name,
            fallback_new_path=target
        )
        tmp_name = None

        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        return target
    finally:
        if tmp_fd >= 0:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def validate_ip_endpoint(
    ip_val: Union[str, Any],
    param_name: str,
    allowed_ips: set,
    expected_family: Optional[int] = None,
    allow_loopback: bool = False
) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """
    Strictly validates an IP address:
    1. Rejects any non-string, whitespace, quotes, semicolon, or injection characters.
    2. Parses with ipaddress.ip_address.
    3. Checks expected family (4 or 6) if provided.
    4. Restricts to known allowlisted PS-028 laboratory endpoints. Loopback is rejected unless allow_loopback=True.
    """
    if not isinstance(ip_val, str) or not ip_val.strip():
        raise PrivilegedHelperError(f"Invalid {param_name}: must be a non-empty string")

    clean_ip = ip_val.strip()
    for ch in (" ", "\t", "\r", "\n", ";", '"', "'", "`", "$", "\\", "|", "&", "<", ">", "{", "}", "(", ")", "[", "]"):
        if ch in clean_ip:
            raise PrivilegedHelperError(f"Security error: {param_name} '{clean_ip}' contains forbidden injection syntax")

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError as exc:
        raise PrivilegedHelperError(f"Invalid {param_name} '{clean_ip}': {exc}") from exc

    if expected_family is not None and ip_obj.version != expected_family:
        raise PrivilegedHelperError(
            f"Address family mismatch for {param_name} '{clean_ip}': expected IPv{expected_family}, got IPv{ip_obj.version}"
        )

    effective_allowed = set(allowed_ips)
    if allow_loopback:
        effective_allowed |= ALLOWED_TEST_LOOPBACK_IPS

    canonical = str(ip_obj)
    if canonical not in effective_allowed and clean_ip not in effective_allowed:
        raise PrivilegedHelperError(
            f"Security error: {param_name} '{clean_ip}' is not an authorized PS-028 endpoint (allowed: {sorted(effective_allowed)})"
        )

    return ip_obj


def get_netns_inode(netns_name: str) -> Optional[Tuple[int, int]]:
    """Retrieves kernel (st_dev, st_ino) of /var/run/netns/<netns_name> or /run/netns/<netns_name>."""
    for base in ("/run/netns", "/var/run/netns"):
        p = Path(base) / netns_name
        try:
            if p.is_symlink() or os.path.islink(str(p)):
                continue
            fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            try:
                st = os.fstat(fd)
                if st.st_uid != 0:
                    continue
                return (st.st_dev, st.st_ino)
            finally:
                os.close(fd)
        except OSError:
            pass
    return None


def get_current_netns_dev_ino() -> Optional[Tuple[int, int]]:
    """Retrieves kernel (st_dev, st_ino) of the current process (/proc/self/ns/net)."""
    try:
        st = os.stat("/proc/self/ns/net")
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def verify_current_netns(netns_name: str) -> bool:
    """
    Positively verifies via kernel dev/inode that the current process is executing inside
    the expected target network namespace.
    Ensures /run/netns/<netns_name> is not a symlink, is owned by root, and matches /proc/self/ns/net.
    """
    target = get_netns_inode(netns_name)
    if target is None:
        return False
    current = get_current_netns_dev_ino()
    return current is not None and current == target


class SnapMountError(PrivilegedHelperError, run_trial.TrialExecutionError):
    """Raised when setup of required Snap namespaces or mounts fails."""
    pass


def is_snap_browser(executable_path: Union[str, Path]) -> bool:
    """
    Determines whether the given browser executable is managed by Snap.
    Checks path prefix, symlink target pointing to snap, or snapd directory.
    """
    p_str = str(executable_path)
    if p_str.startswith("/snap/") or "/snap/" in p_str or "/var/lib/snapd/snap/" in p_str:
        return True

    # Check if executable in PATH is under /snap
    resolved_which = shutil.which(p_str)
    if resolved_which:
        if resolved_which.startswith("/snap/") or "/snap/" in resolved_which or "/var/lib/snapd/snap/" in resolved_which:
            return True
        try:
            p_which = Path(resolved_which).resolve()
            if str(p_which).startswith("/snap/") or p_which == Path("/usr/bin/snap") or p_which.name == "snap":
                return True
        except (OSError, RuntimeError):
            pass

    try:
        p = Path(executable_path).resolve()
        if str(p).startswith("/snap/") or p == Path("/usr/bin/snap") or p.name == "snap":
            return True
    except (OSError, RuntimeError):
        pass

    return False


def get_invoking_uid_gid() -> Tuple[int, int]:
    """
    Returns the invoking user's UID and GID.
    Authoritatively backed by the Linux passwd database via lab.identity.
    """
    ident = identity.resolve_invoking_identity()
    return ident.uid, ident.gid


def is_mount_present(
    mount_point: str,
    expected_fstype: Optional[str] = None,
    mounts_file: Union[str, Path] = "/proc/mounts"
) -> bool:
    """
    Checks if mount_point is currently an active mount point with optional matching filesystem type.
    """
    try:
        with open(mounts_file, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    mp, fstype = parts[1], parts[2]
                    if mp == mount_point:
                        if expected_fstype is None or fstype == expected_fstype:
                            return True
    except OSError:
        pass
    return False


def setup_snap_mounts(
    mounts_file: Union[str, Path] = "/proc/mounts",
    mount_cmd_runner: Optional[Callable[[List[str]], None]] = None
) -> Dict[str, bool]:
    """
    Ensures cgroup2 is mounted at /sys/fs/cgroup and securityfs is mounted at /sys/kernel/security.
    Mounts them ONLY when missing.
    Raises SnapMountError if mount setup fails.
    Returns dict indicating which filesystems were mounted, e.g.:
    {"cgroup2": bool, "securityfs": bool}
    """
    targets = [
        ("/sys/fs/cgroup", "cgroup2", "cgroup2"),
        ("/sys/kernel/security", "securityfs", "securityfs"),
    ]
    results = {}

    for mp, fstype, src in targets:
        if is_mount_present(mp, expected_fstype=fstype, mounts_file=mounts_file):
            results[fstype] = False
            continue

        try:
            Path(mp).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

        cmd = ["mount", "-t", fstype, src, mp]
        if mount_cmd_runner:
            try:
                mount_cmd_runner(cmd)
            except Exception as e:
                raise SnapMountError(f"Failed to mount {fstype} on {mp}: {e}") from e
        else:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False
                )
                if proc.returncode != 0:
                    err_msg = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
                    raise SnapMountError(f"Failed to mount {fstype} on {mp}: {err_msg}")
            except Exception as e:
                if isinstance(e, SnapMountError):
                    raise
                raise SnapMountError(f"Failed to mount {fstype} on {mp}: {e}") from e

        results[fstype] = True

    return results


def get_lab_resolver_ip(
    resolv_conf_path: Optional[Path] = None,
    expected_ip: str = "10.0.1.1"
) -> str:
    """
    Validates and extracts the lab DNS resolver IP.
    Checks resolv_conf_path if provided, else /etc/netns/ps028-cl/resolv.conf, then /etc/resolv.conf.
    Fails closed (raises SnapMountError) if the expected IP (10.0.1.1) is not configured.
    """
    if resolv_conf_path is not None:
        candidates = [Path(resolv_conf_path)]
    else:
        candidates = [Path("/etc/netns") / CLIENT_NETNS / "resolv.conf", Path("/etc/resolv.conf")]

    for p in candidates:
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ns_ip = parts[1]
                        if ns_ip == expected_ip:
                            return ns_ip
            except OSError:
                continue

    raise SnapMountError(
        f"Lab resolver selection failed: Expected resolver {expected_ip} not found in any candidate "
        f"configuration ({[str(c) for c in candidates]}). Refusing to proceed with unverified or WSL resolver."
    )


NS_GET_NSTYPE = (0xb7 << 8) | 0x3  # 0xb703
CLONE_NEWNS = 0x00020000


def is_genuine_mount_ns_fd(fd: int) -> bool:
    """
    Verifies whether an open file descriptor refers to a genuine CLONE_NEWNS Linux mount namespace.
    Returns True only if ioctl(fd, NS_GET_NSTYPE) returns CLONE_NEWNS.
    Returns False on regular files, other namespace types, or invalid FDs.
    """
    if not isinstance(fd, int) or fd < 0:
        return False
    try:
        nstype = fcntl.ioctl(fd, NS_GET_NSTYPE)
        return nstype == CLONE_NEWNS
    except OSError:
        return False


def acquire_snap_namespace_fd(
    snap_name: str,
    snap_ns_dir: Union[str, Path] = "/run/snapd/ns",
    host_proc_root: Union[str, Path] = "/proc/1/root"
) -> Tuple[Optional[int], bool]:
    """
    Acquires a genuine CLONE_NEWNS source namespace FD for the specified snap.
    Distinguishes a genuine namespace FD from a regular file placeholder.
    Inspects candidate local path first. If local path is a regular file placeholder
    (e.g. inside ps028-cl where /run/snapd/ns is a tmpfs without nsfs mounts),
    attempts to acquire the genuine namespace FD from the host mount namespace via host_proc_root (/proc/1/root).

    Returns:
        (source_fd, placeholder_detected):
        - (fd, False) if a genuine mount namespace FD was acquired.
        - (None, True) if a placeholder file was found but no genuine namespace is accessible.
        - (None, False) if neither local nor host namespace file exists.
    """
    snap_ns_path = Path(snap_ns_dir)
    local_file = snap_ns_path / f"{snap_name}.mnt"
    placeholder_detected = False

    # 1. Try local candidate path first
    if local_file.exists():
        try:
            fd = os.open(str(local_file), os.O_RDONLY | os.O_CLOEXEC)
            if is_genuine_mount_ns_fd(fd):
                return fd, False
            os.close(fd)
            placeholder_detected = True
        except OSError:
            placeholder_detected = True

    # 2. If local path is a placeholder or missing, try host root (/proc/1/root)
    # In ps028-cl, /run/snapd/ns may be a tmpfs, but host Process 1 is in the host
    # mount namespace where /run/snapd/ns/<snap_name>.mnt is backed by nsfs.
    try:
        proc_root = Path(host_proc_root)
        resolved_snap_dir = snap_ns_path.resolve()
        rel_snap_dir = resolved_snap_dir.relative_to("/") if resolved_snap_dir.is_absolute() else resolved_snap_dir
        host_candidate = proc_root / rel_snap_dir / f"{snap_name}.mnt"

        if host_candidate.exists():
            try:
                fd = os.open(str(host_candidate), os.O_RDONLY | os.O_CLOEXEC)
                if is_genuine_mount_ns_fd(fd):
                    return fd, False
                os.close(fd)
                placeholder_detected = True
            except OSError:
                placeholder_detected = True

        fallback_host_file = proc_root / "run" / "snapd" / "ns" / f"{snap_name}.mnt"
        if fallback_host_file != host_candidate and fallback_host_file.exists():
            try:
                fd = os.open(str(fallback_host_file), os.O_RDONLY | os.O_CLOEXEC)
                if is_genuine_mount_ns_fd(fd):
                    return fd, False
                os.close(fd)
                placeholder_detected = True
            except OSError:
                placeholder_detected = True
    except Exception:
        pass

    return None, placeholder_detected


def _clone_snap_mount_namespace(
    source_fd: int,
    resolver_ip: str,
    target_mnt_path: Path,
    mount_cmd_runner: Optional[Callable[[List[str]], None]] = None
) -> None:
    """
    Spawns a worker child to attach to source_fd, clone the namespace via unshare(CLONE_NEWNS),
    apply the lab resolver, and expose it to target_mnt_path via nsfs bind-mount.
    """
    # 1. Pre-flight verification of source namespace FD and its type
    try:
        os.fstat(source_fd)
    except OSError as e:
        raise SnapMountError(f"Snap namespace cloner failed at verify_source_fd: FD {source_fd} is invalid: {e}") from e

    NS_GET_NSTYPE = (0xb7 << 8) | 0x3  # 0xb703
    CLONE_NEWNS = 0x00020000
    try:
        nstype = fcntl.ioctl(source_fd, NS_GET_NSTYPE)
    except OSError as e:
        raise SnapMountError(
            f"Snap namespace cloner failed at verify_source_type: FD {source_fd} ioctl(NS_GET_NSTYPE) failed: {e} "
            f"(file descriptor does not refer to a Linux namespace)"
        ) from e

    if nstype != CLONE_NEWNS:
        raise SnapMountError(
            f"Snap namespace cloner failed at verify_source_type: FD {source_fd} namespace type is {hex(nstype)}, "
            f"expected {hex(CLONE_NEWNS)} (CLONE_NEWNS)"
        )

    pipe_r, pipe_w = os.pipe()

    child_pid = os.fork()
    if child_pid == 0:
        stage = "init"
        try:
            os.close(pipe_r)
            libc = ctypes.CDLL(None, use_errno=True)

            # Stage: Unshare filesystem context (CLONE_FS).
            # Linux kernel fs/namespace.c (mntns_install):
            # if (fs->users != 1) return -EINVAL;
            # When a process shares filesystem attributes (CLONE_FS) via threads or runtime setup,
            # setns() on a mount namespace returns EINVAL. Calling unshare(CLONE_FS)
            # unshares current->fs to ensure fs->users == 1.
            stage = "unshare_fs"
            CLONE_FS = 0x00000200
            rc = libc.unshare(CLONE_FS)
            if rc != 0:
                err = ctypes.get_errno()
                # Non-fatal if unshare(CLONE_FS) returns EINVAL/ENOSYS on older kernels; proceed to setns

            # Stage: Verify source FD inside child
            stage = "verify_child_fd"
            child_nstype = fcntl.ioctl(source_fd, NS_GET_NSTYPE)
            if child_nstype != CLONE_NEWNS:
                raise OSError(
                    errno.EINVAL,
                    f"Child source_fd {source_fd} nstype {hex(child_nstype)} != {hex(CLONE_NEWNS)}"
                )

            # Stage: Enter source namespace
            stage = "setns"
            try:
                os.setns(source_fd, os.CLONE_NEWNS)
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    # Fallback to nstype=0 to allow kernel to infer namespace type
                    try:
                        os.setns(source_fd, 0)
                    except OSError as exc2:
                        raise OSError(
                            exc.errno,
                            f"setns(source_fd={source_fd}, CLONE_NEWNS) failed: {exc}; fallback setns(source_fd, 0) failed: {exc2}"
                        ) from exc2
                else:
                    raise
            os.close(source_fd)

            # Stage: Create private clone of namespace via unshare(CLONE_NEWNS)
            stage = "unshare_clone_newns"
            rc = libc.unshare(CLONE_NEWNS)
            if rc != 0:
                err = ctypes.get_errno()
                raise OSError(err, f"unshare(CLONE_NEWNS) failed: {os.strerror(err)}")

            # Stage: Make propagation private
            stage = "mount_make_private"
            MS_REC = 16384
            MS_PRIVATE = 262144
            rc = libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)
            if rc != 0:
                err = ctypes.get_errno()
                raise OSError(err, f"mount(/, private) failed: {os.strerror(err)}")

            # Stage: Write lab resolv.conf
            stage = "write_resolv_conf"
            resolv_content = (
                "# PS-028 Isolated Snap Resolver Configuration\n"
                f"nameserver {resolver_ip}\n"
                "options timeout:1 attempts:1\n"
            ).encode("utf-8")

            resolv_src = Path("/run/ps028_resolv.conf")
            try:
                resolv_src.write_bytes(resolv_content)
                resolv_src.chmod(0o644)
            except OSError:
                resolv_src = Path("/tmp/.ps028_resolv.conf")
                resolv_src.write_bytes(resolv_content)
                try:
                    resolv_src.chmod(0o644)
                except OSError:
                    pass

            # Stage: Bind mount resolv.conf to stub and standard targets
            stage = "bind_mount_resolv"
            MS_BIND = 4096
            targets = [Path("/etc/resolv.conf")]
            try:
                if Path("/etc/resolv.conf").is_symlink():
                    targets.append(Path("/etc/resolv.conf").resolve())
            except OSError:
                pass
            targets.extend([
                Path("/run/systemd/resolve/stub-resolv.conf"),
                Path("/run/systemd/resolve/resolv.conf"),
                Path("/mnt/wsl/resolv.conf"),
            ])

            for target in targets:
                if target.exists():
                    try:
                        libc.mount(
                            str(resolv_src).encode("utf-8"),
                            str(target).encode("utf-8"),
                            None,
                            MS_BIND,
                            None
                        )
                    except Exception:
                        pass

            # Stage: Notify parent of readiness
            stage = "notify_ready"
            os.write(pipe_w, b"READY\n")
            os.close(pipe_w)

            # Wait for parent to bind-mount /proc/self/ns/mnt
            signal.pause()
        except Exception as exc:
            try:
                os.write(pipe_w, f"ERROR:stage={stage}:{exc}\n".encode("utf-8"))
                os.close(pipe_w)
            except Exception:
                pass
            os._exit(1)

    # Parent process
    os.close(pipe_w)
    try:
        resp = os.read(pipe_r, 4096).decode("utf-8", errors="replace")
        os.close(pipe_r)

        if not resp.startswith("READY"):
            clean_resp = resp.strip()
            raise SnapMountError(f"Snap namespace cloner failed: {clean_resp}")

        stage = "bind_mount_target"
        child_ns_mnt = f"/proc/{child_pid}/ns/mnt"
        bind_cmd = ["mount", "--bind", child_ns_mnt, str(target_mnt_path)]
        if mount_cmd_runner:
            try:
                mount_cmd_runner(bind_cmd)
            except Exception as e:
                raise SnapMountError(f"Failed to bind mount isolated namespace onto {target_mnt_path}: {e}") from e
        else:
            proc = subprocess.run(bind_cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
                raise SnapMountError(f"Failed to bind mount isolated namespace onto {target_mnt_path}: {err}")
    finally:
        try:
            os.kill(child_pid, signal.SIGTERM)
            os.waitpid(child_pid, 0)
        except OSError:
            pass


def _preseed_outer_resolver_stubs(
    resolver_ip: str,
    mount_cmd_runner: Optional[Callable[[List[str]], None]] = None
) -> None:
    """Pre-seeds stub resolver locations in calling namespace if missing."""
    resolv_content = (
        "# PS-028 Isolated Outer Resolver Configuration\n"
        f"nameserver {resolver_ip}\n"
        "options timeout:1 attempts:1\n"
    ).encode("utf-8")
    src = Path("/run/ps028_outer_resolv.conf")
    try:
        src.write_bytes(resolv_content)
        src.chmod(0o644)
    except OSError:
        src = Path("/tmp/.ps028_outer_resolv.conf")
        src.write_bytes(resolv_content)
        try:
            src.chmod(0o644)
        except OSError:
            pass

    targets = [
        Path("/run/systemd/resolve/stub-resolv.conf"),
        Path("/run/systemd/resolve/resolv.conf"),
        Path("/mnt/wsl/resolv.conf"),
        Path("/etc/resolv.conf"),
    ]
    try:
        if Path("/etc/resolv.conf").is_symlink():
            targets.append(Path("/etc/resolv.conf").resolve())
    except OSError:
        pass

    seen = set()
    for target in targets:
        target_str = str(target)
        if target_str in seen:
            continue
        seen.add(target_str)
        if target.exists():
            cmd = ["mount", "--bind", str(src), target_str]
            if mount_cmd_runner:
                try:
                    mount_cmd_runner(cmd)
                except Exception:
                    pass
            else:
                try:
                    subprocess.run(cmd, capture_output=True, check=False)
                except Exception:
                    pass


def setup_snap_isolated_dns(
    snap_name: str,
    resolver_ip: str = "10.0.1.1",
    resolv_conf_path: Optional[Path] = None,
    snap_ns_dir: Union[str, Path] = "/run/snapd/ns",
    isolated_cloner: Optional[Callable[[int, str, Path], None]] = None,
    mount_cmd_runner: Optional[Callable[[List[str]], None]] = None,
    source_fd: Optional[int] = None,
    host_proc_root: Union[str, Path] = "/proc/1/root"
) -> Dict[str, Any]:
    """
    Configures a dedicated, isolated mount namespace for Snap browsers (Chromium / Firefox)
    ensuring they use the lab DNS resolver (10.0.1.1):
    1. Validates the lab resolver IP is present and fails closed if missing.
    2. Acquires genuine source namespace FD from host nsfs mount BEFORE overlaying tmpfs.
    3. Fails clearly if a placeholder is detected and the genuine host namespace cannot be accessed.
    4. Isolates /run/snapd/ns within the private mount namespace using tmpfs so host state is never modified.
    5. Preserves the acquired source FD across the tmpfs overlay without reopening the placeholder path.
    6. Clones the source namespace into an independent, private mount namespace, replaces /etc/resolv.conf
       with the lab resolver, and bind-mounts it to the target placeholder inside the private tmpfs.
    7. Leaves host /run/snapd/ns, host /etc/resolv.conf, and unrelated browser processes completely untouched.
    """
    # 1. Resolver validation
    verified_ip = get_lab_resolver_ip(resolv_conf_path=resolv_conf_path, expected_ip=resolver_ip)

    snap_ns_path = Path(snap_ns_dir)
    if not snap_ns_path.exists():
        return {
            "status": "SKIPPED",
            "reason": f"Snap namespace directory {snap_ns_path} does not exist",
            "resolver_ip": verified_ip
        }

    # 2. Acquire genuine source namespace FD BEFORE mounting private tmpfs
    owned_source_fd = None
    if source_fd is not None:
        if not is_genuine_mount_ns_fd(source_fd):
            raise SnapMountError(
                f"Provided source_fd {source_fd} is not a valid CLONE_NEWNS mount namespace "
                "(NS_GET_NSTYPE validation failed)"
            )
    else:
        acquired_fd, placeholder_detected = acquire_snap_namespace_fd(
            snap_name=snap_name,
            snap_ns_dir=snap_ns_path,
            host_proc_root=host_proc_root
        )
        if acquired_fd is not None:
            source_fd = acquired_fd
            owned_source_fd = acquired_fd
        elif placeholder_detected:
            raise SnapMountError(
                f"Snap namespace cloner failed: '{snap_ns_path / f'{snap_name}.mnt'}' is a regular file placeholder "
                "(not backed by nsfs, NS_GET_NSTYPE failed) and genuine host mount namespace could not be accessed."
            )

    # 3. Cache metadata files (.info, .fstab)
    metadata_cache: Dict[str, bytes] = {}
    try:
        for item in snap_ns_path.iterdir():
            if item.is_file() and not item.name.endswith(".mnt"):
                try:
                    metadata_cache[item.name] = item.read_bytes()
                except OSError:
                    pass
    except OSError:
        pass

    # 4. Mount private tmpfs over /run/snapd/ns
    tmpfs_mounted = False
    try:
        tmpfs_cmd = ["mount", "-t", "tmpfs", "-o", "mode=0755,uid=0,gid=0", "tmpfs", str(snap_ns_path)]
        if mount_cmd_runner:
            try:
                mount_cmd_runner(tmpfs_cmd)
            except Exception as e:
                raise SnapMountError(f"Failed to isolate {snap_ns_path} with tmpfs: {e}") from e
        else:
            proc = subprocess.run(tmpfs_cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
                raise SnapMountError(f"Failed to mount private tmpfs on {snap_ns_path}: {err}")
        tmpfs_mounted = True

        # 5. Restore metadata files and create mnt placeholder
        for fname, data in metadata_cache.items():
            try:
                (snap_ns_path / fname).write_bytes(data)
            except OSError:
                pass

        target_mnt_path = snap_ns_path / f"{snap_name}.mnt"

        # 6. Verify source_fd remains valid after tmpfs overlay; DO NOT reopen target_mnt_path
        if source_fd is not None:
            if not is_genuine_mount_ns_fd(source_fd):
                raise SnapMountError(
                    f"Source namespace FD {source_fd} became invalid after private tmpfs overlay"
                )
            try:
                target_mnt_path.touch(mode=0o444)
            except OSError as e:
                raise SnapMountError(f"Failed to create mount namespace placeholder {target_mnt_path}: {e}") from e

            try:
                if isolated_cloner:
                    isolated_cloner(source_fd, verified_ip, target_mnt_path)
                else:
                    _clone_snap_mount_namespace(
                        source_fd=source_fd,
                        resolver_ip=verified_ip,
                        target_mnt_path=target_mnt_path,
                        mount_cmd_runner=mount_cmd_runner
                    )
            except SnapMountError as exc:
                # Stop ineffective workaround: do NOT fall back to fresh namespace or outer resolver stubs
                # which snap-confine ignores by re-entering PID 1 mount namespace.
                # Rollback target placeholder and raise clear blocker error.
                try:
                    target_mnt_path.unlink(missing_ok=True)
                except OSError:
                    pass
                raise SnapMountError(
                    f"Snap per-trial DNS isolation failed for '{snap_name}' on WSL2: bind mounting cloned namespace failed ({exc}). "
                    "Snap confinement (snap-confine) on WSL2 re-enters PID 1's mount namespace (/proc/1/ns/mnt), overriding container DNS with host DNS (10.255.255.254). "
                    "Preserving host DNS and shared Snap namespaces prevents reliable per-trial resolver redirection. "
                    "Please use a non-Snap browser binary (such as google-chrome) instead."
                ) from exc
        else:
            try:
                target_mnt_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise SnapMountError(
                f"Snap per-trial DNS isolation failed for '{snap_name}': no genuine mount namespace found. "
                "Snap confinement (snap-confine) on WSL2 re-enters PID 1's mount namespace (/proc/1/ns/mnt) and cannot be reliably isolated per-trial. "
                "Please use a non-Snap browser binary (such as google-chrome) instead."
            )
    except Exception:
        if tmpfs_mounted:
            umount_cmd = ["umount", "-l", str(snap_ns_path)]
            try:
                if mount_cmd_runner:
                    mount_cmd_runner(umount_cmd)
                else:
                    subprocess.run(umount_cmd, capture_output=True, check=False)
            except Exception:
                pass
        for temp_resolv in [
            Path("/run/ps028_resolv.conf"), Path("/tmp/.ps028_resolv.conf"),
            Path("/run/ps028_outer_resolv.conf"), Path("/tmp/.ps028_outer_resolv.conf")
        ]:
            try:
                temp_resolv.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    finally:
        if owned_source_fd is not None:
            try:
                os.close(owned_source_fd)
            except OSError:
                pass

    return {
        "status": "OK",
        "snap_name": snap_name,
        "resolver_ip": verified_ip,
        "isolated": True
    }


def launch_snap_browser_main(args: argparse.Namespace) -> None:
    """
    Main entrypoint for launch-snap-browser subparser.
    Called inside ps028-cl in a private mount namespace:
    1. Validates target unprivileged UID/GID.
    2. Sets up missing mounts (cgroup2, securityfs).
    3. Sets up isolated Snap mount namespace with lab DNS resolver (10.0.1.1).
    4. Drops privileges to target UID and GID.
    5. Replaces process image with the browser executable.
    """
    target_uid = getattr(args, "reuid", 0)
    target_gid = getattr(args, "regid", 0)
    if target_uid <= 0 or target_gid <= 0:
        sys.stderr.write(
            f"Security error: refusing to launch browser as root or invalid identity (UID={target_uid}, GID={target_gid})\n"
        )
        sys.stderr.flush()
        sys.exit(74)

    # 1. Mount setup
    try:
        setup_snap_mounts(mounts_file=args.mounts_file)
    except SnapMountError as exc:
        sys.stderr.write(f"Snap mount setup error: {exc}\n")
        sys.stderr.flush()
        sys.exit(71)

    # 2. Extract browser command and snap name
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        sys.stderr.write("Snap browser launcher error: No browser executable specified\n")
        sys.stderr.flush()
        sys.exit(72)

    snap_name = getattr(args, "snap_name", None)
    if not snap_name:
        exe_name = Path(cmd[0]).name
        if exe_name in ("chrome", "google-chrome"):
            snap_name = "chromium"
        else:
            snap_name = exe_name

    # 3. Setup isolated Snap mount namespace & DNS
    try:
        setup_snap_isolated_dns(
            snap_name=snap_name,
            resolver_ip=getattr(args, "resolver_ip", "10.0.1.1") or "10.0.1.1",
            resolv_conf_path=Path(args.resolv_conf) if getattr(args, "resolv_conf", None) else None,
            snap_ns_dir=getattr(args, "snap_ns_dir", "/run/snapd/ns") or "/run/snapd/ns",
            source_fd=getattr(args, "source_fd", None),
            host_proc_root=getattr(args, "host_proc_root", "/proc/1/root") or "/proc/1/root"
        )
    except SnapMountError as exc:
        sys.stderr.write(f"Snap isolated DNS setup error: {exc}\n")
        sys.stderr.flush()
        sys.exit(71)

    target_uid = args.reuid
    target_gid = args.regid

    # Clean unprivileged environment for the browser process
    try:
        browser_env = run_trial.get_browser_env(target_uid, target_gid)
        os.environ.clear()
        os.environ.update(browser_env)
    except Exception as env_exc:
        sys.stderr.write(f"Failed to prepare browser environment: {env_exc}\n")
        sys.stderr.flush()
        sys.exit(76)

    # 4. Drop privileges and exec browser
    setpriv_bin = shutil.which("setpriv")
    if setpriv_bin:
        exec_args = [setpriv_bin, f"--reuid={target_uid}", f"--regid={target_gid}", "--init-groups", *cmd]
        try:
            os.execvp(setpriv_bin, exec_args)
        except OSError as e:
            sys.stderr.write(f"Failed to exec setpriv: {e}\n")
            sys.stderr.flush()
            sys.exit(73)
    else:
        try:
            ident = identity.resolve_user_by_uid(target_uid)
            os.initgroups(ident.username, target_gid)
        except identity.IdentityResolutionError as e:
            sys.stderr.write(f"Failed to resolve target UID {target_uid} for browser: {e}\n")
            sys.stderr.flush()
            raise PrivilegedHelperError(f"Failed to resolve target UID {target_uid} for browser: {e}") from e
        except OSError as e:
            sys.stderr.write(f"Failed to initialize groups for {ident.username} (GID {target_gid}): {e}\n")
            sys.stderr.flush()
            raise PrivilegedHelperError(f"Failed to initialize groups for {ident.username}: {e}") from e
        try:
            os.setgid(target_gid)
            os.setuid(target_uid)
        except OSError as e:
            sys.stderr.write(f"Failed to drop privileges to {target_uid}:{target_gid}: {e}\n")
            sys.stderr.flush()
            sys.exit(74)

        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            sys.stderr.write(f"Failed to exec {cmd[0]}: {e}\n")
            sys.stderr.flush()
            sys.exit(75)


# ==============================================================================
# Sudo & Authorization Checks
# ==============================================================================

def check_sudo_authorization() -> Dict[str, Any]:
    """
    Verifies non-interactive root authorization via sudo -n.
    Returns: {"authorized": bool, "method": str, "message": str, "error": Optional[str]}
    """
    if os.geteuid() == 0:
        return {
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
                "authorized": True,
                "method": "sudo -n",
                "message": "Non-interactive sudo authorization verified."
            }
        else:
            err = (proc.stderr or proc.stdout).strip() or "Password required"
            return {
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
            "authorized": False,
            "method": "sudo -n",
            "error": "sudo binary not found",
            "message": "The sudo utility is not available in PATH."
        }


def is_sudo_available() -> bool:
    """Convenience boolean check for sudo -n availability."""
    return check_sudo_authorization()["authorized"]


# ==============================================================================
# Lock Coordination & Deadlock Prevention
# ==============================================================================

def verify_caller_holds_lock(lock_path: Path) -> None:
    """
    Verifies that the caller process actively holds an exclusive flock on lock_path.
    Fails closed if the lock is not held: NEVER silently bypasses locks.
    """
    target = Path(lock_path).resolve()
    if not target.exists():
        raise concurrency.LabLockError(
            f"Lock verification failed: lock file {target} does not exist. Refusing to bypass active lock."
        )

    try:
        fd = os.open(
            str(target),
            os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        )
    except PermissionError:
        fd = os.open(
            str(target),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        )

    try:
        # Non-blocking exclusive lock probe:
        # If flock SUCCEEDS, the lock was NOT held by any process!
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Immediately release our probe lock and fail closed
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        raise concurrency.LabLockError(
            f"Lock verification failed: caller claimed to hold lock on {target}, "
            "but lock was not held by any process. Refusing to silently bypass lock."
        )
    except (BlockingIOError, OSError) as exc:
        if isinstance(exc, concurrency.LabLockError):
            raise
        # EWOULDBLOCK / EAGAIN indicates lock IS held by caller (or another process).
        # Lock presence confirmed. Close probe fd cleanly.
        os.close(fd)


@contextlib.contextmanager
def coordinate_lock(
    caller_holds_lock: bool,
    lock_path: Optional[Path] = None,
    timeout: float = 5.0,
    lock_file: Optional[Path] = None
):
    """
    Coordinates lock acquisition or verification:
    - If caller_holds_lock is True: verifies lock is actively held without re-locking (prevents deadlock).
    - If caller_holds_lock is False: acquires exclusive flock via concurrency.acquire_lab_lock.
    """
    target = Path(lock_path or lock_file or LAB_LOCK_FILE).resolve()
    if caller_holds_lock:
        verify_caller_holds_lock(target)
        yield
    else:
        with concurrency.acquire_lab_lock(timeout=timeout, lock_path=target):
            yield


# ==============================================================================
# Privileged Scenario Management (S0 - S6)
# ==============================================================================

def apply_scenario_privileged(
    scenario_id: str,
    scenarios_path: Path = DEFAULT_SCENARIOS_PATH,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Applies scenario S0-S6 network impairments with root privileges:
    1. Validates scenario ID against canonical list.
    2. Coordinates lab lock.
    3. Clears existing impairments and resets to baseline.
    4. Applies tc netem delays on project interfaces.
    5. Applies strictly validated nftables rules in ps028-rt.
    6. Applies DNS delays if scenario requires (e.g. S6: A=0ms, AAAA=500ms).
    7. Saves scenario state.
    """
    sc_clean = scenario_id.upper()
    if sc_clean not in ALLOWED_SCENARIOS:
        raise PrivilegedHelperError(f"Scenario '{scenario_id}' invalid. Must be one of: {ALLOWED_SCENARIOS}")

    scenarios_path = validate_operation_path(scenarios_path, FileOperationType.CONFIG_FILE, "scenarios_path", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        data = impair.load_scenarios_config(scenarios_path)
        scenario = data["scenarios"][sc_clean]

        # Reset baseline first
        restore_baseline_privileged(
            scenarios_path=scenarios_path,
            caller_holds_lock=True,
            lock_file=lock_file,
            lock_timeout=lock_timeout,
            is_test_fixture=is_test_fixture
        )

        try:
            # 1. Apply netem delays
            delays = scenario.get("network", {}).get("delays", impair.BASELINE_DELAYS)
            impair.apply_netem_delays(delays, dry_run=False)

            # 2. Apply nftables rules
            nft_rules = scenario.get("nftables", [])
            if nft_rules:
                impair.apply_nftables_rules(nft_rules, dry_run=False, scenario_id=sc_clean)

            # 3. Apply DNS delays if required (e.g. S6)
            dns_cfg = scenario.get("dns", {})
            a_delay = int(dns_cfg.get("A_delay_ms", 0))
            aaaa_delay = int(dns_cfg.get("AAAA_delay_ms", 0))
            if a_delay > 0 or aaaa_delay > 0:
                impair.apply_dns_delays(
                    a_delay_ms=a_delay,
                    aaaa_delay_ms=aaaa_delay,
                    dry_run=False
                )
                # Verify DNS delays
                cfg = impair.load_dns_config()
                act_a = cfg.get("rules", {}).get("A", {}).get("delay_ms")
                act_aaaa = cfg.get("rules", {}).get("AAAA", {}).get("delay_ms")
                if act_a != a_delay or act_aaaa != aaaa_delay:
                    raise PrivilegedHelperError(
                        f"DNS delay verification failed: expected A={a_delay}ms, AAAA={aaaa_delay}ms, got A={act_a}ms, AAAA={act_aaaa}ms"
                    )

            impair.save_state(sc_clean, {"name": scenario["name"], "type": scenario["type"]}, dry_run=False)
            res = {
                "status": "OK",
                "scenario_id": sc_clean,
                "name": scenario["name"],
                "delays": delays,
                "nftables_rules_applied": len(nft_rules)
            }
            if a_delay > 0 or aaaa_delay > 0:
                res["dns_delays"] = {"A_delay_ms": a_delay, "AAAA_delay_ms": aaaa_delay}
            return res
        except Exception as exc:
            # Rollback to baseline on any failure
            try:
                restore_baseline_privileged(caller_holds_lock=True, lock_file=lock_file)
            except Exception:
                pass
            raise PrivilegedHelperError(f"Failed to apply scenario {sc_clean}: {exc}")


def restore_baseline_privileged(
    scenarios_path: Path = DEFAULT_SCENARIOS_PATH,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Restores network baseline with root privileges:
    1. Coordinates lab lock.
    2. Deletes nftables table ps028_impair in ps028-rt.
    3. Restores 10ms netem delay on all 4 interfaces.
    4. Restores DNS baseline (0ms A and AAAA) and unlinks backup.
    5. Clears impairment state file.
    """
    scenarios_path = validate_operation_path(scenarios_path, FileOperationType.CONFIG_FILE, "scenarios_path", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        errors: List[str] = []

        try:
            impair.clear_nftables_rules(dry_run=False)
        except Exception as exc:
            errors.append(f"clear_nftables_rules: {exc}")

        try:
            impair.restore_baseline_delays(dry_run=False)
        except Exception as exc:
            errors.append(f"restore_baseline_delays: {exc}")

        try:
            impair.restore_dns_baseline(dry_run=False)
            cfg = impair.load_dns_config()
            act_a = cfg.get("rules", {}).get("A", {}).get("delay_ms")
            act_aaaa = cfg.get("rules", {}).get("AAAA", {}).get("delay_ms")
            if act_a != 0 or act_aaaa != 0:
                errors.append(f"restore_dns_baseline: DNS delays not restored (A={act_a}ms, AAAA={act_aaaa}ms)")
            if impair.DNS_BACKUP_A4.exists():
                errors.append("restore_dns_baseline: DNS impairment backup still exists")
        except Exception as exc:
            errors.append(f"restore_dns_baseline: {exc}")

        try:
            impair.clear_state(dry_run=False)
        except Exception as exc:
            errors.append(f"clear_state: {exc}")

        if errors:
            raise PrivilegedHelperError("; ".join(errors))

        return {
            "status": "OK",
            "message": "Baseline network impairments and DNS cleared and 10ms delays restored."
        }


def apply_dns_delays_privileged(
    a_delay_ms: int = 0,
    aaaa_delay_ms: int = 0,
    config_file: Optional[Path] = None,
    backup_file_a3: Optional[Path] = None,
    backup_file_a4: Optional[Path] = None,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Applies DNS delays (rules.A and rules.AAAA) with root privileges.
    Guarantees baseline backup, atomic updates, SIGHUP reload, and verification.
    Never reports success if application or verification fails.
    """
    if not isinstance(a_delay_ms, int) or isinstance(a_delay_ms, bool) or not (0 <= a_delay_ms <= 2000):
        raise PrivilegedHelperError(f"Invalid a_delay_ms {a_delay_ms}: must be integer between 0 and 2000")
    if not isinstance(aaaa_delay_ms, int) or isinstance(aaaa_delay_ms, bool) or not (0 <= aaaa_delay_ms <= 2000):
        raise PrivilegedHelperError(f"Invalid aaaa_delay_ms {aaaa_delay_ms}: must be integer between 0 and 2000")

    if config_file:
        config_file = validate_operation_path(config_file, FileOperationType.CONFIG_FILE, "config_file", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if backup_file_a3:
        backup_file_a3 = validate_operation_path(backup_file_a3, FileOperationType.BACKUP_FILE, "backup_file_a3", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if backup_file_a4:
        backup_file_a4 = validate_operation_path(backup_file_a4, FileOperationType.BACKUP_FILE, "backup_file_a4", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        try:
            impair.apply_dns_delays(
                a_delay_ms=a_delay_ms,
                aaaa_delay_ms=aaaa_delay_ms,
                dry_run=False,
                config_file=config_file,
                backup_file_a3=backup_file_a3,
                backup_file_a4=backup_file_a4
            )
            # Verify delays applied
            cfg_p = config_file or impair.DNS_CONFIG_FILE
            cfg = impair.load_dns_config(path=cfg_p)
            act_a = cfg.get("rules", {}).get("A", {}).get("delay_ms")
            act_aaaa = cfg.get("rules", {}).get("AAAA", {}).get("delay_ms")
            if act_a != a_delay_ms or act_aaaa != aaaa_delay_ms:
                raise PrivilegedHelperError(
                    f"DNS delays not correctly applied: expected A={a_delay_ms}ms, AAAA={aaaa_delay_ms}ms, got A={act_a}ms, AAAA={act_aaaa}ms"
                )
            return {
                "status": "OK",
                "a_delay_ms": a_delay_ms,
                "aaaa_delay_ms": aaaa_delay_ms
            }
        except Exception as exc:
            raise PrivilegedHelperError(f"apply_dns_delays failed: {exc}")


def restore_dns_privileged(
    config_file: Optional[Path] = None,
    backup_file_a4: Optional[Path] = None,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Restores clean DNS baseline (0ms delays and reloads DNS server) with root privileges.
    Never reports success if restoration fails or is unverified.
    """
    if config_file:
        config_file = validate_operation_path(config_file, FileOperationType.CONFIG_FILE, "config_file", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if backup_file_a4:
        backup_file_a4 = validate_operation_path(backup_file_a4, FileOperationType.BACKUP_FILE, "backup_file_a4", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        try:
            impair.restore_dns_baseline(
                dry_run=False,
                config_file=config_file,
                backup_file_a4=backup_file_a4
            )
            # Verification: never report success unless verified
            cfg_p = config_file or impair.DNS_CONFIG_FILE
            if not cfg_p.is_file():
                raise PrivilegedHelperError(f"DNS config file {cfg_p} does not exist after restore")
            cfg = impair.load_dns_config(path=cfg_p)
            act_a = cfg.get("rules", {}).get("A", {}).get("delay_ms")
            act_aaaa = cfg.get("rules", {}).get("AAAA", {}).get("delay_ms")
            if act_a != 0 or act_aaaa != 0:
                raise PrivilegedHelperError(
                    f"DNS baseline not restored: delays are A={act_a}ms, AAAA={act_aaaa}ms (expected 0ms)"
                )
            bak = backup_file_a4 or impair.DNS_BACKUP_A4
            if bak.exists():
                raise PrivilegedHelperError(f"DNS impairment backup {bak} still exists after restore")
            return {
                "status": "OK",
                "message": "DNS baseline restored and verified (0ms delays for A and AAAA)."
            }
        except Exception as exc:
            raise PrivilegedHelperError(f"restore_dns_baseline failed: {exc}")


# ==============================================================================
# Privileged Baseline Live Verification
# ==============================================================================

def verify_baseline_privileged(
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Executes full live baseline verification requiring root privileges:
    1. Coordinates lab lock.
    2. Verifies state file is clean.
    3. Verifies DNS config file has 0ms delays.
    4. Verifies no leftover DNS backups.
    5. Verifies absence of ps028_impair nftables table in ps028-rt.
    6. Verifies 10ms netem delay on all 4 server interfaces.
    7. Verifies live ping connectivity from ps028-cl to IPv4 (10.0.2.10) and IPv6 (2001:db8:2::10).
    8. Verifies live DNS resolution from ps028-cl for A and AAAA records.
    Never reports success if any check fails.
    """
    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        errors: List[str] = []
        checks: Dict[str, Any] = {}

        # 1. State file check
        st = impair.get_current_state()
        if st is not None:
            err = f"Active scenario state found: {st.get('active_scenario')}"
            errors.append(err)
            checks["state_file"] = {"valid": False, "error": err}
        else:
            checks["state_file"] = {"valid": True}

        # 2. DNS config check
        try:
            cfg = impair.load_dns_config()
            a_d = cfg["rules"]["A"]["delay_ms"]
            aaaa_d = cfg["rules"]["AAAA"]["delay_ms"]
            if a_d == 0 and aaaa_d == 0:
                checks["dns_config"] = {"valid": True, "A_delay_ms": a_d, "AAAA_delay_ms": aaaa_d}
            else:
                err = f"Non-zero DNS delays: A={a_d}ms, AAAA={aaaa_d}ms"
                errors.append(err)
                checks["dns_config"] = {"valid": False, "error": err}
        except Exception as exc:
            errors.append(f"DNS config unreadable: {exc}")
            checks["dns_config"] = {"valid": False, "error": str(exc)}

        # 3. DNS backups check
        if impair.DNS_BACKUP_A4.exists():
            err = f"Leftover impairment backup exists: {impair.DNS_BACKUP_A4.name}"
            errors.append(err)
            checks["dns_backups"] = {"valid": False, "error": err}
        else:
            checks["dns_backups"] = {"valid": True}

        # 4. nftables absence check in router netns
        rc, stdout, stderr = impair.execute_netns_cmd(
            impair.NFT_NAMESPACE,
            ["nft", "list", "table", impair.NFT_FAMILY, impair.NFT_TABLE_NAME],
            check=False
        )
        if rc == 0:
            err = f"Impairment table {impair.NFT_TABLE_NAME} still exists in {impair.NFT_NAMESPACE}"
            errors.append(err)
            checks["nftables"] = {"valid": False, "error": err}
        else:
            checks["nftables"] = {"valid": True}

        # 5. tc qdiscs on all 4 interfaces
        tc_valid = True
        tc_details = {}
        for iface, netns in impair.INTERFACE_MAPPING.items():
            rc, stdout, _ = impair.execute_netns_cmd(
                netns,
                ["tc", "qdisc", "show", "dev", iface],
                check=False
            )
            is_10ms = rc == 0 and "netem" in stdout and ("delay 10ms" in stdout or "delay 10.0ms" in stdout)
            tc_details[f"{netns}/{iface}"] = {"valid": is_10ms, "output": stdout.strip()}
            if not is_10ms:
                tc_valid = False
                err = f"Interface {netns}/{iface} tc qdisc mismatch: {stdout.strip()}"
                errors.append(err)
        checks["tc_qdisc"] = {"valid": tc_valid, "interfaces": tc_details}

        # 6. Live ping connectivity from ps028-cl
        ping_valid = True
        ping_details = {}
        for proto, target in [("IPv4", impair.BASELINE_A_ADDR), ("IPv6", impair.BASELINE_AAAA_ADDR)]:
            ping_cmd = ["ping"] + (["-6"] if proto == "IPv6" else []) + ["-c", "3", "-W", "2", target]
            rc, stdout, _ = impair.execute_netns_cmd(CLIENT_NETNS, ping_cmd, check=False)
            if rc != 0:
                ping_valid = False
                err = f"{proto} ping to {target} failed in {CLIENT_NETNS}"
                errors.append(err)
                ping_details[proto] = {"valid": False, "target": target}
            else:
                m = re.search(r"(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)", stdout)
                avg_rtt = m.group(2) if m else "unknown"
                ping_details[proto] = {"valid": True, "target": target, "mean_rtt_ms": avg_rtt}
        checks["ping"] = {"valid": ping_valid, "results": ping_details}

        # 7. Live DNS query verification from ps028-cl
        dns_valid = True
        dns_details = {}
        for qtype, expected in [("A", impair.BASELINE_A_ADDR), ("AAAA", impair.BASELINE_AAAA_ADDR)]:
            dig_cmd = ["dig", f"@{impair.DNS_SERVER_IP}", "-p", "53", "he.test", qtype, "+time=1", "+tries=1", "+short"]
            rc, stdout, _ = impair.execute_netns_cmd(CLIENT_NETNS, dig_cmd, check=False)
            ans = stdout.strip()
            if rc == 0 and ans == expected:
                dns_details[qtype] = {"valid": True, "answer": ans}
            else:
                dns_valid = False
                err = f"DNS {qtype} expected '{expected}', got '{ans}' (rc={rc})"
                errors.append(err)
                dns_details[qtype] = {"valid": False, "answer": ans, "expected": expected}
        checks["dns_queries"] = {"valid": dns_valid, "results": dns_details}

        all_passed = (len(errors) == 0)
        return {
            "all_passed": all_passed,
            "checks": checks,
            "errors": errors
        }


# ==============================================================================
# Privileged Packet Capture Management (tcpdump)
# ==============================================================================

def _reap_capture_on_startup_failure(
    parent_proc: Optional[Any],
    tcpdump_pid: Optional[int] = None,
    log_fp: Optional[Any] = None,
    pid_file: Optional[Path] = None,
    pcap_file: Optional[Path] = None
) -> None:
    """
    Terminates and reaps any capture processes launched when startup fails.
    Prevents orphaned tcpdump processes and unlinks stale PID file and partial capture file.
    """
    if log_fp and not getattr(log_fp, "closed", True):
        try:
            log_fp.close()
        except Exception:
            pass

    if pid_file:
        try:
            Path(pid_file).unlink(missing_ok=True)
        except Exception:
            pass

    if pcap_file:
        try:
            Path(pcap_file).unlink(missing_ok=True)
        except Exception:
            pass

    if parent_proc is None:
        return

    pids = set()
    pid_val = getattr(parent_proc, "pid", None)
    if isinstance(pid_val, int) and pid_val > 0:
        pids.add(pid_val)
        try:
            c_pid = run_trial.find_tcpdump_pid(pid_val)
            if c_pid and c_pid > 0:
                pids.add(c_pid)
        except Exception:
            pass
    if isinstance(tcpdump_pid, int) and tcpdump_pid > 0:
        pids.add(tcpdump_pid)

    for p in pids:
        if run_trial._is_pid_alive(p):
            try:
                os.kill(p, signal.SIGTERM)
            except OSError:
                pass

    t0 = time.time()
    while time.time() - t0 < 0.5:
        if not any(run_trial._is_pid_alive(p) for p in pids):
            break
        time.sleep(0.05)

    for p in pids:
        if run_trial._is_pid_alive(p):
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass

    try:
        if hasattr(parent_proc, "wait"):
            parent_proc.wait(timeout=1.0)
    except Exception:
        try:
            if hasattr(parent_proc, "poll"):
                parent_proc.poll()
        except Exception:
            pass


def _resolve_and_validate_capture_owner(
    owner_user: Optional[str] = None,
    owner_group: Optional[Union[str, int]] = None
) -> Tuple[str, int]:
    """
    Derives the invoking unprivileged identity via identity.resolve_invoking_identity()
    and strictly validates that any supplied owner_user and owner_group match or are
    authorized for that invoking identity.

    Returns:
        Tuple[str, int]: (validated_username, validated_gid)

    Raises:
        PrivilegedHelperError: If resolution fails, or if supplied owner_user or owner_group is unauthorized.
    """
    try:
        invoking_ident = identity.resolve_invoking_identity()
    except identity.IdentityResolutionError as exc:
        raise PrivilegedHelperError(
            f"Cannot determine unprivileged capture owner: {exc}"
        ) from exc

    if invoking_ident.uid == 0 or invoking_ident.username == "root":
        raise PrivilegedHelperError("Security error: capture owner must be an unprivileged user, not root")

    if owner_user is not None and owner_user != invoking_ident.username:
        raise PrivilegedHelperError(
            f"Supplied owner_user '{owner_user}' does not match invoking identity '{invoking_ident.username}'"
        )

    target_user = invoking_ident.username

    if owner_group is not None:
        try:
            import grp
            if isinstance(owner_group, int) or (isinstance(owner_group, str) and str(owner_group).isdigit()):
                target_gid = int(owner_group)
                grp.getgrgid(target_gid)
            else:
                target_gid = grp.getgrnam(str(owner_group)).gr_gid
        except (KeyError, OverflowError, OSError) as exc:
            raise PrivilegedHelperError(
                f"Supplied owner_group '{owner_group}' cannot be resolved: {exc}"
            ) from exc

        if target_gid == 0 or str(owner_group) in ("0", "root", "wheel", "sudo"):
            raise PrivilegedHelperError(
                f"Security error: owner_group '{owner_group}' (GID 0/privileged) is unauthorized"
            )

        try:
            permitted_gids = set(os.getgrouplist(target_user, invoking_ident.gid))
        except (KeyError, OverflowError, OSError) as exc:
            raise PrivilegedHelperError(
                f"Failed to resolve group membership for invoking identity '{target_user}': {exc}"
            ) from exc
        if target_gid not in permitted_gids:
            raise PrivilegedHelperError(
                f"Supplied owner_group '{owner_group}' (GID {target_gid}) is not authorized for "
                f"invoking identity '{target_user}'"
            )
    else:
        target_gid = invoking_ident.gid
        if target_gid == 0:
            raise PrivilegedHelperError("Security error: primary GID for capture owner cannot be GID 0")

    return target_user, target_gid


def start_capture_privileged(
    output_pcap: Path,
    log_file: Path,
    netns: str = CLIENT_NETNS,
    interface: str = CLIENT_CAPTURE_INTERFACE,
    bpf_filter: str = DEFAULT_BPF_FILTER,
    buffer_size_kb: int = DEFAULT_CAPTURE_BUFFER_KB,
    owner_user: Optional[str] = None,
    owner_group: Optional[str] = None,
    readiness_timeout: float = 3.0,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Starts tcpdump inside the target network namespace with root privileges:
    - Sets immediate mode and unbuffered write for fast flush.
    - Sets operating system capture buffer size via -B (buffer_size_kb).
    - Drops capture write privileges to owner_user (via -Z).
    - Writes PCAP data directly to a pre-opened, validated file descriptor passed as stdout (-w -).
    - Verifies readiness ('listening on') within readiness_timeout.
    - Writes PID file and returns JSON-serializable capture handle.
    - Cleans up and reaps spawned process on any startup failure.
    """
    if netns not in ALLOWED_NETNS:
        raise PrivilegedHelperError(f"Unauthorized netns '{netns}'. Allowed: {sorted(ALLOWED_NETNS)}")

    output_pcap = validate_operation_path(output_pcap, FileOperationType.PCAP_FILE, "output_pcap", allow_symlinks=False, is_test_fixture=is_test_fixture)
    log_file = validate_operation_path(log_file, FileOperationType.LOG_FILE, "log_file", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        output_pcap = Path(output_pcap).resolve()
        log_file = Path(log_file).resolve()
        output_pcap.parent.mkdir(parents=True, exist_ok=True)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "ip", "netns", "exec", netns,
            "tcpdump",
            "-i", interface,
            "-n",
            "--immediate-mode",
            "-U",
        ]
        if buffer_size_kb and buffer_size_kb > 0:
            cmd.extend(["-B", str(buffer_size_kb)])
        target_user, target_gid = _resolve_and_validate_capture_owner(owner_user, owner_group)
        cmd.extend(["-Z", target_user])

        # Pass -w - to write to stdout (pre-opened, validated file descriptor)
        cmd.extend([
            "-w", "-",
            bpf_filter
        ])

        target_uid = None
        if target_user:
            try:
                import pwd
                target_uid = pwd.getpwnam(target_user).pw_uid
            except Exception:
                pass

        pcap_name = output_pcap.name
        if "/" in pcap_name or "\\" in pcap_name or pcap_name in (".", "..") or "\0" in pcap_name:
            raise PrivilegedHelperError(f"Security error: invalid capture filename '{pcap_name}'")
        pcap_dir = output_pcap.parent
        pcap_dir.mkdir(parents=True, exist_ok=True)
        try:
            pcap_dir_fd = os.open(str(pcap_dir), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        except OSError as err:
            raise PrivilegedHelperError(f"Security error: cannot safely open capture output parent directory '{pcap_dir}': {err}")
        pcap_created_fd = -1
        pcap_fp = None
        log_fp = None
        try:
            try:
                verify_trusted_parent_directory(pcap_dir_fd, pcap_dir, param_name="output_pcap", expected_uid=target_uid, expected_gid=target_gid, is_test_fixture=is_test_fixture)
                try:
                    pcap_st = os.stat(pcap_name, dir_fd=pcap_dir_fd, follow_symlinks=False)
                    if stat.S_ISLNK(pcap_st.st_mode):
                        raise PrivilegedHelperError(f"Security error: capture output '{output_pcap}' is a symlink")
                    if not stat.S_ISREG(pcap_st.st_mode):
                        raise PrivilegedHelperError(f"Security error: capture output '{output_pcap}' is not a regular file")
                    if pcap_st.st_nlink > 1:
                        raise PrivilegedHelperError(f"Security error: capture output '{output_pcap}' has multiple hardlinks (st_nlink={pcap_st.st_nlink})")
                    raise PrivilegedHelperError(f"Security error: capture output '{output_pcap}' already exists (refusing to overwrite existing file to prevent inode truncation attacks)")
                except FileNotFoundError:
                    pass

                pcap_crea_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                pcap_created_fd = os.open(pcap_name, pcap_crea_flags, 0o644, dir_fd=pcap_dir_fd)
                pcap_created_st = os.fstat(pcap_created_fd)
                if not stat.S_ISREG(pcap_created_st.st_mode):
                    raise PrivilegedHelperError(f"Security error: newly created capture output '{output_pcap}' is not a regular file")
                if pcap_created_st.st_nlink != 1:
                    raise PrivilegedHelperError(f"Security error: newly created capture output '{output_pcap}' has unexpected link count {pcap_created_st.st_nlink}")

                if os.geteuid() == 0 and target_uid is not None:
                    try:
                        os.fchown(pcap_created_fd, target_uid, target_gid if target_gid is not None else -1)
                    except OSError:
                        pass

                pcap_fp = open(pcap_created_fd, "wb", closefd=True)
                pcap_created_fd = -1
            finally:
                if pcap_created_fd >= 0:
                    try:
                        os.close(pcap_created_fd)
                    except OSError:
                        pass
                os.close(pcap_dir_fd)

            pid_file = output_pcap.with_suffix(".pid")
            validate_operation_path(pid_file, FileOperationType.PID_FILE, "pid_file", allow_symlinks=False, is_test_fixture=is_test_fixture)
            proc = None
            log_name = log_file.name
            if "/" in log_name or "\\" in log_name or log_name in (".", "..") or "\0" in log_name:
                raise PrivilegedHelperError(f"Security error: invalid log filename '{log_name}'")
            log_dir = log_file.parent
            log_dir.mkdir(parents=True, exist_ok=True)
            try:
                log_dir_fd = os.open(str(log_dir), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            except OSError as err:
                raise PrivilegedHelperError(f"Security error: cannot safely open log file parent directory '{log_dir}': {err}")
            tmp_log_name = None
            log_fd = -1
            try:
                verify_trusted_parent_directory(log_dir_fd, log_dir, param_name="log_file", expected_uid=target_uid, expected_gid=target_gid, is_test_fixture=is_test_fixture)

                try:
                    log_st_check = os.stat(log_name, dir_fd=log_dir_fd, follow_symlinks=False)
                    if stat.S_ISLNK(log_st_check.st_mode):
                        raise PrivilegedHelperError(f"Security error: log file '{log_file}' is a symlink")
                    if not stat.S_ISREG(log_st_check.st_mode):
                        raise PrivilegedHelperError(f"Security error: log file '{log_file}' is not a regular file")
                    if log_st_check.st_nlink > 1:
                        raise PrivilegedHelperError(f"Security error: log file '{log_file}' has multiple hardlinks (st_nlink={log_st_check.st_nlink})")
                except FileNotFoundError:
                    pass

                tmp_log_name = f".tmp_log_{log_name}_{secrets.token_hex(8)}"
                excl_flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0)
                )
                log_fd = os.open(tmp_log_name, excl_flags, 0o644, dir_fd=log_dir_fd)
                log_st = os.fstat(log_fd)
                if not stat.S_ISREG(log_st.st_mode):
                    raise PrivilegedHelperError(f"Security error: staging log file '{tmp_log_name}' is not a regular file")
                if log_st.st_nlink != 1:
                    raise PrivilegedHelperError(f"Security error: staging log file '{tmp_log_name}' has unexpected link count {log_st.st_nlink}")

                if os.geteuid() == 0 and target_uid is not None:
                    try:
                        os.fchown(log_fd, target_uid, target_gid if target_gid is not None else -1)
                    except OSError:
                        pass

                _safe_renameat(
                    log_dir_fd,
                    tmp_log_name,
                    log_dir_fd,
                    log_name,
                    fallback_old_path=log_dir / tmp_log_name,
                    fallback_new_path=log_file
                )
                tmp_log_name = None

                log_fp = open(log_fd, "w+", encoding="utf-8", closefd=True)
                log_fd = -1
            finally:
                if tmp_log_name is not None:
                    try:
                        os.unlink(tmp_log_name, dir_fd=log_dir_fd)
                    except OSError:
                        pass
                if log_fd >= 0:
                    try:
                        os.close(log_fd)
                    except OSError:
                        pass
                os.close(log_dir_fd)

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=pcap_fp,
                    stderr=log_fp,
                    start_new_session=True
                )
            except Exception as exc:
                raise PrivilegedHelperError(f"Failed to spawn tcpdump: {exc}")
        finally:
            # Parent immediately closes its copies of the descriptors after child spawn or on any failure
            if pcap_fp:
                try:
                    pcap_fp.close()
                except OSError:
                    pass
            if log_fp:
                try:
                    log_fp.close()
                except OSError:
                    pass

        try:
            # Poll for readiness
            t0 = time.time()
            ready = False
            while time.time() - t0 < readiness_timeout:
                if proc.poll() is not None:
                    raise PrivilegedHelperError(f"tcpdump terminated prematurely with code {proc.returncode}. Check {log_file}.")
                if log_file.is_file():
                    try:
                        content = log_file.read_text(encoding="utf-8", errors="replace")
                        if "listening on" in content:
                            ready = True
                            break
                    except Exception:
                        pass
                time.sleep(0.05)

            if not ready:
                if proc.poll() is not None:
                    raise PrivilegedHelperError(f"tcpdump exited before readiness (code {proc.returncode}).")
                # Kill unready process cleanly
                try:
                    run_trial.stop_packet_capture(proc, timeout=1.0)
                except Exception:
                    try:
                        os.kill(proc.pid, signal.SIGKILL)
                    except OSError:
                        pass
                raise PrivilegedHelperError(
                    f"tcpdump capture startup timed out waiting for readiness ('listening on' not observed within {readiness_timeout}s)."
                )

            # Locate child tcpdump PID if ip spawned it
            tcpdump_pid = run_trial.find_tcpdump_pid(proc.pid)

            # Save PID file safely for tracking
            safe_write_pid_file(pid_file, f"{proc.pid}:{tcpdump_pid}\n", owner_user=target_user, owner_group=target_gid, is_test_fixture=is_test_fixture)

            # Set file ownership if requested or running as root
            if target_user:
                _chown_file(log_file, target_user, target_gid)

            # Close open log file handle in parent process
            try:
                log_fp.close()
            except Exception:
                pass

            handle = {
                "status": "OK",
                "parent_pid": proc.pid,
                "tcpdump_pid": tcpdump_pid,
                "pcap_path": str(output_pcap),
                "log_path": str(log_file),
                "netns": netns,
                "interface": interface,
                "filter": bpf_filter,
                "buffer_size_kb": buffer_size_kb,
                "start_time": time.time(),
            }
            # Verify JSON serializability: MUST NEVER serialize Popen
            json.dumps(handle)
            return handle

        except Exception as exc:
            _reap_capture_on_startup_failure(
                parent_proc=proc,
                log_fp=log_fp,
                pid_file=pid_file,
                pcap_file=output_pcap
            )
            if isinstance(exc, PrivilegedHelperError):
                raise
            raise PrivilegedHelperError(f"Capture startup failed: {exc}")


def _is_alive_proc(p: int, proc_dir: Optional[Path] = None) -> bool:
    """Safely invokes run_trial._is_pid_alive respecting mock signatures."""
    if proc_dir is not None:
        try:
            return run_trial._is_pid_alive(p, proc_dir=proc_dir)
        except TypeError:
            return run_trial._is_pid_alive(p)
    return run_trial._is_pid_alive(p)


def stop_capture_privileged(
    pid: int,
    pcap_path: Optional[Path] = None,
    timeout: float = 5.0,
    owner_user: Optional[str] = None,
    owner_group: Optional[str] = None,
    verify_pcap: bool = True,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    proc_dir: Optional[Path] = None,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Gracefully stops the capture process with root privileges:
    1. Verifies PID belongs to tcpdump before signaling (never signals unrelated processes).
    2. Verifies PID against recorded .pid file if available.
    3. Rejects unrelated or recycled PIDs.
    4. Sends SIGINT gracefully to allow buffer flushing and PCAP trailer finalization.
    5. Escalates to SIGTERM, then SIGKILL only if graceful shutdown times out.
    6. Confirms process has completely exited.
    7. Sets file permissions and ownership so normal user can read/write.
    8. Confirms PCAP validity if verify_pcap is True.
    """
    if not isinstance(pid, int) or pid <= 0:
        raise PrivilegedHelperError(f"Invalid capture PID: {pid}")

    if pcap_path:
        pcap_path = validate_operation_path(pcap_path, FileOperationType.PCAP_FILE, "pcap_path", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        pcap_file = Path(pcap_path).resolve() if pcap_path else None
        pid_file = pcap_file.with_suffix(".pid") if pcap_file else None

        # Verify against recorded PID file if present
        recorded_parent_pid = None
        recorded_tcpdump_pid = None
        if pid_file and pid_file.is_file():
            try:
                content = pid_file.read_text(encoding="utf-8").strip()
                parts = content.split(":")
                if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                    recorded_parent_pid = int(parts[0])
                    recorded_tcpdump_pid = int(parts[1])
            except Exception:
                pass

        if recorded_parent_pid is not None:
            if pid not in (recorded_parent_pid, recorded_tcpdump_pid):
                raise run_trial.CaptureShutdownError(
                    f"PID {pid} does not match recorded capture PIDs ({recorded_parent_pid}, {recorded_tcpdump_pid}) for {pcap_file}"
                )

        tcpdump_pid = recorded_tcpdump_pid or run_trial.find_tcpdump_pid(pid)

        # Verify target PID before signaling
        target_pids = [p for p in (tcpdump_pid, pid) if isinstance(p, int) and p > 0]
        target_pids = list(dict.fromkeys(target_pids))
        for p in target_pids:
            if _is_alive_proc(p, proc_dir):
                if not run_trial.is_safe_capture_process(
                    p,
                    is_parent=(p == pid),
                    proc_dir=proc_dir,
                    expected_pcap=pcap_file
                ):
                    raise run_trial.CaptureShutdownError(
                        f"Refusing to signal PID {p}: belongs to unverified or unrelated process"
                    )

        # Step 1: Send SIGINT gracefully (only to alive processes)
        for p in target_pids:
            if _is_alive_proc(p, proc_dir):
                try:
                    os.kill(p, signal.SIGINT)
                except (ProcessLookupError, OSError):
                    pass

        # Step 2: Wait for process to exit and reap
        t0 = time.time()
        exited = False
        while time.time() - t0 < timeout:
            for p in target_pids:
                try:
                    wpid, _ = os.waitpid(p, os.WNOHANG)
                except (ChildProcessError, OSError):
                    pass
            if not any(_is_alive_proc(p, proc_dir) for p in target_pids):
                exited = True
                break
            time.sleep(0.05)

        # Step 3: Escalate to SIGTERM if not exited
        if not exited:
            for p in target_pids:
                if _is_alive_proc(p, proc_dir):
                    if run_trial.is_safe_capture_process(
                        p,
                        is_parent=(p == pid),
                        proc_dir=proc_dir,
                        expected_pcap=pcap_file
                    ):
                        try:
                            os.kill(p, signal.SIGTERM)
                        except (ProcessLookupError, OSError):
                            pass
            t_term = time.time()
            term_timeout = min(1.5, max(0.5, timeout / 2.0))
            while time.time() - t_term < term_timeout:
                for p in target_pids:
                    try:
                        wpid, _ = os.waitpid(p, os.WNOHANG)
                    except (ChildProcessError, OSError):
                        pass
                if not any(_is_alive_proc(p, proc_dir) for p in target_pids):
                    exited = True
                    break
                time.sleep(0.05)

        # Step 4: Escalate to SIGKILL if still alive
        if not exited:
            for p in target_pids:
                if _is_alive_proc(p, proc_dir):
                    if run_trial.is_safe_capture_process(
                        p,
                        is_parent=(p == pid),
                        proc_dir=proc_dir,
                        expected_pcap=pcap_file
                    ):
                        try:
                            os.kill(p, signal.SIGKILL)
                        except (ProcessLookupError, OSError):
                            pass
            t_kill = time.time()
            kill_timeout = min(1.0, max(0.3, timeout / 4.0))
            while time.time() - t_kill < kill_timeout:
                for p in target_pids:
                    try:
                        wpid, _ = os.waitpid(p, os.WNOHANG)
                    except (ChildProcessError, OSError):
                        pass
                if not any(_is_alive_proc(p, proc_dir) for p in target_pids):
                    exited = True
                    break
                time.sleep(0.05)

            if not exited and any(_is_alive_proc(p, proc_dir) for p in target_pids):
                raise run_trial.CaptureShutdownError(f"tcpdump capture process {target_pids} failed to exit after escalation")

        # Step 5: Fix file ownership and permissions for normal user
        target_user, target_gid = _resolve_and_validate_capture_owner(owner_user, owner_group)

        if pcap_file and pcap_file.is_file():
            _chown_file(pcap_file, target_user, target_gid)
            try:
                pcap_file.chmod(0o664)
            except OSError as exc:
                raise PrivilegedHelperError(
                    f"Failed to set permissions on capture file {pcap_file}: {exc}"
                ) from exc

        # Step 6: Validate PCAP
        if verify_pcap and pcap_file:
            if not pcap_file.is_file():
                raise run_trial.CaptureShutdownError(f"Capture PCAP {pcap_file} missing after capture stop")
            is_valid, sha256_hex, size, pkt_count, msg = run_trial.validate_pcap_file(pcap_file)
            if not is_valid:
                raise run_trial.CaptureShutdownError(f"Capture PCAP {pcap_file} is invalid ({msg})")
            if pid_file and pid_file.is_file():
                try:
                    pid_file.unlink(missing_ok=True)
                except Exception:
                    pass
            return {
                "status": "OK",
                "pcap_valid": True,
                "pcap_path": str(pcap_file),
                "sha256": sha256_hex,
                "size": size,
                "packet_count": pkt_count
            }

        if pid_file and pid_file.is_file():
            try:
                pid_file.unlink(missing_ok=True)
            except Exception:
                pass

        return {"status": "OK", "stopped": True}


def _chown_file(path: Union[str, Path], user: str, group: Optional[Union[str, int]] = None) -> None:
    """Safely chowns file to validated unprivileged user/group if running as root."""
    if os.geteuid() == 0:
        p = Path(path)
        if not p.exists():
            return
        if p.is_symlink() or os.path.islink(str(p)):
            raise PrivilegedHelperError(f"Security error: refusing to chown symlink target '{path}'")

        validate_secure_path(p, "chown_target", allow_symlinks=False)

        if user in ("root", "0"):
            raise PrivilegedHelperError("Security error: refusing to chown to root UID 0")
        if group is not None and str(group) in ("0", "root", "wheel", "sudo"):
            raise PrivilegedHelperError(f"Security error: refusing to chown to privileged group '{group}' (GID 0)")

        try:
            ident = identity.resolve_user_by_name(user)
            if ident.uid == 0:
                raise PrivilegedHelperError("Security error: refusing to chown to root UID 0")
            uid = ident.uid
            if group is not None:
                if isinstance(group, int):
                    gid = group
                elif isinstance(group, str) and group.isdigit():
                    gid = int(group)
                else:
                    import grp
                    gid = grp.getgrnam(str(group)).gr_gid
                if gid == 0 or str(group) in ("0", "root", "wheel", "sudo"):
                    raise PrivilegedHelperError(f"Security error: refusing to chown to privileged group '{group}' (GID 0)")
            else:
                gid = ident.gid
                if gid == 0:
                    raise PrivilegedHelperError("Security error: refusing to chown to root GID 0")
            try:
                fd = os.open(
                    str(p),
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        raise PrivilegedHelperError(f"Security error: refusing to chown non-regular file '{path}'")
                    if st.st_nlink > 1:
                        raise PrivilegedHelperError(f"Security error: refusing to chown hardlinked file '{path}'")
                    try:
                        os.fchown(fd, uid, gid)
                    except PermissionError:
                        os.chown(str(p), uid, gid)
                finally:
                    os.close(fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.EMLINK):
                    raise PrivilegedHelperError(f"Security error: refusing to chown symlink target '{path}'")
                if isinstance(exc, PrivilegedHelperError):
                    raise
                os.chown(str(p), uid, gid)
        except identity.IdentityResolutionError as exc:
            if "UID 0" in str(exc) or "root" in str(exc):
                raise PrivilegedHelperError("Security error: refusing to chown to root UID 0") from exc
            raise PrivilegedHelperError(f"Failed to change ownership of {path} to {user}: {exc}") from exc
        except (KeyError, OSError) as exc:
            if isinstance(exc, PrivilegedHelperError):
                raise
            raise PrivilegedHelperError(
                f"Failed to change ownership of {path} to {user}: {exc}"
            ) from exc


chown_file = _chown_file

ALLOWED_S5_IFACES = {"ps028-rt-sv6", "ps028-rt-sv4"}
ALLOWED_S5_NETNS = {"ps028-cl"}


def validate_s5_params(
    port: int,
    probe_count: Optional[int] = None,
    timeout: Optional[float] = None,
    concurrency: Optional[int] = None,
    drop_pct: Optional[int] = None,
    oifname: Optional[str] = None,
    netns: Optional[str] = None,
    client_ip: Optional[str] = None,
    target_ip: Optional[str] = None,
    allow_loopback: bool = False
) -> None:
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise PrivilegedHelperError(f"Invalid port {port}: must be between 1 and 65535")
    if probe_count is not None and (not isinstance(probe_count, int) or isinstance(probe_count, bool) or not (1 <= probe_count <= 500)):
        raise PrivilegedHelperError(f"Invalid probe_count {probe_count}: must be between 1 and 500")
    if timeout is not None:
        try:
            f_timeout = float(timeout)
            if not (0.05 <= f_timeout <= 10.0):
                raise ValueError()
        except (ValueError, TypeError):
            raise PrivilegedHelperError(f"Invalid timeout {timeout}: must be between 0.05s and 10.0s")
    if concurrency is not None and (not isinstance(concurrency, int) or isinstance(concurrency, bool) or not (1 <= concurrency <= 50)):
        raise PrivilegedHelperError(f"Invalid concurrency {concurrency}: must be between 1 and 50")
    if drop_pct is not None and (not isinstance(drop_pct, int) or isinstance(drop_pct, bool) or not (1 <= drop_pct <= 99)):
        raise PrivilegedHelperError(f"Invalid drop_pct {drop_pct}: must be between 1 and 99")
    if oifname is not None and oifname not in ALLOWED_S5_IFACES:
        raise PrivilegedHelperError(f"Invalid oifname '{oifname}': not in allowlist {sorted(ALLOWED_S5_IFACES)}")
    if netns is not None and netns not in ALLOWED_S5_NETNS:
        raise PrivilegedHelperError(f"Invalid netns '{netns}': not in allowlist {sorted(ALLOWED_S5_NETNS)}")

    c_obj = None
    if client_ip is not None:
        c_obj = validate_ip_endpoint(client_ip, "client_ip", ALLOWED_PS028_CLIENT_IPS, allow_loopback=allow_loopback)

    t_obj = None
    if target_ip is not None:
        t_obj = validate_ip_endpoint(target_ip, "target_ip", ALLOWED_PS028_TARGET_IPS, allow_loopback=allow_loopback)

    if c_obj is not None and t_obj is not None:
        if c_obj.version != t_obj.version:
            raise PrivilegedHelperError(
                f"Address family mismatch: client_ip '{client_ip}' is IPv{c_obj.version} "
                f"but target_ip '{target_ip}' is IPv{t_obj.version}"
            )
        if oifname is not None:
            if c_obj.version == 6 and oifname == "ps028-rt-sv4":
                raise PrivilegedHelperError(f"Interface '{oifname}' is invalid for IPv6 traffic")
            elif c_obj.version == 4 and oifname == "ps028-rt-sv6":
                raise PrivilegedHelperError(f"Interface '{oifname}' is invalid for IPv4 traffic")


def setup_s5_counters_privileged(
    client_ip: str = "2001:db8:1::2",
    target_ip: str = "2001:db8:2::10",
    port: int = 80,
    oifname: str = "ps028-rt-sv6",
    drop_pct: int = 50,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    allow_loopback: bool = False,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Configures project-scoped nftables counters in table inet ps028_impair inside ps028-rt.
    Idempotent: flushes forward chain and initializes syn_total, syn_dropped, and syn_not_dropped.
    """
    validate_s5_params(
        port=port,
        drop_pct=drop_pct,
        oifname=oifname,
        client_ip=client_ip,
        target_ip=target_ip,
        allow_loopback=allow_loopback
    )
    c_obj = validate_ip_endpoint(client_ip, "client_ip", ALLOWED_PS028_CLIENT_IPS, allow_loopback=allow_loopback)
    t_obj = validate_ip_endpoint(target_ip, "target_ip", ALLOWED_PS028_TARGET_IPS, allow_loopback=allow_loopback)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file):
        ip_family_str = "ip6" if c_obj.version == 6 else "ip"
        common_filter = (
            f'oifname "{oifname}" {ip_family_str} saddr {str(c_obj)} {ip_family_str} daddr {str(t_obj)} '
            f'tcp dport {port} tcp flags syn / syn,ack'
        )
        nft_script = (
            f"add table {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME}\n"
            f"add chain {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {{ type filter hook forward priority 0; policy accept; }}\n"
            f"add counter {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} syn_total\n"
            f"add counter {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} syn_dropped\n"
            f"add counter {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} syn_not_dropped\n"
            f"flush chain {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward\n"
            f"add rule {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {common_filter} counter name \"syn_total\"\n"
            f"add rule {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {common_filter} numgen random mod 100 < {drop_pct} counter name \"syn_dropped\" drop\n"
            f"add rule {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {common_filter} counter name \"syn_not_dropped\"\n"
        )
        rc, stdout, stderr = impair.execute_netns_cmd(
            impair.NFT_NAMESPACE,
            ["nft", "-f", "-"],
            check=False,
            stdin_data=nft_script
        )
        if rc != 0:
            raise PrivilegedHelperError(f"Failed to setup S5 nftables counters: {stderr.strip() or stdout.strip()}")
        return {
            "status": "OK",
            "action": "setup-s5-counters",
            "netns": impair.NFT_NAMESPACE,
            "table": impair.NFT_TABLE_NAME,
            "counters": ["syn_total", "syn_dropped", "syn_not_dropped"],
            "drop_pct": drop_pct,
            "filter": common_filter
        }


def read_s5_counters_privileged(
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Reads S5 kernel packet counters from inet ps028_impair in ps028-rt.
    Queries structured JSON with regular text fallback. Fails closed if any counter is missing.
    """
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)
    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file):
        # 1. JSON query
        rc, stdout, stderr = impair.execute_netns_cmd(
            impair.NFT_NAMESPACE,
            ["nft", "-j", "list", "counters", "table", impair.NFT_FAMILY, impair.NFT_TABLE_NAME],
            check=False
        )
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                res = {}
                for item in data.get("nftables", []):
                    ctr = item.get("counter")
                    if ctr and isinstance(ctr, dict) and "name" in ctr and "packets" in ctr:
                        name = ctr["name"]
                        if name in ("syn_total", "syn_dropped", "syn_not_dropped"):
                            val = ctr["packets"]
                            if isinstance(val, int) and val >= 0:
                                res[name] = val
                if len(res) == 3:
                    res["status"] = "OK"
                    return res
            except Exception:
                pass

        # 2. Text query fallback
        rc_t, stdout_t, stderr_t = impair.execute_netns_cmd(
            impair.NFT_NAMESPACE,
            ["nft", "list", "counters", "table", impair.NFT_FAMILY, impair.NFT_TABLE_NAME],
            check=False
        )
        if rc_t == 0 and stdout_t.strip():
            res_t = {}
            for match in re.finditer(r"counter\s+(\w+)\s*(?:\{([^}]*)\}|packets\s+(\S+))", stdout_t):
                cname = match.group(1)
                body = match.group(2)
                direct = match.group(3)
                if cname in ("syn_total", "syn_dropped", "syn_not_dropped"):
                    val_str = direct
                    if val_str is None and body:
                        bmatch = re.search(r"\bpackets\s+(\S+)", body)
                        if bmatch:
                            val_str = bmatch.group(1)
                    if val_str is not None:
                        res_t[cname] = int(val_str)
            if len(res_t) == 3:
                res_t["status"] = "OK"
                return res_t

        raise PrivilegedHelperError(
            f"Failed to read S5 nftables counters in {impair.NFT_NAMESPACE} table {impair.NFT_TABLE_NAME}"
        )


def probe_single_socket(
    probe_id: int,
    target_ip: str,
    target_port: int,
    timeout: float,
    af: int
) -> Dict[str, Any]:
    """
    Executes a single TCP connection probe, pre-allocating an ephemeral port (bind to port 0)
    to capture the local 5-tuple endpoint even if connection times out or fails.
    """
    start_time = time.time()
    sock = socket.socket(af, socket.SOCK_STREAM)
    local_ip = "::" if af == socket.AF_INET6 else "0.0.0.0"
    local_port = 0
    outcome = "ERROR"
    err_no = None
    err_msg = None

    try:
        sock.bind((local_ip, 0))
        sockname = sock.getsockname()
        local_ip, local_port = sockname[0], sockname[1]

        sock.settimeout(timeout)
        sock.connect((target_ip, target_port))
        outcome = "CONNECTED"
        err_no = 0
    except (socket.timeout, TimeoutError):
        outcome = "TIMEOUT"
        err_no = errno.ETIMEDOUT
        err_msg = "Connection timed out"
    except ConnectionRefusedError as exc:
        outcome = "REFUSED"
        err_no = errno.ECONNREFUSED
        err_msg = "Connection refused"
    except OSError as exc:
        outcome = "ERROR"
        err_no = exc.errno or errno.EIO
        err_msg = str(exc)
    finally:
        end_time = time.time()
        try:
            sock.close()
        except Exception:
            pass

    duration_ms = round((end_time - start_time) * 1000.0, 3)
    return {
        "probe_id": probe_id,
        "timestamp": start_time,
        "start_time": start_time,
        "end_time": end_time,
        "duration_ms": duration_ms,
        "target_ip": target_ip,
        "target_port": target_port,
        "local_endpoint": {"ip": local_ip, "port": local_port},
        "connect_outcome": outcome,
        "outcome": outcome,
        "errno": err_no,
        "error_message": err_msg
    }


def measure_s5_privileged(
    target_ip: str = "2001:db8:2::10",
    port: int = 80,
    probe_count: int = 50,
    timeout: float = 0.4,
    concurrency: int = 10,
    netns: str = "ps028-cl",
    output_jsonl: Optional[Union[str, Path]] = None,
    owner_user: Optional[str] = None,
    owner_group: Optional[str] = None,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None,
    in_netns: bool = False,
    _skip_netns_check: bool = False,
    allow_loopback: bool = False,
    is_test_fixture: bool = False
) -> Dict[str, Any]:
    """
    Executes in-namespace S5 SYN probes and emits line-by-line JSONL records.
    Coordinates lock on host and dispatches via typed argv list into target netns.
    """
    validate_s5_params(
        port=port,
        probe_count=probe_count,
        timeout=timeout,
        concurrency=concurrency,
        netns=netns,
        target_ip=target_ip,
        allow_loopback=allow_loopback
    )
    t_obj = validate_ip_endpoint(target_ip, "target_ip", ALLOWED_PS028_TARGET_IPS, allow_loopback=allow_loopback)

    if output_jsonl:
        output_jsonl = validate_operation_path(output_jsonl, FileOperationType.DATA_FILE, "output_jsonl", allow_symlinks=False, is_test_fixture=is_test_fixture)
    if lock_file:
        lock_file = validate_operation_path(lock_file, FileOperationType.LOCK_FILE, "lock_file", allow_symlinks=False, is_test_fixture=is_test_fixture)

    if not in_netns:
        with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file):
            helper_script = SCRIPT_DIR / "privileged_helper.py"
            cmd = [
                "ip", "netns", "exec", netns,
                sys.executable, str(helper_script),
                "measure-s5-worker",
                "--target-ip", str(t_obj),
                "--port", str(port),
                "--probe-count", str(probe_count),
                "--timeout", str(timeout),
                "--concurrency", str(concurrency),
                "--netns", netns
            ]
            if output_jsonl:
                cmd.extend(["--output-jsonl", str(output_jsonl)])
            if owner_user:
                cmd.extend(["--owner-user", str(owner_user)])
            if owner_group:
                cmd.extend(["--owner-group", str(owner_group)])

            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                raise PrivilegedHelperError(f"measure-s5 in {netns} failed: {proc.stderr.strip() or proc.stdout.strip()}")

            lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            for line in reversed(lines):
                if line.startswith("{") and line.endswith("}"):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        pass
            return {"status": "OK", "raw_output": proc.stdout}

    # Worker path: positively verify network namespace containment before executing probes
    if not _skip_netns_check:
        is_valid_netns = verify_current_netns(netns)
        if not is_valid_netns:
            if os.geteuid() != 0 and allow_loopback and target_ip in ("127.0.0.1", "::1"):
                pass
            else:
                raise PrivilegedHelperError(
                    f"Network namespace verification failed: current process is not executing "
                    f"inside network namespace '{netns}'. Host network namespace execution is strictly prohibited."
                )

    af = socket.AF_INET6 if t_obj.version == 6 else socket.AF_INET
    records = []
    connected_count = 0
    timeout_count = 0
    refused_count = 0
    error_count = 0

    t_start_all = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(probe_single_socket, i, str(t_obj), port, timeout, af)
            for i in range(probe_count)
        ]
        for fut in concurrent.futures.as_completed(futures):
            rec = fut.result()
            records.append(rec)
            outcome = str(rec.get("connect_outcome") or rec.get("outcome") or "ERROR").upper()
            if outcome == "CONNECTED":
                connected_count += 1
            elif outcome == "TIMEOUT":
                timeout_count += 1
            elif outcome == "REFUSED":
                refused_count += 1
            else:
                error_count += 1
            print(json.dumps(rec), flush=True)

    t_end_all = time.time()
    total_duration_ms = round((t_end_all - t_start_all) * 1000.0, 3)

    records.sort(key=lambda r: r["probe_id"])

    if output_jsonl:
        out_p = validate_operation_path(output_jsonl, FileOperationType.DATA_FILE, "output_jsonl", allow_symlinks=False, is_test_fixture=is_test_fixture)
        content = "".join(json.dumps(rec) + "\n" for rec in records)
        safe_atomic_write_text(
            out_p,
            content,
            op_type=FileOperationType.DATA_FILE,
            param_name="output_jsonl",
            owner_user=owner_user,
            owner_group=owner_group,
            is_test_fixture=is_test_fixture
        )

    summary = {
        "status": "OK",
        "action": "measure-s5",
        "probe_count": probe_count,
        "probes_sent": probe_count,
        "connected": connected_count,
        "timed_out": timeout_count,
        "refused": refused_count,
        "error": error_count,
        "duration_total_ms": total_duration_ms,
        "output_jsonl": str(output_jsonl) if output_jsonl else None
    }
    return summary


def start_nginx_privileged(
    repo_root: Optional[Path] = None,
    config_file: Optional[Path] = None,
    worker_user: Optional[str] = None,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Starts the Nginx HTTP measurement endpoint inside network namespace ps028-sv.
    Enforces that config_file strictly resides within repo_root, tests syntax,
    and forces the worker process to drop privileges to an unprivileged user.
    """
    if repo_root:
        repo_root = validate_secure_path(repo_root, "repo_root", allow_symlinks=False)
    if config_file:
        config_file = validate_secure_path(config_file, "config_file", allow_symlinks=False)
    if lock_file:
        lock_file = validate_secure_path(lock_file, "lock_file", allow_symlinks=False)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file):
        root_dir = (repo_root or REPO_ROOT).resolve()
        conf = (config_file or (root_dir / "lab" / "nginx.conf")).resolve()

        # Path validation: must reside inside root_dir
        try:
            conf.relative_to(root_dir)
        except ValueError:
            raise PrivilegedHelperError(f"Config file {conf} must reside within repository root {root_dir}")

        if not conf.is_file():
            raise PrivilegedHelperError(f"Nginx config file not found: {conf}")

        # Ensure ps028-sv exists
        res = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
        if SERVER_NETNS not in res.stdout:
            raise PrivilegedHelperError(f"Network namespace {SERVER_NETNS} does not exist. Run topology setup first.")

        # Test syntax inside netns
        t_cmd = ["ip", "netns", "exec", SERVER_NETNS, "nginx", "-t", "-p", f"{root_dir}/", "-c", str(conf)]
        t_res = subprocess.run(t_cmd, capture_output=True, text=True)
        if t_res.returncode != 0:
            raise PrivilegedHelperError(f"Nginx configuration syntax test failed: {t_res.stderr.strip()}")

        # Determine unprivileged worker user
        effective_user = worker_user or os.environ.get("SUDO_USER")
        if not effective_user:
            try:
                effective_user = identity.resolve_user_by_uid(os.getuid()).username
            except Exception:
                effective_user = "nobody"

        # Check if already running
        pid_file = root_dir / "lab" / "nginx.pid"
        if pid_file.exists():
            try:
                old_pid = int(pid_file.read_text().strip())
                if _is_alive_proc(old_pid):
                    return {"status": "OK", "action": "start-nginx", "pid": old_pid, "message": "Already running"}
            except Exception:
                pid_file.unlink(missing_ok=True)

        cmd = [
            "ip", "netns", "exec", SERVER_NETNS,
            "nginx", "-p", f"{root_dir}/", "-c", str(conf),
            "-g", f"user {effective_user};"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise PrivilegedHelperError(f"Failed to start Nginx in {SERVER_NETNS}: {res.stderr.strip()}")

        # Verify PID file within 3 seconds
        deadline = time.time() + 3.0
        pid = None
        while time.time() < deadline:
            if pid_file.exists():
                try:
                    p = int(pid_file.read_text().strip())
                    if _is_alive_proc(p):
                        pid = p
                        break
                except Exception:
                    pass
            time.sleep(0.05)

        if pid is None:
            raise PrivilegedHelperError("Nginx process started but PID file inactive or missing after launch")

        return {"status": "OK", "action": "start-nginx", "pid": pid}


def stop_nginx_privileged(
    repo_root: Optional[Path] = None,
    config_file: Optional[Path] = None,
    caller_holds_lock: bool = False,
    lock_file: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Gracefully stops the Nginx HTTP measurement endpoint in ps028-sv and removes pid file.
    """
    if repo_root:
        repo_root = validate_secure_path(repo_root, "repo_root", allow_symlinks=False)
    if config_file:
        config_file = validate_secure_path(config_file, "config_file", allow_symlinks=False)
    if lock_file:
        lock_file = validate_secure_path(lock_file, "lock_file", allow_symlinks=False)

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file):
        root_dir = (repo_root or REPO_ROOT).resolve()
        conf = (config_file or (root_dir / "lab" / "nginx.conf")).resolve()
        pid_file = root_dir / "lab" / "nginx.pid"

        if not pid_file.exists():
            return {"status": "OK", "action": "stop-nginx", "message": "No PID file present"}

        try:
            pid = int(pid_file.read_text().strip())
        except Exception:
            pid_file.unlink(missing_ok=True)
            return {"status": "OK", "action": "stop-nginx", "message": "Unlinked corrupted PID file"}

        # Signal stop inside namespace if netns alive and proc alive
        res = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
        if SERVER_NETNS in res.stdout and _is_alive_proc(pid):
            subprocess.run(
                ["ip", "netns", "exec", SERVER_NETNS, "nginx", "-p", f"{root_dir}/", "-c", str(conf), "-s", "stop"],
                capture_output=True,
                check=False
            )

        deadline = time.time() + 3.0
        while time.time() < deadline:
            if not _is_alive_proc(pid):
                break
            time.sleep(0.05)

        if _is_alive_proc(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        pid_file.unlink(missing_ok=True)
        return {"status": "OK", "action": "stop-nginx", "pid": pid, "stopped": True}


# ==============================================================================
# Helper Invocation Wrapper & Unified Dispatch Contract
# ==============================================================================

def dispatch_action(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Authoritative single dispatch contract shared between in-process and CLI execution.
    All parameter validation, type conversion, and bounds checks are uniformly enforced.
    """
    lock_p = Path(args.lock_file) if getattr(args, "lock_file", None) else None

    if args.action == "apply-scenario":
        sc_path = Path(args.scenarios_path) if getattr(args, "scenarios_path", None) else DEFAULT_SCENARIOS_PATH
        return apply_scenario_privileged(
            scenario_id=args.scenario,
            scenarios_path=sc_path,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "restore-baseline":
        sc_path = Path(args.scenarios_path) if getattr(args, "scenarios_path", None) else DEFAULT_SCENARIOS_PATH
        return restore_baseline_privileged(
            scenarios_path=sc_path,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "apply-dns":
        if not (0 <= args.a_delay <= 2000):
            raise PrivilegedHelperError(f"Invalid a_delay {args.a_delay}: must be between 0 and 2000")
        if not (0 <= args.aaaa_delay <= 2000):
            raise PrivilegedHelperError(f"Invalid aaaa_delay {args.aaaa_delay}: must be between 0 and 2000")
        return apply_dns_delays_privileged(
            a_delay_ms=args.a_delay,
            aaaa_delay_ms=args.aaaa_delay,
            config_file=Path(args.config_file) if getattr(args, "config_file", None) else None,
            backup_file_a3=Path(args.backup_file_a3) if getattr(args, "backup_file_a3", None) else None,
            backup_file_a4=Path(args.backup_file_a4) if getattr(args, "backup_file_a4", None) else None,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "restore-dns":
        return restore_dns_privileged(
            config_file=Path(args.config_file) if getattr(args, "config_file", None) else None,
            backup_file_a4=Path(args.backup_file_a4) if getattr(args, "backup_file_a4", None) else None,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "verify-baseline":
        return verify_baseline_privileged(
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "start-capture":
        return start_capture_privileged(
            output_pcap=Path(args.output_pcap),
            log_file=Path(args.log_file),
            netns=args.netns,
            interface=args.interface,
            bpf_filter=args.filter,
            buffer_size_kb=args.buffer_size_kb,
            owner_user=args.owner_user,
            owner_group=args.owner_group,
            readiness_timeout=args.readiness_timeout,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "stop-capture":
        pcap = Path(args.pcap) if args.pcap else None
        return stop_capture_privileged(
            pid=args.pid,
            pcap_path=pcap,
            timeout=args.timeout,
            owner_user=args.owner_user,
            owner_group=args.owner_group,
            verify_pcap=not args.no_verify_pcap,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "check-auth":
        return check_sudo_authorization()
    elif args.action == "setup-s5-counters":
        return setup_s5_counters_privileged(
            client_ip=args.client_ip,
            target_ip=args.target_ip,
            port=args.port,
            oifname=args.oifname,
            drop_pct=args.drop_pct,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "read-s5-counters":
        return read_s5_counters_privileged(
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "measure-s5":
        return measure_s5_privileged(
            target_ip=args.target_ip,
            port=args.port,
            probe_count=args.probe_count,
            timeout=args.timeout,
            concurrency=args.concurrency,
            netns=args.netns,
            output_jsonl=args.output_jsonl,
            owner_user=args.owner_user,
            owner_group=args.owner_group,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p,
            in_netns=False
        )
    elif args.action == "measure-s5-worker":
        return measure_s5_privileged(
            target_ip=args.target_ip,
            port=args.port,
            probe_count=args.probe_count,
            timeout=args.timeout,
            concurrency=args.concurrency,
            netns=args.netns,
            output_jsonl=args.output_jsonl,
            owner_user=args.owner_user,
            owner_group=args.owner_group,
            caller_holds_lock=False,
            lock_file=None,
            in_netns=True
        )
    elif args.action == "launch-snap-browser":
        launch_snap_browser_main(args)
        return {"status": "OK", "action": "launch-snap-browser"}
    elif args.action == "start-nginx":
        return start_nginx_privileged(
            repo_root=Path(args.repo_root) if args.repo_root else None,
            config_file=Path(args.config_file) if args.config_file else None,
            worker_user=args.worker_user,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    elif args.action == "stop-nginx":
        return stop_nginx_privileged(
            repo_root=Path(args.repo_root) if args.repo_root else None,
            config_file=Path(args.config_file) if args.config_file else None,
            caller_holds_lock=args.caller_holds_lock,
            lock_file=lock_p
        )
    else:
        raise PrivilegedHelperError(f"Unknown helper action: {args.action}")


def run_helper_action(
    action: str,
    extra_args: Optional[List[str]] = None,
    caller_holds_lock: bool = True,
    lock_file: Optional[Path] = None,
    timeout: float = 15.0
) -> Dict[str, Any]:
    """
    Invokes the privileged helper via sudo -n if running unprivileged,
    or directly in-process if already root (e.g. in test fixtures).
    Parses JSON output from helper.
    """
    if os.geteuid() == 0:
        argv = [str(action)] + [str(a) for a in (extra_args or [])]
        if caller_holds_lock and "--caller-holds-lock" not in argv and action not in ("check-auth", "measure-s5-worker"):
            argv.append("--caller-holds-lock")
        if lock_file and "--lock-file" not in argv and action not in ("check-auth", "measure-s5-worker"):
            argv.extend(["--lock-file", str(lock_file)])

        parser = build_parser()
        try:
            parsed_args = parser.parse_args(argv)
        except SystemExit as exc:
            raise PrivilegedHelperError(f"Argument parsing failed for action '{action}': {exc}")

        return dispatch_action(parsed_args)

    # Not root: execute via sudo -n
    helper_script = SCRIPT_DIR / "privileged_helper.py"
    cmd = ["sudo", "-n", sys.executable, str(helper_script), action]

    if action != "check-auth":
        if caller_holds_lock:
            cmd.append("--caller-holds-lock")
        if lock_file:
            cmd.extend(["--lock-file", str(lock_file)])
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
    except FileNotFoundError as exc:
        raise PrivilegedHelperError(f"Required binary not found: {exc}")
    except subprocess.TimeoutExpired:
        raise PrivilegedHelperError(f"Privileged helper operation '{action}' timed out after {timeout}s")

    err_out = (proc.stderr or "").strip()
    if proc.returncode != 0:
        if "password is required" in err_out.lower() or "sudo: a password is required" in err_out.lower():
            raise PrivilegedHelperError(
                "Non-interactive sudo authorization is unavailable (sudo -n failed). "
                "Please authenticate by running 'sudo -v' in your terminal before executing live measurements."
            )
        raise PrivilegedHelperError(
            f"Privileged helper action '{action}' failed (code {proc.returncode}): {err_out or proc.stdout.strip()}"
        )

    out = proc.stdout.strip()
    if out:
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

    return {"status": "OK", "raw_output": proc.stdout}


call_privileged_helper = run_helper_action


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PS-028 Privileged Operations Helper")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # apply-scenario
    p_apply = subparsers.add_parser("apply-scenario", help="Apply S0-S6 impairments")
    p_apply.add_argument("--scenario", required=True, choices=ALLOWED_SCENARIOS)
    p_apply.add_argument("--scenarios-path", default=str(DEFAULT_SCENARIOS_PATH))
    p_apply.add_argument("--caller-holds-lock", action="store_true")
    p_apply.add_argument("--lock-file", default=None)

    # restore-baseline
    p_restore = subparsers.add_parser("restore-baseline", help="Restore clean baseline")
    p_restore.add_argument("--scenarios-path", default=str(DEFAULT_SCENARIOS_PATH))
    p_restore.add_argument("--caller-holds-lock", action="store_true")
    p_restore.add_argument("--lock-file", default=None)

    # apply-dns
    p_apply_dns = subparsers.add_parser("apply-dns", help="Apply DNS delays")
    p_apply_dns.add_argument("--a-delay", type=int, default=0)
    p_apply_dns.add_argument("--aaaa-delay", type=int, default=0)
    p_apply_dns.add_argument("--config-file", default=None)
    p_apply_dns.add_argument("--backup-file-a3", default=None)
    p_apply_dns.add_argument("--backup-file-a4", default=None)
    p_apply_dns.add_argument("--caller-holds-lock", action="store_true")
    p_apply_dns.add_argument("--lock-file", default=None)

    # restore-dns
    p_dns = subparsers.add_parser("restore-dns", help="Restore clean DNS baseline")
    p_dns.add_argument("--config-file", default=None)
    p_dns.add_argument("--backup-file-a4", default=None)
    p_dns.add_argument("--caller-holds-lock", action="store_true")
    p_dns.add_argument("--lock-file", default=None)

    # verify-baseline
    p_verify = subparsers.add_parser("verify-baseline", help="Verify live baseline state")
    p_verify.add_argument("--caller-holds-lock", action="store_true")
    p_verify.add_argument("--lock-file", default=None)

    # start-capture
    p_start = subparsers.add_parser("start-capture", help="Start tcpdump in ps028-cl")
    p_start.add_argument("--output-pcap", required=True)
    p_start.add_argument("--log-file", required=True)
    p_start.add_argument("--netns", default=CLIENT_NETNS)
    p_start.add_argument("--interface", default=CLIENT_CAPTURE_INTERFACE)
    p_start.add_argument("--filter", default=DEFAULT_BPF_FILTER)
    p_start.add_argument("--buffer-size-kb", type=int, default=DEFAULT_CAPTURE_BUFFER_KB)
    p_start.add_argument("--owner-user", default=None)
    p_start.add_argument("--owner-group", default=None)
    p_start.add_argument("--readiness-timeout", type=float, default=3.0)
    p_start.add_argument("--caller-holds-lock", action="store_true")
    p_start.add_argument("--lock-file", default=None)

    # stop-capture
    p_stop = subparsers.add_parser("stop-capture", help="Stop tcpdump capture")
    p_stop.add_argument("--pid", type=int, required=True)
    p_stop.add_argument("--pcap", default=None)
    p_stop.add_argument("--timeout", type=float, default=5.0)
    p_stop.add_argument("--owner-user", default=None)
    p_stop.add_argument("--owner-group", default=None)
    p_stop.add_argument("--no-verify-pcap", action="store_true")
    p_stop.add_argument("--caller-holds-lock", action="store_true")
    p_stop.add_argument("--lock-file", default=None)

    # check-auth
    subparsers.add_parser("check-auth", help="Verify sudo authorization")

    # setup-s5-counters
    p_setup_s5 = subparsers.add_parser("setup-s5-counters", help="Configure router S5 nftables counters")
    p_setup_s5.add_argument("--client-ip", default="2001:db8:1::2", help="Client source IP filter")
    p_setup_s5.add_argument("--target-ip", default="2001:db8:2::10", help="Target server IP filter")
    p_setup_s5.add_argument("--port", type=int, default=80, help="Target TCP port (1-65535)")
    p_setup_s5.add_argument("--oifname", default="ps028-rt-sv6", choices=["ps028-rt-sv6", "ps028-rt-sv4"], help="Outgoing router interface")
    p_setup_s5.add_argument("--drop-pct", type=int, default=50, help="Drop percentage (1-99)")
    p_setup_s5.add_argument("--caller-holds-lock", action="store_true")
    p_setup_s5.add_argument("--lock-file", default=None)

    # read-s5-counters
    p_read_s5 = subparsers.add_parser("read-s5-counters", help="Read router S5 nftables counters")
    p_read_s5.add_argument("--caller-holds-lock", action="store_true")
    p_read_s5.add_argument("--lock-file", default=None)

    # measure-s5 (Host CLI entry: dispatches into netns worker)
    p_meas_s5 = subparsers.add_parser("measure-s5", help="Coordinate and execute S5 SYN probes inside ps028-cl")
    p_meas_s5.add_argument("--target-ip", default="2001:db8:2::10", help="Target server IP")
    p_meas_s5.add_argument("--port", type=int, default=80, help="Target TCP port (1-65535)")
    p_meas_s5.add_argument("--probe-count", "--probes", dest="probe_count", type=int, default=50, help="Probe count (1-500)")
    p_meas_s5.add_argument("--timeout", type=float, default=0.4, help="Connect timeout in seconds (0.05-10.0)")
    p_meas_s5.add_argument("--concurrency", type=int, default=10, help="Concurrency workers (1-50)")
    p_meas_s5.add_argument("--netns", default="ps028-cl", choices=["ps028-cl"], help="Client network namespace")
    p_meas_s5.add_argument("--output-jsonl", default=None, help="Output path for JSONL records")
    p_meas_s5.add_argument("--owner-user", default=None, help="Owner user for output file")
    p_meas_s5.add_argument("--owner-group", default=None, help="Owner group for output file")
    p_meas_s5.add_argument("--caller-holds-lock", action="store_true")
    p_meas_s5.add_argument("--lock-file", default=None)

    # measure-s5-worker (Internal worker executed exclusively inside ps028-cl)
    p_meas_s5_worker = subparsers.add_parser("measure-s5-worker", help="Internal worker: execute probes inside netns")
    p_meas_s5_worker.add_argument("--target-ip", default="2001:db8:2::10", help="Target server IP")
    p_meas_s5_worker.add_argument("--port", type=int, default=80, help="Target TCP port (1-65535)")
    p_meas_s5_worker.add_argument("--probe-count", "--probes", dest="probe_count", type=int, default=50, help="Probe count (1-500)")
    p_meas_s5_worker.add_argument("--timeout", type=float, default=0.4, help="Connect timeout in seconds (0.05-10.0)")
    p_meas_s5_worker.add_argument("--concurrency", type=int, default=10, help="Concurrency workers (1-50)")
    p_meas_s5_worker.add_argument("--netns", default="ps028-cl", choices=["ps028-cl"], help="Client network namespace")
    p_meas_s5_worker.add_argument("--output-jsonl", default=None, help="Output path for JSONL records")
    p_meas_s5_worker.add_argument("--owner-user", default=None, help="Owner user for output file")
    p_meas_s5_worker.add_argument("--owner-group", default=None, help="Owner group for output file")

    # launch-snap-browser
    p_snap = subparsers.add_parser("launch-snap-browser", help="Setup mounts and launch Snap browser")
    p_snap.add_argument("--reuid", type=int, required=True, help="Target UID to drop privileges to")
    p_snap.add_argument("--regid", type=int, required=True, help="Target GID to drop privileges to")
    p_snap.add_argument("--mounts-file", default="/proc/mounts", help="Mounts table file path")
    p_snap.add_argument("--snap-name", default=None, help="Snap package/instance name")
    p_snap.add_argument("--resolver-ip", default="10.0.1.1", help="Target DNS resolver IP")
    p_snap.add_argument("--resolv-conf", default=None, help="Path to source resolv.conf")
    p_snap.add_argument("--snap-ns-dir", default="/run/snapd/ns", help="Snap namespace directory")
    p_snap.add_argument("--source-fd", type=int, default=None, help="Optional pre-opened source namespace FD")
    p_snap.add_argument("--host-proc-root", default="/proc/1/root", help="Host root filesystem path")
    p_snap.add_argument("cmd", nargs=argparse.REMAINDER, help="Browser executable and arguments")

    # start-nginx
    p_start_nginx = subparsers.add_parser("start-nginx", help="Start Nginx in ps028-sv")
    p_start_nginx.add_argument("--repo-root", default=None)
    p_start_nginx.add_argument("--config-file", default=None)
    p_start_nginx.add_argument("--worker-user", default=None)
    p_start_nginx.add_argument("--caller-holds-lock", action="store_true")
    p_start_nginx.add_argument("--lock-file", default=None)

    # stop-nginx
    p_stop_nginx = subparsers.add_parser("stop-nginx", help="Stop Nginx in ps028-sv")
    p_stop_nginx.add_argument("--repo-root", default=None)
    p_stop_nginx.add_argument("--config-file", default=None)
    p_stop_nginx.add_argument("--caller-holds-lock", action="store_true")
    p_stop_nginx.add_argument("--lock-file", default=None)

    return parser


def main() -> int:
    verify_privileged_import_closure(allow_repo=bool(os.environ.get("PS028_TEST_SUITE")))
    parser = build_parser()
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    try:
        res = dispatch_action(args)
        print(json.dumps(res))
        if args.action == "verify-baseline":
            return 0 if res.get("all_passed") else 1
        elif args.action == "check-auth":
            return 0 if res.get("authorized") else 1
        return 0 if res.get("status") == "OK" else 1
    except Exception as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
