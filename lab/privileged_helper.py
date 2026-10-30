#!/usr/bin/env python3
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
import contextlib
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.impair as impair
import lab.run_trial as run_trial

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


class PrivilegedHelperError(Exception):
    """Raised when a privileged helper operation fails."""
    pass


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
    If running under sudo (os.geteuid() == 0 or os.getuid() == 0),
    checks SUDO_UID and SUDO_GID, then SUDO_USER.
    Otherwise returns current process os.getuid() and os.getgid().
    """
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0:
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid is not None and sudo_gid is not None:
            try:
                return int(sudo_uid), int(sudo_gid)
            except ValueError:
                pass
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            try:
                import pwd
                pw = pwd.getpwnam(sudo_user)
                return pw.pw_uid, pw.pw_gid
            except (KeyError, ImportError):
                pass
        user_env = os.environ.get("USER") or os.environ.get("LOGNAME")
        if user_env and user_env != "root":
            try:
                import pwd
                pw = pwd.getpwnam(user_env)
                if pw.pw_uid != 0:
                    return pw.pw_uid, pw.pw_gid
            except (KeyError, ImportError):
                pass
        try:
            st = Path(__file__).stat()
            if st.st_uid != 0:
                return st.st_uid, st.st_gid
        except OSError:
            pass
        try:
            import pwd
            pw = pwd.getpwuid(1000)
            if pw.pw_uid != 0:
                return pw.pw_uid, pw.pw_gid
        except (KeyError, ImportError):
            pass
    return uid, gid


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
    1. Sets up missing mounts (cgroup2, securityfs).
    2. Sets up isolated Snap mount namespace with lab DNS resolver (10.0.1.1).
    3. Drops privileges to target UID and GID.
    4. Replaces process image with the browser executable.
    """
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
            import pwd
            user_name = pwd.getpwuid(target_uid).pw_name
            os.initgroups(user_name, target_gid)
        except Exception:
            try:
                os.setgroups([])
            except OSError:
                pass
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
        fd = os.open(str(target), os.O_RDWR)
    except PermissionError:
        fd = os.open(str(target), os.O_RDONLY)

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
def coordinate_lock(caller_holds_lock: bool, lock_path: Optional[Path] = None, timeout: float = 5.0):
    """
    Coordinates lock acquisition or verification:
    - If caller_holds_lock is True: verifies lock is actively held without re-locking (prevents deadlock).
    - If caller_holds_lock is False: acquires exclusive flock via concurrency.acquire_lab_lock.
    """
    target = Path(lock_path or LAB_LOCK_FILE).resolve()
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
    lock_timeout: float = 5.0
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

    with coordinate_lock(caller_holds_lock=caller_holds_lock, lock_path=lock_file, timeout=lock_timeout):
        data = impair.load_scenarios_config(scenarios_path)
        scenario = data["scenarios"][sc_clean]

        # Reset baseline first
        restore_baseline_privileged(
            scenarios_path=scenarios_path,
            caller_holds_lock=True,
            lock_file=lock_file,
            lock_timeout=lock_timeout
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
    lock_timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Restores network baseline with root privileges:
    1. Coordinates lab lock.
    2. Deletes nftables table ps028_impair in ps028-rt.
    3. Restores 10ms netem delay on all 4 interfaces.
    4. Restores DNS baseline (0ms A and AAAA) and unlinks backup.
    5. Clears impairment state file.
    """
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
    lock_timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Applies DNS delays (rules.A and rules.AAAA) with root privileges.
    Guarantees baseline backup, atomic updates, SIGHUP reload, and verification.
    Never reports success if application or verification fails.
    """
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
    lock_timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Restores clean DNS baseline (0ms delays and reloads DNS server) with root privileges.
    Never reports success if restoration fails or is unverified.
    """
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
    pid_file: Optional[Path] = None
) -> None:
    """
    Terminates and reaps any capture processes launched when startup fails.
    Prevents orphaned tcpdump processes and unlinks stale PID file.
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
    lock_timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Starts tcpdump inside the target network namespace with root privileges:
    - Sets immediate mode and unbuffered write for fast flush.
    - Sets operating system capture buffer size via -B (buffer_size_kb).
    - Drops capture write privileges to owner_user (via -Z).
    - Verifies readiness ('listening on') within readiness_timeout.
    - Writes PID file and returns JSON-serializable capture handle.
    - Cleans up and reaps spawned process on any startup failure.
    """
    if netns not in ALLOWED_NETNS:
        raise PrivilegedHelperError(f"Unauthorized netns '{netns}'. Allowed: {sorted(ALLOWED_NETNS)}")

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
        target_user = owner_user or os.environ.get("SUDO_USER") or os.environ.get("USER") or "indrani"
        if target_user:
            cmd.extend(["-Z", target_user])
        else:
            cmd.extend(["-Z", "root"])

        cmd.extend([
            "-w", str(output_pcap),
            bpf_filter
        ])

        pid_file = output_pcap.with_suffix(".pid")
        proc = None
        log_fp = open(log_file, "w", encoding="utf-8")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=log_fp,
                start_new_session=True
            )
        except Exception as exc:
            log_fp.close()
            raise PrivilegedHelperError(f"Failed to spawn tcpdump: {exc}")

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

            # Save PID file for tracking
            pid_file.write_text(f"{proc.pid}:{tcpdump_pid}\n", encoding="utf-8")

            # Set file ownership if requested or running as root
            if target_user:
                _chown_file(log_file, target_user, owner_group)
                _chown_file(pid_file, target_user, owner_group)

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
                pid_file=pid_file
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
    proc_dir: Optional[Path] = None
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
        target_user = owner_user or os.environ.get("SUDO_USER") or os.environ.get("USER") or "indrani"
        if pcap_file and pcap_file.is_file():
            if target_user:
                _chown_file(pcap_file, target_user, owner_group)
            try:
                pcap_file.chmod(0o664)
            except OSError:
                pass

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


def _chown_file(path: Path, user: str, group: Optional[str] = None) -> None:
    """Safely chowns file if running as root."""
    if os.geteuid() == 0 and path.exists():
        try:
            import pwd
            import grp
            uid = pwd.getpwnam(user).pw_uid
            gid = grp.getgrnam(group or user).gr_gid if group else pwd.getpwnam(user).pw_gid
            os.chown(str(path), uid, gid)
        except Exception:
            pass


# ==============================================================================
# Helper Invocation Wrapper (Called from unprivileged Python processes)
# ==============================================================================

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
        # Run directly in-process if already root
        if action == "apply-scenario":
            sc_id = "S0"
            sc_path = DEFAULT_SCENARIOS_PATH
            if extra_args:
                for i, a in enumerate(extra_args):
                    if a == "--scenario" and i + 1 < len(extra_args):
                        sc_id = extra_args[i + 1]
                    elif a == "--scenarios-path" and i + 1 < len(extra_args):
                        sc_path = Path(extra_args[i + 1])
            return apply_scenario_privileged(
                scenario_id=sc_id,
                scenarios_path=sc_path,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "restore-baseline":
            return restore_baseline_privileged(
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "apply-dns":
            a_d = 0
            aaaa_d = 0
            cfg_p = None
            bak_a3 = None
            bak_a4 = None
            if extra_args:
                for i, a in enumerate(extra_args):
                    if a == "--a-delay" and i + 1 < len(extra_args):
                        a_d = int(extra_args[i + 1])
                    elif a == "--aaaa-delay" and i + 1 < len(extra_args):
                        aaaa_d = int(extra_args[i + 1])
                    elif a == "--config-file" and i + 1 < len(extra_args):
                        cfg_p = Path(extra_args[i + 1])
                    elif a == "--backup-file-a3" and i + 1 < len(extra_args):
                        bak_a3 = Path(extra_args[i + 1])
                    elif a == "--backup-file-a4" and i + 1 < len(extra_args):
                        bak_a4 = Path(extra_args[i + 1])
            return apply_dns_delays_privileged(
                a_delay_ms=a_d,
                aaaa_delay_ms=aaaa_d,
                config_file=cfg_p,
                backup_file_a3=bak_a3,
                backup_file_a4=bak_a4,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "restore-dns":
            cfg_p = None
            bak_a4 = None
            if extra_args:
                for i, a in enumerate(extra_args):
                    if a == "--config-file" and i + 1 < len(extra_args):
                        cfg_p = Path(extra_args[i + 1])
                    elif a == "--backup-file-a4" and i + 1 < len(extra_args):
                        bak_a4 = Path(extra_args[i + 1])
            return restore_dns_privileged(
                config_file=cfg_p,
                backup_file_a4=bak_a4,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "verify-baseline":
            return verify_baseline_privileged(
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "start-capture":
            out_pcap = None
            log_f = None
            netns = CLIENT_NETNS
            iface = "any"
            filt = "port 53 or port 80"
            user = None
            group = None
            r_timeout = 3.0
            if extra_args:
                for i, a in enumerate(extra_args):
                    if a == "--output-pcap" and i + 1 < len(extra_args):
                        out_pcap = Path(extra_args[i + 1])
                    elif a == "--log-file" and i + 1 < len(extra_args):
                        log_f = Path(extra_args[i + 1])
                    elif a == "--netns" and i + 1 < len(extra_args):
                        netns = extra_args[i + 1]
                    elif a == "--interface" and i + 1 < len(extra_args):
                        iface = extra_args[i + 1]
                    elif a == "--filter" and i + 1 < len(extra_args):
                        filt = extra_args[i + 1]
                    elif a == "--owner-user" and i + 1 < len(extra_args):
                        user = extra_args[i + 1]
                    elif a == "--owner-group" and i + 1 < len(extra_args):
                        group = extra_args[i + 1]
                    elif a == "--readiness-timeout" and i + 1 < len(extra_args):
                        r_timeout = float(extra_args[i + 1])
            return start_capture_privileged(
                output_pcap=out_pcap,
                log_file=log_f,
                netns=netns,
                interface=iface,
                bpf_filter=filt,
                owner_user=user,
                owner_group=group,
                readiness_timeout=r_timeout,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "stop-capture":
            target_pid = 0
            pcap = None
            t_out = 5.0
            user = None
            group = None
            v_pcap = True
            if extra_args:
                for i, a in enumerate(extra_args):
                    if a == "--pid" and i + 1 < len(extra_args):
                        target_pid = int(extra_args[i + 1])
                    elif a == "--pcap" and i + 1 < len(extra_args):
                        pcap = Path(extra_args[i + 1])
                    elif a == "--timeout" and i + 1 < len(extra_args):
                        t_out = float(extra_args[i + 1])
                    elif a == "--owner-user" and i + 1 < len(extra_args):
                        user = extra_args[i + 1]
                    elif a == "--owner-group" and i + 1 < len(extra_args):
                        group = extra_args[i + 1]
                    elif a == "--no-verify-pcap":
                        v_pcap = False
            return stop_capture_privileged(
                pid=target_pid,
                pcap_path=pcap,
                timeout=t_out,
                owner_user=user,
                owner_group=group,
                verify_pcap=v_pcap,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        elif action == "check-auth":
            return {"authorized": True, "method": "root"}

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
            f"Privileged helper failed (action={action}, code={proc.returncode}): {err_out or proc.stdout.strip()}"
        )

    # Parse JSON output from last line of stdout
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

    return {"status": "OK", "raw_output": proc.stdout}


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> int:
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

    args = parser.parse_args()

    try:
        lock_p = Path(args.lock_file) if getattr(args, "lock_file", None) else None
        if args.action == "apply-scenario":
            res = apply_scenario_privileged(
                scenario_id=args.scenario,
                scenarios_path=Path(args.scenarios_path),
                caller_holds_lock=args.caller_holds_lock,
                lock_file=lock_p
            )
            print(json.dumps(res))
            return 0

        elif args.action == "restore-baseline":
            res = restore_baseline_privileged(
                scenarios_path=Path(args.scenarios_path),
                caller_holds_lock=args.caller_holds_lock,
                lock_file=lock_p
            )
            print(json.dumps(res))
            return 0

        elif args.action == "apply-dns":
            res = apply_dns_delays_privileged(
                a_delay_ms=args.a_delay,
                aaaa_delay_ms=args.aaaa_delay,
                config_file=Path(args.config_file) if getattr(args, "config_file", None) else None,
                backup_file_a3=Path(args.backup_file_a3) if getattr(args, "backup_file_a3", None) else None,
                backup_file_a4=Path(args.backup_file_a4) if getattr(args, "backup_file_a4", None) else None,
                caller_holds_lock=args.caller_holds_lock,
                lock_file=lock_p
            )
            print(json.dumps(res))
            return 0

        elif args.action == "restore-dns":
            res = restore_dns_privileged(
                config_file=Path(args.config_file) if getattr(args, "config_file", None) else None,
                backup_file_a4=Path(args.backup_file_a4) if getattr(args, "backup_file_a4", None) else None,
                caller_holds_lock=args.caller_holds_lock,
                lock_file=lock_p
            )
            print(json.dumps(res))
            return 0

        elif args.action == "verify-baseline":
            res = verify_baseline_privileged(
                caller_holds_lock=args.caller_holds_lock,
                lock_file=lock_p
            )
            print(json.dumps(res))
            return 0 if res.get("all_passed") else 1

        elif args.action == "start-capture":
            res = None
            try:
                res = start_capture_privileged(
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
                print(json.dumps(res))
                return 0
            except Exception as exc:
                if res and isinstance(res, dict) and "parent_pid" in res:
                    try:
                        stop_capture_privileged(
                            pid=res["parent_pid"],
                            pcap_path=Path(res["pcap_path"]) if "pcap_path" in res else None,
                            verify_pcap=False,
                            caller_holds_lock=args.caller_holds_lock,
                            lock_file=lock_p
                        )
                    except Exception:
                        pass
                print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
                return 1

        elif args.action == "stop-capture":
            pcap = Path(args.pcap) if args.pcap else None
            res = stop_capture_privileged(
                pid=args.pid,
                pcap_path=pcap,
                timeout=args.timeout,
                owner_user=args.owner_user,
                owner_group=args.owner_group,
                verify_pcap=not args.no_verify_pcap,
                caller_holds_lock=args.caller_holds_lock,
                lock_file=lock_p
            )
            print(json.dumps(res))
            return 0

        elif args.action == "check-auth":
            auth = check_sudo_authorization()
            print(json.dumps(auth))
            return 0 if auth["authorized"] else 1

        elif args.action == "launch-snap-browser":
            launch_snap_browser_main(args)
            return 0

    except Exception as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
