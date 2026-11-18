#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Unified Linux Identity Resolver
Work Package A6/A7: Cross-Machine Identity Resolution & Privilege Safety

Authoritative Linux user identity resolution backed strictly by the system
passwd database (pwd). Guarantees consistent non-root identity resolution
across unprivileged browser execution, packet capture ownership, and lab
state management on arbitrary developer workstations.

Strictly enforces:
- Real Linux passwd database as single source of truth.
- Frozen, immutable UserIdentity dataclass.
- Validation and cross-checking of SUDO_UID, SUDO_GID, and SUDO_USER.
- Refusal to trust SUDO_USER alone when real UID is root.
- Rejection of root (UID 0), contradictory, or malformed metadata.
- Zero fallback to hardcoded usernames, UID 1000, or 'nobody'.
- Zero reliance on getpass.getuser() or os.getlogin().
"""

from dataclasses import dataclass
import os
from pathlib import Path
import pwd
from typing import Any, Dict, Optional


class IdentityResolutionError(RuntimeError):
    """Raised when an unprivileged Linux identity cannot be safely or authoritatively resolved."""
    pass


@dataclass(frozen=True)
class UserIdentity:
    """
    Immutable representation of a validated unprivileged Linux user account.
    All attributes originate strictly from an authoritative struct passwd entry.
    """
    uid: int
    gid: int
    username: str
    home_dir: Path
    shell: str

    def __post_init__(self) -> None:
        if isinstance(self.uid, bool) or not isinstance(self.uid, int):
            raise IdentityResolutionError(
                f"UserIdentity uid must be an integer, got {type(self.uid).__name__}"
            )
        if self.uid <= 0:
            raise IdentityResolutionError(
                f"UserIdentity uid must be greater than zero for browser identity, got {self.uid}"
            )
        if isinstance(self.gid, bool) or not isinstance(self.gid, int):
            raise IdentityResolutionError(
                f"UserIdentity gid must be an integer, got {type(self.gid).__name__}"
            )
        if self.gid < 0:
            raise IdentityResolutionError(
                f"UserIdentity gid must be a non-negative integer, got {self.gid}"
            )
        if not isinstance(self.username, str) or not self.username.strip():
            raise IdentityResolutionError(
                f"UserIdentity username must be a non-empty string, got {self.username!r}"
            )
        if not isinstance(self.home_dir, Path):
            raise IdentityResolutionError(
                f"UserIdentity home_dir must be a Path, got {type(self.home_dir).__name__}"
            )
        if not self.home_dir.is_absolute():
            raise IdentityResolutionError(
                f"UserIdentity home_dir must be an absolute path, got {self.home_dir}"
            )
        if not isinstance(self.shell, str) or not self.shell.strip():
            raise IdentityResolutionError(
                f"UserIdentity shell must be a non-empty string, got {self.shell!r}"
            )


def _parse_int_env(name: str, val: Any) -> int:
    """
    Parses and validates an integer environment value.
    Strictly rejects booleans, non-numeric strings, and empty values.
    """
    if isinstance(val, bool) or not isinstance(val, (int, str)):
        raise IdentityResolutionError(
            f"Malformed {name}: expected integer or numeric string, got {val!r}"
        )
    val_str = str(val).strip()
    if not val_str:
        raise IdentityResolutionError(f"Malformed {name}: empty value")
    try:
        return int(val_str)
    except (ValueError, TypeError) as exc:
        raise IdentityResolutionError(f"Malformed {name}: {val!r}") from exc


def resolve_user_by_uid(uid: int) -> UserIdentity:
    """
    Resolves an unprivileged UserIdentity strictly from the passwd database by numeric UID.

    Args:
        uid: Positive integer UID of the account.

    Returns:
        A validated, immutable UserIdentity.

    Raises:
        IdentityResolutionError: If UID is non-integer, <= 0, or missing from the passwd database.
    """
    if isinstance(uid, bool) or not isinstance(uid, int):
        raise IdentityResolutionError(f"UID must be an integer, got {type(uid).__name__}")
    if uid <= 0:
        raise IdentityResolutionError(f"UID must be greater than zero for browser identity, got {uid}")

    try:
        pw = pwd.getpwuid(uid)
    except (KeyError, OverflowError) as exc:
        raise IdentityResolutionError(f"Account for UID {uid} not found in passwd database") from exc
    except OSError as exc:
        raise IdentityResolutionError(
            f"Operating system error reading passwd database for UID {uid}: {exc}"
        ) from exc

    if pw.pw_uid != uid:
        raise IdentityResolutionError(
            f"Passwd database inconsistency: requested UID {uid} but got record with UID {pw.pw_uid}"
        )

    home_path = Path(pw.pw_dir) if pw.pw_dir else Path("")
    # When the passwd shell field is empty or whitespace-only, use the
    # conventional system-shell path on Linux: /bin/sh.
    shell_val = pw.pw_shell if (pw.pw_shell and pw.pw_shell.strip()) else "/bin/sh"
    return UserIdentity(
        uid=pw.pw_uid,
        gid=pw.pw_gid,
        username=pw.pw_name,
        home_dir=home_path,
        shell=shell_val,
    )


def resolve_user_by_name(username: str) -> UserIdentity:
    """
    Resolves an unprivileged UserIdentity strictly from the passwd database by account name.

    Args:
        username: Non-empty account name string.

    Returns:
        A validated, immutable UserIdentity.

    Raises:
        IdentityResolutionError: If username is empty, non-string, missing, or maps to root (UID 0).
    """
    if not isinstance(username, str) or not username.strip():
        raise IdentityResolutionError(f"Username must be a non-empty string, got {username!r}")

    try:
        pw = pwd.getpwnam(username)
    except KeyError as exc:
        raise IdentityResolutionError(f"Account '{username}' not found in passwd database") from exc
    except OSError as exc:
        raise IdentityResolutionError(
            f"Operating system error reading passwd database for username '{username}': {exc}"
        ) from exc

    if pw.pw_name != username:
        raise IdentityResolutionError(
            f"Passwd database inconsistency: requested username '{username}' but got record with name '{pw.pw_name}'"
        )

    if pw.pw_uid <= 0:
        raise IdentityResolutionError(
            f"Account '{username}' resolved to root or invalid UID {pw.pw_uid}; browser identity must be > 0"
        )

    home_path = Path(pw.pw_dir) if pw.pw_dir else Path("")
    # When the passwd shell field is empty or whitespace-only, use the
    # conventional system-shell path on Linux: /bin/sh.
    shell_val = pw.pw_shell if (pw.pw_shell and pw.pw_shell.strip()) else "/bin/sh"
    return UserIdentity(
        uid=pw.pw_uid,
        gid=pw.pw_gid,
        username=pw.pw_name,
        home_dir=home_path,
        shell=shell_val,
    )


def resolve_invoking_identity(env: Optional[Dict[str, str]] = None) -> UserIdentity:
    """
    Authoritatively determines the invoking unprivileged Linux identity.

    Rules:
    - Normal execution (os.getuid() != 0):
      1. Obtains real UID via os.getuid().
      2. Resolves that UID through pwd.getpwuid().
      3. Uses passwd record's primary GID.
      4. If SUDO_UID, SUDO_GID, or SUDO_USER is present, validates against resolved passwd identity.
      5. Contradictory metadata raises IdentityResolutionError.
      Where os.getuid() is nonzero but os.geteuid() is zero, the real UID remains the invoking identity.
    - Root execution (os.getuid() == 0):
      1. Requires a valid SUDO_UID.
      2. Resolves that UID through pwd.getpwuid().
      3. If SUDO_USER is supplied, requires an exact username match.
      4. If SUDO_GID is supplied, requires a valid integer matching the primary GID.
      5. Rejects UID 0.
      6. If trustworthy invoking identity cannot be established, raises IdentityResolutionError.
      Does not trust SUDO_USER alone when real UID is root.
    """
    active_env = os.environ if env is None else env
    real_uid = os.getuid()

    if isinstance(real_uid, bool) or not isinstance(real_uid, int):
        raise IdentityResolutionError(f"os.getuid() returned invalid non-integer: {real_uid!r}")

    if real_uid != 0:
        # Normal execution (including setuid root where os.geteuid() == 0)
        ident = resolve_user_by_uid(real_uid)

        # Validate SUDO_UID if present
        if "SUDO_UID" in active_env and active_env["SUDO_UID"] is not None:
            s_uid = _parse_int_env("SUDO_UID", active_env["SUDO_UID"])
            if s_uid != real_uid:
                raise IdentityResolutionError(
                    f"Contradictory SUDO_UID: environment has {s_uid} but real UID is {real_uid}"
                )

        # Validate SUDO_USER if present
        if "SUDO_USER" in active_env and active_env["SUDO_USER"] is not None:
            s_user = str(active_env["SUDO_USER"]).strip()
            if s_user != ident.username:
                raise IdentityResolutionError(
                    f"Contradictory SUDO_USER: environment has {s_user!r} but real username is {ident.username!r}"
                )

        # Validate SUDO_GID if present
        if "SUDO_GID" in active_env and active_env["SUDO_GID"] is not None:
            s_gid = _parse_int_env("SUDO_GID", active_env["SUDO_GID"])
            if s_gid != ident.gid:
                raise IdentityResolutionError(
                    f"Contradictory SUDO_GID: environment has {s_gid} but primary GID is {ident.gid}"
                )

        return ident

    # Root execution (real_uid == 0)
    if "SUDO_UID" not in active_env or active_env["SUDO_UID"] is None:
        raise IdentityResolutionError(
            "Root execution requires a valid SUDO_UID in the environment to establish an unprivileged invoking identity. "
            "SUDO_USER alone is not trusted when real UID is root."
        )

    sudo_uid = _parse_int_env("SUDO_UID", active_env["SUDO_UID"])
    if sudo_uid <= 0:
        raise IdentityResolutionError(
            f"Root execution cannot use root or non-positive SUDO_UID ({sudo_uid}); unprivileged identity required"
        )

    ident = resolve_user_by_uid(sudo_uid)

    if "SUDO_USER" in active_env and active_env["SUDO_USER"] is not None:
        sudo_user = str(active_env["SUDO_USER"]).strip()
        if sudo_user != ident.username:
            raise IdentityResolutionError(
                f"Contradictory SUDO_USER: environment has {sudo_user!r} but UID {sudo_uid} resolves to {ident.username!r}"
            )

    if "SUDO_GID" in active_env and active_env["SUDO_GID"] is not None:
        sudo_gid = _parse_int_env("SUDO_GID", active_env["SUDO_GID"])
        if sudo_gid != ident.gid:
            raise IdentityResolutionError(
                f"Contradictory SUDO_GID: environment has {sudo_gid} but primary GID for UID {sudo_uid} is {ident.gid}"
            )

    return ident
