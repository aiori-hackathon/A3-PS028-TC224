#!/usr/bin/env bash
# ==============================================================================
# PS-028 Trusted Privileged Helper Deployment Specification
# Work Package A10 & Milestone 4 / Gate B Transactional Updater
#
# Deploys / Upgrades the privileged helper and its trusted execution boundary to:
#   /usr/local/libexec/ps028/
#
# Enforces:
# 1. Root ownership (root:root) and strict permissions (0755 / 0750 / 0644 / 0440)
# 2. Complete isolation from unprivileged, user-writable repository checkouts
# 3. Python -I (isolated mode) invocation via sudoers
# 4. Strict provenance verification (clean git tree across entire repo, exact 40-char SHA)
# 5. Non-destructive transactional upgrade with state-machine recovery and automatic rollback
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${PS028_REPO_ROOT:-$(dirname "${SCRIPT_DIR}")}"
TARGET_DIR="${PS028_TARGET_DIR:-/usr/local/libexec/ps028}"
TARGET_SUDOERS="${PS028_TARGET_SUDOERS:-/etc/sudoers.d/ps028-helper}"
EXPECTED_RELEASE_SHA="${PS028_EXPECTED_RELEASE_SHA:-}"
IS_TEST_FIXTURE="${PS028_TEST_FIXTURE:-0}"
MIGRATE_UNMANIFESTED="${PS028_MIGRATE_UNMANIFESTED:-0}"
LEGACY_BASELINE_COMMIT="${PS028_LEGACY_BASELINE_COMMIT:-}"

DRY_RUN=0
UNINSTALL=0
EXPLICIT_USER=""

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Deploys or upgrades the PS-028 privileged helper to /usr/local/libexec/ps028/"
    echo ""
    echo "Options:"
    echo "  --dry-run                    Audit deployment specification without modifying the host"
    echo "  --user, -u <USER>            Operating username for sudoers authorization (default: current user)"
    echo "  --target-dir <DIR>           Target deployment directory (default: /usr/local/libexec/ps028)"
    echo "  --target-sudoers <FILE>      Target sudoers drop-in file (default: /etc/sudoers.d/ps028-helper)"
    echo "  --repo-root <DIR>            Repository root path (default: parent of script dir)"
    echo "  --release-sha <SHA>          Expected 40-character Git commit SHA to deploy"
    echo "  --migrate-unmanifested       Explicitly migrate and verify an unmanifested legacy installation"
    echo "  --legacy-baseline-commit <S> Expected historical Git commit SHA for legacy migration verification"
    echo "  --uninstall                  Safely remove installed helper files and sudoers drop-in"
    echo "  -h, --help                   Show this help message and exit"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --user|-u)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "[ERROR] Option $1 requires a non-empty username argument." >&2
                exit 1
            fi
            EXPLICIT_USER="$2"
            shift 2
            ;;
        --user=*)
            EXPLICIT_USER="${1#*=}"
            if [[ -z "${EXPLICIT_USER}" ]]; then
                echo "[ERROR] Option --user= requires a non-empty username argument." >&2
                exit 1
            fi
            shift
            ;;
        --target-dir)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "[ERROR] Option $1 requires a non-empty directory argument." >&2
                exit 1
            fi
            TARGET_DIR="$2"
            shift 2
            ;;
        --target-dir=*)
            TARGET_DIR="${1#*=}"
            shift
            ;;
        --target-sudoers)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "[ERROR] Option $1 requires a non-empty file argument." >&2
                exit 1
            fi
            TARGET_SUDOERS="$2"
            shift 2
            ;;
        --target-sudoers=*)
            TARGET_SUDOERS="${1#*=}"
            shift
            ;;
        --repo-root)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "[ERROR] Option $1 requires a non-empty path argument." >&2
                exit 1
            fi
            REPO_ROOT="$2"
            shift 2
            ;;
        --repo-root=*)
            REPO_ROOT="${1#*=}"
            shift
            ;;
        --release-sha)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "[ERROR] Option $1 requires a 40-character hex SHA argument." >&2
                exit 1
            fi
            EXPECTED_RELEASE_SHA="$2"
            shift 2
            ;;
        --release-sha=*)
            EXPECTED_RELEASE_SHA="${1#*=}"
            shift
            ;;
        --migrate-unmanifested)
            MIGRATE_UNMANIFESTED=1
            shift
            ;;
        --legacy-baseline-commit)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "[ERROR] Option $1 requires a 40-character hex SHA argument." >&2
                exit 1
            fi
            LEGACY_BASELINE_COMMIT="$2"
            MIGRATE_UNMANIFESTED=1
            shift 2
            ;;
        --legacy-baseline-commit=*)
            LEGACY_BASELINE_COMMIT="${1#*=}"
            MIGRATE_UNMANIFESTED=1
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unrecognized argument: $1" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

# Validate operating user
if [[ -n "${EXPLICIT_USER}" ]]; then
    if [[ ! "${EXPLICIT_USER}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
        echo "[ERROR] Invalid operating username . Must match POSIX user pattern: ^[a-z_][a-z0-9_-]*[$]?$" >&2
        exit 1
    fi
    OPERATING_USER="${EXPLICIT_USER}"
else
    OPERATING_USER="${SUDO_USER:-$(id -un)}"
fi

# ------------------------------------------------------------------------------
# Production Path Locking & Security Validation (Section E)
# ------------------------------------------------------------------------------
if [[ "${TARGET_DIR}" != /* ]]; then
    echo "[ERROR] TARGET_DIR must be an absolute path: ${TARGET_DIR}" >&2
    exit 1
fi
if [[ "${TARGET_SUDOERS}" != /* ]]; then
    echo "[ERROR] TARGET_SUDOERS must be an absolute path: ${TARGET_SUDOERS}" >&2
    exit 1
fi
if [[ "${REPO_ROOT}" != /* ]]; then
    REPO_ROOT="$(cd "${REPO_ROOT}" && pwd)"
fi

# Path traversal checks
if [[ "${TARGET_DIR}" == *"/.."* || "${TARGET_DIR}" == *"/." || "${TARGET_SUDOERS}" == *"/.."* || "${TARGET_SUDOERS}" == *"/." ]]; then
    echo "[ERROR] Path traversal components (.. or .) are prohibited: TARGET_DIR=${TARGET_DIR}, TARGET_SUDOERS=${TARGET_SUDOERS}" >&2
    exit 1
fi

# Production path locking & Test fixture isolation (Item 1)
if [[ "${IS_TEST_FIXTURE}" -ne 0 ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
        echo "[ERROR] PS028_TEST_FIXTURE is prohibited when running as root." >&2
        exit 1
    fi
    if [[ -z "${PS028_TEST_ROOT:-}" ]]; then
        echo "[ERROR] PS028_TEST_ROOT must be explicitly set when PS028_TEST_FIXTURE is enabled." >&2
        exit 1
    fi
    if [[ ! -d "${PS028_TEST_ROOT}" ]]; then
        echo "[ERROR] PS028_TEST_ROOT does not exist or is not a directory: ${PS028_TEST_ROOT}" >&2
        exit 1
    fi
    CANONICAL_TEST_ROOT="$(cd "${PS028_TEST_ROOT}" && pwd -P)"
    if [[ "${CANONICAL_TEST_ROOT}" == "/" || "${CANONICAL_TEST_ROOT}" == "/usr" || "${CANONICAL_TEST_ROOT}" == "/etc" || "${CANONICAL_TEST_ROOT}" == "/var" || "${CANONICAL_TEST_ROOT}" == "/home" || "${CANONICAL_TEST_ROOT}" == "/root" ]]; then
        echo "[ERROR] PS028_TEST_ROOT cannot be a system root directory: ${CANONICAL_TEST_ROOT}" >&2
        exit 1
    fi

    if [[ "${TARGET_DIR}" == "/usr/local/libexec/ps028" || "${TARGET_SUDOERS}" == "/etc/sudoers.d/ps028-helper" ]]; then
        echo "[ERROR] Test fixtures must use isolated paths, not real host paths." >&2
        exit 1
    fi

    TARGET_PARENT_DIR="$(dirname "${TARGET_DIR}")"
    if [[ ! -d "${TARGET_PARENT_DIR}" ]]; then
        echo "[ERROR] Parent directory for target does not exist: ${TARGET_PARENT_DIR}" >&2
        exit 1
    fi
    CANONICAL_TARGET_PARENT="$(cd "${TARGET_PARENT_DIR}" && pwd -P)"
    CANONICAL_TARGET_DIR="${CANONICAL_TARGET_PARENT}/$(basename "${TARGET_DIR}")"

    SUDOERS_PARENT_DIR="$(dirname "${TARGET_SUDOERS}")"
    if [[ ! -d "${SUDOERS_PARENT_DIR}" ]]; then
        echo "[ERROR] Parent directory for sudoers does not exist: ${SUDOERS_PARENT_DIR}" >&2
        exit 1
    fi
    CANONICAL_SUDOERS_PARENT="$(cd "${SUDOERS_PARENT_DIR}" && pwd -P)"
    CANONICAL_TARGET_SUDOERS="${CANONICAL_SUDOERS_PARENT}/$(basename "${TARGET_SUDOERS}")"

    if [[ "${CANONICAL_TARGET_DIR}" != "${CANONICAL_TEST_ROOT}"/* || "${CANONICAL_TARGET_SUDOERS}" != "${CANONICAL_TEST_ROOT}"/* ]]; then
        echo "[ERROR] Test fixture target paths must reside strictly within PS028_TEST_ROOT (${CANONICAL_TEST_ROOT})." >&2
        exit 1
    fi
    if [[ "${CANONICAL_TARGET_DIR}" == "/usr/local/libexec/ps028" || "${CANONICAL_TARGET_SUDOERS}" == "/etc/sudoers.d/ps028-helper" ]]; then
        echo "[ERROR] Test fixtures must use isolated paths, not real host paths." >&2
        exit 1
    fi
    TARGET_DIR="${CANONICAL_TARGET_DIR}"
    TARGET_SUDOERS="${CANONICAL_TARGET_SUDOERS}"
else
    # In production
    if [[ "${TARGET_DIR}" != "/usr/local/libexec/ps028" ]]; then
        echo "[ERROR] In production, target directory is strictly locked to /usr/local/libexec/ps028. Custom target directories are prohibited." >&2
        exit 1
    fi
    if [[ "${TARGET_SUDOERS}" != "/etc/sudoers.d/ps028-helper" ]]; then
        echo "[ERROR] In production, target sudoers file is strictly locked to /etc/sudoers.d/ps028-helper. Custom sudoers destinations are prohibited." >&2
        exit 1
    fi
    if [[ -z "${EXPECTED_RELEASE_SHA}" ]]; then
        echo "[ERROR] Production deployment requires explicit --release-sha <SHA>. Refusing unpinned deployment." >&2
        exit 1
    fi
fi

# Disallow dangerous root, system or sensitive destinations
DANGEROUS_TARGETS=("" "/" "/bin" "/sbin" "/usr" "/usr/bin" "/usr/sbin" "/usr/lib" "/usr/local" "/usr/local/bin" "/etc" "/etc/sudoers.d" "/var" "/home" "/root")
for dt in "${DANGEROUS_TARGETS[@]}"; do
    if [[ "${TARGET_DIR}" == "${dt}" ]]; then
        echo "[ERROR] Disallowed system target directory: ${TARGET_DIR}" >&2
        exit 1
    fi
done

DANGEROUS_SUDOERS=("" "/" "/etc" "/etc/sudoers" "/etc/shadow" "/etc/passwd" "/etc/group" "/usr/local/bin")
for ds in "${DANGEROUS_SUDOERS[@]}"; do
    if [[ "${TARGET_SUDOERS}" == "${ds}" ]]; then
        echo "[ERROR] Disallowed target sudoers path: ${TARGET_SUDOERS}" >&2
        exit 1
    fi
done

# Prevent symlink attacks on target locations
if [[ -L "${TARGET_DIR}" ]]; then
    echo "[ERROR] Target directory is a symlink: ${TARGET_DIR}. Refusing to proceed for security." >&2
    exit 1
fi
if [[ -L "${TARGET_SUDOERS}" ]]; then
    echo "[ERROR] Target sudoers file is a symlink: ${TARGET_SUDOERS}. Refusing to proceed for security." >&2
    exit 1
fi

TARGET_PARENT="$(dirname "${TARGET_DIR}")"
TARGET_BASENAME="$(basename "${TARGET_DIR}")"
SUDOERS_PARENT="$(dirname "${TARGET_SUDOERS}")"
STATE_FILE="${TARGET_PARENT}/.ps028_tx_state_${TARGET_BASENAME}"

# Verify parent directory exists and check symlinks
if [[ ! -d "${TARGET_PARENT}" ]]; then
    echo "[ERROR] Parent directory for target does not exist: ${TARGET_PARENT}" >&2
    exit 1
fi
if [[ -L "${TARGET_PARENT}" ]]; then
    echo "[ERROR] Target parent directory is a symlink: ${TARGET_PARENT}" >&2
    exit 1
fi
if [[ ! -d "${SUDOERS_PARENT}" ]]; then
    echo "[ERROR] Parent directory for sudoers does not exist: ${SUDOERS_PARENT}" >&2
    exit 1
fi
if [[ -L "${SUDOERS_PARENT}" ]]; then
    echo "[ERROR] Sudoers parent directory is a symlink: ${SUDOERS_PARENT}" >&2
    exit 1
fi

# Check same-filesystem requirement between target directory and parent
if [[ -d "${TARGET_DIR}" && -d "${TARGET_PARENT}" ]]; then
    dev_target="$(stat -c "%d" "${TARGET_DIR}")"
    dev_parent="$(stat -c "%d" "${TARGET_PARENT}")"
    if [[ "${dev_target}" != "${dev_parent}" ]]; then
        echo "[ERROR] Target directory ${TARGET_DIR} and parent ${TARGET_PARENT} are on different filesystems; atomic directory rename cannot be guaranteed." >&2
        exit 1
    fi
fi

# ------------------------------------------------------------------------------
# Target Root & Parent Directory Mode Audits
# ------------------------------------------------------------------------------
target_parent_mode="$(stat -c "%a" "${TARGET_PARENT}")"
if [[ ${#target_parent_mode} -gt 3 ]]; then
    echo "[ERROR] TARGET_PARENT has special bits set (${target_parent_mode}): ${TARGET_PARENT}" >&2
    exit 1
fi
if [[ "${target_parent_mode}" =~ [2367]$ || "${target_parent_mode}" =~ [2367].$ ]]; then
    echo "[ERROR] TARGET_PARENT cannot be group- or world-writable (${target_parent_mode}): ${TARGET_PARENT}" >&2
    exit 1
fi
if [[ "${target_parent_mode}" != "755" && "${target_parent_mode}" != "750" ]]; then
    echo "[ERROR] TARGET_PARENT mode unsafe (${target_parent_mode}). Allowed modes: 0755 or 0750: ${TARGET_PARENT}" >&2
    exit 1
fi

if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
    if [[ "${PS028_TEST_TARGET_PARENT_UID:-0}" -ne 0 ]]; then
        echo "[ERROR] TARGET_PARENT must be owned by root (uid ${PS028_TEST_TARGET_PARENT_UID}): ${TARGET_PARENT}" >&2
        exit 1
    fi
    if [[ "${PS028_TEST_TARGET_PARENT_GID:-0}" -ne 0 ]]; then
        echo "[ERROR] TARGET_PARENT must have root group (gid ${PS028_TEST_TARGET_PARENT_GID}): ${TARGET_PARENT}" >&2
        exit 1
    fi
elif [[ "$(id -u)" -eq 0 ]]; then
    target_parent_uid="$(stat -c "%u" "${TARGET_PARENT}")"
    target_parent_gid="$(stat -c "%g" "${TARGET_PARENT}")"
    if [[ "${target_parent_uid}" -ne 0 || "${target_parent_gid}" -ne 0 ]]; then
        echo "[ERROR] TARGET_PARENT must be owned by root:root (uid=${target_parent_uid}, gid=${target_parent_gid}): ${TARGET_PARENT}" >&2
        exit 1
    fi
fi

if [[ -d "${TARGET_DIR}" ]]; then
    target_dir_mode="$(stat -c "%a" "${TARGET_DIR}")"
    if [[ ${#target_dir_mode} -gt 3 ]]; then
        echo "[ERROR] TARGET_DIR has special bits set (${target_dir_mode}): ${TARGET_DIR}" >&2
        exit 1
    fi
    if [[ "${target_dir_mode}" =~ [2367]$ || "${target_dir_mode}" =~ [2367].$ ]]; then
        echo "[ERROR] TARGET_DIR cannot be group- or world-writable (${target_dir_mode}): ${TARGET_DIR}" >&2
        exit 1
    fi
    if [[ "${target_dir_mode}" != "755" && "${target_dir_mode}" != "750" ]]; then
        echo "[ERROR] TARGET_DIR mode unsafe (${target_dir_mode}). Allowed modes: 0755 or 0750: ${TARGET_DIR}" >&2
        exit 1
    fi
    if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
        if [[ "${PS028_TEST_TARGET_DIR_UID:-0}" -ne 0 ]]; then
            echo "[ERROR] TARGET_DIR must be owned by root (uid ${PS028_TEST_TARGET_DIR_UID}): ${TARGET_DIR}" >&2
            exit 1
        fi
        if [[ "${PS028_TEST_TARGET_DIR_GID:-0}" -ne 0 ]]; then
            echo "[ERROR] TARGET_DIR must have root group (gid ${PS028_TEST_TARGET_DIR_GID}): ${TARGET_DIR}" >&2
            exit 1
        fi
    elif [[ "$(id -u)" -eq 0 ]]; then
        target_dir_uid="$(stat -c "%u" "${TARGET_DIR}")"
        target_dir_gid="$(stat -c "%g" "${TARGET_DIR}")"
        if [[ "${target_dir_uid}" -ne 0 || "${target_dir_gid}" -ne 0 ]]; then
            echo "[ERROR] TARGET_DIR must be owned by root:root (uid=${target_dir_uid}, gid=${target_dir_gid}): ${TARGET_DIR}" >&2
            exit 1
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Process Crash Hook (Section K)
# ------------------------------------------------------------------------------
check_test_kill_boundary() {
    local boundary="$1"
    if [[ "${IS_TEST_FIXTURE}" -eq 1 && -n "${PS028_TEST_KILL_AT:-}" ]]; then
        if [[ "${PS028_TEST_KILL_AT}" == "${boundary}" ]]; then
            echo "[TEST_SIGKILL] Delivering genuine SIGKILL at boundary ${boundary} (PID $$)" >&2
            kill -9 $$
        fi
    fi
}

# ------------------------------------------------------------------------------
# Exclusive Deployment Lock (Section I)
# ------------------------------------------------------------------------------
if [[ "${IS_TEST_FIXTURE}" -eq 0 ]]; then
    LOCK_FILE="/usr/local/libexec/.ps028_deploy.lock"
else
    LOCK_FILE="${PS028_LOCK_FILE:-${TARGET_PARENT}/.ps028_deploy.lock}"
    LOCK_PARENT_DIR="$(dirname "${LOCK_FILE}")"
    if [[ -d "${LOCK_PARENT_DIR}" ]]; then
        CANONICAL_LOCK_PARENT="$(cd "${LOCK_PARENT_DIR}" && pwd -P)"
        CANONICAL_LOCK_FILE="${CANONICAL_LOCK_PARENT}/$(basename "${LOCK_FILE}")"
        if [[ "${CANONICAL_LOCK_FILE}" != "${CANONICAL_TEST_ROOT}"/* ]]; then
            echo "[ERROR] Test fixture lock file must reside strictly within PS028_TEST_ROOT (${CANONICAL_TEST_ROOT})." >&2
            exit 1
        fi
        LOCK_FILE="${CANONICAL_LOCK_FILE}"
    fi
fi

acquire_deployment_lock() {
    if [[ -L "${LOCK_FILE}" ]]; then
        echo "[ERROR] Deployment lock file is a symlink: ${LOCK_FILE}. Refusing execution for security." >&2
        exit 1
    fi

    exec 200>>"${LOCK_FILE}"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_LOCK_CHMOD:-0}" -eq 1 ]]; then
        echo "[ERROR] Simulated lock file chmod failure: ${LOCK_FILE}" >&2
        exit 1
    fi
    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_LOCK_CHOWN:-0}" -eq 1 ]]; then
        echo "[ERROR] Simulated lock file chown failure: ${LOCK_FILE}" >&2
        exit 1
    fi

    python3 -c '
import os, sys, stat, fcntl

st200 = os.fstat(200)
if not stat.S_ISREG(st200.st_mode):
    sys.stderr.write(f"[ERROR] Lock descriptor 200 is not a regular file: mode {oct(st200.st_mode)}\n")
    sys.exit(1)

flags = fcntl.fcntl(200, fcntl.F_GETFD)
fcntl.fcntl(200, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

lock_path = sys.argv[1]
is_test = (sys.argv[2] == "1")

try:
    fd_nofollow = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    st_nofollow = os.fstat(fd_nofollow)
    os.close(fd_nofollow)
    if (st200.st_dev, st200.st_ino) != (st_nofollow.st_dev, st_nofollow.st_ino):
        sys.stderr.write(f"[ERROR] Lock descriptor 200 inode does not match {lock_path} (symlink race detected)\n")
        sys.exit(1)
except OSError as exc:
    sys.stderr.write(f"[ERROR] Lock file O_NOFOLLOW verification failed: {exc}\n")
    sys.exit(1)

if os.environ.get("PS028_TEST_LOCK_WRONG_MODE", "0") == "1":
    sys.stderr.write(f"[ERROR] Lock descriptor 200 wrong mode: {oct(st200.st_mode & 0o777)} (expected 0600)\n")
    sys.exit(1)

mode_perm = st200.st_mode & 0o777
if mode_perm != 0o600:
    try:
        os.fchmod(200, 0o600)
        st200 = os.fstat(200)
        if (st200.st_mode & 0o777) != 0o600:
            sys.stderr.write("[ERROR] Failed to set mode 0600 on lock descriptor 200\n")
            sys.exit(1)
    except OSError as exc:
        sys.stderr.write(f"[ERROR] Failed to fchmod lock descriptor 200: {exc}\n")
        sys.exit(1)

if os.environ.get("PS028_TEST_LOCK_WRONG_OWNER", "0") == "1" or (not is_test and os.geteuid() == 0 and st200.st_uid != 0):
    sys.stderr.write(f"[ERROR] Lock descriptor 200 wrong owner: UID={st200.st_uid} (expected 0)\n")
    sys.exit(1)
if os.environ.get("PS028_TEST_LOCK_WRONG_GROUP", "0") == "1" or (not is_test and os.geteuid() == 0 and st200.st_gid != 0):
    sys.stderr.write(f"[ERROR] Lock descriptor 200 wrong group: GID={st200.st_gid} (expected 0)\n")
    sys.exit(1)
' "${LOCK_FILE}" "${IS_TEST_FIXTURE}"

    if ! flock -n 200; then
        echo "[ERROR] Another instance of PS-028 privileged helper deployment or upgrade is currently running (lock held on ${LOCK_FILE})." >&2
        exit 1
    fi

    check_test_kill_boundary "AFTER_LOCK_ACQUISITION"
}

if [[ "${DRY_RUN}" -eq 0 ]]; then
    acquire_deployment_lock
fi

# ------------------------------------------------------------------------------
# Incomplete Prior Transaction Detection & Recovery (Sections C & D)
# ------------------------------------------------------------------------------
recover_prior_transaction() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        if [[ -f "${STATE_FILE}" && ! -L "${STATE_FILE}" ]]; then
            local prior_state
            prior_state="$(grep '^STATE=' "${STATE_FILE}" | cut -d= -f2 || true)"
            echo "[DRY-RUN] Notice: Pending uncommitted prior transaction detected in journal (state: ${prior_state}). Recovery would run during live deployment."
        fi
        return 0
    fi

    # Clean up stale unlinked temporary journal files from interrupted set_tx_state
    if [[ -d "${TARGET_PARENT}" ]]; then
        find "${TARGET_PARENT}" -maxdepth 1 -name ".ps028_tx_state_${TARGET_BASENAME}.tmp.*" -type f ! -type l -exec rm -f {} + 2>/dev/null || true
    fi

    if [[ -f "${STATE_FILE}" ]]; then
        if [[ -L "${STATE_FILE}" ]]; then
            echo "[ERROR] Transaction state file is a symlink: ${STATE_FILE}. Refusing recovery for security." >&2
            exit 1
        fi
        echo "[WARN] Incomplete prior transaction detected in ${STATE_FILE}. Initiating state-dependent recovery..." >&2

        python3 -c '
import sys, os, stat, json, hashlib, subprocess, shutil
from pathlib import Path

state_file = Path(sys.argv[1])
target_dir = Path(sys.argv[2])
target_sudoers = Path(sys.argv[3])
target_parent = Path(sys.argv[4])
sudoers_parent = Path(sys.argv[5])
is_test = (sys.argv[6] == "1")

if state_file.is_symlink() or not state_file.is_file():
    sys.stderr.write(f"[ERROR] Transaction state file is invalid or a symlink: {state_file}\n")
    sys.exit(1)

known_keys = {
    "STATE", "INSTALL_TYPE", "SUDOERS_EXISTED", "TARGET_DIR", "BACKUP_DIR",
    "TARGET_SUDOERS", "BACKUP_SUDOERS", "STAGING_DIR", "STAGING_SUDOERS",
    "CREATED_RUNTIME_DIRS", "ORIGINAL_SUDOERS_SHA256", "NEW_SUDOERS_SHA256", "TIMESTAMP"
}
journal = {}
with open(state_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if "=" not in line:
            sys.stderr.write(f"[ERROR] Invalid journal line (missing =): {line}\n")
            sys.exit(1)
        k, v = line.split("=", 1)
        if k in journal:
            sys.stderr.write(f"[ERROR] Duplicate key in journal: {k}\n")
            sys.exit(1)
        if k not in known_keys:
            sys.stderr.write(f"[ERROR] Unknown key in journal: {k}\n")
            sys.exit(1)
        journal[k] = v

for rk in ["INSTALL_TYPE", "SUDOERS_EXISTED", "STATE"]:
    if rk not in journal:
        sys.stderr.write(f"[ERROR] Transaction state journal has unknown/legacy schema (missing or invalid {rk}: ''). Refusing automatic recovery to prevent data loss. Manual recovery required. Journal and backups retained.\n")
        sys.exit(1)
ts_val = journal.get("TIMESTAMP", "")
if not ts_val or not ts_val.isdigit():
    sys.stderr.write(f"[ERROR] Transaction state journal has invalid or missing TIMESTAMP: {repr(ts_val)}. Manual recovery required. Journal and backups retained.\n".replace(repr(ts_val), f"'{ts_val}'"))
    sys.exit(1)
for rk in ["TARGET_DIR", "TARGET_SUDOERS"]:
    if rk not in journal:
        sys.stderr.write(f"[ERROR] Missing required key in journal: {rk}\n")
        sys.exit(1)

state = journal["STATE"]
install_type = journal["INSTALL_TYPE"]
sudoers_existed = journal["SUDOERS_EXISTED"]
j_target = Path(journal["TARGET_DIR"])
j_sudoers = Path(journal["TARGET_SUDOERS"])
j_backup = Path(journal["BACKUP_DIR"]) if journal.get("BACKUP_DIR") else None
j_sudoers_bak = Path(journal["BACKUP_SUDOERS"]) if journal.get("BACKUP_SUDOERS") else None
j_staging = Path(journal["STAGING_DIR"]) if journal.get("STAGING_DIR") else None
j_staging_sudoers = Path(journal["STAGING_SUDOERS"]) if journal.get("STAGING_SUDOERS") else None
created_rdirs = journal.get("CREATED_RUNTIME_DIRS", "").split()

if j_target.resolve() != target_dir.resolve():
    sys.stderr.write(f"[ERROR] Journal TARGET_DIR mismatch: {j_target} vs {target_dir}\n")
    sys.exit(1)
if j_sudoers.resolve() != target_sudoers.resolve():
    sys.stderr.write(f"[ERROR] Journal TARGET_SUDOERS mismatch: {j_sudoers} vs {target_sudoers}\n")
    sys.exit(1)

if j_target.resolve() != target_dir.resolve():
    sys.stderr.write(f"[ERROR] Transaction state journal TARGET_DIR mismatch or missing: journal has '{j_target}', current invocation is '{target_dir}'.\n")
    sys.exit(1)
if j_sudoers.resolve() != target_sudoers.resolve():
    sys.stderr.write(f"[ERROR] Transaction state journal TARGET_SUDOERS mismatch or missing: journal has '{j_sudoers}', current invocation is '{target_sudoers}'.\n")
    sys.exit(1)

for p, parent, prefix, name in [(j_backup, target_parent, ".ps028_backup_", "BACKUP_DIR"),
                                (j_staging, target_parent, ".ps028_staging_", "STAGING_DIR"),
                                (j_sudoers_bak, sudoers_parent, ".ps028_sudoers_backup_", "BACKUP_SUDOERS"),
                                (j_staging_sudoers, sudoers_parent, ".ps028_sudoers_stg_", "STAGING_SUDOERS")]:
    if p is not None:
        if ".." in p.parts or not str(p).startswith("/") or p.parent.resolve() != parent.resolve() or not p.name.startswith(prefix):
            sys.stderr.write(f"[ERROR] Transaction state contains invalid {name}: '{p}'. Must reside directly in {parent}.\n")
            sys.exit(1)
        if p.is_symlink():
            sys.stderr.write(f"[ERROR] {name} is a symlink: '{p}'. Refusing recovery.\n")
            sys.exit(1)

valid_states = {
    "TRANSACTION_INITIALIZED", "EXISTING_VERIFIED", "STAGING_COMPLETED",
    "TARGET_BACKUP_PREPARED", "TARGET_BACKED_UP", "TARGET_ACTIVATED",
    "SUDOERS_BACKED_UP", "SUDOERS_ACTIVATED", "POST_VERIFY_SUCCESS", "COMMITTED"
}
orig_sud_sha = journal.get("ORIGINAL_SUDOERS_SHA256", "").strip()
new_sud_sha = journal.get("NEW_SUDOERS_SHA256", "").strip()

if not install_type or install_type not in ("fresh", "upgrade"):
    sys.stderr.write(f"[ERROR] Transaction state journal has unknown/legacy schema (missing or invalid INSTALL_TYPE: '{install_type}'). Refusing automatic recovery to prevent data loss. Manual recovery required. Journal and backups retained.\n")
    sys.exit(1)
if not sudoers_existed or sudoers_existed not in ("0", "1"):
    sys.stderr.write(f"[ERROR] Transaction state journal has unknown/legacy schema (missing or invalid SUDOERS_EXISTED: '{sudoers_existed}'). Refusing automatic recovery to prevent data loss. Manual recovery required. Journal and backups retained.\n")
    sys.exit(1)
if not state or state not in valid_states:
    sys.stderr.write(f"[ERROR] Transaction state journal has unknown/invalid STATE: '{state}'. Refusing automatic recovery to prevent data loss. Manual recovery required. Journal and backups retained.\n")
    sys.exit(1)

if install_type == "fresh":
    if state in ("EXISTING_VERIFIED", "TARGET_BACKUP_PREPARED", "TARGET_BACKED_UP"):
        sq = chr(39)
        sys.stderr.write(f"[ERROR] Transaction state journal has invalid state {sq}{state}{sq} for INSTALL_TYPE=fresh. Manual recovery required. Journal and backups retained.\n")
        sys.exit(1)
    if state == "SUDOERS_BACKED_UP" and sudoers_existed != "1":
        sq = chr(39)
        sys.stderr.write(f"[ERROR] Transaction state journal has invalid state {sq}{state}{sq} for INSTALL_TYPE=fresh. Manual recovery required. Journal and backups retained.\n")
        sys.exit(1)

def norm_mode(m):
    if isinstance(m, int):
        return f"{m:04o}"
    s = str(m).strip()
    if s.startswith("0o"):
        s = s[2:]
    try:
        return f"{int(s, 8):04o}"
    except Exception:
        return str(m)

def verify_manifest(dir_path):
    mf = dir_path / "deployment_manifest.json"
    if mf.is_symlink() or not mf.is_file():
        return False, "Missing or symlink deployment_manifest.json"
    st_mf = mf.stat()
    if (st_mf.st_mode & 0o777) != 0o644:
        return False, f"Manifest mode is {oct(st_mf.st_mode)}, expected 0644"
    if not is_test and (st_mf.st_uid != 0 or st_mf.st_gid != 0):
        return False, "Manifest not owned by root:root"
    try:
        data = json.loads(mf.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in manifest: {exc}"
    if not isinstance(data, dict):
        return False, "Manifest is not a dict"
    sha = data.get("release_sha", "")
    if len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha):
        return False, f"Invalid release_sha: {sha}"
    raw_files = data.get("files", [])
    if not isinstance(raw_files, list) or len(raw_files) != 14:
        return False, "Invalid files list or file_count mismatch (expected 14 canonical files)"

    expected_files = {
        "privileged_helper.py": "0750",
        "lab/__init__.py": "0644",
        "lab/identity.py": "0644",
        "lab/concurrency.py": "0644",
        "lab/impair.py": "0644",
        "lab/run_trial.py": "0644",
        "lab/analyze.py": "0644",
        "lab/teardown.py": "0644",
        "lab/scenarios.yaml": "0644",
        "lab/dns_config.json": "0644",
        "lab/dns_server.py": "0750",
        "lab/cl_resolv.conf": "0644",
        "lab/nginx.conf": "0644",
        "lab/www/index.html": "0644",
    }
    seen = {}
    for item in raw_files:
        if not isinstance(item, dict) or "path" not in item or "sha256" not in item or "mode" not in item:
            return False, "Malformed file entry in manifest"
        p_str = item["path"]
        if p_str in seen:
            return False, f"Duplicate file entry in manifest: {p_str}"
        if p_str.startswith("/") or ".." in Path(p_str).parts or os.path.normpath(p_str) != p_str:
            return False, f"Illegal path in manifest: {p_str}"
        if p_str not in expected_files:
            return False, f"Unexpected file in manifest: {p_str}"
        # Require manifest mode fields to equal canonical expected modes
        if norm_mode(item["mode"]) != expected_files[p_str]:
            return False, f"Manifest mode field altered for {p_str}: {item['mode']} vs expected {expected_files[p_str]}"
        seen[p_str] = item

    if set(seen.keys()) != set(expected_files.keys()):
        return False, "File inventory mismatch in manifest"

    for rel_p, exp_mode in expected_files.items():
        fp = dir_path / rel_p
        if fp.is_symlink() or not fp.is_file():
            return False, f"Installed file missing or symlink: {rel_p}"
        st_f = fp.stat()
        if not is_test and (st_f.st_uid != 0 or st_f.st_gid != 0):
            return False, f"File {rel_p} not owned by root:root"
        act_mode = norm_mode(st_f.st_mode & 0o777)
        if act_mode != exp_mode:
            return False, f"File {rel_p} mode mismatch: {act_mode} vs {exp_mode}"
        act_h = hashlib.sha256(fp.read_bytes()).hexdigest()
        exp_h = seen[rel_p].get("sha256")
        if act_h != exp_h:
            return False, f"File {rel_p} hash mismatch: {act_h} vs {exp_h}"

    allowed_dirs = {".", "lab", "lab/www"}
    for root, dirs, files in os.walk(dir_path, followlinks=False):
        rel_root = str(Path(root).relative_to(dir_path))
        if rel_root not in allowed_dirs:
            return False, f"Unexpected directory: {rel_root}"
        for d in dirs:
            dp = Path(root) / d
            if dp.is_symlink():
                return False, f"Symlink directory: {dp}"
            st_d = dp.stat()
            if not is_test and (st_d.st_uid != 0 or st_d.st_gid != 0):
                return False, f"Directory {dp} not owned by root:root"
            if (st_d.st_mode & 0o777) not in (0o755, 0o750):
                return False, f"Directory {dp} unsafe mode: {oct(st_d.st_mode)}"
        for fn in files:
            fp = Path(root) / fn
            if fp.is_symlink():
                return False, f"Symlink file: {fp}"
            rel_file = str(fp.relative_to(dir_path))
            if rel_file != "deployment_manifest.json" and rel_file not in expected_files:
                return False, f"Unmanifested extra file on disk: {rel_file}"
    return True, "OK"

if state == "COMMITTED":
    if not target_dir.is_dir() or target_dir.is_symlink():
        sys.stderr.write(f"[ERROR] COMMITTED recovery failed: active target {target_dir} is not a valid directory\n")
        sys.exit(1)
    ok, msg = verify_manifest(target_dir)
    if not ok:
        sys.stderr.write(f"[ERROR] COMMITTED recovery failed: active target verification failed: {msg}\n")
        sys.exit(1)
    if not target_sudoers.is_file() or target_sudoers.is_symlink():
        sys.stderr.write(f"[ERROR] COMMITTED recovery failed: active sudoers {target_sudoers} is missing\n")
        sys.exit(1)
    st_sud = target_sudoers.stat()
    if (st_sud.st_mode & 0o777) != 0o440:
        sys.stderr.write(f"[ERROR] COMMITTED recovery failed: active sudoers mode {oct(st_sud.st_mode)} != 0440\n")
        sys.exit(1)
    if not is_test and (st_sud.st_uid != 0 or st_sud.st_gid != 0):
        sys.stderr.write("[ERROR] COMMITTED recovery failed: active sudoers not owned by root:root\n")
        sys.exit(1)
    vis_ret = subprocess.run(["visudo", "-cf", str(target_sudoers)], capture_output=True)
    if vis_ret.returncode != 0:
        sys.stderr.write("[ERROR] COMMITTED recovery failed: active sudoers failed visudo check\n")
        sys.exit(1)
    if new_sud_sha:
        act_sud_sha = hashlib.sha256(target_sudoers.read_bytes()).hexdigest()
        if act_sud_sha != new_sud_sha:
            sys.stderr.write(f"[ERROR] COMMITTED recovery failed: active sudoers SHA256 {act_sud_sha} != expected {new_sud_sha}\n")
            sys.exit(1)

    if j_backup and j_backup.is_dir() and not j_backup.is_symlink():
        shutil.rmtree(j_backup, ignore_errors=True)
    if j_sudoers_bak and j_sudoers_bak.is_file() and not j_sudoers_bak.is_symlink():
        j_sudoers_bak.unlink()
    if j_staging and j_staging.is_dir() and not j_staging.is_symlink():
        shutil.rmtree(j_staging, ignore_errors=True)
    if j_staging_sudoers and j_staging_sudoers.is_file() and not j_staging_sudoers.is_symlink():
        j_staging_sudoers.unlink()
    state_file.unlink()
    print("[OK] COMMITTED transaction verified and finalized.")
    sys.exit(0)

# Rollback uncommitted transaction
if sudoers_existed == "1":
    if state in ("SUDOERS_ACTIVATED", "POST_VERIFY_SUCCESS"):
        if not j_sudoers_bak or not j_sudoers_bak.is_file() or j_sudoers_bak.is_symlink():
            sys.stderr.write("[ERROR] Recovery failed: required sudoers backup missing/invalid. Manual recovery required.\n")
            sys.exit(1)
        st_sb = j_sudoers_bak.stat()
        if (st_sb.st_mode & 0o777) != 0o440:
            sys.stderr.write(f"[ERROR] Recovery failed: sudoers backup mode unsafe: {oct(st_sb.st_mode)}\n")
            sys.exit(1)
        if orig_sud_sha:
            act_bak_sha = hashlib.sha256(j_sudoers_bak.read_bytes()).hexdigest()
            if act_bak_sha != orig_sud_sha:
                sys.stderr.write(f"[ERROR] Recovery failed: sudoers backup hash mismatch: {act_bak_sha} vs {orig_sud_sha}\n")
                sys.exit(1)
        if target_sudoers.is_symlink():
            target_sudoers.unlink()
        shutil.move(str(j_sudoers_bak), str(target_sudoers))
        target_sudoers.chmod(0o440)
        subprocess.run(["sync", str(target_sudoers)], check=True)
        subprocess.run(["sync", str(sudoers_parent)], check=True)
    elif state in ("TARGET_BACKED_UP", "TARGET_ACTIVATED", "SUDOERS_BACKED_UP"):
        if j_sudoers_bak and j_sudoers_bak.is_file() and not j_sudoers_bak.is_symlink():
            if orig_sud_sha:
                act_bak_sha = hashlib.sha256(j_sudoers_bak.read_bytes()).hexdigest()
                if act_bak_sha != orig_sud_sha:
                    sys.stderr.write(f"[ERROR] Recovery failed: sudoers backup hash mismatch: {act_bak_sha} vs {orig_sud_sha}\n")
                    sys.exit(1)
            if target_sudoers.is_symlink():
                target_sudoers.unlink()
            shutil.move(str(j_sudoers_bak), str(target_sudoers))
            target_sudoers.chmod(0o440)
            subprocess.run(["sync", str(target_sudoers)], check=True)
            subprocess.run(["sync", str(sudoers_parent)], check=True)
    else:
        if j_sudoers_bak and j_sudoers_bak.is_file() and not j_sudoers_bak.is_symlink():
            if orig_sud_sha:
                act_bak_sha = hashlib.sha256(j_sudoers_bak.read_bytes()).hexdigest()
                if act_bak_sha != orig_sud_sha:
                    sys.stderr.write(f"[ERROR] Recovery failed: sudoers backup hash mismatch: {act_bak_sha} vs {orig_sud_sha}\n")
                    sys.exit(1)
            if target_sudoers.is_symlink():
                target_sudoers.unlink()
            shutil.move(str(j_sudoers_bak), str(target_sudoers))
            target_sudoers.chmod(0o440)
            subprocess.run(["sync", str(target_sudoers)], check=True)
            subprocess.run(["sync", str(sudoers_parent)], check=True)
elif sudoers_existed == "0":
    if target_sudoers.is_file() and not target_sudoers.is_symlink():
        target_sudoers.unlink()
        subprocess.run(["sync", str(sudoers_parent)], check=True)

if install_type == "upgrade":
    if state in ("TRANSACTION_INITIALIZED", "EXISTING_VERIFIED", "SUDOERS_BACKED_UP", "STAGING_COMPLETED", "TARGET_BACKUP_PREPARED"):
        if not target_dir.is_dir():
            if j_backup and j_backup.is_dir() and not j_backup.is_symlink():
                shutil.move(str(j_backup), str(target_dir))
            else:
                sys.stderr.write(f"[ERROR] Recovery failed: target {target_dir} is missing in state {state}\n")
                sys.exit(1)
        elif j_backup and j_backup.is_dir() and not j_backup.is_symlink():
            shutil.rmtree(j_backup, ignore_errors=True)
    else:
        if not j_backup or not j_backup.is_dir() or j_backup.is_symlink():
            sys.stderr.write("[ERROR] Recovery failed: required target backup is missing or invalid. Manual recovery required.\n")
            sys.exit(1)
        helper_in_bak = j_backup / "privileged_helper.py"
        if not helper_in_bak.is_file() or helper_in_bak.is_symlink():
            sys.stderr.write("[ERROR] Recovery failed: backup lacks privileged_helper.py. Manual recovery required.\n")
            sys.exit(1)
        if target_dir.exists():
            if target_dir.is_symlink() or target_dir.is_file():
                target_dir.unlink()
            else:
                shutil.rmtree(target_dir, ignore_errors=True)
        shutil.move(str(j_backup), str(target_dir))
elif install_type == "fresh":
    if target_dir.exists():
        if target_dir.is_symlink() or target_dir.is_file():
            target_dir.unlink()
        else:
            shutil.rmtree(target_dir, ignore_errors=True)

if j_staging and j_staging.is_dir() and not j_staging.is_symlink():
    shutil.rmtree(j_staging, ignore_errors=True)
if j_staging_sudoers and j_staging_sudoers.is_file() and not j_staging_sudoers.is_symlink():
    j_staging_sudoers.unlink()

for rdir_str in created_rdirs:
    rp = Path(rdir_str)
    if rp.is_dir() and not rp.is_symlink():
        try:
            rp.rmdir()
        except OSError:
            pass

if install_type == "upgrade" and (not target_dir.is_dir() or target_dir.is_symlink()):
    sys.stderr.write("[ERROR] Recovery failed: restored target directory is missing. Manual recovery required.\n")
    sys.exit(1)
if install_type == "fresh" and target_dir.exists():
    sys.stderr.write("[ERROR] Recovery failed: partial fresh target could not be removed. Manual recovery required.\n")
    sys.exit(1)
if sudoers_existed == "1":
    if not target_sudoers.is_file() or target_sudoers.is_symlink():
        sys.stderr.write("[ERROR] Recovery failed: restored sudoers drop-in is missing. Manual recovery required.\n")
        sys.exit(1)
    if orig_sud_sha:
        act_restored_sha = hashlib.sha256(target_sudoers.read_bytes()).hexdigest()
        if act_restored_sha != orig_sud_sha:
            sys.stderr.write(f"[ERROR] Recovery failed: restored sudoers SHA256 {act_restored_sha} != expected {orig_sud_sha}\n")
            sys.exit(1)
if sudoers_existed == "0" and target_sudoers.exists():
    sys.stderr.write("[ERROR] Recovery failed: temporary sudoers could not be removed. Manual recovery required.\n")
    sys.exit(1)

state_file.unlink()
print("[OK] Prior incomplete transaction rolled back and original state restored.")
sys.exit(0)
' "${STATE_FILE}" "${TARGET_DIR}" "${TARGET_SUDOERS}" "${TARGET_PARENT}" "${SUDOERS_PARENT}" "${IS_TEST_FIXTURE}"
    elif [[ ! -d "${TARGET_DIR}" && -d "${TARGET_PARENT}" ]]; then
        local orphaned_backup
        orphaned_backup="$(find "${TARGET_PARENT}" -maxdepth 1 -name ".ps028_backup_*" -type d 2>/dev/null | sort -r | head -n 1 || true)"
        if [[ -n "${orphaned_backup}" && -d "${orphaned_backup}" && ! -L "${orphaned_backup}" ]]; then
            if [[ "$(dirname "${orphaned_backup}")" == "${TARGET_PARENT}" && "$(basename "${orphaned_backup}")" =~ ^\.ps028_backup_ ]]; then
                echo "[WARN] Orphaned backup directory found (${orphaned_backup}) while target (${TARGET_DIR}) is missing. Recovering target from backup..." >&2
                mv "${orphaned_backup}" "${TARGET_DIR}"
                echo "[OK] Recovered target from orphaned backup." >&2
            fi
        fi
    fi
}

recover_prior_transaction

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[INFO] Running in --dry-run mode (no files will be written to host)."
fi
if [[ "${UNINSTALL}" -eq 1 ]]; then
    echo "[INFO] Running in --uninstall mode."
fi

echo "=============================================================================="
echo "PS-028 Privileged Helper Deployment Specification"
echo "Repository Root:  ${REPO_ROOT}"
echo "Target Directory: ${TARGET_DIR}"
echo "Target Sudoers:   ${TARGET_SUDOERS}"
echo "Operating User:   ${OPERATING_USER}"
echo "=============================================================================="

MODULES=(
    "identity.py"
    "concurrency.py"
    "impair.py"
    "run_trial.py"
    "analyze.py"
    "teardown.py"
    "scenarios.yaml"
    "dns_config.json"
    "dns_server.py"
    "cl_resolv.conf"
    "nginx.conf"
)

STATIC_FILES=(
    "www/index.html"
)

# ------------------------------------------------------------------------------
# Safe Uninstallation Mode
# ------------------------------------------------------------------------------
if [[ "${UNINSTALL}" -eq 1 ]]; then
    if [[ "${DRY_RUN}" -eq 0 && "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -ne 0 ]]; then
        echo "[ERROR] Uninstallation requires root privileges. Run with sudo: sudo ./lab/deploy_privileged_helper.sh --uninstall" >&2
        exit 1
    fi

    echo "[INFO] Evaluating safe uninstallation prerequisites..."

    for pid_path in "/run/ps028/dns.pid" "/run/ps028/nginx.pid"; do
        if [[ -f "${pid_path}" ]]; then
            pid_val=$(tr -d '[:space:]' < "${pid_path}" || true)
            if [[ -n "${pid_val}" && "${pid_val}" =~ ^[0-9]+$ ]] && kill -0 "${pid_val}" 2>/dev/null; then
                echo "[ERROR] Refusing uninstallation: active service detected (PID ${pid_val} from ${pid_path}). Stop all PS-028 services before uninstalling." >&2
                exit 1
            fi
        fi
    done

    for ns in ps028-cl ps028-rt ps028-sv; do
        if ip netns list 2>/dev/null | grep -qw "${ns}"; then
            echo "[ERROR] Refusing uninstallation: network namespace '${ns}' remains active. Run 'sudo ./lab/teardown.sh' before uninstalling." >&2
            exit 1
        fi
    done

    MANIFEST_PATH="${TARGET_DIR}/deployment_manifest.json"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[DRY-RUN] Safe uninstallation prerequisites passed: no active services or namespaces."
        if [[ -f "${TARGET_SUDOERS}" ]]; then
            echo "[DRY-RUN] Would remove sudoers rule: ${TARGET_SUDOERS}"
        fi
        if [[ -f "${MANIFEST_PATH}" ]]; then
            echo "[DRY-RUN] Would verify and remove installed files from manifest: ${MANIFEST_PATH}"
        fi
        echo "[DRY-RUN] Would remove empty directory: ${TARGET_DIR}/lab/www"
        echo "[DRY-RUN] Would remove empty directory: ${TARGET_DIR}/lab"
        echo "[DRY-RUN] Would remove empty directory: ${TARGET_DIR}"
        echo "[DRY-RUN] Would clean inactive PID/marker files from /run/ps028 and rmdir /run/ps028 if empty"
        echo "[DRY-RUN] Would preserve persistent state and logs in /var/log/ps028 and /var/lib/ps028"
        echo "[SUCCESS] Safe uninstallation dry-run check complete."
        exit 0
    fi

    if [[ -f "${TARGET_SUDOERS}" ]]; then
        if [[ -L "${TARGET_SUDOERS}" ]]; then
            echo "[ERROR] Sudoers rule ${TARGET_SUDOERS} is a symlink; refusing to unlink for security." >&2
            exit 1
        fi
        if grep -q "ps028-helper" "${TARGET_SUDOERS}" 2>/dev/null; then
            echo "[INFO] Removing verified sudoers rule: ${TARGET_SUDOERS}..."
            rm -f "${TARGET_SUDOERS}"
            visudo -c || true
        else
            echo "[WARN] ${TARGET_SUDOERS} does not match PS-028 signature; leaving file untouched."
        fi
    fi

    if [[ -f "${MANIFEST_PATH}" && ! -L "${MANIFEST_PATH}" ]]; then
        echo "[INFO] Verifying and removing deployed files recorded in ${MANIFEST_PATH}..."
        python3 -c '
import sys, json, hashlib, os
from pathlib import Path

target_dir = Path(sys.argv[1]).resolve()
is_test = (sys.argv[2] == "1")
manifest_path = target_dir / "deployment_manifest.json"

def norm_mode(m):
    if isinstance(m, int):
        return f"{m:04o}"
    s = str(m).strip()
    if s.startswith("0o"):
        s = s[2:]
    try:
        return f"{int(s, 8):04o}"
    except Exception:
        return str(m)

if not manifest_path.is_file() or manifest_path.is_symlink():
    sys.stderr.write(f"[ERROR] Cannot uninstall: manifest missing or symlink: {manifest_path}\n")
    sys.exit(1)

st_mf = manifest_path.stat()
if (st_mf.st_mode & 0o777) != 0o644:
    sys.stderr.write(f"[ERROR] Manifest mode is {oct(st_mf.st_mode)}, expected 0644\n")
    sys.exit(1)

if not is_test and (st_mf.st_uid != 0 or st_mf.st_gid != 0):
    sys.stderr.write("[ERROR] Manifest not owned by root:root\n")
    sys.exit(1)

try:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
except Exception as exc:
    sys.stderr.write(f"[ERROR] Manifest is invalid JSON: {exc}\n")
    sys.exit(1)

if not isinstance(manifest, dict):
    sys.stderr.write("[ERROR] Manifest is not a dictionary\n")
    sys.exit(1)

raw_files = manifest.get("files")
if not isinstance(raw_files, list) or len(raw_files) != 14:
    sys.stderr.write("[ERROR] Manifest files inventory invalid (expected 14 canonical files)\n")
    sys.exit(1)

expected_files = {
    "privileged_helper.py": "0750",
    "lab/__init__.py": "0644",
    "lab/identity.py": "0644",
    "lab/concurrency.py": "0644",
    "lab/impair.py": "0644",
    "lab/run_trial.py": "0644",
    "lab/analyze.py": "0644",
    "lab/teardown.py": "0644",
    "lab/scenarios.yaml": "0644",
    "lab/dns_config.json": "0644",
    "lab/dns_server.py": "0750",
    "lab/cl_resolv.conf": "0644",
    "lab/nginx.conf": "0644",
    "lab/www/index.html": "0644",
}

files_to_unlink = []
seen = set()
for item in raw_files:
    if not isinstance(item, dict) or "path" not in item or "sha256" not in item or "mode" not in item:
        sys.stderr.write("[ERROR] Malformed entry in manifest\n")
        sys.exit(1)
    p_str = item["path"]
    if p_str in seen:
        sys.stderr.write(f"[ERROR] Duplicate entry in manifest: {p_str}\n")
        sys.exit(1)
    if p_str.startswith("/") or ".." in Path(p_str).parts or os.path.normpath(p_str) != p_str:
        sys.stderr.write(f"[ERROR] Illegal traversal/absolute path in manifest: {p_str}\n")
        sys.exit(1)
    if p_str not in expected_files:
        sys.stderr.write(f"[ERROR] Unrecognized file in manifest: {p_str}\n")
        sys.exit(1)
    if norm_mode(item["mode"]) != expected_files[p_str]:
        sys.stderr.write(f"[ERROR] Manifest altered mode for {p_str}: {item['mode']}\n")
        sys.exit(1)
    seen.add(p_str)

    fpath = (target_dir / p_str).resolve()
    try:
        fpath.relative_to(target_dir)
    except ValueError:
        sys.stderr.write(f"[ERROR] Deletion target escapes target_dir: {fpath}\n")
        sys.exit(1)

    files_to_unlink.append((fpath, p_str, item["sha256"]))

if seen != set(expected_files.keys()):
    sys.stderr.write("[ERROR] Manifest does not match canonical 14 files inventory\n")
    sys.exit(1)

# All validation passed! Unlink verified files:
for fpath, rel, exp_h in files_to_unlink:
    if fpath.is_symlink():
        sys.stderr.write(f"[WARN] Skipping symlink: {fpath}\n")
        continue
    if not fpath.is_file():
        continue
    act_h = hashlib.sha256(fpath.read_bytes()).hexdigest()
    if act_h != exp_h:
        sys.stderr.write(f"[WARN] Preserving altered file (hash mismatch): {fpath}\n")
        continue
    try:
        fpath.unlink()
        print(f"[OK] Removed verified deployed file: {rel}")
    except OSError as err:
        sys.stderr.write(f"[ERROR] Failed to unlink {fpath}: {err}\n")
' "${TARGET_DIR}" "${IS_TEST_FIXTURE}"
        rm -f "${MANIFEST_PATH}"
    fi

    rmdir "${TARGET_DIR}/lab/www" 2>/dev/null || true
    rmdir "${TARGET_DIR}/lab" 2>/dev/null || true
    rmdir "${TARGET_DIR}" 2>/dev/null || true

    rm -f /run/ps028/dns.pid /run/ps028/nginx.pid /run/ps028/.resolv_installed_by_ps028 /run/ps028/.verify_dns.lock 2>/dev/null || true
    rmdir /run/ps028 2>/dev/null || true

    echo "[INFO] Preserved diagnostic logs and persistent state in /var/log/ps028 and /var/lib/ps028."
    echo "[SUCCESS] Privileged helper safely uninstalled."
    exit 0
fi

# ------------------------------------------------------------------------------
# Privilege Check
# ------------------------------------------------------------------------------
if [[ "${DRY_RUN}" -eq 0 && "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] Host deployment requires root privileges. Run with sudo or pass --dry-run:" >&2
    echo "  sudo ./lab/deploy_privileged_helper.sh" >&2
    echo "  ./lab/deploy_privileged_helper.sh --dry-run" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Provenance Verification (Section F)
# ------------------------------------------------------------------------------
echo "[INFO] Verifying repository source provenance and cleanliness..."

if ! git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    echo "[ERROR] Missing Git repository metadata in ${REPO_ROOT}. Cannot verify source provenance." >&2
    exit 1
fi

COMMIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD 2>/dev/null || true)"
if [[ -z "${COMMIT_SHA}" || ! "${COMMIT_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "[ERROR] Git cannot resolve a valid 40-character HEAD commit SHA. Refusing to deploy unversioned source." >&2
    exit 1
fi

if [[ "${IS_TEST_FIXTURE}" -eq 0 ]]; then
    if [[ -z "${EXPECTED_RELEASE_SHA}" ]]; then
        echo "[ERROR] Production deployment requires explicit --release-sha <SHA>. Refusing unpinned deployment." >&2
        exit 1
    fi
fi

if [[ -n "${EXPECTED_RELEASE_SHA}" ]]; then
    if [[ ! "${EXPECTED_RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "[ERROR] Release SHA must be a 40-character lowercase hexadecimal string: '${EXPECTED_RELEASE_SHA}'" >&2
        exit 1
    fi
    if [[ "${COMMIT_SHA}" != "${EXPECTED_RELEASE_SHA}" ]]; then
        echo "[ERROR] Release SHA mismatch: expected ${EXPECTED_RELEASE_SHA}, but repository HEAD is ${COMMIT_SHA}." >&2
        exit 1
    fi
fi

if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)" ]]; then
    echo "[ERROR] Working tree is dirty. Refusing to deploy from repository with uncommitted, staged, or untracked changes." >&2
    git -C "${REPO_ROOT}" status --short >&2
    exit 1
fi

echo "[OK] Source provenance verified: commit ${COMMIT_SHA} (working tree clean across entire repository)."

# ------------------------------------------------------------------------------
# Source File Integrity & Syntax Check (No Bytecode Pollution)
# ------------------------------------------------------------------------------
echo "[INFO] Verifying presence, permissions, and syntax of source modules..."
ALL_SRCS=("privileged_helper.py" "${MODULES[@]}" "${STATIC_FILES[@]}")
for mod in "${ALL_SRCS[@]}"; do
    src="${REPO_ROOT}/lab/${mod}"
    if [[ ! -f "${src}" ]]; then
        echo "[ERROR] Missing required deployment source: ${src}" >&2
        exit 1
    fi
    if [[ -L "${src}" ]]; then
        echo "[ERROR] Deployment source cannot be a symlink: ${src}" >&2
        exit 1
    fi
    src_mode="$(stat -c "%a" "${src}")"
    if [[ ${#src_mode} -gt 3 || "${src_mode}" =~ [2367]$ || "${src_mode}" =~ [2367].$ ]]; then
        echo "[ERROR] Deployment source has unsafe permissions (${src_mode}): ${src}" >&2
        exit 1
    fi
    if [[ "${mod}" == *.py ]]; then
        python3 -c "import ast, sys; ast.parse(open(sys.argv[1], 'rb').read(), filename=sys.argv[1])" "${src}"
    fi
done
echo "[OK] All source files present, strict permissions verified, Python syntax parsed."

# ------------------------------------------------------------------------------
# Service Identity Prerequisites
# ------------------------------------------------------------------------------
echo "[INFO] Auditing dedicated service identity 'ps028-sv'..."

SV_EXISTS=0
SV_UID=""
SV_GID=""
SV_GNAME=""
SV_GROUPS=""
SV_SHELL=""

if [[ "${IS_TEST_FIXTURE}" -eq 1 && -n "${PS028_MOCK_SV_EXISTS:-}" ]]; then
    if [[ "${PS028_MOCK_SV_EXISTS}" -eq 1 ]]; then
        SV_EXISTS=1
        SV_UID="${PS028_MOCK_SV_UID:-1028}"
        SV_GID="${PS028_MOCK_SV_GID:-1028}"
        SV_GNAME="${PS028_MOCK_SV_GNAME:-ps028-sv}"
        SV_GROUPS="${PS028_MOCK_SV_GROUPS:-1028}"
        SV_SHELL="${PS028_MOCK_SV_SHELL:-/usr/sbin/nologin}"
    else
        SV_EXISTS=0
    fi
else
    if id -u ps028-sv >/dev/null 2>&1; then
        SV_EXISTS=1
        SV_UID="$(id -u ps028-sv)"
        SV_GID="$(id -g ps028-sv)"
        SV_GNAME="$(id -gn ps028-sv)"
        SV_GROUPS="$(id -G ps028-sv)"
        SV_SHELL="$(getent passwd ps028-sv 2>/dev/null | cut -d: -f7 || true)"
    else
        SV_EXISTS=0
    fi
fi

if [[ "${SV_EXISTS}" -eq 0 ]]; then
    echo "[ERROR] Mandatory deployment prerequisite failed: Dedicated Nginx service user 'ps028-sv' does not exist on host." >&2
    echo "        For privilege isolation, Nginx worker cannot run under the operator account." >&2
    echo "        The service account must be pre-created by host administration: sudo useradd --system --no-create-home -s /usr/sbin/nologin ps028-sv" >&2
    exit 1
fi

PROHIBITED_GROUPS="^(root|sudo|docker|lxd|adm|wheel|shadow|disk|kmem|sys)$"

if [[ "${SV_UID}" -eq 0 || "${SV_GID}" -eq 0 ]]; then
    echo "[ERROR] Dedicated Nginx service user 'ps028-sv' cannot have root UID (${SV_UID}) or primary GID (${SV_GID})." >&2
    exit 1
fi
if [[ "${SV_GNAME}" =~ ${PROHIBITED_GROUPS} || "${SV_GID}" -eq 27 ]]; then
    echo "[ERROR] Dedicated Nginx service user 'ps028-sv' cannot belong to privileged primary group '${SV_GNAME}' (GID ${SV_GID})." >&2
    exit 1
fi
if [[ "${SV_GNAME}" != "ps028-sv" ]]; then
    echo "[ERROR] Dedicated Nginx service user 'ps028-sv' must have dedicated primary group 'ps028-sv', got '${SV_GNAME}' (GID ${SV_GID})." >&2
    exit 1
fi
if [[ $(echo "${SV_GROUPS}" | wc -w) -gt 1 ]]; then
    echo "[ERROR] Dedicated Nginx service user 'ps028-sv' has unexpected supplementary groups (${SV_GROUPS}). Must have zero supplementary groups." >&2
    exit 1
fi
if [[ "${SV_SHELL}" != "/usr/sbin/nologin" && "${SV_SHELL}" != "/bin/false" && "${SV_SHELL}" != "/sbin/nologin" && "${SV_SHELL}" != "/usr/bin/false" ]]; then
    echo "[ERROR] Dedicated Nginx service user 'ps028-sv' must have a non-interactive shell (/usr/sbin/nologin), got '${SV_SHELL}'." >&2
    exit 1
fi

echo "[OK] Dedicated service identity 'ps028-sv' verified (UID ${SV_UID}, primary group ${SV_GNAME}, zero supplementary groups, shell ${SV_SHELL})."

# ------------------------------------------------------------------------------
# Audit Existing Installation if Present (Section J)
# ------------------------------------------------------------------------------
IS_UPGRADE=0

if [[ -e "${TARGET_DIR}" ]]; then
    if [[ ! -d "${TARGET_DIR}" ]]; then
        echo "[ERROR] Target path exists and is not a directory: ${TARGET_DIR}" >&2
        exit 1
    fi
    if [[ -L "${TARGET_DIR}" ]]; then
        echo "[ERROR] Target path exists and is a symlink: ${TARGET_DIR}" >&2
        exit 1
    fi

    echo "[INFO] Existing target installation detected at ${TARGET_DIR}. Auditing existing installation integrity before upgrade..."

    AUDIT_ROOT_FLAG="1"
    if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
        AUDIT_ROOT_FLAG="0"
    elif [[ "$(id -u)" -ne 0 ]]; then
        AUDIT_ROOT_FLAG="0"
    fi

    python3 -c '
import sys, json, hashlib, os, subprocess
from pathlib import Path

target_dir = Path(sys.argv[1])
audit_root = (sys.argv[2] == "1")
migrate_unmanifested = (sys.argv[3] == "1")
repo_root = Path(sys.argv[4])
legacy_baseline_commit = sys.argv[5].strip() if len(sys.argv) > 5 else ""

def norm_mode(m):
    if isinstance(m, int):
        return f"{m:04o}"
    s = str(m).strip()
    if s.startswith("0o"):
        s = s[2:]
    try:
        return f"{int(s, 8):04o}"
    except Exception:
        return str(m)

manifest_file = target_dir / "deployment_manifest.json"
registered_files = {}

st_root = target_dir.stat()
if audit_root and (st_root.st_uid != 0 or st_root.st_gid != 0):
    sys.stderr.write(f"[ERROR] Target root unexpected ownership: UID={st_root.st_uid}, GID={st_root.st_gid}\n")
    sys.exit(1)
if st_root.st_mode & 0o022:
    sys.stderr.write(f"[ERROR] Target root is group- or world-writable: {oct(st_root.st_mode)}\n")
    sys.exit(1)
if (st_root.st_mode & 0o777) not in (0o755, 0o750):
    sys.stderr.write(f"[ERROR] Target root mode unsafe: {oct(st_root.st_mode)}. Allowed: 0755 or 0750\n")
    sys.exit(1)
if st_root.st_mode & 0o7000:
    sys.stderr.write(f"[ERROR] Target root has special bits set: {oct(st_root.st_mode)}\n")
    sys.exit(1)

if manifest_file.exists():
    if manifest_file.is_symlink():
        sys.stderr.write(f"[ERROR] Existing deployment_manifest.json is a symlink: {manifest_file}\n")
        sys.exit(1)
    st_mf = manifest_file.stat()
    if (st_mf.st_mode & 0o777) != 0o644:
        sys.stderr.write(f"[ERROR] Existing deployment_manifest.json mode is {oct(st_mf.st_mode)}, expected 0644\n")
        sys.exit(1)
    if audit_root and (st_mf.st_uid != 0 or st_mf.st_gid != 0):
        sys.stderr.write("[ERROR] Existing deployment_manifest.json not owned by root:root\n")
        sys.exit(1)

    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Existing deployment_manifest.json is invalid JSON: {exc}\n")
        sys.exit(1)

    if not isinstance(manifest, dict):
        sys.stderr.write("[ERROR] Existing manifest schema is invalid (not a dictionary).\n")
        sys.exit(1)

    expected_canonical_files = {
        "privileged_helper.py": "0750",
        "lab/__init__.py": "0644",
        "lab/identity.py": "0644",
        "lab/concurrency.py": "0644",
        "lab/impair.py": "0644",
        "lab/run_trial.py": "0644",
        "lab/analyze.py": "0644",
        "lab/teardown.py": "0644",
        "lab/scenarios.yaml": "0644",
        "lab/dns_config.json": "0644",
        "lab/dns_server.py": "0750",
        "lab/cl_resolv.conf": "0644",
        "lab/nginx.conf": "0644",
        "lab/www/index.html": "0644",
    }

    raw_files = manifest.get("files")
    if isinstance(raw_files, list):
        for idx, item in enumerate(raw_files):
            if isinstance(item, dict) and "path" in item and "sha256" in item:
                p_rel = item["path"]
                if p_rel.startswith("/") or ".." in Path(p_rel).parts or os.path.normpath(p_rel) != p_rel:
                    sys.stderr.write(f"[ERROR] Existing manifest contains illegal path: {p_rel}\n")
                    sys.exit(1)
                if p_rel in registered_files:
                    sys.stderr.write(f"[ERROR] Existing manifest contains duplicate file entry: {p_rel}\n")
                    sys.exit(1)
                if p_rel not in expected_canonical_files:
                    sys.stderr.write(f"[ERROR] Existing manifest contains unknown file: {p_rel}\n")
                    sys.exit(1)
                if "mode" in item and norm_mode(item["mode"]) != expected_canonical_files[p_rel]:
                    m_val = item.get("mode")
                    exp_m = expected_canonical_files[p_rel]
                    sys.stderr.write(f"[ERROR] Existing manifest altered mode field for {p_rel}: {m_val} vs expected {exp_m}\n")
                    sys.exit(1)
                registered_files[p_rel] = item["sha256"]
    elif isinstance(raw_files, dict):
        for p, val in raw_files.items():
            if p.startswith("/") or ".." in Path(p).parts or os.path.normpath(p) != p:
                sys.stderr.write(f"[ERROR] Existing manifest contains illegal path: {p}\n")
                sys.exit(1)
            if p not in expected_canonical_files:
                sys.stderr.write(f"[ERROR] Existing manifest contains unknown file: {p}\n")
                sys.exit(1)
            if isinstance(val, dict) and "sha256" in val:
                if "mode" in val and norm_mode(val["mode"]) != expected_canonical_files[p]:
                    m_val = val.get("mode")
                    exp_m = expected_canonical_files[p]
                    sys.stderr.write(f"[ERROR] Existing manifest altered mode field for {p}: {m_val} vs expected {exp_m}\n")
                    sys.exit(1)
                registered_files[p] = val["sha256"]
            elif isinstance(val, str):
                registered_files[p] = val
    else:
        sys.stderr.write("[ERROR] Existing manifest files section must be a list or dictionary.\n")
        sys.exit(1)

    if set(registered_files.keys()) != set(expected_canonical_files.keys()):
        sys.stderr.write("[ERROR] Existing manifest file inventory does not match canonical 14 files.\n")
        sys.exit(1)

    for rel_str, exp_h in registered_files.items():
        fpath = target_dir / rel_str
        if not fpath.exists():
            sys.stderr.write(f"[ERROR] Registered file missing from existing installation: {rel_str}\n")
            sys.exit(1)
        if fpath.is_symlink():
            sys.stderr.write(f"[ERROR] Registered file is a symlink: {rel_str}\n")
            sys.exit(1)
        if not fpath.is_file():
            sys.stderr.write(f"[ERROR] Registered path is not a regular file: {rel_str}\n")
            sys.exit(1)
        st = fpath.stat()
        if audit_root:
            if st.st_uid != 0 or st.st_gid != 0:
                sys.stderr.write(f"[ERROR] File {rel_str} unexpected ownership: UID={st.st_uid}, GID={st.st_gid}\n")
                sys.exit(1)
        if st.st_mode & 0o022:
            sys.stderr.write(f"[ERROR] File {rel_str} is group- or world-writable: {oct(st.st_mode)}\n")
            sys.exit(1)
        act_mode = norm_mode(st.st_mode & 0o777)
        if act_mode != expected_canonical_files[rel_str]:
            sys.stderr.write(f"[ERROR] Existing file mode mismatch: {rel_str} mode {act_mode} vs expected {expected_canonical_files[rel_str]}\n")
            sys.exit(1)
        act_h = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if act_h != exp_h:
            sys.stderr.write(f"[ERROR] Existing file altered (hash mismatch): {rel_str} (expected {exp_h}, actual {act_h})\n")
            sys.exit(1)

    allowed_audit_dirs = {".", "lab", "lab/www"}
    for root, dirs, files in os.walk(target_dir, followlinks=False):
        rel_root = str(Path(root).relative_to(target_dir))
        if rel_root not in allowed_audit_dirs:
            sys.stderr.write(f"[ERROR] Unexpected directory in existing installation: {rel_root}\n")
            sys.exit(1)
        for d in dirs:
            dp = Path(root) / d
            if dp.is_symlink():
                sys.stderr.write(f"[ERROR] Symlink directory detected in existing installation: {dp}\n")
                sys.exit(1)
            st_d = dp.stat()
            if audit_root and (st_d.st_uid != 0 or st_d.st_gid != 0):
                sys.stderr.write(f"[ERROR] Directory {dp} unexpected ownership: UID={st_d.st_uid}, GID={st_d.st_gid}\n")
                sys.exit(1)
            if st_d.st_mode & 0o022:
                sys.stderr.write(f"[ERROR] Directory {dp} is group- or world-writable: {oct(st_d.st_mode)}\n")
                sys.exit(1)
            if (st_d.st_mode & 0o777) not in (0o755, 0o750):
                sys.stderr.write(f"[ERROR] Directory {dp} unsafe mode: {oct(st_d.st_mode)}\n")
                sys.exit(1)
        for fn in files:
            fp = Path(root) / fn
            if fp.is_symlink():
                sys.stderr.write(f"[ERROR] Symlink detected in existing installation: {fp}\n")
                sys.exit(1)
            if fn == "deployment_manifest.json":
                continue
            rel = str(fp.relative_to(target_dir))
            if rel not in registered_files:
                sys.stderr.write(f"[ERROR] Unmanifested file detected in existing installation: {rel}\n")
                sys.exit(1)

else:
    if not migrate_unmanifested:
        sys.stderr.write(
            f"[ERROR] Existing installation at {target_dir} lacks deployment_manifest.json.\n"
            "        To safely upgrade an unmanifested legacy deployment, run with --migrate-unmanifested\n"
            "        to verify legacy file hashes against Git commit history before upgrade.\n"
        )
        sys.exit(1)

    helper_path = target_dir / "privileged_helper.py"
    if not helper_path.is_file() or helper_path.is_symlink():
        sys.stderr.write(f"[ERROR] Legacy target lacks valid privileged_helper.py: {helper_path}\n")
        sys.exit(1)

    KNOWN_HISTORICAL_FILES = {
        "privileged_helper.py",
        "lab/__init__.py",
        "lab/identity.py",
        "lab/concurrency.py",
        "lab/impair.py",
        "lab/run_trial.py",
        "lab/analyze.py",
        "lab/teardown.py",
        "lab/scenarios.yaml",
        "lab/dns_config.json",
        "lab/dns_server.py",
        "lab/cl_resolv.conf",
        "lab/nginx.conf",
        "lab/www/index.html",
    }
    MINIMUM_REQUIRED_LEGACY_FILES = {
        "privileged_helper.py",
        "lab/__init__.py",
        "lab/identity.py",
        "lab/concurrency.py",
        "lab/impair.py",
        "lab/run_trial.py",
        "lab/analyze.py",
        "lab/teardown.py",
        "lab/scenarios.yaml",
        "lab/dns_config.json",
    }
    EXECUTABLE_LEGACY_FILES = {"privileged_helper.py", "lab/dns_server.py"}
    ALLOWED_LEGACY_DIRS = {".", "lab", "lab/www", "lab/__pycache__"}

    st_root = target_dir.stat()
    if audit_root and (st_root.st_uid != 0 or st_root.st_gid != 0):
        sys.stderr.write(f"[ERROR] Legacy target root unexpected ownership: UID={st_root.st_uid}, GID={st_root.st_gid}\n")
        sys.exit(1)
    if st_root.st_mode & 0o022:
        sys.stderr.write(f"[ERROR] Legacy target root is group- or world-writable: {oct(st_root.st_mode)}\n")
        sys.exit(1)
    if (st_root.st_mode & 0o777) not in (0o755, 0o750):
        sys.stderr.write(f"[ERROR] Legacy target root mode unsafe: {oct(st_root.st_mode)}. Allowed: 0755 or 0750\n")
        sys.exit(1)

    existing_disk = {}
    for root, dirs, files in os.walk(target_dir, followlinks=False):
        rel_root = str(Path(root).relative_to(target_dir))
        if rel_root not in ALLOWED_LEGACY_DIRS:
            sys.stderr.write(f"[ERROR] Unexpected directory in legacy installation: {rel_root}\n")
            sys.exit(1)
        for d in dirs:
            dp = Path(root) / d
            if dp.is_symlink():
                sys.stderr.write(f"[ERROR] Symlink directory detected in legacy installation: {dp}\n")
                sys.exit(1)
            rel_dir = str(dp.relative_to(target_dir))
            if rel_dir not in ALLOWED_LEGACY_DIRS:
                sys.stderr.write(f"[ERROR] Unexpected directory in legacy installation: {rel_dir}\n")
                sys.exit(1)
            st_dir = dp.stat()
            if audit_root and (st_dir.st_uid != 0 or st_dir.st_gid != 0):
                sys.stderr.write(f"[ERROR] Legacy directory {rel_dir} unexpected ownership: UID={st_dir.st_uid}, GID={st_dir.st_gid}\n")
                sys.exit(1)
            if st_dir.st_mode & 0o022:
                sys.stderr.write(f"[ERROR] Legacy directory {rel_dir} is group- or world-writable: {oct(st_dir.st_mode)}\n")
                sys.exit(1)
            if (st_dir.st_mode & 0o777) not in (0o755, 0o750):
                sys.stderr.write(f"[ERROR] Legacy directory {rel_dir} mode unsafe: {oct(st_dir.st_mode)}. Allowed: 0755 or 0750\n")
                sys.exit(1)

        for fn in files:
            fp = Path(root) / fn
            if fp.is_symlink():
                sys.stderr.write(f"[ERROR] Symlink detected in legacy installation: {fp}\n")
                sys.exit(1)
            if not fp.is_file():
                sys.stderr.write(f"[ERROR] Special non-regular file detected in legacy installation: {fp}\n")
                sys.exit(1)
            rel = str(fp.relative_to(target_dir))
            st = fp.stat()
            if audit_root and (st.st_uid != 0 or st.st_gid != 0):
                sys.stderr.write(f"[ERROR] Legacy file {rel} unexpected ownership: UID={st.st_uid}, GID={st.st_gid}\n")
                sys.exit(1)
            if st.st_mode & 0o022:
                sys.stderr.write(f"[ERROR] Legacy file {rel} is group- or world-writable: {oct(st.st_mode)}\n")
                sys.exit(1)
            if st.st_mode & 0o7000:
                sys.stderr.write(f"[ERROR] Legacy file {rel} has dangerous setuid/setgid/sticky bits: {oct(st.st_mode)}\n")
                sys.exit(1)
            fmode = st.st_mode & 0o777

            # Partner legacy: allow generated Python bytecode cache files under lab/__pycache__
            if rel.startswith("lab/__pycache__/"):
                if not fn.endswith(".pyc"):
                    sys.stderr.write(f"[ERROR] Unexpected non-pyc file in legacy bytecode cache: {rel}\n")
                    sys.exit(1)
                if fmode not in (0o640, 0o644):
                    sys.stderr.write(f"[ERROR] Legacy bytecode cache {rel} mode unsafe: {oct(st.st_mode)}\n")
                    sys.exit(1)
                continue # do not treat .pyc as tracked source module

            if rel not in KNOWN_HISTORICAL_FILES:
                sys.stderr.write(f"[ERROR] Legacy installation contains unknown extra file: {rel}\n")
                sys.exit(1)

            if rel in EXECUTABLE_LEGACY_FILES:
                if fmode not in (0o750, 0o755):
                    sys.stderr.write(f"[ERROR] Legacy executable {rel} mode unsafe: {oct(st.st_mode)}. Allowed: 0750 or 0755\n")
                    sys.exit(1)
            else:
                if fmode not in (0o640, 0o644):
                    sys.stderr.write(f"[ERROR] Legacy module/config {rel} mode unsafe: {oct(st.st_mode)}. Allowed: 0640 or 0644\n")
                    sys.exit(1)
            existing_disk[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()

    disk_files = set(existing_disk.keys())
    missing_req = MINIMUM_REQUIRED_LEGACY_FILES - disk_files
    if missing_req:
        sys.stderr.write(f"[ERROR] Legacy installation is incomplete. Missing required files: {sorted(missing_req)}\n")
        sys.exit(1)

    candidate_commits = []
    if legacy_baseline_commit:
        try:
            verified_c = subprocess.check_output(
                ["git", "-C", str(repo_root), "rev-parse", "--verify", f"{legacy_baseline_commit}^{{commit}}"],
                stderr=subprocess.DEVNULL, text=True
            ).strip()
            candidate_commits.append(verified_c)
        except Exception:
            sys.stderr.write(f"[ERROR] Specified --legacy-baseline-commit is not a valid commit: {legacy_baseline_commit}\n")
            sys.exit(1)
    else:
        try:
            rev_list = subprocess.check_output(
                ["git", "-C", str(repo_root), "rev-list", "-n", "30", "HEAD"], text=True
            ).strip().splitlines()
            candidate_commits.extend(rev_list)
        except Exception:
            pass

    matching_commits = []
    for c in candidate_commits:
        all_match = True
        for rel, act_h in existing_disk.items():
            if rel == "lab/__init__.py":
                if act_h != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                    all_match = False
                    break
                continue
            git_path = f"lab/{rel}" if not rel.startswith("lab/") and (rel != "privileged_helper.py") else ("lab/privileged_helper.py" if rel == "privileged_helper.py" else rel)
            try:
                blob = subprocess.check_output(
                    ["git", "-C", str(repo_root), "show", f"{c}:{git_path}"], stderr=subprocess.DEVNULL
                )
                exp_h = hashlib.sha256(blob).hexdigest()
                if act_h != exp_h:
                    all_match = False
                    break
            except Exception:
                all_match = False
                break
        if all_match:
            matching_commits.append(c)

    if not matching_commits:
        sys.stderr.write("[ERROR] Unmanifested legacy installation does not match authentic repository commit history. Refusing to upgrade tampered unmanifested directory.\n")
        sys.exit(1)

    unique_lab_trees = set()
    for c in matching_commits:
        try:
            t_sha = subprocess.check_output(
                ["git", "-C", str(repo_root), "rev-parse", f"{c}:lab"], stderr=subprocess.DEVNULL, text=True
            ).strip()
            unique_lab_trees.add(t_sha)
        except Exception:
            pass

    if len(unique_lab_trees) > 1 and not legacy_baseline_commit:
        sys.stderr.write(
            f"[ERROR] Multiple historical commits match legacy installation with different tree states ({len(unique_lab_trees)} distinct trees). "
            "Ambiguous provenance. Specify explicit baseline with --legacy-baseline-commit <SHA>.\n"
        )
        sys.exit(1)

    matched_commit = matching_commits[0]
    print(f"[OK] Legacy unmanifested installation verified against authentic Git commit {matched_commit}.")
' "${TARGET_DIR}" "${AUDIT_ROOT_FLAG}" "${MIGRATE_UNMANIFESTED}" "${REPO_ROOT}" "${LEGACY_BASELINE_COMMIT}"

    if [[ -f "${TARGET_SUDOERS}" ]]; then
        if [[ -L "${TARGET_SUDOERS}" ]]; then
            echo "[ERROR] Existing sudoers rule is a symlink: ${TARGET_SUDOERS}." >&2
            exit 1
        fi
        if ! visudo -cf "${TARGET_SUDOERS}" >/dev/null 2>&1; then
            echo "[ERROR] Existing sudoers rule syntax validation failed with visudo." >&2
            exit 1
        fi
    fi

    echo "[OK] Existing target installation passed comprehensive integrity audit."
    IS_UPGRADE=1
fi

# ------------------------------------------------------------------------------
# Sudoers Specification Pre-validation (visudo -cf /dev/stdin)
# ------------------------------------------------------------------------------
echo "[INFO] Validating proposed sudoers specification with visudo..."
if ! visudo -cf /dev/stdin << EOF
# /etc/sudoers.d/ps028-helper (syntax validation)
User_Alias PS028_OPERATOR = ${OPERATING_USER}

PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py apply-scenario *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py restore-baseline *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py apply-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py restore-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py verify-baseline *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py start-capture *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py stop-capture *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py check-auth
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py setup-s5-counters *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py read-s5-counters *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py measure-s5 *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py launch-snap-browser *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py start-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py stop-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py status-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py start-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py stop-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py status-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py reload-dns *
EOF
then
    echo "[ERROR] Sudoers specification failed visudo validation." >&2
    exit 1
fi
echo "[OK] Proposed sudoers specification validated successfully by visudo."

# ------------------------------------------------------------------------------
# Dry-Run Completion Check (Zero Filesystem Writes)
# ------------------------------------------------------------------------------
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "------------------------------------------------------------------------------"
    echo "[DRY-RUN] All deployment prerequisites, provenance, source files, service identity, and sudoers syntax verified."
    if [[ "${IS_UPGRADE}" -eq 1 ]]; then
        echo "[DRY-RUN] Target mode: TRANSACTIONAL UPGRADE of existing installation at ${TARGET_DIR}."
    else
        echo "[DRY-RUN] Target mode: FRESH TRANSACTIONAL INSTALLATION to ${TARGET_DIR}."
    fi
    echo "[SUCCESS] Dry-run specification check complete."
    exit 0
fi

# ------------------------------------------------------------------------------
# Live Transactional Staging & State Machine (Section B, C & D)
# ------------------------------------------------------------------------------
STAGING_DIR=""
STAGING_SUDOERS=""
BACKUP_DIR=""
BACKUP_SUDOERS=""
ACTIVATION_STARTED=0
TX_STATE="IDLE"
CREATED_RUNTIME_DIRS=""
ORIGINAL_SUDOERS_SHA256=""
NEW_SUDOERS_SHA256=""

if [[ "${IS_UPGRADE}" -eq 1 ]]; then
    INSTALL_TYPE="upgrade"
else
    INSTALL_TYPE="fresh"
fi

if [[ -e "${TARGET_SUDOERS}" ]]; then
    if [[ ! -f "${TARGET_SUDOERS}" || -L "${TARGET_SUDOERS}" ]]; then
        echo "[ERROR] Pre-existing sudoers path is not a regular file or is a symlink: ${TARGET_SUDOERS}" >&2
        exit 1
    fi
    st_sud_mode="$(stat -c "%a" "${TARGET_SUDOERS}")"
    if [[ ${#st_sud_mode} -gt 3 || "${st_sud_mode}" =~ [2367]$ || "${st_sud_mode}" =~ [2367].$ ]]; then
        echo "[ERROR] Pre-existing sudoers file has unsafe mode (${st_sud_mode}): ${TARGET_SUDOERS}" >&2
        exit 1
    fi
    if [[ "${st_sud_mode}" != "440" ]]; then
        echo "[ERROR] Pre-existing sudoers file must have mode 0440, got ${st_sud_mode}: ${TARGET_SUDOERS}" >&2
        exit 1
    fi
    if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
        st_sud_uid="$(stat -c "%u" "${TARGET_SUDOERS}")"
        st_sud_gid="$(stat -c "%g" "${TARGET_SUDOERS}")"
        if [[ "${st_sud_uid}" -ne 0 || "${st_sud_gid}" -ne 0 ]]; then
            echo "[ERROR] Pre-existing sudoers file must be owned by root:root: ${TARGET_SUDOERS}" >&2
            exit 1
        fi
    fi
    if ! visudo -cf "${TARGET_SUDOERS}" >/dev/null 2>&1; then
        echo "[ERROR] Pre-existing sudoers file failed visudo validation: ${TARGET_SUDOERS}" >&2
        exit 1
    fi
    SUDOERS_EXISTED="1"
    ORIGINAL_SUDOERS_SHA256="$(sha256sum "${TARGET_SUDOERS}" | awk '{print $1}')"
else
    SUDOERS_EXISTED="0"
    ORIGINAL_SUDOERS_SHA256=""
fi

set_tx_state() {
    local state="$1"
    if [[ -z "${INSTALL_TYPE}" || ("${INSTALL_TYPE}" != "fresh" && "${INSTALL_TYPE}" != "upgrade") ]]; then
        echo "[ASSERTION_FAILED] INSTALL_TYPE not set or invalid: '${INSTALL_TYPE}'" >&2
        exit 1
    fi
    if [[ -z "${SUDOERS_EXISTED}" || ("${SUDOERS_EXISTED}" != "0" && "${SUDOERS_EXISTED}" != "1") ]]; then
        echo "[ASSERTION_FAILED] SUDOERS_EXISTED not set or invalid: '${SUDOERS_EXISTED}'" >&2
        exit 1
    fi

    local tmp_state="${TARGET_PARENT}/.ps028_tx_state_${TARGET_BASENAME}.tmp.$$"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_WRITE_STATE:-0}" -eq 1 ]]; then
        echo "[ERROR] Simulated write failure on transaction state journal: ${tmp_state}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if ! cat > "${tmp_state}" << EOF
STATE=${state}
INSTALL_TYPE=${INSTALL_TYPE}
SUDOERS_EXISTED=${SUDOERS_EXISTED}
TARGET_DIR=${TARGET_DIR}
BACKUP_DIR=${BACKUP_DIR:-}
TARGET_SUDOERS=${TARGET_SUDOERS}
BACKUP_SUDOERS=${BACKUP_SUDOERS:-}
STAGING_DIR=${STAGING_DIR:-}
STAGING_SUDOERS=${STAGING_SUDOERS:-}
CREATED_RUNTIME_DIRS=${CREATED_RUNTIME_DIRS:-}
ORIGINAL_SUDOERS_SHA256=${ORIGINAL_SUDOERS_SHA256:-}
NEW_SUDOERS_SHA256=${NEW_SUDOERS_SHA256:-}
TIMESTAMP=$(date +%s)
EOF
    then
        echo "[ERROR] Failed to write transaction state journal: ${tmp_state}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_CHMOD_STATE:-0}" -eq 1 ]]; then
        echo "[ERROR] Simulated chmod failure on transaction state journal: ${tmp_state}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if ! chmod 0600 "${tmp_state}"; then
        echo "[ERROR] Failed to set mode 0600 on transaction state journal: ${tmp_state}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
        if ! chown root:root "${tmp_state}"; then
            echo "[ERROR] Failed to set root ownership on transaction state journal: ${tmp_state}" >&2
            rm -f "${tmp_state}" 2>/dev/null || true
            exit 1
        fi
    fi

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_SYNC_FILE:-0}" -eq 1 ]]; then
        echo "[ERROR] Simulated file fsync failure on transaction state journal: ${tmp_state}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if ! sync "${tmp_state}"; then
        echo "[ERROR] Checked file synchronization failed on transaction state journal: ${tmp_state}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_RENAME_STATE:-0}" -eq 1 ]]; then
        echo "[ERROR] Simulated atomic rename failure for transaction state journal: ${tmp_state} -> ${STATE_FILE}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    if ! mv -f "${tmp_state}" "${STATE_FILE}"; then
        echo "[ERROR] Atomic rename of transaction state journal failed: ${tmp_state} -> ${STATE_FILE}" >&2
        rm -f "${tmp_state}" 2>/dev/null || true
        exit 1
    fi

    TX_STATE="${state}"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
        if [[ "${PS028_TEST_FAIL_SYNC_DIR:-0}" -eq 1 || "${PS028_TEST_FAIL_SYNC_DIR_STATE:-}" == "${state}" ]]; then
            echo "[ERROR] Simulated parent directory synchronization failure on ${TARGET_PARENT} (state: ${state})" >&2
            exit 1
        fi
    fi

    if ! sync "${TARGET_PARENT}"; then
        echo "[ERROR] Checked parent directory synchronization failed on ${TARGET_PARENT}" >&2
        exit 1
    fi
}

cleanup_and_rollback() {
    local sig="${1:-ERR}"
    local exit_code="${2:-$?}"
    if [[ "${exit_code}" -eq 0 ]]; then
        exit_code=1
    fi
    trap - EXIT HUP INT TERM ERR

    echo "[ERROR] Deployment interrupted (${sig}) or failed with exit code ${exit_code} (state: ${TX_STATE})." >&2

    if [[ "${SUDOERS_EXISTED}" == "1" ]]; then
        if [[ -n "${BACKUP_SUDOERS:-}" && -f "${BACKUP_SUDOERS}" && ! -L "${BACKUP_SUDOERS}" ]]; then
            echo "[INFO] Restoring previous sudoers rule from ${BACKUP_SUDOERS} -> ${TARGET_SUDOERS}..." >&2
            mv -f "${BACKUP_SUDOERS}" "${TARGET_SUDOERS}"
            chmod 0440 "${TARGET_SUDOERS}"
            sync "${TARGET_SUDOERS}" 2>/dev/null || true
            sync "${SUDOERS_PARENT}" 2>/dev/null || true
        fi
    elif [[ "${SUDOERS_EXISTED}" == "0" ]]; then
        if [[ -f "${TARGET_SUDOERS}" && ! -L "${TARGET_SUDOERS}" ]]; then
            echo "[INFO] Removing newly created sudoers drop-in: ${TARGET_SUDOERS}..." >&2
            rm -f "${TARGET_SUDOERS}"
            sync "${SUDOERS_PARENT}" 2>/dev/null || true
        fi
    fi

    if [[ "${IS_UPGRADE:-0}" -eq 1 ]]; then
        if [[ -n "${BACKUP_DIR:-}" && -d "${BACKUP_DIR}" && ! -L "${BACKUP_DIR}" ]]; then
            echo "[INFO] Restoring previous installation from ${BACKUP_DIR} -> ${TARGET_DIR}..." >&2
            rm -rf "${TARGET_DIR}"
            mv "${BACKUP_DIR}" "${TARGET_DIR}"
            sync "${TARGET_DIR}" 2>/dev/null || true
            sync "${TARGET_PARENT}" 2>/dev/null || true
        fi
    else
        if [[ -d "${TARGET_DIR}" && ! -L "${TARGET_DIR}" ]]; then
            echo "[INFO] Cleaning up partial fresh target installation: ${TARGET_DIR}..." >&2
            rm -rf "${TARGET_DIR}"
            sync "${TARGET_PARENT}" 2>/dev/null || true
        fi
    fi

    if [[ -n "${STAGING_DIR:-}" && -d "${STAGING_DIR}" && ! -L "${STAGING_DIR}" ]]; then
        rm -rf "${STAGING_DIR}"
    fi
    if [[ -n "${STAGING_SUDOERS:-}" && -f "${STAGING_SUDOERS}" && ! -L "${STAGING_SUDOERS}" ]]; then
        rm -f "${STAGING_SUDOERS}"
    fi

    if [[ -n "${CREATED_RUNTIME_DIRS:-}" ]]; then
        for rdir in ${CREATED_RUNTIME_DIRS}; do
            if [[ -d "${rdir}" && ! -L "${rdir}" ]]; then
                rmdir "${rdir}" 2>/dev/null || true
            fi
        done
    fi

    rm -f "${STATE_FILE:-}"
    sync "${TARGET_PARENT}" 2>/dev/null || true

    flock -u 200 2>/dev/null || true
    exec 200>&- 2>/dev/null || true

    exit "${exit_code}"
}

on_exit_cleanup() {
    local exit_code="$?"
    if [[ "${TX_STATE}" != "IDLE" && "${TX_STATE}" != "COMMITTED" ]]; then
        if [[ "${exit_code}" -eq 0 ]]; then
            exit_code=1
        fi
        cleanup_and_rollback "EXIT" "${exit_code}"
    fi
    flock -u 200 2>/dev/null || true
    exec 200>&- 2>/dev/null || true
}

trap on_exit_cleanup EXIT
trap 'cleanup_and_rollback HUP' HUP
trap 'cleanup_and_rollback INT' INT
trap 'cleanup_and_rollback TERM' TERM
trap 'cleanup_and_rollback ERR' ERR

# Initial journal state record (durable before ANY mutation!)
if [[ "${IS_UPGRADE}" -eq 1 ]]; then
    set_tx_state "EXISTING_VERIFIED"
else
    set_tx_state "TRANSACTION_INITIALIZED"
fi
check_test_kill_boundary "INITIAL_JOURNAL_CREATION"

# Sudoers backup (if pre-existing)
if [[ "${SUDOERS_EXISTED}" == "1" ]]; then
    BACKUP_SUDOERS="${SUDOERS_PARENT}/.ps028_sudoers_backup_$(date +%s)_$$"
    cp -p "${TARGET_SUDOERS}" "${BACKUP_SUDOERS}"
    chmod 0440 "${BACKUP_SUDOERS}"
    if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
        chown root:root "${BACKUP_SUDOERS}"
    fi
    h_orig="${ORIGINAL_SUDOERS_SHA256}"
    h_bak="$(sha256sum "${BACKUP_SUDOERS}" | awk '{print $1}')"
    if [[ "${h_orig}" != "${h_bak}" ]]; then
        echo "[ERROR] Sudoers backup hash mismatch: original=${h_orig}, backup=${h_bak}" >&2
        rm -f "${BACKUP_SUDOERS}"
        exit 1
    fi
    if ! sync "${BACKUP_SUDOERS}"; then
        echo "[ERROR] Checked file synchronization failed on sudoers backup: ${BACKUP_SUDOERS}" >&2
        exit 1
    fi
    if ! sync "${SUDOERS_PARENT}"; then
        echo "[ERROR] Checked parent directory synchronization failed on sudoers parent: ${SUDOERS_PARENT}" >&2
        exit 1
    fi
    set_tx_state "SUDOERS_BACKED_UP"
    check_test_kill_boundary "AFTER_SUDOERS_BACKUP"
fi

# Audit and inventory runtime directories (Section H)
if [[ "${IS_TEST_FIXTURE}" -eq 0 || -n "${PS028_TEST_RUNTIME_DIRS:-}" ]]; then
    if [[ "${IS_TEST_FIXTURE}" -eq 1 && -n "${PS028_TEST_RUNTIME_DIRS:-}" ]]; then
        read -r -a RUNTIME_DIRS <<< "${PS028_TEST_RUNTIME_DIRS}"
    else
        RUNTIME_DIRS=("/run/ps028" "/var/log/ps028" "/var/lib/ps028")
    fi

    for rdir in "${RUNTIME_DIRS[@]}"; do
        if [[ -e "${rdir}" ]]; then
            if [[ ! -d "${rdir}" || -L "${rdir}" ]]; then
                echo "[ERROR] Pre-existing runtime path ${rdir} is not a directory or is a symlink. Manual administrator action required." >&2
                exit 1
            fi
            st_mode="$(stat -c "%a" "${rdir}")"
            if [[ ${#st_mode} -gt 3 || "${st_mode}" =~ [2367]$ || "${st_mode}" =~ [2367].$ ]]; then
                echo "[ERROR] Pre-existing runtime directory ${rdir} has unsafe permissions (${st_mode}). Manual administrator action required." >&2
                exit 1
            fi
            if [[ "${st_mode}" != "755" && "${st_mode}" != "750" ]]; then
                echo "[ERROR] Pre-existing runtime directory ${rdir} mode unsafe (${st_mode}). Expected 0755 or 0750. Manual administrator action required." >&2
                exit 1
            fi
            if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
                st_uid="$(stat -c "%u" "${rdir}")"
                st_gid="$(stat -c "%g" "${rdir}")"
                if [[ "${st_uid}" -ne 0 || "${st_gid}" -ne 0 ]]; then
                    echo "[ERROR] Pre-existing runtime directory ${rdir} has incorrect ownership (UID=${st_uid}, GID=${st_gid}). Expected root:root. Manual administrator action required." >&2
                    exit 1
                fi
            fi
        else
            mkdir -p "${rdir}"
            chmod 0755 "${rdir}"
            if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
                chown root:root "${rdir}"
            fi
            CREATED_RUNTIME_DIRS="${CREATED_RUNTIME_DIRS:+${CREATED_RUNTIME_DIRS} }${rdir}"
            set_tx_state "${TX_STATE}"
            check_test_kill_boundary "AFTER_RUNTIME_MKDIR_$(basename "${rdir}")"
        fi
    done
fi

# 1. Create root-owned staging directory on the same filesystem
if [[ ! -d "${TARGET_PARENT}" ]]; then
    mkdir -p "${TARGET_PARENT}"
    chmod 0755 "${TARGET_PARENT}"
    if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
        chown root:root "${TARGET_PARENT}"
    fi
fi

STAGING_DIR="$(mktemp -d "${TARGET_PARENT}/.ps028_staging_XXXXXX")"
chmod 0700 "${STAGING_DIR}"
if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
    chown root:root "${STAGING_DIR}"
fi

echo "[INFO] Staging new helper build from immutable Git object tree in: ${STAGING_DIR}..."

# 2. Build directory layout inside staging
mkdir -p "${STAGING_DIR}/lab/www"

# 3. Extract executable helper and modules directly from immutable Git object tree (Section F)
extract_git_blob() {
    local git_rel="$1"
    local dest_path="$2"
    local mode="$3"

    local obj_type
    obj_type="$(git -C "${REPO_ROOT}" cat-file -t "${COMMIT_SHA}:${git_rel}" 2>/dev/null || true)"
    if [[ "${obj_type}" != "blob" ]]; then
        echo "[ERROR] Git object ${COMMIT_SHA}:${git_rel} is not a regular blob (type: '${obj_type}'). Refusing to deploy non-blob object." >&2
        exit 1
    fi

    git -C "${REPO_ROOT}" cat-file -p "${COMMIT_SHA}:${git_rel}" > "${dest_path}"
    chmod "${mode}" "${dest_path}"

    local extracted_h exp_h
    extracted_h="$(sha256sum "${dest_path}" | cut -d' ' -f1)"
    exp_h="$(git -C "${REPO_ROOT}" cat-file -p "${COMMIT_SHA}:${git_rel}" | sha256sum | cut -d' ' -f1)"
    if [[ "${extracted_h}" != "${exp_h}" ]]; then
        echo "[ERROR] Extracted payload hash mismatch for ${git_rel}: extracted=${extracted_h}, expected=${exp_h}" >&2
        exit 1
    fi
}

extract_git_blob "lab/privileged_helper.py" "${STAGING_DIR}/privileged_helper.py" 0750

touch "${STAGING_DIR}/lab/__init__.py"
chmod 0644 "${STAGING_DIR}/lab/__init__.py"

for mod in "${MODULES[@]}"; do
    target_mode="0644"
    if [[ "${mod}" == "dns_server.py" ]]; then
        target_mode="0750"
    fi
    extract_git_blob "lab/${mod}" "${STAGING_DIR}/lab/${mod}" "${target_mode}"
done

for sf in "${STATIC_FILES[@]}"; do
    extract_git_blob "lab/${sf}" "${STAGING_DIR}/lab/${sf}" 0644
done

if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
    chown -R root:root "${STAGING_DIR}"
fi
chmod 0755 "${STAGING_DIR}"
chmod 0755 "${STAGING_DIR}/lab"
chmod 0755 "${STAGING_DIR}/lab/www"

# 4. Generate new deployment manifest using exact source commit SHA
echo "[INFO] Generating new deployment manifest with release SHA ${COMMIT_SHA}..."
MANIFEST_STAGING="${STAGING_DIR}/deployment_manifest.json"
python3 -c '
import sys, json, hashlib, os
from pathlib import Path

staging_dir = Path(sys.argv[1])
commit_sha = sys.argv[2]
target_dir_str = sys.argv[3]

files_record = []
for p in sorted(staging_dir.rglob("*")):
    if p.is_file() and p.name != "deployment_manifest.json":
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        mode = f"{p.stat().st_mode & 0o777:04o}"
        rel = str(p.relative_to(staging_dir))
        files_record.append({"path": rel, "sha256": h, "mode": mode})

manifest = {
    "release_sha": commit_sha,
    "target_dir": target_dir_str,
    "file_count": len(files_record),
    "files": files_record
}

with open(staging_dir / "deployment_manifest.json", "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
' "${STAGING_DIR}" "${COMMIT_SHA}" "${TARGET_DIR}"

chmod 0644 "${MANIFEST_STAGING}"
if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
    chown root:root "${MANIFEST_STAGING}"
fi

# 5. Generate sudoers rule in temporary staging location and run visudo -cf
echo "[INFO] Staging sudoers drop-in and verifying syntax..."
STAGING_SUDOERS="$(mktemp "${SUDOERS_PARENT}/.ps028_sudoers_stg_XXXXXX")"

cat > "${STAGING_SUDOERS}" << EOF
# /etc/sudoers.d/ps028-helper
# PS-028 Hardened Non-Interactive Sudoers Rules
# Deployed: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Release SHA: ${COMMIT_SHA}

User_Alias PS028_OPERATOR = ${OPERATING_USER}

PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py apply-scenario *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py restore-baseline *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py apply-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py restore-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py verify-baseline *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py start-capture *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py stop-capture *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py check-auth
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py setup-s5-counters *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py read-s5-counters *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py measure-s5 *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py launch-snap-browser *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py start-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py stop-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py status-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py start-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py stop-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py status-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I ${TARGET_DIR}/privileged_helper.py reload-dns *
EOF

if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_CORRUPT_SUDOERS:-0}" -eq 1 ]]; then
    echo "CORRUPT SYNTAX" >> "${STAGING_SUDOERS}"
fi

chmod 0440 "${STAGING_SUDOERS}"
if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
    chown root:root "${STAGING_SUDOERS}"
fi

if ! visudo -cf "${STAGING_SUDOERS}"; then
    echo "[ERROR] Staged sudoers failed visudo validation. Aborting before activation." >&2
    exit 1
fi

NEW_SUDOERS_SHA256="$(sha256sum "${STAGING_SUDOERS}" | awk '{print $1}')"
if ! sync "${STAGING_SUDOERS}"; then
    echo "[ERROR] Checked file synchronization failed on staging sudoers: ${STAGING_SUDOERS}" >&2
    exit 1
fi
if ! sync "${SUDOERS_PARENT}"; then
    echo "[ERROR] Checked parent directory synchronization failed on sudoers parent: ${SUDOERS_PARENT}" >&2
    exit 1
fi

set_tx_state "STAGING_COMPLETED"
check_test_kill_boundary "AFTER_STAGING_COMPLETED"

# ------------------------------------------------------------------------------
# Transactional Activation (Explicit state transitions)
# ------------------------------------------------------------------------------
ACTIVATION_STARTED=1
echo "[INFO] Activating new installation transactionally..."

if [[ "${IS_UPGRADE}" -eq 1 ]]; then
    BACKUP_DIR="${TARGET_PARENT}/.ps028_backup_$(date +%s)_$$"
    set_tx_state "TARGET_BACKUP_PREPARED"
    check_test_kill_boundary "AFTER_BACKUP_PREPARATION"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_INTERRUPT_PRE_TARGET_MOVE:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_INT_PRE_TARGET_MOVE"
    fi

    mv "${TARGET_DIR}" "${BACKUP_DIR}"
    if ! sync "${BACKUP_DIR}"; then
        echo "[ERROR] Checked synchronization failed on target backup: ${BACKUP_DIR}" >&2
        exit 1
    fi
    if ! sync "${TARGET_PARENT}"; then
        echo "[ERROR] Checked synchronization failed on target parent directory: ${TARGET_PARENT}" >&2
        exit 1
    fi
    set_tx_state "TARGET_BACKED_UP"
    check_test_kill_boundary "AFTER_TARGET_RENAME"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_INTERRUPT_ACTIVATION:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_INT"
    fi

    if ! mv "${STAGING_DIR}" "${TARGET_DIR}"; then
        echo "[ERROR] Failed to move staging directory to target path. Initiating rollback..." >&2
        mv "${BACKUP_DIR}" "${TARGET_DIR}"
        exit 1
    fi
    if ! sync "${TARGET_DIR}"; then
        echo "[ERROR] Checked synchronization failed on target directory: ${TARGET_DIR}" >&2
        exit 1
    fi
    if ! sync "${TARGET_PARENT}"; then
        echo "[ERROR] Checked synchronization failed on target parent directory: ${TARGET_PARENT}" >&2
        exit 1
    fi
    set_tx_state "TARGET_ACTIVATED"
    check_test_kill_boundary "AFTER_TARGET_ACTIVATION"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_INTERRUPT_POST_TARGET_ACT:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_INT_POST_TARGET_ACT"
    fi
else
    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_INTERRUPT_PRE_TARGET_ACT:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_INT_PRE_TARGET_ACT"
    fi

    mv "${STAGING_DIR}" "${TARGET_DIR}"
    if ! sync "${TARGET_DIR}"; then
        echo "[ERROR] Checked synchronization failed on target directory: ${TARGET_DIR}" >&2
        exit 1
    fi
    if ! sync "${TARGET_PARENT}"; then
        echo "[ERROR] Checked synchronization failed on target parent directory: ${TARGET_PARENT}" >&2
        exit 1
    fi
    set_tx_state "TARGET_ACTIVATED"
    check_test_kill_boundary "AFTER_TARGET_ACTIVATION"

    if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_CRASH_FRESH_POST_TARGET:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_CRASH_FRESH_POST_TARGET"
    fi
fi

if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
    if [[ "${PS028_TEST_INTERRUPT_PRE_SUDOERS_ACT:-0}" -eq 1 || "${PS028_TEST_CRASH_FRESH_PRE_SUDOERS:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_INT_PRE_SUDOERS_ACT"
    fi
fi

mv -f "${STAGING_SUDOERS}" "${TARGET_SUDOERS}"
chmod 0440 "${TARGET_SUDOERS}"
if [[ "${IS_TEST_FIXTURE}" -eq 0 && "$(id -u)" -eq 0 ]]; then
    chown root:root "${TARGET_SUDOERS}"
fi
if ! sync "${TARGET_SUDOERS}"; then
    echo "[ERROR] Checked synchronization failed on activated sudoers: ${TARGET_SUDOERS}" >&2
    exit 1
fi
if ! sync "${SUDOERS_PARENT}"; then
    echo "[ERROR] Checked synchronization failed on sudoers parent directory: ${SUDOERS_PARENT}" >&2
    exit 1
fi

if ! visudo -cf "${TARGET_SUDOERS}"; then
    echo "[ERROR] Activated sudoers failed visudo check. Initiating rollback..." >&2
    cleanup_and_rollback "VISUDO_FAILED"
fi
set_tx_state "SUDOERS_ACTIVATED"
check_test_kill_boundary "AFTER_SUDOERS_ACTIVATION"

if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
    if [[ "${PS028_TEST_CRASH_POST_SUDOERS_ACT:-0}" -eq 1 || "${PS028_TEST_CRASH_FRESH_POST_SUDOERS:-0}" -eq 1 ]]; then
        cleanup_and_rollback "TEST_CRASH_POST_SUDOERS"
    fi
fi

# ------------------------------------------------------------------------------
# Post-Installation Integrity Verification (Section G)
# ------------------------------------------------------------------------------
echo "[INFO] Running post-installation integrity verification..."
check_test_kill_boundary "DURING_POST_VERIFICATION"

VERIFY_ROOT_FLAG="1"
if [[ "${IS_TEST_FIXTURE}" -eq 1 ]]; then
    VERIFY_ROOT_FLAG="0"
elif [[ "$(id -u)" -ne 0 ]]; then
    VERIFY_ROOT_FLAG="0"
fi

POST_VERIFY_SUCCESS=1
if ! python3 -c '
import sys, json, hashlib, os, subprocess
from pathlib import Path

target_dir = Path(sys.argv[1])
verify_root = (sys.argv[2] == "1")
target_sudoers = Path(sys.argv[3])
exp_sud_sha = sys.argv[4].strip()

def norm_mode(m):
    if isinstance(m, int):
        return f"{m:04o}"
    s = str(m).strip()
    if s.startswith("0o"):
        s = s[2:]
    try:
        return f"{int(s, 8):04o}"
    except Exception:
        return str(m)

manifest_file = target_dir / "deployment_manifest.json"
if not manifest_file.is_file() or manifest_file.is_symlink():
    sys.exit(1)

with open(manifest_file, "r", encoding="utf-8") as f:
    manifest = json.load(f)

expected_files = {
    "privileged_helper.py": "0750",
    "lab/__init__.py": "0644",
    "lab/identity.py": "0644",
    "lab/concurrency.py": "0644",
    "lab/impair.py": "0644",
    "lab/run_trial.py": "0644",
    "lab/analyze.py": "0644",
    "lab/teardown.py": "0644",
    "lab/scenarios.yaml": "0644",
    "lab/dns_config.json": "0644",
    "lab/dns_server.py": "0750",
    "lab/cl_resolv.conf": "0644",
    "lab/nginx.conf": "0644",
    "lab/www/index.html": "0644",
}

raw_files = manifest.get("files", [])
if not isinstance(raw_files, list) or len(raw_files) != 14:
    sys.exit(1)

seen = {}
for item in raw_files:
    p_str = item.get("path", "")
    if not p_str or p_str in seen or p_str not in expected_files:
        sys.exit(1)
    if norm_mode(item.get("mode")) != expected_files[p_str]:
        sys.exit(1)
    seen[p_str] = item

for rel_p, exp_mode in expected_files.items():
    fp = target_dir / rel_p
    if not fp.is_file() or fp.is_symlink():
        sys.exit(1)
    st = fp.stat()
    if verify_root and (st.st_uid != 0 or st.st_gid != 0):
        sys.exit(1)
    act_mode = norm_mode(st.st_mode & 0o777)
    if act_mode != exp_mode:
        sys.exit(1)
    act_h = hashlib.sha256(fp.read_bytes()).hexdigest()
    if act_h != seen[rel_p]["sha256"]:
        sys.exit(1)

# Check active sudoers file
if not target_sudoers.is_file() or target_sudoers.is_symlink():
    sys.exit(1)
st_sud = target_sudoers.stat()
if (st_sud.st_mode & 0o777) != 0o440:
    sys.exit(1)
if verify_root and (st_sud.st_uid != 0 or st_sud.st_gid != 0):
    sys.exit(1)
if exp_sud_sha:
    act_sud_sha = hashlib.sha256(target_sudoers.read_bytes()).hexdigest()
    if act_sud_sha != exp_sud_sha:
        sys.exit(1)
vis = subprocess.run(["visudo", "-cf", str(target_sudoers)], capture_output=True)
if vis.returncode != 0:
    sys.exit(1)
' "${TARGET_DIR}" "${VERIFY_ROOT_FLAG}" "${TARGET_SUDOERS}" "${NEW_SUDOERS_SHA256}"; then
    POST_VERIFY_SUCCESS=0
fi

if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_POST_VERIFY:-0}" -eq 1 ]]; then
    POST_VERIFY_SUCCESS=0
fi

if [[ "${POST_VERIFY_SUCCESS}" -eq 0 ]]; then
    echo "[ERROR] Post-installation integrity verification failed! Rolling back..." >&2
    cleanup_and_rollback "POST_VERIFY_FAILED"
fi

set_tx_state "POST_VERIFY_SUCCESS"
check_test_kill_boundary "PRE_COMMITTED"

if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_CRASH_PRE_COMMITTED:-0}" -eq 1 ]]; then
    cleanup_and_rollback "TEST_CRASH_PRE_COMMITTED"
fi

# ------------------------------------------------------------------------------
# Commit Ordering & Backup Cleanup (Section D)
# ------------------------------------------------------------------------------
set_tx_state "COMMITTED"
check_test_kill_boundary "POST_COMMITTED_PRE_CLEANUP"

if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_CRASH_POST_COMMITTED:-0}" -eq 1 ]]; then
    exit 0
fi

if [[ "${IS_TEST_FIXTURE}" -eq 1 && "${PS028_TEST_FAIL_BACKUP_CLEANUP:-0}" -eq 1 ]]; then
    echo "[ERROR] Simulated backup cleanup failure" >&2
    exit 1
fi

check_test_kill_boundary "DURING_BACKUP_CLEANUP"

if [[ -n "${BACKUP_DIR}" && -d "${BACKUP_DIR}" ]]; then
    rm -rf "${BACKUP_DIR}"
    check_test_kill_boundary "DURING_CLEANUP_BACKUPS"
fi
if [[ -n "${BACKUP_SUDOERS}" && -f "${BACKUP_SUDOERS}" ]]; then
    rm -f "${BACKUP_SUDOERS}"
    check_test_kill_boundary "DURING_CLEANUP_SUDOERS"
fi
if [[ -n "${STAGING_SUDOERS}" && -f "${STAGING_SUDOERS}" ]]; then
    rm -f "${STAGING_SUDOERS}"
fi

rm -f "${STATE_FILE}"

trap - HUP INT TERM ERR

if [[ "${IS_UPGRADE}" -eq 1 ]]; then
    echo "[SUCCESS] Hardened privileged helper upgraded successfully to ${TARGET_DIR}."
else
    echo "[SUCCESS] Hardened privileged helper deployed successfully to ${TARGET_DIR}."
fi
exit 0
