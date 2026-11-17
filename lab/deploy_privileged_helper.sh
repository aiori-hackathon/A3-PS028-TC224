#!/usr/bin/env bash
# ==============================================================================
# PS-028 Trusted Privileged Helper Deployment Specification
# Work Package A10 & Milestone 4 / Task P1 Security Remediation
#
# Deploys the privileged helper and its trusted execution boundary to:
#   /usr/local/libexec/ps028/
#
# Enforces:
# 1. Root ownership (root:root) and strict permissions (0755 / 0644)
# 2. Complete isolation from unprivileged, user-writable repository checkouts
# 3. Python -I (isolated mode) invocation via sudoers
# ==============================================================================

set -euo pipefail

TARGET_DIR="/usr/local/libexec/ps028"
TARGET_SUDOERS="/etc/sudoers.d/ps028-helper"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

DRY_RUN=0
UNINSTALL=0
EXPLICIT_USER=""

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Deploys the PS-028 privileged helper to /usr/local/libexec/ps028/"
    echo ""
    echo "Options:"
    echo "  --dry-run              Audit deployment specification without modifying the host"
    echo "  --user, -u <USER>      Operating username for sudoers authorization (default: current user)"
    echo "  --uninstall            Safely remove installed helper files and sudoers drop-in"
    echo "  -h, --help             Show this help message and exit"
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

if [[ -n "${EXPLICIT_USER}" ]]; then
    # Validate username conforms strictly to POSIX standard
    if [[ ! "${EXPLICIT_USER}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
        echo "[ERROR] Invalid operating username '${EXPLICIT_USER}'. Must match POSIX user pattern: ^[a-z_][a-z0-9_-]*[$]?$" >&2
        exit 1
    fi
    OPERATING_USER="${EXPLICIT_USER}"
else
    OPERATING_USER="${SUDO_USER:-$(id -un)}"
fi

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
echo "Operating User:   ${OPERATING_USER}"
echo "=============================================================================="

if [[ "${UNINSTALL}" -eq 1 ]]; then
    if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
        echo "[ERROR] Uninstallation requires root privileges. Run with sudo: sudo ./lab/deploy_privileged_helper.sh --uninstall" >&2
        exit 1
    fi

    echo "[INFO] Evaluating safe uninstallation prerequisites..."

    # 1. Refuse uninstallation if DNS or Nginx processes are active
    for pid_path in "/run/ps028/dns.pid" "/run/ps028/nginx.pid"; do
        if [[ -f "${pid_path}" ]]; then
            pid_val=$(tr -d '[:space:]' < "${pid_path}" || true)
            if [[ -n "${pid_val}" && "${pid_val}" =~ ^[0-9]+$ ]] && kill -0 "${pid_val}" 2>/dev/null; then
                echo "[ERROR] Refusing uninstallation: active service detected (PID ${pid_val} from ${pid_path}). Stop all PS-028 services before uninstalling." >&2
                exit 1
            fi
        fi
    done

    # 2. Refuse uninstallation if PS-028 network namespaces remain active
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

    # Live Safe Uninstallation
    # Remove sudoers rule only if it is a regular file containing PS-028 signature
    if [[ -f "${TARGET_SUDOERS}" ]]; then
        if [[ -L "${TARGET_SUDOERS}" ]]; then
            echo "[ERROR] Sudoers rule ${TARGET_SUDOERS} is a symlink; refusing to unlink for security." >&2
            exit 1
        fi
        if grep -q "ps028-helper" "${TARGET_SUDOERS}" 2>/dev/null; then
            echo "[INFO] Removing verified sudoers rule: ${TARGET_SUDOERS}..."
            rm -f "${TARGET_SUDOERS}"
            visudo -c
        else
            echo "[WARN] ${TARGET_SUDOERS} does not match PS-028 signature; leaving file untouched."
        fi
    fi

    # Remove only verified installed files recorded in deployment manifest
    if [[ -f "${MANIFEST_PATH}" && ! -L "${MANIFEST_PATH}" ]]; then
        echo "[INFO] Verifying and removing deployed files recorded in ${MANIFEST_PATH}..."
        python3 -c '
import sys, json, hashlib, os
from pathlib import Path

target_dir = Path(sys.argv[1])
manifest_path = target_dir / "deployment_manifest.json"
with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

for item in manifest.get("files", []):
    rel = item["path"]
    exp_h = item["sha256"]
    fpath = target_dir / rel
    if fpath.is_symlink():
        sys.stderr.write(f"[WARN] Refusing to remove symlink during uninstallation: {fpath}\n")
        continue
    if not fpath.is_file():
        continue
    act_h = hashlib.sha256(fpath.read_bytes()).hexdigest()
    if act_h != exp_h:
        sys.stderr.write(f"[WARN] Preserving altered installed file: {fpath} (hash mismatch)\n")
        continue
    try:
        fpath.unlink()
        print(f"[OK] Removed verified deployed file: {rel}")
    except OSError as err:
        sys.stderr.write(f"[ERROR] Failed to unlink {fpath}: {err}\n")
' "${TARGET_DIR}"
        rm -f "${MANIFEST_PATH}"
    fi

    # Attempt to remove empty directories only (rmdir safely fails if untracked files exist)
    rmdir "${TARGET_DIR}/lab/www" 2>/dev/null || true
    rmdir "${TARGET_DIR}/lab" 2>/dev/null || true
    rmdir "${TARGET_DIR}" 2>/dev/null || true

    # Clean inactive runtime state in /run/ps028 (never remove /var/log/ps028 or /var/lib/ps028)
    rm -f /run/ps028/dns.pid /run/ps028/nginx.pid /run/ps028/.resolv_installed_by_ps028 /run/ps028/.verify_dns.lock 2>/dev/null || true
    rmdir /run/ps028 2>/dev/null || true

    echo "[INFO] Preserved diagnostic logs and persistent state in /var/log/ps028 and /var/lib/ps028."
    echo "[SUCCESS] Privileged helper safely uninstalled."
    exit 0
fi

if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] Host deployment requires root privileges. Run with sudo or pass --dry-run:" >&2
    echo "  sudo ./lab/deploy_privileged_helper.sh" >&2
    echo "  ./lab/deploy_privileged_helper.sh --dry-run" >&2
    exit 1
fi

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

RUNTIME_DIRS=(
    "/run/ps028"
    "/var/log/ps028"
    "/var/lib/ps028"
)

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[DRY-RUN] Verifying presence, permissions, and syntax of source modules and static content..."
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
        src_mode="$(stat -c '%a' "${src}")"
        if [[ "${src_mode}" =~ [2367]$ ]]; then
            echo "[ERROR] Deployment source cannot be world-writable (${src_mode}): ${src}" >&2
            exit 1
        fi
        if [[ "${mod}" == *.py ]]; then
            python3 -m py_compile "${src}"
        fi
        echo "  [OK] Verified source: ${mod} (mode ${src_mode})"
    done

    echo "[DRY-RUN] Auditing service identity prerequisites..."
    if id -u ps028-sv >/dev/null 2>&1; then
        SV_UID="$(id -u ps028-sv 2>/dev/null || true)"
        SV_GID="$(id -g ps028-sv 2>/dev/null || true)"
        SV_GNAME="$(id -gn ps028-sv 2>/dev/null || true)"
        SV_GROUPS="$(id -G ps028-sv 2>/dev/null || true)"
        SV_SHELL="$(getent passwd ps028-sv 2>/dev/null | cut -d: -f7 || true)"
        PROHIBITED_GROUPS="^(root|sudo|docker|lxd|adm|wheel|shadow|disk|kmem|sys)$"
        if [[ "${SV_UID}" -eq 0 || "${SV_GID}" -eq 0 ]]; then
            echo "  [ERROR] Dedicated Nginx service user 'ps028-sv' has root UID (${SV_UID}) or GID (${SV_GID})." >&2
        elif [[ "${SV_GNAME}" =~ ${PROHIBITED_GROUPS} || "${SV_GID}" -eq 27 ]]; then
            echo "  [ERROR] Dedicated Nginx service user 'ps028-sv' cannot belong to privileged primary group '${SV_GNAME}' (GID ${SV_GID})." >&2
        elif [[ "${SV_GNAME}" != "ps028-sv" ]]; then
            echo "  [ERROR] Dedicated Nginx service user 'ps028-sv' must have dedicated primary group 'ps028-sv', got '${SV_GNAME}' (GID ${SV_GID})." >&2
        elif [[ $(echo "${SV_GROUPS}" | wc -w) -gt 1 ]]; then
            echo "  [ERROR] Dedicated Nginx service user 'ps028-sv' has supplementary groups (${SV_GROUPS}). Must have zero supplementary groups." >&2
        elif [[ "${SV_SHELL}" != "/usr/sbin/nologin" && "${SV_SHELL}" != "/bin/false" && "${SV_SHELL}" != "/sbin/nologin" && "${SV_SHELL}" != "/usr/bin/false" ]]; then
            echo "  [ERROR] Dedicated Nginx service user 'ps028-sv' has interactive shell '${SV_SHELL}'. Must be non-interactive (/usr/sbin/nologin)." >&2
        else
            echo "  [OK] Dedicated Nginx service user 'ps028-sv' exists (UID ${SV_UID}, primary group ${SV_GNAME} [GID ${SV_GID}], zero supplementary groups, shell ${SV_SHELL})"
        fi
    else
        echo "  [PREREQUISITE NOTICE] Dedicated Nginx service user 'ps028-sv' is not present on host."
        echo "                        Must be created before starting live Nginx: sudo useradd --system --no-create-home -s /usr/sbin/nologin ps028-sv"
    fi

    echo "[DRY-RUN] Auditing browser executable prerequisites..."
    for b_exe in "/usr/bin/google-chrome" "/usr/bin/firefox"; do
        if [[ -x "${b_exe}" ]]; then
            echo "  [OK] Found executable browser binary: ${b_exe}"
        else
            echo "  [INFO] Browser binary ${b_exe} not present at default path"
        fi
    done

    echo "[DRY-RUN] Auditing runtime parent directories..."
    for parent_dir in "/usr/local/libexec" "/run" "/var/log" "/var/lib"; do
        if [[ -d "${parent_dir}" ]]; then
            p_uid="$(stat -c '%u' "${parent_dir}")"
            p_mode="$(stat -c '%a' "${parent_dir}")"
            echo "  [OK] Runtime parent directory exists: ${parent_dir} (owner UID ${p_uid}, mode ${p_mode})"
        fi
    done

    echo "[DRY-RUN] Would create directory: ${TARGET_DIR}/lab (owned root:root, mode 0755)"
    echo "[DRY-RUN] Would create directory: ${TARGET_DIR}/lab/www (owned root:root, mode 0755)"
    for rdir in "${RUNTIME_DIRS[@]}"; do
        echo "[DRY-RUN] Would create privileged runtime directory: ${rdir} (owned root:root, mode 0755)"
    done
    echo "[DRY-RUN] Would create file: ${TARGET_DIR}/lab/__init__.py (owned root:root, mode 0644)"
    echo "[DRY-RUN] Would copy: ${REPO_ROOT}/lab/privileged_helper.py -> ${TARGET_DIR}/privileged_helper.py (mode 0750)"
    for mod in "${MODULES[@]}"; do
        target_mode="0644"
        if [[ "${mod}" == "dns_server.py" ]]; then
            target_mode="0750"
        fi
        echo "[DRY-RUN] Would copy: ${REPO_ROOT}/lab/${mod} -> ${TARGET_DIR}/lab/${mod} (mode ${target_mode})"
    done
    for sf in "${STATIC_FILES[@]}"; do
        echo "[DRY-RUN] Would copy: ${REPO_ROOT}/lab/${sf} -> ${TARGET_DIR}/lab/${sf} (mode 0644)"
    done

    echo "[DRY-RUN] Verifying sudoers specification syntax with visudo..."
    TMP_SUDOERS="$(mktemp /tmp/ps028_sudoers_dryrun_XXXXXX)"
    cat > "${TMP_SUDOERS}" << EOF
# /etc/sudoers.d/ps028-helper (dry-run validation)
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
    visudo -cf "${TMP_SUDOERS}"
    echo "[DRY-RUN] Generated sudoers specification content:"
    cat "${TMP_SUDOERS}"
    rm -f "${TMP_SUDOERS}"

    echo "[DRY-RUN] Would write hardened sudoers specification to: ${TARGET_SUDOERS} (mode 0440)"
    echo "[SUCCESS] Dry-run specification check complete."
    exit 0
fi

# Rollback trap on unexpected error during live installation
rollback_on_failure() {
    local exit_code="$?"
    echo "[ERROR] Deployment failed (exit code: ${exit_code}). Rolling back partial deployment..." >&2
    rm -rf "${TARGET_DIR}"
    rm -f "${TARGET_SUDOERS}"
    exit "${exit_code}"
}
trap rollback_on_failure ERR

# Pre-deployment validation of sources
ALL_SRCS=("privileged_helper.py" "${MODULES[@]}" "${STATIC_FILES[@]}")
for mod in "${ALL_SRCS[@]}"; do
    src="${REPO_ROOT}/lab/${mod}"
    if [[ ! -f "${src}" ]]; then
        echo "[ERROR] Required deployment source missing: ${src}" >&2
        exit 1
    fi
    if [[ -L "${src}" ]]; then
        echo "[ERROR] Deployment source cannot be a symlink: ${src}" >&2
        exit 1
    fi
    src_mode="$(stat -c '%a' "${src}")"
    if [[ "${src_mode}" =~ [2367]$ ]]; then
        echo "[ERROR] Deployment source cannot be world-writable (${src_mode}): ${src}" >&2
        exit 1
    fi
done

# Verify dedicated service identity exists on host before live deployment
if ! id -u ps028-sv >/dev/null 2>&1; then
    echo "[ERROR] Prerequisite failed: Dedicated Nginx service user 'ps028-sv' does not exist on host." >&2
    echo "        For privilege isolation, Nginx worker cannot run under the operator account." >&2
    echo "        Create service user: sudo useradd --system --no-create-home -s /usr/sbin/nologin ps028-sv" >&2
    exit 1
fi

SV_UID="$(id -u ps028-sv 2>/dev/null || true)"
SV_GID="$(id -g ps028-sv 2>/dev/null || true)"
SV_GNAME="$(id -gn ps028-sv 2>/dev/null || true)"
SV_GROUPS="$(id -G ps028-sv 2>/dev/null || true)"
SV_SHELL="$(getent passwd ps028-sv 2>/dev/null | cut -d: -f7 || true)"
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

# 1. Create target directories and dedicated runtime directories
mkdir -p "${TARGET_DIR}/lab/www"
chown -R root:root "${TARGET_DIR}"
chmod 0755 "${TARGET_DIR}"
chmod 0755 "${TARGET_DIR}/lab"
chmod 0755 "${TARGET_DIR}/lab/www"

for rdir in "${RUNTIME_DIRS[@]}"; do
    mkdir -p "${rdir}"
    chown root:root "${rdir}"
    chmod 0755 "${rdir}"
done

# 2. Deploy executable helper and modules
cp "${REPO_ROOT}/lab/privileged_helper.py" "${TARGET_DIR}/privileged_helper.py"
chmod 0750 "${TARGET_DIR}/privileged_helper.py"
chown root:root "${TARGET_DIR}/privileged_helper.py"

touch "${TARGET_DIR}/lab/__init__.py"
chmod 0644 "${TARGET_DIR}/lab/__init__.py"
chown root:root "${TARGET_DIR}/lab/__init__.py"

for mod in "${MODULES[@]}"; do
    src="${REPO_ROOT}/lab/${mod}"
    target_mode="0644"
    if [[ "${mod}" == "dns_server.py" ]]; then
        target_mode="0750"
    fi
    cp "${src}" "${TARGET_DIR}/lab/${mod}"
    chmod "${target_mode}" "${TARGET_DIR}/lab/${mod}"
    chown root:root "${TARGET_DIR}/lab/${mod}"
done

for sf in "${STATIC_FILES[@]}"; do
    src="${REPO_ROOT}/lab/${sf}"
    cp "${src}" "${TARGET_DIR}/lab/${sf}"
    chmod 0644 "${TARGET_DIR}/lab/${sf}"
    chown root:root "${TARGET_DIR}/lab/${sf}"
done

# 3. Create hardened sudoers rule
cat > "${TARGET_SUDOERS}" << EOF
# /etc/sudoers.d/ps028-helper
# PS-028 Hardened Non-Interactive Sudoers Rules
# Deployed: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

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

chmod 0440 "${TARGET_SUDOERS}"
visudo -cf "${TARGET_SUDOERS}"

# 4. Generate deployment integrity manifest
COMMIT_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "002a17d673b0c07162eb55fa6a3b81cf07e153c4")"
MANIFEST_FILE="${TARGET_DIR}/deployment_manifest.json"
echo "[INFO] Generating deployment integrity manifest: ${MANIFEST_FILE}..."
python3 -c '
import sys, json, hashlib, os
from pathlib import Path

target_dir = Path(sys.argv[1])
commit_sha = sys.argv[2]
files_record = []
for p in sorted(target_dir.rglob("*")):
    if p.is_file() and p.name != "deployment_manifest.json":
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        mode = oct(p.stat().st_mode & 0o777)
        rel = str(p.relative_to(target_dir))
        files_record.append({"path": rel, "sha256": h, "mode": mode})

manifest = {
    "release_sha": commit_sha,
    "target_dir": str(target_dir),
    "file_count": len(files_record),
    "files": files_record
}
with open(target_dir / "deployment_manifest.json", "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
' "${TARGET_DIR}" "${COMMIT_SHA}"
chmod 0644 "${MANIFEST_FILE}"
chown root:root "${MANIFEST_FILE}"

echo "[SUCCESS] Hardened privileged helper deployed successfully to ${TARGET_DIR}."
