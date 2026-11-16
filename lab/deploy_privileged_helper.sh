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
OPERATING_USER="${SUDO_USER:-$(id -un)}"

DRY_RUN=0
UNINSTALL=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    echo "[INFO] Running in --dry-run mode (no files will be written to host)."
elif [[ "${1:-}" == "--uninstall" ]]; then
    UNINSTALL=1
    echo "[INFO] Running in --uninstall mode."
fi

echo "=============================================================================="
echo "PS-028 Privileged Helper Deployment Specification"
echo "Repository Root:  ${REPO_ROOT}"
echo "Target Directory: ${TARGET_DIR}"
echo "Operating User:   ${OPERATING_USER}"
echo "=============================================================================="

if [[ "${UNINSTALL}" -eq 1 ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "[ERROR] Uninstallation requires root privileges. Run with sudo: sudo ./lab/deploy_privileged_helper.sh --uninstall" >&2
        exit 1
    fi
    echo "[INFO] Removing sudoers rule: ${TARGET_SUDOERS}..."
    rm -f "${TARGET_SUDOERS}"
    echo "[INFO] Removing deployed directory: ${TARGET_DIR}..."
    rm -rf "${TARGET_DIR}"
    echo "[SUCCESS] Privileged helper successfully uninstalled."
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
)

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[DRY-RUN] Verifying presence, permissions, and syntax of source modules..."
    ALL_SRCS=("privileged_helper.py" "${MODULES[@]}")
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

    echo "[DRY-RUN] Would create directory: ${TARGET_DIR}/lab (owned root:root, mode 0755)"
    echo "[DRY-RUN] Would create file: ${TARGET_DIR}/lab/__init__.py (owned root:root, mode 0644)"
    echo "[DRY-RUN] Would copy: ${REPO_ROOT}/lab/privileged_helper.py -> ${TARGET_DIR}/privileged_helper.py (mode 0750)"
    for mod in "${MODULES[@]}"; do
        echo "[DRY-RUN] Would copy: ${REPO_ROOT}/lab/${mod} -> ${TARGET_DIR}/lab/${mod} (mode 0644)"
    done
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
ALL_SRCS=("privileged_helper.py" "${MODULES[@]}")
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

# 1. Create target directories
mkdir -p "${TARGET_DIR}/lab"
chown -R root:root "${TARGET_DIR}"
chmod 0755 "${TARGET_DIR}"
chmod 0755 "${TARGET_DIR}/lab"

# 2. Deploy executable helper and modules
cp "${REPO_ROOT}/lab/privileged_helper.py" "${TARGET_DIR}/privileged_helper.py"
chmod 0750 "${TARGET_DIR}/privileged_helper.py"
chown root:root "${TARGET_DIR}/privileged_helper.py"

touch "${TARGET_DIR}/lab/__init__.py"
chmod 0644 "${TARGET_DIR}/lab/__init__.py"
chown root:root "${TARGET_DIR}/lab/__init__.py"

for mod in "${MODULES[@]}"; do
    src="${REPO_ROOT}/lab/${mod}"
    if [[ -f "${src}" ]]; then
        cp "${src}" "${TARGET_DIR}/lab/${mod}"
        chmod 0644 "${TARGET_DIR}/lab/${mod}"
        chown root:root "${TARGET_DIR}/lab/${mod}"
    else
        echo "[ERROR] Required module file missing: ${src}" >&2
        exit 1
    fi
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
EOF

chmod 0440 "${TARGET_SUDOERS}"
visudo -cf "${TARGET_SUDOERS}"

echo "[SUCCESS] Hardened privileged helper deployed successfully to ${TARGET_DIR}."
