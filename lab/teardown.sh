#!/usr/bin/env bash
# ==============================================================================
# PS-028 Happy Eyeballs Measurement Lab: Safe Teardown Script
# Work Package A6: PS-028 Lab Hardening
#
# Delegates directly to the Python teardown controller (lab/teardown.py).
# The Python controller exclusively owns the lab lock (.lab.lock) and executes
# safe, re-entrant restoration, service shutdown, resolver cleanup, and
# topology removal in a single process.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# Root / Privileges Check
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    # Allow --dry-run, --help, and -h without root
    skip_root=0
    for arg in "$@"; do
        if [[ "$arg" == "--dry-run" || "$arg" == "--help" || "$arg" == "-h" ]]; then
            skip_root=1
            break
        fi
    done
    if [[ $skip_root -eq 0 ]]; then
        echo -e "\033[1;31m[ERROR]\033[0m This script requires root privileges to manage network namespaces and services. Please run with sudo." >&2
        exit 1
    fi
fi

# ------------------------------------------------------------------------------
# Delegate to Python Teardown Controller
# ------------------------------------------------------------------------------
exec python3 "${SCRIPT_DIR}/teardown.py" "$@"
