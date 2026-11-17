# PS-028 Non-Interactive Sudoers Configuration Specification

- **Document Version**: 2.0.0
- **Governing Milestone**: Milestone 4: Batch C5 (S5 Privilege Isolation & DNS Robustness)
- **Problem Statement**: AIORI PS-028 Happy Eyeballs Measurement Lab
- **Target File on Host**: `/etc/sudoers.d/ps028-helper`
- **Security Policy**: Non-negotiable Rule R11 (Strict Host Safety & Least Privilege)

---

## Deployment Status & Authority Boundary

| Parameter | Specification Status |
|---|---|
| **Intended Deployment Configuration** | Target path: `/etc/sudoers.d/ps028-helper`<br>Intended Owner: `root:root`<br>Intended Mode: `0440`<br>Executable Target: `/usr/local/libexec/ps028/privileged_helper.py`<br>Flags: `!setenv`, `secure_path` sanitization, strict action token formatting<br>Validation Tool: `visudo -c -f /etc/sudoers.d/ps028-helper` |
| **Actual Host Deployment Status** | **NOT INSTALLED / NOT INDEPENDENTLY VERIFIED ON CURRENT HOST**<br>Host installation is explicitly **PROHIBITED** during automated CI, evaluation, and audit tasks (Rule R11). No claim is made that the host currently has this rule installed. Testing is performed via `./lab/deploy_privileged_helper.sh --dry-run` and unprivileged fixtures only. |

---

## 1. Executive Summary & Operational Rationale

The PS-028 testbed operates three isolated Linux network namespaces (`ps028-cl`, `ps028-rt`, `ps028-sv`) interconnected via veth pairs to simulate client, dual-stack router, and web origin server topologies. Conducting Happy Eyeballs measurement campaigns requires executing kernel-level operations:
1. Applying and restoring `tc netem` latency impairments and `nftables` packet drop rules inside router and server namespaces.
2. Managing packet captures (`tcpdump`) inside the client network namespace.
3. Setting up isolated mount namespaces for browser execution and redirecting DNS resolver queries to the lab responder (`10.0.1.1`).
4. Configuring and querying dedicated router `nftables` hardware/kernel counters for Scenario S5 (IPv6 SYN Loss 50%).
5. Executing synthesized SYN connection probes inside `ps028-cl`.

To preserve the principle of least privilege and eliminate interactive password prompts during automated measurement campaigns, all kernel-level operations are isolated into a single Python script:
`lab/privileged_helper.py`

This document specifies the **exact sudoers rules** required to permit the unprivileged lab operator to execute `lab/privileged_helper.py` via `sudo -n` without entering a password.

---

## 2. Rule R11 Compliance Statement (Immutable Safety Guardrail)

> **CRITICAL ARCHITECTURAL CONSTRAINT (RULE R11)**:
> Automated test suites, test runners, subagents, and explorer/worker scripts **MUST NEVER** edit `/etc/sudoers`, modify files in `/etc/sudoers.d/`, or alter system-wide security configurations.
>
> All configuration files described herein must be **manually inspected, verified, and installed by the human system administrator** or lab host owner using `visudo`.

---

## 3. Exact Sudoers File Content (`/etc/sudoers.d/ps028-helper`)

Create the file `/etc/sudoers.d/ps028-helper` with permissions `0440` (read-only for root) containing the following exact lines:

```sudoers
# ==============================================================================
# /etc/sudoers.d/ps028-helper
# PS-028 Happy Eyeballs Measurement Lab: Privileged Helper Non-Interactive Rules
#
# Work Package: Batch C5 (Privilege Isolation & S5 Counter Management)
# Repository: <repo_root>
# ==============================================================================

# User alias for PS-028 lab operator (replace with actual operating user if different)
User_Alias PS028_OPERATOR = promotheshchatterjee

# Hardened trusted deployment location: /usr/local/libexec/ps028/
# Eliminates execution of unprivileged, user-writable repository code as root.
# Python is executed in isolated mode (-I) to prevent PYTHONPATH or CWD poisoning.
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py apply-scenario *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py restore-baseline *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py apply-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py restore-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py verify-baseline *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py start-capture *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py stop-capture *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py check-auth
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py setup-s5-counters *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py read-s5-counters *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py measure-s5 *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py launch-snap-browser *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py start-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py stop-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py status-nginx *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py start-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py stop-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py status-dns *
PS028_OPERATOR ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py reload-dns *
```

### Parameterized Template for Multi-User or Alternative Environments

If the repository is checked out by a different user or into an alternative workspace directory, deploy via `lab/deploy_privileged_helper.sh` or use the following parameterized template:

```sudoers
# Template variables: %USER%, %PYTHON_BIN%, %DEPLOY_ROOT% (e.g. /usr/local/libexec/ps028)
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py apply-scenario *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py restore-baseline *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py apply-dns *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py restore-dns *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py verify-baseline *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py start-capture *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py stop-capture *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py check-auth
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py setup-s5-counters *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py read-s5-counters *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py measure-s5 *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py launch-snap-browser *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py start-nginx *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py stop-nginx *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py status-nginx *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py start-dns *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py stop-dns *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py status-dns *
%USER% ALL=(root) NOPASSWD: %PYTHON_BIN% -I %DEPLOY_ROOT%/privileged_helper.py reload-dns *
```

---

## 4. Defense-in-Depth & Privilege Separation Architecture

The sudoers configuration delegates permissions exclusively to `lab/privileged_helper.py`. Inside `privileged_helper.py`, strict defense-in-depth mechanisms prevent privilege escalation or unintended system state modification:

1. **Strict Subcommand Validation**:
   - Only explicitly registered argparse subcommands (`apply-scenario`, `restore-baseline`, `apply-dns`, `restore-dns`, `verify-baseline`, `start-capture`, `stop-capture`, `check-auth`, `setup-s5-counters`, `read-s5-counters`, `measure-s5`, `launch-snap-browser`, `start-nginx`, `stop-nginx`, `status-nginx`, `start-dns`, `stop-dns`, `status-dns`, `reload-dns`) are accepted.
   - Any unlisted command line argument causes `argparse` to immediately exit with status code 2 without executing any privileged operations.

2. **No Shell Execution (`shell=True` Prohibited)**:
   - All subprocess calls strictly pass list arguments (`argv` lists) directly to the OS kernel via `execve`.
   - No command strings are passed through `/bin/sh` or `/bin/bash`, eliminating shell injection risks (Finding A12-CRIT-03).

3. **Narrow Namespace Scope**:
   - Privileged operations are strictly restricted to the lab's dedicated network namespaces:
     * `ps028-cl` (client)
     * `ps028-rt` (router)
     * `ps028-sv` (server)
   - Host-level network configuration is never modified.

4. **Dedicated Nftables Table Isolation**:
   - All firewall operations are confined to table `inet ps028_impair` inside `ps028-rt`.
   - The helper never runs `nft flush ruleset` or interferes with host firewall rules.

5. **Integer Bounds and Value Allowlisting**:
   - `--port`: strictly bounded to `1 <= port <= 65535`.
   - `--probe-count`: strictly bounded to `1 <= probe_count <= 500`.
   - `--concurrency`: strictly bounded to `1 <= concurrency <= 50`.
   - `--timeout`: strictly bounded to `0.05 <= timeout <= 10.0` seconds.
   - `--drop-pct`: strictly bounded to `1 <= drop_pct <= 99`.
   - `--oifname`: strictly restricted to allowlist `{"ps028-rt-sv6", "ps028-rt-sv4"}`.
   - `--netns`: strictly restricted to allowlist `{"ps028-cl"}` for probes.

6. **Privilege Dropping for Unprivileged Evidence**:
   - S5 TCP probe sockets inside `ps028-cl` run with unprivileged user permissions (UID 1000).
   - Packet capture files (`.pcap`) and capture logs are opened via descriptor validation with `O_CREAT | O_EXCL | O_NOFOLLOW`, verified `st_nlink == 1`, ownership transferred to the invoking user (`UserIdentity.uid, gid`), and written by unprivileged subprocesses (`tcpdump -Z target_user -w -`).

7. **Three-Tier Path Separation Architecture**:
   - **Tier 1 (Trusted Executable Root)**: `/usr/local/libexec/ps028/` (owned by `root:root`, mode `0755`/`0750`/`0644`).
   - **Tier 2 (Dedicated Privileged Runtime State)**: `/run/ps028` (PIDs, lock files, resolver markers), `/var/log/ps028` (daemon service logs), and `/var/lib/ps028` (persistent state). All owned by `root:root`, mode `0755`. Privileged daemons and helpers are strictly forbidden from writing runtime state into user workspaces.
   - **Tier 3 (Unprivileged Evidence Output)**: User workspace (`lab/campaigns/...` or `results/...`) where all data files are written with unprivileged user ownership under dropped privileges.

8. **Dedicated Nginx Worker Identity (`ps028-sv`)**:
   - Master process runs with root privileges strictly to bind ports 80 and 443 inside network namespace `ps028-sv`.
   - Worker processes drop privileges immediately to dedicated system service user `ps028-sv` via directive `user ps028-sv;`.
   - The worker process has read-only access to `/usr/local/libexec/ps028/lab/www/index.html` (mode `0644`).
   - The worker process is strictly prohibited from running under the operator account (`indrani`) and has zero write access to helper binaries, checkout directories, or host filesystems.

9. **Browser Executable Confinement & Ancestor Verification**:
   - `launch-snap-browser` strictly enforces approved canonical paths (`/usr/bin/google-chrome`, `/usr/bin/firefox`, `/snap/bin/chromium`, etc.).
   - All symlinks are resolved prior to validation.
   - Executables and all ancestor directories must be root-owned and not world-writable.
   - Basenames are matched against `ALLOWED_BROWSER_BINARIES` and reject all shells, interpreters, and utilities (`PROHIBITED_BROWSER_EXECUTABLES`).

10. **Race-Free Process Signalling via `pidfd`**:
    - All process signaling (`SIGTERM`, `SIGHUP`, `SIGQUIT`, `SIGKILL`) utilizes Linux `pidfd_open` and `pidfd_send_signal`.
    - Identity, command line, and network namespace are validated while holding the open kernel file descriptor.
    - Prevents PID reuse attacks and eliminates validation-to-signal race conditions.

11. **Genuinely Non-Destructive Status Inspection**:
    - `status-dns` and `status-nginx` perform read-only inspection of process state and socket bindings.
    - Status reporting never deletes or alters PID files on disk (reporting states `MISSING`, `MALFORMED`, `STALE`, `MISMATCHED`, or `VALID`).

---

## 5. Step-by-Step Installation Runbook

System administrators should execute the following sequence to install and verify the configuration:

### Preferred Method: Automated Deployment Script
```bash
# 1. Validate in dry-run mode
./lab/deploy_privileged_helper.sh --dry-run

# 2. Deploy helper and configure sudoers
sudo ./lab/deploy_privileged_helper.sh --user promotheshchatterjee
```

### Alternative Method: Manual Configuration

### Step 1: Create the Sudoers Drop-in File
Use `visudo` to create the drop-in file safely:
```bash
sudo visudo -f /etc/sudoers.d/ps028-helper
```
Paste the exact configuration from Section 3 above into the editor and save.

### Step 2: Enforce Strict File Permissions
Ensure the file is owned by `root:root` with mode `0440` (read-only):
```bash
sudo chown root:root /etc/sudoers.d/ps028-helper
sudo chmod 0440 /etc/sudoers.d/ps028-helper
```

### Step 3: Verify Sudoers File Syntax
Run `visudo -c` to verify that there are no syntax errors in the file:
```bash
sudo visudo -c -f /etc/sudoers.d/ps028-helper
```
Expected output:
```text
/etc/sudoers.d/ps028-helper: parsed OK
```

### Step 4: Validate Non-Interactive Execution
As the unprivileged operator user, test non-interactive authentication:
```bash
# Clear any cached credentials
sudo -k

# Verify non-interactive execution via check-auth
sudo -n /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py check-auth
```
Expected output:
```json
{"authorized": true, "method": "sudo -n"}
```

---

## 6. Decommissioning & Rollback Runbook

To remove the privileged helper authorization upon lab decommissioning or project completion:

```bash
# Automated uninstallation via deployment script:
sudo ./lab/deploy_privileged_helper.sh --uninstall

# Or manual removal:
sudo rm -f /etc/sudoers.d/ps028-helper
sudo rm -rf /usr/local/libexec/ps028 /run/ps028 /var/log/ps028 /var/lib/ps028
sudo visudo -c
```
Verify that `sudo -n` no longer allows passwordless execution of the helper script:
```bash
sudo -k
sudo -n /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py check-auth
```
Expected output:
```text
sudo: a password is required
```
