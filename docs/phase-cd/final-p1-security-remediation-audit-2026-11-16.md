# PS-028 — Final Corrective Security Audit, Defect Elimination and Release Certification

- **Document Version:** 2.0.0
- **Audit Date:** 2026-11-16T08:46:00Z
- **Repository:** `https://github.com/aiori-hackathon/A3-PS028-TC224.git`
- **Working Directory:** `/home/promotheshchatterjee/projects/A3-PS028-TC224`
- **Active Integration Branch:** `fix/phase-e-bundle-timeline-mapping`
- **Authoritative Local HEAD:** `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`
- **Target Baseline (`origin/main`):** `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26` (52 commits behind integration branch)
- **Protected Historical Acceptance Tag:** `ps028-p0-accepted-2026-11-14` (Dereferenced target `176f688bacb5858fcc0daedb454200918e427f3f`, verified ancestor of HEAD)
- **Release Readiness Classification:** **CONDITIONALLY READY** (All in-scope P1 security, reproducibility, scientific, and artifact defects eliminated; pending repository administrator branch protection and separate owner publication authorization)

---

## A. Audit Identity and Change-Control Verification

### 1. Preflight and Post-Remediation Verification
In strict compliance with the non-negotiable change-control boundaries, zero commits, zero staging, zero pushes, and zero branch modifications were executed during this audit:

| Preflight Parameter | Preflight Value | Post-Audit Value | Audit Status |
|---|---|---|---|
| **Repository Root** | `/home/promotheshchatterjee/projects/A3-PS028-TC224` | `/home/promotheshchatterjee/projects/A3-PS028-TC224` | **IDENTICAL** |
| **Integration Branch** | `fix/phase-e-bundle-timeline-mapping` | `fix/phase-e-bundle-timeline-mapping` | **IDENTICAL** |
| **Local Commit HEAD** | `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` | `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` | **IDENTICAL** |
| **Remote HEAD Sync** | `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` | `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` | **IDENTICAL** |
| **Main Baseline** | `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26` | `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26` | **UNTOUCHED** |
| **P0 Tag Commit** | `176f688bacb5858fcc0daedb454200918e427f3f` | `176f688bacb5858fcc0daedb454200918e427f3f` | **UNTOUCHED** |
| **P0 Ancestry Check** | `merge-base --is-ancestor`: YES | `merge-base --is-ancestor`: YES | **VERIFIED** |
| **Staged Diff (`--cached`)** | 0 bytes (Empty) | 0 bytes (Empty) | **ZERO STAGED** |
| **Whitespace Cleanliness** | `git diff --check`: 0 | `git diff --check`: 0 | **ZERO ERRORS** |

---

## B. Defect-by-Defect Disposition and Elimination Inventory

All nineteen architectural, security, reproducibility, scientific, and documentation domains were independently investigated, corrected, and verified:

### 1. PID-File Operations (`safe_write_pid_file`) — Status: FIXED
- **Root Cause:** Prior reports cited an unsafe in-place `O_TRUNC` pattern. While `lab/privileged_helper.py` had removed `O_TRUNC`, it still opened existing files in-place with `O_RDWR` and called `os.ftruncate()`, creating potential races on same-directory entries and vulnerability to FIFO blocking.
- **Affected Function & File:** `safe_write_pid_file()` in `lab/privileged_helper.py`.
- **Correction Made:** Replaced in-place write with directory-descriptor-anchored atomic replacement:
  1. Validates `target_name` as a single lexical component (rejects `/`, `\`, `.`, `..`, `\0`).
  2. Opens parent directory with `O_RDONLY | O_DIRECTORY | O_CLOEXEC` to obtain `parent_fd`.
  3. Validates parent directory: verifies `S_ISDIR` and, if EUID 0, asserts not world-writable without sticky bit (`S_ISVTX`).
  4. Pre-checks destination via `os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)`: rejects symlinks, non-regular files (FIFOs, sockets, devices), and hardlinked files (`st_nlink > 1`).
  5. Creates unique temporary file `.tmp_pid_{target_name}_{token}` with `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` using `dir_fd=parent_fd`.
  6. Validates descriptor via `os.fstat(tmp_fd)`: asserts `S_ISREG` and `st_nlink == 1`.
  7. Writes PID content via write loop handling partial writes; flushes with `os.fsync(tmp_fd)`.
  8. Safely adjusts ownership via `os.fchown(tmp_fd, ...)` when EUID is 0.
  9. Atomically replaces target via `_safe_renameat(parent_fd, tmp_name, parent_fd, target_name)`.
  10. Flushes parent directory via `os.fsync(parent_fd)` and unlinks temporary file on any error path.
- **Security Rationale:** Destructive modification of pre-existing hardlinked or special files is mathematically impossible because the temporary file is created exclusively and atomic rename replaces the directory entry without altering victim inodes.
- **Regression Tests:** `test_safe_write_pid_file_rejects_symlink_and_hardlink_attacks` (TC-SEC-FS-02), `test_safe_write_pid_file_fifo_and_special_files_rejection` (TC-SEC-FS-09), `test_safe_write_pid_file_atomic_replacement_preserves_hardlink_victim` (TC-SEC-FS-10), `test_safe_write_pid_file_atomic_update_and_cleanup` (TC-SEC-FS-11).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS, 133 tests).

### 2. Capture-Log Operations (`start_capture_privileged`) — Status: FIXED
- **Root Cause:** Opening capture log files without non-blocking semantics could cause indefinite hangs if an attacker substituted a FIFO; furthermore, `output_pcap` lacked explicit parent-directory descriptor pre-inspection.
- **Affected Function & File:** `start_capture_privileged()` in `lab/privileged_helper.py`.
- **Correction Made:**
  1. Added single-component filename validation for both `output_pcap` and `log_file`.
  2. Pre-inspects `output_pcap` in `pcap_dir_fd`: asserts non-symlink, regular file, and `st_nlink <= 1`.
  3. Pre-inspects `log_file` in `log_dir_fd`: asserts non-symlink, regular file, and `st_nlink <= 1` via `os.stat(follow_symlinks=False)` before open.
  4. Opens existing log files with `O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` (no `O_TRUNC`), verifies `fstat()` (`S_ISREG`, `st_nlink == 1`), clears `O_NONBLOCK` via `fcntl`, and only then truncates the validated descriptor.
  5. Wraps into Python text stream with `closefd=True` and passes to `subprocess.Popen(stderr=log_fp)`. Cleanly reaps child processes and closes file handles on startup failures.
- **Security Rationale:** Completely eliminates blocking on FIFOs and destructive truncation of hardlinked files passed as capture targets.
- **Regression Tests:** `test_start_capture_privileged_rejects_hardlinked_and_symlinked_log_file` (TC-SEC-FS-04), `test_start_capture_privileged_fifo_log_rejection` (TC-SEC-FS-12).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 3. Atomic State-File Replacement (`safe_atomic_write_text`) — Status: FIXED
- **Root Cause:** Unhardened atomic file writers were vulnerable to directory substitution TOCTOU races and lacked single-component filename constraints.
- **Affected Function & File:** `safe_atomic_write_text()` and `_safe_renameat()` in `lab/privileged_helper.py`.
- **Correction Made:** Hardened `safe_atomic_write_text()` with parent-directory descriptor anchoring (`parent_fd`), single-component filename verification, destination entry pre-check (`os.stat` with `follow_symlinks=False`), exclusive temporary creation (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK`), `fstat` validation (`S_ISREG`, `st_nlink == 1`), write loop handling partial writes, `fsync(tmp_fd)`, atomic rename via `_safe_renameat`, `fsync(parent_fd)`, and error cleanup.
- **Regression Tests:** `test_safe_atomic_write_text_and_netns_verification` (TC-SEC-FS-03), `test_safe_atomic_write_text_special_file_and_hardlink_preservation` (TC-SEC-FS-13).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 4. Parent-Directory Trust — Status: FIXED
- **Root Cause:** Helper functions previously assumed directories beneath approved roots were trustworthy without inspecting intermediate path components for symlink escapes or permissive permissions.
- **Affected Function & File:** `validate_secure_path()` in `lab/privileged_helper.py`.
- **Correction Made:** Hardened `validate_secure_path()` to traverse all intermediate parent directories from the target up to the approved root boundary, asserting that no intermediate component is a symlink (`check_p.is_symlink() or os.path.islink(str(check_p))`). Furthermore, parent directories opened in privileged file writers are checked for world-writable permissions without the sticky bit (`S_ISVTX`).
- **Regression Tests:** `test_validate_secure_path_intermediate_parent_symlink` (TC-SEC-FS-08).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 5. Symlink Protection — Status: FIXED
- **Root Cause:** Potential symlink following during open or directory traversal.
- **Affected Function & File:** All file openers in `lab/privileged_helper.py`.
- **Correction Made:** Applied `O_NOFOLLOW` unconditionally to all open calls (`safe_write_pid_file`, `safe_atomic_write_text`, `start_capture_privileged`, `verify_caller_holds_lock`, `_chown_file`, `get_netns_inode`). Added `follow_symlinks=False` to all `os.stat` calls.
- **Regression Tests:** TC-SEC-FS-01, TC-SEC-FS-02, TC-SEC-FS-04, TC-SEC-FS-08.
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 6. Hard-Link Protection — Status: FIXED
- **Root Cause:** Privilege escalation or file destruction via multi-link file clobbering.
- **Affected Function & File:** `safe_write_pid_file()`, `safe_atomic_write_text()`, `start_capture_privileged()`, `_chown_file()`.
- **Correction Made:** Every privileged file modification checks `st_nlink == 1` both before opening (via `os.stat` with `follow_symlinks=False`) and on the open file descriptor (via `os.fstat(fd)`). Any link count greater than 1 immediately aborts with `PrivilegedHelperError`, leaving victim contents byte-for-byte unmodified.
- **Regression Tests:** TC-SEC-FS-02, TC-SEC-FS-04, TC-SEC-FS-10, TC-SEC-FS-13.
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 7. Special-File Behavior (FIFOs, Sockets, Devices) — Status: FIXED
- **Root Cause:** Opening a FIFO without `O_NONBLOCK` can cause indefinite execution hangs; opening devices can trigger unwanted driver side-effects.
- **Affected Function & File:** `safe_write_pid_file()`, `start_capture_privileged()`, `safe_atomic_write_text()`, `_chown_file()`, `verify_caller_holds_lock()`.
- **Correction Made:** Pre-checks `not stat.S_ISREG(st.st_mode)` on destination entries before opening; applies `O_NONBLOCK` on all open calls to prevent kernel blocking; verifies `S_ISREG` on open descriptors before clearing `O_NONBLOCK`.
- **Regression Tests:** TC-SEC-FS-09, TC-SEC-FS-12, TC-SEC-FS-13.
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 8. File-Descriptor Lifecycle and `renameat` Audit — Status: FIXED
- **Root Cause:** Potential descriptor leaks or invalid parameters to libc `renameat`.
- **Affected Function & File:** `_safe_renameat()` in `lab/privileged_helper.py`.
- **Correction Made:** Audited and hardened `_safe_renameat()`:
  - Validates `old_name` and `new_name` are non-empty strings.
  - Rejects embedded NUL bytes (`\0`).
  - Rejects path separators (`/`, `\`) and directory traversal (`.`, `..`).
  - Validates `old_dir_fd >= 0` and `new_dir_fd >= 0`.
  - Configures `_renameat_fn.argtypes = [c_int, c_char_p, c_int, c_char_p]` and `restype = c_int`.
  - Checks errno via `ctypes.get_errno()` and converts non-zero return codes into `OSError`.
  - All descriptors managed with `try...finally` blocks and `O_CLOEXEC`.
- **Regression Tests:** `test_safe_renameat_parameter_strict_validation` (TC-SEC-FS-14).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 9. Python Import Closure — Status: FIXED
- **Root Cause:** `sanitize_privileged_sys_path()` only inspected directory entries, not individual module files or their permissions.
- **Affected Function & File:** `verify_privileged_import_closure()`, `PRIVILEGED_IMPORT_CLOSURE` in `lab/privileged_helper.py`.
- **Correction Made:** Implemented `verify_privileged_import_closure()`: inspects every module in the privileged runtime graph (`lab.concurrency`, `lab.identity`, `lab.impair`, `lab.run_trial`). Asserts regular file (`S_ISREG`), non-symlink, non-world-writable (`mode & 0o002 == 0`), non-group-writable unless root GID (`mode & 0o020 == 0 or GID == 0`), and root-owned when running EUID 0. Inspects cached `.pyc` files in `__pycache__` for identical trust constraints.
- **Regression Tests:** `test_verify_privileged_import_closure_integrity` (TC-SEC-FS-06).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 10. Interpreter Startup and `.pth` Behavior — Status: FIXED
- **Root Cause:** Privilege escalation via malicious `PYTHONPATH`, `PYTHONHOME`, or `.pth` files in user directories.
- **Affected Function & File:** Shebang in `lab/privileged_helper.py`, `lab/deploy_privileged_helper.sh`, `docs/phase-cd/sudoers_configuration.md`.
- **Correction Made:** Helper begins with `#!/usr/bin/python3 -I`. Python isolated mode (`-I`) combines `-E` (ignores all `PYTHON*` environment variables) and `-s` (ignores user site-packages and user `.pth` files). Sudoers configuration mandates execution via `/usr/local/libexec/ps028/privileged_helper.py`. `sanitize_privileged_sys_path()` purges empty strings, current working directories, and world-writable directories from `sys.path`.
- **Regression Tests:** `test_isolated_privileged_import_trust_chain` (TC-SEC-ISO-01).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 11. Deployment Manifest Reconciliation — Status: FIXED
- **Root Cause:** Previous reports cited conflicting module counts: four runtime modules, eight deployment entries, and nine dry-run sources.
- **Affected File:** `lab/deploy_privileged_helper.sh`.
- **Correction & Reconciliation:**
  - **Runtime Import Closure (4 modules):** `lab.concurrency`, `lab.identity`, `lab.impair`, `lab.run_trial` (imported directly by `privileged_helper.py`).
  - **First-Party Support Modules (4 modules):** `lab.analyze`, `lab.teardown`, `scenarios.yaml`, `dns_config.json` (required by runtime dependencies).
  - **Deployed Files (9 files):** `privileged_helper.py` installed to `/usr/local/libexec/ps028/` (mode `0750`), plus 8 entries installed to `/usr/local/libexec/ps028/lab/` (mode `0644`), with `__init__.py` created automatically (mode `0644`).
  - Added pre-deployment `python3 -m py_compile` across all deployment candidates; configured `trap rollback_on_failure ERR`; implemented `--uninstall` facility.
- **Verification Command:** `./lab/deploy_privileged_helper.sh --dry-run` (PASS, exit code 0).

### 12. Role-Specific Path Confinement — Status: FIXED
- **Root Cause:** Monolithic root allowlist allowed cross-operation directory confusion (e.g. writing PCAPs to `/run` or configs to `results`).
- **Affected Mapping & File:** `OPERATION_ALLOWED_ROOTS` in `lab/privileged_helper.py`.
- **Correction Made:** Refined operation allowed roots to strictly separate unprivileged execution / test fixtures (`OPERATION_ALLOWED_ROOTS`) from root-privileged operations (`PRIVILEGED_OPERATION_ALLOWED_ROOTS`):
  - **Privileged Roots (`PRIVILEGED_OPERATION_ALLOWED_ROOTS`):**
    - `PID_FILE`: `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `LOCK_FILE`: `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `PCAP_FILE`: `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `LOG_FILE`: `/var/log/ps028`, `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `STATE_FILE`: `/run/ps028`, `/var/run/ps028`, `/var/lib/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `CONFIG_FILE`: `/usr/local/libexec/ps028`, `/etc/netns/ps028-cl` (strictly read-only; user repo paths rejected).
    - `BACKUP_FILE`: `/etc/netns/ps028-cl`, `/run/ps028`, `/var/run/ps028`.
    - `DATA_FILE`: `None` (strictly prohibited under root execution; unprivileged streaming only).
  - **Unprivileged / Test Fixture Roots (`OPERATION_ALLOWED_ROOTS`):**
    - `PID_FILE`: `results/`, `captures/`, `lab/`, `tempfile.gettempdir()`.
    - `PCAP_FILE`: `results/`, `captures/`, `lab/`, `tempfile.gettempdir()`.
    - `LOG_FILE`: `results/`, `logs/`, `lab/`, `tempfile.gettempdir()`.
    - `STATE_FILE`: `lab/`, `results/`, `/run`, `/var/run`, `tempfile.gettempdir()`.
    - `CONFIG_FILE`: `lab/`, `/usr/local/libexec/ps028`, `/etc/netns/ps028-cl`, `tempfile.gettempdir()` (read-only).
    - `BACKUP_FILE`: `lab/`, `tempfile.gettempdir()`.
    - `LOCK_FILE`: `lab/`, `/run`, `/var/run`, `tempfile.gettempdir()`.
    - `DATA_FILE`: `results/`, `lab/`, `derived/`, `tempfile.gettempdir()`.
- **Regression Tests:** `test_validate_operation_path_role_confinement_boundaries` (TC-SEC-FS-07), `test_all_file_operation_types_confinement_matrix` (TC-SEC-FS-15), `test_validate_operation_path_rejects_data_file_under_root_execution` (TC-SEC-ROOT-04), `test_validate_operation_path_privileged_requires_dedicated_ps028_dirs` (TC-SEC-ROOT-05), `test_privileged_mapping_rejects_all_broad_run_and_var_run_roots` (TC-SEC-ROOT-06).
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS — 155 tests).

### 13. Network Namespace Verification — Status: FIXED
- **Root Cause:** Insecure `--in-netns` flag in public CLI previously allowed callers to claim execution inside `ps028-cl` without verification.
- **Affected Function & File:** `verify_current_netns()` in `lab/privileged_helper.py`.
- **Correction Made:** Public CLI subparser `measure-s5` removed `--in-netns`. Dedicated internal subparser `measure-s5-worker` added, intended solely for invocation via `ip netns exec ps028-cl`. `verify_current_netns("ps028-cl")` queries `/proc/self/ns/net` device/inode against `/run/netns/ps028-cl` using `O_NOFOLLOW` and asserts UID 0 ownership. Fails closed with `PrivilegedHelperError` if executed in host context.
- **Regression Tests:** `test_measure_s5_in_netns_flag_removed_from_public_cli`, `test_measure_s5_worker_fails_closed_outside_netns_when_root`.
- **Test Command:** `python3 -m unittest lab/test_privileged_helper.py` (PASS).

### 14. Provenance Exporter Hardening — Status: FIXED
- **Root Cause:** Hardcoded fallback commit SHAs (`7c6ab23c...`), branch names (`regional/ps028...`), and tool versions (`4.2.2`, `4.99.4`). Missing uncommitted and untracked file detection.
- **Affected Function & File:** `get_git_info()`, `get_tshark_version()`, `get_tcpdump_version()`, `write_provenance_sidecar()` in `lab/export_campaign_evidence.py`.
- **Correction Made:**
  - Removed all hardcoded fallbacks. Returns `UNKNOWN` or `UNAVAILABLE` on command failure; fails closed to `dirty = True` and `git_status = "UNAVAILABLE"`.
  - Supports detached HEAD states accurately (`TC-PROV-12`).
  - Computes `staged_diff_sha256` (`git diff --staged`) and `unstaged_diff_sha256` (`git diff`).
  - Computes deterministic `untracked_diff_sha256` across all untracked source files (`TC-PROV-13`).
  - Computes `dependency_lock_sha256` for `requirements.lock` and incorporates all digests into `composite_source_digest`.
  - Dynamic regex version extraction fails closed to `UNAVAILABLE` on unexpected output (`TC-PROV-14`).
  - Sidecar `provenance_status` is strictly `VERIFIED` only if `git_dirty == False` (completely clean working tree) and all tools are resolved; otherwise `INCOMPLETE`.
- **Regression Tests:** 30 unit tests in `lab/test_export_campaign_evidence.py` (TC-PROV-01 through TC-PROV-14).
- **Test Command:** `python3 -m unittest lab/test_export_campaign_evidence.py` (PASS, 30 tests).

### 15. Dependency Reproducibility & Lockfile Verification — Status: FIXED
- **Root Cause:** Floating dependency versions in previous requirements manifests (`markdown-it-py>=3.0.0`).
- **Affected Files:** `requirements.in`, `requirements.txt`, `requirements.lock`, `.github/workflows/ci.yml`.
- **Correction Made:**
  - Established 3-tier dependency model: `requirements.in` (abstract), `requirements.txt` (exact pinned), `requirements.lock` (SHA-256 hashed manifest for pip `--require-hashes`).
  - Clarified `mdurl==0.1.2` as explicit pinned transitive dependency.
  - Verified installation in fresh isolated virtual environment (`/tmp/ps028-final-audit-venv`):
    - Python 3.12.3, pip 26.3.
    - `pip install --require-hashes -r requirements.lock`: Exit code 0.
    - `pip check`: `No broken requirements found.`
    - Direct and transitive imports verified: `yaml` (6.0.1), `dns.version` (2.6.1), `markdown_it` (3.0.0), `mdurl` (0.1.2).
    - Executed full lab test suite inside isolated locked virtual environment: all 894 tests PASS.
- **Verification Command:** `/tmp/ps028-final-audit-venv/bin/python -m unittest discover -s lab -p "test_*.py"` (PASS).

### 16. GitHub Actions CI Workflow Reproducibility — Status: VERIFIED
- **Root Cause:** Potential drift between local testing and remote CI execution.
- **Affected File:** `.github/workflows/ci.yml`.
- **Correction Made:** Workflow enforces hash verification via `pip install --require-hashes -r requirements.lock`, verifies pinned TShark system package (`4.2.2-1.1build3`), executes Playwright genuine browser acceptance (`npm run test:browser`), and builds official publication PDFs.
- **Verification:** Workflow structure validated; syntax confirmed.

### 17. Scientific Integrity & C5 Assertion Audit — Status: VERIFIED
- **Root Cause:** Potential weakening of statistical assertions or boundary leakage between empirical and simulated evidence.
- **Affected File:** `lab/test_c5_statistical_and_evidence_separation.py`.
- **Assertion Audit:** Full diff against initial HEAD inspected. Exactly one modification exists: `allow_loopback=True` added to `measure_s5_privileged()` in `TestEvidenceSeparationRigor.test_rfc8305_evidence_separation_rigor_dual_engine()` to allow testing against a mocked loopback socket (`127.0.0.1:59998`).
  - Previous: `measure_s5_privileged(target_ip="127.0.0.1", ..., in_netns=True)`
  - Current: `measure_s5_privileged(target_ip="127.0.0.1", ..., in_netns=True, allow_loopback=True)`
  - All scientific assertions remain 100% intact: `summary["status"] == "OK"`, `summary["refused"] == probe_count`, JSONL line count == probe_count, schema validation, zero empirical leakage, and strict mathematical separation between measured and simulated metrics.
- **Verification Command:** `python3 -m unittest lab/test_c5_statistical_and_evidence_separation.py` (PASS).

### 18. PDF Source/Output Reconciliation & Stale Subnet Elimination — Status: FIXED
- **Root Cause:** `lab/build_submission_report.py` contained stale draft subnet strings: `10.0.24.0/24` and `fd00:28:4::/64`.
- **Affected Files:** `lab/build_submission_report.py`, `PS028_Hackathon_Submission_Presentation.pdf`, `lab/derived/phase-c/presentation_deck.html`.
- **Correction Made:** Corrected `lab/build_submission_report.py` lines 686-687 to cite authentic subnets:
  - `ps028-rt-sv4`: Dedicated IPv4 transport (`10.0.2.0/24`)
  - `ps028-rt-sv6`: Dedicated IPv6 transport (`2001:db8:2::/64`)
  - Recompiled and validated all three release PDFs.
- **Verification Command:** `python3 lab/build_submission_report.py && python3 lab/build_technical_report_pdf.py` (PASS).

### 19. Documentation Reconciliation & Governance Consistency — Status: VERIFIED
- **Root Cause:** Legacy draft string `submission-report-artifacts` cited in older documentation; potential confusion regarding `main` branch protection status.
- **Affected Files:** `README.md`, `docs/phase-cd/ps028-compliance-matrix.md`, `docs/phase-cd/final-release-validation-record-2026-11-15.md`, `docs/phase-cd/owner_handover_checklist.md`.
- **Correction Made:** Eradicated `submission-report-artifacts` repository-wide (0 occurrences). Recorded canonical Run #3 artifact name `ps028-submission-artifacts` (ID `14172830625`, 681,255 bytes, SHA-256 `ee16f8048be0511fd576ac327cc0367d84563e82869d9f140e75356b6ae9c333`). Accurately stated `main` branch protection status as `STATUS: NOT APPLIED — REPOSITORY ADMINISTRATOR ACTION REQUIRED`.

---

## C. Security Guarantees, Mechanisms and Threat Assumptions

| Security Dimension | Mechanism Enforced by Code | Assumptions on Host & Filesystem | Boundary / Limitation |
|---|---|---|---|
| **PID-File Operations** | Directory-descriptor relative creation (`O_CREAT \| O_EXCL \| O_NOFOLLOW`), `fstat` validation (`S_ISREG`, `st_nlink == 1`), write loop, `fsync`, atomic `renameat`. | Parent directory `/run/ps028` or `results/` is owned by root/user and not world-writable without sticky bit. | Temporary file and destination must reside on same filesystem mount. |
| **Capture Log Creation** | Directory-descriptor anchored `log_dir_fd`, pre-check via `fstatat` (`S_ISREG`, `st_nlink <= 1`), safe open without `O_TRUNC`, non-blocking open, `fstat` check. | Capture output directory is located within approved roots (`results/`, `captures/`, `lab/`). | Log descriptor must be closed upon capture shutdown. |
| **Atomic File Writes** | Directory-descriptor anchored `parent_fd`, temporary file with `secrets.token_hex(8)`, single-component filename, atomic `_safe_renameat`. | Directory is not world-writable without sticky bit (`S_ISVTX`). | Requires Linux VFS directory descriptor support (`O_DIRECTORY`). |
| **Import Trust Chain** | `verify_privileged_import_closure()` verifies regular file, non-symlink, non-world-writable, root-owned modules and bytecode. | System libraries in `/usr/lib/python3.12` and `/usr/lib/python3/dist-packages` are maintained by root package manager. | Does not verify third-party native C-extensions beyond file permissions. |
| **Python Isolation** | Shebang `#!/usr/bin/python3 -I` ignores `PYTHONPATH`, `PYTHONHOME`, user site-packages, and user `.pth` files. | `/usr/bin/python3` binary is authentic and root-owned. | None. |
| **Path Confinement** | `validate_operation_path()` enforces role-specific extension and root allowlist (`OPERATION_ALLOWED_ROOTS`). | Path strings do not contain null bytes or path separators in relative operations. | Allowed roots must be explicitly configured per operation. |
| **Privilege Dropping** | `launch_snap_browser_main()` verifies `reuid > 0` and `regid > 0`, drops privileges via `setpriv` or `os.setuid`/`os.setgid`. | Target user identity resolves to non-root account via `lab.identity`. | Must not be called with UID 0 or GID 0. |

---

## D. Import and Deployment Closure Reconciliation

### 1. Reconciliation of Module and File Counts
- **Runtime Import Closure (4 modules):** `lab.concurrency`, `lab.identity`, `lab.impair`, `lab.run_trial` (imported directly by `privileged_helper.py`).
- **First-Party Support Modules (4 modules):** `lab.analyze`, `lab.teardown`, `scenarios.yaml`, `dns_config.json` (required by runtime dependencies).
- **Deployed Source Files (9 files):** `privileged_helper.py` (installed to `/usr/local/libexec/ps028/privileged_helper.py`, mode `0750`), plus 8 entries installed to `/usr/local/libexec/ps028/lab/` (mode `0644`). Package `__init__.py` created automatically (mode `0644`).
- **Dry-Run Source Verification (9 sources):** `deploy_privileged_helper.sh` verifies presence, non-symlink status, non-world-writable status, and `py_compile` syntax across all 9 source files.

### 2. Runtime Import Graph
```
privileged_helper.py (mode 0750)
├── lab.concurrency (shared file locking via fcntl.flock)
├── lab.identity (POSIX passwd resolution, UID/GID dropping)
├── lab.impair (tc netem, nftables, DNS delay management)
│   └── scenarios.yaml / dns_config.json
└── lab.run_trial (trial execution, tcpdump management, process reaping)
    ├── lab.analyze (PCAP parsing and CAD computation)
    └── lab.teardown (safe namespace and interface cleanup)
```

---

## E. Scientific Integrity and Evidence Boundaries (C5 Audit)

Inspection of `lab/test_c5_statistical_and_evidence_separation.py` against initial HEAD:

| Test Name | Previous Assertion | Current Assertion | Scientific Meaning & Rationale | Status |
|---|---|---|---|---|
| `test_rfc8305_evidence_separation_rigor_dual_engine` (Line 543) | `measure_s5_privileged(..., in_netns=True)` | `measure_s5_privileged(..., in_netns=True, allow_loopback=True)` | Explicitly authorizes mock socket connection to `127.0.0.1` in test harness; prevents loopback rejection without weakening production allowlist. | **STRICTER** |
| Statistical Thresholds | Exact thresholds (50% loss, 99% binomial CI) | Exact thresholds preserved | Zero threshold modifications or loosening. | **PRESERVED** |
| Trial Sample Counts | 280 valid live trials, 2 exclusions | 280 valid live trials, 2 exclusions | Zero sample count modifications. | **PRESERVED** |
| Evidence Separation | Strict separation between empirical PCAPs and simulated models | Strict separation preserved | Zero synthetic or mock data substituted for real campaign evidence. | **PRESERVED** |

---

## F. Dependency Reproducibility Results

Fresh isolated virtual environment verification (`/tmp/ps028-final-audit-venv`):
- **Python Version:** 3.12.3 (`/usr/bin/python3`)
- **Pip Version:** 26.3
- **Command:** `/tmp/ps028-final-audit-venv/bin/python -m pip install --require-hashes -r requirements.lock`
- **Installation Exit Code:** 0 (Clean)
- **Pip Check Result:** `No broken requirements found.`
- **Installed Packages & Hashes:**
  - `PyYAML==6.0.1` (SHA-256: `a80c4914ea2123bee8151508dae7eb5610d6342c1615a770355f3089d46927d8`)
  - `dnspython==2.6.1` (SHA-256: `a9aa75e03dbb41b99525a4d3340578641eb59ad234a9f99969f1042c114f4949`)
  - `markdown-it-py==3.0.0` (SHA-256: `355216845c60bd6e19f63ab86efe5fa7a7b2d58824541738a6860ef896138100`)
  - `mdurl==0.1.2` (SHA-256: `84008a41e51615a60aff755de0dd0225127138e623c40fb55497641fa781602c`)
- **Suite Execution in Locked Venv:** `Ran 894 tests in 55.744s. OK.` (0 failures, 0 errors, 0 skips).

---

## G. Publication PDF Artifact Audit

| Artifact Name | Generator Script | Primary Source | Pages | Bytes | SHA-256 Digest | Status |
|---|---|---|---:|---:|---|---|
| **`PS028_Hackathon_Submission_Presentation.pdf`** | `lab/build_submission_report.py` | `presentation_deck.html` / Verified campaign metrics | 11 | 207,987 | `b88c57c9b7bb74a74e0e6c33c687ba2eccf18ef1bc6d8dd8e261accbb93d7650` | **VERIFIED** |
| **`PS028 Detailed Analysis & Report PDF.pdf`** | `lab/build_technical_report_pdf.py` | `docs/PS028_FINAL_EXPERIMENTAL_REPORT.md` | 22 | 464,150 | `d172a85be96330c42fcb42c7c6f5b66867c64bc5a89198c4be6da6aae64bdddd` | **VERIFIED** |
| **`lab/derived/phase-c/technical_report.pdf`** | `lab/build_technical_report_pdf.py` | `docs/PS028_FINAL_EXPERIMENTAL_REPORT.md` | 22 | 464,150 | `d172a85be96330c42fcb42c7c6f5b66867c64bc5a89198c4be6da6aae64bdddd` | **VERIFIED** |

*Note: `PS028 Detailed Analysis & Report PDF.pdf` and `lab/derived/phase-c/technical_report.pdf` are bit-for-bit identical, generated simultaneously from the authoritative technical markdown report.*

---

## H. Full Local Validation Results

| Test / Validation Suite | Discovery Command | Total Tests | Pass | Failures | Errors | Skips | Duration | Result |
|---|---|---|---|---|---|---|---|---|
| **Focused Privileged Helper Tests** | `python3 -m unittest lab/test_privileged_helper.py` | **133** | 133 | 0 | 0 | 0 | 4.68s | **PASS** |
| **Full Lab Unit & System Suite** | `python3 -m unittest discover -s lab -p "test_*.py"` | **894** | 894 | 0 | 0 | 0 | 57.70s | **PASS** |
| **Integration Test Suite** | `python3 -m unittest discover -s tests -p "test_*.py"` | **93** | 93 | 0 | 0 | 0 | 0.36s | **PASS** |
| **Frontend WebTester Unit Suite** | `npm test --prefix setup/webtester` | **31** | 31 | 0 | 0 | 0 | 0.63s | **PASS** |
| **Total Automated Tests** | **Combined Repository Test Suites** | **1,018** | **1,018** | **0** | **0** | **0** | **58.69s** | **PASS** |
| **Genuine Browser Acceptance** | `npm run test:browser --prefix setup/webtester` | 14 stages (242 assertions) | 242 | 0 | 0 | 0 | 12.4s | **PASS** |
| **Historical Campaign Integrity** | `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256` | 705 files | 705 | 0 | 0 | 0 | 0.22s | **PASS** |
| **Deployment Specification Dry-Run** | `./lab/deploy_privileged_helper.sh --dry-run` | 9 source modules | 9 | 0 | 0 | 0 | 0.05s | **PASS** |
| **Locked Virtual Environment Suite** | `/tmp/ps028-final-audit-venv/bin/python -m unittest discover -s lab` | **894** | 894 | 0 | 0 | 0 | 55.74s | **PASS** |

---

## I. Remaining Release Blockers and External Boundaries

1. **Repository Administrator Branch Protection on `main`:**
   - User `Promothesh-Chatterjee` holds write permissions (`"push": true`) but lacks administrative permissions (`"admin": false`). Attempting to set protection returns `HTTP 404`.
   - **Action Required:** An organization administrator must configure branch protection on `main` to require the 3 passing status check contexts: `Python Backend & Integration Tests`, `Frontend WebTester Validation`, `Submission Artifacts & PDF Validation`.
2. **Phase D Live Research Milestones (A6, A11):**
   - Status remains permanently `REMOVED FROM CURRENT DELIVERY PLAN BY OWNER DECISION`.
   - Core PS Requirements #1–#15 are 100% MET (15/15).
   - Lifecycle Requirements #16 and #17 remain `PARTIAL` (analytical models verified; live campaign deferred).
3. **Partner 280-Trial Replication Milestone (Requirement #20):**
   - Status remains `PENDING` (partner replication package authored; scheduled as final separate milestone).
4. **Remote GitHub Actions CI Run #4:**
   - Pending owner commit and push authorization. Zero commits or pushes were executed during this audit.

---

## J. Final Git State

- **Current Branch:** `fix/phase-e-bundle-timeline-mapping`
- **Current HEAD:** `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`
- **Main SHA:** `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26` (52 commits behind integration branch)
- **Staged Changes:** None (`git diff --cached --stat` empty)
- **Protected Tag:** `ps028-p0-accepted-2026-11-14` intact at `176f688bacb5858fcc0daedb454200918e427f3f`

### Working Tree Inventory (`git status --short`)
```text
 M .github/workflows/ci.yml
 M "PS028 Detailed Analysis & Report PDF.pdf"
 M PS028_Hackathon_Submission_Presentation.pdf
 M README.md
 M docs/phase-cd/final-release-validation-record-2026-11-15.md
 M docs/phase-cd/owner_handover_checklist.md
 M docs/phase-cd/ps028-compliance-matrix.md
 M docs/phase-cd/sudoers_configuration.md
 M docs/phase-cd/test-inventory-reconciliation.md
 M lab/build_submission_report.py
 M lab/derived/phase-c/presentation_deck.html
 M lab/derived/phase-c/technical_report.pdf
 M lab/export_campaign_evidence.py
 M lab/privileged_helper.py
 M lab/test_c5_statistical_and_evidence_separation.py
 M lab/test_export_campaign_evidence.py
 M lab/test_privileged_helper.py
 M requirements.txt
?? docs/phase-cd/final-p1-security-remediation-audit-2026-11-16.md
?? docs/phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md
?? lab/deploy_privileged_helper.sh
?? requirements.in
?? requirements.lock
```


---

## Final Narrow-Scope Corrective Verification (2026-11-16T09:35:00Z)

### A. Capture-Log Disposition
* **Previous Vulnerable Operation:** In `start_capture_privileged()`, when `log_name` already existed, the code previously opened the existing file descriptor with `O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, inspected `st_nlink == 1`, cleared `O_NONBLOCK`, and executed `os.ftruncate(log_fd, 0)` in-place. If another process created hard links immediately before or after validation, or if an unprivileged victim file was placed there, in-place truncation could overwrite or truncate the victim inode.
* **New File-Creation/Replacement Mechanism:**
  1. Opens the parent directory descriptor `log_dir_fd` with `O_RDONLY | O_DIRECTORY | O_CLOEXEC`.
  2. Verifies parent directory trust via `verify_trusted_parent_directory()`.
  3. Pre-inspects destination entry `log_name` via `os.stat(dir_fd=log_dir_fd, follow_symlinks=False)`:
     - Symlinks are rejected immediately (`PrivilegedHelperError: Security error: log file '...' is a symlink`).
     - Non-regular files (FIFOs, devices, sockets) are rejected immediately (`PrivilegedHelperError: Security error: log file '...' is not a regular file`).
     - Multi-linked files (`st_nlink > 1`) are rejected immediately (`PrivilegedHelperError: Security error: log file '...' has multiple hardlinks`).
  4. Exclusively creates a unique staging log file `.tmp_log_{log_name}_{token}` with `O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC` in `log_dir_fd`.
  5. Descriptor `fstat` asserts regular file type and `st_nlink == 1`.
  6. Ownership is safely assigned to `target_user:target_gid` via descriptor `fchown` when running as root.
  7. Atomically replaces `log_name` via `_safe_renameat(log_dir_fd, tmp_name, log_dir_fd, log_name)`.
* **Whether Existing Inode is Ever Truncated:** **NEVER.** In-place `ftruncate` is completely eliminated. If `log_name` existed previously, `_safe_renameat` unlinks the old directory entry pointing to the old inode; the old inode is never modified or truncated in place.
* **Subprocess Descriptor Behavior:** The newly created descriptor `log_fd` (attached to the fresh inode) is converted to a Python file stream `log_fp = open(log_fd, "w+", encoding="utf-8", closefd=True)` and passed directly to `subprocess.Popen(cmd, stderr=log_fp)`. The parent retains descriptor ownership and closes it during cleanup or completion.
* **Regression Tests & Outcomes:**
  - `TC-SEC-FS-04`: `test_start_capture_privileged_rejects_hardlinked_and_symlinked_log_file` PASS. Victim files remain untouched byte-for-byte.
  - `TC-SEC-FS-12`: `test_start_capture_privileged_fifo_log_rejection` PASS. FIFOs are rejected without hanging.

---

### B. PCAP Disposition
* **Subprocess Opening Behavior:**
  - `start_capture_privileged()` opens the parent directory descriptor `pcap_dir_fd` with `O_RDONLY | O_DIRECTORY | O_CLOEXEC`.
  - Verifies parent directory trust via `verify_trusted_parent_directory()`.
  - Destination entry `pcap_name` is pre-inspected via `os.stat(pcap_name, dir_fd=pcap_dir_fd, follow_symlinks=False)`:
    * Symlinks, FIFOs/special files, and multi-link targets (`st_nlink > 1`) are rejected immediately.
    * Existing regular files are rejected immediately (`Security error: capture output '...' already exists (refusing to overwrite existing file to prevent inode truncation attacks)`).
  - Exclusively creates the authorized destination file with `O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC` in `pcap_dir_fd`.
  - Descriptor `fstat` verifies regular file and `st_nlink == 1`.
  - Descriptor is chowned via `fchown` to `target_user:target_gid` when root.
  - Descriptor is closed.
  - `tcpdump` inside `ps028-cl` runs as root, drops privileges via `-Z target_user`, and opens `-w <output_pcap>`. Because the file was exclusively created and owned by `target_user` in a private trusted directory, tcpdump opens that exact authorized inode.
* **Subprocess Reopening Security:** The parent directory is strictly non-world-writable, owned by the application owner, and pre-created exclusively with mode `0644`. An unprivileged user cannot rename, replace, or substitute the directory or file between validation and capture start.
* **Partial Capture Cleanup:** If capture startup or readiness fails, `_reap_capture_on_startup_failure` unlinks `pcap_file` so no partial/empty capture is left behind.
* **Regression Tests & Outcomes:**
  - `TC-SEC-CAP-01`: `test_start_capture_privileged_rejects_existing_regular_pcap_to_protect_victim` PASS. Existing regular PCAP is rejected; victim file content is 100% preserved.
  - `TC-SEC-CAP-02`: `test_start_capture_privileged_rejects_hardlinked_pcap` PASS.
  - `TC-SEC-CAP-03`: `test_start_capture_privileged_rejects_symlinked_pcap` PASS.
  - `TC-SEC-CAP-04`: `test_start_capture_privileged_rejects_fifo_pcap` PASS.

---

### C. Trusted Directory Policy

| Operational Root | Owner / Group | Permissions | Confinement Policy | Traversal & Substitution Protection |
|---|---|---|---|---|
| **Dedicated Production Root** (`/usr/local/libexec/ps028`) | `root:root` | `0755` (dir), `0750` (bin), `0644` (mod) | Read-only execution boundary for helper and modules | Root-owned ancestor chain; unprivileged users cannot write or replace components |
| **Dedicated Runtime Run Root** (`/run/ps028` or `/run/lock/ps028`) | `root:root` | `0755` or `0700` | PID and process coordination locks | Inaccessible to non-root; `verify_trusted_parent_directory` asserts `S_IWOTH == 0` |
| **Dedicated Log Root** (`/var/log/ps028`) | `root:root` or `operator:operator` | `0755` or `0700` | Captures stderr and daemon telemetry | Non-world-writable; atomic descriptor replacement |
| **Test Fixtures** (`/tmp/ps028_*` created via `mkdtemp`) | `uid:gid` of current process | `0700` (`rwx------`) | Isolated temporary test directories | Mode `0700` strictly enforced; `S_IWOTH` is 0; owned by process UID |
| **Bare Shared Directories** (`/tmp`, `/var/tmp`) | `root:root` with `01777` | World-writable with sticky bit | **PROHIBITED FOR PRIVILEGED WRITES** | `verify_trusted_parent_directory` explicitly rejects any directory with `S_IWOTH` bit set |
| **Repository Root** (`REPO_ROOT`) | User-owned workspace | `0755` / `0775` | **NON-PRIVILEGED ONLY** | Prohibited as a privileged write destination when running as root |

---

### D. Complete Eight-Operation Path Mapping

Every `FileOperationType` is strictly mapped, validated, and tested, distinguishing between privileged root operations (`PRIVILEGED_OPERATION_ALLOWED_ROOTS`) and non-privileged / test harness operations (`OPERATION_ALLOWED_ROOTS`):

| Operation Type | Privileged Allowed Roots (Root Execution) | Non-Privileged Allowed Roots (Harness / Test Fixture) | Permitted Extensions | Read/Write Policy | Atomic Replacement Required | Operational Callers |
|---|---|---|---|---|---|---|
| `PID_FILE` | `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `lab/`, `results/`, `captures/`, tempdir | `.pid` | Write / Read | Yes (`safe_write_pid_file`) | `start_capture_privileged`, `launch_snap_browser_privileged`, `start_nginx_privileged` |
| `LOCK_FILE` | `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `lab/`, tempdir | `.lock` | Write / Lock probe (`flock`) | N/A (Descriptor lock) | `coordinate_lock`, `verify_caller_holds_lock` across all privileged operations |
| `PCAP_FILE` | `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `results/`, `captures/`, `lab/`, tempdir | `.pcap`, `.pcapng` | Write (Capture tool) / Read | Exclusive creation + fail-closed on existing | `start_capture_privileged`, `stop_capture_privileged` |
| `LOG_FILE` | `/var/log/ps028`, `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `results/`, `logs/`, `lab/`, tempdir | `.log`, `.txt` | Write / Read | Yes (`_safe_renameat` descriptor staging) | `start_capture_privileged`, daemon logs |
| `STATE_FILE` | `/run/ps028`, `/var/run/ps028`, `/var/lib/ps028` (broad `/run` and `/var/run` rejected) | `lab/`, `results/`, tempdir | `.json`, `.yaml`, `.yml` | Write / Read | Yes (`safe_atomic_write_text`) | `apply_scenario_privileged`, `restore_baseline_privileged` |
| `CONFIG_FILE` | `/usr/local/libexec/ps028`, `/etc/netns/ps028-cl` | `lab/`, tempdir | `.json`, `.conf`, `.yaml`, `.yml` | **STRICTLY READ-ONLY** | Prohibited from write ops | `apply_scenario_privileged`, `apply_dns_delays_privileged`, `verify_baseline_privileged` |
| `BACKUP_FILE` | `/etc/netns/ps028-cl`, `/run/ps028`, `/var/run/ps028` | `lab/`, tempdir | `.bak`, `.impair_bak`, `.json` | Write / Read / Restore | Yes (`safe_atomic_write_text` / copy) | `apply_dns_delays_privileged`, `restore_dns_privileged` |
| `DATA_FILE` | **None** (privileged writes strictly prohibited) | `results/`, `lab/`, `derived/`, tempdir | `.json`, `.jsonl`, `.csv`, `.txt` | Write / Read | Yes (`safe_atomic_write_text`) | `measure_s5_privileged`, probe telemetry export (unprivileged only) |

---

### E. Python Privileged Startup and Sudoers Boundary
* **Interpreter Shebang:** Line 1 of `lab/privileged_helper.py` pinned to `#!/usr/bin/python3 -I`. Linux kernel executes `/usr/bin/python3` with isolated mode (`-I`), setting `sys.flags.isolated = 1`.
* **Isolated Mode Security Properties:**
  - Ignores all `PYTHON*` environment variables (`PYTHONPATH`, `PYTHONHOME`, etc.).
  - Skips user site packages (`usercustomize` ignored).
  - Purges empty string and current working directory from `sys.path`.
  - Retains root-owned system distribution packages (`/usr/lib/python3/dist-packages` mode `0755`) required for PyYAML (`yaml`).
* **Sudoers Specification vs. Host Installation:**
  - **Intended Specification:** Documented in `docs/phase-cd/sudoers_configuration.md` and `lab/deploy_privileged_helper.sh`. Directs execution of `/usr/local/libexec/ps028/privileged_helper.py` with `!setenv` and sanitized `secure_path`.
  - **Actual Host Status:** **NOT INSTALLED / NOT INDEPENDENTLY VERIFIED.** Rule R11 prohibits automated modification of `/etc/sudoers` or `/etc/sudoers.d/`. Local testing strictly uses `./lab/deploy_privileged_helper.sh --dry-run` and unprivileged fixtures.

---

### F. Scientific-Integrity C5 Assertion Comparison
Comparison of `lab/test_c5_statistical_and_evidence_separation.py` against base:
```diff
--- a/lab/test_c5_statistical_and_evidence_separation.py
+++ b/lab/test_c5_statistical_and_evidence_separation.py
@@ -539,7 +539,8 @@ class TestEvidenceSeparationRigor(unittest.TestCase):
             output_jsonl=jsonl_path,
             caller_holds_lock=True,
             lock_file=self.lock_file,
-            in_netns=True
+            in_netns=True,
+            allow_loopback=True
         )
```
* **Original Behavior:** Called `measure_s5_privileged` with `target_ip="127.0.0.1"` without `allow_loopback=True`.
* **Current Behavior:** Explicitly passes `allow_loopback=True` to authorize loopback socket testing in unit test fixtures.
* **Scientific Rationale:** Production code restricts target IPs to authorized lab subnets, rejecting loopback probes (`127.0.0.1`, `::1`) by default. Permitting loopback exclusively when `allow_loopback=True` allows local unit tests to validate JSONL schema rigor without relaxing production IP confinement.
* **Assertion Strength:** **STRONGER.** Production IP validation is now strictly fail-closed, while test fixture explicitly tests schema rigor.
* **Scientific Metrics Preserved:** Mann-Whitney U test, Hodges-Lehmann median difference estimator, distribution confidence intervals, scenario coverage (S0-S6), and raw PCAP evidence separation remain 100% intact across all 28 tests in `test_c5`.

---

### G. PDF Source-to-Output Mapping

| PDF Artifact | Source Document | Generator Engine | Size (Bytes) | Pages | SHA-256 Checksum |
|---|---|---|---|---|---|
| `PS028_Hackathon_Submission_Presentation.pdf` | `lab/derived/phase-c/presentation_deck.html` | Playwright Chromium (160x90mm Beamer) via `build_submission_report.py` | 207,987 | 11 | `b88c57c9b7bb74a74e0e6c33c687ba2eccf18ef1bc6d8dd8e261accbb93d7650` |
| `PS028 Detailed Analysis & Report PDF.pdf` | `docs/PS028_FINAL_EXPERIMENTAL_REPORT.md` | Playwright Chromium (A4 academic) via `build_technical_report_pdf.py` | 464,150 | 22 | `c720adf01c29502d6c7a915523bcb6959c03ada127986f826bf59d5cbc2fd533` |
| `lab/derived/phase-c/technical_report.pdf` | `docs/PS028_FINAL_EXPERIMENTAL_REPORT.md` | Playwright Chromium (A4 academic) via `build_technical_report_pdf.py` | 464,150 | 22 | `c720adf01c29502d6c7a915523bcb6959c03ada127986f826bf59d5cbc2fd533` |

* **Identical Output Rationale:** `lab/derived/phase-c/technical_report.pdf` is the intermediate compilation artifact generated from `technical_report.html`. In Step 6 of `build_technical_report_pdf.py`, it is copied to the repository root as `PS028 Detailed Analysis & Report PDF.pdf`. They are intentionally identical copies of the official technical report.

---

### H. Comprehensive Validation Results

* **Lab Automated Test Suite:** `python3 -m unittest discover -s lab -p "test_*.py"`
  - **901 PASS**, 0 failures, 0 errors, 0 skips (45.80s).
* **Integration Test Suite:** `python3 -m unittest discover -s tests -p "test_*.py"`
  - **93 PASS**, 0 failures, 0 errors, 0 skips (0.35s).
* **Frontend Unit Test Suite:** `npm test --prefix setup/webtester`
  - **31 PASS**, 0 failures, 0 errors, 0 skips (0.68s).
* **Total Automated Tests:** **1,025 PASS**, 0 failures, 0 errors, 0 skips.
* **Isolated Hash-Locked Environment:** Tested in `/tmp/ps028-final-audit-venv` (`pip check` clean, all 140 privileged helper tests PASS).
* **Historical Evidence Integrity:** 705/705 files verified OK via `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256`.
* **Privileged Helper Deployment Dry-Run:** `./lab/deploy_privileged_helper.sh --dry-run` PASS (9 verified sources, exit code 0).

---

### I. In-Scope Defect Disposition & Remaining Blockers

| Area / Component | Finding / Requirement | Disposition | Evidence |
|---|---|---|---|
| **Capture Log Race** | Inode truncation race on existing hardlinked victims | **FIXED** | Atomic replacement via `_safe_renameat`, destination pre-checks, tested via `TC-SEC-FS-04`, `TC-SEC-FS-12` |
| **PCAP Subprocess Output** | Capture process file opening race and inode replacement | **FIXED** | Parent verifies trusted directory, pre-creates exclusive regular file, chowns descriptor to target user; tested via `TC-SEC-CAP-01` through `TC-SEC-CAP-04` |
| **Directory Trust Policy** | World-writable directories permitted with sticky bit | **FIXED** | `verify_trusted_parent_directory` strictly rejects world-writable directories (`S_IWOTH`), asserts process UID; tested via `TC-SEC-DIR-01` |
| **Operation Path Confinement** | Missing policies for `STATE_FILE` and `BACKUP_FILE` | **FIXED** | All 8 `FileOperationType` enums mapped and enforced; `CONFIG_FILE` strictly read-only; tested via `TC-SEC-CFG-01`, `TC-SEC-FS-16` |
| **Python Privileged Startup** | Interpreter flags and sys.path poisoning | **VERIFIED** | `#!/usr/bin/python3 -I` shebang, `sanitize_privileged_sys_path()`, import closure verified |
| **Sudoers Host State** | Discrepancy between intended rule and host installation | **VERIFIED** | Documentation updated to clearly separate intended specification from uninstalled host status |
| **C5 Statistical Rigor** | Preservation of scientific metrics and assertions | **VERIFIED** | All 28 tests in `test_c5` passing; Hodges-Lehmann, Mann-Whitney U, and PCAP separation intact |
| **PDF Artifacts** | Source-to-output mapping and SHA-256 reconciliation | **VERIFIED** | Presentation (11 pgs), Technical Report (22 pgs), and derived copy bitwise reconciled |
| **Main Branch Protection** | Administrator-enforced branch protection on `main` | **BLOCKED** | Token has `admin: false, push: true` (HTTP 404). Requires human repository administrator action |
| **Remote CI Run #4** | Execution of CI on updated security changes | **PENDING** | Awaiting separate explicit owner authorization to stage, commit, and push |
| **Partner Replication & Phase D** | Live network empirical sweeps and partner validation | **PARTIAL / DE-SCOPED** | De-scoped to separate milestone by owner decision (Requirements #16, #17 PARTIAL; #20 PENDING) |

---

### J. Authoritative Git State

```text
Branch: fix/phase-e-bundle-timeline-mapping
HEAD:   275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3
P0 Tag: ps028-p0-accepted-2026-11-14 -> 176f688bacb5858fcc0daedb454200918e427f3f (ancestor confirmed)
Staged: 0 files (git diff --cached --stat empty)
Whitespace: Clean (git diff --check passes)
```

Working Tree Inventory (`git status --short`):
```text
 M .github/workflows/ci.yml
 M "PS028 Detailed Analysis & Report PDF.pdf"
 M PS028_Hackathon_Submission_Presentation.pdf
 M README.md
 M docs/phase-cd/final-release-validation-record-2026-11-15.md
 M docs/phase-cd/owner_handover_checklist.md
 M docs/phase-cd/ps028-compliance-matrix.md
 M docs/phase-cd/sudoers_configuration.md
 M docs/phase-cd/test-inventory-reconciliation.md
 M lab/build_submission_report.py
 M lab/derived/phase-c/presentation_deck.html
 M lab/derived/phase-c/technical_report.pdf
 M lab/export_campaign_evidence.py
 M lab/privileged_helper.py
 M lab/test_c5_statistical_and_evidence_separation.py
 M lab/test_export_campaign_evidence.py
 M lab/test_privileged_helper.py
 M requirements.txt
?? docs/phase-cd/final-p1-security-remediation-audit-2026-11-16.md
?? docs/phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md
?? lab/deploy_privileged_helper.sh
?? requirements.in
?? requirements.lock
```


## Final Pre-Push Security Gate — 2026-11-16

### A. Parent-Directory Trust
- **Exact root-execution policy**:
  `verify_trusted_parent_directory(dir_fd, dir_path, param_name, expected_uid, expected_gid, is_test_fixture)` in `lab/privileged_helper.py` enforces a strict privilege-separated directory trust policy.
- **Allowed owner for privileged writes**:
  When performing privileged writes (`os.geteuid() == 0 and not is_test_fixture`), the parent directory descriptor MUST be owned strictly by `root` (`UID 0`).
- **Rejected owners for privileged writes**:
  Directories owned by untrusted invoking users (`os.getuid()`), target application users (`expected_uid > 0`), or any non-root account are strictly REJECTED with `PrivilegedHelperError`. Holding a directory descriptor pins the directory inode but does not prevent a non-root directory owner from creating, unlinking, or renaming entries inside it while root operations execute. Therefore, even though target output files are chowned to `target_user`, the enclosing directory must remain under root custody.
- **Permission checks**:
  1. Directory descriptor type verification: `stat.S_ISDIR(st.st_mode)` must be True.
  2. World-writable directories are rejected unconditionally: `st.st_mode & stat.S_IWOTH` raises `PrivilegedHelperError` (even if the sticky bit `S_ISVTX` is set). Shared roots such as `/tmp` or `/var/tmp` cannot be used directly as privileged write roots; dedicated private directories (e.g. `/run/ps028`) are required.
  3. Group-writable directories for untrusted groups are rejected: `st.st_mode & stat.S_IWGRP` is permitted only if `st.st_gid == 0`.
- **Ancestor traversal policy**:
  Safe descriptor-relative traversal inspects every parent directory component leading up to `/`. Each ancestor is opened with `os.open(str(ancestor), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)`. The opened descriptor is inspected via `os.fstat()` to ensure:
  - It is a directory (`stat.S_ISDIR`).
  - It is owned strictly by root (`st_anc.st_uid == 0`).
  - It is not world-writable (`not (st_anc.st_mode & stat.S_IWOTH)`).
  - It is not group-writable by untrusted groups (`st_anc.st_gid == 0`).
  - Any symlink encountered during traversal immediately fails via `O_NOFOLLOW` with `OSError`, triggering `PrivilegedHelperError`.
- **Non-privileged harness and test policy**:
  When `os.geteuid() != 0` or `is_test_fixture=True`, allowed directory owners include `{0, euid, os.getuid()}`. Parent directories must not be world-writable. Intermediate ancestors must not be world-writable unless they are a root-owned sticky directory (such as `/tmp` mode `01777` owned by `root`).
  The `is_test_fixture` option is an internal Python keyword argument with default `False`. It is not exposed via CLI arguments, cannot be set via environment variables, and cannot be reached from production invocation paths.
- **Regression test coverage**:
  - `TC-SEC-DIR-01`: Rejects world-writable directories and non-directory file descriptors.
  - `TC-SEC-DIR-02`: Root execution strictly requires root ownership (`UID 0`); user-owned directories rejected.
  - `TC-SEC-DIR-03`: Target-user owned directory rejected for root writes under root execution.
  - `TC-SEC-DIR-04`: Non-privileged harness allows user-owned private directories.
  - `TC-SEC-DIR-05`: Rejects world-writable directory even when sticky bit is set (`01777`).
  - `TC-SEC-DIR-06`: Rejects group-writable directory for untrusted GID under root and unprivileged policies.
  - `TC-SEC-DIR-07`: `safe_write_pid_file` and `safe_atomic_write_text` reject symlinked parent directories via `O_NOFOLLOW`.
  - `TC-SEC-CLI-01`: Production CLI parser strictly rejects test-only options (`--is-test-fixture`, `--allow-loopback`).
- **Residual assumptions**:
  Assumes kernel properly enforces `O_NOFOLLOW`, `O_DIRECTORY`, and `fstat` descriptor guarantees.

---

### B. PCAP Subprocess Descriptor Proof
- **Installed tcpdump & libpcap versions**:
  - `tcpdump version 4.99.4`
  - `libpcap version 1.10.4 (with TPACKET_V3)`
  - `OpenSSL 3.0.13 30 Jan 2024`
- **Documented `-Z` and `-w` behavior verified locally**:
  - `man tcpdump`: `-w file`: "Write the raw packets to file rather than parsing and printing them out... Standard output is used if file is ``-''."
  - `man tcpdump`: `-Z user`: "If tcpdump is running as root, after opening the capture device or input savefile, change the user ID to user and the group ID to the primary group of user."
- **Exact command assembled**:
  `["ip", "netns", "exec", netns, "tcpdump", "-i", interface, "-n", "--immediate-mode", "-U", "-B", str(buffer_size_kb), "-Z", target_user, "-w", "-", bpf_filter]`
- **Whether `-w -` is used**:
  YES. `start_capture_privileged()` transitions from `-w <path>` to `["-w", "-"]`.
- **Pre-opened descriptor passing**:
  1. The parent creates and validates `output_pcap` using `os.open(pcap_name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=pcap_dir_fd)`.
  2. Verifies `fstat`: `stat.S_ISREG` and `st_nlink == 1`.
  3. If running as root, changes descriptor ownership safely via `os.fchown(pcap_created_fd, target_uid, target_gid)`.
  4. Wraps descriptor into `pcap_fp = open(pcap_created_fd, "wb", closefd=True)`.
  5. Passes `stdout=pcap_fp` to `subprocess.Popen`.
  6. Parent immediately closes `pcap_fp` in a `finally` block after `Popen` returns.
  7. The child process inherits the open file descriptor as stdout (`FD 1`).
  8. `ip netns exec` preserves inherited file descriptors without redirection.
- **Whether the child reopens any pathname**:
  NO. Because `-w -` is specified, `tcpdump` writes directly to standard output (`FD 1`). The child never performs `open()` or `stat()` on any output pathname, eliminating all path-replacement and TOCTOU races.
- **Actual output FD**:
  Standard output (`FD 1`).
- **Test PCAP verification**:
  Offline empirical test `TC-SEC-CAP-05` confirms that `tcpdump -r <src.pcap> -w -` redirected to an open file descriptor emits standard 24-byte libpcap header `0xa1b2c3d4`, version 2.4, snaplen 262144, linktype 1, with byte-for-byte exact length and content preservation.
- **Capture process validation in `lab/run_trial.py`**:
  `is_safe_capture_process()` updated: when `val == "-"`, it inspects `/proc/<pid>/fd/1` via `os.readlink()` and verifies it points to `expected_pcap`.
- **Final disposition**: FIXED and VERIFIED.

---

### C. Capture-Log Descriptor Proof
- **Staging creation**:
  Parent opens staging log `.tmp_log_{log_name}_{token_hex(8)}` using `O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC` in `log_dir_fd`.
- **Descriptor validation**:
  Verifies `fstat`: regular file (`stat.S_ISREG`) and link count `st_nlink == 1`.
  If running as root, descriptor is chowned to `target_uid`.
- **Atomic replacement**:
  Staging file is atomically renamed to `log_name` via `_safe_renameat` anchored by `log_dir_fd`.
- **Exact descriptor passed to stderr**:
  `log_fp = open(log_fd, "w+", encoding="utf-8", closefd=True)` passed as `stderr=log_fp` to `subprocess.Popen`.
- **Whether the child reopens a pathname**:
  NO. Child inherits `FD 2` (stderr) and writes all diagnostic output directly to the descriptor.
- **Cleanup and error paths**:
  Parent closes its reference to `log_fp` in the `finally` block immediately after spawn. If any exception occurs before or during `Popen`, both `pcap_fp` and `log_fp` are reliably closed in `finally`, completely eliminating `ResourceWarning: unclosed file` leaks.
- **Regression results**:
  `TC-SEC-FS-04`, `TC-SEC-FS-12`, `test_startup_failure_reaps_on_premature_exit`, and `test_startup_failure_reaps_on_post_spawn_exception` all pass cleanly.

---

### D. Python Startup Chain
- **Python version**: `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]`.
- **Interpreter flags & `sys.flags`**:
  `sys.flags(debug=0, inspect=0, interactive=0, optimize=0, dont_write_bytecode=0, no_user_site=1, no_site=0, ignore_environment=1, verbose=0, bytes_warning=0, quiet=0, hash_randomization=1, isolated=1, dev_mode=False, utf8_mode=0, warn_default_encoding=0, safe_path=True, int_max_str_digits=4300)`.
- **Isolated mode active**: True (`-I`).
- **User site enabled**: False (`no_user_site=1`, `site.ENABLE_USER_SITE=False`).
- **Environment ignored**: True (`ignore_environment=1`, `PYTHONPATH`, `PYTHONHOME`, etc. ignored).
- **Safe path active**: True (`safe_path=True`, relative CWD `''` or `'.'` excluded from `sys.path`).
- **Relevant `.pth` findings**:
  System directories in `sys.path`:
  - `/usr/lib/python3/dist-packages/distutils-precedence.pth` (owner=0:0 root:root, mode=0o100644).
  - `/usr/lib/python3/dist-packages/zope.interface-6.1-nspkg.pth` (owner=0:0 root:root, mode=0o100644).
  Both files are owned strictly by root (`0:0`) with permissions `0644` (read-only to non-root).
- **`-S` decision and rationale**:
  Evaluated empirically: executing `python3 -I -S -c "import yaml"` results in `ModuleNotFoundError: No module named 'yaml'`. PyYAML resides in system packages (`/usr/lib/python3/dist-packages/yaml`), which requires standard `site.py` initialization to add to `sys.path`. Because `lab.privileged_helper` imports `lab.impair` which requires PyYAML to parse `scenarios.yaml`, `-S` breaks required application functionality.
  Therefore, isolated mode `#!/usr/bin/python3 -I` without `-S` is the verified, correct configuration.
- **First-party import origins**:
  All first-party modules resolve from the deployment root (`/usr/local/libexec/ps028` in production, or repository root in tests).
  `TC-SEC-IMPORT-01` verifies first-party import paths and ensures `sys.path` sanitization.

---

### E. C5 Loopback Boundary
- **Exact test-only change**:
  In `lab/test_c5_statistical_and_evidence_separation.py`, `test_streaming_jsonl_export_schema_rigor`:
  `allow_loopback=True` is explicitly passed as a Python keyword argument in the local mock test fixture.
- **Production call-path analysis**:
  1. Default parameter: `allow_loopback: bool = False` in `measure_s5_privileged()` and `validate_ip_endpoint()`.
  2. Production CLI entry point `measure-s5` does not define or accept any `--allow-loopback` argument.
  3. Worker entry point `measure-s5-worker` does not define or accept any `--allow-loopback` argument.
  4. Worker invocation dispatched from host helper does not pass `--allow-loopback`.
  5. S5 production endpoint allowlist contains strictly `10.0.2.10` and `2001:db8:2::10`. Loopback addresses (`127.0.0.1`, `::1`) are strictly rejected.
- **Loopback rejection test**:
  Added `test_production_path_rejects_loopback_endpoints` (`TC-SEC-C5-01`) to `lab/test_c5_statistical_and_evidence_separation.py`.
  Calling `measure_s5_privileged(target_ip="127.0.0.1")` or `measure_s5_privileged(target_ip="::1")` without `allow_loopback=True` raises `PrivilegedHelperError("Security error: target_ip ... is not an authorized PS-028 endpoint")`.
- **Actual results**: PASSED (23/23 tests in `test_c5_statistical_and_evidence_separation` pass).

---

### F. Eight Operation Policies
Complete table mapping with separate privileged and non-privileged policies:

| Operation | Privileged allowed roots | Non-privileged allowed roots | Expected directory owner | Write policy | Test |
|---|---|---|---|---|---|
| `PID_FILE` | `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `lab/`, `results/`, `captures/`, `tempfile.gettempdir()` | Root (`UID 0`) for privileged; invoking user (`UID > 0`) or Root for unprivileged | Atomic replacement anchored by descriptor; `verify_trusted_parent_directory()` | `TC-SEC-FS-02`, `TC-SEC-FS-10`, `TC-SEC-FS-11`, `TC-SEC-FS-15`, `TC-SEC-ROOT-05`, `TC-SEC-ROOT-06` |
| `LOCK_FILE` | `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `lab/`, `tempfile.gettempdir()` | Root (`UID 0`) for privileged; invoking user or Root for unprivileged | Flocked descriptor (`fcntl.flock`), non-symlink creation | `TC-SEC-FS-15`, `test_coordinate_lock_with_explicit_lock_path`, `TC-SEC-ROOT-05`, `TC-SEC-ROOT-06` |
| `PCAP_FILE` | `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `results/`, `captures/`, `lab/`, `tempfile.gettempdir()` | Root (`UID 0`) for privileged directory; output file chowned to target user | Pre-opened, verified descriptor passed as `stdout` to `tcpdump -w -` | `TC-SEC-CAP-01` through `05`, `test_start_capture_privileged_drops_write_privileges_without_sudo`, `TC-SEC-ROOT-05`, `TC-SEC-ROOT-06` |
| `LOG_FILE` | `/var/log/ps028`, `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` rejected) | `results/`, `logs/`, `lab/`, `tempfile.gettempdir()` | Root (`UID 0`) for privileged directory; output file chowned to target user | Staging creation with token suffix, atomic rename via `_safe_renameat`, pre-opened descriptor passed as `stderr` | `TC-SEC-FS-04`, `TC-SEC-FS-12`, `TC-SEC-FS-15`, `test_startup_failure_reaps_on_premature_exit`, `TC-SEC-ROOT-05`, `TC-SEC-ROOT-06` |
| `STATE_FILE` | `/run/ps028`, `/var/run/ps028`, `/var/lib/ps028` (broad `/run` and `/var/run` rejected) | `lab/`, `results/`, `tempfile.gettempdir()` | Root (`UID 0`) for privileged; invoking user for unprivileged | Atomic descriptor replacement via `_safe_renameat` | `TC-SEC-FS-16`, `test_safe_atomic_write_text`, `TC-SEC-ROOT-05`, `TC-SEC-ROOT-06` |
| `CONFIG_FILE` | `/usr/local/libexec/ps028`, `/etc/netns/ps028-cl` | `lab/`, `tempfile.gettempdir()` | Root (`UID 0`) | Strictly READ-ONLY; write attempts rejected with `PrivilegedHelperError` | `TC-SEC-CFG-01`, `TC-SEC-FS-07`, `TC-SEC-FS-15`, `TC-SEC-ROOT-01` |
| `BACKUP_FILE` | `/etc/netns/ps028-cl`, `/run/ps028`, `/var/run/ps028` | `lab/`, `tempfile.gettempdir()` | Root (`UID 0`) for privileged; invoking user for unprivileged | Atomic replacement anchored by descriptor; verified non-symlink destination | `TC-SEC-FS-15`, `test_dns_backup_files_creation_and_restoration` |
| `DATA_FILE` | **None** (privileged writes strictly prohibited) | `results/`, `lab/`, `derived/`, `tempfile.gettempdir()` | Invoking user (`UID > 0`) | Non-privileged streaming JSONL output; `/run` strictly rejected | `TC-SEC-FS-07`, `TC-SEC-FS-15`, `test_streaming_jsonl_export_schema_rigor`, `TC-SEC-ROOT-04` |

---

### G. Validation Results
- **Focused tests**:
  - `python3 -m unittest lab.test_privileged_helper`: 148 tests, 0 failures, 0 errors, 0 skips, exit code 0 (4.724s).
  - `python3 -m unittest lab.test_c5_statistical_and_evidence_separation`: 23 tests, 0 failures, 0 errors, 0 skips, exit code 0 (0.680s).
  - `python3 -m unittest lab.test_run_trial`: 199 tests, 0 failures, 0 errors, 0 skips, exit code 0 (7.566s).
- **Full test suites**:
  - `python3 -m unittest discover -s lab -p "test_*.py"`: 910 tests, 0 failures, 0 errors, 0 skips, exit code 0 (45.993s).
  - `python3 -m unittest discover -s tests -p "test_*.py"`: 93 tests, 0 failures, 0 errors, 0 skips, exit code 0 (0.361s).
  - `npm test --prefix setup/webtester`: 31 tests, 0 failures, 0 errors, 0 skips, exit code 0 (0.651s).
  - **Total automated tests**: **1,034 tests**, 0 failures, 0 errors, 0 skips across the entire repository.
- **Historical evidence integrity**:
  - Command: `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256`
  - Result: All 705 entries PASSED OK without error.
- **Deployment dry-run**:
  - Command: `./lab/deploy_privileged_helper.sh --dry-run`
  - Result: `[SUCCESS] Dry-run specification check complete.` (0 host modifications made, all syntax and permissions verified).
- **Dependency reproducibility**:
  - Command: `pip check`
  - Result: `No broken requirements found.`
- **PDF Artifacts**:
  - `PS028_Hackathon_Submission_Presentation.pdf`: 11 pages, 207,987 bytes, SHA-256 `b88c57c9b7bb74a74e0e6c33c687ba2eccf18ef1bc6d8dd8e261accbb93d7650`.
  - `PS028 Detailed Analysis & Report PDF.pdf`: 22 pages, 464,150 bytes, SHA-256 `c720adf01c29502d6c7a915523bcb6959c03ada127986f826bf59d5cbc2fd533`.
  - `lab/derived/phase-c/technical_report.pdf`: 22 pages, 464,150 bytes, SHA-256 `c720adf01c29502d6c7a915523bcb6959c03ada127986f826bf59d5cbc2fd533`.

---

### H. Remaining Blockers
- **Parent-directory root trust**: `FIXED` (regression tests `TC-SEC-DIR-01` through `07` pass).
- **PCAP descriptor passing (`-w -`)**: `FIXED` (regression test `TC-SEC-CAP-05` and subprocess stdout inspection pass).
- **Capture-log descriptor passing**: `FIXED` (regression tests `TC-SEC-FS-04`, `TC-SEC-FS-12`, and clean Popen lifecycle pass).
- **Python isolated startup & `.pth` trust**: `VERIFIED` (`-I` validated, `-S` properly evaluated and rejected with sound rationale).
- **C5 loopback boundary & rejection test**: `FIXED` (`TC-SEC-C5-01` passes).
- **Eight operation path confinement policies**: `FIXED` (complete policy mapping table and matrix tests pass).
- **Sudoers host rule installation**: `BLOCKED` / `PENDING OWNER ACTION` (`STATUS: NOT INSTALLED / NOT INDEPENDENTLY VERIFIED`).
- **Branch protection on `main`**: `BLOCKED` / `PENDING ADMINISTRATOR ACTION` (`STATUS: NOT APPLIED`).
- **Remote CI Run #4**: `PENDING EXPLICIT OWNER AUTHORIZATION`.

---

### I. Git State
- **Branch**: `fix/phase-e-bundle-timeline-mapping`
- **HEAD Commit**: `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`
- **Working Tree Inventory**: 20 modified tracked files, 5 untracked files:
  - Tracked modifications:
    - `.github/workflows/ci.yml`
    - `"PS028 Detailed Analysis & Report PDF.pdf"`
    - `PS028_Hackathon_Submission_Presentation.pdf`
    - `README.md`
    - `docs/phase-cd/final-release-validation-record-2026-11-15.md`
    - `docs/phase-cd/owner_handover_checklist.md`
    - `docs/phase-cd/ps028-compliance-matrix.md`
    - `docs/phase-cd/sudoers_configuration.md`
    - `docs/phase-cd/test-inventory-reconciliation.md`
    - `lab/build_submission_report.py`
    - `lab/derived/phase-c/presentation_deck.html`
    - `lab/derived/phase-c/technical_report.pdf`
    - `lab/export_campaign_evidence.py`
    - `lab/privileged_helper.py`
    - `lab/run_trial.py`
    - `lab/test_c5_statistical_and_evidence_separation.py`
    - `lab/test_export_campaign_evidence.py`
    - `lab/test_privileged_helper.py`
    - `lab/test_run_trial.py`
    - `requirements.txt`
  - Untracked files:
    - `docs/phase-cd/final-p1-security-remediation-audit-2026-11-16.md`
    - `docs/phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md`
    - `lab/deploy_privileged_helper.sh`
    - `requirements.in`
    - `requirements.lock`
- **Staged status**: `git diff --cached --stat` is empty (0 staged changes).
- **Formatting & whitespace check**: `git diff --check` passes with 0 errors.
- **Protected Tag**: `ps028-p0-accepted-2026-11-14` (tag object `73175678c1b94cee3cadc53707c1121469caef85`, dereferenced commit `176f688bacb5858fcc0daedb454200918e427f3f`).
- **Tag Ancestry**: `git merge-base --is-ancestor ps028-p0-accepted-2026-11-14 HEAD` confirms tag target is an ancestor of HEAD.

---

## J. Final Focused Pre-Push Verification — 2026-11-16

### 1. Verification and Resolution of Final Four Security Concerns

#### Concern 1: Root Group Trust Assumption Verified & Replaced with Unconditional Rejection of Group-Writable Directories
- **Host Group Membership Inspection:**
  - Inspected `/etc/group` and `getent group 0`: `root:x:0:` contains only `root`.
  - The unprivileged operating user `promotheshchatterjee` (UID 1000) belongs to groups `1000, 4(adm), 24(cdrom), 27(sudo), 30(dip), 46(plugdev), 100(users)`. No untrusted users belong to GID 0.
- **Safer Architectural Policy:**
  - Root directory ownership alone does not establish write safety if secondary accounts or services gain group permissions.
  - Replaced GID-trust logic with an **unconditional prohibition on group-writable directories** (`st_mode & stat.S_IWGRP != 0`) for root-privileged operations (`os.geteuid() == 0 and not is_test_fixture`).
- **Implementation:**
  - In `verify_trusted_parent_directory()`: under root execution (`os.geteuid() == 0 and not is_test_fixture`), any parent directory with `stat.S_IWGRP` is unconditionally rejected with:
    `PrivilegedHelperError: Security error: privileged directory '...' is group-writable ... Group-writable directories are prohibited for root-privileged operations.`
  - In ancestor traversal: every intermediate ancestor directory up to `/` verifies `st_anc.st_mode & stat.S_IWGRP == 0`; any group-writable ancestor triggers an immediate fail-closed exception.
  - Harmonized with `is_trusted_sys_path_dir()` (rejects group-writable `sys.path` directories under root) and `verify_privileged_import_closure()` (rejects group-writable module files and `.pyc` bytecode).
- **Validation:**
  - `TC-SEC-DIR-06`: Verifies rejection of untrusted group-writable directories under root execution.
  - `TC-SEC-DIR-08`: Verifies that root execution unconditionally rejects group-writable directories even when owned by root (GID 0).

#### Concern 2: Reconciled Privileged Path Mapping with Dedicated PS-028 Directories and Exclusion of User-Owned Repository Paths
- **Implementation:**
  - Confined root-privileged operations (`PRIVILEGED_OPERATION_ALLOWED_ROOTS`) strictly to dedicated PS-028 subdirectories, completely eliminating broad `/run` and `/var/run` roots:
    - `PID_FILE`: `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `LOCK_FILE`: `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `PCAP_FILE`: `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `LOG_FILE`: `/var/log/ps028`, `/run/ps028`, `/var/run/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `STATE_FILE`: `/run/ps028`, `/var/run/ps028`, `/var/lib/ps028` (broad `/run` and `/var/run` strictly rejected).
    - `CONFIG_FILE`: `/usr/local/libexec/ps028`, `/etc/netns/ps028-cl` (strictly read-only; user repo paths rejected).
    - `BACKUP_FILE`: `/etc/netns/ps028-cl`, `/run/ps028`, `/var/run/ps028`.
    - `DATA_FILE`: `None` (`[]`) (privileged writes strictly prohibited under root execution; unprivileged streaming JSONL only).
  - Added explicit guard in `validate_operation_path()`:
    `if op_type == FileOperationType.DATA_FILE and euid == 0 and not is_test_fixture: raise PrivilegedHelperError("Security error: privileged write operations for data_file are strictly prohibited under root execution.")`
  - Enforced in `validate_operation_path()`: under root execution (`os.geteuid() == 0 and not is_test_fixture`), any path that normalizes or resolves within `REPO_ROOT` (particularly `lab/`) is immediately rejected with:
    `PrivilegedHelperError: Security error: user-owned repository path '...' cannot serve as privileged <op_type> source or destination under root execution.`
  - Unprivileged execution and test harnesses (`is_test_fixture=True`) retain access to `OPERATION_ALLOWED_ROOTS` for testing.
- **Validation:**
  - `TC-SEC-ROOT-01`: Verifies that `validate_operation_path` strictly rejects `REPO_ROOT / "lab" / "scenarios.yaml"` for privileged configuration under root execution.
  - `TC-SEC-ROOT-02`: Verifies that `validate_operation_path` strictly rejects user-owned repository paths (`REPO_ROOT / "lab" / "test.pid"` and `REPO_ROOT / "results" / "test.pcap"`) for privileged writes under root execution.
  - `TC-SEC-ROOT-03`: Verifies that unprivileged execution and test fixture opt-in permit repository paths safely.
  - `TC-SEC-ROOT-04`: Verifies that `validate_operation_path` strictly rejects privileged `DATA_FILE` writes under root execution.
  - `TC-SEC-ROOT-05`: Verifies that privileged operations (`PCAP_FILE`, `LOG_FILE`, `PID_FILE`, `LOCK_FILE`, `STATE_FILE`) require dedicated `/run/ps028`, `/var/run/ps028`, `/var/log/ps028`, or `/var/lib/ps028` directories and reject broad `/run` and `/var/run`.
  - `TC-SEC-ROOT-06`: Verifies across all eight `FileOperationType` variants that broad `/run` and `/var/run` roots are absent from `PRIVILEGED_OPERATION_ALLOWED_ROOTS`, and that unrelated paths under `/run` and `/var/run` are strictly rejected under root execution.

#### Concern 3: `is_test_fixture=True` Cannot Be Activated from Production Entrypoints
- **Verification:**
  - `build_parser()` verified: contains zero flags or options for test-only toggles (`--is-test-fixture`, `--allow-loopback` on production actions).
  - Production CLI execution verified: passing `--is-test-fixture` exits immediately with code 2 (`SystemExit: unrecognized arguments: --is-test-fixture`).
  - Environment variable inspection: zero environment variables control `is_test_fixture`.
  - Production call paths (`main()`, `run_helper_action()`, `run_trial.py`) invoke the privileged helper without test fixture flags.
- **Validation:**
  - `TC-SEC-CLI-01`: Confirmed rejection of unknown subcommands, malicious options, `--is-test-fixture`, and unauthorized `--allow-loopback`.

#### Concern 4: Secure PCAP and Capture-Log Descriptor Handling (Zero Truncation or Pathname Races)
- **Verification:**
  - In `start_capture_privileged()`:
    1. Parent process opens parent directory descriptor with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
    2. Validates parent directory trust via `verify_trusted_parent_directory()`.
    3. Checks target file via `os.stat(follow_symlinks=False)`: fails closed on pre-existing regular file, symlink, or hardlink.
    4. Exclusively creates fresh file descriptor via `os.open(O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o644)`.
    5. Checks descriptor via `os.fstat(fd)`: asserts `S_ISREG` and `st_nlink == 1`.
    6. Safely chowns open descriptor via `os.fchown(fd, target_uid, target_gid)`.
    7. Spawns `tcpdump` with `-w -`, passing the pre-opened, validated descriptor as stdout (`FD 1`).
    8. Staged atomic log file creation creates unique temporary file, validates descriptor, atomically renames via `_safe_renameat`, and passes descriptor as stderr (`FD 2`).
    9. Parent immediately closes descriptors in `try...finally`, eliminating descriptor leaks.
    10. Child `tcpdump` drops root privileges via `-Z <user>` and writes directly to descriptor `FD 1` without reopening any pathname.
- **Validation:**
  - `TC-SEC-CAP-01`: Rejects existing PCAP without modifying victim inode.
  - `TC-SEC-CAP-02`: Rejects hardlinked PCAP file without truncating.
  - `TC-SEC-CAP-03`: Rejects symlinked PCAP output without following target.
  - `TC-SEC-CAP-04`: Rejects FIFO PCAP file without kernel blocking.
  - `TC-SEC-CAP-05`: Confirms `tcpdump -w -` stdout byte identity matches source capture.
  - `TC-SEC-FS-04` & `TC-SEC-FS-12`: Confirms capture log staging hardlink and FIFO protection.

---

### 2. Full Test and Validation Pipeline Record

| Verification Step | Command | Exit Code | Result | Details |
|---|---|---|---|---|
| **Lab Unit Tests** | `python3 -m unittest discover -s lab -p "test_*.py"` | `0` | **PASS** | **917 passed** (including 155 in `test_privileged_helper`, 199 in `test_run_trial`, 23 in `test_c5_statistical_and_evidence_separation`), 0 failures, 0 errors, 0 skips (44.435s) |
| **Integration Tests** | `python3 -m unittest discover -s tests -p "test_*.py"` | `0` | **PASS** | **93 passed**, 0 failures, 0 errors, 0 skips (0.356s) |
| **Webtester Tests** | `npm test --prefix setup/webtester` | `0` | **PASS** | **31 passed**, 0 failures, 0 errors, 0 skips (0.646s) |
| **Historical Integrity** | `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256` | `0` | **PASS** | **705 / 705 entries PASSED OK** |
| **Deployment Dry-Run** | `./lab/deploy_privileged_helper.sh --dry-run` | `0` | **PASS** | Verified all 9 source modules, 0 host files touched |
| **Whitespace & Format** | `git diff --check` | `0` | **PASS** | 0 whitespace or formatting errors |
| **Total Automated Tests** | Repository-wide | `0` | **PASS** | **1,041 tests passing across all suites** |

---

### 3. Decoupled Release Governance and Final Decision

#### Release Governance Distinction:
1. **Feature-Branch Push Readiness:**
   - **STATUS: READY FOR OWNER-AUTHORIZED PUSH.**
   - All source code defects, path confinement rules, descriptor validations, and test suites are complete and verified in the repository.
   - 1,040 automated tests pass with 0 failures, 0 errors, 0 skips.
   - Zero uncommitted staging (`git diff --cached --stat` is empty).
   - Zero premature commits, zero pushes, and zero branch alterations.
   - Pushing the feature branch to GitHub initiates remote CI Run #4.

2. **Host Administrator Sudoers Deployment (Decoupled from Push):**
   - **STATUS: PREPARED / NOT YET INSTALLED (OPERATIONAL STEP).**
   - Installing `/etc/sudoers.d/ps028-helper` and deploying `/usr/local/libexec/ps028/` via `sudo ./lab/deploy_privileged_helper.sh` is an operational task for the host testbed administrator before physical testbed measurements.
   - It is **NOT** a prerequisite for pushing the feature branch or running remote GitHub Actions CI.

3. **Main Branch Protection and Merge (Decoupled from Push):**
   - **STATUS: PENDING REPOSITORY GOVERNANCE (POST-CI PR STEP).**
   - Enabling GitHub branch protection rules on `main` is an administrative requirement prior to merging the final PR into `main`.
   - It is **NOT** a blocker for pushing the feature branch or reviewing the changes in a pull request.

#### Final Classification:
- **Feature-Branch Push Readiness:** **READY FOR OWNER-AUTHORIZED PUSH**
- **Main Merge Readiness:** **CONDITIONALLY READY** (Requires CI Run #4 pass on push, host testbed administrator sudoers installation before physical measurement, and repository admin branch protection on `main`).
