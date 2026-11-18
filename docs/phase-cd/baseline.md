# Baseline Environment and Offline Test Suite Execution Log

- **Date / Timestamp**: 2026-11-11T18:15:00Z
- **Repository**: `<repo_root>`
- **Work Branch**: `regional/ps028-phase-cd`
- **Base Branch**: `regional/p0-remediation`
- **Base Commit**: `7c6ab23c2a378bbc8556fcc15f5911f626502576` (`Finalize A5 portability and B3 PCAP regressions`)
- **Git Status**: Clean working tree on branch `regional/ps028-phase-cd` (untracked: `.agents/`, `PROJECT.md`)

---

## 1. Environment & Toolchain Versions

### 1.1 Python Version & Path
- **Command**: `python3 --version && which python3`
- **Version**: `Python 3.12.3`
- **Binary Path**: `/usr/bin/python3`

### 1.2 Operating System & Kernel
- **Command**: `uname -a && cat /etc/os-release`
- **Kernel (`uname -a`)**:
  ```
  Linux DELLg15-C6S8DCG 6.18.58.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Tue Oct 27 00:24:11 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
  ```
- **OS Distribution**:
  ```
  NAME="Ubuntu"
  VERSION_ID="24.04"
  VERSION="24.04.5 LTS (Noble Numbat)"
  ID=ubuntu
  ID_LIKE=debian
  PRETTY_NAME="Ubuntu 24.04.5 LTS"
  VERSION_CODENAME=noble
  UBUNTU_CODENAME=noble
  ```

### 1.3 TShark (Wireshark)
- **Command**: `tshark --version`
- **Version**: `TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)`
- **Binary Path**: `/usr/bin/tshark`
- **Build / Library Details**:
  - Compiled (64-bit) using GCC 13.2.0, with GLib 2.80.0, with libpcap, with POSIX capabilities (Linux), with libnl 3, with zlib 1.3, with PCRE2, with Lua 5.2.4, with GnuTLS 3.8.3 and PKCS #11 support, with Gcrypt 1.10.3, with Kerberos (MIT), with MaxMind, with nghttp2 1.59.0, with nghttp3 0.8.0, with brotli, with LZ4, with Zstandard, with Snappy, with libxml2 2.9.14, with libsmi 0.4.8, with binary plugins.
  - Running on Linux 6.18.58.1-microsoft-standard-WSL2, with 13th Gen Intel(R) Core(TM) i5-13450HX, with libpcap 1.10.4, with c-ares 1.27.0.

### 1.4 Git
- **Command**: `git --version && which git`
- **Version**: `git version 2.43.0`
- **Binary Path**: `/usr/bin/git`

---

## 2. Baseline Test Suite Execution

### 2.1 Execution Command
```bash
python3 -m unittest discover -s lab -p "test_*.py" -v
```

### 2.2 Test Results Summary
- **Total Tests Run**: 524
- **Passed**: 524 (100.0%)
- **Failures**: 0
- **Errors**: 0
- **Skipped**: 0
- **Execution Duration**: 18.317 seconds
- **Exit Code**: 0 (OK)

### 2.3 Module Breakdown
| Test Module | Test Count | Status | Description / Coverage Area |
|---|:---:|:---:|---|
| `lab/test_analyze.py` | 64 | PASS | Analysis metrics, Wilson CI, bootstrap CI, schema handling, exclusions |
| `lab/test_campaign_pcap_regression.py` | 4 | PASS | TShark regression on historical campaign PCAPs |
| `lab/test_concurrency.py` | 8 | PASS | Advisory file locking and concurrency protections |
| `lab/test_dns_server.py` | 11 | PASS | Custom DNS server packet handling and response logic |
| `lab/test_impair.py` | 35 | PASS | Impairment logic, CLI parser, netem and nftables generation |
| `lab/test_nginx.py` | 4 | PASS | Nginx configuration parsing and port bindings |
| `lab/test_preflight.py` | 6 | PASS | Preflight verification and namespace checks |
| `lab/test_privileged_helper.py` | 85 | PASS | Allowlisted actions, integer bounds, dry-run safety |
| `lab/test_run_campaign.py` | 32 | PASS | Campaign orchestration, matrix permutation, slot recovery |
| `lab/test_run_trial.py` | 185 | PASS | Trial execution, PCAP dissection, TCP handshake tracking |
| `lab/test_self_test_scenarios.py` | 67 | PASS | S0–S6 scenario self-testing, RTT parsing, probe generation |
| `lab/test_teardown.py` | 23 | PASS | Multi-stage safe teardown and resource cleanup |
| **Total** | **524** | **100% PASS** | **Complete pre-operation test baseline** |

---

## 3. Baseline Conclusion
The test suite executed completely cleanly without any modifications to source code. The baseline of 524 unit and regression tests is 100% passing. This establishes the pre-flight baseline prior to any Phase C/D implementations.
