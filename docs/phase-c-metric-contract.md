# PS-028 Phase C Metric Contract & Evidence Specification

- **Document Version**: `1.1.0` (Binding Interface Contract)
- **Status**: **PRE-IMPLEMENTATION CONTRACT (DESIGN GATE)**
- **Governing Requirement**: AIORI-3 PS-028 / Master Prompt Section 4, 5, 6 (Step 0.7)
- **Applicability**: All Phase C metric engines, parsers (`lab/run_trial.py`), analyzers (`lab/analyze.py`), and evidence exporters (`lab/export_campaign_evidence.py`).

---

## 1. Mathematical Metric Definitions & Principles

### 1.1 Core Principles
1. **Rule R3 (Field Meaning Preservation)**: Legacy `connection_setup_time_ms` retains its historical SYN-to-SYN/ACK definition and is exported as `syn_to_synack_ms` in new outputs. New metrics receive distinct, unambiguous names.
2. **Rule R4 (Unavailable $\ne$ Zero)**: Missing, unpairable, or incomplete values MUST be represented as `null` with an explicit null reason code (e.g., `INDETERMINATE_NO_FINAL_ACK`). Null values MUST NEVER be coerced to `0.0`.
3. **Rule R5 (Fail Closed)**: Incomplete classifications, unknown schemas, unverified process reloads, or missing evidence reject the trial fail-closed.
4. **Amendment A4 (Capture Vantage Point)**: All packet-derived metrics are defined strictly at the **client-side capture vantage point** (`ps028-cl` namespace, interface `ps028-cl-rt`, kernel monotonic/epoch timestamping). TShark version (`4.2.2`), parser version (`1.1.0`), and dissector flags (`-o tcp.relative_sequence_numbers:FALSE`) must be recorded in evidence provenance.
5. **Amendment A10 (Specification Pin Integrity & Status Tracking)**: The campaign's pinned specification revision of record is [`draft-ietf-happy-happyeyeballs-v3-04`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-04) (published 1 July 2026). It remains the immutable baseline of record. A dated status check tracks Datatracker status without silently altering the pin. No draft is ever described as an RFC or settled standard (Rule R7).

   > [!NOTE]
   > **Happy Eyeballs v3 Draft Status and Historical Baseline Notice (as of 13 November 2026)**
   >
   > - **Historical Experimental Baseline**: The October 2026 PS-028 campaign used [`draft-ietf-happy-happyeyeballs-v3-04`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-04), published on 1 July 2026. The campaign's methodology and historical RFC/draft assessments retain that revision as their immutable experimental reference.
   > - **Subsequent Revision**: On 2 November 2026, the IETF published [`draft-ietf-happy-happyeyeballs-v3-05`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-05). As of 13 November 2026, this revision is an active Internet-Draft in the HAPPY Working Group, with intended status Standards Track (IESG state: I-D Exists, expiring on 6 May 2027). It is not a published RFC or finalized standard.
   > - **Scope Limitation**: The October 2026 campaign predates publication of revision -05. Its historical observations and assessment results have not been evaluated or reclassified against revision -05. Revision -05 does not retroactively alter or invalidate the empirical findings obtained under revision -04.
6. **Amendment A13 (Determinism & Sibling Provenance Files)**: All derived data files (`attempts.csv`, `connection_attempts.csv`, `trial_timeline.csv`) must be deterministic and idempotent (stable sort, fixed float formatting, `\n` line endings, and **no generation timestamps inside data files**). All execution provenance (timestamps, git commit, host OS, tool versions) must be stored in sibling files named `<filename>.provenance.json`.

---

### 1.2 Handshake Latency Metrics (RFC 9293 §3.5)

```
Client (ps028-cl)                                Server (ps028-sv)
      |                                                 |
      |--- Initial SYN (t_initial_syn) ---------------->|  [SYN_SENT]
      |<-- Server SYN/ACK (t_synack) -------------------|  [SYNACK_RCVD]
      |--- Client Final ACK (t_final_ack) ------------->|  [ESTABLISHED]
      |                                                 |
```

#### 1. Primary TCP Connection Completion Time (`t_connect_ms`)
- **Governing Standards**: RFC 9293 §3.5 (Handshake Completion), Decision 1
- **Definition**: The elapsed time between the client's initial (first) SYN segment on the primary `GET /` stream and the matching client final ACK segment that transitions the connection to `ESTABLISHED`.
- **Mathematical Formula**:
  $$t_{\text{connect}} = \left( t_{\text{final\_ack, primary}} - t_{\text{initial\_syn, primary}} \right) \times 1000$$
- **Invariants**:
  - Measured **strictly** on the TCP stream carrying the primary `GET /` or `/index.html` HTTP request (`main_http_flow`).
  - **Retransmission Invariance**: Retransmitted SYNs on the primary stream MUST NOT move or advance $t_{\text{initial\_syn}}$. $t_{\text{initial\_syn}}$ is locked to the very first SYN segment observed on that stream.
  - If the server never responds with SYN/ACK, or if the client never transmits the matching final ACK, $t_{\text{connect\_ms}} = \text{null}$ with reason code `INDETERMINATE_NO_FINAL_ACK` or `INDETERMINATE_NO_SYNACK`.

#### 2. Fallback Total Setup Time (`t_setup_total_ms`)
- **Governing Requirement**: Amendment A3, Decision 1
- **Definition**: The total elapsed time from the client's first target-host SYN of **any** address family in the trial to the final ACK of the primary stream.
- **Mathematical Formula**:
  $$t_{\text{setup\_total}} = \left( t_{\text{final\_ack, primary}} - \min_{f \in \{\text{IPv4}, \text{IPv6}\}} \left( t_{\text{first\_syn, } f} \right) \right) \times 1000$$
- **Significance**:
  - In direct IPv6 connections (S0, S3), $t_{\text{setup\_total\_ms}} \approx t_{\text{connect\_ms}}$.
  - In fallback scenarios (S1, S2, S4, S5), $t_{\text{connect\_ms}}$ of the winning IPv4 stream captures only the IPv4 handshake ($\sim 20\text{ ms}$), omitting the initial failed/delayed IPv6 attempt and Connection Attempt Delay (CAD). $t_{\text{setup\_total\_ms}}$ includes the entire transport fallback setup interval before the primary stream completes and serves as the headline connection setup metric for fallback cost evaluations (without measuring application response time or page rendering).
- **Invariants**:
  - If no primary stream establishes, $t_{\text{setup\_total\_ms}} = \text{null}$.

#### 3. Diagnostic Legacy Metric (`syn_to_synack_ms`)
- **Governing Requirement**: Rule R3, Finding C1-03
- **Definition**: The elapsed time between the initial SYN on the primary stream and the matching server SYN/ACK.
- **Mathematical Formula**:
  $$t_{\text{syn\_to\_synack}} = \left( t_{\text{synack, primary}} - t_{\text{initial\_syn, primary}} \right) \times 1000$$
- **Significance**: Serves as a diagnostic path RTT proxy.

#### 4. Observed Connection Attempt Delay (`cad_ms`)
- **Governing Standard**: RFC 8305 §5
- **Definition**: The elapsed time between the initial SYN of the preferred address family (IPv6) and the initial SYN of the alternate address family (IPv4).
- **Mathematical Formula**:
  $$\text{CAD} = \left( t_{\text{first\_syn, IPv4}} - t_{\text{first\_syn, IPv6}} \right) \times 1000$$
- **Validity Rule**: Defined only when $t_{\text{first\_syn, IPv4}} \ge t_{\text{first\_syn, IPv6}}$. If IPv6 is never attempted, or IPv4 is attempted first, `cad_ms` is null with reason code `INVALID_FAMILY_CHRONOLOGY`.

---

### 1.3 DNS Resolution & Application Setup Metrics

#### 1. Exact DNS Transaction Pairing (Decision 3, Finding C1-02)
- **Correlation Tuple**: DNS queries and responses MUST be paired using a 4-field composite key:
  $$\text{DnsKey} = \left( \text{dns.id}, \text{normalized\_qname}, \text{qtype}, \text{transport\_5tuple} \right)$$
- **Normalization**:
  - `normalized_qname`: lowercased, stripped of trailing dots (e.g. `trial-xyz.he.test`). Substring matching is strictly prohibited.
  - `qtype`: standard string representation (`"A"`, `"AAAA"`, `"HTTPS"`, `"SVCB"`, `"TXT"`, etc.).
  - `transport_5tuple`: `(client_ip, client_port, server_ip, server_port, protocol)` where protocol is UDP or TCP.
- **Unmatched Transactions**: Queries without matching responses within the capture window are marked `INDETERMINATE_UNANSWERED_QUERY`. Responses without prior queries are marked `INDETERMINATE_ORPHAN_RESPONSE`.

#### 2. Per-Family DNS Resolution Durations
- For each address family $f \in \{\text{A}, \text{AAAA}\}$:
  $$\tau_{\text{dns}, f} = \left( t_{\text{response}, f} - t_{\text{query}, f} \right) \times 1000$$

#### 3. DNS-to-First-Byte Latency Metrics (Decision 2, Finding C1-04)
- **First Payload Timestamp ($t_{\text{first\_payload}}$)**: Epoch timestamp of the first data-bearing TCP segment ($(\text{tcp.len} > 0)$) received from the server on the primary `GET /` stream.
- **DNS Query to First Payload (`dns_query_to_first_payload_ms`)**:
  $$t_{\text{query\_to\_payload}} = \left( t_{\text{first\_payload, primary}} - \min \left( t_{\text{dns\_query, A}}, t_{\text{dns\_query, AAAA}} \right) \right) \times 1000$$
- **Last Positive Response to First Payload (`dns_last_positive_response_to_first_payload_ms`)**:
  $$t_{\text{response\_to\_payload}} = \left( t_{\text{first\_payload, primary}} - \max \left( t_{\text{dns\_resp, A}}, t_{\text{dns\_resp, AAAA}} \right) \right) \times 1000$$
  *(Where positive response means `RCODE == NOERROR` and answer count $> 0$)*.

#### 4. HTTPS / SVCB Query Isolation (Amendment A8, Finding C1-04)
- DNS queries for QTYPE 65 (`HTTPS`) or QTYPE 64 (`SVCB`) MUST be extracted into a dedicated collection `https_svcb_queries`.
- They MUST NOT be pooled into A or AAAA query lists or distort A/AAAA latency distributions.

---

## 2. Null Reason Codes & Validity Matrix

### 2.1 Standardized Null Reason Codes
When any metric cannot be computed from authentic packet evidence, the value MUST be `null` and accompanied by one of the following canonical reason codes:

| Reason Code | Category | Definition / Trigger Condition |
|---|---|---|
| `INDETERMINATE_NO_SYN` | Handshake | No TCP SYN segment observed for the target address family. |
| `INDETERMINATE_NO_SYNACK` | Handshake | TCP SYN was transmitted, but no server SYN/ACK segment was received (e.g. S1 blackhole). |
| `INDETERMINATE_NO_FINAL_ACK` | Handshake | Server SYN/ACK was received, but client never transmitted the completing ACK. |
| `INDETERMINATE_CONN_RESET` | Handshake | TCP SYN was actively rejected with TCP RST before handshake completion (e.g. S2 active reset). |
| `INDETERMINATE_NO_PRIMARY_FLOW` | Application | No HTTP `GET /` or `/index.html` transaction was correlated on any stream. |
| `INDETERMINATE_NO_PAYLOAD` | Application | Connection reached ESTABLISHED, but no server data payload (`tcp.len > 0`) was received. |
| `INDETERMINATE_UNPAIRABLE_DNS` | DNS | DNS query and response could not be paired by exact ID, QNAME, and 5-tuple. |
| `INDETERMINATE_CAPTURE_LOSS` | Packet Loss | PCAP capture interface reported packet drop ($>0$), invalidating timing chronology. |
| `INVALID_FAMILY_CHRONOLOGY` | Pacing | Alternate family attempt occurred before primary family attempt, preventing CAD calculation. |
| `NOT_APPLICABLE_HEALTHY_PATH` | Scenario | Fallback or CAD metric not applicable in healthy dual-stack conditions where primary path won immediately. |

---

### 2.2 Shared Fallback Classification Enum (C2-02)

Every trial is assigned exactly one classification from the canonical shared enum:

```python
class FallbackClassification(str, Enum):
    DIRECT_IPV6 = "DIRECT_IPV6"
    DIRECT_IPV4 = "DIRECT_IPV4"
    IPV6_TO_IPV4_FALLBACK = "IPV6_TO_IPV4_FALLBACK"
    IPV4_TO_IPV6_FALLBACK = "IPV4_TO_IPV6_FALLBACK"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
```

#### Decision Rules for Classification:
1. `DIRECT_IPV6`: IPv6 primary stream established; HTTP `GET /` succeeded on IPv6; no IPv4 SYN sent, OR IPv4 SYN sent after IPv6 established but not used.
2. `DIRECT_IPV4`: IPv4 primary stream established; HTTP `GET /` succeeded on IPv4; no IPv6 SYN sent.
3. `IPV6_TO_IPV4_FALLBACK`: IPv6 SYN sent first; IPv4 SYN sent subsequently; IPv4 primary stream successfully established and served the primary HTTP document.
4. `IPV4_TO_IPV6_FALLBACK`: IPv4 SYN sent first; IPv6 SYN sent subsequently; IPv6 primary stream established and served primary HTTP document.
5. `CONNECTION_FAILED`: Neither address family established a primary HTTP connection.
6. `INCONCLUSIVE`: Measurement failure, zero packets captured, capture drop $>0$ masking alternate attempts, or uncorroborated telemetry.

---

### 2.3 Shared Trial Validity Enum (C2-02)

Every trial attempt is categorized by a single validity enum:

```python
class TrialValidity(str, Enum):
    VALID_LIVE = "VALID_LIVE"
    SIMULATION = "SIMULATION"
    CLEANUP_FAILURE = "CLEANUP_FAILURE"
    MEASUREMENT_FAILURE = "MEASUREMENT_FAILURE"
    CORRUPTED_RECORD = "CORRUPTED_RECORD"
```

---

## 3. Result Schema Evolution (Schema 1.1.0)

### 3.1 Version Compatibility Contract
- **Schema Version**: `"1.1.0"`.
- **Backward Compatibility**: `lab/analyze.py` MUST accept both `"1.0.0"` and `"1.1.0"`.
- **Fail-Closed Enforcement**: Any record with `schema_version` outside `["1.0.0", "1.1.0"]` MUST be rejected fail-closed as `CORRUPTED_RECORD`.

### 3.2 Schema 1.1.0 Structure (`result.json`)
```json
{
  "schema_version": "1.1.0",
  "trial_id": "trial-20261111180000-a1b2c3d4",
  "campaign_id": "ps028-a10-live-20261030-01",
  "scenario_id": "S1",
  "browser": "google-chrome",
  "browser_version": "156.0.8078.73",
  "repetition": 1,
  "execution_mode": "LIVE",
  "is_simulation": false,
  "validity_category": "VALID_LIVE",
  "classification": "IPV6_TO_IPV4_FALLBACK",
  "classification_reason": "IPv6 SYN blackholed; IPv4 fallback SYN launched at 301.19ms; primary GET / served over IPv4.",
  "metrics": {
    "t_connect_ms": 20.45,
    "t_setup_total_ms": 321.64,
    "syn_to_synack_ms": 19.82,
    "connection_attempt_delay_ms": 301.19,
    "dns_query_to_first_payload_ms": 332.10,
    "dns_last_positive_response_to_first_payload_ms": 326.85,
    "dns_resolution_time_ms": 5.25,
    "dns_latency_a_ms": 5.25,
    "dns_latency_aaaa_ms": 5.10,
    "retransmitted_syn_count_ipv6": 1,
    "retransmitted_syn_count_ipv4": 0,
    "null_reasons": {}
  },
  "primary_flow": {
    "stream_id": "IPv4:10.0.1.2:48912->10.0.2.10:80",
    "family": "IPv4",
    "client_endpoint": ["10.0.1.2", 48912],
    "server_endpoint": ["10.0.2.10", 80],
    "syn_frame": 12,
    "syn_time": 1730242500.30119,
    "syn_ack_frame": 14,
    "syn_ack_time": 1730242500.32101,
    "final_ack_frame": 15,
    "final_ack_time": 1730242500.32164,
    "handshake_completed": true,
    "http_request_frame": 16,
    "http_response_frame": 18,
    "http_status_code": 200,
    "pcap_sha256": "69fd09eb63b53f2be42428e40d99ed61eeef4da47bead93fe129ecab1ba47f72"
  },
  "dns_transactions": [
    {
      "dns_id": 41235,
      "qname": "trial-20261111180000-a1b2c3d4.he.test",
      "qtype": "AAAA",
      "rcode": "NOERROR",
      "transport": "UDP",
      "query_frame": 2,
      "query_time": 1730242500.00010,
      "response_frame": 4,
      "response_time": 1730242500.00520,
      "duration_ms": 5.10,
      "answers": ["2001:db8:2::10"]
    },
    {
      "dns_id": 41236,
      "qname": "trial-20261111180000-a1b2c3d4.he.test",
      "qtype": "A",
      "rcode": "NOERROR",
      "transport": "UDP",
      "query_frame": 3,
      "query_time": 1730242500.00015,
      "response_frame": 5,
      "response_time": 1730242500.00540,
      "duration_ms": 5.25,
      "answers": ["10.0.2.10"]
    }
  ],
  "https_svcb_queries": [],
  "evidence_provenance": {
    "vantage_point": "ps028-cl:ps028-cl-rt",
    "tshark_version": "4.2.2",
    "tcpdump_version": "4.99.4",
    "parser_version": "1.1.0",
    "dissector_flags": ["-o", "tcp.relative_sequence_numbers:FALSE"]
  }
}
```

---

## 4. Evidence Export File Specifications (WP C2)

### 4.1 Campaign Attempts Export (`attempts.csv`)
- **Governing Requirement**: Finding C2-01, Amendment A1
- **File Location**: `lab/derived/phase-c/attempts.csv`
- **Rows**: Exactly 282 rows reconciling 280 valid live attempts + 2 preserved cleanup failures.
- **Header Columns**:
  ```csv
  attempt_id,slot_id,slot_index,campaign_id,scenario_id,browser,repetition,attempt_number,trial_id,status,validity_category,classification,http_status,t_connect_ms,t_setup_total_ms,syn_to_synack_ms,cad_ms,pcap_sha256,start_time,end_time
  ```

---

### 4.2 Per-TCP-Flow Connection Attempts (`connection_attempts.csv`)
- **Governing Requirement**: Amendment A1, Decision 1
- **File Location**: `lab/derived/phase-c/connection_attempts.csv`
- **Definition**: One row per distinct TCP connection attempt to the target service in every trial across all 280 historical trials and new trials.
- **Header Columns**:
  ```csv
  trial_id,pcap_sha256,tcp_stream,family,client_ip,client_port,server_ip,server_port,syn_time,synack_time,final_ack_time,rst_time,offset_from_first_syn_ms,outcome,is_primary,retransmitted_syn_count
  ```
- **Allowed `outcome` Values**:
  - `ESTABLISHED_PRIMARY`: Connection completed handshake and carried the primary HTTP GET request.
  - `ESTABLISHED_ANCILLARY`: Connection completed handshake for ancillary traffic (e.g. favicon, preconnect).
  - `RESET`: Connection actively rejected via TCP RST.
  - `NO_SYNACK_TIMEOUT`: SYN transmitted, but server never responded (timed out / abandoned).
  - `ABANDONED`: Connection attempt abandoned by client before completion.
  - `INDETERMINATE`: Packet loss or unpairable frames prevent outcome determination.

---

### 4.3 Unified Packet-and-Harness Timeline (`trial_timeline.csv`)
- **Governing Requirement**: Amendment A9
- **File Location**: `lab/derived/phase-c/trial_timeline.csv`
- **Definition**: Chronologically ordered events merging harness orchestration timestamps with packet-level network events. Missing timestamps remain empty/null; timestamps MUST NEVER be fabricated.
- **Header Columns**:
  ```csv
  trial_id,event_index,event_timestamp_epoch,event_source,event_type,address_family,tcp_stream,frame_number,details,pcap_sha256,source_path
  ```
- **Allowed `event_source` Values**:
  - `HARNESS`: Orchestrator event (e.g. `TRIAL_START`, `IMPAIRMENT_APPLIED`, `BROWSER_LAUNCH`, `CLEANUP_COMPLETE`).
  - `PCAP`: Packet capture event (e.g. `DNS_QUERY`, `DNS_RESPONSE`, `TCP_SYN`, `TCP_SYNACK`, `TCP_FINAL_ACK`, `TCP_RST`, `HTTP_GET`, `HTTP_RESPONSE_HEADERS`).
  - `BROWSER_TELEMETRY`: Diagnostic browser log event (e.g. NetLog `URL_REQUEST_START_JOB`).

---

### 4.4 Sibling Provenance Files (Amendment A13)
- In accordance with Amendment A13, derived data files (`attempts.csv`, `connection_attempts.csv`, `trial_timeline.csv`) contain pure experimental data and NEVER contain generation timestamps or environment ephemera that would break byte-identical re-generation.
- Every export is accompanied by a sibling JSON file: `<export_path>.provenance.json` (e.g. `attempts.csv.provenance.json`).
- **Required Provenance Fields**:
  ```json
  {
    "target_file": "attempts.csv",
    "sha256": "...",
    "row_count": 282,
    "generated_by_command": "python3 lab/export_campaign_evidence.py",
    "git_commit": "7c6ab23c2a378bbc8556fcc15f5911f626502576",
    "git_branch": "regional/ps028-phase-cd",
    "python_version": "3.12.3",
    "tshark_version": "4.2.2",
    "platform": "Linux-6.18.58.1-microsoft-standard-WSL2-x86_64",
    "dissector_flags": ["-o", "tcp.relative_sequence_numbers:FALSE"]
  }
  ```

---

## 5. Four Evidence Classes Reporting Protocol (Rule R6)

All verification reports and batch gate reports MUST partition evidence into four distinct, non-overlapping classes:
1. **Class A: Deterministic Unit Tests** (`lab/test_*.py`): Fully offline, mock-based or loopback tests verifying algorithms, state machines, and schemas.
2. **Class B: Synthetic & Fixture PCAP Tests** (`tests/`, `lab/test_analyze.py` fixtures): Boundary fixtures testing synthetic packet timestamps (<10ms, >2000ms, corrupt headers, etc.).
3. **Class C: Historical Authentic-PCAP Validation**: Offline re-derivation across all 280 preserved October 29 campaign PCAPs (`lab/campaigns/ps028-a10-live-20261030-01/`).
4. **Class D: New Live Acceptance**: New live network namespace executions (`ps028-cl`, `ps028-rt`, `ps028-sv`) performed ONLY under explicit operator approval.

These four classes MUST NEVER be merged into a single generic "PASS" indicator.
