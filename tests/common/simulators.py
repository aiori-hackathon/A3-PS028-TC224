"""
PS-028 Common Simulators and Validators
Pure-Python, offline implementations of RFC 8305 Happy Eyeballs state machine,
DNS wire codec, result schema validator, and export reconciler.
"""

import io
import math
import random
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from tests.common.models import (
    AddressFamily,
    AttemptRecord,
    AttemptValidity,
    ConnectionAttemptRecord,
    ConnectionOutcome,
    DNSTransaction,
    EventSource,
    ScenarioSpec,
    TCPPacket,
    TimelineRecord,
    TrialMetrics,
)


# ==============================================================================
# RFC 8305 Happy Eyeballs Racing Simulator
# ==============================================================================

class HappyEyeballsSimulator:
    """
    Opaque-box reference simulation of RFC 8305 connection racing and RFC 9293
    TCP handshake mechanics.
    """

    def __init__(
        self,
        resolution_delay_ms: float = 50.0,
        connection_attempt_delay_ms: float = 250.0,
        dns_a_delay_ms: float = 0.0,
        dns_aaaa_delay_ms: float = 0.0,
        ipv6_rtt_ms: Optional[float] = 20.0,
        ipv4_rtt_ms: Optional[float] = 20.0,
        ipv6_rst: bool = False,
        ipv4_rst: bool = False,
        ipv6_syn_loss_pct: float = 0.0,
        ipv4_syn_loss_pct: float = 0.0,
        syn_retransmit_timeout_ms: float = 1000.0,
        max_syn_retransmits: int = 2,
        simulate_missing_final_ack: bool = False,
        include_svcb: bool = False,
        dns_svcb_delay_ms: float = 0.0,
        seed: Optional[int] = 42,
    ):
        self.resolution_delay_ms = float(resolution_delay_ms)
        self.cad_ms = float(connection_attempt_delay_ms)
        self.dns_a_delay_ms = float(dns_a_delay_ms)
        self.dns_aaaa_delay_ms = float(dns_aaaa_delay_ms)
        self.ipv6_rtt_ms = float(ipv6_rtt_ms) if ipv6_rtt_ms is not None else None
        self.ipv4_rtt_ms = float(ipv4_rtt_ms) if ipv4_rtt_ms is not None else None
        self.ipv6_rst = bool(ipv6_rst)
        self.ipv4_rst = bool(ipv4_rst)
        self.ipv6_syn_loss_pct = float(ipv6_syn_loss_pct)
        self.ipv4_syn_loss_pct = float(ipv4_syn_loss_pct)
        self.syn_retransmit_timeout_ms = float(syn_retransmit_timeout_ms)
        self.max_syn_retransmits = int(max_syn_retransmits)
        self.simulate_missing_final_ack = bool(simulate_missing_final_ack)
        self.include_svcb = bool(include_svcb)
        self.dns_svcb_delay_ms = float(dns_svcb_delay_ms)
        self.rng = random.Random(seed)

    def run(self, trial_id: str = "trial-sim-001") -> Tuple[TrialMetrics, List[TCPPacket], List[TimelineRecord], List[ConnectionAttemptRecord]]:
        packets: List[TCPPacket] = []
        timeline: List[TimelineRecord] = []
        conn_attempts: List[ConnectionAttemptRecord] = []
        dns_transactions: List[DNSTransaction] = []
        https_svcb_queries: List[DNSTransaction] = []

        timeline.append(TimelineRecord(trial_id, 0.0, EventSource.HARNESS.value, "TRIAL_START", f"Starting trial {trial_id}"))

        # Step 1: DNS Resolution Phase (RFC 8305 §3)
        # Simultaneous A and AAAA queries dispatched at t=0
        dns_tx_a = DNSTransaction(
            dns_id=1001,
            qname="test.happy-eyeballs.lab",
            qtype=1,
            qtype_name="A",
            rcode=0,
            transport="UDP",
            answers=["10.0.2.10"],
            query_time_ms=0.0,
            response_time_ms=self.dns_a_delay_ms,
            duration_ms=self.dns_a_delay_ms,
        )
        dns_transactions.append(dns_tx_a)

        dns_tx_aaaa = DNSTransaction(
            dns_id=1002,
            qname="test.happy-eyeballs.lab",
            qtype=28,
            qtype_name="AAAA",
            rcode=0,
            transport="UDP",
            answers=["2001:db8:2::10"],
            query_time_ms=0.0,
            response_time_ms=self.dns_aaaa_delay_ms,
            duration_ms=self.dns_aaaa_delay_ms,
        )
        dns_transactions.append(dns_tx_aaaa)

        if self.include_svcb:
            dns_tx_svcb = DNSTransaction(
                dns_id=1003,
                qname="test.happy-eyeballs.lab",
                qtype=65,
                qtype_name="HTTPS",
                rcode=0,
                transport="UDP",
                answers=["alpn=h2,h3"],
                query_time_ms=0.0,
                response_time_ms=self.dns_svcb_delay_ms,
                duration_ms=self.dns_svcb_delay_ms,
            )
            https_svcb_queries.append(dns_tx_svcb)

        timeline.append(TimelineRecord(trial_id, self.dns_a_delay_ms, EventSource.PCAP.value, "DNS_RESPONSE_A", "A record received"))
        timeline.append(TimelineRecord(trial_id, self.dns_aaaa_delay_ms, EventSource.PCAP.value, "DNS_RESPONSE_AAAA", "AAAA record received"))

        # Step 2: Scheduling Connection Attempts (RFC 8305 §3 & §5)
        # If AAAA response arrives within resolution_delay_ms, IPv6 is preferred and scheduled first.
        # If A arrives and AAAA does not arrive within resolution_delay_ms, IPv4 is scheduled first.
        t_v6_start: Optional[float] = None
        t_v4_start: Optional[float] = None

        if self.dns_aaaa_delay_ms <= self.resolution_delay_ms:
            # Normal Happy Eyeballs: IPv6 is scheduled immediately upon AAAA receipt
            t_v6_start = self.dns_aaaa_delay_ms
        else:
            # AAAA is delayed beyond resolution delay
            if self.dns_a_delay_ms <= self.resolution_delay_ms:
                # IPv4 is started when resolution delay expires
                t_v4_start = self.resolution_delay_ms
                # IPv6 will start when AAAA arrives, if IPv4 hasn't already won
                t_v6_start = self.dns_aaaa_delay_ms
            else:
                # Both delayed beyond resolution delay; start IPv4 when A arrives
                t_v4_start = self.dns_a_delay_ms
                t_v6_start = self.dns_aaaa_delay_ms

        # State tracking for streams
        # stream 0: IPv6 (if attempted first) or whichever starts first
        stream_counter = 0

        # Helper to simulate a single family's handshake
        def simulate_flow(
            family: str,
            start_time: float,
            rtt: Optional[float],
            is_rst: bool,
            loss_pct: float,
            src_ip: str,
            dst_ip: str,
            stream_id: int,
        ) -> Dict[str, Any]:
            flow_packets: List[TCPPacket] = []
            cur_time = start_time
            initial_syn_time = start_time
            attempts = 0

            flow_packets.append(TCPPacket(
                timestamp_ms=cur_time,
                src_ip=src_ip,
                src_port=40000 + stream_id,
                dst_ip=dst_ip,
                dst_port=80,
                family=family,
                stream_id=stream_id,
                syn=True,
                seq=1000,
            ))

            while attempts <= self.max_syn_retransmits:
                attempts += 1
                # Check for SYN drop/loss
                lost = (self.rng.random() * 100.0) < loss_pct if loss_pct > 0 else False

                if lost or rtt is None:
                    # Packet lost or blackholed
                    if attempts <= self.max_syn_retransmits:
                        cur_time += self.syn_retransmit_timeout_ms
                        flow_packets.append(TCPPacket(
                            timestamp_ms=cur_time,
                            src_ip=src_ip,
                            src_port=40000 + stream_id,
                            dst_ip=dst_ip,
                            dst_port=80,
                            family=family,
                            stream_id=stream_id,
                            syn=True,
                            seq=1000,
                        ))
                        continue
                    else:
                        # Timeout
                        return {
                            "outcome": ConnectionOutcome.TIMEOUT.value,
                            "initial_syn_ms": initial_syn_time,
                            "syn_ack_ms": None,
                            "final_ack_ms": None,
                            "established": False,
                            "reset": False,
                            "packets": flow_packets,
                        }

                if is_rst:
                    # Server sends RST
                    rst_time = cur_time + (rtt / 2.0 if rtt else 1.0)
                    flow_packets.append(TCPPacket(
                        timestamp_ms=rst_time,
                        src_ip=dst_ip,
                        src_port=80,
                        dst_ip=src_ip,
                        dst_port=40000 + stream_id,
                        family=family,
                        stream_id=stream_id,
                        rst=True,
                        seq=0,
                        ack_seq=1001,
                    ))
                    return {
                        "outcome": ConnectionOutcome.RESET.value,
                        "initial_syn_ms": initial_syn_time,
                        "syn_ack_ms": None,
                        "final_ack_ms": None,
                        "established": False,
                        "reset": True,
                        "reset_time_ms": rst_time,
                        "packets": flow_packets,
                    }

                # Normal SYN/ACK
                syn_ack_time = cur_time + (rtt / 2.0)
                flow_packets.append(TCPPacket(
                    timestamp_ms=syn_ack_time,
                    src_ip=dst_ip,
                    src_port=80,
                    dst_ip=src_ip,
                    dst_port=40000 + stream_id,
                    family=family,
                    stream_id=stream_id,
                    syn=True,
                    ack=True,
                    seq=2000,
                    ack_seq=1001,
                ))

                if self.simulate_missing_final_ack:
                    # Client fails to emit final ACK
                    return {
                        "outcome": ConnectionOutcome.INCOMPLETE.value,
                        "initial_syn_ms": initial_syn_time,
                        "syn_ack_ms": syn_ack_time,
                        "final_ack_ms": None,
                        "established": False,
                        "reset": False,
                        "packets": flow_packets,
                    }

                # Final ACK
                final_ack_time = cur_time + rtt
                flow_packets.append(TCPPacket(
                    timestamp_ms=final_ack_time,
                    src_ip=src_ip,
                    src_port=40000 + stream_id,
                    dst_ip=dst_ip,
                    dst_port=80,
                    family=family,
                    stream_id=stream_id,
                    ack=True,
                    seq=1001,
                    ack_seq=2001,
                ))

                # HTTP GET / request and response payload
                get_req_time = final_ack_time + 1.0
                flow_packets.append(TCPPacket(
                    timestamp_ms=get_req_time,
                    src_ip=src_ip,
                    src_port=40000 + stream_id,
                    dst_ip=dst_ip,
                    dst_port=80,
                    family=family,
                    stream_id=stream_id,
                    ack=True,
                    payload_len=75,
                ))

                payload_resp_time = get_req_time + (rtt / 2.0)
                flow_packets.append(TCPPacket(
                    timestamp_ms=payload_resp_time,
                    src_ip=dst_ip,
                    src_port=80,
                    dst_ip=src_ip,
                    dst_port=40000 + stream_id,
                    family=family,
                    stream_id=stream_id,
                    ack=True,
                    payload_len=256,
                ))

                return {
                    "outcome": ConnectionOutcome.ESTABLISHED.value,
                    "initial_syn_ms": initial_syn_time,
                    "syn_ack_ms": syn_ack_time,
                    "final_ack_ms": final_ack_time,
                    "first_payload_ms": payload_resp_time,
                    "established": True,
                    "reset": False,
                    "packets": flow_packets,
                }

        # Step 3: Run the race
        # Case A: IPv6 scheduled first
        v6_res: Optional[Dict[str, Any]] = None
        v4_res: Optional[Dict[str, Any]] = None
        v6_stream_id = 0
        v4_stream_id = 1

        first_syn_time: Optional[float] = None

        if t_v6_start is not None and (t_v4_start is None or t_v6_start <= t_v4_start):
            first_syn_time = t_v6_start
            v6_res = simulate_flow(
                family=AddressFamily.IPV6.value,
                start_time=t_v6_start,
                rtt=self.ipv6_rtt_ms,
                is_rst=self.ipv6_rst,
                loss_pct=self.ipv6_syn_loss_pct,
                src_ip="2001:db8:1::2",
                dst_ip="2001:db8:2::10",
                stream_id=v6_stream_id,
            )
            packets.extend(v6_res["packets"])

            # Check if IPv6 established before CAD expires
            v6_est_time = v6_res.get("final_ack_ms")
            v6_reset_time = v6_res.get("reset_time_ms")

            if v6_res["reset"]:
                # RFC 8305 §5: Immediate fallback on RST
                t_v4_start = v6_reset_time
            elif v6_res["established"] and v6_est_time is not None and (v6_est_time - t_v6_start) <= self.cad_ms:
                # IPv6 established before CAD timer expired; no IPv4 needed
                t_v4_start = None
            else:
                # CAD expires before IPv6 established; launch IPv4
                t_v4_start = t_v6_start + self.cad_ms

        if t_v4_start is not None:
            if first_syn_time is None or t_v4_start < first_syn_time:
                first_syn_time = t_v4_start
            v4_res = simulate_flow(
                family=AddressFamily.IPV4.value,
                start_time=t_v4_start,
                rtt=self.ipv4_rtt_ms,
                is_rst=self.ipv4_rst,
                loss_pct=self.ipv4_syn_loss_pct,
                src_ip="10.0.1.2",
                dst_ip="10.0.2.10",
                stream_id=v4_stream_id,
            )
            packets.extend(v4_res["packets"])

        # If IPv6 had delayed start after IPv4:
        if v6_res is None and t_v6_start is not None:
            # Check if IPv4 already completed before t_v6_start
            v4_est = v4_res.get("final_ack_ms") if v4_res else None
            if v4_est is None or v4_est > t_v6_start:
                v6_res = simulate_flow(
                    family=AddressFamily.IPV6.value,
                    start_time=t_v6_start,
                    rtt=self.ipv6_rtt_ms,
                    is_rst=self.ipv6_rst,
                    loss_pct=self.ipv6_syn_loss_pct,
                    src_ip="2001:db8:1::2",
                    dst_ip="2001:db8:2::10",
                    stream_id=v6_stream_id,
                )
                packets.extend(v6_res["packets"])

        # Sort all packets deterministically by timestamp
        packets.sort(key=lambda p: p.timestamp_ms)

        # Step 4: Determine Winner and Compute Metrics
        # Winner is whichever established first
        v6_win_time = v6_res.get("final_ack_ms") if (v6_res and v6_res.get("established")) else None
        v4_win_time = v4_res.get("final_ack_ms") if (v4_res and v4_res.get("established")) else None

        winning_family: Optional[str] = None
        primary_res: Optional[Dict[str, Any]] = None

        if v6_win_time is not None and v4_win_time is not None:
            if v6_win_time <= v4_win_time:
                winning_family = AddressFamily.IPV6.value
                primary_res = v6_res
            else:
                winning_family = AddressFamily.IPV4.value
                primary_res = v4_res
        elif v6_win_time is not None:
            winning_family = AddressFamily.IPV6.value
            primary_res = v6_res
        elif v4_win_time is not None:
            winning_family = AddressFamily.IPV4.value
            primary_res = v4_res

        # Record connection attempts
        if v6_res:
            dur = None
            if v6_res.get("final_ack_ms"):
                dur = round(v6_res["final_ack_ms"] - v6_res["initial_syn_ms"], 3)
            conn_attempts.append(ConnectionAttemptRecord(
                trial_id=trial_id,
                stream_id=v6_stream_id,
                family=AddressFamily.IPV6.value,
                src_ip="2001:db8:1::2",
                src_port=40000 + v6_stream_id,
                dst_ip="2001:db8:2::10",
                dst_port=80,
                syn_start_ms=round(v6_res["initial_syn_ms"], 3),
                ack_end_ms=round(v6_res["final_ack_ms"], 3) if v6_res.get("final_ack_ms") else None,
                duration_ms=dur,
                outcome=v6_res["outcome"],
            ))

        if v4_res:
            dur = None
            if v4_res.get("final_ack_ms"):
                dur = round(v4_res["final_ack_ms"] - v4_res["initial_syn_ms"], 3)
            conn_attempts.append(ConnectionAttemptRecord(
                trial_id=trial_id,
                stream_id=v4_stream_id,
                family=AddressFamily.IPV4.value,
                src_ip="10.0.1.2",
                src_port=40000 + v4_stream_id,
                dst_ip="10.0.2.10",
                dst_port=80,
                syn_start_ms=round(v4_res["initial_syn_ms"], 3),
                ack_end_ms=round(v4_res["final_ack_ms"], 3) if v4_res.get("final_ack_ms") else None,
                duration_ms=dur,
                outcome=v4_res["outcome"],
            ))

        # Calculate connection metrics
        t_connect_ms: Optional[float] = None
        t_setup_total_ms: Optional[float] = None
        syn_to_synack_ms: Optional[float] = None
        dns_query_to_first_payload_ms: Optional[float] = None
        dns_last_positive_response_to_first_payload_ms: Optional[float] = None
        reason_code: Optional[str] = None

        if primary_res and winning_family:
            final_ack = primary_res["final_ack_ms"]
            initial_syn = primary_res["initial_syn_ms"]
            syn_ack = primary_res["syn_ack_ms"]

            t_connect_ms = round(final_ack - initial_syn, 3)
            if first_syn_time is not None:
                t_setup_total_ms = round(final_ack - first_syn_time, 3)
            if syn_ack is not None:
                syn_to_synack_ms = round(syn_ack - initial_syn, 3)

            first_payload = primary_res.get("first_payload_ms")
            if first_payload:
                dns_query_to_first_payload_ms = round(first_payload - 0.0, 3)
                last_dns = max(self.dns_a_delay_ms, self.dns_aaaa_delay_ms)
                dns_last_positive_response_to_first_payload_ms = round(first_payload - last_dns, 3)
        else:
            # Failure reason
            if self.simulate_missing_final_ack:
                reason_code = "MISSING_FINAL_ACK"
            elif (v6_res and v6_res["reset"]) and (v4_res and v4_res["reset"]):
                reason_code = "BOTH_FAMILIES_RESET"
            elif (v6_res and v6_res["outcome"] == ConnectionOutcome.TIMEOUT.value) and (v4_res and v4_res["outcome"] == ConnectionOutcome.TIMEOUT.value):
                reason_code = "BOTH_FAMILIES_TIMEOUT"
            else:
                reason_code = "HANDSHAKE_INCOMPLETE"

        metrics = TrialMetrics(
            winning_family=winning_family,
            t_connect_ms=t_connect_ms,
            t_setup_total_ms=t_setup_total_ms,
            syn_to_synack_ms=syn_to_synack_ms,
            dns_query_to_first_payload_ms=dns_query_to_first_payload_ms,
            dns_last_positive_response_to_first_payload_ms=dns_last_positive_response_to_first_payload_ms,
            dns_transactions=dns_transactions,
            https_svcb_queries=https_svcb_queries,
            reason_code=reason_code,
        )

        return metrics, packets, timeline, conn_attempts


# ==============================================================================
# Pure-Python DNS Wire Codec (RFC 1035 / RFC 9460)
# ==============================================================================

class DNSWireCodec:
    """
    Encoder and decoder for RFC 1035 DNS wire messages.
    Supports A (1), AAAA (28), and HTTPS (65).
    """

    TYPE_A = 1
    TYPE_AAAA = 28
    TYPE_HTTPS = 65

    @classmethod
    def encode_query(cls, qid: int, qname: str, qtype: int) -> bytes:
        # Header: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
        # Flags = 0x0100 (Standard query, RD=1)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qname_bytes = bytearray()
        for label in qname.strip(".").split("."):
            encoded = label.encode("ascii")
            if len(encoded) > 63:
                raise ValueError(f"Label exceeds 63 octets: {label}")
            qname_bytes.append(len(encoded))
            qname_bytes.extend(encoded)
        qname_bytes.append(0)  # Root null byte
        question = bytes(qname_bytes) + struct.pack(">HH", qtype, 1)  # QCLASS IN = 1
        return header + question

    @classmethod
    def decode_message(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 12:
            raise ValueError(f"Truncated DNS packet: length {len(data)} < 12")
        qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        rcode = flags & 0x000F
        qr = (flags >> 15) & 1

        offset = 12
        questions = []
        for _ in range(qdcount):
            labels = []
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                if (length & 0xC0) == 0xC0:
                    # Compression pointer
                    offset += 1
                    labels.append("<ptr>")
                    break
                if offset + length > len(data):
                    raise ValueError("Label length exceeds packet bounds")
                labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
                offset += length
            if offset + 4 > len(data):
                raise ValueError("Truncated question section")
            qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
            offset += 4
            questions.append({"qname": ".".join(labels), "qtype": qtype, "qclass": qclass})

        return {
            "qid": qid,
            "qr": qr,
            "rcode": rcode,
            "qdcount": qdcount,
            "ancount": ancount,
            "questions": questions,
        }


# ==============================================================================
# Schema Validator (Schema 1.0.0 & 1.1.0)
# ==============================================================================

class SchemaValidator:
    """
    Opaque-box validator for result JSON records under Schema 1.1.0 and 1.0.0.
    """

    SUPPORTED_VERSIONS: Set[str] = {"1.0.0", "1.1.0"}

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(data, dict):
            return False, "Record is not a dictionary"

        version = data.get("schema_version")
        if version not in cls.SUPPORTED_VERSIONS:
            return False, f"Unsupported schema version: {version}. Expected one of {cls.SUPPORTED_VERSIONS}"

        # Top-level required keys for both versions
        required_keys = {"schema_version", "trial_id", "scenario_id", "browser_name", "execution_mode"}
        missing = required_keys - set(data.keys())
        if missing:
            return False, f"Missing required top-level keys: {missing}"

        # Schema 1.1.0 structure validation
        if version == "1.1.0":
            if "primary_flow" not in data or not isinstance(data["primary_flow"], dict):
                return False, "Schema 1.1.0 requires 'primary_flow' object"
            pf = data["primary_flow"]
            for field in ["t_connect_ms", "t_setup_total_ms", "syn_to_synack_ms"]:
                val = pf.get(field)
                if val is not None and not isinstance(val, (int, float)):
                    return False, f"Field primary_flow.{field} must be numeric or null, got {type(val)}"

            if "dns_metrics" not in data or not isinstance(data["dns_metrics"], dict):
                return False, "Schema 1.1.0 requires 'dns_metrics' object"

        # Schema 1.0.0 structure validation
        elif version == "1.0.0":
            if "metrics" in data:
                metrics = data["metrics"]
                for field in ["connection_setup_time_ms", "handshake_time_ms"]:
                    val = metrics.get(field)
                    if val is not None and not isinstance(val, (int, float)):
                        return False, f"Legacy metric {field} must be numeric or null, got {type(val)}"

        return True, None


# ==============================================================================
# Export Reconciler
# ==============================================================================

class ExportReconciler:
    """
    Reconciles and verifies deterministic evidence exports:
    - attempts.csv
    - connection_attempts.csv
    - trial_timeline.csv
    """

    VALID_EVENT_SOURCES: Set[str] = {
        EventSource.HARNESS.value,
        EventSource.PCAP.value,
        EventSource.BROWSER_TELEMETRY.value,
    }

    VALID_CLASSIFICATIONS: Set[str] = {
        AttemptValidity.VALID_LIVE.value,
        AttemptValidity.SIMULATION.value,
        AttemptValidity.EXCLUDED_CLEANUP_FAILURE.value,
        AttemptValidity.EXCLUDED_INCOMPLETE.value,
        AttemptValidity.EXCLUDED_ZERO_PACKETS.value,
        AttemptValidity.EXCLUDED_CORRUPTED.value,
    }

    @classmethod
    def verify_attempts_rows(cls, rows: List[Dict[str, Any]], expected_count: int = 282) -> Tuple[bool, Optional[str]]:
        if len(rows) != expected_count:
            return False, f"Row count mismatch: expected {expected_count}, got {len(rows)}"

        seen_trials: Set[str] = set()
        for idx, row in enumerate(rows):
            tid = row.get("trial_id")
            if not tid:
                return False, f"Row {idx}: missing trial_id"
            if tid in seen_trials:
                return False, f"Row {idx}: duplicate trial_id {tid}"
            seen_trials.add(tid)

            status = row.get("validity_status")
            if status not in cls.VALID_CLASSIFICATIONS:
                return False, f"Row {idx}: invalid classification status {status}"

        return True, None

    @classmethod
    def verify_timeline_provenance(cls, rows: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
        for idx, row in enumerate(rows):
            src = row.get("event_source")
            if src not in cls.VALID_EVENT_SOURCES:
                return False, f"Row {idx}: invalid event_source '{src}'. Must be one of {cls.VALID_EVENT_SOURCES}"
        return True, None
