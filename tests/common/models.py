"""
PS-028 Common Domain Models
Data structures representing packets, DNS records, trial metrics, and exports
for the Happy Eyeballs Measurement Lab opaque-box test track.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AddressFamily(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DUAL = "dual"


class EventSource(str, Enum):
    HARNESS = "HARNESS"
    PCAP = "PCAP"
    BROWSER_TELEMETRY = "BROWSER_TELEMETRY"


class AttemptValidity(str, Enum):
    VALID_LIVE = "VALID_LIVE"
    SIMULATION = "SIMULATION"
    EXCLUDED_CLEANUP_FAILURE = "EXCLUDED_CLEANUP_FAILURE"
    EXCLUDED_INCOMPLETE = "EXCLUDED_INCOMPLETE"
    EXCLUDED_ZERO_PACKETS = "EXCLUDED_ZERO_PACKETS"
    EXCLUDED_CORRUPTED = "EXCLUDED_CORRUPTED"


class ConnectionOutcome(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    RESET = "RESET"
    TIMEOUT = "TIMEOUT"
    ABORTED = "ABORTED"
    INCOMPLETE = "INCOMPLETE"


@dataclass
class TCPPacket:
    timestamp_ms: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    family: str
    stream_id: int
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False
    seq: int = 0
    ack_seq: int = 0
    payload_len: int = 0

    @property
    def is_syn(self) -> bool:
        return self.syn and not self.ack

    @property
    def is_syn_ack(self) -> bool:
        return self.syn and self.ack

    @property
    def is_final_ack(self) -> bool:
        return self.ack and not self.syn and not self.fin and not self.rst and self.payload_len == 0

    @property
    def is_rst(self) -> bool:
        return self.rst

    @property
    def is_data(self) -> bool:
        return self.payload_len > 0


@dataclass
class DNSTransaction:
    dns_id: int
    qname: str
    qtype: int
    qtype_name: str
    rcode: int
    transport: str  # "UDP" or "TCP"
    answers: List[str] = field(default_factory=list)
    query_time_ms: float = 0.0
    response_time_ms: float = 0.0
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dns_id": self.dns_id,
            "qname": self.qname,
            "qtype": self.qtype,
            "qtype_name": self.qtype_name,
            "rcode": self.rcode,
            "transport": self.transport,
            "answers": list(self.answers),
            "query_time_ms": round(self.query_time_ms, 3),
            "response_time_ms": round(self.response_time_ms, 3),
            "duration_ms": round(self.duration_ms, 3),
        }


@dataclass
class TrialMetrics:
    winning_family: Optional[str]
    t_connect_ms: Optional[float]
    t_setup_total_ms: Optional[float]
    syn_to_synack_ms: Optional[float]
    dns_query_to_first_payload_ms: Optional[float] = None
    dns_last_positive_response_to_first_payload_ms: Optional[float] = None
    dns_transactions: List[DNSTransaction] = field(default_factory=list)
    https_svcb_queries: List[DNSTransaction] = field(default_factory=list)
    reason_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "winning_family": self.winning_family,
            "t_connect_ms": self.t_connect_ms,
            "t_setup_total_ms": self.t_setup_total_ms,
            "syn_to_synack_ms": self.syn_to_synack_ms,
            "dns_query_to_first_payload_ms": self.dns_query_to_first_payload_ms,
            "dns_last_positive_response_to_first_payload_ms": self.dns_last_positive_response_to_first_payload_ms,
            "dns_transactions": [tx.to_dict() for tx in self.dns_transactions],
            "https_svcb_queries": [tx.to_dict() for tx in self.https_svcb_queries],
            "reason_code": self.reason_code,
        }


@dataclass
class AttemptRecord:
    trial_id: str
    slot_id: str
    scenario_id: str
    browser: str
    execution_mode: str
    validity_status: str
    primary_family: Optional[str]
    t_connect_ms: Optional[float]
    t_setup_total_ms: Optional[float]
    http_status_code: Optional[int]
    reason: Optional[str] = None


@dataclass
class ConnectionAttemptRecord:
    trial_id: str
    stream_id: int
    family: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    syn_start_ms: float
    ack_end_ms: Optional[float]
    duration_ms: Optional[float]
    outcome: str


@dataclass
class TimelineRecord:
    trial_id: str
    timestamp_ms: float
    event_source: str  # Must match EventSource enum
    event_name: str
    event_details: str


@dataclass
class ScenarioSpec:
    id: str
    name: str
    description: str
    type: str  # "baseline", "nftables", "netem", "dns"
    target_family: str
    ipv4_rtt_ms: Optional[int]
    ipv6_rtt_ms: Optional[int]
    A_delay_ms: int
    AAAA_delay_ms: int
    nftables: List[str] = field(default_factory=list)
