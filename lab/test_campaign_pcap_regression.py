#!/usr/bin/env python3
"""Authentic October 29 S0-S5 PCAP regressions and evidence-path portability tests.

These tests deliberately use committed live campaign captures and a real TShark
binary. Synthetic captures and mocked TShark output are not substitutes here.
"""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import lab.run_trial as run_trial

REPO_ROOT = run_trial.REPO_ROOT
CAMPAIGN_ROOT = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
CHECKSUM_SIDECAR = REPO_ROOT / "lab" / "recovery" / "pcap_sha256_checksums.relative.txt"

# One authentic Chrome capture per scenario. Expected digests and packet counts
# are pinned to the campaign result records and portable checksum sidecar.
RECORDED_CASES = {
    "S0": {
        "trial_id": "trial-20261029215755-6c37ab97",
        "sha256": "6c45166582b1fd90b9520948f11422dcd0574516856fa9d5a946b1899d2bfaef",
        "packet_count": 148,
        "family": "IPv6",
        "classification": "DIRECT_IPV6",
    },
    "S1": {
        "trial_id": "trial-20261029221926-0051c888",
        "sha256": "2c09bafe8152dad51e0531bd5830cd164f6bd6fe496cf647b6d2d1c34340eb41",
        "packet_count": 171,
        "family": "IPv4",
        "classification": "IPV6_TO_IPV4_FALLBACK",
    },
    "S2": {
        "trial_id": "trial-20261029215159-1536b235",
        "sha256": "44edb561f42ab37020f2f05333404e7ddded350baed6dbe20443e93165784029",
        "packet_count": 172,
        "family": "IPv4",
        "classification": "IPV6_TO_IPV4_FALLBACK",
    },
    "S3": {
        "trial_id": "trial-20261029221332-b0040d40",
        "sha256": "9d71bc8324548f97c5febf5aac6e5ae735c15eeca181b4dad6457b2c2b3a1912",
        "packet_count": 171,
        "family": "IPv6",
        "classification": "DIRECT_IPV6",
    },
    "S4": {
        "trial_id": "trial-20261029223826-f2df1200",
        "sha256": "2532a20d47624d156a7bc8ec8d7fd75c77144c04d381178c31d9e47c03d8af8d",
        "packet_count": 181,
        "family": "IPv4",
        "classification": "IPV6_TO_IPV4_FALLBACK",
    },
    "S5": {
        "trial_id": "trial-20261029221757-d19c9af6",
        "sha256": "60b3f2cef7adc5fea6a2d0381d16312fb10692dcecdbdb2a6e62e504f5c56b3f",
        "packet_count": 171,
        "family": "IPv4",
        "classification": "IPV6_TO_IPV4_FALLBACK",
    },
}


class TestPortableEvidencePathSerialization(unittest.TestCase):
    """Project-owned path metadata must not retain one developer's home directory."""

    def test_repository_path_serializes_relative_to_checkout(self):
        source = REPO_ROOT / "lab" / "scenarios.yaml"
        self.assertEqual(run_trial._serialize_evidence_path(source), "lab/scenarios.yaml")

    def test_external_path_remains_absolute_and_explicit(self):
        external = Path(tempfile.gettempdir()) / "ps028-external" / "capture.pcap"
        self.assertEqual(run_trial._serialize_evidence_path(external), str(external.resolve()))

    def test_none_path_remains_none(self):
        self.assertIsNone(run_trial._serialize_evidence_path(None))


class TestOctober29CampaignPcapRegression(unittest.TestCase):
    """Re-dissect one unmodified live capture for each S0-S5 scenario."""

    def test_authentic_recorded_pcaps_cover_s0_through_s5(self):
        tshark = shutil.which("tshark")
        self.assertIsNotNone(
            tshark,
            "A real TShark installation is required; mocked dissection is not accepted for this regression.",
        )

        self.assertTrue(
            CHECKSUM_SIDECAR.is_file(),
            f"Portable PCAP checksum sidecar missing: {CHECKSUM_SIDECAR}",
        )
        sidecar_entries = {}
        for line_number, line in enumerate(
            CHECKSUM_SIDECAR.read_text(encoding="utf-8").splitlines(), 1
        ):
            fields = line.split(maxsplit=1)
            self.assertEqual(
                len(fields), 2,
                f"Malformed checksum sidecar line {line_number}: {line!r}",
            )
            digest, relative_path = fields
            self.assertTrue(
                len(digest) == 64 and all(char in "0123456789abcdef" for char in digest),
                f"Invalid SHA-256 on sidecar line {line_number}: {digest!r}",
            )
            self.assertNotIn(
                relative_path, sidecar_entries,
                f"Duplicate path in checksum sidecar: {relative_path}",
            )
            sidecar_entries[relative_path] = digest

        self.assertEqual(
            len(sidecar_entries), 280,
            "Portable sidecar should enumerate all 280 campaign PCAPs",
        )

        for scenario_id, expected in RECORDED_CASES.items():
            with self.subTest(scenario=scenario_id, trial=expected["trial_id"]):
                trial_id = expected["trial_id"]
                trial_dir = CAMPAIGN_ROOT / "trials" / trial_id
                pcap_path = trial_dir / "capture.pcap"
                result_path = trial_dir / "result.json"
                relative_pcap_path = (
                    Path("lab") / "campaigns" / CAMPAIGN_ROOT.name
                    / "trials" / trial_id / "capture.pcap"
                ).as_posix()
                self.assertEqual(
                    sidecar_entries.get(relative_pcap_path),
                    expected["sha256"],
                    f"{scenario_id} digest does not match the portable checksum sidecar",
                )
                self.assertTrue(result_path.is_file(), f"Recorded result JSON missing: {result_path}")
                self.assertTrue(pcap_path.is_file(), f"Authentic {scenario_id} PCAP missing: {pcap_path}")

                recorded = json.loads(result_path.read_text(encoding="utf-8"))
                hostname = f"{trial_id}.he.test"
                self.assertEqual(recorded.get("trial_id"), trial_id)
                self.assertEqual(recorded.get("scenario_id"), scenario_id)
                self.assertEqual(recorded.get("hostname"), hostname)
                self.assertEqual(recorded.get("execution_mode"), "LIVE")
                self.assertFalse(recorded.get("is_simulation", True))

                metadata = recorded.get("capture_metadata", {})
                self.assertTrue(metadata.get("pcap_valid"))
                self.assertFalse(metadata.get("capture_loss"), "Campaign capture reports packet loss")
                self.assertEqual(metadata.get("pcap_sha256"), expected["sha256"])
                self.assertEqual(metadata.get("packet_count"), expected["packet_count"])

                actual_sha256 = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
                self.assertEqual(actual_sha256, expected["sha256"])

                valid, digest, size, packet_count, message = run_trial.validate_pcap_file(
                    pcap_path, min_packets=1
                )
                self.assertTrue(valid, message)
                self.assertEqual(digest, expected["sha256"])
                self.assertEqual(size, metadata.get("pcap_size_bytes"))
                self.assertEqual(packet_count, expected["packet_count"])

                # Independently ensure TShark can read every frame before invoking
                # the production dissection path (which intentionally fails closed
                # only through its returned evidence structure on parser errors).
                tshark_probe = subprocess.run(
                    [tshark, "-n", "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )
                self.assertEqual(tshark_probe.returncode, 0, tshark_probe.stderr.strip())
                frame_rows = [line for line in tshark_probe.stdout.splitlines() if line.strip()]
                self.assertEqual(len(frame_rows), expected["packet_count"])

                dissection = run_trial.dissect_pcap(pcap_path, target_hostname=hostname)
                dns = dissection.get("dns", {})
                queries = dns.get("queries", [])
                responses = dns.get("responses", [])
                self.assertTrue(queries, "No target DNS queries were dissected")
                self.assertTrue(responses, "No target DNS responses were dissected")
                self.assertTrue(all(item.get("qname") == hostname for item in queries))
                self.assertTrue(all(item.get("qname") == hostname for item in responses))
                query_types = {item.get("qtype") for item in queries}
                response_by_type = {item.get("qtype"): item for item in responses}
                self.assertIn("A", query_types)
                self.assertIn("AAAA", query_types)
                self.assertEqual(response_by_type.get("A", {}).get("address"), "10.0.2.10")
                self.assertEqual(response_by_type.get("AAAA", {}).get("address"), "2001:db8:2::10")

                main_flow = dissection.get("main_http_flow") or {}
                self.assertTrue(main_flow.get("correlated"), "Primary GET / was not correlated to a TCP stream")
                self.assertEqual(main_flow.get("request"), ("GET", "/"))
                self.assertEqual(main_flow.get("status_code"), 200)
                self.assertEqual(main_flow.get("family"), expected["family"])
                self.assertTrue(main_flow.get("tcp_handshake_completed"))
                self.assertEqual(dissection.get("http_status_code"), 200)
                self.assertEqual(dissection.get("http_response_family"), expected["family"])
                winning_family_key = "ipv6" if expected["family"] == "IPv6" else "ipv4"
                self.assertTrue(dissection[winning_family_key]["tcp_handshake_completed"])

                classification = run_trial.classify_fallback(
                    dissection,
                    recorded.get("http_outcome", {}),
                    pcap_valid=True,
                    capture_loss=bool(metadata.get("capture_loss")),
                    capture_loss_message=metadata.get("capture_loss_message"),
                )
                self.assertEqual(classification.get("classification"), expected["classification"])
                self.assertEqual(
                    classification.get("classification"),
                    recorded.get("network_observations", {}).get("classification"),
                )
                self.assertEqual(
                    classification.get("fallback_occurred"),
                    recorded.get("network_observations", {}).get("fallback_occurred"),
                )
                for observation_key in ("ipv6_attempt", "ipv4_attempt", "ipv6_success", "ipv4_success"):
                    self.assertEqual(
                        classification.get(observation_key),
                        recorded.get("network_observations", {}).get(observation_key),
                        f"Re-dissected {observation_key} differs from the recorded trial result",
                    )


if __name__ == "__main__":
    unittest.main()
