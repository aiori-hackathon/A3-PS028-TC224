#!/usr/bin/env python3
"""
Unit and Regression Test Suite for Phase D Empirical Research Sweeps
Tests:
- lab/run_research_sweep.py: Link delay calculations, tolerances, simulation determinism, CSV exports, Amendment A13 sidecars
- lab/plot_research_sweeps.py: Crossover transition interval estimation, logistic regression fitting, Wilson CIs, SVG rendering
"""

import csv
import json
from pathlib import Path
import random
import tempfile
import unittest

from lab.run_research_sweep import (
    calculate_symmetric_link_delay,
    calculate_rtt_tolerance,
    simulate_trial_rtt_outcome,
    simulate_trial_dns_outcome,
    execute_d1_rtt_sweep,
    execute_d2_dns_sweep,
    D1_CSV_HEADER,
    D2_CSV_HEADER,
)
from lab.plot_research_sweeps import (
    fit_logistic_crossover,
    generate_d1_summary,
    generate_d2_summary,
    render_svg_rtt_crossover,
)


class TestResearchSweeps(unittest.TestCase):

    def test_symmetric_link_delay_calculation(self):
        # 0ms target RTT -> 0ms link delay (applied via delay 0ms 0ms for qdisc uniformity)
        self.assertEqual(calculate_symmetric_link_delay(0.0), 0.0)
        self.assertEqual(calculate_symmetric_link_delay(-10.0), 0.0)

        # 100ms target RTT -> (100 - 0.2) / 2 = 49.9ms
        self.assertAlmostEqual(calculate_symmetric_link_delay(100.0, baseline_floor_ms=0.2), 49.9, places=2)

        # 200ms target RTT -> (200 - 0.2) / 2 = 99.9ms
        self.assertAlmostEqual(calculate_symmetric_link_delay(200.0, baseline_floor_ms=0.2), 99.9, places=2)

    def test_rtt_tolerance_bounds(self):
        # Pre-declared tolerance: max(5.0 ms, 5% of target RTT)
        self.assertEqual(calculate_rtt_tolerance(0.0), 5.0)
        self.assertEqual(calculate_rtt_tolerance(50.0), 5.0)
        self.assertEqual(calculate_rtt_tolerance(100.0), 5.0)
        # At 200ms: 5% is 10.0ms > 5.0ms
        self.assertEqual(calculate_rtt_tolerance(200.0), 10.0)
        # At 800ms: 5% is 40.0ms
        self.assertEqual(calculate_rtt_tolerance(800.0), 40.0)

    def test_simulate_rtt_outcome_determinism(self):
        rng1 = random.Random(42)
        res1 = simulate_trial_rtt_outcome(250.0, "google-chrome", 1, rng1)

        rng2 = random.Random(42)
        res2 = simulate_trial_rtt_outcome(250.0, "google-chrome", 1, rng2)

        self.assertEqual(res1, res2)
        self.assertIn(res1["winning_family"], ["IPv6", "IPv4"])
        self.assertGreater(res1["t_connect_ms"], 0.0)
        self.assertTrue(res1["within_tolerance"])

    def test_simulate_dns_outcome_determinism(self):
        rng1 = random.Random(42)
        res1 = simulate_trial_dns_outcome(0.0, 500.0, "google-chrome", 1, rng1)

        rng2 = random.Random(42)
        res2 = simulate_trial_dns_outcome(0.0, 500.0, "google-chrome", 1, rng2)

        self.assertEqual(res1, res2)
        self.assertIn(res1["winning_family"], ["IPv6", "IPv4"])
        self.assertGreater(res1["t_connect_ms"], 0.0)

    def test_logistic_crossover_fit(self):
        # Construct synthetic transition: IPv6 wins up to 300ms, IPv4 wins above 300ms
        rtts = [100.0, 200.0, 250.0, 300.0, 350.0, 400.0, 500.0] * 5
        y = [0 if r < 300.0 else 1 for r in rtts]

        crossover, ci_l, ci_h = fit_logistic_crossover(rtts, y, seed=42)
        # Fitted crossover should be in the neighborhood of 250-350ms
        self.assertTrue(200.0 <= crossover <= 400.0)
        self.assertTrue(ci_l <= crossover <= ci_h)

    def test_full_d1_and_d2_sweep_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)

            # Run small sample D1 sweep (n=2 per condition for fast test)
            c1_path, p1_path = execute_d1_rtt_sweep(
                output_dir=out_dir,
                sample_size=2,
                is_simulation=True,
                seed=42,
            )
            self.assertTrue(c1_path.is_file())
            self.assertTrue(p1_path.is_file())

            # Verify D1 CSV headers and contents
            with open(c1_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, D1_CSV_HEADER)
                # 9 screening + 7 refinement = 16 conditions * 2 browsers * 2 reps = 64 rows
                self.assertEqual(len(rows), 64)
                for r in rows:
                    self.assertEqual(r["is_simulation"], "True")
                    self.assertIn(r["winning_family"], ["IPv6", "IPv4"])

            # Verify D1 Provenance
            with open(p1_path, "r", encoding="utf-8") as f:
                prov = json.load(f)
                self.assertEqual(prov["target_file"], "d1_rtt_sweep.csv")
                self.assertEqual(prov["row_count"], 64)
                self.assertTrue(prov["amendment_a13_compliant"])

            # Test D1 summary and SVG generation
            d1_sum = generate_d1_summary(c1_path, out_dir)
            self.assertTrue(d1_sum.is_file())

            svg_out = out_dir / "d1_test_plot.svg"
            render_svg_rtt_crossover(d1_sum, svg_out)
            self.assertTrue(svg_out.is_file())
            self.assertGreater(svg_out.stat().st_size, 500)

            # Run small sample D2 sweep
            c2_path, p2_path = execute_d2_dns_sweep(
                output_dir=out_dir,
                sample_size=2,
                is_simulation=True,
                seed=42,
            )
            self.assertTrue(c2_path.is_file())
            self.assertTrue(p2_path.is_file())

            # Verify D2 summary
            d2_sum = generate_d2_summary(c2_path, out_dir)
            self.assertTrue(d2_sum.is_file())


if __name__ == "__main__":
    unittest.main()
