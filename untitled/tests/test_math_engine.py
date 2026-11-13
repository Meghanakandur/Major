"""
tests/test_math_engine.py
Automated unit test suite verifying all 10 mathematical components, boundary conditions,
division-by-zero protection, missing timestamp safety, and worked numerical examples.
Run with: `python3 -m unittest discover -s tests`
Compatible with Python 3.11+.
"""

from __future__ import annotations

import math
import unittest

from config import IndicatorCategory, RiskTier
from engine.classifier import classify_score_with_guidance
from engine.prioritiser import calculate_rpi
from engine.risk_calculator import (
    calculate_asset_criticality_weights,
    calculate_compensating_control_factor,
    calculate_context_multiplier_phi,
    calculate_effective_severity,
    calculate_exploitability_omega,
    calculate_individual_asset_risk,
    calculate_internet_exposure_psi,
    calculate_overall_system_risk,
    calculate_temporal_decay,
)
from engine.worked_examples import run_all_worked_examples


class TestDynamicRiskScoringEngine(unittest.TestCase):
    """Unit tests for the Dynamic Cybersecurity Risk Scoring Engine."""

    def test_asset_criticality_weights(self) -> None:
        weights = calculate_asset_criticality_weights({"A1": 5, "A2": 3, "A3": 2})
        self.assertAlmostEqual(weights["A1"], 0.50)
        self.assertAlmostEqual(weights["A2"], 0.30)
        self.assertAlmostEqual(weights["A3"], 0.20)
        self.assertAlmostEqual(sum(weights.values()), 1.0)

        # Empty input safe handling
        self.assertEqual(calculate_asset_criticality_weights({}), {})

        # Invalid criticality out of [1, 5]
        with self.assertRaises(ValueError):
            calculate_asset_criticality_weights({"A1": 0})
        with self.assertRaises(ValueError):
            calculate_asset_criticality_weights({"A1": 6})

    def test_temporal_decay_and_missing_timestamps(self) -> None:
        # 1. Category 1 CTI decays at lambda = 0.05/day
        d_cti, lam_cti, _ = calculate_temporal_decay(
            IndicatorCategory.EXTERNAL_CTI, elapsed_days_override=10.0
        )
        self.assertAlmostEqual(lam_cti, 0.05)
        self.assertAlmostEqual(d_cti, math.exp(-0.5))

        # 2. Unresolved vulnerabilities and missing MFA MUST NOT decay (lambda = 0.0)
        for persistent_cat in (
            IndicatorCategory.PERIMETER_EXPOSURE,
            IndicatorCategory.ENDPOINT_PATCH,
            IndicatorCategory.IDENTITY_AUTH,
        ):
            d_pers, lam_pers, _ = calculate_temporal_decay(
                persistent_cat, elapsed_days_override=90.0, explicit_lambda=0.05
            )
            self.assertEqual(lam_pers, 0.0)
            self.assertEqual(d_pers, 1.0)

        # 3. Missing or malformed timestamps safely default to elapsed = 0.0 -> D = 1.0
        d_missing, _, elapsed_missing = calculate_temporal_decay(
            IndicatorCategory.EXTERNAL_CTI,
            observed_at_t0=None,
            evaluation_time_t=None,
        )
        self.assertEqual(elapsed_missing, 0.0)
        self.assertEqual(d_missing, 1.0)

        d_malformed, _, elapsed_malformed = calculate_temporal_decay(
            IndicatorCategory.EXTERNAL_CTI,
            observed_at_t0="not-a-timestamp",
            evaluation_time_t="also-invalid",
        )
        self.assertEqual(elapsed_malformed, 0.0)
        self.assertEqual(d_malformed, 1.0)

    def test_context_multipliers_and_bounds(self) -> None:
        # CISA KEV = 1.8 precedence
        self.assertEqual(calculate_exploitability_omega(True, 0.05), 1.8)
        self.assertEqual(calculate_exploitability_omega(True, 0.95), 1.8)
        # EPSS >= 0.20 = 1.5
        self.assertEqual(calculate_exploitability_omega(False, 0.20), 1.5)
        self.assertEqual(calculate_exploitability_omega(False, 0.85), 1.5)
        # Otherwise EPSS = 1.0
        self.assertEqual(calculate_exploitability_omega(False, 0.199), 1.0)

        # Exposure factor Psi_exp
        self.assertEqual(calculate_internet_exposure_psi(True), 1.4)
        self.assertEqual(calculate_internet_exposure_psi(False), 1.0)

        # Compensating control factor [0.3, 1.0]
        self.assertEqual(calculate_compensating_control_factor(0.3), 0.3)
        self.assertEqual(calculate_compensating_control_factor(1.0), 1.0)
        with self.assertRaises(ValueError):
            calculate_compensating_control_factor(0.25)
        with self.assertRaises(ValueError):
            calculate_compensating_control_factor(1.05)

    def test_effective_severity_cap(self) -> None:
        phi, _, _, _ = calculate_context_multiplier_phi(True, 0.9, True, 1.0)
        self.assertAlmostEqual(phi, 1.8 * 1.4 * 1.0)
        s_capped = calculate_effective_severity(0.95, 1.0, phi)
        self.assertEqual(s_capped, 1.0)

    def test_asset_and_system_risk_bounds(self) -> None:
        # Asset with 0 indicators -> R_i = 0.0
        r_zero, surv_zero, _, _ = calculate_individual_asset_risk(5, [])
        self.assertEqual(r_zero, 0.0)
        self.assertEqual(surv_zero, 1.0)

        # Asset with maximum possible indicator -> R_i = 100.0
        r_max, _, _, _ = calculate_individual_asset_risk(5, [(1.0, 1.0)])
        self.assertEqual(r_max, 100.0)

        # System risk on empty list -> 0.0
        r_sys_empty, _, _ = calculate_overall_system_risk([])
        self.assertEqual(r_sys_empty, 0.0)

    def test_rpi_and_zero_division_protection(self) -> None:
        rpi, delta = calculate_rpi(80.0, 50.0, 2.0, 1.8)
        self.assertAlmostEqual(delta, 30.0)
        self.assertAlmostEqual(rpi, (30.0 / 2.0) * 1.8)

        # Division-by-zero protection when E_k <= 0
        with self.assertRaises(ValueError):
            calculate_rpi(80.0, 50.0, 0.0, 1.8)
        with self.assertRaises(ValueError):
            calculate_rpi(80.0, 50.0, -1.5, 1.8)

    def test_all_five_worked_examples(self) -> None:
        examples = run_all_worked_examples()
        self.assertEqual(len(examples), 5)
        for ex in examples:
            self.assertTrue(
                ex.verified_exact_match,
                f"Worked Example #{ex.example_number} ({ex.title}) failed verification!",
            )

    def test_risk_classifier(self) -> None:
        self.assertEqual(classify_score_with_guidance(10.0).tier, RiskTier.LOW)
        self.assertEqual(classify_score_with_guidance(35.0).tier, RiskTier.MODERATE)
        self.assertEqual(classify_score_with_guidance(60.0).tier, RiskTier.HIGH)
        self.assertEqual(classify_score_with_guidance(85.0).tier, RiskTier.CRITICAL)


if __name__ == "__main__":
    unittest.main()
