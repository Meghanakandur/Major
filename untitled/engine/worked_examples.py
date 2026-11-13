"""
engine/worked_examples.py
Five deterministic, self-verifying worked numerical examples proving the exact
mathematical precision of the Dynamic Cybersecurity Risk Scoring Engine.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any

from config import IndicatorCategory
from engine.prioritiser import calculate_rpi
from engine.risk_calculator import (
    calculate_asset_criticality_weights,
    calculate_context_multiplier_phi,
    calculate_effective_severity,
    calculate_individual_asset_risk,
    calculate_overall_system_risk,
    calculate_temporal_decay,
)


@dataclass(slots=True)
class WorkedExampleResult:
    """Structured representation of a worked numerical example and its verification."""

    example_number: int
    title: str
    scenario_description: str
    formulas_tested: list[str]
    inputs: dict[str, Any]
    step_by_step_derivation: list[str]
    expected_outputs: dict[str, float]
    engine_outputs: dict[str, float]
    verified_exact_match: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_example_1_cti_temporal_decay() -> WorkedExampleResult:
    """
    Worked Example 1: External Cyber Threat Intelligence (Category 1) with Temporal Decay
    on an Internet-Facing Asset.
    - Tests: D(t, t0) = exp(-0.05 * (t - t0)), Omega_KEV (EPSS >= 0.20 -> 1.5),
      Psi_exp (Internet-facing -> 1.4), Gamma_ctrl (0.80), Phi_ik, and S(I_ik, t).
    """
    s0 = 0.80
    elapsed_days = 10.0
    is_cisa_kev = False
    epss = 0.25          # >= 0.20 -> Omega_KEV = 1.5
    is_internet = True   # -> Psi_exp = 1.4
    gamma_ctrl = 0.80

    # Hand-calculated exact values:
    # 1. D(t, t0) = exp(-0.05 * 10) = exp(-0.5) = 0.6065306597
    # 2. Phi_ik = 1.5 * 1.4 * 0.80 = 1.6800
    # 3. Raw S = 0.80 * 0.6065306597 * 1.68 = 0.8151772066 -> min(1.0, 0.8151772066) = 0.8151772066
    expected_d = math.exp(-0.05 * 10.0)
    expected_phi = 1.5 * 1.4 * 0.80
    expected_s = min(1.0, s0 * expected_d * expected_phi)

    d_val, lam_k, _ = calculate_temporal_decay(
        category=IndicatorCategory.EXTERNAL_CTI,
        elapsed_days_override=elapsed_days,
    )
    phi_val, omega_val, psi_val, gamma_val = calculate_context_multiplier_phi(
        is_cisa_kev=is_cisa_kev,
        epss_score=epss,
        is_internet_facing=is_internet,
        gamma_ctrl=gamma_ctrl,
    )
    s_eff = calculate_effective_severity(
        base_severity_s0=s0,
        temporal_decay_d=d_val,
        context_multiplier_phi=phi_val,
    )

    verified = (
        math.isclose(d_val, expected_d, rel_tol=1e-9)
        and math.isclose(phi_val, expected_phi, rel_tol=1e-9)
        and math.isclose(s_eff, expected_s, rel_tol=1e-9)
    )

    return WorkedExampleResult(
        example_number=1,
        title="Category 1 External CTI Indicator with 10-Day Temporal Decay",
        scenario_description=(
            "A malicious IP brute-force alert (S0 = 0.80) observed 10 days ago on an "
            "internet-facing gateway (Psi_exp = 1.4) with EPSS = 0.25 (Omega_KEV = 1.5) "
            "and rate-limiting control Gamma_ctrl = 0.80."
        ),
        formulas_tested=[
            "D(t,t0) = exp(-0.05 * (t - t0))",
            "Phi_ik = Omega_KEV(k) * Psi_exp(i) * Gamma_ctrl(i,k)",
            "S(I_ik,t) = min(1.0, S0(k) * D(t,t0) * Phi_ik)",
        ],
        inputs={
            "category": IndicatorCategory.EXTERNAL_CTI.value,
            "S0(k)": s0,
            "lambda_k": lam_k,
            "elapsed_days (t - t0)": elapsed_days,
            "is_cisa_kev": is_cisa_kev,
            "epss_score": epss,
            "is_internet_facing": is_internet,
            "Gamma_ctrl": gamma_ctrl,
        },
        step_by_step_derivation=[
            "1. Temporal Decay: D(10, 0) = exp(-0.05 * 10) = exp(-0.5) = 0.606531",
            "2. Exploitability Factor: is_cisa_kev=False, EPSS=0.25 >= 0.20 => Omega_KEV = 1.50",
            "3. Exposure Factor: is_internet_facing=True => Psi_exp = 1.40",
            "4. Context Multiplier: Phi_ik = 1.50 * 1.40 * 0.80 = 1.6800",
            "5. Effective Severity: S(I_ik, t) = min(1.0, 0.80 * 0.606531 * 1.6800) = 0.815177",
        ],
        expected_outputs={
            "D(t,t0)": round(expected_d, 6),
            "Omega_KEV": 1.5,
            "Psi_exp": 1.4,
            "Phi_ik": round(expected_phi, 6),
            "S(I_ik,t)": round(expected_s, 6),
        },
        engine_outputs={
            "D(t,t0)": round(d_val, 6),
            "Omega_KEV": omega_val,
            "Psi_exp": psi_val,
            "Phi_ik": round(phi_val, 6),
            "S(I_ik,t)": round(s_eff, 6),
        },
        verified_exact_match=verified,
    )


def run_example_2_cisa_kev_persistent_cap() -> WorkedExampleResult:
    """
    Worked Example 2: Unresolved CISA KEV Vulnerability with Zero Decay (lambda = 0)
    and Upper-Bound Severity Capping at 1.0.
    """
    s0 = 0.90
    elapsed_days = 45.0  # 45 days old, but unresolved vulnerability must NOT decay!
    is_cisa_kev = True   # -> Omega_KEV = 1.8
    epss = 0.92
    is_internet = True   # -> Psi_exp = 1.4
    gamma_ctrl = 0.85

    # Hand-calculated exact values:
    # 1. Unresolved Endpoint Patch vulnerability -> lambda_k = 0.0 -> D(t, t0) = exp(0) = 1.0
    # 2. Phi_ik = 1.8 * 1.4 * 0.85 = 2.1420
    # 3. Uncapped product = 0.90 * 1.0 * 2.1420 = 1.9278 -> capped by min(1.0, 1.9278) = 1.0000
    expected_d = 1.0
    expected_phi = 1.8 * 1.4 * 0.85
    expected_s = 1.0

    d_val, lam_k, _ = calculate_temporal_decay(
        category=IndicatorCategory.ENDPOINT_PATCH,
        elapsed_days_override=elapsed_days,
    )
    phi_val, omega_val, psi_val, _ = calculate_context_multiplier_phi(
        is_cisa_kev=is_cisa_kev,
        epss_score=epss,
        is_internet_facing=is_internet,
        gamma_ctrl=gamma_ctrl,
    )
    s_eff = calculate_effective_severity(
        base_severity_s0=s0,
        temporal_decay_d=d_val,
        context_multiplier_phi=phi_val,
    )

    verified = (
        math.isclose(d_val, expected_d, rel_tol=1e-9)
        and math.isclose(phi_val, expected_phi, rel_tol=1e-9)
        and math.isclose(s_eff, expected_s, rel_tol=1e-9)
    )

    return WorkedExampleResult(
        example_number=2,
        title="Unresolved CISA KEV Vulnerability (Zero Decay & Severity Cap at 1.0)",
        scenario_description=(
            "A 45-day-old unpatched CISA KEV vulnerability (S0 = 0.90, Omega_KEV = 1.8) "
            "on an internet-facing server (Psi_exp = 1.4) with Gamma_ctrl = 0.85. "
            "Verifies that lambda = 0 prevents automatic decay and min(1.0, ...) caps S(I_ik,t)."
        ),
        formulas_tested=[
            "lambda_k = 0.0 for unresolved vulnerabilities => D(t,t0) = 1.0",
            "Phi_ik = 1.8 * 1.4 * 0.85 = 2.142",
            "S(I_ik,t) = min(1.0, 0.90 * 1.0 * 2.142) = min(1.0, 1.9278) = 1.0",
        ],
        inputs={
            "category": IndicatorCategory.ENDPOINT_PATCH.value,
            "S0(k)": s0,
            "elapsed_days (t - t0)": elapsed_days,
            "is_cisa_kev": is_cisa_kev,
            "is_internet_facing": is_internet,
            "Gamma_ctrl": gamma_ctrl,
        },
        step_by_step_derivation=[
            "1. Mandatory Rule: Unresolved vulnerability has lambda_k = 0.0 => D(45, 0) = exp(0) = 1.0000",
            "2. Exploitability Factor: CISA KEV = True => Omega_KEV = 1.80",
            "3. Exposure Factor: Internet-facing = True => Psi_exp = 1.40",
            "4. Context Multiplier: Phi_ik = 1.80 * 1.40 * 0.85 = 2.1420",
            "5. Uncapped Severity: 0.90 * 1.0000 * 2.1420 = 1.9278",
            "6. Effective Severity Cap: S(I_ik, t) = min(1.0, 1.9278) = 1.0000",
        ],
        expected_outputs={
            "lambda_k": 0.0,
            "D(t,t0)": 1.0,
            "Phi_ik": round(expected_phi, 6),
            "S(I_ik,t)": 1.0,
        },
        engine_outputs={
            "lambda_k": lam_k,
            "D(t,t0)": d_val,
            "Phi_ik": round(phi_val, 6),
            "S(I_ik,t)": s_eff,
        },
        verified_exact_match=verified,
    )


def run_example_3_individual_asset_risk() -> WorkedExampleResult:
    """
    Worked Example 3: Individual Asset Risk Calculation R_i(t) with Multiple Indicators
    and Asset Criticality Scaling (beta = 0.5).
    """
    a_i = 4
    # Indicator 1: C_i1 = 0.90, S(I_i1, t) = 0.80 -> C*S = 0.72 -> survival_1 = 0.28
    # Indicator 2: C_i2 = 0.80, S(I_i2, t) = 0.50 -> C*S = 0.40 -> survival_2 = 0.60
    # Product of survival terms = 0.28 * 0.60 = 0.1680
    # Combined threat probability = 1 - 0.1680 = 0.8320
    # Criticality modifier = (4 / 5)^0.5 = sqrt(0.8) = 0.8944271910
    # R_i(t) = 100 * 0.8320 * 0.8944271910 = 74.41634229
    pairs = [(0.90, 0.80), (0.80, 0.50)]

    expected_survival = (1.0 - 0.90 * 0.80) * (1.0 - 0.80 * 0.50)
    expected_prob = 1.0 - expected_survival
    expected_crit_mod = math.sqrt(4.0 / 5.0)
    expected_r_i = 100.0 * expected_prob * expected_crit_mod

    r_i, survival_prod, combined_prob, crit_mod = calculate_individual_asset_risk(
        criticality_a_i=a_i,
        indicator_pairs=pairs,
        beta=0.5,
    )

    verified = (
        math.isclose(survival_prod, expected_survival, rel_tol=1e-9)
        and math.isclose(crit_mod, expected_crit_mod, rel_tol=1e-9)
        and math.isclose(r_i, expected_r_i, rel_tol=1e-9)
    )

    return WorkedExampleResult(
        example_number=3,
        title="Individual Asset Risk R_i(t) with Two Active Threat Indicators",
        scenario_description=(
            "An internal database server with criticality A_i = 4 and two active indicators: "
            "Indicator 1 (C_i1 = 0.90, S_1 = 0.80) and Indicator 2 (C_i2 = 0.80, S_2 = 0.50)."
        ),
        formulas_tested=[
            "R_i(t) = 100 * [1 - product(1 - C_ik * S(I_ik, t))] * (A_i / 5)^beta, beta = 0.5"
        ],
        inputs={
            "criticality_A_i": a_i,
            "beta": 0.5,
            "Indicator_1 (C_i1, S_1)": [0.90, 0.80],
            "Indicator_2 (C_i2, S_2)": [0.80, 0.50],
        },
        step_by_step_derivation=[
            "1. Indicator 1 Survival Term: 1 - (0.90 * 0.80) = 1 - 0.72 = 0.2800",
            "2. Indicator 2 Survival Term: 1 - (0.80 * 0.50) = 1 - 0.40 = 0.6000",
            "3. Survival Product: 0.2800 * 0.6000 = 0.1680",
            "4. Combined Threat Probability: 1 - 0.1680 = 0.8320",
            "5. Criticality Scaling: (4 / 5)^0.5 = sqrt(0.80) = 0.894427",
            "6. Final Asset Risk Score: R_i(t) = 100 * 0.8320 * 0.894427 = 74.4163 (High Risk)",
        ],
        expected_outputs={
            "survival_product": round(expected_survival, 6),
            "combined_threat_prob": round(expected_prob, 6),
            "criticality_modifier": round(expected_crit_mod, 6),
            "R_i(t)": round(expected_r_i, 4),
        },
        engine_outputs={
            "survival_product": round(survival_prod, 6),
            "combined_threat_prob": round(combined_prob, 6),
            "criticality_modifier": round(crit_mod, 6),
            "R_i(t)": round(r_i, 4),
        },
        verified_exact_match=verified,
    )


def run_example_4_system_risk_aggregation() -> WorkedExampleResult:
    """
    Worked Example 4: Asset Criticality Weighting w_i and Overall System Risk R_sys
    across a 3-Asset SME Portfolio (alpha = 0.65).
    """
    # 3 SME Assets:
    # Asset 1: A_1 = 5, R_1 = 88.0
    # Asset 2: A_2 = 3, R_2 = 50.0
    # Asset 3: A_3 = 2, R_3 = 20.0
    # Sum(A_j) = 5 + 3 + 2 = 10
    # Weights: w_1 = 0.50, w_2 = 0.30, w_3 = 0.20
    # Weighted Mean = (0.50 * 88.0) + (0.30 * 50.0) + (0.20 * 20.0) = 44.0 + 15.0 + 4.0 = 63.0
    # Max(R_i) = 88.0
    # R_sys = 0.65 * 88.0 + 0.35 * 63.0 = 57.20 + 22.05 = 79.25 (Critical Risk)
    crit_map = {"AST-1": 5, "AST-2": 3, "AST-3": 2}
    weights = calculate_asset_criticality_weights(crit_map)

    r_sys, max_r, weighted_mean = calculate_overall_system_risk(
        [
            (88.0, weights["AST-1"]),
            (50.0, weights["AST-2"]),
            (20.0, weights["AST-3"]),
        ],
        alpha=0.65,
    )

    expected_w1, expected_w2, expected_w3 = 0.50, 0.30, 0.20
    expected_mean = 63.0
    expected_max = 88.0
    expected_r_sys = 79.25

    verified = (
        math.isclose(weights["AST-1"], expected_w1, rel_tol=1e-9)
        and math.isclose(weighted_mean, expected_mean, rel_tol=1e-9)
        and math.isclose(r_sys, expected_r_sys, rel_tol=1e-9)
    )

    return WorkedExampleResult(
        example_number=4,
        title="Asset Criticality Weights w_i & Overall System Risk R_sys (alpha = 0.65)",
        scenario_description=(
            "A 3-asset SME environment with criticalities A = [5, 3, 2] and individual "
            "asset risk scores R = [88.0, 50.0, 20.0]."
        ),
        formulas_tested=[
            "w_i = A_i / sum(A_j)",
            "R_sys = alpha * max(R_i) + (1 - alpha) * sum(w_i * R_i), alpha = 0.65",
        ],
        inputs={
            "Assets (A_i, R_i)": {"AST-1": [5, 88.0], "AST-2": [3, 50.0], "AST-3": [2, 20.0]},
            "alpha": 0.65,
        },
        step_by_step_derivation=[
            "1. Total Criticality Sum: sum(A_j) = 5 + 3 + 2 = 10",
            "2. Normalised Weights: w_1 = 5/10 = 0.50, w_2 = 3/10 = 0.30, w_3 = 2/10 = 0.20",
            "3. Maximum Asset Risk: max(R_i) = max(88.0, 50.0, 20.0) = 88.00",
            "4. Weighted Mean Risk: sum(w_i * R_i) = (0.50*88.0) + (0.30*50.0) + (0.20*20.0) = 44.0 + 15.0 + 4.0 = 63.00",
            "5. System Risk Score: R_sys = (0.65 * 88.00) + (0.35 * 63.00) = 57.20 + 22.05 = 79.25 (Critical Risk)",
        ],
        expected_outputs={
            "w_1": expected_w1,
            "w_2": expected_w2,
            "w_3": expected_w3,
            "max(R_i)": expected_max,
            "sum(w_i * R_i)": expected_mean,
            "R_sys": expected_r_sys,
        },
        engine_outputs={
            "w_1": round(weights["AST-1"], 4),
            "w_2": round(weights["AST-2"], 4),
            "w_3": round(weights["AST-3"], 4),
            "max(R_i)": round(max_r, 4),
            "sum(w_i * R_i)": round(weighted_mean, 4),
            "R_sys": round(r_sys, 4),
        },
        verified_exact_match=verified,
    )


def run_example_5_counterfactual_rpi() -> WorkedExampleResult:
    """
    Worked Example 5: Counterfactual Leave-One-Out Remediation Priority Index (RPI)
    Comparing Two Candidate Remediations on the Same Asset.
    """
    # Using Asset from Example 3 (A_i = 4, Current R_i = 74.416342):
    # Indicator 1 (CISA KEV, Omega_KEV = 1.8, Effort E_1 = 2.0h): C_1 = 0.90, S_1 = 0.80
    # Indicator 2 (Non-KEV, EPSS < 0.20, Omega_KEV = 1.0, Effort E_2 = 1.0h): C_2 = 0.80, S_2 = 0.50
    a_i = 4
    r_curr, _, _, _ = calculate_individual_asset_risk(a_i, [(0.90, 0.80), (0.80, 0.50)])

    # Counterfactual R_i(-1): Remove Indicator 1 -> only Indicator 2 remains:
    # R_i(-1) = 100 * (0.80 * 0.50) * sqrt(4/5) = 40.0 * 0.894427191 = 35.77708764
    r_without_1, _, _, _ = calculate_individual_asset_risk(a_i, [(0.80, 0.50)])
    rpi_1, delta_1 = calculate_rpi(
        current_asset_risk_r_i=r_curr,
        counterfactual_asset_risk_without_k=r_without_1,
        remediation_effort_e_k=2.0,
        omega_kev_k=1.8,
    )

    # Counterfactual R_i(-2): Remove Indicator 2 -> only Indicator 1 remains:
    # R_i(-2) = 100 * (0.90 * 0.80) * sqrt(4/5) = 72.0 * 0.894427191 = 64.39875775
    r_without_2, _, _, _ = calculate_individual_asset_risk(a_i, [(0.90, 0.80)])
    rpi_2, delta_2 = calculate_rpi(
        current_asset_risk_r_i=r_curr,
        counterfactual_asset_risk_without_k=r_without_2,
        remediation_effort_e_k=1.0,
        omega_kev_k=1.0,
    )

    expected_delta_1 = r_curr - r_without_1
    expected_rpi_1 = (expected_delta_1 / 2.0) * 1.8
    expected_delta_2 = r_curr - r_without_2
    expected_rpi_2 = (expected_delta_2 / 1.0) * 1.0

    verified = (
        math.isclose(rpi_1, expected_rpi_1, rel_tol=1e-9)
        and math.isclose(rpi_2, expected_rpi_2, rel_tol=1e-9)
        and rpi_1 > rpi_2
    )

    return WorkedExampleResult(
        example_number=5,
        title="Counterfactual Remediation Priority Index (RPI) Leave-One-Out Ranking",
        scenario_description=(
            "On the asset from Example 3 (R_i = 74.4163), compares remediating "
            "Indicator 1 (CISA KEV: Omega_KEV = 1.8, E_1 = 2.0h) versus "
            "Indicator 2 (Standard config gap: Omega_KEV = 1.0, E_2 = 1.0h)."
        ),
        formulas_tested=[
            "RPI = [(R_i - R_i(-k)) / E_k] * Omega_KEV(k)"
        ],
        inputs={
            "current_R_i": round(r_curr, 4),
            "Indicator_1": {"C": 0.90, "S": 0.80, "E_1": 2.0, "Omega_KEV": 1.8},
            "Indicator_2": {"C": 0.80, "S": 0.50, "E_2": 1.0, "Omega_KEV": 1.0},
        },
        step_by_step_derivation=[
            f"1. Current Asset Risk with both indicators: R_i = {r_curr:.4f}",
            f"2. Counterfactual R_i(-1) (Indicator 1 removed): 100 * (0.80*0.50) * sqrt(0.8) = {r_without_1:.4f}",
            f"3. Risk Reduction Delta_R_1 = {r_curr:.4f} - {r_without_1:.4f} = {delta_1:.4f}",
            f"4. RPI_1 = ({delta_1:.4f} / 2.0) * 1.8 = {rpi_1:.4f} (Rank #1 Priority)",
            f"5. Counterfactual R_i(-2) (Indicator 2 removed): 100 * (0.90*0.80) * sqrt(0.8) = {r_without_2:.4f}",
            f"6. Risk Reduction Delta_R_2 = {r_curr:.4f} - {r_without_2:.4f} = {delta_2:.4f}",
            f"7. RPI_2 = ({delta_2:.4f} / 1.0) * 1.0 = {rpi_2:.4f} (Rank #2 Priority)",
        ],
        expected_outputs={
            "R_i(-1)": round(r_without_1, 4),
            "Delta_R_1": round(expected_delta_1, 4),
            "RPI_1": round(expected_rpi_1, 4),
            "R_i(-2)": round(r_without_2, 4),
            "Delta_R_2": round(expected_delta_2, 4),
            "RPI_2": round(expected_rpi_2, 4),
        },
        engine_outputs={
            "R_i(-1)": round(r_without_1, 4),
            "Delta_R_1": round(delta_1, 4),
            "RPI_1": round(rpi_1, 4),
            "R_i(-2)": round(r_without_2, 4),
            "Delta_R_2": round(delta_2, 4),
            "RPI_2": round(rpi_2, 4),
        },
        verified_exact_match=verified,
    )


def run_all_worked_examples() -> list[WorkedExampleResult]:
    """Execute and verify all 5 worked numerical examples."""
    return [
        run_example_1_cti_temporal_decay(),
        run_example_2_cisa_kev_persistent_cap(),
        run_example_3_individual_asset_risk(),
        run_example_4_system_risk_aggregation(),
        run_example_5_counterfactual_rpi(),
    ]
