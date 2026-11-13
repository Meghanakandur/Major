"""
engine/__init__.py
Modular Dynamic Cybersecurity Risk Scoring & Remediation Prioritisation Engine.
Implements the exact mathematical specifications:
1. Asset criticality weighting: w_i = A_i / sum(A_j)
2. Temporal decay: D(t, t0) = exp(-lambda_k * (t - t0))
3. Exploitability multiplier Omega_KEV(k): CISA KEV (1.8), EPSS >= 0.20 (1.5), else (1.0)
4. Internet exposure multiplier Psi_exp(i): Internet-facing (1.4), Internal (1.0)
5. Compensating control multiplier Gamma_ctrl(i,k) in [0.3, 1.0]
6. Context multiplier: Phi_ik = Omega_KEV(k) * Psi_exp(i) * Gamma_ctrl(i,k)
7. Effective severity: S(I_ik, t) = min(1.0, S0(k) * D(t, t0) * Phi_ik)
8. Asset risk: R_i(t) = 100 * [1 - product(1 - C_ik * S(I_ik, t))] * (A_i / 5)^0.5
9. System risk: R_sys = 0.65 * max(R_i) + 0.35 * sum(w_i * R_i)
10. Remediation Priority Index: RPI = [(R_i - R_i(-k)) / E_k] * Omega_KEV(k)
"""

from engine.classifier import RiskBandMetadata, classify_score_with_guidance
from engine.prioritiser import (
    calculate_rpi,
    compute_asset_remediation_priorities,
    rank_system_remediation_plan,
)
from engine.remediation_advisor import (
    DEFAULT_EFFORT_HOURS_BY_TYPE,
    AutomatedRemediationRecommendation,
    generate_automated_remediation_recommendations,
)
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
    evaluate_single_asset,
    evaluate_system_portfolio,
)
from engine.worked_examples import run_all_worked_examples

__all__ = [
    "calculate_asset_criticality_weights",
    "calculate_temporal_decay",
    "calculate_exploitability_omega",
    "calculate_internet_exposure_psi",
    "calculate_compensating_control_factor",
    "calculate_context_multiplier_phi",
    "calculate_effective_severity",
    "calculate_individual_asset_risk",
    "calculate_overall_system_risk",
    "evaluate_single_asset",
    "evaluate_system_portfolio",
    "calculate_rpi",
    "compute_asset_remediation_priorities",
    "rank_system_remediation_plan",
    "RiskBandMetadata",
    "classify_score_with_guidance",
    "run_all_worked_examples",
]
