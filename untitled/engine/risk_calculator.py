"""
engine/risk_calculator.py
Core Dynamic Cybersecurity Risk Scoring Engine.
Implements the exact mathematical equations and parameter values:
1. Asset criticality weighting:
   w_i = A_i / sum(A_j)
2. Temporal decay:
   D(t, t0) = exp(-lambda_k * (t - t0))
   - lambda = 0.05 per day for temporary threat intelligence indicators (Category 1).
   - lambda = 0.00 for unresolved vulnerabilities, exposure, and missing MFA until remediation.
3. Context multiplier:
   Phi_ik = Omega_KEV(k) * Psi_exp(i) * Gamma_ctrl(i,k)
   - CISA KEV factor = 1.8
   - EPSS >= 0.20 factor = 1.5
   - Otherwise EPSS factor = 1.0
   - Internet-facing asset factor = 1.4
   - Non-internet-facing asset factor = 1.0
   - Compensating control factor between 0.3 and 1.0
4. Effective severity:
   S(I_ik, t) = min(1.0, S0(k) * D(t, t0) * Phi_ik)
5. Individual asset risk:
   R_i(t) = 100 * [1 - product(1 - C_ik * S(I_ik, t))] * (A_i / 5)^beta, where beta = 0.5
6. Overall system risk:
   R_sys = alpha * max(R_i) + (1 - alpha) * sum(w_i * R_i), where alpha = 0.65

All functions validate inputs, prevent division-by-zero, handle missing timestamps safely,
and bound risk scores strictly within [0.0, 100.0].
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Sequence

from config import (
    ALPHA_SYSTEM_RISK,
    BETA_CRITICALITY_EXPONENT,
    CRITICALITY_MAX,
    CRITICALITY_MIN,
    EFFECTIVE_SEVERITY_MAX,
    EPSS_THRESHOLD,
    GAMMA_CTRL_MAX,
    GAMMA_CTRL_MIN,
    IndicatorCategory,
    LAMBDA_PERSISTENT,
    LAMBDA_TEMPORARY_CTI,
    OMEGA_CISA_KEV,
    OMEGA_EPSS_DEFAULT,
    OMEGA_EPSS_HIGH,
    PSI_INTERNAL_ONLY,
    PSI_INTERNET_FACING,
    classify_risk_score,
)
from models import (
    Asset,
    AssetRiskResult,
    EvaluatedIndicatorDetail,
    ThreatIndicator,
    parse_iso_timestamp,
)


def _ensure_finite_float(value: float | int, name: str) -> float:
    """Validate that a numeric parameter is a finite float (not NaN, Inf, or bool)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"Parameter '{name}' must be a number, got {type(value).__name__}.")
    f_val = float(value)
    if math.isnan(f_val) or math.isinf(f_val):
        raise ValueError(f"Parameter '{name}' must be finite, got {value}.")
    return f_val


# ==============================================================================
# 1. ASSET CRITICALITY WEIGHTING: w_i = A_i / sum(A_j)
# ==============================================================================
def calculate_asset_criticality_weights(
    criticalities: dict[str, int | float],
) -> dict[str, float]:
    """
    Compute normalised asset criticality weights:
        w_i = A_i / sum_{j=1}^N A_j
    Validates that every A_i is in [1, 5] and avoids division-by-zero on empty input.
    """
    if not criticalities:
        return {}

    validated: dict[str, float] = {}
    for asset_id, raw_a in criticalities.items():
        a_val = _ensure_finite_float(raw_a, f"criticality A_i for {asset_id}")
        if not (CRITICALITY_MIN <= a_val <= CRITICALITY_MAX):
            raise ValueError(
                f"Asset '{asset_id}' criticality A_i must be in "
                f"[{CRITICALITY_MIN}, {CRITICALITY_MAX}], got {a_val}."
            )
        validated[asset_id] = a_val

    total_sum = sum(validated.values())
    if total_sum <= 0.0:
        raise ValueError("Sum of asset criticalities sum(A_j) must be strictly positive.")

    return {asset_id: a_val / total_sum for asset_id, a_val in validated.items()}


# ==============================================================================
# 2. TEMPORAL DECAY: D(t, t0) = exp(-lambda_k * (t - t0))
# ==============================================================================
def resolve_category_decay_lambda(
    category: str | IndicatorCategory,
    explicit_lambda: float | None = None,
) -> float:
    """
    Enforce the mathematical rule:
    - Unresolved vulnerabilities, perimeter exposures, and missing MFA must NOT
      decay automatically (lambda_k = 0.00).
    - Temporary threat intelligence indicators (Category 1) use lambda_k = 0.05 per day.
    """
    cat_str = str(category).strip()
    if cat_str != IndicatorCategory.EXTERNAL_CTI.value:
        # Mandatory rule: unresolved vulnerabilities and missing MFA must not decay
        return LAMBDA_PERSISTENT

    if explicit_lambda is not None:
        lam = _ensure_finite_float(explicit_lambda, "decay_lambda")
        if lam < 0.0:
            raise ValueError(f"decay_lambda cannot be negative, got {lam}.")
        return lam

    return LAMBDA_TEMPORARY_CTI


def safe_elapsed_days(
    observed_at_t0: str | datetime | None,
    evaluation_time_t: str | datetime | None = None,
) -> float:
    """
    Safely compute elapsed days (t - t0) >= 0.0.
    - If `observed_at_t0` or `evaluation_time_t` is None, empty, or malformed,
      safely defaults to 0.0 elapsed days (meaning D(t, t0) = 1.0, i.e., no artificial
      decay reduction of severity).
    - If t0 is slightly in the future due to clock skew, clamps (t - t0) to 0.0.
    """
    if observed_at_t0 is None or (isinstance(observed_at_t0, str) and not observed_at_t0.strip()):
        return 0.0

    try:
        t0_dt = (
            observed_at_t0
            if isinstance(observed_at_t0, datetime)
            else parse_iso_timestamp(str(observed_at_t0))
        )
        if t0_dt.tzinfo is None:
            t0_dt = t0_dt.replace(tzinfo=timezone.utc)
        else:
            t0_dt = t0_dt.astimezone(timezone.utc)
    except Exception:
        return 0.0

    if evaluation_time_t is None or (
        isinstance(evaluation_time_t, str) and not evaluation_time_t.strip()
    ):
        t_dt = datetime.now(timezone.utc)
    else:
        try:
            t_dt = (
                evaluation_time_t
                if isinstance(evaluation_time_t, datetime)
                else parse_iso_timestamp(str(evaluation_time_t))
            )
            if t_dt.tzinfo is None:
                t_dt = t_dt.replace(tzinfo=timezone.utc)
            else:
                t_dt = t_dt.astimezone(timezone.utc)
        except Exception:
            return 0.0

    delta_days = (t_dt - t0_dt).total_seconds() / 86400.0
    return max(0.0, delta_days)


def calculate_temporal_decay(
    category: str | IndicatorCategory,
    observed_at_t0: str | datetime | None = None,
    evaluation_time_t: str | datetime | None = None,
    elapsed_days_override: float | None = None,
    explicit_lambda: float | None = None,
) -> tuple[float, float, float]:
    """
    Compute temporal decay factor:
        D(t, t0) = exp(-lambda_k * (t - t0))
    Returns a tuple of (D_value, lambda_k, elapsed_days).
    """
    lambda_k = resolve_category_decay_lambda(category, explicit_lambda=explicit_lambda)

    if elapsed_days_override is not None:
        elapsed = _ensure_finite_float(elapsed_days_override, "elapsed_days_override")
        if elapsed < 0.0:
            elapsed = 0.0
    else:
        elapsed = safe_elapsed_days(observed_at_t0, evaluation_time_t)

    if lambda_k == 0.0 or elapsed == 0.0:
        return 1.0, lambda_k, elapsed

    d_val = math.exp(-lambda_k * elapsed)
    return d_val, lambda_k, elapsed


# ==============================================================================
# 3 & 4. CISA KEV & EPSS MULTIPLIER: Omega_KEV(k)
# ==============================================================================
def calculate_exploitability_omega(
    is_cisa_kev: bool,
    epss_score: float = 0.0,
) -> float:
    """
    Compute exploitability multiplier Omega_KEV(k):
    - CISA KEV factor = 1.8
    - EPSS >= 0.20 factor = 1.5
    - Otherwise EPSS factor = 1.0
    """
    epss = _ensure_finite_float(epss_score, "epss_score")
    if not (0.0 <= epss <= 1.0):
        raise ValueError(f"epss_score must be in [0.0, 1.0], got {epss}.")

    if bool(is_cisa_kev):
        return OMEGA_CISA_KEV
    if epss >= EPSS_THRESHOLD:
        return OMEGA_EPSS_HIGH
    return OMEGA_EPSS_DEFAULT


# ==============================================================================
# 5. INTERNET EXPOSURE MULTIPLIER: Psi_exp(i)
# ==============================================================================
def calculate_internet_exposure_psi(is_internet_facing: bool) -> float:
    """
    Compute asset exposure factor Psi_exp(i):
    - Internet-facing asset factor = 1.4
    - Non-internet-facing asset factor = 1.0
    """
    return PSI_INTERNET_FACING if bool(is_internet_facing) else PSI_INTERNAL_ONLY


# ==============================================================================
# 6. COMPENSATING CONTROL MULTIPLIER: Gamma_ctrl(i, k)
# ==============================================================================
def calculate_compensating_control_factor(gamma_ctrl: float) -> float:
    """
    Validate and return compensating control factor Gamma_ctrl(i, k) in [0.3, 1.0].
    """
    g_val = _ensure_finite_float(gamma_ctrl, "gamma_ctrl")
    if not (GAMMA_CTRL_MIN <= g_val <= GAMMA_CTRL_MAX):
        raise ValueError(
            f"Compensating control factor Gamma_ctrl(i,k) must be between "
            f"{GAMMA_CTRL_MIN} and {GAMMA_CTRL_MAX}, got {g_val}."
        )
    return g_val


# ==============================================================================
# CONTEXT MULTIPLIER: Phi_ik = Omega_KEV(k) * Psi_exp(i) * Gamma_ctrl(i, k)
# ==============================================================================
def calculate_context_multiplier_phi(
    is_cisa_kev: bool,
    epss_score: float,
    is_internet_facing: bool,
    gamma_ctrl: float,
) -> tuple[float, float, float, float]:
    """
    Compute context multiplier:
        Phi_ik = Omega_KEV(k) * Psi_exp(i) * Gamma_ctrl(i,k)
    Returns (Phi_ik, Omega_KEV, Psi_exp, Gamma_ctrl).
    """
    omega = calculate_exploitability_omega(is_cisa_kev=is_cisa_kev, epss_score=epss_score)
    psi = calculate_internet_exposure_psi(is_internet_facing=is_internet_facing)
    gamma = calculate_compensating_control_factor(gamma_ctrl=gamma_ctrl)
    phi = omega * psi * gamma
    return phi, omega, psi, gamma


# ==============================================================================
# 7. EFFECTIVE SEVERITY: S(I_ik, t) = min(1.0, S0(k) * D(t, t0) * Phi_ik)
# ==============================================================================
def calculate_effective_severity(
    base_severity_s0: float,
    temporal_decay_d: float,
    context_multiplier_phi: float,
) -> float:
    """
    Compute effective indicator severity:
        S(I_ik, t) = min(1.0, S0(k) * D(t, t0) * Phi_ik)
    """
    s0 = _ensure_finite_float(base_severity_s0, "base_severity_s0")
    if not (0.0 < s0 <= 1.0):
        raise ValueError(f"Base severity S0(k) must be in (0.0, 1.0], got {s0}.")

    d_val = _ensure_finite_float(temporal_decay_d, "temporal_decay_d")
    if not (0.0 <= d_val <= 1.0):
        raise ValueError(f"Temporal decay D(t,t0) must be in [0.0, 1.0], got {d_val}.")

    phi_val = _ensure_finite_float(context_multiplier_phi, "context_multiplier_phi")
    if phi_val < 0.0:
        raise ValueError(f"Context multiplier Phi_ik cannot be negative, got {phi_val}.")

    raw_s = s0 * d_val * phi_val
    return max(0.0, min(EFFECTIVE_SEVERITY_MAX, raw_s))


# ==============================================================================
# 8. INDIVIDUAL ASSET RISK:
#    R_i(t) = 100 * [1 - product(1 - C_ik * S(I_ik, t))] * (A_i / 5)^beta
# ==============================================================================
def calculate_individual_asset_risk(
    criticality_a_i: int | float,
    indicator_pairs: Sequence[tuple[float, float]],
    beta: float = BETA_CRITICALITY_EXPONENT,
) -> tuple[float, float, float, float]:
    """
    Compute individual asset risk score R_i(t):
        R_i(t) = 100 * [1 - product_{k}(1 - C_ik * S(I_ik, t))] * (A_i / 5)^beta
    where `indicator_pairs` is a sequence of (C_ik, S(I_ik, t)) tuples.
    Returns (R_i(t), survival_product, combined_threat_prob, criticality_modifier).
    """
    a_val = _ensure_finite_float(criticality_a_i, "criticality_a_i")
    if not (CRITICALITY_MIN <= a_val <= CRITICALITY_MAX):
        raise ValueError(
            f"Asset criticality A_i must be in [{CRITICALITY_MIN}, {CRITICALITY_MAX}], got {a_val}."
        )

    beta_val = _ensure_finite_float(beta, "beta")
    if beta_val <= 0.0:
        raise ValueError(f"Exponent beta must be positive, got {beta_val}.")

    criticality_modifier = (a_val / float(CRITICALITY_MAX)) ** beta_val

    survival_product = 1.0
    for idx, (c_ik, s_eff) in enumerate(indicator_pairs):
        c_val = _ensure_finite_float(c_ik, f"C_ik[{idx}]")
        s_val = _ensure_finite_float(s_eff, f"S(I_ik,t)[{idx}]")
        if not (0.0 < c_val <= 1.0):
            raise ValueError(f"Confidence C_ik[{idx}] must be in (0.0, 1.0], got {c_val}.")
        if not (0.0 <= s_val <= 1.0):
            raise ValueError(
                f"Effective severity S(I_ik,t)[{idx}] must be in [0.0, 1.0], got {s_val}."
            )
        term = max(0.0, min(1.0, 1.0 - (c_val * s_val)))
        survival_product *= term

    combined_threat_prob = 1.0 - survival_product
    raw_r_i = 100.0 * combined_threat_prob * criticality_modifier
    bounded_r_i = max(0.0, min(100.0, raw_r_i))
    return bounded_r_i, survival_product, combined_threat_prob, criticality_modifier


# ==============================================================================
# 9. OVERALL SYSTEM RISK:
#    R_sys = alpha * max(R_i) + (1 - alpha) * sum(w_i * R_i)
# ==============================================================================
def calculate_overall_system_risk(
    asset_risks_and_weights: Sequence[tuple[float, float]],
    alpha: float = ALPHA_SYSTEM_RISK,
) -> tuple[float, float, float]:
    """
    Compute overall system risk score:
        R_sys = alpha * max(R_i) + (1 - alpha) * sum(w_i * R_i)
    where `asset_risks_and_weights` is a sequence of (R_i, w_i) tuples.
    Returns (R_sys, max_R_i, weighted_mean_R_i).
    """
    if not asset_risks_and_weights:
        return 0.0, 0.0, 0.0

    alpha_val = _ensure_finite_float(alpha, "alpha")
    if not (0.0 <= alpha_val <= 1.0):
        raise ValueError(f"System risk alpha must be in [0.0, 1.0], got {alpha_val}.")

    r_list: list[float] = []
    w_list: list[float] = []

    for idx, (r_i, w_i) in enumerate(asset_risks_and_weights):
        r_val = _ensure_finite_float(r_i, f"R_i[{idx}]")
        w_val = _ensure_finite_float(w_i, f"w_i[{idx}]")
        if not (0.0 <= r_val <= 100.0):
            raise ValueError(f"Asset risk R_i[{idx}] must be in [0, 100], got {r_val}.")
        if not (0.0 <= w_val <= 1.0):
            raise ValueError(f"Asset weight w_i[{idx}] must be in [0, 1], got {w_val}.")
        r_list.append(r_val)
        w_list.append(w_val)

    weight_sum = sum(w_list)
    if weight_sum <= 0.0:
        raise ValueError("Sum of asset weights w_i must be strictly positive.")

    # Normalise weights if caller passed slightly unrounded weights
    norm_weights = [w / weight_sum for w in w_list]

    max_r_i = max(r_list)
    weighted_mean_r_i = sum(w * r for w, r in zip(norm_weights, r_list))
    raw_r_sys = alpha_val * max_r_i + (1.0 - alpha_val) * weighted_mean_r_i
    bounded_r_sys = max(0.0, min(100.0, raw_r_sys))
    return bounded_r_sys, max_r_i, weighted_mean_r_i


# ==============================================================================
# COMPOSITE ASSET & PORTFOLIO EVALUATORS
# ==============================================================================
def evaluate_single_asset(
    asset: Asset,
    weight_w_i: float,
    indicators: Sequence[ThreatIndicator],
    evaluation_time_t: datetime | str | None = None,
) -> AssetRiskResult:
    """
    Evaluate all open indicators on a single Asset and return a full AssetRiskResult.
    """
    evaluated_details: list[EvaluatedIndicatorDetail] = []
    cs_pairs: list[tuple[float, float]] = []

    for ind in indicators:
        d_val, lam_k, elapsed = calculate_temporal_decay(
            category=ind.category,
            observed_at_t0=ind.observed_at_t0,
            evaluation_time_t=evaluation_time_t,
            explicit_lambda=ind.decay_lambda,
        )
        phi_val, omega_val, psi_val, gamma_val = calculate_context_multiplier_phi(
            is_cisa_kev=ind.is_cisa_kev,
            epss_score=ind.epss_score,
            is_internet_facing=asset.is_internet_facing,
            gamma_ctrl=ind.control_factor_gamma,
        )
        s_eff = calculate_effective_severity(
            base_severity_s0=ind.base_severity_s0,
            temporal_decay_d=d_val,
            context_multiplier_phi=phi_val,
        )
        cs_product = ind.confidence_c * s_eff
        survival = max(0.0, 1.0 - cs_product)
        cs_pairs.append((ind.confidence_c, s_eff))

        evaluated_details.append(
            EvaluatedIndicatorDetail(
                indicator_id=ind.indicator_id,
                sha256_hash=ind.sha256_hash,
                asset_id=ind.asset_id,
                category=ind.category,
                indicator_type=ind.indicator_type,
                identifier_key=ind.identifier_key,
                title=ind.title,
                s0=ind.base_severity_s0,
                confidence_c=ind.confidence_c,
                decay_lambda=lam_k,
                elapsed_days=elapsed,
                temporal_decay_d=d_val,
                omega_kev=omega_val,
                psi_exp=psi_val,
                gamma_ctrl=gamma_val,
                context_phi=phi_val,
                effective_severity_s=s_eff,
                weighted_impact_cs=cs_product,
                survival_term=survival,
                remediation_effort_e=ind.remediation_effort_e,
            )
        )

    r_i, survival_prod, combined_prob, crit_mod = calculate_individual_asset_risk(
        criticality_a_i=asset.criticality_score,
        indicator_pairs=cs_pairs,
        beta=BETA_CRITICALITY_EXPONENT,
    )

    return AssetRiskResult(
        asset=asset,
        weight_w_i=weight_w_i,
        criticality_modifier=crit_mod,
        open_indicator_count=len(indicators),
        survival_product=survival_prod,
        combined_threat_prob=combined_prob,
        risk_score_r_i=r_i,
        risk_tier=classify_risk_score(r_i),
        evaluated_indicators=evaluated_details,
    )


def evaluate_system_portfolio(
    assets: Sequence[Asset],
    open_indicators: Sequence[ThreatIndicator],
    evaluation_time_t: datetime | str | None = None,
) -> tuple[list[AssetRiskResult], float, float, float]:
    """
    Evaluate an entire portfolio of SME assets and open indicators.
    Returns (sorted_asset_results, R_sys, max_R_i, weighted_mean_R_i).
    """
    if not assets:
        return [], 0.0, 0.0, 0.0

    weights_map = calculate_asset_criticality_weights(
        {a.asset_id: a.criticality_score for a in assets}
    )

    inds_by_asset: dict[str, list[ThreatIndicator]] = {a.asset_id: [] for a in assets}
    for ind in open_indicators:
        if ind.asset_id in inds_by_asset:
            inds_by_asset[ind.asset_id].append(ind)

    asset_results: list[AssetRiskResult] = []
    for asset in assets:
        w_i = weights_map[asset.asset_id]
        res_i = evaluate_single_asset(
            asset=asset,
            weight_w_i=w_i,
            indicators=inds_by_asset[asset.asset_id],
            evaluation_time_t=evaluation_time_t,
        )
        asset_results.append(res_i)

    asset_results.sort(key=lambda r: r.risk_score_r_i, reverse=True)

    r_sys, max_r_i, weighted_mean_r_i = calculate_overall_system_risk(
        [(r.risk_score_r_i, r.weight_w_i) for r in asset_results],
        alpha=ALPHA_SYSTEM_RISK,
    )
    return asset_results, r_sys, max_r_i, weighted_mean_r_i
