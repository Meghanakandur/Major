"""
engine/prioritiser.py
Counterfactual Leave-One-Out Remediation Priority Index (RPI) Engine:
    RPI = [(R_i - R_i(-k)) / E_k] * Omega_KEV(k)
Includes strict validation against division-by-zero when E_k <= 0.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime
import math
from typing import Sequence

from engine.risk_calculator import (
    calculate_exploitability_omega,
    evaluate_single_asset,
)
from models import Asset, RemediationPriorityItem, ThreatIndicator


def calculate_rpi(
    current_asset_risk_r_i: float,
    counterfactual_asset_risk_without_k: float,
    remediation_effort_e_k: float,
    omega_kev_k: float,
) -> tuple[float, float]:
    """
    Compute the Remediation Priority Index (RPI):
        RPI = [(R_i - R_i(-k)) / E_k] * Omega_KEV(k)
    Validates inputs and prevents division-by-zero on E_k <= 0.
    Returns (RPI_score, risk_reduction_delta).
    """
    for name, val in (
        ("current_asset_risk_r_i", current_asset_risk_r_i),
        ("counterfactual_asset_risk_without_k", counterfactual_asset_risk_without_k),
        ("remediation_effort_e_k", remediation_effort_e_k),
        ("omega_kev_k", omega_kev_k),
    ):
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise TypeError(f"{name} must be numeric.")
        if math.isnan(float(val)) or math.isinf(float(val)):
            raise ValueError(f"{name} must be finite.")

    if remediation_effort_e_k <= 0.0:
        raise ValueError(
            f"Remediation effort E_k must be strictly positive (> 0) to prevent division by zero, got {remediation_effort_e_k}."
        )
    if omega_kev_k <= 0.0:
        raise ValueError(f"Omega_KEV(k) must be strictly positive, got {omega_kev_k}.")

    r_curr = max(0.0, min(100.0, float(current_asset_risk_r_i)))
    r_without = max(0.0, min(100.0, float(counterfactual_asset_risk_without_k)))

    delta_r = max(0.0, r_curr - r_without)
    rpi_score = (delta_r / float(remediation_effort_e_k)) * float(omega_kev_k)
    return rpi_score, delta_r


def compute_asset_remediation_priorities(
    asset: Asset,
    weight_w_i: float,
    asset_indicators: Sequence[ThreatIndicator],
    current_asset_risk_r_i: float,
    evaluation_time_t: datetime | str | None = None,
) -> list[RemediationPriorityItem]:
    """
    Perform counterfactual leave-one-out evaluation for each indicator k on `asset`:
    computes R_i(-k) with indicator k removed and calculates RPI.
    """
    items: list[RemediationPriorityItem] = []

    for idx, target_ind in enumerate(asset_indicators):
        remaining_inds = [
            other for j, other in enumerate(asset_indicators) if j != idx
        ]
        counterfactual_res = evaluate_single_asset(
            asset=asset,
            weight_w_i=weight_w_i,
            indicators=remaining_inds,
            evaluation_time_t=evaluation_time_t,
        )
        r_i_without_k = counterfactual_res.risk_score_r_i
        omega_k = calculate_exploitability_omega(
            is_cisa_kev=target_ind.is_cisa_kev,
            epss_score=target_ind.epss_score,
        )
        rpi_val, delta_r = calculate_rpi(
            current_asset_risk_r_i=current_asset_risk_r_i,
            counterfactual_asset_risk_without_k=r_i_without_k,
            remediation_effort_e_k=target_ind.remediation_effort_e,
            omega_kev_k=omega_k,
        )

        items.append(
            RemediationPriorityItem(
                rank=0,
                indicator_id=target_ind.indicator_id,
                sha256_hash=target_ind.sha256_hash,
                asset_id=asset.asset_id,
                asset_name=asset.asset_name,
                category=target_ind.category,
                identifier_key=target_ind.identifier_key,
                title=target_ind.title,
                current_asset_risk_r_i=current_asset_risk_r_i,
                counterfactual_risk_r_i_minus_k=r_i_without_k,
                risk_reduction_delta=delta_r,
                remediation_effort_e=target_ind.remediation_effort_e,
                omega_kev=omega_k,
                rpi_score=rpi_val,
            )
        )

    return items


def rank_system_remediation_plan(
    unranked_items: Sequence[RemediationPriorityItem],
) -> list[RemediationPriorityItem]:
    """
    Sort all remediation items across the SME in descending order of RPI score
    and assign 1-based priority ranks.
    """
    sorted_items = sorted(
        unranked_items,
        key=lambda item: (item.rpi_score, item.risk_reduction_delta),
        reverse=True,
    )
    for rank_idx, item in enumerate(sorted_items, start=1):
        item.rank = rank_idx
    return sorted_items
