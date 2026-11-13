"""
engine/classifier.py
Maps continuous 0-100 risk scores into qualitative risk classification bands
with plain-English remediation SLAs for SMEs.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any

from config import RISK_TIER_COLORS, RiskTier, classify_risk_score


@dataclass(slots=True, frozen=True)
class RiskBandMetadata:
    """Detailed qualitative classification for a numerical 0-100 risk score."""

    score: float
    tier: RiskTier
    color_hex: str
    sla_window: str
    sme_guidance: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["tier"] = self.tier.value
        return data


def classify_score_with_guidance(score: float) -> RiskBandMetadata:
    """
    Validate and classify a numerical risk score in [0, 100] into Low, Moderate,
    High, or Critical risk with actionable guidance for SME operators.
    """
    if math.isnan(score) or math.isinf(score):
        raise ValueError(f"Risk score must be a finite number, got {score}.")

    clamped = max(0.0, min(100.0, float(score)))
    tier = classify_risk_score(clamped)
    color = RISK_TIER_COLORS[tier]

    if tier == RiskTier.LOW:
        return RiskBandMetadata(
            score=round(clamped, 4),
            tier=tier,
            color_hex=color,
            sla_window="Routine Maintenance (30–90 Days)",
            sme_guidance="Baseline posture is acceptable. Continue passive indicator collection and scheduled patching.",
        )
    if tier == RiskTier.MODERATE:
        return RiskBandMetadata(
            score=round(clamped, 4),
            tier=tier,
            color_hex=color,
            sla_window="Scheduled Remediation (14–30 Days)",
            sme_guidance="Moderate exposure detected. Prioritise top RPI findings during the next standard maintenance window.",
        )
    if tier == RiskTier.HIGH:
        return RiskBandMetadata(
            score=round(clamped, 4),
            tier=tier,
            color_hex=color,
            sla_window="Urgent Action Required (3–7 Days)",
            sme_guidance="Significant vulnerability or identity hygiene gap present. Apply patches or compensating controls promptly.",
        )
    return RiskBandMetadata(
        score=round(clamped, 4),
        tier=tier,
        color_hex=color,
        sla_window="Immediate Emergency Remediation (< 24–48 Hours)",
        sme_guidance="Critical risk of imminent compromise on business-vital SME infrastructure. Execute #1 RPI action immediately.",
    )
