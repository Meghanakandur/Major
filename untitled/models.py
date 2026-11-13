"""
models.py
Domain data structures, input sanitisation, mathematical parameter validation,
and deterministic SHA-256 deduplication hashing.
Compatible with Python 3.11+.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from config import (
    AssetType,
    CRITICALITY_MAX,
    CRITICALITY_MIN,
    DataSource,
    EFFECTIVE_SEVERITY_MAX,
    EPSS_THRESHOLD,
    GAMMA_CTRL_MAX,
    GAMMA_CTRL_MIN,
    IndicatorCategory,
    IndicatorStatus,
    OMEGA_CISA_KEV,
    OMEGA_EPSS_DEFAULT,
    OMEGA_EPSS_HIGH,
    PSI_INTERNAL_ONLY,
    PSI_INTERNET_FACING,
    RiskTier,
    get_default_decay_lambda,
)

# ==============================================================================
# 1. SECURITY & INPUT SANITISATION HELPERS
# ==============================================================================
DANGEROUS_CSV_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def sanitise_text(value: str, field_name: str, max_length: int = 255) -> str:
    """
    Sanitise user-provided or uploaded strings against CSV/formula injection
    and enforce non-empty bounded lengths.
    """
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string, got {type(value).__name__}.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty.")
    while cleaned and cleaned[0] in DANGEROUS_CSV_PREFIXES:
        cleaned = cleaned[1:].strip()
    if not cleaned:
        raise ValueError(f"{field_name} contained only unsafe prefix characters.")
    return cleaned[:max_length]


def parse_iso_timestamp(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string into a timezone-aware UTC datetime."""
    cleaned = ts_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def compute_indicator_sha256(
    asset_id: str,
    category: str,
    indicator_type: str,
    identifier_key: str,
    status: str = IndicatorStatus.OPEN.value,
) -> str:
    """
    Generate a deterministic SHA-256 hash for indicator deduplication.
    Identical open indicators on the same asset produce the exact same digest.
    """
    canonical_payload = "|".join(
        [
            asset_id.strip().upper(),
            category.strip().upper(),
            indicator_type.strip().upper(),
            identifier_key.strip().upper(),
            status.strip().upper(),
        ]
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


# ==============================================================================
# 2. CORE ENTITY MODELS
# ==============================================================================
@dataclass(slots=True)
class Asset:
    """Represents an SME asset with criticality A_i and internet exposure."""

    asset_id: str
    asset_name: str
    asset_type: str
    criticality_score: int
    is_internet_facing: bool
    owner_department: str = "IT Operations"
    ip_or_hostname: str = "N/A"
    data_source: str = DataSource.SIMULATED.value
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        self.asset_id = sanitise_text(self.asset_id, "asset_id", max_length=64).upper()
        self.asset_name = sanitise_text(self.asset_name, "asset_name", max_length=128)
        self.owner_department = sanitise_text(
            self.owner_department, "owner_department", max_length=128
        )
        self.ip_or_hostname = sanitise_text(
            self.ip_or_hostname, "ip_or_hostname", max_length=128
        )

        valid_types = {item.value for item in AssetType}
        if self.asset_type not in valid_types:
            raise ValueError(
                f"Invalid asset_type '{self.asset_type}'. Must be one of {sorted(valid_types)}."
            )

        self.criticality_score = int(self.criticality_score)
        if not (CRITICALITY_MIN <= self.criticality_score <= CRITICALITY_MAX):
            raise ValueError(
                f"criticality_score A_i must be between {CRITICALITY_MIN} and {CRITICALITY_MAX}, "
                f"got {self.criticality_score}."
            )

        self.is_internet_facing = bool(self.is_internet_facing)

        valid_sources = {item.value for item in DataSource}
        if self.data_source not in valid_sources:
            raise ValueError(
                f"Invalid data_source '{self.data_source}'. Must be one of {sorted(valid_sources)}."
            )
        _ = parse_iso_timestamp(self.created_at)

    @property
    def exposure_factor_psi(self) -> float:
        """
        Return Psi_exp(i):
        - Internet-facing asset factor = 1.4
        - Non-internet-facing asset factor = 1.0
        """
        return PSI_INTERNET_FACING if self.is_internet_facing else PSI_INTERNAL_ONLY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ThreatIndicator:
    """
    Represents a normalised cybersecurity threat indicator linked to an Asset.
    """

    asset_id: str
    category: str
    indicator_type: str
    identifier_key: str
    title: str
    base_severity_s0: float
    confidence_c: float
    is_cisa_kev: bool
    epss_score: float
    control_factor_gamma: float
    remediation_effort_e: float
    observed_at_t0: str
    decay_lambda: float | None = None
    status: str = IndicatorStatus.OPEN.value
    data_source: str = DataSource.SIMULATED.value
    sha256_hash: str = ""
    indicator_id: int | None = None

    def __post_init__(self) -> None:
        self.asset_id = sanitise_text(self.asset_id, "asset_id", max_length=64).upper()
        self.indicator_type = sanitise_text(
            self.indicator_type, "indicator_type", max_length=64
        ).upper()
        self.identifier_key = sanitise_text(
            self.identifier_key, "identifier_key", max_length=128
        )
        self.title = sanitise_text(self.title, "title", max_length=255)

        valid_categories = {item.value for item in IndicatorCategory}
        if self.category not in valid_categories:
            raise ValueError(
                f"Invalid category '{self.category}'. Must be one of {sorted(valid_categories)}."
            )

        self.base_severity_s0 = float(self.base_severity_s0)
        if not (0.0 < self.base_severity_s0 <= 1.0):
            raise ValueError(
                f"base_severity_s0 S0(k) must be in (0.0, 1.0], got {self.base_severity_s0}."
            )

        self.confidence_c = float(self.confidence_c)
        if not (0.0 < self.confidence_c <= 1.0):
            raise ValueError(
                f"confidence_c C_ik must be in (0.0, 1.0], got {self.confidence_c}."
            )

        self.is_cisa_kev = bool(self.is_cisa_kev)

        self.epss_score = float(self.epss_score)
        if not (0.0 <= self.epss_score <= 1.0):
            raise ValueError(
                f"epss_score must be in [0.0, 1.0], got {self.epss_score}."
            )

        self.control_factor_gamma = float(self.control_factor_gamma)
        if not (GAMMA_CTRL_MIN <= self.control_factor_gamma <= GAMMA_CTRL_MAX):
            raise ValueError(
                f"control_factor_gamma Gamma_ctrl(i,k) must be in "
                f"[{GAMMA_CTRL_MIN}, {GAMMA_CTRL_MAX}], got {self.control_factor_gamma}."
            )

        self.remediation_effort_e = float(self.remediation_effort_e)
        if self.remediation_effort_e <= 0.0:
            raise ValueError(
                f"remediation_effort_e E_k must be > 0, got {self.remediation_effort_e}."
            )

        if self.decay_lambda is None:
            self.decay_lambda = get_default_decay_lambda(self.category)
        else:
            self.decay_lambda = float(self.decay_lambda)
            if self.decay_lambda < 0.0:
                raise ValueError("decay_lambda cannot be negative.")

        valid_statuses = {item.value for item in IndicatorStatus}
        if self.status not in valid_statuses:
            raise ValueError(f"Invalid status '{self.status}'.")

        valid_sources = {item.value for item in DataSource}
        if self.data_source not in valid_sources:
            raise ValueError(f"Invalid data_source '{self.data_source}'.")

        _ = parse_iso_timestamp(self.observed_at_t0)

        self.sha256_hash = compute_indicator_sha256(
            asset_id=self.asset_id,
            category=self.category,
            indicator_type=self.indicator_type,
            identifier_key=self.identifier_key,
            status=self.status,
        )

    @property
    def omega_kev_factor(self) -> float:
        """
        Return Omega_KEV(k):
        - CISA KEV factor = 1.8
        - EPSS >= 0.20 factor = 1.5
        - Otherwise EPSS factor = 1.0
        """
        if self.is_cisa_kev:
            return OMEGA_CISA_KEV
        if self.epss_score >= EPSS_THRESHOLD:
            return OMEGA_EPSS_HIGH
        return OMEGA_EPSS_DEFAULT

    def compute_elapsed_days(self, evaluation_time_t: datetime) -> float:
        """Compute non-negative elapsed time (t - t0) in fractional days."""
        t0 = parse_iso_timestamp(self.observed_at_t0)
        t_eval = (
            evaluation_time_t.replace(tzinfo=timezone.utc)
            if evaluation_time_t.tzinfo is None
            else evaluation_time_t.astimezone(timezone.utc)
        )
        delta_seconds = (t_eval - t0).total_seconds()
        return max(0.0, delta_seconds / 86400.0)

    def compute_temporal_decay(self, evaluation_time_t: datetime) -> float:
        """
        Compute temporal decay:
        D(t, t0) = exp(-lambda_k * (t - t0))
        """
        elapsed_days = self.compute_elapsed_days(evaluation_time_t)
        decay_rate = float(self.decay_lambda or 0.0)
        return math.exp(-decay_rate * elapsed_days)

    def compute_context_multiplier_phi(self, psi_exp: float) -> float:
        """
        Compute context multiplier:
        Phi_ik = Omega_KEV(k) * Psi_exp(i) * Gamma_ctrl(i, k)
        """
        return self.omega_kev_factor * psi_exp * self.control_factor_gamma

    def compute_effective_severity(
        self, psi_exp: float, evaluation_time_t: datetime
    ) -> float:
        """
        Compute effective severity:
        S(I_ik, t) = min(1.0, S0(k) * D(t, t0) * Phi_ik)
        """
        d_val = self.compute_temporal_decay(evaluation_time_t)
        phi_val = self.compute_context_multiplier_phi(psi_exp)
        raw_severity = self.base_severity_s0 * d_val * phi_val
        return min(EFFECTIVE_SEVERITY_MAX, raw_severity)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 3. MATHEMATICAL EVALUATION OUTPUT MODELS
# ==============================================================================
@dataclass(slots=True)
class EvaluatedIndicatorDetail:
    """Stores step-by-step mathematical intermediate values for an indicator."""

    indicator_id: int | None
    sha256_hash: str
    asset_id: str
    category: str
    indicator_type: str
    identifier_key: str
    title: str
    s0: float
    confidence_c: float
    decay_lambda: float
    elapsed_days: float
    temporal_decay_d: float
    omega_kev: float
    psi_exp: float
    gamma_ctrl: float
    context_phi: float
    effective_severity_s: float
    weighted_impact_cs: float  # C_ik * S(I_ik, t)
    survival_term: float       # 1 - C_ik * S(I_ik, t)
    remediation_effort_e: float


@dataclass(slots=True)
class AssetRiskResult:
    """Stores the computed risk parameters for a single asset i."""

    asset: Asset
    weight_w_i: float
    criticality_modifier: float  # (A_i / 5)^beta
    open_indicator_count: int
    survival_product: float      # product(1 - C_ik * S(I_ik, t))
    combined_threat_prob: float  # 1 - survival_product
    risk_score_r_i: float        # R_i(t) in [0, 100]
    risk_tier: RiskTier
    evaluated_indicators: list[EvaluatedIndicatorDetail]


@dataclass(slots=True)
class RemediationPriorityItem:
    """Stores the Remediation Priority Index (RPI) calculation for an indicator."""

    rank: int
    indicator_id: int | None
    sha256_hash: str
    asset_id: str
    asset_name: str
    category: str
    identifier_key: str
    title: str
    current_asset_risk_r_i: float
    counterfactual_risk_r_i_minus_k: float
    risk_reduction_delta: float  # R_i - R_i(-k)
    remediation_effort_e: float
    omega_kev: float
    rpi_score: float             # [(R_i - R_i(-k)) / E_k] * Omega_KEV(k)


@dataclass(slots=True)
class SystemRiskSummary:
    """Complete system-wide evaluation result at timestamp t."""

    evaluated_at: str
    data_source_filter: str
    system_risk_r_sys: float
    system_risk_tier: RiskTier
    max_asset_risk: float
    weighted_mean_asset_risk: float
    total_assets: int
    total_open_indicators: int
    asset_results: list[AssetRiskResult]
    remediation_plan: list[RemediationPriorityItem]
