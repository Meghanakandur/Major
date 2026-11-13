"""
collectors/base_collector.py
Defines the StandardisedIndicatorRecord data structure, input validation,
deterministic SHA-256 deduplication hashing, and conversion to ThreatIndicator.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any

from config import (
    DataSource,
    GAMMA_CTRL_MAX,
    GAMMA_CTRL_MIN,
    IndicatorCategory,
    IndicatorStatus,
    get_default_decay_lambda,
)
from models import ThreatIndicator, parse_iso_timestamp, sanitise_text


def compute_record_sha256(
    asset_id: str,
    category: str,
    indicator_type: str,
    identifier_key: str,
    status: str = IndicatorStatus.OPEN.value,
) -> str:
    """
    Generate a deterministic SHA-256 digest across canonical indicator attributes.
    Identical open findings on the same SME asset produce the exact same hash.
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


@dataclass(slots=True)
class StandardisedIndicatorRecord:
    """
    Standardised Cybersecurity Indicator Data Structure.
    Contains all required fields across the four indicator categories:
    - indicator_id: Canonical unique key or CVE/rule identifier (e.g., 'CVE-2024-21762')
    - asset_id: Target SME asset identifier (e.g., 'AST-001')
    - category: One of the 4 mandatory IndicatorCategory values
    - severity: Normalised base severity S0(k) in (0.0, 1.0] (auto-scaled if 1.0..10.0 CVSS given)
    - confidence: Indicator confidence C_ik in (0.0, 1.0] (auto-scaled if 1..100% given)
    - timestamp: Observation timestamp t0 in ISO-8601 UTC format
    - source: Origin feed or collector name (e.g., 'CISA_KEV_FEED', 'CSV_IMPORT', 'SYNTHETIC_GENERATOR')
    - description: Human-readable explanation of the finding
    """

    indicator_id: str
    asset_id: str
    category: str
    severity: float
    confidence: float
    timestamp: str
    source: str
    description: str
    indicator_type: str = "GENERAL_INDICATOR"
    is_cisa_kev: bool = False
    epss_score: float = 0.05
    control_factor_gamma: float = 0.85
    remediation_effort_e: float = 2.0
    decay_lambda: float | None = None
    data_source: str = DataSource.SIMULATED.value
    status: str = IndicatorStatus.OPEN.value
    sha256_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.indicator_id = sanitise_text(
            str(self.indicator_id), "indicator_id", max_length=128
        ).upper()
        self.asset_id = sanitise_text(
            str(self.asset_id), "asset_id", max_length=64
        ).upper()
        self.source = sanitise_text(str(self.source), "source", max_length=128)
        self.description = sanitise_text(
            str(self.description), "description", max_length=255
        )
        self.indicator_type = sanitise_text(
            str(self.indicator_type), "indicator_type", max_length=64
        ).upper()

        valid_categories = {c.value for c in IndicatorCategory}
        if self.category not in valid_categories:
            raise ValueError(
                f"Invalid category '{self.category}'. Expected one of {sorted(valid_categories)}."
            )

        # Normalise severity: if provided on a 1.0-10.0 CVSS scale or 1-100 scale, normalise to (0.0, 1.0]
        raw_sev = float(self.severity)
        if 1.0 < raw_sev <= 10.0:
            raw_sev = raw_sev / 10.0
        elif 10.0 < raw_sev <= 100.0:
            raw_sev = raw_sev / 100.0
        if not (0.0 < raw_sev <= 1.0):
            raise ValueError(
                f"Normalised severity S0(k) must be in (0.0, 1.0], got {self.severity}."
            )
        self.severity = round(raw_sev, 4)

        # Normalise confidence: if provided on a 1-100 percentage scale, normalise to (0.0, 1.0]
        raw_conf = float(self.confidence)
        if 1.0 < raw_conf <= 100.0:
            raw_conf = raw_conf / 100.0
        if not (0.0 < raw_conf <= 1.0):
            raise ValueError(
                f"Normalised confidence C_ik must be in (0.0, 1.0], got {self.confidence}."
            )
        self.confidence = round(raw_conf, 4)

        # Validate & normalise timestamp t0
        parsed_dt = parse_iso_timestamp(str(self.timestamp))
        self.timestamp = parsed_dt.isoformat()

        self.is_cisa_kev = bool(self.is_cisa_kev)
        self.epss_score = max(0.0, min(1.0, float(self.epss_score)))
        self.control_factor_gamma = max(
            GAMMA_CTRL_MIN, min(GAMMA_CTRL_MAX, float(self.control_factor_gamma))
        )
        self.remediation_effort_e = max(0.1, float(self.remediation_effort_e))

        if self.decay_lambda is None:
            self.decay_lambda = get_default_decay_lambda(self.category)
        else:
            self.decay_lambda = max(0.0, float(self.decay_lambda))

        valid_sources = {ds.value for ds in DataSource}
        if self.data_source not in valid_sources:
            self.data_source = DataSource.REAL.value

        self.sha256_hash = compute_record_sha256(
            asset_id=self.asset_id,
            category=self.category,
            indicator_type=self.indicator_type,
            identifier_key=self.indicator_id,
            status=self.status,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def record_to_threat_indicator(record: StandardisedIndicatorRecord) -> ThreatIndicator:
    """Convert a StandardisedIndicatorRecord into the SQLite-persisted ThreatIndicator model."""
    return ThreatIndicator(
        asset_id=record.asset_id,
        category=record.category,
        indicator_type=record.indicator_type,
        identifier_key=record.indicator_id,
        title=f"[{record.source}] {record.description}"[:255],
        base_severity_s0=record.severity,
        confidence_c=record.confidence,
        is_cisa_kev=record.is_cisa_kev,
        epss_score=record.epss_score,
        control_factor_gamma=record.control_factor_gamma,
        remediation_effort_e=record.remediation_effort_e,
        observed_at_t0=record.timestamp,
        decay_lambda=record.decay_lambda,
        status=record.status,
        data_source=record.data_source,
    )


@dataclass(slots=True)
class BatchIngestionReport:
    """Summary report returned after collecting or importing a batch of indicators."""

    source_label: str
    total_processed: int
    inserted_unique: int
    duplicates_suppressed: int
    validation_errors: int
    error_messages: list[str]
    inserted_hashes: list[str]
    duplicate_hashes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
