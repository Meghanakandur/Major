"""
collectors/identity_collector.py
Category 4 Collector: Identity and Authentication Hygiene.
- Enforces persistent temporal decay lambda = 0.00 for missing MFA and privileged
  account hygiene gaps until remediation.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base_collector import StandardisedIndicatorRecord
from config import DataSource, IndicatorCategory, LAMBDA_PERSISTENT


class IdentityHygieneCollector:
    """
    Collects and normalises Category 4: Identity and Authentication Hygiene indicators.
    Missing MFA and privileged identity flaws do not decay over time (lambda = 0.00).
    """

    CATEGORY: str = IndicatorCategory.IDENTITY_AUTH.value
    DEFAULT_LAMBDA: float = LAMBDA_PERSISTENT

    IDENTITY_SEVERITY_DEFAULTS: dict[str, float] = {
        "MISSING_MFA_PRIVILEGED": 0.95,
        "MISSING_MFA_STANDARD_USER": 0.72,
        "DORMANT_DOMAIN_ADMIN": 0.78,
        "SHARED_DB_SUPERUSER": 0.68,
        "WEAK_PASSWORD_POLICY": 0.64,
        "UNROTATED_API_KEY": 0.70,
    }

    def normalise_raw_entry(
        self,
        raw: dict[str, Any],
        default_data_source: str = DataSource.REAL.value,
    ) -> StandardisedIndicatorRecord:
        """
        Normalise an IAM / Active Directory / Cloud identity hygiene audit row
        into a StandardisedIndicatorRecord.
        """
        indicator_type = str(
            raw.get("indicator_type") or "MISSING_MFA_PRIVILEGED"
        ).strip().upper()
        default_sev = self.IDENTITY_SEVERITY_DEFAULTS.get(indicator_type, 0.78)

        indicator_id = str(
            raw.get("indicator_id")
            or raw.get("identifier_key")
            or f"IAM-{indicator_type}"
        )
        asset_id = str(raw.get("asset_id") or "AST-006")
        severity = float(raw.get("severity") or raw.get("base_severity_s0") or default_sev)
        confidence = float(raw.get("confidence") or raw.get("confidence_c") or 0.98)
        timestamp = str(
            raw.get("timestamp")
            or raw.get("observed_at_t0")
            or datetime.now(timezone.utc).isoformat()
        )
        source = str(raw.get("source") or "IDENTITY_HYGIENE_AUDITOR")
        description = str(
            raw.get("description")
            or raw.get("title")
            or f"Identity & authentication hygiene gap: {indicator_id}"
        )

        return StandardisedIndicatorRecord(
            indicator_id=indicator_id,
            asset_id=asset_id,
            category=self.CATEGORY,
            severity=severity,
            confidence=confidence,
            timestamp=timestamp,
            source=source,
            description=description,
            indicator_type=indicator_type,
            is_cisa_kev=bool(raw.get("is_cisa_kev", False)),
            epss_score=float(raw.get("epss_score", 0.30)),
            control_factor_gamma=float(raw.get("control_factor_gamma", 0.95)),
            remediation_effort_e=float(raw.get("remediation_effort_e", 1.5)),
            decay_lambda=self.DEFAULT_LAMBDA,
            data_source=str(raw.get("data_source") or default_data_source),
        )

    def collect_synthetic_samples(
        self, reference_time: datetime | None = None
    ) -> list[StandardisedIndicatorRecord]:
        """
        Return realistic synthetic Identity and Authentication Hygiene indicators.
        """
        ref = reference_time or datetime.now(timezone.utc)
        return [
            StandardisedIndicatorRecord(
                indicator_id="MFA-DISABLED-GLOBAL-ADMIN-02",
                asset_id="AST-006",
                category=self.CATEGORY,
                severity=0.95,
                confidence=1.00,
                timestamp=(ref - timedelta(days=11.0)).isoformat(),
                source="ENTRA_ID_HYGIENE_SYNTHETIC",
                description="Multi-Factor Authentication (MFA) not enforced on backup Global Administrator account",
                indicator_type="MISSING_MFA_PRIVILEGED",
                is_cisa_kev=False,
                epss_score=0.45,
                control_factor_gamma=1.00,
                remediation_effort_e=1.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="AD-SVC-LEGACY-BACKUP-ADMIN",
                asset_id="AST-003",
                category=self.CATEGORY,
                severity=0.78,
                confidence=0.95,
                timestamp=(ref - timedelta(days=42.0)).isoformat(),
                source="ACTIVE_DIRECTORY_AUDIT_SYNTHETIC",
                description="Dormant Domain Admin service account with PasswordNeverExpires flag enabled (>365 days)",
                indicator_type="DORMANT_DOMAIN_ADMIN",
                is_cisa_kev=False,
                epss_score=0.22,
                control_factor_gamma=0.80,
                remediation_effort_e=1.5,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="POSTGRES-SHARED-SA-CREDENTIALS",
                asset_id="AST-004",
                category=self.CATEGORY,
                severity=0.65,
                confidence=0.90,
                timestamp=(ref - timedelta(days=18.0)).isoformat(),
                source="DB_PRIVILEGE_AUDIT_SYNTHETIC",
                description="Shared PostgreSQL superuser account used across multiple internal billing services",
                indicator_type="SHARED_DB_SUPERUSER",
                is_cisa_kev=False,
                epss_score=0.10,
                control_factor_gamma=0.70,
                remediation_effort_e=3.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
        ]
