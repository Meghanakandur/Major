"""
collectors/perimeter_collector.py
Category 2 Collector: Perimeter and Attack Surface Exposure.
- Enforces persistent temporal decay lambda = 0.00 until remediation.
- Processes passive firewall configuration exports, TLS certificate metadata,
  and external attack surface audit logs without performing active/unauthorised port scanning.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base_collector import StandardisedIndicatorRecord
from config import DataSource, IndicatorCategory, LAMBDA_PERSISTENT


class PerimeterExposureCollector:
    """
    Collects and normalises Category 2: Perimeter and Attack Surface Exposure indicators.
    Unresolved exposure findings maintain lambda = 0.0 until remediated.
    """

    CATEGORY: str = IndicatorCategory.PERIMETER_EXPOSURE.value
    DEFAULT_LAMBDA: float = LAMBDA_PERSISTENT

    # Baseline severity lookup for common passive perimeter exposure types
    EXPOSURE_SEVERITY_MAP: dict[str, float] = {
        "OPEN_RDP_PORT_3389": 0.92,
        "OPEN_SMB_PORT_445": 0.95,
        "OPEN_ADMIN_PORT": 0.78,
        "WEAK_TLS_CIPHER_SUITE": 0.58,
        "EXPIRED_TLS_CERTIFICATE": 0.62,
        "LEGACY_AUTH_PROTOCOL_EXPOSED": 0.72,
        "MISSING_SPF_DMARC_POLICY": 0.55,
    }

    def normalise_raw_entry(
        self,
        raw: dict[str, Any],
        default_data_source: str = DataSource.REAL.value,
    ) -> StandardisedIndicatorRecord:
        """
        Normalise a passive perimeter audit entry or uploaded CSV/JSON row into
        a StandardisedIndicatorRecord.
        """
        indicator_type = str(
            raw.get("indicator_type") or "PERIMETER_EXPOSURE_FINDING"
        ).strip().upper()
        default_sev = self.EXPOSURE_SEVERITY_MAP.get(indicator_type, 0.70)

        indicator_id = str(
            raw.get("indicator_id")
            or raw.get("identifier_key")
            or f"PERIM-{indicator_type}"
        )
        asset_id = str(raw.get("asset_id") or "AST-001")
        severity = float(raw.get("severity") or raw.get("base_severity_s0") or default_sev)
        confidence = float(raw.get("confidence") or raw.get("confidence_c") or 0.95)
        timestamp = str(
            raw.get("timestamp")
            or raw.get("observed_at_t0")
            or datetime.now(timezone.utc).isoformat()
        )
        source = str(raw.get("source") or "PASSIVE_PERIMETER_AUDIT")
        description = str(
            raw.get("description")
            or raw.get("title")
            or f"Perimeter attack surface exposure: {indicator_id}"
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
            epss_score=float(raw.get("epss_score", 0.22)),
            control_factor_gamma=float(raw.get("control_factor_gamma", 0.90)),
            remediation_effort_e=float(raw.get("remediation_effort_e", 2.0)),
            decay_lambda=self.DEFAULT_LAMBDA,
            data_source=str(raw.get("data_source") or default_data_source),
        )

    def collect_synthetic_samples(
        self, reference_time: datetime | None = None
    ) -> list[StandardisedIndicatorRecord]:
        """
        Return realistic synthetic Perimeter and Attack Surface Exposure indicators
        derived from passive configuration audits (no active scanning).
        """
        ref = reference_time or datetime.now(timezone.utc)
        return [
            StandardisedIndicatorRecord(
                indicator_id="TCP-8443-ADMIN-CONSOLE-EXPOSED",
                asset_id="AST-001",
                category=self.CATEGORY,
                severity=0.76,
                confidence=0.95,
                timestamp=(ref - timedelta(days=16.0)).isoformat(),
                source="FIREWALL_CONFIG_AUDIT_SYNTHETIC",
                description="Staging management console port TCP/8443 exposed on WAN rule without IP allowlist",
                indicator_type="OPEN_ADMIN_PORT",
                is_cisa_kev=False,
                epss_score=0.24,
                control_factor_gamma=0.90,
                remediation_effort_e=2.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="TLS-1.0-1.1-WAN-GATEWAY",
                asset_id="AST-002",
                category=self.CATEGORY,
                severity=0.56,
                confidence=1.00,
                timestamp=(ref - timedelta(days=28.0)).isoformat(),
                source="TLS_PASSIVE_INSPECTOR_SYNTHETIC",
                description="Deprecated TLS 1.0/1.1 protocols and weak CBC cipher suites enabled on VPN gateway",
                indicator_type="WEAK_TLS_CIPHER_SUITE",
                is_cisa_kev=False,
                epss_score=0.09,
                control_factor_gamma=1.00,
                remediation_effort_e=1.5,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="IMAP-POP3-LEGACY-AUTH-WAN",
                asset_id="AST-006",
                category=self.CATEGORY,
                severity=0.72,
                confidence=0.95,
                timestamp=(ref - timedelta(days=22.0)).isoformat(),
                source="CLOUD_TENANT_EXPOSURE_AUDIT",
                description="Legacy basic authentication endpoints (IMAP/POP3/SMTP) reachable from external internet",
                indicator_type="LEGACY_AUTH_PROTOCOL_EXPOSED",
                is_cisa_kev=False,
                epss_score=0.26,
                control_factor_gamma=0.85,
                remediation_effort_e=2.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
        ]
