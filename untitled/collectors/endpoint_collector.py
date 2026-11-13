"""
collectors/endpoint_collector.py
Category 3 Collector: Endpoint Configuration and Patch Indicators.
- Enforces persistent temporal decay lambda = 0.00 for unresolved vulnerabilities
  and endpoint misconfigurations until remediation.
- Normalises CVSS scores (0-10) or raw severities (0-1), CISA KEV flags, and EPSS probabilities.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base_collector import StandardisedIndicatorRecord
from config import DataSource, IndicatorCategory, LAMBDA_PERSISTENT


class EndpointPatchCollector:
    """
    Collects and normalises Category 3: Endpoint Configuration and Patch Indicators.
    Unresolved CVE vulnerabilities and missing patches use decay_lambda = 0.00.
    """

    CATEGORY: str = IndicatorCategory.ENDPOINT_PATCH.value
    DEFAULT_LAMBDA: float = LAMBDA_PERSISTENT

    def normalise_raw_entry(
        self,
        raw: dict[str, Any],
        default_data_source: str = DataSource.REAL.value,
    ) -> StandardisedIndicatorRecord:
        """
        Normalise a vulnerability scanner export row or endpoint configuration compliance
        finding into a StandardisedIndicatorRecord.
        """
        indicator_id = str(
            raw.get("indicator_id")
            or raw.get("identifier_key")
            or raw.get("cve_id")
            or "ENDPOINT-FINDING-001"
        )
        asset_id = str(raw.get("asset_id") or "AST-001")

        # Accept either S0 in (0, 1] or CVSS v3 score in (0, 10]
        raw_severity = float(
            raw.get("severity")
            or raw.get("base_severity_s0")
            or raw.get("cvss_score")
            or 0.75
        )
        confidence = float(raw.get("confidence") or raw.get("confidence_c") or 0.92)
        timestamp = str(
            raw.get("timestamp")
            or raw.get("observed_at_t0")
            or datetime.now(timezone.utc).isoformat()
        )
        source = str(raw.get("source") or "ENDPOINT_PATCH_AUDITOR")
        description = str(
            raw.get("description")
            or raw.get("title")
            or f"Unpatched endpoint vulnerability or configuration gap: {indicator_id}"
        )

        is_kev_raw = raw.get("is_cisa_kev", False)
        is_cisa_kev = str(is_kev_raw).strip().lower() in ("1", "true", "yes", "y")

        return StandardisedIndicatorRecord(
            indicator_id=indicator_id,
            asset_id=asset_id,
            category=self.CATEGORY,
            severity=raw_severity,
            confidence=confidence,
            timestamp=timestamp,
            source=source,
            description=description,
            indicator_type=str(raw.get("indicator_type") or "CVE_VULNERABILITY"),
            is_cisa_kev=is_cisa_kev,
            epss_score=float(raw.get("epss_score", 0.15)),
            control_factor_gamma=float(raw.get("control_factor_gamma", 0.80)),
            remediation_effort_e=float(raw.get("remediation_effort_e", 3.0)),
            decay_lambda=self.DEFAULT_LAMBDA,
            data_source=str(raw.get("data_source") or default_data_source),
        )

    def collect_synthetic_samples(
        self, reference_time: datetime | None = None
    ) -> list[StandardisedIndicatorRecord]:
        """
        Return realistic synthetic Endpoint Configuration and Patch Indicators.
        """
        ref = reference_time or datetime.now(timezone.utc)
        return [
            StandardisedIndicatorRecord(
                indicator_id="CVE-2024-21762",
                asset_id="AST-002",
                category=self.CATEGORY,
                severity=0.98,
                confidence=0.95,
                timestamp=(ref - timedelta(days=9.0)).isoformat(),
                source="CISA_KEV_PATCH_AUDIT_SYNTHETIC",
                description="Critical out-of-bounds write RCE vulnerability in SSL-VPN appliance firmware (CISA KEV)",
                indicator_type="CVE_VULNERABILITY",
                is_cisa_kev=True,
                epss_score=0.94,
                control_factor_gamma=0.85,
                remediation_effort_e=3.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="CVE-2023-44487",
                asset_id="AST-001",
                category=self.CATEGORY,
                severity=0.75,
                confidence=0.90,
                timestamp=(ref - timedelta(days=19.0)).isoformat(),
                source="NGINX_PATCH_INSPECTOR_SYNTHETIC",
                description="HTTP/2 Rapid Reset denial-of-service vulnerability on unpatched reverse proxy",
                indicator_type="CVE_VULNERABILITY",
                is_cisa_kev=True,
                epss_score=0.78,
                control_factor_gamma=0.65,
                remediation_effort_e=2.5,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="CIS-WIN-SMBV1-LDAP-UNSIGNED",
                asset_id="AST-003",
                category=self.CATEGORY,
                severity=0.82,
                confidence=0.95,
                timestamp=(ref - timedelta(days=35.0)).isoformat(),
                source="CIS_BENCHMARK_AUDITOR_SYNTHETIC",
                description="Unsigned LDAP binds and legacy SMBv1 protocol active on primary Domain Controller",
                indicator_type="ENDPOINT_MISCONFIGURATION",
                is_cisa_kev=False,
                epss_score=0.31,
                control_factor_gamma=0.75,
                remediation_effort_e=3.5,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="EDR-TAMPER-PROTECTION-DISABLED",
                asset_id="AST-005",
                category=self.CATEGORY,
                severity=0.68,
                confidence=1.00,
                timestamp=(ref - timedelta(days=6.0)).isoformat(),
                source="ENDPOINT_EDR_TELEMETRY_SYNTHETIC",
                description="EDR real-time behavioral monitoring and tamper protection disabled on Finance workstation",
                indicator_type="EDR_TAMPER_PROTECTION_OFF",
                is_cisa_kev=False,
                epss_score=0.06,
                control_factor_gamma=0.90,
                remediation_effort_e=1.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
        ]
