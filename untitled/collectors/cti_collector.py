"""
collectors/cti_collector.py
Category 1 Collector: External Cyber Threat Intelligence.
- Enforces temporal decay lambda = 0.05 per day.
- Supports optional, safe, read-only public feed correlation (e.g. CISA KEV / FIRST EPSS API)
  with strict timeouts and automatic fallback to synthetic or imported data when offline
  or unconfigured.
- Never performs unauthorised network scanning.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from collectors.base_collector import StandardisedIndicatorRecord
from config import DataSource, IndicatorCategory, LAMBDA_TEMPORARY_CTI


class ExternalCTICollector:
    """
    Collects and normalises Category 1: External Cyber Threat Intelligence indicators.
    All indicators in this category receive decay_lambda = 0.05 per day.
    """

    CATEGORY: str = IndicatorCategory.EXTERNAL_CTI.value
    DEFAULT_LAMBDA: float = LAMBDA_TEMPORARY_CTI

    def __init__(self, enable_external_api: bool = False, timeout_seconds: float = 4.0) -> None:
        self.enable_external_api = enable_external_api
        self.timeout_seconds = timeout_seconds

    def fetch_optional_epss_enrichment(self, cve_id: str) -> float | None:
        """
        Optionally query the public FIRST.org EPSS read-only API for a CVE identifier.
        If `enable_external_api` is False or the network/API is unreachable, safely
        returns None without raising an unhandled exception.
        """
        if not self.enable_external_api:
            return None
        clean_cve = cve_id.strip().upper()
        if not clean_cve.startswith("CVE-"):
            return None

        url = f"https://api.first.org/data/v1/epss?cve={clean_cve}"
        try:
            req = Request(url, headers={"Accept": "application/json", "User-Agent": "SME-CyberRiskScorer/1.0"})
            with urlopen(req, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
                data_rows = payload.get("data", [])
                if data_rows and "epss" in data_rows[0]:
                    return float(data_rows[0]["epss"])
        except (URLError, TimeoutError, ValueError, KeyError, OSError):
            return None
        return None

    def normalise_raw_entry(
        self,
        raw: dict[str, Any],
        default_data_source: str = DataSource.REAL.value,
    ) -> StandardisedIndicatorRecord:
        """
        Convert a raw dictionary (from CSV, JSON, or passive CTI feed log) into
        a StandardisedIndicatorRecord for Category 1.
        """
        indicator_id = str(
            raw.get("indicator_id")
            or raw.get("identifier_key")
            or raw.get("ioc_value")
            or "CTI-IOC-UNKNOWN"
        )
        asset_id = str(raw.get("asset_id") or "AST-001")
        severity = float(raw.get("severity") or raw.get("base_severity_s0") or 0.75)
        confidence = float(raw.get("confidence") or raw.get("confidence_c") or 0.85)
        timestamp = str(
            raw.get("timestamp")
            or raw.get("observed_at_t0")
            or datetime.now(timezone.utc).isoformat()
        )
        source = str(raw.get("source") or "EXTERNAL_CTI_FEED")
        description = str(
            raw.get("description")
            or raw.get("title")
            or f"External threat intelligence match for {indicator_id}"
        )

        epss = float(raw.get("epss_score", 0.25))
        optional_live_epss = self.fetch_optional_epss_enrichment(indicator_id)
        if optional_live_epss is not None:
            epss = optional_live_epss

        return StandardisedIndicatorRecord(
            indicator_id=indicator_id,
            asset_id=asset_id,
            category=self.CATEGORY,
            severity=severity,
            confidence=confidence,
            timestamp=timestamp,
            source=source,
            description=description,
            indicator_type=str(raw.get("indicator_type") or "CTI_THREAT_MATCH"),
            is_cisa_kev=bool(raw.get("is_cisa_kev", False)),
            epss_score=epss,
            control_factor_gamma=float(raw.get("control_factor_gamma", 0.75)),
            remediation_effort_e=float(raw.get("remediation_effort_e", 1.5)),
            decay_lambda=self.DEFAULT_LAMBDA,
            data_source=str(raw.get("data_source") or default_data_source),
        )

    def collect_synthetic_samples(
        self, reference_time: datetime | None = None
    ) -> list[StandardisedIndicatorRecord]:
        """
        Return realistic synthetic External Cyber Threat Intelligence indicators
        for demonstration or offline fallback.
        """
        ref = reference_time or datetime.now(timezone.utc)
        return [
            StandardisedIndicatorRecord(
                indicator_id="OTX-TOR-185.220.101.44",
                asset_id="AST-001",
                category=self.CATEGORY,
                severity=0.74,
                confidence=0.88,
                timestamp=(ref - timedelta(days=3.0)).isoformat(),
                source="ALIENVAULT_OTX_SYNTHETIC",
                description="Sustained credential-stuffing & L7 web exploit probes from known Tor exit node",
                indicator_type="CTI_BOTNET_PROBES",
                is_cisa_kev=False,
                epss_score=0.28,
                control_factor_gamma=0.70,
                remediation_effort_e=1.5,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="ABUSEIPDB-91.214.124.88",
                asset_id="AST-002",
                category=self.CATEGORY,
                severity=0.82,
                confidence=0.92,
                timestamp=(ref - timedelta(days=1.5)).isoformat(),
                source="ABUSEIPDB_SYNTHETIC",
                description="High-velocity SSL-VPN password spraying from ransomware affiliate infrastructure",
                indicator_type="CTI_VPN_BRUTEFORCE",
                is_cisa_kev=False,
                epss_score=0.36,
                control_factor_gamma=0.80,
                remediation_effort_e=1.0,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
            StandardisedIndicatorRecord(
                indicator_id="URLHAUS-C2-CDN-SYNC.TOP",
                asset_id="AST-005",
                category=self.CATEGORY,
                severity=0.79,
                confidence=0.76,
                timestamp=(ref - timedelta(days=12.0)).isoformat(),
                source="ABUSE_CH_URLHAUS_SYNTHETIC",
                description="Outbound DNS query to known infostealer command-and-control staging domain",
                indicator_type="CTI_DNS_BEACON",
                is_cisa_kev=False,
                epss_score=0.18,
                control_factor_gamma=0.60,
                remediation_effort_e=2.5,
                decay_lambda=self.DEFAULT_LAMBDA,
                data_source=DataSource.SIMULATED.value,
            ),
        ]
