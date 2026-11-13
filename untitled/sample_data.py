"""
sample_data.py
Generates realistic, clearly labeled synthetic SME assets and cybersecurity indicators
across all four required categories for demonstration and testing, plus downloadable
CSV templates for real data ingestion.
Compatible with Python 3.11+.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from typing import Any

from config import (
    AssetType,
    DataSource,
    IndicatorCategory,
    LAMBDA_PERSISTENT,
    LAMBDA_TEMPORARY_CTI,
    TEMPLATE_DIR,
    ensure_directories,
)
from database import DatabaseManager
from models import Asset, ThreatIndicator

SAMPLE_CSV_PAYLOAD_DEFAULT: str = """asset_id,category,indicator_type,identifier_key,title,base_severity_s0,confidence_c,is_cisa_kev,epss_score,control_factor_gamma,remediation_effort_e,observed_at_t0
AST-001,External Cyber Threat Intelligence,CTI_SHODAN_HONEYPOT_MATCH,GREYNOISE-45.155.205.233,Inbound HTTP header exploit reconnaissance from malicious scanner ASN,0.74,0.88,0,0.32,0.75,1.5,2026-11-08T10:00:00Z
AST-002,Perimeter and Attack Surface Exposure,OPEN_SNMP_UDP_161,UDP-161-SNMPV2-PUBLIC,SNMP v2c service with default community string reachable on WAN interface,0.84,0.95,0,0.29,0.95,1.5,2026-11-01T08:30:00Z
AST-003,Endpoint Configuration and Patch Indicators,CVE_VULNERABILITY,CVE-2024-38063,Windows TCP/IP IPv6 Remote Code Execution Vulnerability on Domain Controller,0.98,0.96,1,0.89,0.80,2.5,2026-11-05T12:00:00Z
AST-006,Identity and Authentication Hygiene,MISSING_MFA_PRIVILEGED,MFA-GAP-FINANCE-DIRECTOR,Conditional Access MFA policy bypass detected on Finance Director cloud account,0.92,1.00,0,0.40,1.00,1.0,2026-11-06T09:15:00Z"""

SAMPLE_JSON_PAYLOAD_DEFAULT: str = """{
  "indicators": [
    {
      "indicator_id": "CVE-2024-21762",
      "asset_id": "AST-002",
      "category": "Endpoint Configuration and Patch Indicators",
      "indicator_type": "CVE_VULNERABILITY",
      "severity": 0.98,
      "confidence": 0.95,
      "is_cisa_kev": true,
      "epss_score": 0.94,
      "control_factor_gamma": 0.85,
      "remediation_effort_e": 3.0,
      "timestamp": "2026-11-01T00:00:00Z",
      "source": "JSON_SCANNER_IMPORT",
      "description": "Intentional duplicate CVE-2024-21762 to test SHA-256 deduplication suppression"
    },
    {
      "indicator_id": "TLS-EXPIRED-CERT-PORTAL",
      "asset_id": "AST-001",
      "category": "Perimeter and Attack Surface Exposure",
      "indicator_type": "EXPIRED_TLS_CERTIFICATE",
      "severity": 0.64,
      "confidence": 1.0,
      "is_cisa_kev": false,
      "epss_score": 0.11,
      "control_factor_gamma": 0.9,
      "remediation_effort_e": 1.0,
      "timestamp": "2026-11-09T06:00:00Z",
      "source": "PASSIVE_TLS_MONITOR",
      "description": "Wildcard TLS certificate on secondary checkout subdomain approaching expiration"
    }
  ]
}"""



def build_synthetic_sme_assets(reference_time: datetime) -> list[Asset]:
    """
    Create 6 realistic SME assets covering varied criticality levels (A_i in 1..5)
    and internet exposure conditions (Psi_exp in {1.4, 1.0}).
    All records are explicitly marked with data_source = 'SIMULATED'.
    """
    created_iso = (reference_time - timedelta(days=60)).isoformat()
    return [
        Asset(
            asset_id="AST-001",
            asset_name="SME Public E-Commerce & Customer Portal",
            asset_type=AssetType.WEB_APPLICATION.value,
            criticality_score=5,
            is_internet_facing=True,
            owner_department="Digital Commerce",
            ip_or_hostname="203.0.113.10 (portal.sme-example.local)",
            data_source=DataSource.SIMULATED.value,
            created_at=created_iso,
        ),
        Asset(
            asset_id="AST-002",
            asset_name="Edge VPN & Firewall Gateway Appliance",
            asset_type=AssetType.NETWORK_DEVICE.value,
            criticality_score=5,
            is_internet_facing=True,
            owner_department="Network Security",
            ip_or_hostname="203.0.113.2 (vpn.sme-example.local)",
            data_source=DataSource.SIMULATED.value,
            created_at=created_iso,
        ),
        Asset(
            asset_id="AST-003",
            asset_name="Primary Active Directory & Identity Controller",
            asset_type=AssetType.SERVER.value,
            criticality_score=5,
            is_internet_facing=False,
            owner_department="IT Infrastructure",
            ip_or_hostname="10.10.1.10 (dc01.internal.sme)",
            data_source=DataSource.SIMULATED.value,
            created_at=created_iso,
        ),
        Asset(
            asset_id="AST-004",
            asset_name="ERP & Customer Billing PostgreSQL Database",
            asset_type=AssetType.DATABASE.value,
            criticality_score=4,
            is_internet_facing=False,
            owner_department="Finance & Operations",
            ip_or_hostname="10.10.2.25 (erp-db.internal.sme)",
            data_source=DataSource.SIMULATED.value,
            created_at=created_iso,
        ),
        Asset(
            asset_id="AST-005",
            asset_name="Finance & Payroll Manager Workstation",
            asset_type=AssetType.WORKSTATION.value,
            criticality_score=3,
            is_internet_facing=False,
            owner_department="Finance & Accounting",
            ip_or_hostname="10.10.20.104 (ws-fin-04.internal.sme)",
            data_source=DataSource.SIMULATED.value,
            created_at=created_iso,
        ),
        Asset(
            asset_id="AST-006",
            asset_name="Microsoft 365 & Cloud Identity Tenant",
            asset_type=AssetType.CLOUD_IDENTITY.value,
            criticality_score=4,
            is_internet_facing=True,
            owner_department="Corporate IT",
            ip_or_hostname="sme-example.onmicrosoft.com",
            data_source=DataSource.SIMULATED.value,
            created_at=created_iso,
        ),
    ]


def build_synthetic_sme_indicators(reference_time: datetime) -> list[ThreatIndicator]:
    """
    Create realistic synthetic cybersecurity threat indicators spanning all 4 categories:
    1. External Cyber Threat Intelligence (lambda = 0.05/day)
    2. Perimeter and Attack Surface Exposure (lambda = 0.0)
    3. Endpoint Configuration and Patch Indicators (lambda = 0.0)
    4. Identity and Authentication Hygiene (lambda = 0.0)

    Also includes 2 intentional duplicate indicators at the end of the list to
    demonstrate and verify the SHA-256 deduplication pipeline.
    """
    def days_ago(days: float) -> str:
        return (reference_time - timedelta(days=days)).isoformat()

    indicators: list[ThreatIndicator] = [
        # ======================================================================
        # CATEGORY 1: External Cyber Threat Intelligence (lambda = 0.05 / day)
        # ======================================================================
        ThreatIndicator(
            asset_id="AST-001",
            category=IndicatorCategory.EXTERNAL_CTI.value,
            indicator_type="CTI_BOTNET_SCAN_MATCH",
            identifier_key="OTX-FEED-185.220.101.44",
            title="Inbound credential-stuffing & web exploit probes from known Tor/botnet node",
            base_severity_s0=0.72,
            confidence_c=0.85,
            is_cisa_kev=False,
            epss_score=0.28,
            control_factor_gamma=0.70,
            decay_lambda=LAMBDA_TEMPORARY_CTI,
            remediation_effort_e=1.5,
            observed_at_t0=days_ago(4.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-002",
            category=IndicatorCategory.EXTERNAL_CTI.value,
            indicator_type="CTI_MALICIOUS_IP_BRUTEFORCE",
            identifier_key="ABUSEIPDB-91.214.124.88",
            title="High-frequency VPN IKE/SSL authentication spraying from ransomware affiliate IP",
            base_severity_s0=0.80,
            confidence_c=0.90,
            is_cisa_kev=False,
            epss_score=0.35,
            control_factor_gamma=0.80,
            decay_lambda=LAMBDA_TEMPORARY_CTI,
            remediation_effort_e=1.0,
            observed_at_t0=days_ago(2.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-005",
            category=IndicatorCategory.EXTERNAL_CTI.value,
            indicator_type="CTI_DNS_C2_BEACON",
            identifier_key="URLHAUS-C2-UPDATER-CDN.TOP",
            title="Outbound DNS query matching known infostealer staging domain (14 days old)",
            base_severity_s0=0.78,
            confidence_c=0.75,
            is_cisa_kev=False,
            epss_score=0.15,
            control_factor_gamma=0.60,
            decay_lambda=LAMBDA_TEMPORARY_CTI,
            remediation_effort_e=2.5,
            observed_at_t0=days_ago(14.0),
            data_source=DataSource.SIMULATED.value,
        ),

        # ======================================================================
        # CATEGORY 2: Perimeter and Attack Surface Exposure (lambda = 0.0)
        # ======================================================================
        ThreatIndicator(
            asset_id="AST-001",
            category=IndicatorCategory.PERIMETER_EXPOSURE.value,
            indicator_type="OPEN_ADMIN_PORT",
            identifier_key="TCP-PORT-8443-ADMIN-CONSOLE",
            title="Staging management console exposed directly to the public internet without IP ACL",
            base_severity_s0=0.75,
            confidence_c=0.95,
            is_cisa_kev=False,
            epss_score=0.22,
            control_factor_gamma=0.90,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=2.0,
            observed_at_t0=days_ago(18.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-002",
            category=IndicatorCategory.PERIMETER_EXPOSURE.value,
            indicator_type="WEAK_TLS_CIPHER_SUITE",
            identifier_key="TLS-1.0-1.1-ENABLED-WAN",
            title="Legacy TLS 1.0/1.1 protocols and CBC ciphers enabled on external VPN interface",
            base_severity_s0=0.55,
            confidence_c=1.00,
            is_cisa_kev=False,
            epss_score=0.08,
            control_factor_gamma=1.00,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=1.5,
            observed_at_t0=days_ago(30.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-006",
            category=IndicatorCategory.PERIMETER_EXPOSURE.value,
            indicator_type="LEGACY_AUTH_PROTOCOL_EXPOSED",
            identifier_key="IMAP-POP3-BASIC-AUTH-ENABLED",
            title="Legacy basic authentication protocols (IMAP/POP3/SMTP) exposed on cloud tenant",
            base_severity_s0=0.70,
            confidence_c=0.95,
            is_cisa_kev=False,
            epss_score=0.25,
            control_factor_gamma=0.85,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=2.0,
            observed_at_t0=days_ago(25.0),
            data_source=DataSource.SIMULATED.value,
        ),

        # ======================================================================
        # CATEGORY 3: Endpoint Configuration and Patch Indicators (lambda = 0.0)
        # ======================================================================
        ThreatIndicator(
            asset_id="AST-002",
            category=IndicatorCategory.ENDPOINT_PATCH.value,
            indicator_type="CVE_VULNERABILITY",
            identifier_key="CVE-2024-21762",
            title="Critical out-of-bounds write RCE vulnerability in SSL VPN appliance (CISA KEV)",
            base_severity_s0=0.98,
            confidence_c=0.95,
            is_cisa_kev=True,
            epss_score=0.94,
            control_factor_gamma=0.85,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=3.0,
            observed_at_t0=days_ago(10.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-001",
            category=IndicatorCategory.ENDPOINT_PATCH.value,
            indicator_type="CVE_VULNERABILITY",
            identifier_key="CVE-2023-44487",
            title="HTTP/2 Rapid Reset DoS & resource exhaustion vulnerability on unpatched Nginx reverse proxy",
            base_severity_s0=0.75,
            confidence_c=0.90,
            is_cisa_kev=True,
            epss_score=0.78,
            control_factor_gamma=0.65,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=2.5,
            observed_at_t0=days_ago(21.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-003",
            category=IndicatorCategory.ENDPOINT_PATCH.value,
            indicator_type="ENDPOINT_MISCONFIGURATION",
            identifier_key="SMBV1-AND-UNSIGNED-LDAP",
            title="Unsigned LDAP binds and legacy SMB signing disabled on Domain Controller",
            base_severity_s0=0.82,
            confidence_c=0.95,
            is_cisa_kev=False,
            epss_score=0.31,
            control_factor_gamma=0.75,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=3.5,
            observed_at_t0=days_ago(40.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-004",
            category=IndicatorCategory.ENDPOINT_PATCH.value,
            indicator_type="CVE_VULNERABILITY",
            identifier_key="CVE-2024-0985",
            title="PostgreSQL non-superuser privilege escalation via REFRESH MATERIALIZED VIEW CONCURRENTLY",
            base_severity_s0=0.80,
            confidence_c=0.90,
            is_cisa_kev=False,
            epss_score=0.12,
            control_factor_gamma=0.60,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=4.0,
            observed_at_t0=days_ago(15.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-005",
            category=IndicatorCategory.ENDPOINT_PATCH.value,
            indicator_type="EDR_TAMPER_PROTECTION_OFF",
            identifier_key="DEFENDER-TAMPER-DISABLED-WS04",
            title="Endpoint Detection & Response (EDR) real-time tamper protection disabled on Finance PC",
            base_severity_s0=0.68,
            confidence_c=1.00,
            is_cisa_kev=False,
            epss_score=0.05,
            control_factor_gamma=0.90,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=1.0,
            observed_at_t0=days_ago(7.0),
            data_source=DataSource.SIMULATED.value,
        ),

        # ======================================================================
        # CATEGORY 4: Identity and Authentication Hygiene (lambda = 0.0)
        # ======================================================================
        ThreatIndicator(
            asset_id="AST-006",
            category=IndicatorCategory.IDENTITY_AUTH.value,
            indicator_type="MISSING_MFA_PRIVILEGED",
            identifier_key="MFA-DISABLED-GLOBAL-ADMIN-02",
            title="Multi-Factor Authentication (MFA) not enforced on backup Global Administrator account",
            base_severity_s0=0.95,
            confidence_c=1.00,
            is_cisa_kev=False,
            epss_score=0.45,
            control_factor_gamma=1.00,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=1.0,
            observed_at_t0=days_ago(12.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-003",
            category=IndicatorCategory.IDENTITY_AUTH.value,
            indicator_type="DORMANT_DOMAIN_ADMIN",
            identifier_key="AD-SVC-LEGACY-BACKUP-ADMIN",
            title="Dormant Domain Admin service account with non-expiring password (>365 days old)",
            base_severity_s0=0.78,
            confidence_c=0.95,
            is_cisa_kev=False,
            epss_score=0.22,
            control_factor_gamma=0.80,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=1.5,
            observed_at_t0=days_ago(45.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-004",
            category=IndicatorCategory.IDENTITY_AUTH.value,
            indicator_type="SHARED_DB_SUPERUSER",
            identifier_key="POSTGRES-SHARED-SA-CREDENTIALS",
            title="Shared database superuser credentials used across multiple application microservices",
            base_severity_s0=0.65,
            confidence_c=0.90,
            is_cisa_kev=False,
            epss_score=0.10,
            control_factor_gamma=0.70,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=3.0,
            observed_at_t0=days_ago(20.0),
            data_source=DataSource.SIMULATED.value,
        ),

        # ======================================================================
        # INTENTIONAL DUPLICATES TO DEMONSTRATE SHA-256 DEDUPLICATION ENGINE
        # ======================================================================
        ThreatIndicator(
            asset_id="AST-002",
            category=IndicatorCategory.ENDPOINT_PATCH.value,
            indicator_type="CVE_VULNERABILITY",
            identifier_key="CVE-2024-21762",
            title="Duplicate vulnerability scan import: CVE-2024-21762 on Edge VPN Appliance",
            base_severity_s0=0.98,
            confidence_c=0.95,
            is_cisa_kev=True,
            epss_score=0.94,
            control_factor_gamma=0.85,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=3.0,
            observed_at_t0=days_ago(1.0),
            data_source=DataSource.SIMULATED.value,
        ),
        ThreatIndicator(
            asset_id="AST-006",
            category=IndicatorCategory.IDENTITY_AUTH.value,
            indicator_type="MISSING_MFA_PRIVILEGED",
            identifier_key="MFA-DISABLED-GLOBAL-ADMIN-02",
            title="Duplicate identity audit import: Missing MFA on backup Global Admin",
            base_severity_s0=0.95,
            confidence_c=1.00,
            is_cisa_kev=False,
            epss_score=0.45,
            control_factor_gamma=1.00,
            decay_lambda=LAMBDA_PERSISTENT,
            remediation_effort_e=1.0,
            observed_at_t0=days_ago(1.0),
            data_source=DataSource.SIMULATED.value,
        ),
    ]
    return indicators


def generate_csv_templates() -> None:
    """Create downloadable CSV templates in `data/templates/` for real SME data uploads."""
    ensure_directories()
    assets_csv = TEMPLATE_DIR / "assets_template.csv"
    indicators_csv = TEMPLATE_DIR / "indicators_template.csv"

    with assets_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "asset_id",
                "asset_name",
                "asset_type",
                "criticality_score",
                "is_internet_facing",
                "owner_department",
                "ip_or_hostname",
            ]
        )
        writer.writerow(
            [
                "REAL-AST-01",
                "Production Web Server",
                "Server",
                5,
                1,
                "IT Operations",
                "198.51.100.15",
            ]
        )

    with indicators_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "asset_id",
                "category",
                "indicator_type",
                "identifier_key",
                "title",
                "base_severity_s0",
                "confidence_c",
                "is_cisa_kev",
                "epss_score",
                "control_factor_gamma",
                "remediation_effort_e",
                "observed_at_t0",
            ]
        )
        writer.writerow(
            [
                "REAL-AST-01",
                IndicatorCategory.ENDPOINT_PATCH.value,
                "CVE_VULNERABILITY",
                "CVE-2024-3094",
                "Critical SSHD library vulnerability",
                0.95,
                0.90,
                1,
                0.88,
                0.80,
                2.0,
                datetime.now(timezone.utc).isoformat(),
            ]
        )


def seed_simulated_sme_environment(
    db: DatabaseManager,
    reset_existing_simulated: bool = False,
    reference_time: datetime | None = None,
) -> dict[str, Any]:
    """
    Populate the SQLite database with the synthetic SME dataset.
    Returns statistics on assets created, unique indicators inserted, and
    duplicate indicators suppressed by SHA-256 deduplication.
    """
    generate_csv_templates()
    ref_time = reference_time or datetime.now(timezone.utc)

    if reset_existing_simulated:
        db.clear_data_by_source(DataSource.SIMULATED.value)

    existing_assets = db.get_assets(data_source=DataSource.SIMULATED.value)
    if existing_assets and not reset_existing_simulated:
        open_inds = db.get_indicators(
            data_source=DataSource.SIMULATED.value, status="OPEN"
        )
        dedup_logs = db.get_deduplication_logs(data_source=DataSource.SIMULATED.value)
        return {
            "seeded_now": False,
            "assets_count": len(existing_assets),
            "inserted_indicators": len(open_inds),
            "duplicates_suppressed": len(dedup_logs),
        }

    assets = build_synthetic_sme_assets(ref_time)
    for asset in assets:
        db.upsert_asset(asset)

    indicators = build_synthetic_sme_indicators(ref_time)
    inserted_count = 0
    duplicate_count = 0

    for indicator in indicators:
        was_inserted, _ = db.insert_indicator_deduplicated(indicator)
        if was_inserted:
            inserted_count += 1
        else:
            duplicate_count += 1

    return {
        "seeded_now": True,
        "assets_count": len(assets),
        "inserted_indicators": inserted_count,
        "duplicates_suppressed": duplicate_count,
    }
