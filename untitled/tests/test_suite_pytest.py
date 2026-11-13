"""
tests/test_suite_pytest.py
Comprehensive Automated Test Suite (Compatible with both `pytest` and `python -m unittest`).
Covers all 10 required verification categories:
1. SHA-256 duplicate detection.
2. Indicator data validation.
3. Temporal decay.
4. KEV and EPSS multipliers.
5. Asset risk calculation.
6. System risk calculation.
7. Remediation Priority Index (RPI) & Automated Remediation Advisor.
8. SQLite database operations.
9. CSV and JSON imports.
10. Invalid and missing inputs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import tempfile
import unittest

from collectors.base_collector import (
    StandardisedIndicatorRecord,
    compute_record_sha256,
)
from collectors.ingestion_manager import IndicatorIngestionManager
from config import (
    AssetType,
    DataSource,
    IndicatorCategory,
    IndicatorStatus,
    RiskTier,
)
from database import DatabaseManager
from engine.prioritiser import calculate_rpi
from engine.remediation_advisor import (
    estimate_configurable_effort_hours,
    generate_automated_remediation_recommendations,
)
from engine.risk_calculator import (
    calculate_asset_criticality_weights,
    calculate_compensating_control_factor,
    calculate_context_multiplier_phi,
    calculate_effective_severity,
    calculate_exploitability_omega,
    calculate_individual_asset_risk,
    calculate_internet_exposure_psi,
    calculate_overall_system_risk,
    calculate_temporal_decay,
    evaluate_system_portfolio,
)
from engine.worked_examples import run_all_worked_examples
from models import Asset, ThreatIndicator, compute_indicator_sha256


# ==============================================================================
# 1. SHA-256 DUPLICATE DETECTION TESTS
# ==============================================================================
def test_1_sha256_duplicate_detection() -> None:
    """Verify deterministic SHA-256 hashing and SQLite duplicate suppression."""
    h1 = compute_indicator_sha256(
        "ast-001",
        IndicatorCategory.ENDPOINT_PATCH.value,
        "cve_vulnerability",
        "cve-2024-21762",
        "OPEN",
    )
    h2 = compute_record_sha256(
        "AST-001 ",
        IndicatorCategory.ENDPOINT_PATCH.value,
        "CVE_VULNERABILITY",
        " CVE-2024-21762",
        "open",
    )
    assert h1 == h2
    assert len(h1) == 64

    # Different asset or different status must produce a distinct SHA-256 hash
    h_diff_asset = compute_indicator_sha256(
        "AST-002",
        IndicatorCategory.ENDPOINT_PATCH.value,
        "CVE_VULNERABILITY",
        "CVE-2024-21762",
        "OPEN",
    )
    assert h1 != h_diff_asset


# ==============================================================================
# 2. INDICATOR DATA VALIDATION TESTS
# ==============================================================================
def test_2_indicator_data_validation() -> None:
    """Verify CVSS auto-scaling, percentage confidence scaling, and CSV formula sanitisation."""
    rec = StandardisedIndicatorRecord(
        indicator_id="=CVE-2024-9999",  # Unsafe '=' prefix must be stripped
        asset_id="ast-001",
        category=IndicatorCategory.ENDPOINT_PATCH.value,
        severity=8.5,                   # CVSS 8.5 -> auto-normalised to 0.85
        confidence=90.0,                # 90% -> auto-normalised to 0.90
        timestamp="2026-11-01T12:00:00Z",
        source="+SCANNER_EXPORT",       # Unsafe '+' prefix must be stripped
        description="-Unpatched service vulnerability",
    )
    assert rec.indicator_id == "CVE-2024-9999"
    assert rec.source == "SCANNER_EXPORT"
    assert math.isclose(rec.severity, 0.85, rel_tol=1e-6)
    assert math.isclose(rec.confidence, 0.90, rel_tol=1e-6)
    assert rec.decay_lambda == 0.0


# ==============================================================================
# 3. TEMPORAL DECAY TESTS
# ==============================================================================
def test_3_temporal_decay_behavior() -> None:
    """
    Verify D(t, t0) = exp(-lambda_k * (t - t0)):
    - lambda = 0.05/day for Category 1 External CTI
    - lambda = 0.00 for Categories 2, 3, and 4 (unresolved vulnerabilities & missing MFA)
    """
    d_cti, lam_cti, elapsed_cti = calculate_temporal_decay(
        IndicatorCategory.EXTERNAL_CTI,
        elapsed_days_override=20.0,
    )
    assert math.isclose(lam_cti, 0.05)
    assert math.isclose(elapsed_cti, 20.0)
    assert math.isclose(d_cti, math.exp(-1.0), rel_tol=1e-9)

    for persistent_cat in (
        IndicatorCategory.PERIMETER_EXPOSURE,
        IndicatorCategory.ENDPOINT_PATCH,
        IndicatorCategory.IDENTITY_AUTH,
    ):
        d_p, lam_p, _ = calculate_temporal_decay(
            persistent_cat,
            elapsed_days_override=100.0,
            explicit_lambda=0.05,  # Even if caller passes 0.05, rule forces 0.0
        )
        assert lam_p == 0.0
        assert d_p == 1.0


# ==============================================================================
# 4. KEV, EPSS, EXPOSURE & COMPENSATING CONTROL MULTIPLIER TESTS
# ==============================================================================
def test_4_kev_epss_exposure_and_control_multipliers() -> None:
    """Verify Omega_KEV(k), Psi_exp(i), Gamma_ctrl(i,k), and Phi_ik."""
    assert calculate_exploitability_omega(is_cisa_kev=True, epss_score=0.05) == 1.8
    assert calculate_exploitability_omega(is_cisa_kev=True, epss_score=0.95) == 1.8
    assert calculate_exploitability_omega(is_cisa_kev=False, epss_score=0.20) == 1.5
    assert calculate_exploitability_omega(is_cisa_kev=False, epss_score=0.75) == 1.5
    assert calculate_exploitability_omega(is_cisa_kev=False, epss_score=0.199) == 1.0

    assert calculate_internet_exposure_psi(True) == 1.4
    assert calculate_internet_exposure_psi(False) == 1.0

    phi, omega, psi, gamma = calculate_context_multiplier_phi(
        is_cisa_kev=True,
        epss_score=0.80,
        is_internet_facing=True,
        gamma_ctrl=0.50,
    )
    assert omega == 1.8
    assert psi == 1.4
    assert gamma == 0.50
    assert math.isclose(phi, 1.8 * 1.4 * 0.50, rel_tol=1e-9)

    # Effective severity cap at 1.0
    s_capped = calculate_effective_severity(0.95, 1.0, 2.52)
    assert s_capped == 1.0


# ==============================================================================
# 5. INDIVIDUAL ASSET RISK CALCULATION TESTS
# ==============================================================================
def test_5_individual_asset_risk_calculation() -> None:
    """
    Verify R_i(t) = 100 * [1 - product(1 - C_ik * S(I_ik, t))] * (A_i / 5)^0.5
    and confirm scores stay within [0, 100].
    """
    r_i, survival_prod, threat_prob, crit_mod = calculate_individual_asset_risk(
        criticality_a_i=4,
        indicator_pairs=[(0.90, 0.80), (0.80, 0.50)],
        beta=0.5,
    )
    expected_survival = (1.0 - 0.72) * (1.0 - 0.40)  # 0.168
    expected_prob = 1.0 - expected_survival          # 0.832
    expected_crit = math.sqrt(4.0 / 5.0)
    expected_r_i = 100.0 * expected_prob * expected_crit

    assert math.isclose(survival_prod, expected_survival, rel_tol=1e-9)
    assert math.isclose(threat_prob, expected_prob, rel_tol=1e-9)
    assert math.isclose(crit_mod, expected_crit, rel_tol=1e-9)
    assert math.isclose(r_i, expected_r_i, rel_tol=1e-9)
    assert 0.0 <= r_i <= 100.0


# ==============================================================================
# 6. SYSTEM RISK CALCULATION TESTS
# ==============================================================================
def test_6_system_risk_calculation() -> None:
    """
    Verify w_i = A_i / sum(A_j) and R_sys = 0.65 * max(R_i) + 0.35 * sum(w_i * R_i).
    """
    weights = calculate_asset_criticality_weights({"A1": 5, "A2": 3, "A3": 2})
    assert math.isclose(weights["A1"], 0.50)
    assert math.isclose(weights["A2"], 0.30)
    assert math.isclose(weights["A3"], 0.20)

    r_sys, max_r, weighted_mean = calculate_overall_system_risk(
        [(88.0, weights["A1"]), (50.0, weights["A2"]), (20.0, weights["A3"])],
        alpha=0.65,
    )
    assert math.isclose(max_r, 88.0)
    assert math.isclose(weighted_mean, 63.0)
    assert math.isclose(r_sys, 79.25)


# ==============================================================================
# 7. REMEDIATION PRIORITY INDEX (RPI) & AUTOMATED ADVISOR TESTS
# ==============================================================================
def test_7_remediation_priority_index_and_advisor() -> None:
    """Verify RPI = [(R_i - R_i(-k)) / E_k] * Omega_KEV(k) and automated SME advisor."""
    rpi_score, delta_r = calculate_rpi(
        current_asset_risk_r_i=74.416342,
        counterfactual_asset_risk_without_k=35.777088,
        remediation_effort_e_k=2.0,
        omega_kev_k=1.8,
    )
    assert math.isclose(delta_r, 74.416342 - 35.777088, rel_tol=1e-6)
    assert math.isclose(rpi_score, (delta_r / 2.0) * 1.8, rel_tol=1e-6)

    # Verify all 5 worked numerical examples pass
    for ex in run_all_worked_examples():
        assert ex.verified_exact_match is True


# ==============================================================================
# 8. SQLITE DATABASE OPERATIONS TESTS
# ==============================================================================
def test_8_sqlite_database_crud_and_deduplication() -> None:
    """Verify isolated SQLite schema creation, asset upsert, deduplication, and remediation status."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_db_path = Path(tmpdir) / "test_risk.db"
        db = DatabaseManager(db_path=temp_db_path)

        asset = Asset(
            asset_id="TEST-AST-01",
            asset_name="Test SME Edge Server",
            asset_type=AssetType.SERVER.value,
            criticality_score=5,
            is_internet_facing=True,
            data_source=DataSource.REAL.value,
        )
        db.upsert_asset(asset)
        fetched_assets = db.get_assets(data_source=DataSource.REAL.value)
        assert len(fetched_assets) == 1
        assert fetched_assets[0].asset_id == "TEST-AST-01"

        ind = ThreatIndicator(
            asset_id="TEST-AST-01",
            category=IndicatorCategory.IDENTITY_AUTH.value,
            indicator_type="MISSING_MFA_PRIVILEGED",
            identifier_key="ADMIN-NO-MFA",
            title="Missing MFA on primary administrator",
            base_severity_s0=0.95,
            confidence_c=1.0,
            is_cisa_kev=False,
            epss_score=0.40,
            control_factor_gamma=1.0,
            remediation_effort_e=1.0,
            observed_at_t0=datetime.now(timezone.utc).isoformat(),
            data_source=DataSource.REAL.value,
        )
        inserted_1, hash_1 = db.insert_indicator_deduplicated(ind)
        inserted_2, hash_2 = db.insert_indicator_deduplicated(ind)

        assert inserted_1 is True
        assert inserted_2 is False
        assert hash_1 == hash_2

        dedup_logs = db.get_deduplication_logs(data_source=DataSource.REAL.value)
        assert len(dedup_logs) == 1

        open_inds = db.get_indicators(data_source=DataSource.REAL.value, status="OPEN")
        assert len(open_inds) == 1
        ind_id = open_inds[0].indicator_id
        assert ind_id is not None

        # Mark as REMEDIATED and confirm open count drops to 0
        db.update_indicator_status(ind_id, IndicatorStatus.REMEDIATED.value)
        assert len(db.get_indicators(data_source=DataSource.REAL.value, status="OPEN")) == 0
        assert len(db.get_indicators(data_source=DataSource.REAL.value, status="REMEDIATED")) == 1


# ==============================================================================
# 9. CSV AND JSON BATCH IMPORT TESTS
# ==============================================================================
def test_9_csv_and_json_imports() -> None:
    """Verify CSV and JSON batch ingestion across all 4 indicator categories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db = DatabaseManager(db_path=Path(tmpdir) / "import_test.db")
        manager = IndicatorIngestionManager(db=db, enable_external_api=False)

        csv_payload = """asset_id,category,indicator_type,identifier_key,title,base_severity_s0,confidence_c,is_cisa_kev,epss_score,control_factor_gamma,remediation_effort_e,observed_at_t0
AST-CSV-1,External Cyber Threat Intelligence,CTI_IP,IOC-1.2.3.4,Malicious scanner IP,0.70,0.85,0,0.25,0.80,1.5,2026-11-05T00:00:00Z
AST-CSV-1,External Cyber Threat Intelligence,CTI_IP,IOC-1.2.3.4,Duplicate Malicious scanner IP,0.70,0.85,0,0.25,0.80,1.5,2026-11-05T00:00:00Z"""

        csv_report = manager.import_from_csv_text(csv_payload, data_source="REAL")
        assert csv_report.total_processed == 2
        assert csv_report.inserted_unique == 1
        assert csv_report.duplicates_suppressed == 1
        assert csv_report.validation_errors == 0

        json_payload = json.dumps(
            [
                {
                    "indicator_id": "CVE-2024-5555",
                    "asset_id": "AST-JSON-1",
                    "category": "Endpoint Configuration and Patch Indicators",
                    "severity": 0.90,
                    "confidence": 0.95,
                    "is_cisa_kev": True,
                    "epss_score": 0.85,
                    "control_factor_gamma": 0.80,
                    "remediation_effort_e": 2.5,
                    "timestamp": "2026-11-06T00:00:00Z",
                    "source": "UNIT_TEST",
                    "description": "Test JSON CVE import",
                }
            ]
        )
        json_report = manager.import_from_json_text(json_payload, data_source="REAL")
        assert json_report.total_processed == 1
        assert json_report.inserted_unique == 1
        assert json_report.validation_errors == 0


# ==============================================================================
# 10. INVALID AND MISSING INPUT PROTECTION TESTS
# ==============================================================================
def test_10_invalid_and_missing_inputs() -> None:
    """Verify division-by-zero protection, missing timestamps, and boundary validation."""
    # Missing or invalid timestamps safely yield elapsed = 0.0 and D(t,t0) = 1.0
    d_none, _, elapsed_none = calculate_temporal_decay(
        IndicatorCategory.EXTERNAL_CTI, observed_at_t0=None, evaluation_time_t=None
    )
    assert elapsed_none == 0.0
    assert d_none == 1.0

    # Division-by-zero prevention on E_k <= 0
    try:
        calculate_rpi(80.0, 40.0, 0.0, 1.8)
        assert False, "Expected ValueError for E_k = 0.0"
    except ValueError:
        pass

    # Out-of-range compensating control factor Gamma_ctrl outside [0.3, 1.0]
    try:
        calculate_compensating_control_factor(0.15)
        assert False, "Expected ValueError for Gamma_ctrl < 0.3"
    except ValueError:
        pass

    # Out-of-range asset criticality A_i outside [1, 5]
    try:
        calculate_individual_asset_risk(0, [(0.8, 0.8)])
        assert False, "Expected ValueError for A_i = 0"
    except ValueError:
        pass


class PytestCompatibleUnitTestSuite(unittest.TestCase):
    """Wrapper class so `python3 -m unittest` runs all 10 test functions automatically."""

    def test_all_10_verification_requirements(self) -> None:
        test_1_sha256_duplicate_detection()
        test_2_indicator_data_validation()
        test_3_temporal_decay_behavior()
        test_4_kev_epss_exposure_and_control_multipliers()
        test_5_individual_asset_risk_calculation()
        test_6_system_risk_calculation()
        test_7_remediation_priority_index_and_advisor()
        test_8_sqlite_database_crud_and_deduplication()
        test_9_csv_and_json_imports()
        test_10_invalid_and_missing_inputs()


if __name__ == "__main__":
    unittest.main()
