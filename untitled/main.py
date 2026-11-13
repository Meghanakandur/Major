"""
main.py
Complete Entry Point for the Lightweight Cybersecurity Risk Scoring System for SMEs:
- 8-Page Streamlit Dashboard (`streamlit run main.py`)
- Deterministic CLI Verification & Worked Examples (`python3 main.py --verify`)
- JSON API Bridge (`python3 main.py --api ...`)

Compatible with Python 3.11+.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import sys
from typing import Any

from config import (
    APP_TITLE,
    DataSource,
    classify_risk_score,
)
from database import DatabaseManager
from engine.classifier import classify_score_with_guidance
from engine.prioritiser import (
    compute_asset_remediation_priorities,
    rank_system_remediation_plan,
)
from engine.risk_calculator import (
    evaluate_single_asset,
    evaluate_system_portfolio,
)
from engine.worked_examples import run_all_worked_examples
from models import (
    Asset,
    AssetRiskResult,
    RemediationPriorityItem,
    SystemRiskSummary,
    ThreatIndicator,
)
from sample_data import seed_simulated_sme_environment


# ==============================================================================
# 1. UNIFIED PORTFOLIO EVALUATION ORCHESTRATOR
# ==============================================================================
def compute_single_asset_risk(
    asset: Asset,
    weight_w_i: float,
    indicators: list[ThreatIndicator],
    evaluation_time_t: datetime,
) -> AssetRiskResult:
    """Delegate single-asset risk calculation to `engine.risk_calculator`."""
    return evaluate_single_asset(
        asset=asset,
        weight_w_i=weight_w_i,
        indicators=indicators,
        evaluation_time_t=evaluation_time_t,
    )


def evaluate_sme_system_risk(
    db: DatabaseManager,
    data_source: str = DataSource.SIMULATED.value,
    evaluation_time_t: datetime | None = None,
) -> SystemRiskSummary:
    """
    Execute the complete end-to-end mathematical pipeline via `engine/`:
    1. Fetch assets and open indicators for `data_source`.
    2. Compute criticality weights w_i, temporal decay D(t,t0), context multiplier Phi_ik,
       effective severity S(I_ik,t), individual asset risk R_i(t), and overall system risk R_sys.
    3. Compute counterfactual leave-one-out R_i(-k) and Remediation Priority Index (RPI).
    """
    eval_t = evaluation_time_t or datetime.now(timezone.utc)
    assets = db.get_assets(data_source=data_source)
    open_indicators = db.get_indicators(data_source=data_source, status="OPEN")

    if not assets:
        return SystemRiskSummary(
            evaluated_at=eval_t.isoformat(),
            data_source_filter=data_source,
            system_risk_r_sys=0.0,
            system_risk_tier=classify_risk_score(0.0),
            max_asset_risk=0.0,
            weighted_mean_asset_risk=0.0,
            total_assets=0,
            total_open_indicators=0,
            asset_results=[],
            remediation_plan=[],
        )

    asset_results, r_sys, max_r_i, weighted_mean_r_i = evaluate_system_portfolio(
        assets=assets,
        open_indicators=open_indicators,
        evaluation_time_t=eval_t,
    )

    inds_by_asset: dict[str, list[ThreatIndicator]] = {a.asset_id: [] for a in assets}
    for ind in open_indicators:
        if ind.asset_id in inds_by_asset:
            inds_by_asset[ind.asset_id].append(ind)

    unranked_remediation: list[RemediationPriorityItem] = []
    for res_i in asset_results:
        asset_inds = inds_by_asset.get(res_i.asset.asset_id, [])
        unranked_remediation.extend(
            compute_asset_remediation_priorities(
                asset=res_i.asset,
                weight_w_i=res_i.weight_w_i,
                asset_indicators=asset_inds,
                current_asset_risk_r_i=res_i.risk_score_r_i,
                evaluation_time_t=eval_t,
            )
        )

    ranked_remediation = rank_system_remediation_plan(unranked_remediation)

    return SystemRiskSummary(
        evaluated_at=eval_t.isoformat(),
        data_source_filter=data_source,
        system_risk_r_sys=r_sys,
        system_risk_tier=classify_risk_score(r_sys),
        max_asset_risk=max_r_i,
        weighted_mean_asset_risk=weighted_mean_r_i,
        total_assets=len(asset_results),
        total_open_indicators=len(open_indicators),
        asset_results=asset_results,
        remediation_plan=ranked_remediation,
    )


# ==============================================================================
# 2. COMMAND-LINE VERIFICATION MODE (`python3 main.py --verify`)
# ==============================================================================
def run_cli_verification() -> None:
    """
    Initialize database, seed synthetic SME dataset, execute mathematical engine,
    verify all 5 worked numerical examples, and print a structured verification report.
    """
    print("=" * 86)
    print(f"{APP_TITLE}")
    print("Full Verification: SQLite Schema, SHA-256 Deduplication, Math Engine & Worked Examples")
    print("=" * 86)

    db = DatabaseManager()
    seed_stats = seed_simulated_sme_environment(db, reset_existing_simulated=True)

    print(
        f"[Database Seeded] Mode: SIMULATED | Assets: {seed_stats['assets_count']} | "
        f"Unique Indicators Inserted: {seed_stats['inserted_indicators']} | "
        f"Duplicate Collisions Suppressed (SHA-256): {seed_stats['duplicates_suppressed']}"
    )

    summary = evaluate_sme_system_risk(db, data_source=DataSource.SIMULATED.value)
    db.save_risk_snapshot(summary)

    print("-" * 86)
    print(
        f"SYSTEM RISK (R_sys) : {summary.system_risk_r_sys:.2f} / 100.00 "
        f"[{summary.system_risk_tier.value.upper()} RISK]"
    )
    print(
        f"Formula Breakdown   : 0.65 * max(R_i) [{summary.max_asset_risk:.2f}] + "
        f"0.35 * sum(w_i * R_i) [{summary.weighted_mean_asset_risk:.2f}]"
    )
    print("-" * 86)
    print("FIVE WORKED NUMERICAL EXAMPLES VERIFICATION:")
    for ex in run_all_worked_examples():
        status_str = "PASS (EXACT MATCH)" if ex.verified_exact_match else "FAIL"
        print(f"  Example #{ex.example_number}: {ex.title:<62} [{status_str}]")
    print("=" * 86)


# ==============================================================================
# 3. 8-PAGE STREAMLIT DASHBOARD (`streamlit run main.py`)
# ==============================================================================
def run_streamlit_app() -> None:
    """Render the complete 8-page Streamlit university major-project dashboard."""
    import streamlit as st
    from ui.pages import (
        render_page_1_home_overview,
        render_page_2_asset_management,
        render_page_3_cybersecurity_indicators,
        render_page_4_risk_assessment,
        render_page_5_risk_visualisation,
        render_page_6_remediation_recommendations,
        render_page_7_data_import,
        render_page_8_system_settings,
    )

    st.set_page_config(
        page_title="SME Cyber Risk Scoring System",
        page_icon="🛡️",
        layout="wide",
    )

    db = DatabaseManager()
    seed_simulated_sme_environment(db, reset_existing_simulated=False)

    st.sidebar.title("SME Cyber Risk Scorer")
    st.sidebar.caption("Lightweight Cybersecurity Risk Scoring System Using Threat Indicators")

    pages = [
        "1. Home / Overview",
        "2. SME Asset Management",
        "3. Cybersecurity Indicators",
        "4. Risk Assessment",
        "5. Risk Visualisation",
        "6. Remediation Recommendations",
        "7. Data Import",
        "8. System Settings",
    ]
    selected_page = st.sidebar.radio("Navigation", options=pages, index=0)

    st.sidebar.divider()
    selected_source = st.sidebar.radio(
        "Dataset Mode",
        options=[DataSource.SIMULATED.value, DataSource.REAL.value],
        index=0,
        help="Separates synthetic demonstration data from real uploaded SME data.",
    )

    days_offset = st.sidebar.slider(
        "Evaluation Horizon (t + Δ days)",
        min_value=0,
        max_value=60,
        value=0,
        step=1,
        help="Fast-forward evaluation time t to observe exponential decay D(t,t0) on Category 1 CTI indicators (lambda=0.05) vs persistent vulnerabilities (lambda=0).",
    )

    eval_time = datetime.now(timezone.utc) + timedelta(days=float(days_offset))
    summary = evaluate_sme_system_risk(
        db=db, data_source=selected_source, evaluation_time_t=eval_time
    )

    if selected_page == pages[0]:
        render_page_1_home_overview(summary)
    elif selected_page == pages[1]:
        render_page_2_asset_management(db, summary, selected_source)
    elif selected_page == pages[2]:
        render_page_3_cybersecurity_indicators(db, summary, selected_source)
    elif selected_page == pages[3]:
        render_page_4_risk_assessment(summary)
    elif selected_page == pages[4]:
        render_page_5_risk_visualisation(summary)
    elif selected_page == pages[5]:
        render_page_6_remediation_recommendations(db, summary, selected_source)
    elif selected_page == pages[6]:
        render_page_7_data_import(db, selected_source)
    elif selected_page == pages[7]:
        render_page_8_system_settings(db, selected_source)


# ==============================================================================
# 4. JSON API BRIDGE FOR LIVE WEB INTERFACE (`python3 main.py --api ...`)
# ==============================================================================
def run_api_bridge(action: str, payload_json: str) -> None:
    """
    Execute database and mathematical operations directly against SQLite (`risk_scoring.db`)
    and emit deterministic JSON to stdout for the live web preview server.
    """
    db = DatabaseManager()
    seed_simulated_sme_environment(db, reset_existing_simulated=False)
    params: dict[str, Any] = json.loads(payload_json) if payload_json else {}

    if action == "evaluate":
        from engine.remediation_advisor import (
            generate_automated_remediation_recommendations,
        )

        data_source = params.get("data_source", DataSource.SIMULATED.value)
        days_offset = float(params.get("days_offset", 0.0))
        effort_overrides = params.get("effort_overrides", None)
        use_stored_effort = bool(params.get("use_indicator_stored_effort", True))

        eval_t = datetime.now(timezone.utc) + timedelta(days=days_offset)
        summary = evaluate_sme_system_risk(
            db=db, data_source=data_source, evaluation_time_t=eval_t
        )
        band = classify_score_with_guidance(summary.system_risk_r_sys)
        assets = db.get_assets(data_source=data_source)
        open_raw = db.get_indicators(data_source=data_source, status="OPEN")
        remediated = db.get_indicators(data_source=data_source, status="REMEDIATED")
        dedup_logs = db.get_deduplication_logs(data_source=data_source)
        history = db.get_risk_history(data_source=data_source)
        worked_examples = [ex.to_dict() for ex in run_all_worked_examples()]

        automated_recs = [
            rec.to_dict()
            for rec in generate_automated_remediation_recommendations(
                assets=assets,
                open_indicators=open_raw,
                asset_results=summary.asset_results,
                current_system_risk_r_sys=summary.system_risk_r_sys,
                evaluation_time_t=eval_t,
                effort_overrides=effort_overrides if isinstance(effort_overrides, dict) else None,
                use_indicator_stored_effort=use_stored_effort,
            )
        ]

        output = {
            "ok": True,
            "summary": asdict(summary),
            "classification_guidance": band.to_dict(),
            "automated_recommendations": automated_recs,
            "open_raw_indicators": [asdict(r) for r in open_raw],
            "remediated_indicators": [asdict(r) for r in remediated],
            "deduplication_logs": dedup_logs,
            "risk_history": history,
            "worked_examples": worked_examples,
        }
        print(json.dumps(output))
        return

    if action == "reset_simulated":
        stats = seed_simulated_sme_environment(db, reset_existing_simulated=True)
        summary = evaluate_sme_system_risk(
            db=db, data_source=DataSource.SIMULATED.value
        )
        db.save_risk_snapshot(summary)
        print(json.dumps({"ok": True, "seed_stats": stats}))
        return

    if action == "clear_real":
        db.clear_data_by_source(DataSource.REAL.value)
        print(json.dumps({"ok": True}))
        return

    if action == "add_asset":
        asset = Asset(
            asset_id=str(params["asset_id"]),
            asset_name=str(params["asset_name"]),
            asset_type=str(params["asset_type"]),
            criticality_score=int(params["criticality_score"]),
            is_internet_facing=bool(params["is_internet_facing"]),
            owner_department=str(params.get("owner_department", "IT Operations")),
            ip_or_hostname=str(params.get("ip_or_hostname", "N/A")),
            data_source=str(params.get("data_source", DataSource.REAL.value)),
        )
        db.upsert_asset(asset)
        print(json.dumps({"ok": True, "asset": asdict(asset)}))
        return

    if action == "add_indicator":
        indicator = ThreatIndicator(
            asset_id=str(params["asset_id"]),
            category=str(params["category"]),
            indicator_type=str(params["indicator_type"]),
            identifier_key=str(params["identifier_key"]),
            title=str(params["title"]),
            base_severity_s0=float(params["base_severity_s0"]),
            confidence_c=float(params["confidence_c"]),
            is_cisa_kev=bool(params["is_cisa_kev"]),
            epss_score=float(params["epss_score"]),
            control_factor_gamma=float(params["control_factor_gamma"]),
            remediation_effort_e=float(params["remediation_effort_e"]),
            observed_at_t0=str(
                params.get("observed_at_t0", datetime.now(timezone.utc).isoformat())
            ),
            decay_lambda=(
                float(params["decay_lambda"])
                if params.get("decay_lambda") is not None
                else None
            ),
            data_source=str(params.get("data_source", DataSource.REAL.value)),
        )
        was_inserted, sha256_digest = db.insert_indicator_deduplicated(indicator)
        print(
            json.dumps(
                {
                    "ok": True,
                    "was_inserted": was_inserted,
                    "sha256_hash": sha256_digest,
                    "indicator": asdict(indicator),
                }
            )
        )
        return

    if action == "update_status":
        indicator_id = int(params["indicator_id"])
        new_status = str(params["status"])
        db.update_indicator_status(indicator_id, new_status)
        data_source = str(params.get("data_source", DataSource.SIMULATED.value))
        summary = evaluate_sme_system_risk(db=db, data_source=data_source)
        db.save_risk_snapshot(summary)
        print(
            json.dumps(
                {"ok": True, "indicator_id": indicator_id, "status": new_status}
            )
        )
        return

    if action == "import_csv":
        from collectors.ingestion_manager import IndicatorIngestionManager

        manager = IndicatorIngestionManager(
            db=db, enable_external_api=bool(params.get("enable_external_api", False))
        )
        report = manager.import_from_csv_text(
            csv_text=str(params.get("csv_text", "")),
            data_source=str(params.get("data_source", DataSource.REAL.value)),
            source_label=str(params.get("source_label", "CSV_UPLOAD")),
        )
        print(json.dumps({"ok": True, "report": report.to_dict()}))
        return

    if action == "import_json":
        from collectors.ingestion_manager import IndicatorIngestionManager

        manager = IndicatorIngestionManager(
            db=db, enable_external_api=bool(params.get("enable_external_api", False))
        )
        report = manager.import_from_json_text(
            json_text=str(params.get("json_text", "")),
            data_source=str(params.get("data_source", DataSource.REAL.value)),
            source_label=str(params.get("source_label", "JSON_UPLOAD")),
        )
        print(json.dumps({"ok": True, "report": report.to_dict()}))
        return

    if action == "collect_synthetic":
        from collectors.ingestion_manager import IndicatorIngestionManager

        manager = IndicatorIngestionManager(db=db, enable_external_api=False)
        report = manager.collect_all_synthetic_categories()
        print(json.dumps({"ok": True, "report": report.to_dict()}))
        return

    raise ValueError(f"Unsupported API action: {action}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lightweight Cybersecurity Risk Scoring System for SMEs"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run deterministic CLI verification of SQLite database, mathematical formulas, and 5 worked examples.",
    )
    parser.add_argument(
        "--api",
        type=str,
        default="",
        help="Execute JSON API action against SQLite and math engine.",
    )
    parser.add_argument(
        "--payload",
        type=str,
        default="{}",
        help="JSON payload string for --api mode.",
    )
    args, _ = parser.parse_known_args()

    if args.verify:
        run_cli_verification()
    elif args.api:
        try:
            run_api_bridge(args.api, args.payload)
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            sys.exit(1)
    else:
        run_streamlit_app()
