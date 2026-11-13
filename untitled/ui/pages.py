"""
ui/pages.py
Implements all 8 Streamlit pages for the university major project dashboard:
1. Home / Overview
2. SME Asset Management
3. Cybersecurity Indicators
4. Risk Assessment
5. Risk Visualisation
6. Remediation Recommendations
7. Data Import
8. System Settings

All views read and write live data from SQLite (`data/risk_scoring.db`) and use
real calculated scores from the mathematical risk engine (`engine/`).
Compatible with Python 3.11+.
"""

from __future__ import annotations

from datetime import datetime, timezone
import pandas as pd
import streamlit as st

from collectors.ingestion_manager import IndicatorIngestionManager
from config import (
    ALPHA_SYSTEM_RISK,
     AssetType,
    BETA_CRITICALITY_EXPONENT,
    GAMMA_CTRL_MAX,
    GAMMA_CTRL_MIN,
    IndicatorCategory,
    LAMBDA_PERSISTENT,
    LAMBDA_TEMPORARY_CTI,
    OMEGA_CISA_KEV,
    OMEGA_EPSS_DEFAULT,
    OMEGA_EPSS_HIGH,
    PSI_INTERNAL_ONLY,
    PSI_INTERNET_FACING,
    TEMPLATE_DIR,
)
from database import DatabaseManager
from engine.classifier import classify_score_with_guidance
from engine.worked_examples import run_all_worked_examples
from models import Asset, SystemRiskSummary, ThreatIndicator, parse_iso_timestamp
from sample_data import (
    SAMPLE_CSV_PAYLOAD_DEFAULT,
    SAMPLE_JSON_PAYLOAD_DEFAULT,
    seed_simulated_sme_environment,
)
from ui.charts import (
    build_asset_criticality_bubble_chart,
    build_asset_risk_bar_chart,
    build_category_distribution_chart,
    build_rpi_pareto_chart,
    build_system_risk_gauge,
    build_temporal_decay_simulation_chart,
)


# ==============================================================================
# PAGE 1: HOME / OVERVIEW
# ==============================================================================
def render_page_1_home_overview(summary: SystemRiskSummary) -> None:
    st.header("1. Home / Executive Overview")
    band = classify_score_with_guidance(summary.system_risk_r_sys)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric(
        "Overall System Risk (R_sys)",
        f"{summary.system_risk_r_sys:.2f} / 100",
        delta=f"{band.tier.value} Risk",
        delta_color="inverse",
    )
    col2.metric("Max Asset Risk max(R_i)", f"{summary.max_asset_risk:.2f}")
    col3.metric(
        "Weighted Mean Σ(w_i·R_i)", f"{summary.weighted_mean_asset_risk:.2f}"
    )
    col4.metric("Monitored SME Assets", f"{summary.total_assets}")
    col5.metric("Open Threat Indicators", f"{summary.total_open_indicators}")

    st.markdown(
        f"**Risk Classification Band:** `{band.tier.value} Risk` · "
        f"**Recommended SLA:** {band.sla_window} · "
        f"**Guidance:** {band.sme_guidance}"
    )

    if summary.total_assets == 0:
        st.warning("No assets found for the selected dataset mode.")
        return

    c1, c2 = st.columns([1, 1.35])
    with c1:
        st.plotly_chart(build_system_risk_gauge(summary), use_container_width=True)
    with c2:
        st.plotly_chart(build_asset_risk_bar_chart(summary), use_container_width=True)

    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Highest-Risk SME Assets")
        top_assets_df = pd.DataFrame(
            [
                {
                    "Asset ID": r.asset.asset_id,
                    "Asset Name": r.asset.asset_name,
                    "Criticality A_i": r.asset.criticality_score,
                    "Weight w_i": round(r.weight_w_i, 3),
                    "Exposure": "WAN (1.4x)" if r.asset.is_internet_facing else "LAN (1.0x)",
                    "Risk R_i(t)": round(r.risk_score_r_i, 2),
                    "Band": r.risk_tier.value,
                }
                for r in summary.asset_results
            ]
        )
        st.dataframe(top_assets_df, use_container_width=True, hide_index=True)

    with col_right:
        st.subheader("Most Important Cybersecurity Threats (Top RPI)")
        top_threats_df = pd.DataFrame(
            [
                {
                    "Rank": f"#{item.rank}",
                    "Asset": item.asset_id,
                    "Threat Key": item.identifier_key,
                    "Category": item.category,
                    "ΔR_i Drop": f"-{item.risk_reduction_delta:.2f}",
                    "RPI": round(item.rpi_score, 2),
                }
                for item in summary.remediation_plan[:6]
            ]
        )
        st.dataframe(top_threats_df, use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 2: SME ASSET MANAGEMENT
# ==============================================================================
def render_page_2_asset_management(
    db: DatabaseManager,
    summary: SystemRiskSummary,
    active_source: str,
) -> None:
    st.header("2. SME Asset Management")
    st.caption(
        "Manage the SME IT inventory, business criticality scores A_i ∈ {1..5}, and internet exposure flags Ψ_exp(i) ∈ {1.4, 1.0}."
    )

    if summary.asset_results:
        asset_df = pd.DataFrame(
            [
                {
                    "Asset ID": r.asset.asset_id,
                    "Asset Name": r.asset.asset_name,
                    "Type": r.asset.asset_type,
                    "Department": r.asset.owner_department,
                    "IP / Hostname": r.asset.ip_or_hostname,
                    "Criticality (A_i)": r.asset.criticality_score,
                    "Weight (w_i)": round(r.weight_w_i, 4),
                    "Exposure (Ψ_exp)": r.asset.exposure_factor_psi,
                    "(A_i/5)^0.5": round(r.criticality_modifier, 4),
                    "Open Indicators": r.open_indicator_count,
                    "Risk Score R_i(t)": round(r.risk_score_r_i, 2),
                    "Classification": r.risk_tier.value,
                }
                for r in summary.asset_results
            ]
        )
        st.dataframe(asset_df, use_container_width=True, hide_index=True)

    st.subheader("Register or Update SME Asset")
    with st.form("register_asset_form"):
        f_col1, f_col2, f_col3 = st.columns(3)
        asset_id = f_col1.text_input("Asset ID", value="AST-007")
        asset_name = f_col2.text_input(
            "Asset Name", value="Internal File & Backup NAS Server"
        )
        asset_type = f_col3.selectbox(
            "Asset Type", options=[t.value for t in AssetType]
        )

        f_col4, f_col5, f_col6 = st.columns(3)
        crit_score = f_col4.slider("Criticality Score A_i (1–5)", 1, 5, 4)
        dept = f_col5.text_input("Owner Department", value="IT Infrastructure")
        hostname = f_col6.text_input("IP or Hostname", value="10.10.5.50")

        is_internet = st.checkbox(
            "Internet-Facing Asset (Sets Exposure Multiplier Ψ_exp = 1.4 instead of 1.0)",
            value=False,
        )
        submitted = st.form_submit_button("Save Asset to SQLite")
        if submitted:
            try:
                new_asset = Asset(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_type=asset_type,
                    criticality_score=crit_score,
                    is_internet_facing=is_internet,
                    owner_department=dept,
                    ip_or_hostname=hostname,
                    data_source=active_source,
                )
                db.upsert_asset(new_asset)
                st.success(f"Saved asset {new_asset.asset_id} ({new_asset.asset_name}).")
                st.rerun()
            except Exception as exc:
                st.error(f"Validation error: {exc}")


# ==============================================================================
# PAGE 3: CYBERSECURITY INDICATORS (WITH MULTI-CRITERIA FILTERS)
# ==============================================================================
def render_page_3_cybersecurity_indicators(
    db: DatabaseManager,
    summary: SystemRiskSummary,
    active_source: str,
) -> None:
    st.header("3. Cybersecurity Indicators Explorer")
    st.caption(
        "Filter and inspect normalised, SHA-256 deduplicated indicators across Asset, Category, Effective Severity, and Observation Date."
    )

    all_raw_inds = db.get_indicators(data_source=active_source, status="OPEN")
    ind_lookup = {i.sha256_hash: i for i in all_raw_inds}

    # Filter Bar
    f1, f2, f3, f4 = st.columns(4)
    asset_options = ["ALL"] + [r.asset.asset_id for r in summary.asset_results]
    selected_asset = f1.selectbox("Filter by Asset", options=asset_options)

    cat_options = ["ALL"] + [c.value for c in IndicatorCategory]
    selected_cat = f2.selectbox("Filter by Category", options=cat_options)

    min_severity = f3.slider(
        "Minimum Effective Severity S(I_ik,t)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.05,
    )
    max_age_days = f4.slider(
        "Max Observation Age (t - t0 Days)",
        min_value=1,
        max_value=120,
        value=90,
        step=1,
    )

    search_text = st.text_input(
        "Search by CVE ID, Identifier Key, or Description", value=""
    )

    filtered_rows: list[dict[str, object]] = []
    for r in summary.asset_results:
        for d in r.evaluated_indicators:
            if selected_asset != "ALL" and d.asset_id != selected_asset:
                continue
            if selected_cat != "ALL" and d.category != selected_cat:
                continue
            if d.effective_severity_s < min_severity:
                continue
            if d.elapsed_days > max_age_days:
                continue
            if search_text.strip():
                q = search_text.strip().lower()
                if (
                    q not in d.identifier_key.lower()
                    and q not in d.title.lower()
                    and q not in d.asset_id.lower()
                ):
                    continue

            raw_obj = ind_lookup.get(d.sha256_hash)
            obs_date = raw_obj.observed_at_t0[:10] if raw_obj else "N/A"
            filtered_rows.append(
                {
                    "ID": d.indicator_id,
                    "Asset": d.asset_id,
                    "Category": d.category,
                    "Key / CVE": d.identifier_key,
                    "Description": d.title,
                    "Observed Date": obs_date,
                    "S0(k)": round(d.s0, 3),
                    "C_ik": round(d.confidence_c, 2),
                    "λ_k": d.decay_lambda,
                    "Age (d)": round(d.elapsed_days, 1),
                    "D(t,t0)": round(d.temporal_decay_d, 4),
                    "Ω_KEV": d.omega_kev,
                    "Ψ_exp": d.psi_exp,
                    "Γ_ctrl": d.gamma_ctrl,
                    "Φ_ik": round(d.context_phi, 3),
                    "Effective S(I_ik,t)": round(d.effective_severity_s, 4),
                    "SHA-256 Prefix": d.sha256_hash[:14] + "…",
                }
            )

    st.markdown(f"**Matching Open Indicators:** `{len(filtered_rows)}`")
    st.dataframe(pd.DataFrame(filtered_rows), use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 4: RISK ASSESSMENT & WORKED EXAMPLES
# ==============================================================================
def render_page_4_risk_assessment(summary: SystemRiskSummary) -> None:
    st.header("4. Mathematical Risk Assessment & Worked Examples")
    st.latex(
        r"S(I_{ik}, t) = \min\bigl(1.0,\; S_0(k)\cdot \exp(-\lambda_k(t-t_0))\cdot \Omega_{\text{KEV}}(k)\cdot \Psi_{\text{exp}}(i)\cdot \Gamma_{\text{ctrl}}(i,k)\bigr)"
    )
    st.latex(
        r"R_i(t) = 100 \times \left[1 - \prod_{k \in K_i}\bigl(1 - C_{ik}\cdot S(I_{ik},t)\bigr)\right]\times \left(\frac{A_i}{5}\right)^{0.5}, \quad R_{\text{sys}} = 0.65\max_i(R_i) + 0.35\sum_i w_i R_i"
    )

    if summary.asset_results:
        st.subheader("Live Asset Step-by-Step Mathematical Breakdown")
        asset_labels = {
            r.asset.asset_id: f"{r.asset.asset_id} — {r.asset.asset_name} (R_i = {r.risk_score_r_i:.2f})"
            for r in summary.asset_results
        }
        chosen_id = st.selectbox(
            "Select SME Asset to Inspect",
            options=list(asset_labels.keys()),
            format_func=lambda k: asset_labels[k],
        )
        chosen_res = next(
            r for r in summary.asset_results if r.asset.asset_id == chosen_id
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Criticality A_i", f"{chosen_res.asset.criticality_score} / 5")
        m2.metric("Weight w_i", f"{chosen_res.weight_w_i:.4f}")
        m3.metric("Survival Product Π", f"{chosen_res.survival_product:.4f}")
        m4.metric(
            "Asset Risk R_i(t)",
            f"{chosen_res.risk_score_r_i:.2f} ({chosen_res.risk_tier.value})",
        )

        trace_df = pd.DataFrame(
            [
                {
                    "Indicator Key": d.identifier_key,
                    "S0(k)": d.s0,
                    "λ_k": d.decay_lambda,
                    "t - t0 (d)": round(d.elapsed_days, 1),
                    "D(t,t0)": round(d.temporal_decay_d, 4),
                    "Ω_KEV": d.omega_kev,
                    "Ψ_exp": d.psi_exp,
                    "Γ_ctrl": d.gamma_ctrl,
                    "Φ_ik": round(d.context_phi, 4),
                    "S(I_ik,t)": round(d.effective_severity_s, 4),
                    "C_ik": d.confidence_c,
                    "1 - C_ik·S": round(d.survival_term, 4),
                }
                for d in chosen_res.evaluated_indicators
            ]
        )
        st.dataframe(trace_df, use_container_width=True, hide_index=True)

    st.subheader("Five Self-Verifying Worked Numerical Examples")
    examples = run_all_worked_examples()
    for ex in examples:
        with st.expander(
            f"Worked Example #{ex.example_number}: {ex.title} — Verified: {ex.verified_exact_match}",
            expanded=(ex.example_number == 1),
        ):
            st.write(ex.scenario_description)
            for step in ex.step_by_step_derivation:
                st.code(step, language="text")
            c_exp, c_eng = st.columns(2)
            c_exp.json(ex.expected_outputs)
            c_eng.json(ex.engine_outputs)


# ==============================================================================
# PAGE 5: RISK VISUALISATION
# ==============================================================================
def render_page_5_risk_visualisation(summary: SystemRiskSummary) -> None:
    st.header("5. Interactive Risk Visualisation Suite")
    if summary.total_assets == 0:
        st.info("No assets available to visualise.")
        return

    r1_col1, r1_col2 = st.columns(2)
    with r1_col1:
        st.plotly_chart(
            build_category_distribution_chart(summary), use_container_width=True
        )
    with r1_col2:
        st.plotly_chart(
            build_asset_criticality_bubble_chart(summary), use_container_width=True
        )

    r2_col1, r2_col2 = st.columns(2)
    with r2_col1:
        st.plotly_chart(build_rpi_pareto_chart(summary), use_container_width=True)
    with r2_col2:
        st.plotly_chart(
            build_temporal_decay_simulation_chart(), use_container_width=True
        )


# ==============================================================================
# PAGE 6: REMEDIATION RECOMMENDATIONS (AUTOMATED SME ADVISOR)
# ==============================================================================
def render_page_6_remediation_recommendations(
    db: DatabaseManager,
    summary: SystemRiskSummary,
    active_source: str,
) -> None:
    from engine.remediation_advisor import (
        generate_automated_remediation_recommendations,
    )

    st.header("6. Automated Cybersecurity Remediation Recommendation Engine")
    st.info(
        "**Projected vs. Verified Risk Accounting:** Counterfactual reductions (Projected ΔR_i and Projected R_sys) "
        "indicate estimated impact *if* an action is taken. Risk scores are only reduced after you click "
        "**Mark as Remediated** and the scoring engine recalculates live SQLite state."
    )
    st.latex(
        r"\text{RPI}_{ik} = \left[\frac{R_i - R_i(-k)}{E_k}\right] \times \Omega_{\text{KEV}}(k)"
    )

    with st.expander("Configurable SME Remediation Effort Assumptions (Hours E_k)", expanded=False):
        st.caption(
            "Override baseline effort assumptions (in hours) to see how remediation cost dynamically shifts RPI rankings."
        )
        use_custom_effort = st.checkbox(
            "Override Indicator Stored Effort with Category/Type Effort Assumptions",
            value=False,
        )
        ec1, ec2, ec3, ec4 = st.columns(4)
        eff_mfa = ec1.number_input("Missing Privileged MFA (h)", 0.25, 40.0, 1.0, 0.25)
        eff_cve = ec2.number_input("CVE Patch Deployment (h)", 0.25, 40.0, 3.0, 0.25)
        eff_perim = ec3.number_input("Firewall / Port Exposure Fix (h)", 0.25, 40.0, 2.0, 0.25)
        eff_cti = ec4.number_input("CTI Blocklist / Rule Tuning (h)", 0.25, 40.0, 1.5, 0.25)

        effort_overrides = (
            {
                "MISSING_MFA_PRIVILEGED": float(eff_mfa),
                "CVE_VULNERABILITY": float(eff_cve),
                "OPEN_ADMIN_PORT": float(eff_perim),
                "CTI_BOTNET_SCAN_MATCH": float(eff_cti),
                "CTI_MALICIOUS_IP_BRUTEFORCE": float(eff_cti),
            }
            if use_custom_effort
            else None
        )

    assets = db.get_assets(data_source=active_source)
    open_inds = db.get_indicators(data_source=active_source, status="OPEN")

    recommendations = generate_automated_remediation_recommendations(
        assets=assets,
        open_indicators=open_inds,
        asset_results=summary.asset_results,
        current_system_risk_r_sys=summary.system_risk_r_sys,
        effort_overrides=effort_overrides,
        use_indicator_stored_effort=not use_custom_effort,
    )

    if not recommendations:
        st.success("All open indicators have been remediated! Current recalculated risk is 0.00.")
    else:
        # Summary counts by urgency and finding type
        u_crit = sum(1 for r in recommendations if r.urgency_level == "Critical")
        u_high = sum(1 for r in recommendations if r.urgency_level == "High")
        u_med = sum(1 for r in recommendations if r.urgency_level == "Medium")
        u_low = sum(1 for r in recommendations if r.urgency_level == "Low")

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Critical Urgency Actions", f"{u_crit}")
        k2.metric("High Urgency Actions", f"{u_high}")
        k3.metric("Medium Urgency Actions", f"{u_med}")
        k4.metric("Low Urgency Actions", f"{u_low}")

        rpi_df = pd.DataFrame(
            [
                {
                    "Rank": f"#{rec.priority_rank}",
                    "Urgency": rec.urgency_level,
                    "Asset": f"{rec.asset_id} (A_i={rec.asset_criticality_a_i})",
                    "Finding Type": rec.finding_domain_label,
                    "Identifier": rec.identifier_key,
                    "Current R_i": rec.current_asset_risk_r_i,
                    "Projected R_i(-k)": rec.projected_asset_risk_after_fix,
                    "Projected ΔR_i": f"-{rec.projected_asset_risk_drop_delta:.2f}",
                    "Effort E_k (h)": rec.estimated_effort_hours_e_k,
                    "Ω_KEV": f"{rec.omega_kev_multiplier:.1f}x",
                    "RPI Score": rec.rpi_score,
                    "Recommendation": rec.recommendation_headline,
                }
                for rec in recommendations
            ]
        )
        st.dataframe(rpi_df, use_container_width=True, hide_index=True)

        st.subheader("Detailed Explainable Recommendations & Action Steps")
        for rec in recommendations:
            with st.expander(
                f"Rank #{rec.priority_rank} [{rec.urgency_level.upper()} URGENCY] — {rec.recommendation_headline} | RPI: {rec.rpi_score:.2f} | Effort: {rec.estimated_effort_hours_e_k}h",
                expanded=(rec.priority_rank <= 2),
            ):
                st.markdown(f"**Finding Classification:** {rec.finding_domain_label} (`{rec.category}`)")
                st.markdown(f"**Why This Recommendation Was Generated:** {rec.why_generated_explanation}")
                st.markdown("**Recommended Practical SME Actions:**")
                for step_idx, step_text in enumerate(rec.practical_action_steps, start=1):
                    st.markdown(f"{step_idx}. {step_text}")
                st.caption(rec.verification_status_note)
                if rec.indicator_id is not None:
                    if st.button(
                        f"Record Remediation & Recalculate Risk (#{rec.indicator_id} — {rec.identifier_key})",
                        key=f"rem_btn_{rec.indicator_id}",
                    ):
                        db.update_indicator_status(int(rec.indicator_id), "REMEDIATED")
                        st.success(
                            f"Recorded remediation for {rec.identifier_key}. Recalculating actual R_i(t) and R_sys..."
                        )
                        st.rerun()

    remediated_list = db.get_indicators(data_source=active_source, status="REMEDIATED")
    if remediated_list:
        st.subheader(f"Verified Completed Remediations ({len(remediated_list)})")
        st.success(
            f"The {len(remediated_list)} remediation(s) below have been recorded in SQLite and are reflected in the current recalculated System Risk R_sys = {summary.system_risk_r_sys:.2f}."
        )
        rem_df = pd.DataFrame(
            [
                {
                    "ID": ind.indicator_id,
                    "Asset": ind.asset_id,
                    "Category": ind.category,
                    "Identifier": ind.identifier_key,
                    "Title": ind.title,
                }
                for ind in remediated_list
            ]
        )
        st.dataframe(rem_df, use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 7: DATA IMPORT & SHA-256 DEDUPLICATION MONITOR
# ==============================================================================
def render_page_7_data_import(
    db: DatabaseManager,
    active_source: str,
) -> None:
    st.header("7. Data Import & SHA-256 Deduplication Pipeline")
    st.caption(
        "Import cybersecurity indicators via CSV or JSON. Duplicate records are automatically identified and blocked via SHA-256 hashing."
    )

    enable_api = st.checkbox(
        "Enable Optional Read-Only FIRST.org EPSS Enrichment (Safe fallback when offline)",
        value=False,
    )
    manager = IndicatorIngestionManager(db=db, enable_external_api=enable_api)

    tab_csv, tab_json, tab_dedup = st.tabs(
        ["CSV Batch Import", "JSON Batch Import", "SHA-256 Deduplication Audit Log"]
    )

    with tab_csv:
        uploaded_csv = st.file_uploader("Upload Indicators CSV File", type=["csv"])
        default_csv = (
            uploaded_csv.getvalue().decode("utf-8")
            if uploaded_csv is not None
            else SAMPLE_CSV_PAYLOAD_DEFAULT
        )
        csv_text = st.text_area("CSV Payload", value=default_csv, height=180)
        if st.button("Normalise & Ingest CSV Batch"):
            report = manager.import_from_csv_text(
                csv_text=csv_text,
                data_source=active_source,
                source_label="STREAMLIT_CSV_IMPORT",
            )
            st.success(
                f"Processed {report.total_processed} rows: {report.inserted_unique} unique inserted, "
                f"{report.duplicates_suppressed} SHA-256 duplicates blocked."
            )

    with tab_json:
        uploaded_json = st.file_uploader("Upload Indicators JSON File", type=["json"])
        default_json = (
            uploaded_json.getvalue().decode("utf-8")
            if uploaded_json is not None
            else SAMPLE_JSON_PAYLOAD_DEFAULT
        )
        json_text = st.text_area("JSON Payload", value=default_json, height=220)
        if st.button("Normalise & Ingest JSON Batch"):
            report = manager.import_from_json_text(
                json_text=json_text,
                data_source=active_source,
                source_label="STREAMLIT_JSON_IMPORT",
            )
            st.success(
                f"Processed {report.total_processed} items: {report.inserted_unique} unique inserted, "
                f"{report.duplicates_suppressed} SHA-256 duplicates blocked."
            )

    with tab_dedup:
        dedup_logs = db.get_deduplication_logs(data_source=active_source)
        st.write(f"**Total Suppressed Duplicate Submissions:** `{len(dedup_logs)}`")
        if dedup_logs:
            st.dataframe(
                pd.DataFrame(dedup_logs), use_container_width=True, hide_index=True
            )


# ==============================================================================
# PAGE 8: SYSTEM SETTINGS
# ==============================================================================
def render_page_8_system_settings(
    db: DatabaseManager,
    active_source: str,
) -> None:
    st.header("8. System Settings & Mathematical Parameter Registry")

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Mathematical Constants (Locked Specification)")
        params_df = pd.DataFrame(
            [
                {"Parameter": "Category 1 CTI Decay Rate (λ_temp)", "Value": f"{LAMBDA_TEMPORARY_CTI} / day"},
                {"Parameter": "Persistent Vuln / Missing MFA Decay (λ_pers)", "Value": f"{LAMBDA_PERSISTENT} / day"},
                {"Parameter": "CISA KEV Multiplier (Ω_KEV)", "Value": f"{OMEGA_CISA_KEV}x"},
                {"Parameter": "EPSS ≥ 0.20 Multiplier (Ω_EPSS)", "Value": f"{OMEGA_EPSS_HIGH}x"},
                {"Parameter": "Base Exploitability Multiplier", "Value": f"{OMEGA_EPSS_DEFAULT}x"},
                {"Parameter": "Internet-Facing Exposure (Ψ_exp)", "Value": f"{PSI_INTERNET_FACING}x"},
                {"Parameter": "Internal Asset Exposure (Ψ_exp)", "Value": f"{PSI_INTERNAL_ONLY}x"},
                {"Parameter": "Compensating Control Range (Γ_ctrl)", "Value": f"[{GAMMA_CTRL_MIN}, {GAMMA_CTRL_MAX}]"},
                {"Parameter": "Criticality Scaling Exponent (β)", "Value": f"{BETA_CRITICALITY_EXPONENT}"},
                {"Parameter": "System Risk Aggregation Weight (α)", "Value": f"{ALPHA_SYSTEM_RISK}"},
            ]
        )
        st.dataframe(params_df, use_container_width=True, hide_index=True)

    with c2:
        st.subheader("Database Maintenance & Reset Controls")
        st.write(f"**Active SQLite Database Path:** `{db.db_path}`")
        if st.button("Reset Simulated SME Demonstration Dataset", use_container_width=True):
            stats = seed_simulated_sme_environment(db, reset_existing_simulated=True)
            st.success(
                f"Reset synthetic dataset: {stats['assets_count']} assets, "
                f"{stats['inserted_indicators']} unique indicators."
            )
            st.rerun()

        if st.button("Clear All Real Uploaded Data", use_container_width=True):
            db.clear_data_by_source("REAL")
            st.warning("Cleared all records where data_source = 'REAL'.")
            st.rerun()

        history = db.get_risk_history(data_source=active_source)
        if history:
            st.subheader("Recent System Risk Evaluation Snapshots")
            st.dataframe(
                pd.DataFrame(history), use_container_width=True, hide_index=True
            )
