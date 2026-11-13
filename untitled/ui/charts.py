"""
ui/charts.py
Interactive Plotly visualisations for the Streamlit Cybersecurity Risk Scoring Dashboard.
All charts consume real calculated values from `engine/` and SQLite.
Compatible with Python 3.11+.
"""

from __future__ import annotations

import math
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config import RISK_TIER_COLORS, RiskTier
from models import SystemRiskSummary

TIER_COLOR_MAP: dict[str, str] = {
    RiskTier.LOW.value: RISK_TIER_COLORS[RiskTier.LOW],
    RiskTier.MODERATE.value: RISK_TIER_COLORS[RiskTier.MODERATE],
    RiskTier.HIGH.value: RISK_TIER_COLORS[RiskTier.HIGH],
    RiskTier.CRITICAL.value: RISK_TIER_COLORS[RiskTier.CRITICAL],
}


def build_system_risk_gauge(summary: SystemRiskSummary) -> go.Figure:
    """Build an interactive Plotly gauge chart for the overall System Risk Score R_sys."""
    tier_color = RISK_TIER_COLORS[summary.system_risk_tier]
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=summary.system_risk_r_sys,
            number={"suffix": " / 100", "font": {"size": 34}},
            title={
                "text": f"System Risk R_sys ({summary.system_risk_tier.value} Risk)",
                "font": {"size": 17},
            },
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": tier_color},
                "steps": [
                    {"range": [0, 25], "color": "rgba(22, 163, 74, 0.18)"},
                    {"range": [25, 50], "color": "rgba(217, 119, 6, 0.18)"},
                    {"range": [50, 75], "color": "rgba(234, 88, 12, 0.18)"},
                    {"range": [75, 100], "color": "rgba(220, 38, 38, 0.18)"},
                ],
            },
        )
    )
    fig.update_layout(
        height=310,
        margin=dict(l=20, r=20, t=50, b=15),
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_asset_risk_bar_chart(summary: SystemRiskSummary) -> go.Figure:
    """Build a horizontal bar chart comparing individual asset risk scores R_i(t)."""
    rows = [
        {
            "Asset ID": r.asset.asset_id,
            "Asset": f"{r.asset.asset_id} — {r.asset.asset_name}",
            "Risk Score R_i(t)": round(r.risk_score_r_i, 2),
            "Classification": r.risk_tier.value,
            "Criticality A_i": r.asset.criticality_score,
            "Open Indicators": r.open_indicator_count,
        }
        for r in summary.asset_results
    ]
    df = pd.DataFrame(rows)
    fig = px.bar(
        df,
        x="Risk Score R_i(t)",
        y="Asset",
        color="Classification",
        orientation="h",
        text="Risk Score R_i(t)",
        color_discrete_map=TIER_COLOR_MAP,
        hover_data=["Criticality A_i", "Open Indicators"],
        title="Asset-Wise Cybersecurity Risk Scores R_i(t)",
        range_x=[0, 108],
    )
    fig.update_layout(
        height=310,
        yaxis={"categoryorder": "total ascending"},
        margin=dict(l=15, r=15, t=45, b=15),
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_category_distribution_chart(summary: SystemRiskSummary) -> go.Figure:
    """Build a grouped chart showing indicator count and mean effective severity across the 4 categories."""
    records: list[dict[str, object]] = []
    for r in summary.asset_results:
        for ind in r.evaluated_indicators:
            records.append(
                {
                    "Category": ind.category,
                    "Effective Severity S(I_ik,t)": ind.effective_severity_s,
                    "Base Severity S0(k)": ind.s0,
                }
            )
    if not records:
        return go.Figure()

    df = pd.DataFrame(records)
    agg = (
        df.groupby("Category", as_index=False)
        .agg(
            Indicator_Count=("Effective Severity S(I_ik,t)", "count"),
            Mean_Effective_Severity=("Effective Severity S(I_ik,t)", "mean"),
        )
        .sort_values("Mean_Effective_Severity", ascending=False)
    )
    agg["Mean_Effective_Severity"] = agg["Mean_Effective_Severity"].round(3)

    fig = px.bar(
        agg,
        x="Category",
        y="Indicator_Count",
        color="Mean_Effective_Severity",
        text="Indicator_Count",
        color_continuous_scale="OrRd",
        title="Active Indicators & Mean Effective Severity by Category",
        labels={
            "Indicator_Count": "Open Indicators",
            "Mean_Effective_Severity": "Mean S(I_ik,t)",
        },
    )
    fig.update_layout(height=340, margin=dict(l=15, r=15, t=45, b=15))
    return fig


def build_asset_criticality_bubble_chart(summary: SystemRiskSummary) -> go.Figure:
    """Build a scatter/bubble plot of Asset Criticality A_i vs Risk Score R_i(t)."""
    rows = [
        {
            "Asset ID": r.asset.asset_id,
            "Asset Name": r.asset.asset_name,
            "Criticality A_i": r.asset.criticality_score,
            "Risk Score R_i(t)": round(r.risk_score_r_i, 2),
            "Weight w_i": round(r.weight_w_i, 3),
            "Open Indicators": max(1, r.open_indicator_count),
            "Exposure": (
                "Internet-Facing (Psi=1.4)"
                if r.asset.is_internet_facing
                else "Internal (Psi=1.0)"
            ),
            "Classification": r.risk_tier.value,
        }
        for r in summary.asset_results
    ]
    df = pd.DataFrame(rows)
    fig = px.scatter(
        df,
        x="Criticality A_i",
        y="Risk Score R_i(t)",
        size="Open Indicators",
        color="Classification",
        symbol="Exposure",
        hover_name="Asset Name",
        text="Asset ID",
        color_discrete_map=TIER_COLOR_MAP,
        title="Asset Business Criticality (A_i) vs. Dynamic Risk Score R_i(t)",
        range_x=[0.5, 5.5],
        range_y=[0, 108],
    )
    fig.update_traces(textposition="top center")
    fig.update_layout(height=360, margin=dict(l=15, r=15, t=45, b=15))
    return fig


def build_rpi_pareto_chart(summary: SystemRiskSummary) -> go.Figure:
    """Build a Pareto bar chart of the top Remediation Priority Index (RPI) actions."""
    top_items = summary.remediation_plan[:10]
    if not top_items:
        return go.Figure()

    df = pd.DataFrame(
        [
            {
                "Action": f"#{item.rank} {item.identifier_key} ({item.asset_id})",
                "RPI Score": round(item.rpi_score, 2),
                "Risk Reduction Delta R_i": round(item.risk_reduction_delta, 2),
                "Effort E_k (h)": item.remediation_effort_e,
                "Category": item.category,
            }
            for item in top_items
        ]
    )
    fig = px.bar(
        df,
        x="RPI Score",
        y="Action",
        color="Category",
        orientation="h",
        text="RPI Score",
        hover_data=["Risk Reduction Delta R_i", "Effort E_k (h)"],
        title="Top Remediation Priority Index (RPI) Actions",
    )
    fig.update_layout(
        height=360,
        yaxis={"categoryorder": "total ascending"},
        margin=dict(l=15, r=15, t=45, b=15),
    )
    return fig


def build_temporal_decay_simulation_chart() -> go.Figure:
    """
    Build a theoretical & interactive curve comparing:
    - Category 1 External CTI decay: D(t, t0) = exp(-0.05 * Δt)
    - Categories 2–4 Persistent vulnerabilities/MFA: D(t, t0) = exp(0 * Δt) = 1.0
    """
    days = list(range(0, 61, 2))
    rows: list[dict[str, object]] = []
    for d in days:
        rows.append(
            {
                "Elapsed Days (t - t0)": d,
                "Temporal Decay D(t,t0)": round(math.exp(-0.05 * d), 4),
                "Indicator Class": "Category 1: Temporary CTI (λ = 0.05/day)",
            }
        )
        rows.append(
            {
                "Elapsed Days (t - t0)": d,
                "Temporal Decay D(t,t0)": 1.0,
                "Indicator Class": "Categories 2–4: Unresolved Vuln & Missing MFA (λ = 0.00)",
            }
        )
    df = pd.DataFrame(rows)
    fig = px.line(
        df,
        x="Elapsed Days (t - t0)",
        y="Temporal Decay D(t,t0)",
        color="Indicator Class",
        title="Temporal Decay Function D(t,t0) = exp(-λ_k · (t - t0)) Over 60 Days",
        range_y=[0, 1.08],
    )
    fig.update_layout(height=340, margin=dict(l=15, r=15, t=45, b=15))
    return fig
