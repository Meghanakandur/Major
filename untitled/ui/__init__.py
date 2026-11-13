"""
ui/__init__.py
Modular Streamlit UI package providing the 8 university major-project dashboard pages
and interactive Plotly visualisations.
"""

from ui.charts import (
    build_asset_criticality_bubble_chart,
    build_asset_risk_bar_chart,
    build_category_distribution_chart,
    build_rpi_pareto_chart,
    build_system_risk_gauge,
    build_temporal_decay_simulation_chart,
)
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

__all__ = [
    "build_system_risk_gauge",
    "build_asset_risk_bar_chart",
    "build_category_distribution_chart",
    "build_asset_criticality_bubble_chart",
    "build_rpi_pareto_chart",
    "build_temporal_decay_simulation_chart",
    "render_page_1_home_overview",
    "render_page_2_asset_management",
    "render_page_3_cybersecurity_indicators",
    "render_page_4_risk_assessment",
    "render_page_5_risk_visualisation",
    "render_page_6_remediation_recommendations",
    "render_page_7_data_import",
    "render_page_8_system_settings",
]
