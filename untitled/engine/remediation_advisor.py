"""
engine/remediation_advisor.py
Automated Cybersecurity Remediation Recommendation Engine for SMEs.
Analyses open threat indicators, asset criticality A_i, CISA KEV status,
EPSS probability, internet exposure, and configurable remediation effort hours E_k
to generate explainable, ranked SME remediation plans using the counterfactual
Remediation Priority Index (RPI):
    RPI = [(R_i - R_i(-k)) / E_k] * Omega_KEV(k)

Strictly distinguishes between:
- PROJECTED / COUNTERFACTUAL risk reduction (before remediation is applied), and
- VERIFIED RECALCULATED risk reduction (only after remediation is recorded in SQLite
  and the risk engine re-evaluates R_i(t) and R_sys).

Compatible with Python 3.11+.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from config import (
    ALPHA_SYSTEM_RISK,
    EPSS_THRESHOLD,
    IndicatorCategory,
    RiskTier,
)
from engine.prioritiser import calculate_rpi
from engine.risk_calculator import (
    calculate_asset_criticality_weights,
    calculate_exploitability_omega,
     calculate_overall_system_risk,
    evaluate_single_asset,
)
from models import Asset, AssetRiskResult, ThreatIndicator

# ==============================================================================
# 1. CONFIGURABLE SME REMEDIATION EFFORT ASSUMPTIONS (IN HOURS)
# ==============================================================================
DEFAULT_EFFORT_HOURS_BY_TYPE: dict[str, float] = {
    # Category 4: Identity and Authentication Hygiene
    "MISSING_MFA_PRIVILEGED": 1.0,
    "MISSING_MFA_STANDARD_USER": 1.5,
    "DORMANT_DOMAIN_ADMIN": 1.5,
    "SHARED_DB_SUPERUSER": 3.0,
    "WEAK_PASSWORD_POLICY": 2.0,
    "UNROTATED_API_KEY": 1.5,
    # Category 3: Endpoint Configuration and Patch Indicators
    "CVE_VULNERABILITY": 3.0,
    "ENDPOINT_MISCONFIGURATION": 3.5,
    "EDR_TAMPER_PROTECTION_OFF": 1.0,
    # Category 2: Perimeter and Attack Surface Exposure
    "OPEN_ADMIN_PORT": 2.0,
    "OPEN_RDP_PORT_3389": 1.5,
    "OPEN_SMB_PORT_445": 1.5,
    "OPEN_SNMP_UDP_161": 1.5,
    "WEAK_TLS_CIPHER_SUITE": 1.5,
    "EXPIRED_TLS_CERTIFICATE": 1.0,
    "LEGACY_AUTH_PROTOCOL_EXPOSED": 2.0,
    # Category 1: External Cyber Threat Intelligence
    "CTI_BOTNET_SCAN_MATCH": 1.5,
    "CTI_MALICIOUS_IP_BRUTEFORCE": 1.0,
    "CTI_DNS_C2_BEACON": 2.5,
    "CTI_SHODAN_HONEYPOT_MATCH": 1.5,
    "CTI_THREAT_MATCH": 1.5,
}


def estimate_configurable_effort_hours(
    indicator: ThreatIndicator,
    effort_overrides: dict[str, float] | None = None,
    use_indicator_stored_effort: bool = True,
) -> float:
    """
    Estimate remediation effort E_k in hours using configurable SME assumptions.
    - If `effort_overrides` specifies a custom hour estimate for `indicator.indicator_type`
      or `indicator.category`, that override is used.
    - Otherwise uses `indicator.remediation_effort_e` (when `use_indicator_stored_effort=True`)
      or falls back to `DEFAULT_EFFORT_HOURS_BY_TYPE`.
    """
    merged_table = dict(DEFAULT_EFFORT_HOURS_BY_TYPE)
    if effort_overrides:
        for k, v in effort_overrides.items():
            if float(v) > 0.0:
                merged_table[k.strip().upper()] = float(v)

    ind_type = indicator.indicator_type.strip().upper()
    if effort_overrides and ind_type in merged_table:
        return max(0.25, float(merged_table[ind_type]))

    if use_indicator_stored_effort and indicator.remediation_effort_e > 0.0:
        return max(0.25, float(indicator.remediation_effort_e))

    return max(0.25, float(merged_table.get(ind_type, 2.0)))


def classify_remediation_urgency(
    rpi_score: float,
    is_cisa_kev: bool,
    epss_score: float,
    asset_criticality: int,
    finding_domain: str,
) -> str:
    """
    Classify remediation urgency into Critical, High, Medium, or Low based on:
    - RPI score
    - CISA KEV status & EPSS probability
    - Asset business criticality A_i
    - Critical hygiene flaws (e.g., Missing MFA on high-criticality assets)
    """
    if is_cisa_kev or rpi_score >= 12.0:
        return RiskTier.CRITICAL.value
    if finding_domain == "MISSING_MFA" and asset_criticality >= 4:
        return RiskTier.CRITICAL.value
    if rpi_score >= 5.0 or (epss_score >= EPSS_THRESHOLD and asset_criticality >= 4):
        return RiskTier.HIGH.value
    if rpi_score >= 2.0 or asset_criticality >= 3:
        return RiskTier.MEDIUM.value
    return RiskTier.LOW.value


def classify_finding_domain(indicator: ThreatIndicator) -> tuple[str, str]:
    """
    Identify whether an indicator represents:
    - Missing MFA / Identity & Privileged Access Gap
    - Outdated Patch / Vulnerable Software (CVE)
    - Exposed Perimeter Service / Port / Legacy Protocol
    - Endpoint Configuration / Security Control Gap
    - Active External Threat Intelligence Sighting
    Returns (domain_code, human_label).
    """
    ind_type = indicator.indicator_type.upper()
    ident = indicator.identifier_key.upper()
    title_up = indicator.title.upper()
    cat = indicator.category

    if "MFA" in ind_type or "MFA" in ident or "MFA" in title_up:
        return ("MISSING_MFA", "Missing Multi-Factor Authentication (MFA)")
    if cat == IndicatorCategory.IDENTITY_AUTH.value:
        return ("PRIVILEGED_IDENTITY_GAP", "Privileged Identity & Authentication Hygiene")
    if "CVE-" in ident or "CVE" in ind_type or "PATCH" in title_up:
        return ("OUTDATED_PATCH_VULN_SOFTWARE", "Outdated Patch & Vulnerable Software (CVE)")
    if cat == IndicatorCategory.ENDPOINT_PATCH.value:
        return ("ENDPOINT_CONFIG_GAP", "Endpoint Security Configuration Gap")
    if cat == IndicatorCategory.PERIMETER_EXPOSURE.value:
        return ("EXPOSED_SERVICE_PERIMETER", "Exposed Perimeter Service & Attack Surface")
    return ("EXTERNAL_CTI_SIGHTING", "External Cyber Threat Intelligence Sighting")


def build_actionable_sme_steps(
    indicator: ThreatIndicator,
    asset: Asset,
    finding_domain_code: str,
) -> tuple[str, list[str]]:
    """
    Generate a clear executive recommendation title and concrete, practical step-by-step
    remediation instructions tailored for an SME IT team.
    """
    ident = indicator.identifier_key
    name = asset.asset_name

    if finding_domain_code == "MISSING_MFA":
        return (
            f"Enforce Phishing-Resistant MFA on {name} ({ident})",
            [
                f"Require FIDO2/WebAuthn or Authenticator App MFA for account/policy '{ident}' on {name}.",
                "Revoke existing active session tokens and require immediate re-authentication.",
                "Disable legacy SMS/voice fallback or basic authentication bypass rules.",
            ],
        )

    if finding_domain_code == "PRIVILEGED_IDENTITY_GAP":
        return (
            f"Remediate Privileged Account Hygiene on {name} ({ident})",
            [
                f"Disable or rotate credentials for dormant/shared privileged account '{ident}' on {name}.",
                "Enforce individual named administrator accounts with least-privilege RBAC.",
                "Configure automated 90-day credential rotation and audit logging.",
            ],
        )

    if finding_domain_code == "OUTDATED_PATCH_VULN_SOFTWARE":
        kev_note = (
            " (CISA KEV actively exploited in the wild — emergency priority)"
            if indicator.is_cisa_kev
            else ""
        )
        return (
            f"Apply Vendor Security Patch for {ident} on {name}{kev_note}",
            [
                f"Deploy the vendor-supplied firmware/OS security update addressing {ident} on {name} ({asset.ip_or_hostname}).",
                "If immediate reboot/patching requires a maintenance window, apply virtual patching or restrict network access via firewall ACL.",
                "Run a post-patch configuration check to confirm the vulnerable version is no longer active.",
            ],
        )

    if finding_domain_code == "ENDPOINT_CONFIG_GAP":
        return (
            f"Harden Endpoint Configuration ({ident}) on {name}",
            [
                f"Re-enable security control or harden baseline setting '{ident}' via Group Policy / MDM on {name}.",
                "Enable tamper protection so local users or malware cannot disable endpoint sensors.",
                "Verify endpoint compliance telemetry in central management console.",
            ],
        )

    if finding_domain_code == "EXPOSED_SERVICE_PERIMETER":
        return (
            f"Restrict Exposed Perimeter Service ({ident}) on {name}",
            [
                f"Remove direct public WAN exposure for '{ident}' on {name} ({asset.ip_or_hostname}).",
                "Place administrative or legacy interfaces behind VPN with MFA or strict source IP allowlisting.",
                "Disable deprecated TLS 1.0/1.1 or cleartext authentication protocols.",
            ],
        )

    # Category 1 External CTI
    return (
        f"Block Malicious Threat Indicator ({ident}) Targeting {name}",
        [
            f"Add indicator '{ident}' to edge firewall / WAF / DNS sinkhole blocklists protecting {name}.",
            "Inspect authentication and netflow logs over the past 14 days for any successful connections.",
            "Tighten rate-limiting and geo/ASN filtering on external authentication endpoints.",
        ],
    )


@dataclass(slots=True)
class AutomatedRemediationRecommendation:
    """
    Complete explainable remediation recommendation generated for an SME.
    Note: `projected_*` fields represent counterfactual estimates prior to execution.
    Risk is only actually reduced once the user marks the indicator as REMEDIATED
    and the engine recalculates SQLite state.
    """

    priority_rank: int
    indicator_id: int | None
    sha256_hash: str
    asset_id: str
    asset_name: str
    asset_type: str
    asset_criticality_a_i: int
    asset_weight_w_i: float
    is_internet_facing: bool
    exposure_psi: float
    category: str
    indicator_type: str
    identifier_key: str
    finding_domain_code: str
    finding_domain_label: str
    recommendation_headline: str
    practical_action_steps: list[str]
    why_generated_explanation: str
    urgency_level: str  # 'Critical' | 'High' | 'Medium' | 'Low'
    is_cisa_kev: bool
    epss_score: float
    omega_kev_multiplier: float
    control_factor_gamma: float
    effective_severity_s: float
    estimated_effort_hours_e_k: float
    current_asset_risk_r_i: float
    projected_asset_risk_after_fix: float
    projected_asset_risk_drop_delta: float
    current_system_risk_r_sys: float
    projected_system_risk_after_fix: float
    projected_system_risk_drop_delta: float
    rpi_score: float
    verification_status_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def generate_automated_remediation_recommendations(
    assets: Sequence[Asset],
    open_indicators: Sequence[ThreatIndicator],
    asset_results: Sequence[AssetRiskResult],
    current_system_risk_r_sys: float,
    evaluation_time_t: datetime | str | None = None,
    effort_overrides: dict[str, float] | None = None,
    use_indicator_stored_effort: bool = True,
) -> list[AutomatedRemediationRecommendation]:
    """
    Analyse all open threat indicators across the SME portfolio and generate ranked,
    explainable remediation recommendations.
    """
    if not assets or not open_indicators:
        return []

    eval_t = evaluation_time_t or datetime.now(timezone.utc)
    weights_map = calculate_asset_criticality_weights(
        {a.asset_id: a.criticality_score for a in assets}
    )
    asset_result_map: dict[str, AssetRiskResult] = {
        r.asset.asset_id: r for r in asset_results
    }
    inds_by_asset: dict[str, list[ThreatIndicator]] = {a.asset_id: [] for a in assets}
    for ind in open_indicators:
        if ind.asset_id in inds_by_asset:
            inds_by_asset[ind.asset_id].append(ind)

    recommendations: list[AutomatedRemediationRecommendation] = []

    for asset in assets:
        res_i = asset_result_map.get(asset.asset_id)
        if res_i is None:
            continue
        asset_inds = inds_by_asset.get(asset.asset_id, [])
        if not asset_inds:
            continue

        w_i = weights_map[asset.asset_id]
        eval_detail_by_hash = {
            d.sha256_hash: d for d in res_i.evaluated_indicators
        }

        for idx, target_ind in enumerate(asset_inds):
            remaining_inds = [
                other for j, other in enumerate(asset_inds) if j != idx
            ]
            counterfactual_asset_res = evaluate_single_asset(
                asset=asset,
                weight_w_i=w_i,
                indicators=remaining_inds,
                evaluation_time_t=eval_t,
            )

            r_i_curr = res_i.risk_score_r_i
            r_i_after = counterfactual_asset_res.risk_score_r_i

            # Calculate counterfactual System Risk R_sys(-k) if this single indicator were remediated
            counterfactual_portfolio_pairs: list[tuple[float, float]] = []
            for other_asset in assets:
                if other_asset.asset_id == asset.asset_id:
                    counterfactual_portfolio_pairs.append(
                        (r_i_after, weights_map[other_asset.asset_id])
                    )
                else:
                    other_res = asset_result_map[other_asset.asset_id]
                    counterfactual_portfolio_pairs.append(
                        (other_res.risk_score_r_i, weights_map[other_asset.asset_id])
                    )

            r_sys_after, _, _ = calculate_overall_system_risk(
                counterfactual_portfolio_pairs,
                alpha=ALPHA_SYSTEM_RISK,
            )
            sys_drop_delta = max(0.0, current_system_risk_r_sys - r_sys_after)

            effort_hours = estimate_configurable_effort_hours(
                indicator=target_ind,
                effort_overrides=effort_overrides,
                use_indicator_stored_effort=use_indicator_stored_effort,
            )
            omega_k = calculate_exploitability_omega(
                is_cisa_kev=target_ind.is_cisa_kev,
                epss_score=target_ind.epss_score,
            )
            rpi_val, delta_r_i = calculate_rpi(
                current_asset_risk_r_i=r_i_curr,
                counterfactual_asset_risk_without_k=r_i_after,
                remediation_effort_e_k=effort_hours,
                omega_kev_k=omega_k,
            )

            domain_code, domain_label = classify_finding_domain(target_ind)
            urgency = classify_remediation_urgency(
                rpi_score=rpi_val,
                is_cisa_kev=target_ind.is_cisa_kev,
                epss_score=target_ind.epss_score,
                asset_criticality=asset.criticality_score,
                finding_domain=domain_code,
            )
            headline, steps = build_actionable_sme_steps(
                indicator=target_ind,
                asset=asset,
                finding_domain_code=domain_code,
            )

            detail = eval_detail_by_hash.get(target_ind.sha256_hash)
            s_eff = detail.effective_severity_s if detail else target_ind.base_severity_s0

            # Build explicit, transparent causal explanation for why this recommendation was generated
            reasons: list[str] = [
                f"Target asset '{asset.asset_name}' ({asset.asset_id}) has business criticality A_i = {asset.criticality_score}/5 (normalised weight w_i = {w_i:.3f}) and current asset risk R_i = {r_i_curr:.2f}/100."
            ]
            if asset.is_internet_facing:
                reasons.append(
                    "The asset is directly internet-facing, amplifying threat severity by Ψ_exp = 1.4x."
                )
            else:
                reasons.append(
                    "The asset is internal-facing (Ψ_exp = 1.0x)."
                )

            if target_ind.is_cisa_kev:
                reasons.append(
                    f"Indicator '{target_ind.identifier_key}' is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog (EPSS = {target_ind.epss_score:.2f}), applying the maximum exploitability multiplier Ω_KEV = 1.8x."
                )
            elif target_ind.epss_score >= EPSS_THRESHOLD:
                reasons.append(
                    f"Indicator '{target_ind.identifier_key}' has an elevated exploit prediction score EPSS = {target_ind.epss_score:.2f} (≥ 0.20), applying Ω_KEV = 1.5x."
                )
            else:
                reasons.append(
                    f"Indicator '{target_ind.identifier_key}' has baseline exploitability Ω_KEV = 1.0x (EPSS = {target_ind.epss_score:.2f})."
                )

            reasons.append(
                f"With effective severity S(I_ik,t) = {s_eff:.4f} and estimated remediation effort E_k = {effort_hours:.1f} hour(s), counterfactual leave-one-out analysis projects that resolving this single issue would reduce asset risk R_i from {r_i_curr:.2f} to {r_i_after:.2f} (projected ΔR_i = -{delta_r_i:.2f} points) and yield RPI = {rpi_val:.2f}."
            )

            recommendations.append(
                AutomatedRemediationRecommendation(
                    priority_rank=0,
                    indicator_id=target_ind.indicator_id,
                    sha256_hash=target_ind.sha256_hash,
                    asset_id=asset.asset_id,
                    asset_name=asset.asset_name,
                    asset_type=asset.asset_type,
                    asset_criticality_a_i=asset.criticality_score,
                    asset_weight_w_i=round(w_i, 4),
                    is_internet_facing=asset.is_internet_facing,
                    exposure_psi=asset.exposure_factor_psi,
                    category=target_ind.category,
                    indicator_type=target_ind.indicator_type,
                    identifier_key=target_ind.identifier_key,
                    finding_domain_code=domain_code,
                    finding_domain_label=domain_label,
                    recommendation_headline=headline,
                    practical_action_steps=steps,
                    why_generated_explanation=" ".join(reasons),
                    urgency_level=urgency,
                    is_cisa_kev=target_ind.is_cisa_kev,
                    epss_score=target_ind.epss_score,
                    omega_kev_multiplier=omega_k,
                    control_factor_gamma=target_ind.control_factor_gamma,
                    effective_severity_s=round(s_eff, 4),
                    estimated_effort_hours_e_k=round(effort_hours, 2),
                    current_asset_risk_r_i=round(r_i_curr, 2),
                    projected_asset_risk_after_fix=round(r_i_after, 2),
                    projected_asset_risk_drop_delta=round(delta_r_i, 2),
                    current_system_risk_r_sys=round(current_system_risk_r_sys, 2),
                    projected_system_risk_after_fix=round(r_sys_after, 2),
                    projected_system_risk_drop_delta=round(sys_drop_delta, 2),
                    rpi_score=round(rpi_val, 2),
                    verification_status_note=(
                        "PENDING REMEDIATION — Values shown are counterfactual projections. "
                        "Actual risk reduction is only recorded after this indicator is marked as REMEDIATED and the engine recalculates R_i(t) and R_sys."
                    ),
                )
            )

    recommendations.sort(
        key=lambda item: (
            item.rpi_score,
            item.projected_asset_risk_drop_delta,
            item.asset_criticality_a_i,
        ),
        reverse=True,
    )
    for rank_idx, rec in enumerate(recommendations, start=1):
        rec.priority_rank = rank_idx

    return recommendations
