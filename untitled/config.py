"""
config.py
Global configuration, mathematical constants, enumerations, and filesystem paths
for the Lightweight Cybersecurity Risk Scoring System for SMEs.
Compatible with Python 3.11+.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Final


class StrEnum(str, Enum):
    """String enumeration compatible with Python 3.10 and Python 3.11+."""

    def __str__(self) -> str:
        return str(self.value)


# ==============================================================================
# 1. PROJECT METADATA & FILESYSTEM PATHS
# ==============================================================================
APP_TITLE: Final[str] = (
    "A Lightweight Cybersecurity Risk Scoring System for SMEs Using Threat Indicators"
)
APP_VERSION: Final[str] = "1.0.0"

BASE_DIR: Final[Path] = Path(__file__).resolve().parent
DATA_DIR: Final[Path] = BASE_DIR / "data"
TEMPLATE_DIR: Final[Path] = DATA_DIR / "templates"
DB_PATH: Final[Path] = DATA_DIR / "risk_scoring.db"


def ensure_directories() -> None:
    """Ensure that the data and template directories exist on disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)


# ==============================================================================
# 2. DOMAIN ENUMERATIONS
# ==============================================================================
class IndicatorCategory(StrEnum):
    """The four mandatory cybersecurity indicator categories."""

    EXTERNAL_CTI = "External Cyber Threat Intelligence"
    PERIMETER_EXPOSURE = "Perimeter and Attack Surface Exposure"
    ENDPOINT_PATCH = "Endpoint Configuration and Patch Indicators"
    IDENTITY_AUTH = "Identity and Authentication Hygiene"


class AssetType(StrEnum):
    """Standard SME IT asset classifications."""

    SERVER = "Server"
    WORKSTATION = "Workstation"
    NETWORK_DEVICE = "Network_Device"
    CLOUD_IDENTITY = "Cloud_Identity"
    DATABASE = "Database"
    WEB_APPLICATION = "Web_Application"


class DataSource(StrEnum):
    """Explicit separation between real collected data and synthetic demo data."""

    REAL = "REAL"
    SIMULATED = "SIMULATED"


class IndicatorStatus(StrEnum):
    """Lifecycle status of an indicator."""

    OPEN = "OPEN"
    REMEDIATED = "REMEDIATED"


class RiskTier(StrEnum):
    """Qualitative risk classification tiers (Low, Medium, High, Critical)."""

    LOW = "Low"
    MODERATE = "Medium"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ==============================================================================
# 3. EXACT MATHEMATICAL CONSTANTS
# ==============================================================================
# Temporal decay rates: D(t, t0) = exp(-lambda_k * (t - t0))
LAMBDA_TEMPORARY_CTI: Final[float] = 0.05  # Per day for temporary CTI indicators
LAMBDA_PERSISTENT: Final[float] = 0.00     # Zero decay for unresolved vulnerabilities/MFA

# Exploitability factor: Omega_KEV(k)
OMEGA_CISA_KEV: Final[float] = 1.8         # CISA Known Exploited Vulnerability factor
OMEGA_EPSS_HIGH: Final[float] = 1.5        # EPSS >= 0.20 factor
OMEGA_EPSS_DEFAULT: Final[float] = 1.0     # Otherwise EPSS factor
EPSS_THRESHOLD: Final[float] = 0.20        # Threshold for high EPSS probability

# Exposure factor: Psi_exp(i)
PSI_INTERNET_FACING: Final[float] = 1.4    # Internet-facing asset factor
PSI_INTERNAL_ONLY: Final[float] = 1.0      # Non-internet-facing asset factor

# Compensating control bounds: Gamma_ctrl(i, k)
GAMMA_CTRL_MIN: Final[float] = 0.30
GAMMA_CTRL_MAX: Final[float] = 1.00

# Effective severity upper bound: S(I_ik, t) = min(1.0, S0(k) * D(t, t0) * Phi_ik)
EFFECTIVE_SEVERITY_MAX: Final[float] = 1.00

# Asset criticality scaling parameters: (A_i / 5)^beta
CRITICALITY_MIN: Final[int] = 1
CRITICALITY_MAX: Final[int] = 5
BETA_CRITICALITY_EXPONENT: Final[float] = 0.50

# System risk aggregation parameter: R_sys = alpha * max(R_i) + (1 - alpha) * sum(w_i * R_i)
ALPHA_SYSTEM_RISK: Final[float] = 0.65

# Risk Classification Thresholds (0 to 100 scale)
RISK_TIER_THRESHOLDS: Final[dict[RiskTier, tuple[float, float]]] = {
    RiskTier.LOW: (0.0, 25.0),
    RiskTier.MODERATE: (25.0, 50.0),
    RiskTier.HIGH: (50.0, 75.0),
    RiskTier.CRITICAL: (75.0, 100.0),
}

RISK_TIER_COLORS: Final[dict[RiskTier, str]] = {
    RiskTier.LOW: "#16A34A",       # Nominal Emerald Green
    RiskTier.MODERATE: "#D97706",  # Warning Amber
    RiskTier.HIGH: "#EA580C",      # High Risk Orange
    RiskTier.CRITICAL: "#DC2626",  # Critical Crimson Red
}


def get_default_decay_lambda(category: IndicatorCategory | str) -> float:
    """
    Return the mathematically mandated decay rate lambda_k based on category:
    - 0.05 per day for temporary threat intelligence indicators.
    - 0.00 for unresolved vulnerabilities, exposure, and missing MFA until remediation.
    """
    if str(category) == IndicatorCategory.EXTERNAL_CTI.value:
        return LAMBDA_TEMPORARY_CTI
    return LAMBDA_PERSISTENT


def classify_risk_score(score: float) -> RiskTier:
    """Classify a numerical risk score [0, 100] into a qualitative RiskTier."""
    clamped = max(0.0, min(100.0, float(score)))
    if clamped < 25.0:
        return RiskTier.LOW
    if clamped < 50.0:
        return RiskTier.MODERATE
    if clamped < 75.0:
        return RiskTier.HIGH
    return RiskTier.CRITICAL
