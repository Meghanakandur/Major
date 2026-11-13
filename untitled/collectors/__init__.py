"""
collectors/__init__.py
Cybersecurity Indicator Collection Package for the four core SME risk categories:
1. External Cyber Threat Intelligence
2. Perimeter and Attack Surface Exposure
3. Endpoint Configuration and Patch Indicators
4. Identity and Authentication Hygiene
"""

from collectors.base_collector import (
    BatchIngestionReport,
    StandardisedIndicatorRecord,
    compute_record_sha256,
    record_to_threat_indicator,
)
from collectors.cti_collector import ExternalCTICollector
from collectors.endpoint_collector import EndpointPatchCollector
from collectors.identity_collector import IdentityHygieneCollector
from collectors.ingestion_manager import IndicatorIngestionManager
from collectors.perimeter_collector import PerimeterExposureCollector

__all__ = [
    "StandardisedIndicatorRecord",
    "BatchIngestionReport",
    "compute_record_sha256",
    "record_to_threat_indicator",
    "ExternalCTICollector",
    "PerimeterExposureCollector",
    "EndpointPatchCollector",
    "IdentityHygieneCollector",
    "IndicatorIngestionManager",
]
