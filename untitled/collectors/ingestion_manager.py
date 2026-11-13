"""
collectors/ingestion_manager.py
Unified Indicator Ingestion Manager supporting:
- CSV file/text import
- JSON file/text import
- Category-specific normalisation across all 4 collectors
- SHA-256 deduplication and SQLite persistence
- Safe fallback to synthetic indicator generation when external feeds are unavailable
Compatible with Python 3.11+.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
from typing import Any

from collectors.base_collector import (
    BatchIngestionReport,
    StandardisedIndicatorRecord,
    record_to_threat_indicator,
)
from collectors.cti_collector import ExternalCTICollector
from collectors.endpoint_collector import EndpointPatchCollector
from collectors.identity_collector import IdentityHygieneCollector
from collectors.perimeter_collector import PerimeterExposureCollector
from config import AssetType, DataSource, IndicatorCategory
from database import DatabaseManager
from models import Asset


class IndicatorIngestionManager:
    """
    Coordinates the 4 category collectors, normalises raw CSV/JSON records,
    enforces SHA-256 deduplication, and persists unique indicators to SQLite.
    """

    def __init__(
        self,
        db: DatabaseManager,
        enable_external_api: bool = False,
    ) -> None:
        self.db = db
        self.cti_collector = ExternalCTICollector(enable_external_api=enable_external_api)
        self.perimeter_collector = PerimeterExposureCollector()
        self.endpoint_collector = EndpointPatchCollector()
        self.identity_collector = IdentityHygieneCollector()

    def route_and_normalise(
        self,
        raw_row: dict[str, Any],
        default_data_source: str = DataSource.REAL.value,
    ) -> StandardisedIndicatorRecord:
        """
        Route a raw dictionary to the appropriate category collector and return
        a validated StandardisedIndicatorRecord.
        """
        raw_cat = str(raw_row.get("category") or "").strip()

        # Fuzzy/alias matching so user-uploaded CSV/JSON files are forgiving
        cat_upper = raw_cat.upper()
        if "EXTERNAL" in cat_upper or "CTI" in cat_upper or "THREAT INTEL" in cat_upper:
            return self.cti_collector.normalise_raw_entry(raw_row, default_data_source)
        if "PERIMETER" in cat_upper or "EXPOSURE" in cat_upper or "SURFACE" in cat_upper:
            return self.perimeter_collector.normalise_raw_entry(raw_row, default_data_source)
        if "ENDPOINT" in cat_upper or "PATCH" in cat_upper or "CVE" in cat_upper:
            return self.endpoint_collector.normalise_raw_entry(raw_row, default_data_source)
        if "IDENTITY" in cat_upper or "AUTH" in cat_upper or "MFA" in cat_upper:
            return self.identity_collector.normalise_raw_entry(raw_row, default_data_source)

        raise ValueError(
            f"Unrecognised indicator category '{raw_cat}'. Must map to one of the 4 SME categories."
        )

    def _ensure_target_asset_exists(self, asset_id: str, data_source: str) -> None:
        """
        Ensure the referenced asset_id exists in the SQLite `assets` table so foreign-key
        integrity is preserved when importing indicators from CSV or JSON.
        """
        existing_assets = {a.asset_id for a in self.db.get_assets()}
        clean_id = asset_id.strip().upper()
        if clean_id not in existing_assets:
            auto_asset = Asset(
                asset_id=clean_id,
                asset_name=f"Imported SME Asset ({clean_id})",
                asset_type=AssetType.SERVER.value,
                criticality_score=3,
                is_internet_facing=False,
                owner_department="Imported Inventory",
                ip_or_hostname="N/A",
                data_source=data_source,
            )
            self.db.upsert_asset(auto_asset)

    def ingest_standardised_records(
        self,
        records: list[StandardisedIndicatorRecord],
        source_label: str = "BATCH_IMPORT",
    ) -> BatchIngestionReport:
        """
        Persist a list of StandardisedIndicatorRecord objects into SQLite with
        SHA-256 deduplication and audit logging.
        """
        inserted_hashes: list[str] = []
        duplicate_hashes: list[str] = []
        errors: list[str] = []

        for idx, rec in enumerate(records, start=1):
            try:
                self._ensure_target_asset_exists(rec.asset_id, rec.data_source)
                threat_ind = record_to_threat_indicator(rec)
                was_inserted, sha_digest = self.db.insert_indicator_deduplicated(
                    threat_ind
                )
                if was_inserted:
                    inserted_hashes.append(sha_digest)
                else:
                    duplicate_hashes.append(sha_digest)
            except Exception as exc:
                errors.append(f"Row {idx} ({rec.indicator_id}): {exc}")

        return BatchIngestionReport(
            source_label=source_label,
            total_processed=len(records),
            inserted_unique=len(inserted_hashes),
            duplicates_suppressed=len(duplicate_hashes),
            validation_errors=len(errors),
            error_messages=errors,
            inserted_hashes=inserted_hashes,
            duplicate_hashes=duplicate_hashes,
        )

    def import_from_csv_text(
        self,
        csv_text: str,
        data_source: str = DataSource.REAL.value,
        source_label: str = "CSV_UPLOAD",
    ) -> BatchIngestionReport:
        """
        Parse CSV text containing cybersecurity indicators, normalise each row through
        the 4 category collectors, deduplicate via SHA-256, and store in SQLite.
        """
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        records: list[StandardisedIndicatorRecord] = []
        errors: list[str] = []
        raw_row_count = 0

        for idx, row in enumerate(reader, start=1):
            raw_row_count += 1
            try:
                clean_row = {
                    (k.strip() if k else ""): (v.strip() if isinstance(v, str) else v)
                    for k, v in row.items()
                }
                rec = self.route_and_normalise(clean_row, default_data_source=data_source)
                records.append(rec)
            except Exception as exc:
                errors.append(f"CSV Row {idx}: {exc}")

        report = self.ingest_standardised_records(records, source_label=source_label)
        report.total_processed = raw_row_count
        report.validation_errors += len(errors)
        report.error_messages = errors + report.error_messages
        return report

    def import_from_json_text(
        self,
        json_text: str,
        data_source: str = DataSource.REAL.value,
        source_label: str = "JSON_UPLOAD",
    ) -> BatchIngestionReport:
        """
        Parse JSON text (either a JSON array of indicator objects or `{"indicators": [...]}`),
        normalise through the 4 category collectors, deduplicate via SHA-256, and store in SQLite.
        """
        parsed = json.loads(json_text.strip())
        if isinstance(parsed, dict):
            raw_list = parsed.get("indicators", [parsed])
        elif isinstance(parsed, list):
            raw_list = parsed
        else:
            raise ValueError("JSON root must be an array of indicator objects or an object with an 'indicators' key.")

        records: list[StandardisedIndicatorRecord] = []
        errors: list[str] = []

        for idx, item in enumerate(raw_list, start=1):
            try:
                if not isinstance(item, dict):
                    raise ValueError("Each JSON entry must be an object.")
                rec = self.route_and_normalise(item, default_data_source=data_source)
                records.append(rec)
            except Exception as exc:
                errors.append(f"JSON Item {idx}: {exc}")

        report = self.ingest_standardised_records(records, source_label=source_label)
        report.total_processed = len(raw_list)
        report.validation_errors += len(errors)
        report.error_messages = errors + report.error_messages
        return report

    def collect_all_synthetic_categories(
        self, reference_time: datetime | None = None
    ) -> BatchIngestionReport:
        """
        Run all 4 category collectors in synthetic fallback mode and store their
        standardised indicators in SQLite.
        """
        ref = reference_time or datetime.now(timezone.utc)
        all_records: list[StandardisedIndicatorRecord] = []
        all_records.extend(self.cti_collector.collect_synthetic_samples(ref))
        all_records.extend(self.perimeter_collector.collect_synthetic_samples(ref))
        all_records.extend(self.endpoint_collector.collect_synthetic_samples(ref))
        all_records.extend(self.identity_collector.collect_synthetic_samples(ref))

        return self.ingest_standardised_records(
            all_records, source_label="FOUR_CATEGORY_SYNTHETIC_COLLECTORS"
        )
