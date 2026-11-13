"""
database.py
SQLite database manager, schema initialization, SHA-256 deduplication enforcement,
and CRUD repository operations.
Compatible with Python 3.11+.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from config import DB_PATH, ensure_directories
from models import Asset, SystemRiskSummary, ThreatIndicator


class DatabaseManager:
    """
    Manages SQLite connections, relational table schemas, and deterministic
    SHA-256 deduplicated persistence.
    """

    def __init__(self, db_path: Path = DB_PATH) -> None:
        ensure_directories()
        self.db_path = db_path
        self.initialize_schema()

    @contextmanager
    def get_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a SQLite connection with foreign keys and Row factory enabled."""
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """Create all required tables and indices if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Assets Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    asset_name TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    criticality_score INTEGER NOT NULL CHECK(criticality_score BETWEEN 1 AND 5),
                    is_internet_facing INTEGER NOT NULL CHECK(is_internet_facing IN (0, 1)),
                    owner_department TEXT NOT NULL DEFAULT 'IT Operations',
                    ip_or_hostname TEXT NOT NULL DEFAULT 'N/A',
                    data_source TEXT NOT NULL CHECK(data_source IN ('REAL', 'SIMULATED')),
                    created_at TEXT NOT NULL
                );
                """
            )

            # 2. Threat Indicators Table (with UNIQUE sha256_hash constraint)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS indicators (
                    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256_hash TEXT UNIQUE NOT NULL,
                    asset_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    identifier_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    base_severity_s0 REAL NOT NULL CHECK(base_severity_s0 > 0.0 AND base_severity_s0 <= 1.0),
                    confidence_c REAL NOT NULL CHECK(confidence_c > 0.0 AND confidence_c <= 1.0),
                    is_cisa_kev INTEGER NOT NULL CHECK(is_cisa_kev IN (0, 1)),
                    epss_score REAL NOT NULL CHECK(epss_score >= 0.0 AND epss_score <= 1.0),
                    control_factor_gamma REAL NOT NULL CHECK(control_factor_gamma >= 0.3 AND control_factor_gamma <= 1.0),
                    decay_lambda REAL NOT NULL CHECK(decay_lambda >= 0.0),
                    remediation_effort_e REAL NOT NULL CHECK(remediation_effort_e > 0.0),
                    observed_at_t0 TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'REMEDIATED')),
                    data_source TEXT NOT NULL CHECK(data_source IN ('REAL', 'SIMULATED')),
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                );
                """
            )

            # 3. SHA-256 Deduplication Audit Log Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS deduplication_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256_hash TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    identifier_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    data_source TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                """
            )

            # 4. System Risk Evaluation Snapshots Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_history (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evaluated_at TEXT NOT NULL,
                    system_risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    max_asset_risk REAL NOT NULL,
                    weighted_mean_risk REAL NOT NULL,
                    total_assets INTEGER NOT NULL,
                    active_indicator_count INTEGER NOT NULL,
                    data_source TEXT NOT NULL
                );
                """
            )

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_asset ON indicators(asset_id);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_status ON indicators(status);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(data_source);"
            )

    # ==========================================================================
    # ASSET CRUD OPERATIONS
    # ==========================================================================
    def upsert_asset(self, asset: Asset) -> None:
        """Insert or update an SME asset record."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    asset_id, asset_name, asset_type, criticality_score,
                    is_internet_facing, owner_department, ip_or_hostname,
                    data_source, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    asset_name = excluded.asset_name,
                    asset_type = excluded.asset_type,
                    criticality_score = excluded.criticality_score,
                    is_internet_facing = excluded.is_internet_facing,
                    owner_department = excluded.owner_department,
                    ip_or_hostname = excluded.ip_or_hostname,
                    data_source = excluded.data_source;
                """,
                (
                    asset.asset_id,
                    asset.asset_name,
                    asset.asset_type,
                    asset.criticality_score,
                    1 if asset.is_internet_facing else 0,
                    asset.owner_department,
                    asset.ip_or_hostname,
                    asset.data_source,
                    asset.created_at,
                ),
            )

    def get_assets(self, data_source: str | None = None) -> list[Asset]:
        """Retrieve all assets, optionally filtered by data_source ('REAL' or 'SIMULATED')."""
        query = "SELECT * FROM assets"
        params: list[Any] = []
        if data_source in ("REAL", "SIMULATED"):
            query += " WHERE data_source = ?"
            params.append(data_source)
        query += " ORDER BY criticality_score DESC, asset_id ASC;"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            Asset(
                asset_id=row["asset_id"],
                asset_name=row["asset_name"],
                asset_type=row["asset_type"],
                criticality_score=int(row["criticality_score"]),
                is_internet_facing=bool(row["is_internet_facing"]),
                owner_department=row["owner_department"],
                ip_or_hostname=row["ip_or_hostname"],
                data_source=row["data_source"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    # ==========================================================================
    # INDICATOR & SHA-256 DEDUPLICATION OPERATIONS
    # ==========================================================================
    def insert_indicator_deduplicated(
        self, indicator: ThreatIndicator
    ) -> tuple[bool, str]:
        """
        Insert a ThreatIndicator if its SHA-256 fingerprint does not already exist.
        If a collision occurs, log the suppressed duplicate in `deduplication_log`
        and return (False, sha256_hash).
        """
        with self.get_connection() as conn:
            existing = conn.execute(
                "SELECT indicator_id FROM indicators WHERE sha256_hash = ?;",
                (indicator.sha256_hash,),
            ).fetchone()

            if existing is not None:
                conn.execute(
                    """
                    INSERT INTO deduplication_log (
                        sha256_hash, asset_id, category, identifier_key,
                        title, data_source, detected_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        indicator.sha256_hash,
                        indicator.asset_id,
                        indicator.category,
                        indicator.identifier_key,
                        indicator.title,
                        indicator.data_source,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                return False, indicator.sha256_hash

            conn.execute(
                """
                INSERT INTO indicators (
                    sha256_hash, asset_id, category, indicator_type,
                    identifier_key, title, base_severity_s0, confidence_c,
                    is_cisa_kev, epss_score, control_factor_gamma,
                    decay_lambda, remediation_effort_e, observed_at_t0,
                    status, data_source
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    indicator.sha256_hash,
                    indicator.asset_id,
                    indicator.category,
                    indicator.indicator_type,
                    indicator.identifier_key,
                    indicator.title,
                    indicator.base_severity_s0,
                    indicator.confidence_c,
                    1 if indicator.is_cisa_kev else 0,
                    indicator.epss_score,
                    indicator.control_factor_gamma,
                    float(indicator.decay_lambda or 0.0),
                    indicator.remediation_effort_e,
                    indicator.observed_at_t0,
                    indicator.status,
                    indicator.data_source,
                ),
            )
            return True, indicator.sha256_hash

    def get_indicators(
        self,
        data_source: str | None = None,
        status: str | None = "OPEN",
        asset_id: str | None = None,
    ) -> list[ThreatIndicator]:
        """Fetch indicators matching the specified filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if data_source in ("REAL", "SIMULATED"):
            clauses.append("data_source = ?")
            params.append(data_source)
        if status in ("OPEN", "REMEDIATED"):
            clauses.append("status = ?")
            params.append(status)
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)

        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM indicators{where_sql} ORDER BY indicator_id ASC;"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            ThreatIndicator(
                indicator_id=int(row["indicator_id"]),
                sha256_hash=row["sha256_hash"],
                asset_id=row["asset_id"],
                category=row["category"],
                indicator_type=row["indicator_type"],
                identifier_key=row["identifier_key"],
                title=row["title"],
                base_severity_s0=float(row["base_severity_s0"]),
                confidence_c=float(row["confidence_c"]),
                is_cisa_kev=bool(row["is_cisa_kev"]),
                epss_score=float(row["epss_score"]),
                control_factor_gamma=float(row["control_factor_gamma"]),
                decay_lambda=float(row["decay_lambda"]),
                remediation_effort_e=float(row["remediation_effort_e"]),
                observed_at_t0=row["observed_at_t0"],
                status=row["status"],
                data_source=row["data_source"],
            )
            for row in rows
        ]

    def update_indicator_status(self, indicator_id: int, new_status: str) -> None:
        """Mark an indicator as OPEN or REMEDIATED and update its SHA-256 hash."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM indicators WHERE indicator_id = ?;", (indicator_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Indicator ID {indicator_id} not found.")

            updated = ThreatIndicator(
                indicator_id=int(row["indicator_id"]),
                asset_id=row["asset_id"],
                category=row["category"],
                indicator_type=row["indicator_type"],
                identifier_key=row["identifier_key"],
                title=row["title"],
                base_severity_s0=float(row["base_severity_s0"]),
                confidence_c=float(row["confidence_c"]),
                is_cisa_kev=bool(row["is_cisa_kev"]),
                epss_score=float(row["epss_score"]),
                control_factor_gamma=float(row["control_factor_gamma"]),
                decay_lambda=float(row["decay_lambda"]),
                remediation_effort_e=float(row["remediation_effort_e"]),
                observed_at_t0=row["observed_at_t0"],
                status=new_status,
                data_source=row["data_source"],
            )
            conn.execute(
                "UPDATE indicators SET status = ?, sha256_hash = ? WHERE indicator_id = ?;",
                (updated.status, updated.sha256_hash, indicator_id),
            )

    def get_deduplication_logs(
        self, data_source: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve SHA-256 collision logs."""
        query = "SELECT * FROM deduplication_log"
        params: list[Any] = []
        if data_source in ("REAL", "SIMULATED"):
            query += " WHERE data_source = ?"
            params.append(data_source)
        query += " ORDER BY log_id DESC;"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_risk_history(
        self, data_source: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve historical risk snapshots."""
        query = "SELECT * FROM risk_history"
        params: list[Any] = []
        if data_source in ("REAL", "SIMULATED"):
            query += " WHERE data_source = ?"
            params.append(data_source)
        query += " ORDER BY snapshot_id DESC LIMIT 30;"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ==========================================================================
    # RISK SNAPSHOT HISTORY & RESET OPERATIONS
    # ==========================================================================
    def save_risk_snapshot(self, summary: SystemRiskSummary) -> None:
        """Persist a system risk calculation snapshot to `risk_history`."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO risk_history (
                    evaluated_at, system_risk_score, risk_level,
                    max_asset_risk, weighted_mean_risk, total_assets,
                    active_indicator_count, data_source
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    summary.evaluated_at,
                    summary.system_risk_r_sys,
                    summary.system_risk_tier.value,
                    summary.max_asset_risk,
                    summary.weighted_mean_asset_risk,
                    summary.total_assets,
                    summary.total_open_indicators,
                    summary.data_source_filter,
                ),
            )

    def clear_data_by_source(self, data_source: str) -> None:
        """Delete assets, indicators, and logs for a specific data_source ('SIMULATED' or 'REAL')."""
        with self.get_connection() as conn:
            conn.execute(
                "DELETE FROM indicators WHERE data_source = ?;", (data_source,)
            )
            conn.execute("DELETE FROM assets WHERE data_source = ?;", (data_source,))
            conn.execute(
                "DELETE FROM deduplication_log WHERE data_source = ?;", (data_source,)
            )
            conn.execute(
                "DELETE FROM risk_history WHERE data_source = ?;", (data_source,)
            )
