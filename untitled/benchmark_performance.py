"""
benchmark_performance.py
Empirical Performance & Memory Benchmarking Script for the Lightweight Cybersecurity
Risk Scoring System for SMEs.

Generates and measures real execution time (ms / seconds) and peak memory usage (MB)
via `time.perf_counter()` and `tracemalloc` across two stress scenarios:
- Scenario A: 150 synthetic SME assets + 1,000 synthetic cybersecurity indicators
- Scenario B: 150 synthetic SME assets + 10,000 synthetic cybersecurity indicators

Measures:
1. Dataset Generation & Normalisation Time
2. SQLite Batch Insertion + SHA-256 Deduplication Time
3. Full Portfolio Risk Evaluation Time (w_i, D(t,t0), Phi_ik, S(I_ik,t), R_i(t), R_sys)
4. Counterfactual Leave-One-Out Remediation Priority Index (RPI) Time
5. Peak Memory Allocation (MB)

Compatible with Python 3.11+.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import time
import tracemalloc
from typing import Any

from config import AssetType, DataSource, IndicatorCategory
from database import DatabaseManager
from engine.prioritiser import (
    compute_asset_remediation_priorities,
    rank_system_remediation_plan,
)
from engine.risk_calculator import evaluate_system_portfolio
from models import Asset, ThreatIndicator

CATEGORIES_LIST: list[str] = [
    IndicatorCategory.EXTERNAL_CTI.value,
    IndicatorCategory.PERIMETER_EXPOSURE.value,
    IndicatorCategory.ENDPOINT_PATCH.value,
    IndicatorCategory.IDENTITY_AUTH.value,
]

ASSET_TYPES_LIST: list[str] = [
    AssetType.SERVER.value,
    AssetType.WORKSTATION.value,
    AssetType.NETWORK_DEVICE.value,
    AssetType.CLOUD_IDENTITY.value,
    AssetType.DATABASE.value,
    AssetType.WEB_APPLICATION.value,
]


def generate_benchmark_assets(count: int, ref_time: datetime) -> list[Asset]:
    """Deterministically generate `count` synthetic SME assets (default: 150)."""
    created_str = ref_time.isoformat()
    assets: list[Asset] = []
    for i in range(1, count + 1):
        crit = (i % 5) + 1  # Cycles 1..5
        is_wan = (i % 3) == 0
        a_type = ASSET_TYPES_LIST[i % len(ASSET_TYPES_LIST)]
        assets.append(
            Asset(
                asset_id=f"BENCH-AST-{i:04d}",
                asset_name=f"Synthetic SME Benchmark Asset #{i:04d}",
                asset_type=a_type,
                criticality_score=crit,
                is_internet_facing=is_wan,
                owner_department=f"Dept-{(i % 6) + 1}",
                ip_or_hostname=f"10.20.{(i // 250) % 255}.{(i % 250) + 1}",
                data_source=DataSource.SIMULATED.value,
                created_at=created_str,
            )
        )
    return assets


def generate_benchmark_indicators(
    indicator_count: int,
    asset_count: int,
    ref_time: datetime,
) -> list[ThreatIndicator]:
    """
    Deterministically generate `indicator_count` synthetic threat indicators distributed
    across `asset_count` SME assets, including a 5% intentional duplicate rate to benchmark
    SHA-256 collision handling under load.
    """
    indicators: list[ThreatIndicator] = []
    for k in range(1, indicator_count + 1):
        # Every 20th indicator intentionally repeats the previous key to test SHA-256 deduplication
        effective_k = k - 1 if (k > 1 and k % 20 == 0) else k

        target_asset_num = ((effective_k - 1) % asset_count) + 1
        asset_id = f"BENCH-AST-{target_asset_num:04d}"
        cat = CATEGORIES_LIST[effective_k % len(CATEGORIES_LIST)]

        s0 = round(0.35 + ((effective_k * 7) % 60) / 100.0, 2)       # 0.35 .. 0.94
        conf = round(0.65 + ((effective_k * 11) % 35) / 100.0, 2)    # 0.65 .. 0.99
        is_kev = (effective_k % 15) == 0
        epss = round(((effective_k * 13) % 95) / 100.0, 2)
        gamma = round(0.40 + ((effective_k * 3) % 60) / 100.0, 2)    # 0.40 .. 0.99
        effort = float((effective_k % 5) + 1)
        obs_t0 = (ref_time - timedelta(days=float(effective_k % 30))).isoformat()

        indicators.append(
            ThreatIndicator(
                asset_id=asset_id,
                category=cat,
                indicator_type=f"BENCH_TYPE_{(effective_k % 8) + 1}",
                identifier_key=f"BENCH-IND-{effective_k:06d}",
                title=f"Synthetic benchmark threat indicator #{effective_k}",
                base_severity_s0=s0,
                confidence_c=conf,
                is_cisa_kev=is_kev,
                epss_score=epss,
                control_factor_gamma=gamma,
                remediation_effort_e=effort,
                observed_at_t0=obs_t0,
                data_source=DataSource.SIMULATED.value,
            )
        )
    return indicators


def run_single_benchmark_scenario(
    asset_count: int,
    indicator_count: int,
) -> dict[str, Any]:
    """
    Execute a single benchmark scenario in an isolated temporary SQLite database
    and return actual measured timings and memory usage.
    """
    ref_time = datetime.now(timezone.utc)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / f"bench_{asset_count}_{indicator_count}.db"

        tracemalloc.start()
        t_start_total = time.perf_counter()

        # 1. Model Generation & Normalisation + SHA-256 Hashing
        t0 = time.perf_counter()
        assets = generate_benchmark_assets(asset_count, ref_time)
        indicators = generate_benchmark_indicators(
            indicator_count=indicator_count,
            asset_count=asset_count,
            ref_time=ref_time,
        )
        t_generation_sec = time.perf_counter() - t0

        # 2. SQLite Persistence & SHA-256 Deduplication
        t1 = time.perf_counter()
        db = DatabaseManager(db_path=db_path)
        with db.get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO assets (
                    asset_id, asset_name, asset_type, criticality_score,
                    is_internet_facing, owner_department, ip_or_hostname,
                    data_source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                [
                    (
                        a.asset_id,
                        a.asset_name,
                        a.asset_type,
                        a.criticality_score,
                        1 if a.is_internet_facing else 0,
                        a.owner_department,
                        a.ip_or_hostname,
                        a.data_source,
                        a.created_at,
                    )
                    for a in assets
                ],
            )

            seen_hashes: set[str] = set()
            unique_rows: list[tuple[Any, ...]] = []
            duplicate_rows: list[tuple[Any, ...]] = []

            for ind in indicators:
                if ind.sha256_hash in seen_hashes:
                    duplicate_rows.append(
                        (
                            ind.sha256_hash,
                            ind.asset_id,
                            ind.category,
                            ind.identifier_key,
                            ind.title,
                            ind.data_source,
                            ref_time.isoformat(),
                        )
                    )
                else:
                    seen_hashes.add(ind.sha256_hash)
                    unique_rows.append(
                        (
                            ind.sha256_hash,
                            ind.asset_id,
                            ind.category,
                            ind.indicator_type,
                            ind.identifier_key,
                            ind.title,
                            ind.base_severity_s0,
                            ind.confidence_c,
                            1 if ind.is_cisa_kev else 0,
                            ind.epss_score,
                            ind.control_factor_gamma,
                            float(ind.decay_lambda or 0.0),
                            ind.remediation_effort_e,
                            ind.observed_at_t0,
                            ind.status,
                            ind.data_source,
                        )
                    )

            conn.executemany(
                """
                INSERT INTO indicators (
                    sha256_hash, asset_id, category, indicator_type,
                    identifier_key, title, base_severity_s0, confidence_c,
                    is_cisa_kev, epss_score, control_factor_gamma,
                    decay_lambda, remediation_effort_e, observed_at_t0,
                    status, data_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                unique_rows,
            )
            conn.executemany(
                """
                INSERT INTO deduplication_log (
                    sha256_hash, asset_id, category, identifier_key,
                    title, data_source, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                duplicate_rows,
            )
        t_sqlite_sec = time.perf_counter() - t1

        # 3. Dynamic Risk Scoring Engine (150 assets + all unique indicators)
        t2 = time.perf_counter()
        stored_assets = db.get_assets(data_source=DataSource.SIMULATED.value)
        stored_open_inds = db.get_indicators(
            data_source=DataSource.SIMULATED.value, status="OPEN"
        )
        asset_results, r_sys, max_r_i, weighted_mean_r_i = evaluate_system_portfolio(
            assets=stored_assets,
            open_indicators=stored_open_inds,
            evaluation_time_t=ref_time,
        )
        t_scoring_sec = time.perf_counter() - t2

        # 4. Counterfactual Leave-One-Out RPI Prioritisation Engine
        t3 = time.perf_counter()
        inds_by_asset: dict[str, list[ThreatIndicator]] = {
            a.asset_id: [] for a in stored_assets
        }
        for ind in stored_open_inds:
            inds_by_asset[ind.asset_id].append(ind)

        unranked_rpi = []
        for res_i in asset_results:
            unranked_rpi.extend(
                compute_asset_remediation_priorities(
                    asset=res_i.asset,
                    weight_w_i=res_i.weight_w_i,
                    asset_indicators=inds_by_asset[res_i.asset.asset_id],
                    current_asset_risk_r_i=res_i.risk_score_r_i,
                    evaluation_time_t=ref_time,
                )
            )
        ranked_rpi = rank_system_remediation_plan(unranked_rpi)
        t_rpi_sec = time.perf_counter() - t3

        total_elapsed_sec = time.perf_counter() - t_start_total
        current_mem_bytes, peak_mem_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return {
            "scenario_name": f"{asset_count} Assets / {indicator_count:,} Indicators",
            "assets_generated": asset_count,
            "indicators_generated": indicator_count,
            "unique_indicators_inserted": len(unique_rows),
            "duplicates_suppressed_sha256": len(duplicate_rows),
            "computed_system_risk_r_sys": round(r_sys, 2),
            "computed_max_asset_risk": round(max_r_i, 2),
            "computed_weighted_mean_risk": round(weighted_mean_r_i, 2),
            "rpi_items_ranked": len(ranked_rpi),
            "generation_and_hashing_ms": round(t_generation_sec * 1000.0, 2),
            "sqlite_dedup_insert_ms": round(t_sqlite_sec * 1000.0, 2),
            "risk_scoring_engine_ms": round(t_scoring_sec * 1000.0, 2),
            "counterfactual_rpi_ms": round(t_rpi_sec * 1000.0, 2),
            "total_execution_time_ms": round(total_elapsed_sec * 1000.0, 2),
            "total_execution_time_sec": round(total_elapsed_sec, 4),
            "peak_memory_mb": round(peak_mem_bytes / (1024.0 * 1024.0), 3),
            "current_memory_mb": round(current_mem_bytes / (1024.0 * 1024.0), 3),
        }


def run_full_benchmark_suite() -> list[dict[str, Any]]:
    """Run both required stress-test scenarios (150 assets with 1,000 and 10,000 indicators)."""
    return [
        run_single_benchmark_scenario(asset_count=150, indicator_count=1000),
        run_single_benchmark_scenario(asset_count=150, indicator_count=10000),
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Performance & Memory Benchmark for SME Cyber Risk Scorer"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit benchmark results as JSON.",
    )
    args = parser.parse_args()

    results = run_full_benchmark_suite()
    if args.json:
        print(json.dumps({"ok": True, "benchmarks": results}))
    else:
        print("=" * 92)
        print("EMPIRICAL PERFORMANCE & MEMORY BENCHMARK REPORT (MEASURED AT RUNTIME)")
        print("=" * 92)
        for r in results:
            print(f"Scenario                    : {r['scenario_name']}")
            print(
                f"  Records Processed         : {r['assets_generated']} Assets | "
                f"{r['indicators_generated']:,} Raw Indicators -> "
                f"{r['unique_indicators_inserted']:,} Unique + "
                f"{r['duplicates_suppressed_sha256']:,} SHA-256 Duplicates Blocked"
            )
            print(
                f"  Generation & SHA-256 Time : {r['generation_and_hashing_ms']:.2f} ms"
            )
            print(
                f"  SQLite Insert & Dedup Time: {r['sqlite_dedup_insert_ms']:.2f} ms"
            )
            print(
                f"  Dynamic Risk Scoring Time : {r['risk_scoring_engine_ms']:.2f} ms"
            )
            print(
                f"  Counterfactual RPI Time   : {r['counterfactual_rpi_ms']:.2f} ms"
            )
            print(
                f"  TOTAL EXECUTION TIME      : {r['total_execution_time_ms']:.2f} ms "
                f"({r['total_execution_time_sec']:.4f} s)"
            )
            print(
                f"  PEAK MEMORY ALLOCATION    : {r['peak_memory_mb']:.3f} MB"
            )
            print("-" * 92)
