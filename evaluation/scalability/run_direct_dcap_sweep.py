#!/usr/bin/env python3
"""Run a direct-DCAP scalability sweep using the existing libtdx_attest benchmark."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

from common import ensure_dir, parse_int_list, percentile, summarize_samples, write_csv


REPO_ROOT = Path(__file__).resolve().parents[2]
DCAP_DIR = REPO_ROOT / "research" / "tdx-dcap-attestation"
sys.path.insert(0, str(DCAP_DIR))

from dcap_with_library import run_benchmark  # type: ignore  # noqa: E402


def effective_wall_time(result: Any) -> float:
    wall = getattr(result, "_wall_time_s", None)
    if wall is not None:
        return float(wall)
    return float(result.total_time_s)


def effective_throughput(result: Any) -> float:
    wall_time = effective_wall_time(result)
    if wall_time <= 0:
        return 0.0
    return float(result.successful) / wall_time


def one_run(method: str, count: int, users: int, ita_config: str, ita_delay: float) -> tuple[dict[str, Any], dict[str, Any]]:
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    bench = run_benchmark(
        method=method,
        count=count,
        threads=users,
        verbose=False,
        ita_config=ita_config,
        ita_delay=ita_delay,
    )
    latencies = list(getattr(bench, "times_ms", []))
    latency_summary = summarize_samples(latencies)
    wall_time_s = effective_wall_time(bench)
    throughput_rps = effective_throughput(bench)

    summary = {
        "model": "direct-dcap",
        "method": method,
        "count": count,
        "users": users,
        "successful": bench.successful,
        "failed": bench.failed,
        "error_rate_pct": (bench.failed / count * 100.0) if count else 0.0,
        "wall_time_s": round(wall_time_s, 4),
        "throughput_rps": round(throughput_rps, 3),
        "mean_ms": round(latency_summary["mean"], 3),
        "median_ms": round(latency_summary["median"], 3),
        "p95_ms": round(latency_summary["p95"], 3),
        "p99_ms": round(latency_summary["p99"], 3),
        "min_ms": round(latency_summary["min"], 3),
        "max_ms": round(latency_summary["max"], 3),
        "stdev_ms": round(latency_summary["stdev"], 3),
        "host": socket.gethostname(),
        "timestamp": started_at,
    }

    raw = {
        "summary": summary,
        "raw_latencies_ms": latencies,
    }
    return summary, raw


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Direct DCAP scalability sweep (fresh quote per request).",
    )
    parser.add_argument(
        "--method",
        default="libtdx_attest",
        help="Benchmark method from dcap_with_library.py (default: libtdx_attest)",
    )
    parser.add_argument(
        "--counts",
        default="500",
        help="Comma-separated request counts to run per user level (default: 500)",
    )
    parser.add_argument(
        "--users",
        default="1,2,4,8,16,32",
        help="Comma-separated concurrency levels, interpreted as concurrent end users (default: 1,2,4,8,16,32)",
    )
    parser.add_argument(
        "--ita-config",
        default=os.path.expanduser("~/config.json"),
        help="ITA config path for the ita method",
    )
    parser.add_argument(
        "--ita-delay",
        type=float,
        default=0.5,
        help="ITA pacing delay in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "evaluation" / "results" / "scalability" / time.strftime("direct-dcap-%Y%m%d-%H%M%S")),
        help="Directory for CSV/JSON outputs",
    )
    args = parser.parse_args()

    counts = parse_int_list(args.counts)
    users_list = parse_int_list(args.users)
    out_dir = ensure_dir(Path(args.out_dir))

    summaries: list[dict[str, Any]] = []
    raws: list[dict[str, Any]] = []

    print("=" * 72)
    print("Direct DCAP Scalability Sweep")
    print("=" * 72)
    print(f"Method:   {args.method}")
    print(f"Counts:   {counts}")
    print(f"Users:    {users_list}")
    print(f"Out dir:  {out_dir}")
    print("=" * 72)

    for count in counts:
        for users in users_list:
            print(f"\n[direct-dcap] count={count} users={users}")
            summary, raw = one_run(args.method, count, users, args.ita_config, args.ita_delay)
            summaries.append(summary)
            raws.append(raw)
            print(
                "  "
                f"ok={summary['successful']}/{count} "
                f"throughput={summary['throughput_rps']:.2f} rps "
                f"mean={summary['mean_ms']:.2f}ms "
                f"p99={summary['p99_ms']:.2f}ms"
            )

    write_csv(out_dir / "direct_dcap_summary.csv", summaries)
    (out_dir / "direct_dcap_raw.json").write_text(
        json.dumps(raws, indent=2),
        encoding="utf-8",
    )

    print(f"\nSaved summary to: {out_dir / 'direct_dcap_summary.csv'}")
    print(f"Saved raw data to: {out_dir / 'direct_dcap_raw.json'}")


if __name__ == "__main__":
    main()

