#!/usr/bin/env python3
"""Generate comparison plots for direct DCAP vs single-WEN Vordr scalability."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt

from scale_common import ensure_dir


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def as_float(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    return float(value) if value else 0.0


def as_int(row: dict[str, str], key: str) -> int:
    value = row.get(key, "")
    return int(float(value)) if value else 0


def pick_direct_rows(rows: list[dict[str, str]], count_filter: int | None) -> list[dict[str, str]]:
    if not rows:
        return []
    if count_filter is None:
        count_filter = max(as_int(row, "count") for row in rows)
    filtered = [row for row in rows if as_int(row, "count") == count_filter]
    return sorted(filtered, key=lambda row: as_int(row, "users"))


def plot_throughput(direct_rows: list[dict[str, str]], vordr_rows: list[dict[str, str]], out_path: Path) -> None:
    plt.figure(figsize=(7.2, 4.6))
    if direct_rows:
        plt.plot(
            [as_int(row, "users") for row in direct_rows],
            [as_float(row, "throughput_rps") for row in direct_rows],
            marker="o",
            linewidth=2.2,
            color="#8f1d21",
            label="Direct DCAP",
        )
    if vordr_rows:
        plt.plot(
            [as_int(row, "users") for row in vordr_rows],
            [as_float(row, "throughput_rps") for row in vordr_rows],
            marker="s",
            linewidth=2.2,
            color="#1f4e79",
            label="Vordr (single WEN)",
        )
    plt.xlabel("Concurrent end users")
    plt.ylabel("Throughput (attestations/s)")
    plt.xscale("log", base=2)
    plt.grid(alpha=0.25)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_latency(direct_rows: list[dict[str, str]], vordr_rows: list[dict[str, str]], out_path: Path) -> None:
    plt.figure(figsize=(7.2, 4.6))
    if direct_rows:
        plt.plot(
            [as_int(row, "users") for row in direct_rows],
            [as_float(row, "p99_ms") for row in direct_rows],
            marker="o",
            linewidth=2.2,
            color="#8f1d21",
            label="Direct DCAP P99",
        )
    if vordr_rows:
        plt.plot(
            [as_int(row, "users") for row in vordr_rows],
            [as_float(row, "p99_ms") for row in vordr_rows],
            marker="s",
            linewidth=2.2,
            color="#1f4e79",
            label="Vordr P99",
        )
    plt.xlabel("Concurrent end users")
    plt.ylabel("P99 latency (ms)")
    plt.xscale("log", base=2)
    plt.yscale("log", base=10)
    plt.grid(alpha=0.25)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_amplification(vordr_rows: list[dict[str, str]], out_path: Path) -> None:
    plt.figure(figsize=(7.2, 4.6))
    users = [as_int(row, "users") for row in vordr_rows]
    amps = [as_float(row, "amplification_total_refreshes") for row in vordr_rows]
    plt.bar(users, amps, width=0.6, color="#3f6b48")
    plt.xlabel("Concurrent end users")
    plt.ylabel("End-user attestations per TDX refresh")
    plt.xscale("log", base=2)
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot direct DCAP vs Vordr scalability results")
    parser.add_argument("--direct-csv", required=True)
    parser.add_argument("--vordr-csv", required=True)
    parser.add_argument("--direct-count", type=int, default=None)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = ensure_dir(Path(args.out_dir))
    direct_rows = pick_direct_rows(load_rows(Path(args.direct_csv)), args.direct_count)
    vordr_rows = sorted(load_rows(Path(args.vordr_csv)), key=lambda row: as_int(row, "users"))

    plot_throughput(direct_rows, vordr_rows, out_dir / "fig_scalability_throughput.pdf")
    plot_latency(direct_rows, vordr_rows, out_dir / "fig_scalability_p99.pdf")
    plot_amplification(vordr_rows, out_dir / "fig_scalability_amplification.pdf")

    print(f"Saved plots to: {out_dir}")


if __name__ == "__main__":
    main()
