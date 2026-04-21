#!/usr/bin/env python3
"""
Join vllm.json + attest.csv + sampler.csv from a single run directory
into a per-run summary.json plus a master table across all runs found
under a root results directory.

Per-run summary (summary.json):
    {
      "run": { ...contents of run.json... },
      "latency": {
          "ttft_ms": {"mean":..., "p50":..., "p95":..., "p99":...},
          "itl_ms":  {"mean":..., "p50":..., "p95":..., "p99":...},
          "e2e_ms":  {"mean":..., "p50":..., "p95":..., "p99":...}
      },
      "throughput": {
          "request_per_s": ..., "output_token_per_s": ...
      },
      "attestation": {
          "rounds": N, "delta_n": {"mean":..., "p50":..., "p95":..., "max":...},
          "t_round_ms": {"mean":..., "p95":..., "max":...},
          "pcr_mismatches": 0
      },
      "ima": {
          "entries_start": N0, "entries_end": N1,
          "growth_per_min": ...
      }
    }

Also writes all_runs.csv (one row per run) at the root to drive plots.

Usage:
    python3 collect_results.py --root ../results/llm/2026-04-21T14-00
"""

import argparse
import csv
import json
import os
import statistics
import sys
from glob import glob


def q(values, p):
    if not values:
        return None
    s = sorted(values)
    k = min(len(s) - 1, max(0, int(round(p * (len(s) - 1)))))
    return s[k]


def stats(values):
    if not values:
        return {"mean": None, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "mean": round(statistics.fmean(values), 3),
        "p50":  round(q(values, 0.50), 3),
        "p95":  round(q(values, 0.95), 3),
        "p99":  round(q(values, 0.99), 3),
        "max":  round(max(values), 3),
    }


def summarize_vllm(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        doc = json.load(f)

    ttft = doc.get("ttfts") or doc.get("ttft_ms") or []
    itl = doc.get("itls") or []
    if isinstance(itl, list) and itl and isinstance(itl[0], list):
        itl_flat = [x for sub in itl for x in sub]
    else:
        itl_flat = list(itl) if itl else []
    e2e = doc.get("e2e_latencies") or doc.get("e2e_ms") or []

    # Convert s → ms where benchmark_serving reports seconds.
    def to_ms(vs):
        if not vs:
            return []
        # Heuristic: if p95 < 10 assume seconds, multiply.
        scale = 1000.0 if max(vs) < 10 else 1.0
        return [v * scale for v in vs]

    ttft_ms = to_ms(ttft)
    itl_ms = to_ms(itl_flat)
    e2e_ms = to_ms(e2e)

    return {
        "latency": {
            "ttft_ms": stats(ttft_ms),
            "itl_ms":  stats(itl_ms),
            "e2e_ms":  stats(e2e_ms),
        },
        "throughput": {
            "request_per_s":      doc.get("request_throughput"),
            "output_token_per_s": doc.get("output_throughput"),
            "total_token_per_s":  doc.get("total_token_throughput"),
        },
        "completed": doc.get("completed"),
    }


def summarize_attest(path):
    if not os.path.exists(path):
        return None
    rounds = []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            if not row.get("t_total_ms"):
                continue
            try:
                rounds.append({
                    "delta_n": int(row.get("delta_n") or 0),
                    "t_total_ms": float(row["t_total_ms"]),
                    "t_server_ima_read_ms": float(row.get("t_server_ima_read_ms") or 0),
                    "ima_data_kb": float(row.get("ima_data_kb") or 0),
                    "pcr_match": row.get("pcr_match") == "True",
                })
            except ValueError:
                continue

    if not rounds:
        return {"rounds": 0}

    dns = [r["delta_n"] for r in rounds]
    tots = [r["t_total_ms"] for r in rounds]
    srv = [r["t_server_ima_read_ms"] for r in rounds]
    return {
        "rounds": len(rounds),
        "delta_n": stats(dns),
        "t_round_ms": stats(tots),
        "t_server_read_ms": stats(srv),
        "pcr_mismatches": sum(1 for r in rounds if not r["pcr_match"]),
    }


def summarize_sampler(path, run_meta):
    if not os.path.exists(path):
        return None
    counts = []
    ts = []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                c = int(row["ima_entry_count"])
                t = float(row["ts_epoch"])
                if c >= 0:
                    counts.append(c)
                    ts.append(t)
            except (ValueError, KeyError):
                continue

    if len(counts) < 2:
        return {"samples": len(counts)}

    total_span_min = (ts[-1] - ts[0]) / 60.0
    growth = (counts[-1] - counts[0]) / max(total_span_min, 1e-6)
    return {
        "samples": len(counts),
        "ima_entries_start": counts[0],
        "ima_entries_end": counts[-1],
        "ima_growth_per_min": round(growth, 2),
    }


def summarize_run(run_dir):
    manifest = os.path.join(run_dir, "run.json")
    if not os.path.exists(manifest):
        return None
    with open(manifest) as f:
        run = json.load(f)

    s = {"run_dir": run_dir, "run": run}
    s["vllm"] = summarize_vllm(os.path.join(run_dir, "vllm.json"))
    s["attest"] = summarize_attest(os.path.join(run_dir, "attest.csv"))
    s["sampler"] = summarize_sampler(os.path.join(run_dir, "sampler.csv"), run)
    return s


def flatten_row(s):
    r = s["run"]
    v = s.get("vllm") or {}
    a = s.get("attest") or {}
    sm = s.get("sampler") or {}
    lat = (v.get("latency") or {})
    tp = (v.get("throughput") or {})
    return {
        "run_dir": s["run_dir"],
        "condition": r.get("condition"),
        "model_key": r.get("model_key"),
        "epoch_sec": r.get("epoch_sec"),
        "log_size": r.get("log_size"),
        "interleave": r.get("interleave"),
        "rps": r.get("rps"),
        "duration_sec": r.get("duration_sec"),
        "req_per_s": tp.get("request_per_s"),
        "out_tok_per_s": tp.get("output_token_per_s"),
        "ttft_p50_ms": (lat.get("ttft_ms") or {}).get("p50"),
        "ttft_p95_ms": (lat.get("ttft_ms") or {}).get("p95"),
        "ttft_p99_ms": (lat.get("ttft_ms") or {}).get("p99"),
        "itl_p50_ms":  (lat.get("itl_ms") or {}).get("p50"),
        "itl_p95_ms":  (lat.get("itl_ms") or {}).get("p95"),
        "itl_p99_ms":  (lat.get("itl_ms") or {}).get("p99"),
        "attest_rounds": a.get("rounds"),
        "delta_n_p50": (a.get("delta_n") or {}).get("p50"),
        "delta_n_p95": (a.get("delta_n") or {}).get("p95"),
        "delta_n_max": (a.get("delta_n") or {}).get("max"),
        "t_round_p95_ms": (a.get("t_round_ms") or {}).get("p95"),
        "pcr_mismatches": a.get("pcr_mismatches"),
        "ima_growth_per_min": sm.get("ima_growth_per_min"),
        "ima_entries_end": sm.get("ima_entries_end"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True,
                    help="Root results directory (contains one subdir per run)")
    args = ap.parse_args()

    runs = []
    for manifest in glob(os.path.join(args.root, "**", "run.json"), recursive=True):
        run_dir = os.path.dirname(manifest)
        try:
            s = summarize_run(run_dir)
            if s is None:
                continue
            with open(os.path.join(run_dir, "summary.json"), "w") as f:
                json.dump(s, f, indent=2, default=str)
            runs.append(s)
        except Exception as e:
            print(f"[collect] failed {run_dir}: {e}", file=sys.stderr)

    if not runs:
        print("[collect] no runs found under", args.root, file=sys.stderr)
        sys.exit(1)

    rows = [flatten_row(r) for r in runs]
    out_csv = os.path.join(args.root, "all_runs.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[collect] {len(rows)} runs → {out_csv}")


if __name__ == "__main__":
    main()
