#!/usr/bin/env python3
"""
Joins wrk.json + attest.csv + sampler.csv from each cell directory under
--root into a per-cell summary.json plus a flat all_runs.csv at the root.

Per-cell summary.json:
  {
    "run": { ...contents of run.json, plus rep extracted from path... },
    "wrk": {
        "completed": int,
        "duration_sec": float,
        "throughput": {"request_per_s": ..., "transfer_bytes_per_s": ..., "bytes_total": ...},
        "latency": {"request_ms": {mean, p50, p95, p99, p999, max, ...}},
        "errors": {connect, read, write, timeout, non2xx_3xx}
    },
    "attest": {
        "rounds": N,
        "delta_n":  {mean, p50, p95, max},
        "t_round_ms": {mean, p95, max},
        "t_server_read_ms": {mean, p95, max},
        "pcr_mismatches": int
    },
    "sampler": {
        "samples": N,
        "ima_entries_start": ..., "ima_entries_end": ...,
        "ima_growth_per_min": ...
    }
  }

Usage:
    python3 collect_results.py --root ../results/nginx/matrix-1kb-20260426
"""

import argparse
import csv
import json
import os
import re
import statistics
import sys
from glob import glob


REP_RE = re.compile(r"_rep(\d+)$")


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


def summarize_wrk(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        doc = json.load(f)

    lat = doc.get("latency_ms") or {}
    return {
        "completed": doc.get("completed"),
        "duration_sec": doc.get("duration_sec"),
        "throughput": {
            "request_per_s":         doc.get("request_throughput"),
            "transfer_bytes_per_s":  doc.get("transfer_per_sec_bytes"),
            "bytes_total":           doc.get("bytes_total"),
        },
        "latency": {
            "request_ms": {
                "mean":  lat.get("mean"),
                "stdev": lat.get("stdev"),
                "p50":   lat.get("p50"),
                "p75":   lat.get("p75"),
                "p90":   lat.get("p90"),
                "p99":   lat.get("p99"),
                "p999":  lat.get("p999"),
                "p9999": lat.get("p9999"),
                "max":   lat.get("max"),
            },
        },
        "errors": doc.get("errors") or {},
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
                    "runtime_verdict": row.get("runtime_verdict") or "",
                })
            except ValueError:
                continue

    if not rounds:
        return {"rounds": 0}

    # A real PCR mismatch only counts when there were new IMA entries to
    # verify (Δn > 0) AND pcr_match is False. When Δn=0 the agent reports
    # pcr_match=False because the field doesn't apply (verdict is
    # CLEAN_NO_DELTA), and counting that as a security failure inflates
    # the mismatch number meaninglessly.
    real_mismatches = sum(
        1 for r in rounds
        if r["delta_n"] > 0 and not r["pcr_match"]
    )
    no_delta_rounds = sum(1 for r in rounds if r["delta_n"] == 0)

    return {
        "rounds": len(rounds),
        "rounds_with_delta": len(rounds) - no_delta_rounds,
        "rounds_no_delta": no_delta_rounds,
        "delta_n":          stats([r["delta_n"] for r in rounds]),
        "t_round_ms":       stats([r["t_total_ms"] for r in rounds]),
        "t_server_read_ms": stats([r["t_server_ima_read_ms"] for r in rounds]),
        "pcr_mismatches":   real_mismatches,
    }


def summarize_sampler(path):
    if not os.path.exists(path):
        return None
    counts, ts = [], []
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

    span_min = (ts[-1] - ts[0]) / 60.0
    growth = (counts[-1] - counts[0]) / max(span_min, 1e-6)
    return {
        "samples": len(counts),
        "ima_entries_start": counts[0],
        "ima_entries_end": counts[-1],
        "ima_growth_per_min": round(growth, 2),
    }


def extract_rep_from_path(run_dir):
    m = REP_RE.search(os.path.basename(run_dir))
    return int(m.group(1)) if m else 1


def summarize_run(run_dir):
    manifest = os.path.join(run_dir, "run.json")
    if not os.path.exists(manifest):
        return None
    with open(manifest) as f:
        run = json.load(f)
    run["rep"] = extract_rep_from_path(run_dir)

    return {
        "run_dir": run_dir,
        "run": run,
        "wrk":     summarize_wrk(os.path.join(run_dir, "wrk.json")),
        "attest":  summarize_attest(os.path.join(run_dir, "attest.csv")),
        "sampler": summarize_sampler(os.path.join(run_dir, "sampler.csv")),
    }


def flatten_row(s):
    r = s["run"]
    w = s.get("wrk") or {}
    a = s.get("attest") or {}
    sm = s.get("sampler") or {}
    lat = ((w.get("latency") or {}).get("request_ms") or {})
    tp = (w.get("throughput") or {})
    err = (w.get("errors") or {})
    return {
        "run_dir": s["run_dir"],
        "condition": r.get("condition"),
        "payload": r.get("payload"),
        "epoch_sec": r.get("epoch_sec"),
        "log_size": r.get("log_size"),
        "interleave": r.get("interleave"),
        "rep": r.get("rep"),
        "rps_target": r.get("rps"),
        "duration_sec": r.get("duration_sec"),
        "completed": w.get("completed"),
        "req_per_s": tp.get("request_per_s"),
        "bytes_per_s": tp.get("transfer_bytes_per_s"),
        "lat_p50_ms":  lat.get("p50"),
        "lat_p90_ms":  lat.get("p90"),
        "lat_p99_ms":  lat.get("p99"),
        "lat_p999_ms": lat.get("p999"),
        "lat_max_ms":  lat.get("max"),
        "errors_timeout": err.get("timeout"),
        "errors_non2xx":  err.get("non2xx_3xx"),
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
                    help="Root results directory (contains <condition>/<tag>/run.json)")
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
        print(f"[collect] no runs under {args.root}", file=sys.stderr)
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
