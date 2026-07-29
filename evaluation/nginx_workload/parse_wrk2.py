#!/usr/bin/env python3
"""
Parses wrk2 stdout (with --latency) into a structured JSON document
shaped to match what collect_results.py expects.

Output schema (mirrors evaluation/llm_workload/vllm.json key style):
  {
    "completed": int,
    "duration_sec": float,
    "request_throughput": float,        # req/s
    "transfer_per_sec_bytes": float,
    "bytes_total": float,
    "errors": {connect, read, write, timeout, non2xx_3xx},
    "latency_ms": {
        "mean": float, "stdev": float, "max": float,
        "p50": float, "p75": float, "p90": float,
        "p95": float, "p99": float, "p999": float, "p9999": float
    },
    "raw": "<verbatim wrk2 stdout>"
  }

Usage:
    wrk -t4 -c200 -d300s -R5000 --latency URL | parse_wrk2.py --out wrk.json
"""

import argparse
import json
import re
import sys


_UNIT_TO_MS = {
    "us": 1e-3,
    "ms": 1.0,
    "s":  1e3,
    "m":  60_000.0,
    "h":  3_600_000.0,
}


def to_ms(value: str) -> float:
    """e.g. '1.23ms' -> 1.23, '500us' -> 0.5, '1.50s' -> 1500.0"""
    m = re.match(r"^\s*([0-9.]+)\s*([a-zA-Z]+)\s*$", value)
    if not m:
        raise ValueError(f"cannot parse latency value: {value!r}")
    n = float(m.group(1))
    unit = m.group(2).lower()
    if unit not in _UNIT_TO_MS:
        raise ValueError(f"unknown latency unit: {unit!r}")
    return n * _UNIT_TO_MS[unit]


def to_bytes(value: str) -> float:
    """e.g. '50.00MB' -> 5e7, '1.67GB' -> 1.67e9"""
    m = re.match(r"^\s*([0-9.]+)\s*([KMGT]?B)\s*$", value)
    if not m:
        raise ValueError(f"cannot parse byte value: {value!r}")
    n = float(m.group(1))
    unit = m.group(2).upper()
    mult = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[unit]
    return n * mult


def to_count(value: str) -> float:
    """e.g. '2.50k' -> 2500.0, '1.20M' -> 1.2e6"""
    m = re.match(r"^\s*([0-9.]+)\s*([kKmMgG])?\s*$", value)
    if not m:
        raise ValueError(f"cannot parse count value: {value!r}")
    n = float(m.group(1))
    suffix = (m.group(2) or "").lower()
    mult = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9}[suffix]
    return n * mult


# Regex patterns for the wrk2 output blocks we care about.
RE_LATENCY_AVG = re.compile(
    r"Latency\s+([0-9.]+\s*[a-zA-Z]+)\s+([0-9.]+\s*[a-zA-Z]+)\s+"
    r"([0-9.]+\s*[a-zA-Z]+)"
)
RE_PCTL = re.compile(r"^\s*([0-9.]+)%\s+([0-9.]+\s*[a-zA-Z]+)\s*$")
RE_TOTAL = re.compile(
    r"^\s*([0-9]+)\s+requests in\s+([0-9.]+\s*[a-zA-Z]+),\s+"
    r"([0-9.]+[KMGT]?B)\s+read"
)
RE_RPS = re.compile(r"^Requests/sec:\s+([0-9.]+)")
RE_TPS = re.compile(r"^Transfer/sec:\s+([0-9.]+\s*[KMGT]?B)")
RE_SOCK_ERR = re.compile(
    r"Socket errors:\s+connect\s+(\d+),\s+read\s+(\d+),\s+"
    r"write\s+(\d+),\s+timeout\s+(\d+)"
)
RE_NON2XX = re.compile(r"Non-2xx or 3xx responses:\s+(\d+)")


# Percentiles we care to extract from the HdrHistogram block. wrk2's
# default block emits 50/75/90/99/99.9/99.99/99.999/100 — note the
# absence of 95. We keep p90 (which is what wrk2 gives us) instead of
# p95, since p90 is a perfectly valid tail metric and avoids needing a
# custom lua script to inject the 95.000% line.
WANTED_PCTLS = {
    "50.000": "p50",
    "75.000": "p75",
    "90.000": "p90",
    "99.000": "p99",
    "99.900": "p999",
    "99.990": "p9999",
}


def parse(text: str) -> dict:
    out = {
        "completed": None,
        "duration_sec": None,
        "request_throughput": None,
        "transfer_per_sec_bytes": None,
        "bytes_total": None,
        "errors": {
            "connect": 0, "read": 0, "write": 0, "timeout": 0, "non2xx_3xx": 0,
        },
        "latency_ms": {
            "mean": None, "stdev": None, "max": None,
            "p50": None, "p75": None, "p90": None,
            "p99": None, "p999": None, "p9999": None,
        },
        "raw": text,
    }

    in_hdr_block = False
    for line in text.splitlines():
        # Latency Distribution (HdrHistogram - Recorded Latency) block.
        # Lines after this header look like "  50.000%    1.23ms".
        if "Latency Distribution" in line:
            in_hdr_block = True
            continue
        if in_hdr_block:
            m = RE_PCTL.match(line)
            if m:
                pct = m.group(1)
                if pct in WANTED_PCTLS:
                    out["latency_ms"][WANTED_PCTLS[pct]] = to_ms(m.group(2))
                continue
            # Block ends on a non-percentile line.
            if line.strip() and "%" not in line:
                in_hdr_block = False

        if "Latency" in line and out["latency_ms"]["mean"] is None:
            m = RE_LATENCY_AVG.search(line)
            if m:
                out["latency_ms"]["mean"]  = to_ms(m.group(1))
                out["latency_ms"]["stdev"] = to_ms(m.group(2))
                out["latency_ms"]["max"]   = to_ms(m.group(3))

        m = RE_TOTAL.match(line)
        if m:
            out["completed"] = int(m.group(1))
            out["duration_sec"] = to_ms(m.group(2)) / 1000.0
            out["bytes_total"] = to_bytes(m.group(3))
            continue

        m = RE_RPS.match(line)
        if m:
            out["request_throughput"] = float(m.group(1))
            continue

        m = RE_TPS.match(line)
        if m:
            out["transfer_per_sec_bytes"] = to_bytes(m.group(1))
            continue

        m = RE_SOCK_ERR.search(line)
        if m:
            out["errors"]["connect"] = int(m.group(1))
            out["errors"]["read"]    = int(m.group(2))
            out["errors"]["write"]   = int(m.group(3))
            out["errors"]["timeout"] = int(m.group(4))
            continue

        m = RE_NON2XX.search(line)
        if m:
            out["errors"]["non2xx_3xx"] = int(m.group(1))
            continue

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="input", default="-",
                    help="path to wrk2 stdout text, or '-' for stdin")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input) as f:
            text = f.read()

    doc = parse(text)
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=2)
    print(f"[parse-wrk2] {doc['completed']} reqs, "
          f"{doc['request_throughput']} rps, "
          f"p99={doc['latency_ms']['p99']}ms → {args.out}")


if __name__ == "__main__":
    main()
