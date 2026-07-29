#!/usr/bin/env python3
"""Validate one PETS 2027 Protocol 1.2 LLM smoke-test directory."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def _true(value: str) -> bool:
    return str(value).strip().lower() == "true"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--expect-environment", choices=("sgx", "python"))
    args = parser.parse_args()

    root = Path(args.run_dir)
    required = [
        root / "run.json",
        root / "vllm.json",
        root / "attestations.csv",
        root / "attestations.jsonl",
        root / "attestation_summary.json",
    ]
    failures = [f"missing {path.name}" for path in required if not path.is_file()]
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1

    with (root / "vllm.json").open(encoding="utf-8") as handle:
        vllm = json.load(handle)
    with (root / "attestation_summary.json").open(encoding="utf-8") as handle:
        summary = json.load(handle)
    with (root / "attestations.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    baseline = [row for row in rows if row["phase"] == "baseline"]
    measured = [row for row in rows if row["phase"] == "measurement"]
    completed = int(vllm.get("completed") or 0)
    environment = summary.get("environment")

    if completed < 1:
        failures.append("vLLM completed no requests")
    if len(baseline) != 1:
        failures.append(f"expected one baseline round, found {len(baseline)}")
    if len(measured) < 2:
        failures.append(
            f"expected at least two measured rounds, found {len(measured)}"
        )
    if not all(_true(row["overall_ok"]) for row in rows):
        failures.append("one or more attestation rounds failed")
    if measured and not any(
        row["verification_mode"] == "incremental-delta" for row in measured
    ):
        failures.append("no measured round used incremental-delta verification")
    if measured and not all(
        int(row["ima_wire_entries"] or 0) < int(row["ima_total_count"] or 0)
        for row in measured
        if int(row["ima_total_count"] or 0) > 0
    ):
        failures.append("at least one measured round sent a full IMA log")
    if environment == "sgx" and not all(
        _true(row["checkpoint_sealed"]) for row in rows
    ):
        failures.append("SGX run did not seal every successful checkpoint")
    if args.expect_environment and environment != args.expect_environment:
        failures.append(
            f"environment is {environment!r}, expected {args.expect_environment!r}"
        )

    fd_generations = {
        int(row["fd_generation"])
        for row in measured
        if row.get("fd_generation") not in ("", "0")
    }
    if len(fd_generations) > 1:
        failures.append(
            f"persistent IMA descriptor generation changed: {fd_generations}"
        )

    print("=" * 72)
    print("PETS 2027 vTPM/RTMR3 LLM smoke validation")
    print("=" * 72)
    print(f"run_dir:                 {root}")
    print(f"environment:             {environment}")
    print(f"vLLM completed requests: {completed}")
    print(f"baseline rounds:         {len(baseline)}")
    print(f"measured rounds:         {len(measured)}")
    print(
        "incremental rounds:      "
        f"{sum(r['verification_mode'] == 'incremental-delta' for r in measured)}"
    )
    print(f"fd generations:          {sorted(fd_generations)}")
    if measured:
        total_ms = [float(row["wall_ms"]) for row in measured]
        wire = [int(row["ima_wire_entries"]) for row in measured]
        print(f"measured wall ms:        {min(total_ms):.1f} .. {max(total_ms):.1f}")
        print(f"wire IMA entries:        {min(wire)} .. {max(wire)}")
    print(f"request throughput:      {vllm.get('request_throughput')}")
    print(f"output token throughput: {vllm.get('output_throughput')}")

    if failures:
        print("\nValidation: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("\nValidation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
