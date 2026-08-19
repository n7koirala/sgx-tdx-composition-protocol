#!/usr/bin/env python3
"""Summarize measured protocol-1.2 Mode 2 and Mode 3 scalability runs."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


MODE_LABELS = {
    "ima-audit": "IMA-Audit RA (Mode 2)",
    "full-audit": "Full-Audit RA (Mode 3)",
}


def as_float(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    return float(value) if value else 0.0


def as_int(row: dict[str, str], key: str) -> int:
    return int(round(as_float(row, key)))


def mean(rows: list[dict[str, str]], key: str) -> float:
    return statistics.fmean(as_float(row, key) for row in rows)


def stdev(rows: list[dict[str, str]], key: str) -> float:
    values = [as_float(row, key) for row in rows]
    return statistics.stdev(values) if len(values) > 1 else 0.0


def parse_input(raw: str) -> tuple[str, int, Path]:
    try:
        mode, nominal_entries, path = raw.split(":", 2)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "--input must have MODE:N:CSV form"
        ) from exc
    if mode not in MODE_LABELS:
        raise argparse.ArgumentTypeError(
            f"MODE must be one of: {', '.join(MODE_LABELS)}"
        )
    try:
        entries = int(nominal_entries)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("N must be an integer") from exc
    csv_path = Path(path).expanduser()
    if not csv_path.is_file():
        raise argparse.ArgumentTypeError(f"CSV does not exist: {csv_path}")
    return mode, entries, csv_path


def load_validated_rows(
    mode: str, path: Path
) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"empty CSV: {path}")
    problems: list[str] = []
    for line, row in enumerate(rows, start=2):
        if row.get("evidence_mode") != mode:
            problems.append(
                f"line {line}: evidence_mode={row.get('evidence_mode')!r}"
            )
        if as_int(row, "failed") != 0:
            problems.append(f"line {line}: failed={row.get('failed')}")
        if row.get("tdx_verdict") != "TRUSTED":
            problems.append(
                f"line {line}: tdx_verdict={row.get('tdx_verdict')!r}"
            )
        if row.get("tdx_runtime_verdict") != "CLEAN":
            problems.append(
                f"line {line}: runtime={row.get('tdx_runtime_verdict')!r}"
            )
        raw_quote_bytes = as_float(row, "mean_raw_quote_bytes")
        if mode == "ima-audit" and raw_quote_bytes != 0:
            problems.append(
                f"line {line}: Mode 2 exposed {raw_quote_bytes:g} raw-quote bytes"
            )
        if mode == "full-audit" and raw_quote_bytes <= 0:
            problems.append(f"line {line}: Mode 3 omitted the raw quote")
    if problems:
        detail = "\n  ".join(problems[:20])
        raise ValueError(f"invalid audit run {path}:\n  {detail}")
    return rows


def summarize(mode: str, nominal_entries: int, path: Path) -> dict[str, str]:
    rows = load_validated_rows(mode, path)
    by_users: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_users[as_int(row, "users")].append(row)
    peak_users, peak_rows = max(
        by_users.items(),
        key=lambda item: mean(item[1], "throughput_rps"),
    )
    return {
        "mode": mode,
        "mode_label": MODE_LABELS[mode],
        "nominal_ima_entries": str(nominal_entries),
        "measured_mean_ima_entries": f"{mean(peak_rows, 'mean_ima_entries'):.1f}",
        "peak_users": str(peak_users),
        "repetitions": str(len(peak_rows)),
        "wire_bytes": f"{mean(peak_rows, 'mean_response_payload_bytes'):.1f}",
        "wire_mib": f"{mean(peak_rows, 'mean_response_payload_bytes') / 2**20:.3f}",
        "raw_ima_mib": f"{mean(peak_rows, 'mean_ima_log_bytes') / 2**20:.3f}",
        "command_log_mib": f"{mean(peak_rows, 'mean_command_log_bytes') / 2**20:.3f}",
        "raw_quote_kib": f"{mean(peak_rows, 'mean_raw_quote_bytes') / 2**10:.3f}",
        "throughput_rps": f"{mean(peak_rows, 'throughput_rps'):.3f}",
        "throughput_stdev_rps": f"{stdev(peak_rows, 'throughput_rps'):.3f}",
        "median_latency_ms": f"{mean(peak_rows, 'median_ms'):.3f}",
        "p99_latency_ms": f"{mean(peak_rows, 'p99_ms'):.3f}",
        "source_csv": str(path),
    }


def write_csv(rows: list[dict[str, str]], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_tex_table(rows: list[dict[str, str]], path: Path) -> None:
    body = []
    for row in rows:
        body.append(
            f"{row['mode_label']} & {int(row['nominal_ima_entries']):,} & "
            f"{row['wire_mib']} & {row['throughput_rps']} & "
            f"{row['median_latency_ms']} & {row['p99_latency_ms']} \\\\"
        )
    text = "\n".join(
        [
            r"\begin{table}[t]",
            r"\centering",
            r"\small",
            r"\setlength{\tabcolsep}{3.5pt}",
            r"\begin{tabular}{lrrrrr}",
            r"\toprule",
            r"Mode & IMA $N$ & Wire (MiB) & Resp./s & Median (ms) & p99 (ms) \\",
            r"\midrule",
            *body,
            r"\bottomrule",
            r"\end{tabular}",
            r"\caption{Measured audit-response serving cost. Each response is authenticated by the SGX WEN; Mode~2 omits the raw TDX quote, whereas Mode~3 includes it.}",
            r"\label{tab:audit-mode-serving}",
            r"\end{table}",
            "",
        ]
    )
    path.write_text(text, encoding="utf-8")


def write_discussion(rows: list[dict[str, str]], path: Path) -> None:
    by_n: dict[int, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rows:
        by_n[int(row["nominal_ima_entries"])][row["mode"]] = row

    comparisons = []
    for n, modes in sorted(by_n.items()):
        if set(modes) != set(MODE_LABELS):
            continue
        mode2 = modes["ima-audit"]
        mode3 = modes["full-audit"]
        extra_kib = (
            float(mode3["wire_bytes"]) - float(mode2["wire_bytes"])
        ) / 1024
        throughput_delta = (
            float(mode3["throughput_rps"]) / float(mode2["throughput_rps"]) - 1
        ) * 100
        comparisons.append(
            f"At nominal $N={n:,}$, adding the raw TDX quote increased the "
            f"mean serialized response by {extra_kib:.1f}~KiB and changed peak "
            f"throughput by {throughput_delta:+.1f}\\%."
        )
    if not comparisons:
        comparisons.append(
            "Mode~2 and Mode~3 were not both measured at the same IMA history size."
        )

    path.write_text(
        "\n".join(
            [
                r"\paragraph{Audit-mode serving cost.}",
                "Both audit modes reuse the latest evidence already verified inside "
                "the SGX WEN; the end-user request path hashes, signs, serializes, and "
                "transports the cached audit snapshot but does not generate a new TDX "
                "or vTPM quote. The dominant variable component is therefore the "
                "binary and ASCII IMA history, while the command log is a separately "
                "reported fixed component in this experiment.",
                *comparisons,
                "Mode~2 does not expose the raw TDX quote and therefore retains the "
                "paper's platform-unlinkability boundary; Mode~3 enables independent "
                "DCAP verification at the cost of disclosing quote certification data.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        type=parse_input,
        metavar="MODE:N:CSV",
        help="Measured ima-audit or full-audit summary CSV",
    )
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = sorted(
        (summarize(mode, entries, path) for mode, entries, path in args.input),
        key=lambda row: (int(row["nominal_ima_entries"]), tuple(MODE_LABELS).index(row["mode"])),
    )
    write_csv(rows, out_dir / "audit_mode_summary.csv")
    write_tex_table(rows, out_dir / "table_audit_mode_serving.tex")
    write_discussion(rows, out_dir / "audit_mode_discussion.tex")
    print(f"Wrote audit summaries to {out_dir}")


if __name__ == "__main__":
    main()
