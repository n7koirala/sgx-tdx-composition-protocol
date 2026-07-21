#!/usr/bin/env python3
"""Generate Protocol 1.2 replacements for paper Figures 1, 2, 3, and 6."""

import argparse
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
from matplotlib.colors import LinearSegmentedColormap


N_VALUES = [10000, 50000, 100000, 200000]
DELTA_VALUES = [100, 500, 1000, 5000, 10000, 15000]
ALL_MODES = ["Non-Optimized", "Optimized (Python)", "Optimized (SGX)"]
OPT_MODES = ["Optimized (Python)", "Optimized (SGX)"]
COLORS = {
    "Non-Optimized": "#c0392b",
    "Optimized (Python)": "#27ae60",
    "Optimized (SGX)": "#2980b9",
}
MARKERS = {
    "Non-Optimized": "s",
    "Optimized (Python)": "^",
    "Optimized (SGX)": "o",
}

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif", "serif"],
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 9,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.05,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "lines.linewidth": 1.8,
    "lines.markersize": 6,
})


def truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "ok"}


def mean(rows, field):
    return float(np.mean([float(row[field]) for row in rows]))


def load_data(paths, allow_failed=False):
    grouped = defaultdict(list)
    rejected = 0
    for path in paths:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                version = row.get("protocol_version", "").strip()
                if version != "1.2":
                    raise ValueError(
                        f"expected Protocol 1.2 data, got {version!r} in {path}"
                    )
                mode = row.get("mode", "").strip()
                if mode not in ALL_MODES:
                    raise ValueError(f"unsupported mode {mode!r} in {path}")
                if not truthy(row.get("overall_ok", "")):
                    rejected += 1
                    if not allow_failed:
                        continue
                key = (mode, int(row["baseline_N"]), int(row["delta_n"]))
                grouped[key].append(row)

    data = {mode: {} for mode in ALL_MODES}
    for (mode, n_value, delta), rows in grouped.items():
        data[mode][(n_value, delta)] = {
            "total": mean(rows, "t_total_ms"),
            "total_std": float(np.std([float(r["t_total_ms"]) for r in rows])),
            "runtime_verify": mean(rows, "t_ima_verify_ms"),
            "checkpoint_commit": mean(rows, "t_checkpoint_commit_ms"),
            "quote_verify": mean(rows, "t_quote_verify_ms"),
            "wire_entries": mean(rows, "ima_entries_received"),
            "wire_kb": mean(rows, "ima_data_kb"),
            "repeats": len(rows),
        }
    return data, rejected


def validate_matrix(data):
    missing = []
    for mode in ALL_MODES:
        for n_value in N_VALUES:
            for delta in DELTA_VALUES:
                if (n_value, delta) not in data[mode]:
                    missing.append(f"{mode}: N={n_value}, delta={delta}")
    if missing:
        preview = "\n  ".join(missing[:12])
        suffix = "\n  ..." if len(missing) > 12 else ""
        raise ValueError(
            f"incomplete experiment matrix ({len(missing)} missing cells):\n"
            f"  {preview}{suffix}"
        )


def savefig(fig, name, output_dir):
    for extension in ("pdf", "png"):
        fig.savefig(os.path.join(output_dir, f"{name}.{extension}"))
    plt.close(fig)
    print(f"  wrote {name}.pdf and {name}.png")


def latency_formatter(value, _position):
    return f"{value:,.0f}" if value >= 1 else f"{value:.1f}"


def fig1_latency_vs_n(data, output_dir):
    shown_deltas = [100, 1000, 5000, 15000]
    fig, axes = plt.subplots(1, 4, figsize=(7.2, 2.6), sharey=False)
    for axis_index, delta in enumerate(shown_deltas):
        axis = axes[axis_index]
        for mode in ALL_MODES:
            values = [data[mode][(n_value, delta)]["total"] for n_value in N_VALUES]
            axis.plot(
                np.array(N_VALUES) / 1000,
                values,
                color=COLORS[mode],
                marker=MARKERS[mode],
                markersize=5,
                linewidth=1.5,
                label=mode,
            )
        axis.set_xlabel("Baseline N (x10^3)")
        delta_label = f"{delta // 1000}K" if delta >= 1000 else str(delta)
        axis.set_title(f"Delta n = {delta_label}", fontsize=10)
        if axis_index == 0:
            axis.set_ylabel("Total Latency (ms)")
        axis.set_yscale("log")
        axis.yaxis.set_major_formatter(mticker.FuncFormatter(latency_formatter))
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="lower center",
        ncol=3,
        bbox_to_anchor=(0.5, -0.18),
        frameon=False,
        fontsize=9,
    )
    fig.suptitle("Protocol 1.2 Attestation Latency vs. IMA Log Size", y=1.02)
    plt.tight_layout()
    savefig(fig, "fig1_latency_vs_N", output_dir)


def fig2_latency_vs_delta(data, output_dir):
    fig, axes = plt.subplots(1, 4, figsize=(7.2, 2.6), sharey=False)
    for axis_index, n_value in enumerate(N_VALUES):
        axis = axes[axis_index]
        for mode in ALL_MODES:
            values = [data[mode][(n_value, delta)]["total"] for delta in DELTA_VALUES]
            axis.plot(
                np.array(DELTA_VALUES) / 1000,
                values,
                color=COLORS[mode],
                marker=MARKERS[mode],
                markersize=5,
                linewidth=1.5,
                label=mode,
            )
        axis.set_xlabel("Delta n (x10^3)")
        axis.set_title(f"N = {n_value // 1000}K", fontsize=10)
        if axis_index == 0:
            axis.set_ylabel("Total Latency (ms)")
        axis.set_yscale("log")
        axis.yaxis.set_major_formatter(mticker.FuncFormatter(latency_formatter))
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="lower center",
        ncol=3,
        bbox_to_anchor=(0.5, -0.18),
        frameon=False,
        fontsize=9,
    )
    fig.suptitle("Protocol 1.2 Attestation Latency vs. Update Size", y=1.02)
    plt.tight_layout()
    savefig(fig, "fig2_latency_vs_delta", output_dir)


def fig3_speedup_heatmap(data, output_dir):
    matrix = np.zeros((len(N_VALUES), len(DELTA_VALUES)))
    for row_index, n_value in enumerate(N_VALUES):
        for column_index, delta in enumerate(DELTA_VALUES):
            baseline = data["Non-Optimized"][(n_value, delta)]["total"]
            optimized = data["Optimized (SGX)"][(n_value, delta)]["total"]
            matrix[row_index, column_index] = baseline / optimized

    figure, axis = plt.subplots(figsize=(4.5, 3.0))
    cmap = LinearSegmentedColormap.from_list(
        "speedup", ["#f7fbff", "#6baed6", "#08519c", "#08306b"]
    )
    maximum = float(np.max(matrix))
    image = axis.imshow(
        matrix,
        cmap=cmap,
        aspect="auto",
        vmin=min(1.0, float(np.min(matrix))),
        vmax=maximum * 1.05,
    )
    axis.set_xticks(range(len(DELTA_VALUES)))
    axis.set_xticklabels(
        [f"{d // 1000}K" if d >= 1000 else str(d) for d in DELTA_VALUES],
        fontsize=9,
    )
    axis.set_yticks(range(len(N_VALUES)))
    axis.set_yticklabels([f"{n // 1000}K" for n in N_VALUES], fontsize=9)
    axis.set_xlabel("Update Size Delta n")
    axis.set_ylabel("Baseline N")
    axis.set_title("Speedup: Persistent-FD SGX vs. Reopen/Reparse", fontsize=11)
    threshold = maximum * 0.45
    for row_index in range(len(N_VALUES)):
        for column_index in range(len(DELTA_VALUES)):
            value = matrix[row_index, column_index]
            color = "white" if value > threshold else "black"
            axis.text(
                column_index,
                row_index,
                f"{value:.1f}x",
                ha="center",
                va="center",
                fontsize=9,
                fontweight="bold",
                color=color,
            )
    colorbar = figure.colorbar(image, ax=axis, shrink=0.8, pad=0.02)
    colorbar.set_label("Speedup Factor", fontsize=10)
    plt.tight_layout()
    savefig(figure, "fig3_speedup_heatmap", output_dir)


def fig6_sgx_overhead(data, output_dir):
    figure, (verify_axis, total_axis, overhead_axis) = plt.subplots(
        1, 3, figsize=(7.2, 2.8)
    )

    for mode in OPT_MODES:
        values = []
        for delta in DELTA_VALUES:
            values.append(
                np.mean(
                    [data[mode][(n_value, delta)]["runtime_verify"] for n_value in N_VALUES]
                )
            )
        verify_axis.plot(
            np.array(DELTA_VALUES) / 1000,
            values,
            color=COLORS[mode],
            marker=MARKERS[mode],
            markersize=5,
            linewidth=1.5,
            label=mode,
        )
    verify_axis.set_xlabel("Delta n (x10^3)")
    verify_axis.set_ylabel("Verification Time (ms)")
    verify_axis.set_title("(a) Composed Runtime Verification", fontsize=10)
    verify_axis.legend(fontsize=7.5)

    shown_n = 200000
    x_positions = np.arange(len(DELTA_VALUES))
    width = 0.35
    for mode_index, mode in enumerate(OPT_MODES):
        values = [data[mode][(shown_n, delta)]["total"] for delta in DELTA_VALUES]
        total_axis.bar(
            x_positions + mode_index * width - width / 2,
            values,
            width,
            label=mode,
            color=COLORS[mode],
            edgecolor="white",
            linewidth=0.5,
        )
    total_axis.set_xticks(x_positions)
    total_axis.set_xticklabels(
        [f"{d // 1000}K" if d >= 1000 else str(d) for d in DELTA_VALUES],
        fontsize=9,
    )
    total_axis.set_xlabel("Delta n")
    total_axis.set_ylabel("Total Latency (ms)")
    total_axis.set_title("(b) End-to-End Latency (N=200K)", fontsize=10)
    total_axis.legend(fontsize=7.5)

    n_markers = {10000: "o", 50000: "s", 100000: "^", 200000: "D"}
    for n_value in N_VALUES:
        overheads = []
        for delta in DELTA_VALUES:
            python_ms = data["Optimized (Python)"][(n_value, delta)][
                "runtime_verify"
            ]
            sgx_ms = data["Optimized (SGX)"][(n_value, delta)]["runtime_verify"]
            overheads.append((sgx_ms - python_ms) / python_ms * 100.0)
        overhead_axis.plot(
            np.array(DELTA_VALUES) / 1000,
            overheads,
            marker=n_markers[n_value],
            markersize=4,
            linewidth=1.0,
            label=f"N={n_value // 1000}K",
        )
    overhead_axis.axhline(
        y=0, color="gray", linestyle="--", linewidth=0.8, alpha=0.5
    )
    overhead_axis.set_xlabel("Delta n (x10^3)")
    overhead_axis.set_ylabel("SGX Overhead (%)")
    overhead_axis.set_title("(c) Runtime Verification Overhead", fontsize=10)
    overhead_axis.legend(fontsize=7, loc="best")

    plt.tight_layout()
    savefig(figure, "fig6_sgx_overhead", output_dir)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate Protocol 1.2 replacements for Figures 1, 2, 3, and 6"
    )
    parser.add_argument("--non-optimized", required=True)
    parser.add_argument("--optimized-python", required=True)
    parser.add_argument("--optimized-sgx", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--allow-failed",
        action="store_true",
        help="Include rows whose overall protocol verdict is false",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    data, rejected = load_data(
        [args.non_optimized, args.optimized_python, args.optimized_sgx],
        allow_failed=args.allow_failed,
    )
    validate_matrix(data)
    print("Generating Protocol 1.2 paper figures")
    print(f"  rejected failed rows: {rejected}")
    fig1_latency_vs_n(data, args.output_dir)
    fig2_latency_vs_delta(data, args.output_dir)
    fig3_speedup_heatmap(data, args.output_dir)
    fig6_sgx_overhead(data, args.output_dir)
    print("Figure 6 compares the same composed verifier in Python and Gramine SGX.")
    print("Panel (a)/(c) use runtime_verify_ms; panel (b) uses end-to-end latency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
