#!/usr/bin/env python3
"""
Plot comparison figures for the DCAP Verification Overhead microbenchmark.

Consumes:
  results_python.csv
  results_sgx.csv

Produces (under charts/):
  fig_verify_boxplot.{pdf,png}         Distribution comparison per verifier
  fig_verify_cdf.{pdf,png}             CDF of per-iteration latency
  fig_verify_slowdown.{pdf,png}        Bar chart of SGX/Py slowdown factor
  fig_verify_histogram.{pdf,png}       Histogram overlay per verifier
  summary.json                         Tabular summary numbers
"""

import csv
import json
import os
import sys
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


HERE = os.path.dirname(os.path.abspath(__file__))
CHARTS = os.path.join(HERE, "charts")
os.makedirs(CHARTS, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.05,
})

COLOR = {"python": "#27ae60", "sgx": "#2980b9"}
LABEL = {"python": "Non-SGX (Python)", "sgx": "SGX (Gramine)"}


def load_csv(path):
    data = defaultdict(list)  # verifier -> [t_us, ...]
    with open(path) as f:
        for r in csv.DictReader(f):
            data[r["verifier"]].append(float(r["t_verify_us"]))
    return {k: np.array(v) for k, v in data.items()}


def summarize(arr):
    arr = np.asarray(arr)
    return {
        "n": int(arr.size),
        "min": float(arr.min()),
        "p50": float(np.median(arr)),
        "mean": float(arr.mean()),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "max": float(arr.max()),
        "std": float(arr.std(ddof=1)) if arr.size > 1 else 0.0,
    }


def savefig(fig, name):
    for ext in (".pdf", ".png"):
        fig.savefig(os.path.join(CHARTS, name + ext))
    plt.close(fig)
    print(f"  → charts/{name}.pdf/.png")


def main():
    py_path  = os.path.join(HERE, "results_python.csv")
    sgx_path = os.path.join(HERE, "results_sgx.csv")
    missing = [p for p in (py_path, sgx_path) if not os.path.exists(p)]
    if missing:
        sys.exit(f"Missing results files: {missing}\n"
                 f"Run `make run-python` and `make run-sgx` first.")

    py  = load_csv(py_path)
    sgx = load_csv(sgx_path)

    verifiers = sorted(set(py) & set(sgx))
    if not verifiers:
        sys.exit("No matching verifier labels across the two CSVs.")

    summary = {"verifiers": {}}
    for v in verifiers:
        summary["verifiers"][v] = {
            "python": summarize(py[v]),
            "sgx":    summarize(sgx[v]),
        }
    summary_path = os.path.join(HERE, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"  → summary.json")

    # ── Figure 1: grouped boxplot ─────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(5.5, 3.3))
    positions, data, colors, tick_labels = [], [], [], []
    x = 0
    for v in verifiers:
        positions += [x, x + 0.8]
        data      += [py[v], sgx[v]]
        colors    += [COLOR["python"], COLOR["sgx"]]
        tick_labels.append(v)
        x += 2.2
    bp = ax.boxplot(data, positions=positions, widths=0.65, patch_artist=True,
                    showfliers=False, medianprops=dict(color="black", linewidth=1.4))
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c)
        patch.set_alpha(0.85)
        patch.set_edgecolor("white")
    ax.set_xticks([0.4 + 2.2 * i for i in range(len(verifiers))])
    ax.set_xticklabels(tick_labels)
    ax.set_ylabel("Per-iteration Latency (µs)")
    ax.set_title("DCAP Verification: SGX vs. Non-SGX")
    import matplotlib.patches as mpatches
    ax.legend(handles=[
        mpatches.Patch(facecolor=COLOR["python"], label=LABEL["python"]),
        mpatches.Patch(facecolor=COLOR["sgx"],    label=LABEL["sgx"]),
    ], fontsize=8, loc="upper left")
    savefig(fig, "fig_verify_boxplot")

    # ── Figure 2: CDFs ────────────────────────────────────────────────────
    fig, axes = plt.subplots(1, len(verifiers), figsize=(3.6 * len(verifiers), 3.2),
                             sharey=True)
    if len(verifiers) == 1:
        axes = [axes]
    for ax, v in zip(axes, verifiers):
        for mode, arr in (("python", py[v]), ("sgx", sgx[v])):
            xs = np.sort(arr)
            ys = np.arange(1, len(xs) + 1) / len(xs)
            ax.plot(xs, ys, color=COLOR[mode], lw=1.6, label=LABEL[mode])
        ax.set_xlabel("Latency (µs)")
        ax.set_title(f"Verifier: {v}")
        ax.legend(fontsize=8, loc="lower right")
    axes[0].set_ylabel("CDF")
    fig.suptitle("CDF of DCAP Verification Latency", y=1.02)
    savefig(fig, "fig_verify_cdf")

    # ── Figure 3: slowdown bar ────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(5.0, 3.0))
    stat_names = ["min", "p50", "mean", "p95", "p99"]
    x = np.arange(len(stat_names))
    bw = 0.8 / len(verifiers)
    for i, v in enumerate(verifiers):
        py_s  = summary["verifiers"][v]["python"]
        sgx_s = summary["verifiers"][v]["sgx"]
        slowdown = [sgx_s[k] / py_s[k] if py_s[k] > 0 else 0 for k in stat_names]
        ax.bar(x + i * bw - bw * (len(verifiers) - 1) / 2, slowdown, bw,
               label=v, edgecolor="white", linewidth=0.5)
    ax.axhline(y=1.0, color="black", linestyle="--", linewidth=0.8, alpha=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(stat_names)
    ax.set_ylabel("SGX / Non-SGX")
    ax.set_title("Slowdown by Summary Statistic")
    ax.legend(fontsize=8, title="Verifier")
    savefig(fig, "fig_verify_slowdown")

    # ── Figure 4: histogram overlay ───────────────────────────────────────
    fig, axes = plt.subplots(1, len(verifiers), figsize=(3.6 * len(verifiers), 3.0))
    if len(verifiers) == 1:
        axes = [axes]
    for ax, v in zip(axes, verifiers):
        lo = min(py[v].min(), sgx[v].min())
        hi = max(np.percentile(py[v], 99.5), np.percentile(sgx[v], 99.5))
        bins = np.linspace(lo, hi, 50)
        ax.hist(py[v],  bins=bins, alpha=0.65, color=COLOR["python"],
                label=LABEL["python"], edgecolor="white", linewidth=0.3)
        ax.hist(sgx[v], bins=bins, alpha=0.65, color=COLOR["sgx"],
                label=LABEL["sgx"], edgecolor="white", linewidth=0.3)
        ax.axvline(summary["verifiers"][v]["python"]["mean"],
                   color=COLOR["python"], linestyle=":", lw=1.2)
        ax.axvline(summary["verifiers"][v]["sgx"]["mean"],
                   color=COLOR["sgx"], linestyle=":", lw=1.2)
        ax.set_xlabel("Latency (µs)")
        ax.set_ylabel("Count")
        ax.set_title(f"Verifier: {v}")
        ax.legend(fontsize=8)
    fig.suptitle("DCAP Verification Latency Distribution", y=1.02)
    savefig(fig, "fig_verify_histogram")

    # ── Print summary table ───────────────────────────────────────────────
    print("\n" + "=" * 78)
    print(f"  {'Verifier':<10}  {'Mode':<8}  {'n':>4}  {'min':>7}  "
          f"{'p50':>7}  {'mean':>7}  {'p95':>7}  {'p99':>7}  {'max':>7}")
    print("=" * 78)
    for v in verifiers:
        for mode in ("python", "sgx"):
            s = summary["verifiers"][v][mode]
            print(f"  {v:<10}  {mode:<8}  {s['n']:>4}  "
                  f"{s['min']:>7.2f}  {s['p50']:>7.2f}  "
                  f"{s['mean']:>7.2f}  {s['p95']:>7.2f}  "
                  f"{s['p99']:>7.2f}  {s['max']:>7.2f}")
        py_s  = summary["verifiers"][v]["python"]
        sgx_s = summary["verifiers"][v]["sgx"]
        print(f"  {v:<10}  slowdown  --     "
              f"{sgx_s['min']/py_s['min']:>6.2f}× "
              f"{sgx_s['p50']/py_s['p50']:>6.2f}× "
              f"{sgx_s['mean']/py_s['mean']:>6.2f}× "
              f"{sgx_s['p95']/py_s['p95']:>6.2f}× "
              f"{sgx_s['p99']/py_s['p99']:>6.2f}× "
              f"{sgx_s['max']/py_s['max']:>6.2f}×")
        print("-" * 78)


if __name__ == "__main__":
    main()
