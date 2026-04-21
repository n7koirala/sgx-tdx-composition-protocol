#!/usr/bin/env python3
"""
Generate publication-quality plots for the LLM-workload evaluation.
Reads all_runs.csv (emitted by collect_results.py) and per-run artifacts
(attest.csv, sampler.csv, vllm.json) under --root.

Produces the six figures described in the evaluation plan:

  fig1_throughput_by_condition.pdf
      Throughput (req/s, out tok/s) across native / tdx-only / tdx-vordr
      at fixed epoch. Two bar groups per condition: steady vs with-updates.

  fig2_ttft_tail_by_condition.pdf
      TTFT p50/p95/p99 across the three conditions, same grouping.

  fig3_epoch_sweep.pdf
      X=epoch (log scale), left-y = throughput overhead % vs tdx-only,
      right-y = p99 TTFT overhead %. One curve per IMA baseline size.

  fig4_delta_n_histogram.pdf
      Pooled Δn-per-round histogram across an entire with-updates run.

  fig5_timeline.pdf
      Two-panel timeline: per-request TTFT scatter (top), Δn per round
      stem plot (bottom). Visual alignment of tail spikes with Δn bursts.

  fig6_ima_growth.pdf
      IMA entries/min bar: cold vs warm × steady vs with-updates.

Usage:
    python3 plots/generate_plots.py --root ../results/llm/2026-04-21T14-00
"""

import argparse
import csv
import json
import os
from collections import defaultdict
from glob import glob

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

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

COND_COLORS = {
    "native":    "#7f8c8d",
    "tdx-only":  "#27ae60",
    "tdx-vordr": "#2980b9",
}
COND_ORDER = ["native", "tdx-only", "tdx-vordr"]


def load_all_runs(root):
    path = os.path.join(root, "all_runs.csv")
    if not os.path.exists(path):
        raise SystemExit(f"missing {path} — run collect_results.py first")
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def to_float(x, default=float("nan")):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def filter_rows(rows, **kv):
    out = []
    for r in rows:
        if all(r.get(k) == v for k, v in kv.items()):
            out.append(r)
    return out


# ───────────────────────────────────────────────────────────────────
# Figure 1: Throughput by condition
# ───────────────────────────────────────────────────────────────────
def fig1_throughput(rows, out_dir, ref_epoch="30", log_size="warm"):
    groups = ["steady", "with-updates"]
    x = np.arange(len(COND_ORDER))
    w = 0.38

    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.2))
    for ax, metric, ylabel in [
        (axes[0], "req_per_s", "Throughput (req/s)"),
        (axes[1], "out_tok_per_s", "Throughput (output tok/s)"),
    ]:
        for gi, g in enumerate(groups):
            vals = []
            for cond in COND_ORDER:
                subset = filter_rows(rows,
                                     condition=cond,
                                     log_size=log_size,
                                     interleave=g)
                # tdx-vordr is epoch-sensitive; pin to reference.
                if cond == "tdx-vordr":
                    subset = [r for r in subset if r.get("epoch_sec") == ref_epoch]
                vs = [to_float(r[metric]) for r in subset]
                vs = [v for v in vs if v == v]
                vals.append(np.mean(vs) if vs else np.nan)
            offset = (gi - 0.5) * w
            bars = ax.bar(x + offset, vals, w,
                          label=g,
                          color=[COND_COLORS[c] for c in COND_ORDER],
                          edgecolor="black", linewidth=0.5,
                          hatch="" if gi == 0 else "//")
        ax.set_xticks(x)
        ax.set_xticklabels(COND_ORDER)
        ax.set_ylabel(ylabel)
        ax.legend(title="interleaving", frameon=False)

    fig.suptitle(f"Throughput across conditions  (epoch={ref_epoch}s, "
                 f"IMA={log_size})", fontsize=11)
    fig.tight_layout()
    path = os.path.join(out_dir, "fig1_throughput_by_condition.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


# ───────────────────────────────────────────────────────────────────
# Figure 2: TTFT tail by condition
# ───────────────────────────────────────────────────────────────────
def fig2_ttft_tail(rows, out_dir, ref_epoch="30", log_size="warm"):
    groups = ["steady", "with-updates"]
    metrics = [("ttft_p50_ms", "p50"),
               ("ttft_p95_ms", "p95"),
               ("ttft_p99_ms", "p99")]
    x = np.arange(len(COND_ORDER))
    w = 0.25

    fig, axes = plt.subplots(1, 2, figsize=(8.8, 3.4), sharey=True)
    for ax, g in zip(axes, groups):
        for i, (col, label) in enumerate(metrics):
            vals = []
            for cond in COND_ORDER:
                subset = filter_rows(rows, condition=cond,
                                     log_size=log_size, interleave=g)
                if cond == "tdx-vordr":
                    subset = [r for r in subset if r.get("epoch_sec") == ref_epoch]
                vs = [to_float(r[col]) for r in subset]
                vs = [v for v in vs if v == v]
                vals.append(np.mean(vs) if vs else np.nan)
            offset = (i - 1) * w
            ax.bar(x + offset, vals, w, label=label,
                   edgecolor="black", linewidth=0.5)
        ax.set_xticks(x)
        ax.set_xticklabels(COND_ORDER)
        ax.set_title(g)
        ax.set_ylabel("TTFT (ms)" if ax is axes[0] else "")
        ax.legend(title="quantile", frameon=False)

    fig.suptitle(f"TTFT tail across conditions  (epoch={ref_epoch}s, "
                 f"IMA={log_size})", fontsize=11)
    fig.tight_layout()
    path = os.path.join(out_dir, "fig2_ttft_tail_by_condition.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


# ───────────────────────────────────────────────────────────────────
# Figure 3: Epoch sweep — overhead vs TDX-only
# ───────────────────────────────────────────────────────────────────
def fig3_epoch_sweep(rows, out_dir, interleave="steady"):
    # Baseline per (log_size) from tdx-only.
    base = {}
    for ls in ("cold", "warm"):
        subset = filter_rows(rows, condition="tdx-only",
                             log_size=ls, interleave=interleave)
        if subset:
            tp = np.mean([to_float(r["req_per_s"]) for r in subset
                          if to_float(r["req_per_s"]) == to_float(r["req_per_s"])])
            p99 = np.mean([to_float(r["ttft_p99_ms"]) for r in subset
                           if to_float(r["ttft_p99_ms"]) == to_float(r["ttft_p99_ms"])])
            base[ls] = (tp, p99)

    fig, ax_tp = plt.subplots(figsize=(5.2, 3.5))
    ax_lat = ax_tp.twinx()

    for ls, marker in (("cold", "o"), ("warm", "s")):
        vordr = filter_rows(rows, condition="tdx-vordr",
                            log_size=ls, interleave=interleave)
        by_epoch = defaultdict(list)
        for r in vordr:
            by_epoch[r["epoch_sec"]].append(r)
        epochs = sorted(by_epoch.keys(), key=lambda s: to_float(s))

        xs = [to_float(e) for e in epochs]
        tp_ov = []
        lat_ov = []
        for e in epochs:
            tp = np.mean([to_float(r["req_per_s"]) for r in by_epoch[e]
                          if to_float(r["req_per_s"]) == to_float(r["req_per_s"])])
            p99 = np.mean([to_float(r["ttft_p99_ms"]) for r in by_epoch[e]
                           if to_float(r["ttft_p99_ms"]) == to_float(r["ttft_p99_ms"])])
            bt, bl = base.get(ls, (np.nan, np.nan))
            tp_ov.append(100.0 * (bt - tp) / bt if bt else np.nan)
            lat_ov.append(100.0 * (p99 - bl) / bl if bl else np.nan)

        ax_tp.plot(xs, tp_ov, marker=marker, linestyle="-",
                   color="#c0392b", label=f"throughput Δ% ({ls})")
        ax_lat.plot(xs, lat_ov, marker=marker, linestyle="--",
                    color="#2980b9", label=f"p99 TTFT Δ% ({ls})")

    ax_tp.set_xscale("log")
    ax_tp.set_xlabel("Attestation epoch (s)")
    ax_tp.set_ylabel("Throughput overhead vs tdx-only (%)", color="#c0392b")
    ax_lat.set_ylabel("p99 TTFT overhead vs tdx-only (%)", color="#2980b9")
    ax_tp.axhline(0, color="black", linewidth=0.5)
    lines = ax_tp.get_lines() + ax_lat.get_lines()
    ax_tp.legend(lines, [l.get_label() for l in lines],
                 loc="best", frameon=False)

    fig.suptitle(f"Vordr epoch sweep  (interleaving={interleave})", fontsize=11)
    fig.tight_layout()
    path = os.path.join(out_dir, "fig3_epoch_sweep.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


# ───────────────────────────────────────────────────────────────────
# Figure 4: Δn histogram from one representative run
# ───────────────────────────────────────────────────────────────────
def fig4_delta_n_hist(rows, out_dir):
    # Prefer with-updates + warm + 30s epoch if present.
    wanted = None
    for pref in (("with-updates", "warm", "30"), ("steady", "warm", "30")):
        cand = [r for r in rows if r["condition"] == "tdx-vordr"
                and r["interleave"] == pref[0]
                and r["log_size"] == pref[1]
                and r["epoch_sec"] == pref[2]]
        if cand:
            wanted = cand[0]
            break
    if wanted is None:
        print("  [fig4] no tdx-vordr run found; skipped")
        return

    attest_csv = os.path.join(wanted["run_dir"], "attest.csv")
    if not os.path.exists(attest_csv):
        print(f"  [fig4] missing {attest_csv}; skipped")
        return

    dns = []
    with open(attest_csv) as f:
        for r in csv.DictReader(f):
            try:
                dns.append(int(r["delta_n"]))
            except ValueError:
                continue

    if not dns:
        print("  [fig4] no Δn values; skipped")
        return

    fig, ax = plt.subplots(figsize=(5.0, 3.2))
    bins = np.logspace(0, np.log10(max(dns) + 1), 30)
    ax.hist(dns, bins=bins, color=COND_COLORS["tdx-vordr"],
            edgecolor="black", linewidth=0.5)
    ax.set_xscale("log")
    ax.set_xlabel("Δn (entries per round)")
    ax.set_ylabel("Rounds")
    ax.set_title(f"Δn distribution  ({wanted['interleave']}, "
                 f"{wanted['log_size']}, epoch={wanted['epoch_sec']}s)")
    fig.tight_layout()
    path = os.path.join(out_dir, "fig4_delta_n_histogram.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


# ───────────────────────────────────────────────────────────────────
# Figure 5: Timeline — TTFT scatter + Δn stem
# ───────────────────────────────────────────────────────────────────
def fig5_timeline(rows, out_dir):
    wanted = None
    for pref in (("with-updates", "warm", "30"), ("steady", "warm", "30")):
        cand = [r for r in rows if r["condition"] == "tdx-vordr"
                and r["interleave"] == pref[0]
                and r["log_size"] == pref[1]
                and r["epoch_sec"] == pref[2]]
        if cand:
            wanted = cand[0]
            break
    if wanted is None:
        print("  [fig5] no tdx-vordr run found; skipped")
        return

    vllm_path = os.path.join(wanted["run_dir"], "vllm.json")
    attest_path = os.path.join(wanted["run_dir"], "attest.csv")
    run_path = os.path.join(wanted["run_dir"], "run.json")
    if not (os.path.exists(vllm_path) and os.path.exists(attest_path)
            and os.path.exists(run_path)):
        print("  [fig5] missing artifacts; skipped")
        return

    with open(run_path) as f:
        t0 = json.load(f).get("t0_epoch")

    with open(vllm_path) as f:
        doc = json.load(f)

    # benchmark_serving.py records per-request timing in seconds.
    ttfts = doc.get("ttfts") or []
    # if arrival timestamps aren't present, synthesize from cumulative arrivals.
    arrivals = doc.get("request_timestamps") or doc.get("arrival_times")
    if not arrivals:
        # Space arrivals uniformly over the run duration.
        dur = doc.get("duration") or (len(ttfts) / max(1.0, to_float(wanted.get("rps", "1"))))
        arrivals = list(np.linspace(0, dur, len(ttfts)))
        t_req = arrivals
    else:
        t_req = [a - t0 for a in arrivals]

    ttft_ms = [v * 1000 if v < 10 else v for v in ttfts]

    rounds_t = []
    rounds_dn = []
    with open(attest_path) as f:
        for r in csv.DictReader(f):
            try:
                ts = float(r["t_start_epoch"]) - t0
                rounds_t.append(ts)
                rounds_dn.append(int(r["delta_n"]))
            except (ValueError, KeyError):
                continue

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.2, 4.2),
                                   sharex=True, gridspec_kw={"height_ratios": [2, 1]})
    ax1.scatter(t_req, ttft_ms, s=8, alpha=0.5, color="#34495e")
    ax1.set_ylabel("TTFT (ms)")
    ax1.set_title(f"Request TTFT and Δn rounds "
                  f"({wanted['interleave']}, epoch={wanted['epoch_sec']}s)")
    ax1.set_yscale("log")

    ax2.stem(rounds_t, rounds_dn,
             linefmt=COND_COLORS["tdx-vordr"],
             markerfmt="o", basefmt=" ")
    ax2.set_xlabel("Time since t0 (s)")
    ax2.set_ylabel("Δn")

    fig.tight_layout()
    path = os.path.join(out_dir, "fig5_timeline.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


# ───────────────────────────────────────────────────────────────────
# Figure 6: IMA growth rate
# ───────────────────────────────────────────────────────────────────
def fig6_ima_growth(rows, out_dir):
    cells = defaultdict(list)
    for r in rows:
        if r["condition"] != "tdx-vordr":
            continue
        key = (r["log_size"], r["interleave"])
        v = to_float(r["ima_growth_per_min"])
        if v == v:
            cells[key].append(v)

    log_sizes = ["cold", "warm"]
    interleaves = ["steady", "with-updates"]
    x = np.arange(len(log_sizes))
    w = 0.38

    fig, ax = plt.subplots(figsize=(5.0, 3.2))
    for i, il in enumerate(interleaves):
        vals = [np.mean(cells[(ls, il)]) if cells.get((ls, il)) else np.nan
                for ls in log_sizes]
        ax.bar(x + (i - 0.5) * w, vals, w, label=il,
               edgecolor="black", linewidth=0.5,
               hatch="" if i == 0 else "//")
    ax.set_xticks(x)
    ax.set_xticklabels(log_sizes)
    ax.set_ylabel("IMA entries / min")
    ax.set_title("IMA log growth rate")
    ax.legend(frameon=False)
    fig.tight_layout()
    path = os.path.join(out_dir, "fig6_ima_growth.pdf")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out-dir", default=None,
                    help="Where to write figures (default: <root>/figures)")
    ap.add_argument("--ref-epoch", default="30",
                    help="Which epoch to use as reference for figs 1,2")
    ap.add_argument("--ref-log-size", default="warm")
    args = ap.parse_args()

    out_dir = args.out_dir or os.path.join(args.root, "figures")
    os.makedirs(out_dir, exist_ok=True)

    rows = load_all_runs(args.root)
    print(f"[plots] {len(rows)} runs loaded")

    fig1_throughput(rows, out_dir, args.ref_epoch, args.ref_log_size)
    fig2_ttft_tail(rows, out_dir, args.ref_epoch, args.ref_log_size)
    fig3_epoch_sweep(rows, out_dir, interleave="steady")
    fig4_delta_n_hist(rows, out_dir)
    fig5_timeline(rows, out_dir)
    fig6_ima_growth(rows, out_dir)
    print(f"[plots] figures → {out_dir}")


if __name__ == "__main__":
    main()
