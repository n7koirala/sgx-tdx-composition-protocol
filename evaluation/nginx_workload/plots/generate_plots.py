#!/usr/bin/env python3
"""
Generates publication-quality figures for the NGINX-workload evaluation.
Reads all_runs.csv (from collect_results.py) plus per-run artefacts
(attest.csv, sampler.csv) under --root.

Five figures:

  fig1_throughput_by_condition.pdf
      Two panels (1KB | 100KB). Bars: req/s across native / tdx-only /
      tdx-vordr × no-updates / with-updates at fixed epoch=30s. Means with
      error bars across reps.

  fig2_latency_tail_by_condition.pdf
      Two panels (1KB | 100KB). Grouped bars for p50/p95/p99/p999
      across the three conditions, fixed epoch=30s, no-updates interleave.

  fig3_matched_delta.pdf
      The headline. Bars showing (tdx-vordr − tdx-only) / tdx-only as a
      percentage, faceted by payload × cold/warm × no-updates/upd. Error
      bars from rep variance. Argues Vordr's marginal cost is small.

  fig4_epoch_sweep.pdf
      log-x epoch axis, p99 latency overhead % vs tdx-only on y. One
      curve per payload. Shows graceful scaling as T shrinks.

  fig5_timeline.pdf
      Two-row timeline aligned on a representative tdx-vordr run:
        top: sampler CPU% over time on the TARGET
        bottom: Δn-per-round stem plot from attest.csv
      Lets reviewer eyeball whether attestation rounds correlate with
      load spikes — the syscall-bound analog of LLM fig5.

Usage:
    python3 plots/generate_plots.py --root ../results/nginx/matrix-1kb-20260426
    # or pass --roots root1,root2 to merge across payloads
"""

import argparse
import csv
import json
import os
import sys
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
})

COND_COLORS = {
    "native":    "#7f8c8d",
    "tdx-only":  "#27ae60",
    "tdx-vordr": "#2980b9",
}
COND_LABELS = {
    "native":    "Native",
    "tdx-only":  "TDX-only",
    "tdx-vordr": "TDX+Vordr",
}
COND_ORDER = ["native", "tdx-only", "tdx-vordr"]
PAYLOADS = ["1kb", "100kb"]
INTERLEAVES = ["no-updates", "with-updates"]
INTERLEAVE_LABELS = {"no-updates": "No updates", "with-updates": "With Updates"}


def to_float(x, default=float("nan")):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def to_int(x, default=None):
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def load_all_runs(roots):
    rows = []
    for root in roots:
        path = os.path.join(root, "all_runs.csv")
        if not os.path.exists(path):
            print(f"[plot] WARN: missing {path}", file=sys.stderr)
            continue
        with open(path) as f:
            for row in csv.DictReader(f):
                row["_root"] = root
                rows.append(row)
    return rows


def filter_rows(rows, **kv):
    out = []
    for r in rows:
        ok = True
        for k, v in kv.items():
            if k.endswith("_in"):
                key = k[:-3]
                if r.get(key) not in v:
                    ok = False; break
            else:
                if str(r.get(k)) != str(v):
                    ok = False; break
        if ok:
            out.append(r)
    return out


def mean_std(values):
    arr = [v for v in values if v is not None and not (isinstance(v, float) and np.isnan(v))]
    if not arr:
        return None, None
    if len(arr) == 1:
        return float(arr[0]), 0.0
    return float(np.mean(arr)), float(np.std(arr, ddof=1))


def aggregate(rows, metric, **filters):
    """Group rows by (condition, interleave) and compute mean/std of metric."""
    sub = filter_rows(rows, **filters)
    out = defaultdict(list)
    for r in sub:
        out[(r["condition"], r["interleave"])].append(to_float(r.get(metric)))
    return {k: mean_std(v) for k, v in out.items()}


def add_value_labels(ax, fmt="{:.2f}", offset_pts=2, fontsize=7, skip_zero=True):
    """Annotate each rectangular patch in `ax` with its height. Used to
    surface small numerical differences that are invisible at the scale of
    the bars themselves (e.g. native 79957 vs tdx-only 79938 rps)."""
    for rect in ax.patches:
        h = rect.get_height()
        if h is None:
            continue
        if isinstance(h, float) and (np.isnan(h) or (skip_zero and h == 0)):
            continue
        ax.annotate(fmt.format(h),
                    xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, offset_pts),
                    textcoords="offset points",
                    ha="center", va="bottom",
                    fontsize=fontsize)


def _zoom_y_to_data(ax, margin_lo=0.985, margin_hi=1.01):
    """Zoom y-axis to span only the (non-zero) data range, so small
    relative differences become visually distinguishable. Otherwise
    bars at e.g. 79957/79938 look identical above an axis starting at 0."""
    heights = [r.get_height() for r in ax.patches
               if r.get_height() is not None and r.get_height() > 0]
    if not heights:
        return
    lo, hi = min(heights), max(heights)
    if lo == hi:
        ax.set_ylim(lo * margin_lo, hi * margin_hi + 1)
    else:
        ax.set_ylim(lo * margin_lo, hi * margin_hi)


def _payloads_with_data(rows):
    """Return ordered list of payload keys that actually have rows in
    the data, so we don't render an empty 100kb panel when only 1kb is
    available."""
    seen = {r.get("payload") for r in rows}
    return [p for p in PAYLOADS if p in seen]


# ─── fig1 throughput ────────────────────────────────────────────────────
def fig1_throughput(rows, out_pdf, fixed_epoch="30"):
    payloads = _payloads_with_data(rows) or PAYLOADS
    n_panels = len(payloads)
    fig, axes = plt.subplots(1, n_panels, figsize=(5 * n_panels, 3.8), sharey=False)
    if n_panels == 1:
        axes = [axes]

    for ax, payload in zip(axes, payloads):
        rows_p = [r for r in rows if r.get("payload") == payload]
        agg = {}
        for cond in COND_ORDER:
            for il in INTERLEAVES:
                kw = dict(condition=cond, interleave=il)
                if cond == "tdx-vordr":
                    kw["epoch_sec"] = fixed_epoch
                a = aggregate(rows_p, "req_per_s", **kw)
                if (cond, il) in a:
                    agg[(cond, il)] = a[(cond, il)]

        x = np.arange(len(COND_ORDER))
        width = 0.4
        for j, il in enumerate(INTERLEAVES):
            means = [agg.get((c, il), (None, None))[0] for c in COND_ORDER]
            stds  = [agg.get((c, il), (None, None))[1] for c in COND_ORDER]
            offsets = x + (j - 0.5) * width
            ax.bar(offsets,
                   [m if m is not None else 0 for m in means],
                   width=width,
                   yerr=[s if s is not None else 0 for s in stds],
                   capsize=3,
                   color=[COND_COLORS[c] for c in COND_ORDER],
                   edgecolor="black", linewidth=0.5,
                   hatch=("" if il == "no-updates" else "//"),
                   label=INTERLEAVE_LABELS[il] if ax is axes[0] else None)

        # Zoom y-axis to data range so small differences are visible.
        _zoom_y_to_data(ax, margin_lo=0.992, margin_hi=1.005)
        # Numerical labels on bar tops — without these, native vs tdx-only
        # at 79957 vs 79938 rps look identical.
        add_value_labels(ax, fmt="{:.0f}", fontsize=7)

        ax.set_xticks(x)
        ax.set_xticklabels([COND_LABELS[c] for c in COND_ORDER])
        ax.set_title(f"/{payload}")
        ax.set_ylabel("Throughput (req/s)")
        ax.ticklabel_format(axis="y", style="plain")
        ax.grid(axis="y", alpha=0.25)

    handles = [plt.Rectangle((0,0),1,1, facecolor="lightgray",
                             hatch=("" if il == "no-updates" else "//"),
                             edgecolor="black")
               for il in INTERLEAVES]
    fig.legend(handles, [INTERLEAVE_LABELS[il] for il in INTERLEAVES],
               loc="upper center", bbox_to_anchor=(0.5, 1.02), ncol=2,
               frameon=False)
    fig.suptitle(f"Throughput by Condition (epoch={fixed_epoch}s for tdx-vordr)",
                 y=1.08)
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"[plot] {out_pdf}")


# ─── fig2 latency tail ──────────────────────────────────────────────────
def fig2_latency_tail(rows, out_pdf, fixed_epoch="30", interleave="no-updates"):
    pcts = [("p50", "p50"), ("p90", "p90"), ("p99", "p99"), ("p999", "p99.9")]
    payloads = _payloads_with_data(rows) or PAYLOADS
    n_panels = len(payloads)
    fig, axes = plt.subplots(1, n_panels, figsize=(5 * n_panels, 4), sharey=False)
    if n_panels == 1:
        axes = [axes]

    for ax, payload in zip(axes, payloads):
        rows_p = [r for r in rows if r.get("payload") == payload]
        x = np.arange(len(pcts))
        width = 0.25
        for i, cond in enumerate(COND_ORDER):
            kw = dict(condition=cond, interleave=interleave)
            if cond == "tdx-vordr":
                kw["epoch_sec"] = fixed_epoch
            sub = filter_rows(rows_p, **kw)
            means, stds = [], []
            for col, _ in pcts:
                vals = [to_float(r.get(f"lat_{col}_ms")) for r in sub]
                m, s = mean_std(vals)
                means.append(m if m is not None else 0)
                stds.append(s if s is not None else 0)
            ax.bar(x + (i - 1) * width, means, width=width,
                   yerr=stds, capsize=3,
                   color=COND_COLORS[cond], edgecolor="black", linewidth=0.5,
                   label=COND_LABELS[cond] if ax is axes[0] else None)

        # Numeric labels on bar tops — values like 1.95/2.00/2.01 are
        # otherwise indistinguishable on a log scale.
        add_value_labels(ax, fmt="{:.2f}", fontsize=6, offset_pts=2)

        ax.set_xticks(x)
        ax.set_xticklabels([lbl for _, lbl in pcts])
        ax.set_title(f"/{payload}")
        ax.set_ylabel("Request latency (ms)")
        # Only log-scale the panel if there are positive values.
        if any(r.get_height() and r.get_height() > 0 for r in ax.patches):
            ax.set_yscale("log")
        ax.grid(axis="y", alpha=0.25, which="both")

    fig.legend(loc="upper center", bbox_to_anchor=(0.5, 1.02), ncol=3,
               frameon=False)
    fig.suptitle(f"Latency Tail by Condition (no-updates, epoch={fixed_epoch}s)",
                 y=1.08)
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"[plot] {out_pdf}")


# ─── fig3 matched delta ─────────────────────────────────────────────────
def fig3_matched_delta(rows, out_pdf, fixed_epoch="30"):
    """(tdx-vordr − tdx-only) / tdx-only %, for throughput and p99, by
    payload × log_size × interleave."""
    fig, axes = plt.subplots(1, 2, figsize=(11, 4), sharey=False)

    metrics = [("req_per_s", "Throughput overhead (%)", -1),
               ("lat_p99_ms", "p99 latency overhead (%)", +1)]

    cells = []
    for payload in PAYLOADS:
        for ls in ["cold", "warm"]:
            for il in INTERLEAVES:
                cells.append((payload, ls, il))

    x = np.arange(len(cells))
    width = 0.4

    for ax, (metric, ylabel, sign) in zip(axes, metrics):
        means, stds = [], []
        for payload, ls, il in cells:
            base = filter_rows(rows, payload=payload, log_size=ls,
                               interleave=il, condition="tdx-only")
            vord = filter_rows(rows, payload=payload, log_size=ls,
                               interleave=il, condition="tdx-vordr",
                               epoch_sec=fixed_epoch)
            base_vals = [to_float(r.get(metric)) for r in base]
            vord_vals = [to_float(r.get(metric)) for r in vord]
            base_m, _ = mean_std(base_vals)
            vord_m, vord_s = mean_std(vord_vals)
            if base_m is None or vord_m is None or base_m == 0:
                means.append(0); stds.append(0); continue
            # sign: throughput positive=better, so flip; latency positive=worse
            delta = (vord_m - base_m) / base_m * 100.0
            std_pct = (vord_s / base_m) * 100.0 if vord_s else 0
            means.append(sign * delta if metric == "req_per_s" else delta)
            stds.append(std_pct)

        bar_colors = []
        for payload, ls, il in cells:
            c = "#1abc9c" if payload == "1kb" else "#9b59b6"
            if il == "with-updates":
                c = matplotlib.colors.to_hex(
                    np.clip(np.array(matplotlib.colors.to_rgb(c)) * 0.7, 0, 1))
            bar_colors.append(c)

        bars = ax.bar(x, means, width=width, yerr=stds, capsize=3,
                      color=bar_colors, edgecolor="black", linewidth=0.5)
        ax.axhline(0, color="black", lw=0.6)
        # Value labels above/below each bar as appropriate (signed %).
        for rect, m in zip(bars, means):
            if m is None or (isinstance(m, float) and np.isnan(m)) or m == 0:
                continue
            offset = 3 if m >= 0 else -3
            va = "bottom" if m >= 0 else "top"
            ax.annotate(f"{m:+.2f}%", xy=(rect.get_x() + rect.get_width() / 2, m),
                        xytext=(0, offset), textcoords="offset points",
                        ha="center", va=va, fontsize=7)
        ax.set_xticks(x)
        ax.set_xticklabels([f"/{p}\n{ls}\n{il}" for p, ls, il in cells],
                           fontsize=8)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", alpha=0.25)

    fig.suptitle("Vordr's marginal overhead vs tdx-only (matched delta, "
                 f"epoch={fixed_epoch}s)", y=1.02)
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"[plot] {out_pdf}")


# ─── fig4 epoch sweep ───────────────────────────────────────────────────
def fig4_epoch_sweep(rows, out_pdf, log_size="cold", interleave="no-updates"):
    """X = epoch (log scale). Y = p99 latency overhead % vs tdx-only.
    One curve per payload."""
    fig, ax = plt.subplots(figsize=(7, 4))

    EPOCHS = ["15", "30", "60", "300"]
    for payload in PAYLOADS:
        base = filter_rows(rows, payload=payload, log_size=log_size,
                           interleave=interleave, condition="tdx-only")
        base_vals = [to_float(r.get("lat_p99_ms")) for r in base]
        base_m, _ = mean_std(base_vals)
        if base_m is None or base_m == 0:
            continue

        xs, ys, errs = [], [], []
        for ep in EPOCHS:
            vord = filter_rows(rows, payload=payload, log_size=log_size,
                               interleave=interleave, condition="tdx-vordr",
                               epoch_sec=ep)
            vals = [to_float(r.get("lat_p99_ms")) for r in vord]
            m, s = mean_std(vals)
            if m is None:
                continue
            xs.append(int(ep))
            ys.append((m - base_m) / base_m * 100.0)
            errs.append((s / base_m * 100.0) if s else 0)

        if xs:
            color = "#1abc9c" if payload == "1kb" else "#9b59b6"
            ax.errorbar(xs, ys, yerr=errs, marker="o",
                        label=f"/{payload}", color=color, capsize=3)

    ax.set_xscale("log")
    ax.set_xticks([15, 30, 60, 300])
    ax.set_xticklabels(["15", "30", "60", "300"])
    ax.set_xlabel("Attestation epoch T (s)")
    ax.set_ylabel("p99 latency overhead vs tdx-only (%)")
    ax.axhline(0, color="black", lw=0.6)
    ax.legend(frameon=False)
    ax.grid(alpha=0.25, which="both")
    ax.set_title(f"Epoch sweep ({log_size}, {interleave})")
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"[plot] {out_pdf}")


# ─── fig5 timeline ──────────────────────────────────────────────────────
def fig5_timeline(roots, out_pdf,
                  payload="1kb", epoch="30", log_size="warm",
                  interleave="with-updates", rep=1):
    """Two-panel timeline aligned on t0 of one representative tdx-vordr cell."""
    target_tag = f"{epoch}s_{log_size}_{interleave}_{payload}_rep{rep}"
    candidates = []
    for root in roots:
        for d in glob(os.path.join(root, "tdx-vordr", target_tag)):
            candidates.append(d)
    if not candidates:
        print(f"[plot] fig5 SKIP: no run matching {target_tag}", file=sys.stderr)
        return
    cell_dir = candidates[0]

    # Load run.json for t0
    with open(os.path.join(cell_dir, "run.json")) as f:
        run = json.load(f)
    t0 = float(run.get("t0_epoch") or 0)

    # Sampler CPU% timeseries
    sampler_path = os.path.join(cell_dir, "sampler.csv")
    samp_t, samp_cpu = [], []
    if os.path.exists(sampler_path):
        with open(sampler_path) as f:
            for row in csv.DictReader(f):
                try:
                    samp_t.append(float(row["ts_epoch"]) - t0)
                    samp_cpu.append(float(row.get("cpu_pct") or 0))
                except (ValueError, KeyError):
                    pass

    # Attest Δn stem
    attest_path = os.path.join(cell_dir, "attest.csv")
    att_t, att_dn = [], []
    if os.path.exists(attest_path):
        with open(attest_path) as f:
            for row in csv.DictReader(f):
                try:
                    att_t.append(float(row["t_start_epoch"]) - t0)
                    att_dn.append(int(row.get("delta_n") or 0))
                except (ValueError, KeyError):
                    pass

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 4.5), sharex=True,
                                   gridspec_kw={"height_ratios": [2, 1]})
    if samp_t:
        ax1.plot(samp_t, samp_cpu, color="#2980b9")
        ax1.fill_between(samp_t, samp_cpu, alpha=0.15, color="#2980b9")
    ax1.set_ylabel("Target CPU (%)")
    ax1.set_title(f"tdx-vordr / {payload} / epoch={epoch}s / "
                  f"{log_size} / {interleave} / rep{rep}")
    ax1.grid(alpha=0.25)

    if att_t:
        ax2.stem(att_t, att_dn, basefmt=" ", linefmt="#c0392b",
                 markerfmt="o")
    ax2.set_xlabel("Time since t0 (s)")
    ax2.set_ylabel("Δn / round")
    ax2.grid(alpha=0.25)

    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"[plot] {out_pdf}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", help="Single results root (one payload)")
    ap.add_argument("--roots", help="Comma-separated roots (multiple payloads)")
    ap.add_argument("--out-dir", default=None,
                    help="Where to write PDFs (default: <root>/figures/)")
    args = ap.parse_args()

    if args.roots:
        roots = [r.strip() for r in args.roots.split(",") if r.strip()]
    elif args.root:
        roots = [args.root]
    else:
        ap.error("--root or --roots required")

    out_dir = args.out_dir or os.path.join(roots[0], "figures")
    os.makedirs(out_dir, exist_ok=True)

    rows = load_all_runs(roots)
    if not rows:
        print("[plot] no rows loaded — aborting", file=sys.stderr)
        sys.exit(1)
    print(f"[plot] loaded {len(rows)} rows from {len(roots)} root(s)")

    fig1_throughput(rows,    os.path.join(out_dir, "fig1_throughput_by_condition.pdf"))
    fig2_latency_tail(rows,  os.path.join(out_dir, "fig2_latency_tail_by_condition.pdf"))
    fig3_matched_delta(rows, os.path.join(out_dir, "fig3_matched_delta.pdf"))
    fig4_epoch_sweep(rows,   os.path.join(out_dir, "fig4_epoch_sweep.pdf"))
    fig5_timeline(roots,     os.path.join(out_dir, "fig5_timeline.pdf"))

    print(f"[plot] done → {out_dir}")


if __name__ == "__main__":
    main()
