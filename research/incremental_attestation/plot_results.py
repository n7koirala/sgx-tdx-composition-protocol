#!/usr/bin/env python3
"""
Incremental Attestation Microbenchmark — Chart Generator

Generates publication-quality charts from benchmark CSV results.

Charts produced:
  1. Latency vs Δn (one subplot per N, lines per mode) — log scale
  2. Server IMA Read Time Heatmap (N × Δn)
  3. SGX Overhead comparison (Optimized-Python vs Optimized-SGX)
  4. Speedup: Non-optimized / Optimized for each (N, Δn)
  5. Stacked time breakdown per phase
  6. Combined summary bar chart

Usage:
    python3 plot_results.py --csv results_all.csv
    python3 plot_results.py --csv results_all.csv --output-dir ./charts/
"""

import argparse
import csv
import os
import sys
import statistics

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    import numpy as np
except ImportError:
    print("ERROR: matplotlib and numpy required. Install with:")
    print("  pip install matplotlib numpy")
    sys.exit(1)

# Publication-quality defaults
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 12,
    'axes.titlesize': 14,
    'axes.labelsize': 13,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 10,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
})

# Color palette
COLORS = {
    'Non-Optimized': '#dc2626',       # Red
    'Optimized (SGX)': '#16a34a',     # Green
    'Optimized (Python)': '#2563eb',  # Blue
}
MARKERS = {
    'Non-Optimized': 'o',
    'Optimized (SGX)': 'D',
    'Optimized (Python)': 's',
}
ORANGE = '#ea580c'
PURPLE = '#7c3aed'
GRAY = '#9ca3af'


def load_csv(path):
    """Load benchmark CSV results."""
    rows = []
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def parse_results(rows):
    """
    Parse CSV rows into structured data.

    Returns:
        dict: {mode: {N: {Δn: [result_dicts]}}}
    """
    data = {}
    for row in rows:
        mode = row['mode']
        N = int(row['baseline_N'])
        dn = int(row['delta_n'])

        if mode not in data:
            data[mode] = {}
        if N not in data[mode]:
            data[mode][N] = {}
        if dn not in data[mode][N]:
            data[mode][N][dn] = []

        data[mode][N][dn].append({
            't_total_ms': float(row['t_total_ms']),
            't_connect_ms': float(row['t_connect_ms']),
            't_request_ms': float(row['t_request_ms']),
            't_response_ms': float(row['t_response_ms']),
            't_server_ima_read_ms': float(row['t_server_ima_read_ms']),
            't_server_quote_ms': float(row['t_server_quote_ms']),
            't_quote_verify_ms': float(row['t_quote_verify_ms']),
            't_ima_verify_ms': float(row['t_ima_verify_ms']),
            'ima_entries_received': int(row['ima_entries_received']),
            'ima_data_kb': float(row['ima_data_kb']),
        })

    return data


def get_all_baselines(data):
    """Get sorted list of all baseline N values."""
    baselines = set()
    for mode in data:
        baselines.update(data[mode].keys())
    return sorted(baselines)


def get_all_deltas(data):
    """Get sorted list of all delta Δn values."""
    deltas = set()
    for mode in data:
        for N in data[mode]:
            deltas.update(data[mode][N].keys())
    return sorted(deltas)


def mean_val(results, key):
    """Compute mean of a field across results."""
    vals = [r[key] for r in results]
    return statistics.mean(vals) if vals else 0


def std_val(results, key):
    """Compute stdev of a field across results."""
    vals = [r[key] for r in results]
    return statistics.stdev(vals) if len(vals) > 1 else 0


# ─── Chart 1: Latency vs Δn (subplots per N) ────────────────────────────────

def plot_latency_vs_delta(data, output_dir):
    """Multi-panel chart: latency vs Δn, one subplot per N, lines per mode."""
    baselines = get_all_baselines(data)
    deltas = get_all_deltas(data)
    modes = sorted(data.keys())

    ncols = min(len(baselines), 2)
    nrows = (len(baselines) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(7 * ncols, 5 * nrows),
                              squeeze=False)

    for idx, N in enumerate(baselines):
        ax = axes[idx // ncols][idx % ncols]

        for mode in modes:
            if N not in data.get(mode, {}):
                continue

            dn_vals = sorted(data[mode][N].keys())
            means = [mean_val(data[mode][N][dn], 't_total_ms') for dn in dn_vals]
            stds = [std_val(data[mode][N][dn], 't_total_ms') for dn in dn_vals]

            color = COLORS.get(mode, GRAY)
            marker = MARKERS.get(mode, 'x')

            ax.errorbar(dn_vals, means, yerr=stds,
                        fmt=f'{marker}-', color=color, linewidth=2,
                        markersize=7, capsize=3, label=mode, zorder=5)

        ax.set_xlabel('Δn (new IMA entries)')
        ax.set_ylabel('End-to-End Latency (ms)')
        ax.set_title(f'N = {N:,} baseline entries')
        ax.set_xscale('log')
        ax.set_yscale('log')
        ax.legend(loc='upper left', fontsize=9)
        ax.grid(True, alpha=0.3, which='both')
        ax.xaxis.set_major_formatter(
            ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))

    # Hide unused subplots
    for idx in range(len(baselines), nrows * ncols):
        axes[idx // ncols][idx % ncols].set_visible(False)

    fig.suptitle('Incremental Attestation Latency vs Delta Size',
                 fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()

    path = os.path.join(output_dir, 'chart_latency_vs_delta.png')
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")


# ─── Chart 2: Server IMA Read Time Heatmap ──────────────────────────────────

def plot_server_read_heatmap(data, output_dir):
    """Heatmap of server-side IMA read time: N × Δn for each mode."""
    modes = sorted(data.keys())
    baselines = get_all_baselines(data)
    deltas = get_all_deltas(data)

    ncols = len(modes)
    fig, axes = plt.subplots(1, ncols, figsize=(6 * ncols, 5), squeeze=False)

    for col, mode in enumerate(modes):
        ax = axes[0][col]

        matrix = np.full((len(baselines), len(deltas)), np.nan)
        for i, N in enumerate(baselines):
            for j, dn in enumerate(deltas):
                if N in data.get(mode, {}) and dn in data[mode][N]:
                    matrix[i][j] = mean_val(data[mode][N][dn], 't_server_ima_read_ms')

        im = ax.imshow(matrix, aspect='auto', cmap='YlOrRd',
                        interpolation='nearest')

        ax.set_xticks(range(len(deltas)))
        ax.set_xticklabels([f'{d:,}' for d in deltas], rotation=45, ha='right')
        ax.set_yticks(range(len(baselines)))
        ax.set_yticklabels([f'{N:,}' for N in baselines])
        ax.set_xlabel('Δn')
        ax.set_ylabel('N (baseline)')
        ax.set_title(f'{mode}')

        # Annotate cells
        for i in range(len(baselines)):
            for j in range(len(deltas)):
                if not np.isnan(matrix[i][j]):
                    val = matrix[i][j]
                    label = f'{val:.0f}' if val < 1000 else f'{val/1000:.1f}s'
                    ax.text(j, i, label, ha='center', va='center',
                            fontsize=8, fontweight='bold',
                            color='white' if val > np.nanmax(matrix) * 0.6 else 'black')

        plt.colorbar(im, ax=ax, label='Read Time (ms)', shrink=0.8)

    fig.suptitle('Server-Side IMA Read Time', fontsize=15, fontweight='bold')
    plt.tight_layout()

    path = os.path.join(output_dir, 'chart_server_read_heatmap.png')
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")


# ─── Chart 3: SGX Overhead ──────────────────────────────────────────────────

def plot_sgx_overhead(data, output_dir):
    """Bar chart comparing Optimized-Python vs Optimized-SGX latency."""
    py_key = 'Optimized (Python)'
    sgx_key = 'Optimized (SGX)'

    if py_key not in data or sgx_key not in data:
        print("  Skipping SGX overhead chart (need both Python and SGX data)")
        return

    baselines = get_all_baselines(data)
    deltas = get_all_deltas(data)

    # Use the largest N for this chart
    N = max(baselines)
    if N not in data[py_key] or N not in data[sgx_key]:
        N = min(set(data[py_key].keys()) & set(data[sgx_key].keys()))

    common_deltas = sorted(set(data[py_key].get(N, {}).keys()) &
                           set(data[sgx_key].get(N, {}).keys()))

    if not common_deltas:
        print("  Skipping SGX overhead chart (no common deltas)")
        return

    fig, ax = plt.subplots(figsize=(10, 5))

    x = np.arange(len(common_deltas))
    width = 0.35

    py_means = [mean_val(data[py_key][N][dn], 't_total_ms') for dn in common_deltas]
    sgx_means = [mean_val(data[sgx_key][N][dn], 't_total_ms') for dn in common_deltas]

    bars1 = ax.bar(x - width/2, py_means, width,
                   label='Optimized (Python)', color=COLORS[py_key], alpha=0.85)
    bars2 = ax.bar(x + width/2, sgx_means, width,
                   label='Optimized (SGX)', color=COLORS[sgx_key], alpha=0.85)

    # Overhead labels
    for i in range(len(common_deltas)):
        if py_means[i] > 0:
            overhead = ((sgx_means[i] - py_means[i]) / py_means[i]) * 100
            y_pos = max(sgx_means[i], py_means[i])
            sign = '+' if overhead >= 0 else ''
            ax.text(i, y_pos + y_pos * 0.05, f'{sign}{overhead:.0f}%',
                    ha='center', va='bottom', fontsize=10,
                    fontweight='bold', color=ORANGE)

    ax.set_xlabel('Delta Size (Δn)')
    ax.set_ylabel('Latency (ms)')
    ax.set_title(f'SGX Enclave Overhead (N={N:,})')
    ax.set_xticks(x)
    ax.set_xticklabels([f'{d:,}' for d in common_deltas])
    ax.legend(loc='upper left')
    ax.grid(True, alpha=0.2, axis='y')

    path = os.path.join(output_dir, 'chart_sgx_overhead.png')
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")


# ─── Chart 4: Speedup (Non-Opt / Optimized) ─────────────────────────────────

def plot_speedup(data, output_dir):
    """Speedup of optimized over non-optimized, grouped by N."""
    non_opt_key = 'Non-Optimized'
    opt_keys = [k for k in data.keys() if k.startswith('Optimized')]

    if non_opt_key not in data or not opt_keys:
        print("  Skipping speedup chart (need non-optimized + optimized data)")
        return

    baselines = sorted(set(data[non_opt_key].keys()))
    deltas = get_all_deltas(data)

    fig, axes = plt.subplots(1, len(baselines), figsize=(6 * len(baselines), 5),
                             squeeze=False, sharey=True)

    for idx, N in enumerate(baselines):
        ax = axes[0][idx]

        if N not in data[non_opt_key]:
            continue

        for opt_key in opt_keys:
            if N not in data.get(opt_key, {}):
                continue

            common_deltas = sorted(
                set(data[non_opt_key][N].keys()) & set(data[opt_key][N].keys())
            )

            speedups = []
            for dn in common_deltas:
                non_opt_mean = mean_val(data[non_opt_key][N][dn], 't_total_ms')
                opt_mean = mean_val(data[opt_key][N][dn], 't_total_ms')
                speedups.append(non_opt_mean / opt_mean if opt_mean > 0 else 0)

            color = COLORS.get(opt_key, GRAY)
            ax.bar(range(len(common_deltas)), speedups,
                   color=color, alpha=0.85, width=0.6, label=opt_key)

            for i, sp in enumerate(speedups):
                ax.text(i, sp + 0.5, f'{sp:.1f}×', ha='center', va='bottom',
                        fontsize=9, fontweight='bold', color=color)

        ax.set_xlabel('Δn')
        ax.set_title(f'N = {N:,}')
        ax.set_xticks(range(len(common_deltas)))
        ax.set_xticklabels([f'{d:,}' for d in common_deltas], rotation=45)
        ax.grid(True, alpha=0.2, axis='y')
        if idx == 0:
            ax.set_ylabel('Speedup over Non-Optimized')
            ax.legend(fontsize=9)

    fig.suptitle('Incremental Attestation Speedup', fontsize=15, fontweight='bold')
    plt.tight_layout()

    path = os.path.join(output_dir, 'chart_speedup.png')
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")


# ─── Chart 5: Stacked Time Breakdown ────────────────────────────────────────

def plot_time_breakdown(data, output_dir):
    """Stacked bar chart showing time breakdown by phase for each mode."""
    modes = sorted(data.keys())
    baselines = get_all_baselines(data)
    deltas = get_all_deltas(data)

    # Pick the largest N
    N = max(baselines)

    fig, ax = plt.subplots(figsize=(14, 6))

    categories = []
    t_connect = []
    t_response = []
    t_quote = []
    t_ima = []

    for mode in modes:
        if N not in data.get(mode, {}):
            continue
        for dn in deltas:
            if dn not in data[mode].get(N, {}):
                continue

            results = data[mode][N][dn]
            categories.append(f'{mode}\nΔ={dn:,}')
            t_connect.append(mean_val(results, 't_connect_ms'))
            t_response.append(mean_val(results, 't_response_ms'))
            t_quote.append(mean_val(results, 't_quote_verify_ms'))
            t_ima.append(mean_val(results, 't_ima_verify_ms'))

    if not categories:
        print("  Skipping time breakdown chart (no data)")
        return

    x = np.arange(len(categories))
    width = 0.7

    bars1 = ax.bar(x, t_response, width, label='Server + Network',
                   color='#2563eb', alpha=0.85)
    bars2 = ax.bar(x, t_ima, width, bottom=t_response,
                   label='IMA Verification', color='#16a34a', alpha=0.85)
    bars3 = ax.bar(x, t_quote, width,
                   bottom=[r + i for r, i in zip(t_response, t_ima)],
                   label='Quote Verification', color='#ea580c', alpha=0.85)
    bars4 = ax.bar(x, t_connect, width,
                   bottom=[r + i + q for r, i, q in zip(t_response, t_ima, t_quote)],
                   label='TLS Connect', color='#7c3aed', alpha=0.85)

    ax.set_ylabel('Latency (ms)')
    ax.set_title(f'Time Breakdown by Phase (N={N:,})')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=8, rotation=45, ha='right')
    ax.legend(loc='upper right')
    ax.set_yscale('log')
    ax.grid(True, alpha=0.2, axis='y', which='both')

    path = os.path.join(output_dir, 'chart_time_breakdown.png')
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")


# ─── Chart 6: Latency Comparison (single combined chart) ────────────────────

def plot_combined_latency(data, output_dir):
    """Combined latency chart with all modes and N values."""
    modes = sorted(data.keys())
    baselines = get_all_baselines(data)
    deltas = get_all_deltas(data)

    fig, ax = plt.subplots(figsize=(10, 6))

    for mode in modes:
        for N in baselines:
            if N not in data.get(mode, {}):
                continue

            dn_vals = sorted(data[mode][N].keys())
            means = [mean_val(data[mode][N][dn], 't_total_ms') for dn in dn_vals]

            color = COLORS.get(mode, GRAY)
            marker = MARKERS.get(mode, 'x')

            # Vary line style by N
            n_idx = baselines.index(N)
            linestyles = ['-', '--', '-.', ':']
            ls = linestyles[n_idx % len(linestyles)]

            label = f'{mode}, N={N:,}'
            ax.plot(dn_vals, means, f'{marker}{ls}', color=color,
                    linewidth=1.5, markersize=6, label=label, alpha=0.8)

    ax.set_xlabel('Δn (new IMA entries)')
    ax.set_ylabel('End-to-End Latency (ms)')
    ax.set_title('Incremental Attestation: All Conditions')
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(loc='upper left', fontsize=8, ncol=2)
    ax.grid(True, alpha=0.3, which='both')
    ax.xaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))

    path = os.path.join(output_dir, 'chart_combined_latency.png')
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate charts from incremental attestation benchmark results"
    )
    parser.add_argument("--csv", required=True,
                        help="Input CSV file with benchmark results")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory for charts (default: same as CSV)")

    args = parser.parse_args()

    output_dir = args.output_dir or os.path.dirname(os.path.abspath(args.csv))
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("Incremental Attestation — Chart Generator")
    print("=" * 60)
    print(f"  Input:  {args.csv}")
    print(f"  Output: {output_dir}/")

    rows = load_csv(args.csv)
    data = parse_results(rows)

    modes = sorted(data.keys())
    baselines = get_all_baselines(data)
    deltas = get_all_deltas(data)

    print(f"\n  Modes:     {modes}")
    print(f"  Baselines: {baselines}")
    print(f"  Deltas:    {deltas}")
    print(f"  Total:     {len(rows)} data points")
    print()

    plot_latency_vs_delta(data, output_dir)
    plot_server_read_heatmap(data, output_dir)
    plot_sgx_overhead(data, output_dir)
    plot_speedup(data, output_dir)
    plot_time_breakdown(data, output_dir)
    plot_combined_latency(data, output_dir)

    print(f"\n  All charts saved to: {output_dir}/")


if __name__ == "__main__":
    main()
