# Incremental Attestation Microbenchmark — Makefile
#
# Convenience targets for running the benchmark experiment.
#
# This benchmark measures end-to-end remote attestation latency with
# three conditions (non-optimized, optimized+SGX, optimized+Python),
# varying baseline IMA size (N) and delta entries (Δn).

# ============================================================================
# Configuration
# ============================================================================

# CVM attestation agent settings
TDX_HOST ?= localhost
TDX_PORT ?= 8443
METHOD ?= dcap

# Certificate paths (relative to sgx-tdx-attestation/certs/)
CERTS_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../sgx-tdx-attestation/certs)
CERT ?= $(CERTS_DIR)/server.crt
KEY ?= $(CERTS_DIR)/server.key

# Experiment matrix
BASELINES ?= 10000,50000,100000,200000
DELTAS ?= 100,500,1000,5000,10000,15000
REPEATS ?= 3

# Gramine / SGX settings
SGX_VERIFIER_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../sgx-tdx-attestation/sgx-verifier)
APP_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../sgx-tdx-attestation)

# Output directory
OUTPUT_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# ============================================================================
# Help
# ============================================================================

.PHONY: help
help:
	@echo "Incremental Attestation Microbenchmark"
	@echo "======================================"
	@echo ""
	@echo "CVM-Side Targets (run on TDX CVM):"
	@echo "  agent                 - Start CVM attestation agent (supports both modes)"
	@echo "  agent-test            - Self-test the agent"
	@echo "  ima-status            - Show current IMA entry count"
	@echo "  ima-baseline-10k      - Generate IMA baseline to 10K entries"
	@echo "  ima-baseline-50k      - Generate IMA baseline to 50K entries"
	@echo "  ima-baseline-100k     - Generate IMA baseline to 100K entries"
	@echo "  ima-baseline-200k     - Generate IMA baseline to 200K entries"
	@echo "  ima-delta-N           - Generate N new IMA entries (e.g., make ima-delta-100)"
	@echo ""
	@echo "Subscriber-Side Targets (run on SGX or benchmark machine):"
	@echo "  bench-non-optimized   - Benchmark non-optimized incremental attestation"
	@echo "  bench-optimized-python - Benchmark optimized incremental (Python, no SGX)"
	@echo "  bench-optimized-sgx   - Benchmark optimized incremental (inside SGX enclave)"
	@echo "  bench-all             - Run all three benchmarks sequentially"
	@echo "  dry-run               - Show experiment matrix without running"
	@echo ""
	@echo "Analysis Targets:"
	@echo "  plot                  - Generate charts from results CSV"
	@echo "  merge-csv             - Merge multiple result CSVs into one"
	@echo ""
	@echo "Configuration:"
	@echo "  TDX_HOST     = $(TDX_HOST)"
	@echo "  TDX_PORT     = $(TDX_PORT)"
	@echo "  METHOD       = $(METHOD)"
	@echo "  BASELINES    = $(BASELINES)"
	@echo "  DELTAS       = $(DELTAS)"
	@echo "  REPEATS      = $(REPEATS)"
	@echo ""
	@echo "Example:"
	@echo "  # On CVM:"
	@echo "  make agent METHOD=dcap"
	@echo ""
	@echo "  # On SGX machine:"
	@echo "  make bench-non-optimized TDX_HOST=10.0.0.1"
	@echo "  make bench-optimized-python TDX_HOST=10.0.0.1"
	@echo "  make bench-optimized-sgx TDX_HOST=10.0.0.1"

# ============================================================================
# CVM-Side Targets
# ============================================================================

.PHONY: agent agent-test ima-status

agent:
	@echo ""
	@echo "Starting CVM Attestation Agent..."
	@echo "=================================="
	sudo python3 cvm_attestation_agent.py \
		--port $(TDX_PORT) \
		--cert $(CERT) \
		--key $(KEY) \
		--method $(METHOD)

agent-test:
	sudo python3 cvm_attestation_agent.py --test

ima-status:
	sudo python3 generate_ima_baseline.py --status

# Generate baselines
.PHONY: ima-baseline-10k ima-baseline-50k ima-baseline-100k ima-baseline-200k

ima-baseline-10k:
	sudo python3 generate_ima_baseline.py --target 10000

ima-baseline-50k:
	sudo python3 generate_ima_baseline.py --target 50000

ima-baseline-100k:
	sudo python3 generate_ima_baseline.py --target 100000

ima-baseline-200k:
	sudo python3 generate_ima_baseline.py --target 200000

# Generate deltas (usage: make ima-delta-100, make ima-delta-5000, etc.)
ima-delta-%:
	sudo python3 generate_ima_baseline.py --delta $*

# ============================================================================
# Subscriber-Side Targets
# ============================================================================

.PHONY: bench-non-optimized bench-optimized-python bench-optimized-sgx bench-all dry-run

bench-non-optimized:
	@echo ""
	@echo "Running Non-Optimized Incremental Attestation Benchmark..."
	@echo "==========================================================="
	python3 benchmark_incremental.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--no-verify \
		--mode non_optimized \
		--baselines $(BASELINES) \
		--deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--output $(OUTPUT_DIR)/results_non_optimized.csv

bench-optimized-python:
	@echo ""
	@echo "Running Optimized Incremental Attestation Benchmark (Python)..."
	@echo "================================================================"
	python3 benchmark_incremental.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--no-verify \
		--mode optimized \
		--baselines $(BASELINES) \
		--deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--output $(OUTPUT_DIR)/results_optimized_python.csv

bench-optimized-sgx:
	@echo ""
	@echo "Running Optimized Incremental Attestation Benchmark (SGX)..."
	@echo "============================================================="
	@echo "NOTE: This requires the Gramine manifest to be built."
	@echo "      Run 'make -C $(SGX_VERIFIER_DIR) all' first if needed."
	@echo ""
	cd $(SGX_VERIFIER_DIR) && \
	gramine-sgx ./verifier $(abspath benchmark_incremental.py) \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--no-verify \
		--mode optimized \
		--baselines $(BASELINES) \
		--deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--output $(OUTPUT_DIR)/results_optimized_sgx.csv

bench-all: bench-non-optimized bench-optimized-python bench-optimized-sgx
	@echo ""
	@echo "All benchmarks complete!"
	@echo "Merging results..."
	$(MAKE) merge-csv
	$(MAKE) plot CSV=$(OUTPUT_DIR)/results_all.csv

dry-run:
	python3 benchmark_incremental.py \
		--tdx-host $(TDX_HOST) \
		--mode all \
		--baselines $(BASELINES) \
		--deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--dry-run

# ============================================================================
# Analysis Targets
# ============================================================================

.PHONY: plot merge-csv

CSV ?= $(OUTPUT_DIR)/results_all.csv

plot:
	@echo ""
	@echo "Generating charts..."
	python3 plot_results.py --csv $(CSV) --output-dir $(OUTPUT_DIR)

merge-csv:
	@echo "Merging result CSVs..."
	@python3 -c "\
import csv, glob, os; \
files = sorted(glob.glob('$(OUTPUT_DIR)/results_*.csv')); \
files = [f for f in files if 'results_all' not in f]; \
print(f'  Found {len(files)} files: {[os.path.basename(f) for f in files]}'); \
all_rows = []; \
header = None; \
[all_rows.extend(list(csv.DictReader(open(f)))) or (header := list(csv.DictReader(open(f)).fieldnames) if header is None else header) for f in files]; \
writer = csv.DictWriter(open('$(OUTPUT_DIR)/results_all.csv', 'w', newline=''), fieldnames=header or list(all_rows[0].keys())); \
writer.writeheader(); writer.writerows(all_rows); \
print(f'  Merged {len(all_rows)} rows → results_all.csv')"

# ============================================================================
# Cleanup
# ============================================================================

.PHONY: clean
clean:
	rm -f $(OUTPUT_DIR)/results_*.csv
	rm -f $(OUTPUT_DIR)/chart_*.png
	@echo "Cleaned results and charts."
