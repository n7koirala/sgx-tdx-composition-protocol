# Incremental Attestation + PCR-10 Replay Microbenchmark — Makefile
#
# Parallel copy of research/incremental_attestation/ with the IMA
# verification step replaced by a merged component that does both the
# existing SHA-1 TLV self-consistency check AND a PCR-10 SHA-1 extend-
# chain replay.  The CVM agent in this folder reads from the SHA-1 PCR
# bank (/sys/class/tpm/tpm0/pcr-sha1/10) so the replay matches.
#
# Output CSVs are suffixed "_pcr" to keep them separate from the
# non-PCR baseline results.

# ============================================================================
# Configuration
# ============================================================================

TDX_HOST ?= localhost
TDX_PORT ?= 8443
METHOD   ?= dcap

CERTS_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../sgx-tdx-attestation/certs)
CERT ?= $(CERTS_DIR)/server.crt
KEY  ?= $(CERTS_DIR)/server.key

# Quick single-point default for the overhead smoke test.
# Override with e.g.  make bench-point-sgx BASELINE=10000 DELTA=1000
BASELINE ?= 10000
DELTA    ?= 1000

# Full matrix (mirrors the original incremental_attestation experiment)
BASELINES ?= 10000,50000,100000,200000
DELTAS    ?= 100,500,1000,5000,10000,15000
REPEATS   ?= 3

PCR_SGX_VERIFIER_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/sgx-verifier)

OUTPUT_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: help
help:
	@echo "Incremental Attestation + PCR-10 Replay"
	@echo "========================================"
	@echo ""
	@echo "CVM-Side:"
	@echo "  agent                     Start the PCR-10 CVM attestation agent"
	@echo "  ima-baseline-N            Generate baseline (10k|50k|100k|200k)"
	@echo "  ima-delta-N               Generate N new IMA entries"
	@echo ""
	@echo "Subscriber-Side (single point — for overhead smoke test):"
	@echo "  bench-point-python        Run ONE (N,Δn) point, native Python"
	@echo "  bench-point-sgx           Run ONE (N,Δn) point, inside SGX enclave"
	@echo ""
	@echo "Subscriber-Side (full matrix):"
	@echo "  bench-non-optimized       Full matrix, native Python, non-optimized"
	@echo "  bench-optimized-python    Full matrix, native Python, optimized"
	@echo "  bench-optimized-sgx       Full matrix, inside SGX enclave"
	@echo ""
	@echo "Config: TDX_HOST=$(TDX_HOST) TDX_PORT=$(TDX_PORT) BASELINE=$(BASELINE) DELTA=$(DELTA)"

# ============================================================================
# CVM-Side Targets
# ============================================================================

.PHONY: agent ima-status

agent:
	@echo "Starting PCR-10 CVM Attestation Agent..."
	sudo python3 cvm_attestation_agent.py \
		--port $(TDX_PORT) \
		--cert $(CERT) \
		--key $(KEY) \
		--method $(METHOD)

ima-status:
	sudo python3 generate_ima_baseline.py --status

.PHONY: ima-baseline-10k ima-baseline-50k ima-baseline-100k ima-baseline-200k

ima-baseline-10k:
	sudo python3 generate_ima_baseline.py --target 10000
ima-baseline-50k:
	sudo python3 generate_ima_baseline.py --target 50000
ima-baseline-100k:
	sudo python3 generate_ima_baseline.py --target 100000
ima-baseline-200k:
	sudo python3 generate_ima_baseline.py --target 200000

ima-delta-%:
	sudo python3 generate_ima_baseline.py --delta $*

# ============================================================================
# Subscriber: single-point overhead smoke tests
# ============================================================================
#
# Run ONE (N,Δn) point in each environment so we can compare the IMA
# verification + PCR replay cost between native Python and SGX without
# burning through the full matrix first.

.PHONY: bench-point-python bench-point-sgx

bench-point-python:
	@echo ""
	@echo "Single-point benchmark (native Python) — N=$(BASELINE), Δn=$(DELTA)"
	@echo "=============================================================="
	python3 benchmark_incremental.py \
		--tdx-host $(TDX_HOST) --tdx-port $(TDX_PORT) \
		--method $(METHOD) --no-verify \
		--mode optimized \
		--baselines $(BASELINE) --deltas $(DELTA) \
		--repeats 1 \
		--output $(OUTPUT_DIR)/results_point_python_pcr.csv

bench-point-sgx: sgx-build
	@echo ""
	@echo "Single-point benchmark (SGX enclave) — N=$(BASELINE), Δn=$(DELTA)"
	@echo "==============================================================="
	@touch $(OUTPUT_DIR)/results_point_sgx_pcr.csv
	cd $(PCR_SGX_VERIFIER_DIR) && \
	gramine-sgx ./verifier /benchmark/benchmark_incremental.py \
		--tdx-host $(TDX_HOST) --tdx-port $(TDX_PORT) \
		--method $(METHOD) --no-verify \
		--mode optimized \
		--baselines $(BASELINE) --deltas $(DELTA) \
		--repeats 1 \
		--output /benchmark/results_point_sgx_pcr.csv

# ============================================================================
# Subscriber: full matrix
# ============================================================================

.PHONY: bench-non-optimized bench-optimized-python bench-optimized-sgx

bench-non-optimized:
	python3 benchmark_incremental.py \
		--tdx-host $(TDX_HOST) --tdx-port $(TDX_PORT) \
		--method $(METHOD) --no-verify \
		--mode non_optimized \
		--baselines $(BASELINES) --deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--output $(OUTPUT_DIR)/results_non_optimized_pcr.csv

bench-optimized-python:
	python3 benchmark_incremental.py \
		--tdx-host $(TDX_HOST) --tdx-port $(TDX_PORT) \
		--method $(METHOD) --no-verify \
		--mode optimized \
		--baselines $(BASELINES) --deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--output $(OUTPUT_DIR)/results_optimized_python_pcr.csv

bench-optimized-sgx: sgx-build
	@touch $(OUTPUT_DIR)/results_optimized_sgx_pcr.csv
	cd $(PCR_SGX_VERIFIER_DIR) && \
	gramine-sgx ./verifier /benchmark/benchmark_incremental.py \
		--tdx-host $(TDX_HOST) --tdx-port $(TDX_PORT) \
		--method $(METHOD) --no-verify \
		--mode optimized \
		--baselines $(BASELINES) --deltas $(DELTAS) \
		--repeats $(REPEATS) \
		--output /benchmark/results_optimized_sgx_pcr.csv

# ============================================================================
# SGX enclave build
# ============================================================================

.PHONY: sgx-build
sgx-build:
	$(MAKE) -C $(PCR_SGX_VERIFIER_DIR) all

.PHONY: clean
clean:
	rm -f $(OUTPUT_DIR)/results_*_pcr.csv
	$(MAKE) -C $(PCR_SGX_VERIFIER_DIR) clean
