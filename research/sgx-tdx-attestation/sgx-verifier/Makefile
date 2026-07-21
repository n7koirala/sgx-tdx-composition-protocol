# Gramine SGX TDX Verifier - Makefile
#
# Builds and runs the SGX enclave that verifies TDX attestation.
# Part of the Hierarchical TEE Attestation Protocol.

# ============================================================================
# Configuration
# ============================================================================

# Detect Python version and paths
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)

# Application directory (parent of sgx-verifier)
APP_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))..)
CHECKPOINT_DIR := $(APP_DIR)/runtime-state/sealed-checkpoints
BENCHMARK_RESULT_DIR := $(APP_DIR)/runtime-state/benchmark-results

# Gramine signing key
SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Log level: error, warning, debug, trace, all
LOG_LEVEL ?= error

# TDX server defaults
TDX_HOST ?= localhost
TDX_PORT ?= 8443

# Attestation method: ita (Intel Trust Authority) or dcap (local DCAP)
METHOD ?= dcap
RUNTIME_ARGS ?= --expected-rtmr3-base auto

# Multi-controller settings
CONTROLLER_ID ?= ctrl-1
CONTROLLER_PORT ?= 9001
REFRESH_INTERVAL ?= 30

# mTLS configuration (client certificate for SGX enclave identity)
CA_CERT ?= /app/certs/ca.crt
CLIENT_CERT ?= /app/certs/sgx_client.crt
CLIENT_KEY ?= /app/certs/sgx_client.key

# ============================================================================
# Targets
# ============================================================================

.PHONY: all checkpoint-dir clean run-sgx run-direct run-controller \
	run-controller-python test-network check-setup help bench-runtime-sgx \
	bench-matrix-non-optimized bench-matrix-python bench-matrix-sgx

# Default target
all: verifier.manifest.sgx verifier.sig

help:
	@echo "SGX TDX Verifier - Hierarchical Attestation"
	@echo "============================================"
	@echo ""
	@echo "Build Targets:"
	@echo "  all                    - Build the Gramine manifest and sign it"
	@echo "  clean                  - Remove generated files"
	@echo ""
	@echo "Run Targets (single-shot verifier):"
	@echo "  run-sgx                - Run verifier inside SGX enclave"
	@echo "  run-direct             - Run verifier in direct mode (no SGX)"
	@echo "  test-network           - Test network connectivity to TDX server"
	@echo ""
	@echo "Run Targets (multi-controller):"
	@echo "  run-controller         - Run long-lived controller (SGX, serves end-users)"
	@echo "  run-controller-python  - Run controller in pure Python (no Gramine)"
	@echo ""
	@echo "Protocol 1.2 paper benchmarks:"
	@echo "  bench-matrix-non-optimized - Reopen/reparse control in Python"
	@echo "  bench-matrix-python        - Persistent-FD verifier in Python"
	@echo "  bench-matrix-sgx           - Persistent-FD verifier in Gramine SGX"
	@echo ""
	@echo "Setup:"
	@echo "  check-setup   - Verify SGX and Gramine setup"
	@echo "  gen-certs     - Generate TLS certificates"
	@echo ""
	@echo "Configuration:"
	@echo "  TDX_HOST          = $(TDX_HOST)"
	@echo "  TDX_PORT          = $(TDX_PORT)"
	@echo "  METHOD            = $(METHOD)"
	@echo "  CONTROLLER_ID     = $(CONTROLLER_ID)"
	@echo "  CONTROLLER_PORT   = $(CONTROLLER_PORT)"
	@echo "  REFRESH_INTERVAL  = $(REFRESH_INTERVAL)s"
	@echo ""
	@echo "Example:"
	@echo "  make run-controller TDX_HOST=10.0.0.1 METHOD=dcap CONTROLLER_PORT=9001"

# ============================================================================
# Build Steps
# ============================================================================

checkpoint-dir:
	mkdir -p $(CHECKPOINT_DIR) $(BENCHMARK_RESULT_DIR)

# Step 1: Generate the manifest from template
verifier.manifest: verifier.manifest.template sgx_tdx_verifier.py sgx_controller.py \
                   benchmark_incremental_runtime.py \
		   benchmark_protocol_matrix.py \
                   ../common/protocol.py ../common/ima_rtmr3.py \
                   ../common/ima_stream.py ../common/vtpm_quote.py \
                   ../common/runtime_agent.py ../common/runtime_verifier.py \
                   ../common/sealed_checkpoint.py | checkpoint-dir
	@echo "[1/2] Generating manifest (this may take a few minutes)..."
	@echo "      Gramine is hashing all trusted files..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dapp_dir=$(APP_DIR) \
		$< $@
	@echo "      ✓ Manifest generated ($$(du -h $@ | cut -f1))"

# Step 2: Sign the manifest for SGX
verifier.manifest.sgx verifier.sig: verifier.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing manifest for SGX..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo "      ✓ Manifest signed"
	@echo ""
	@echo "Enclave ready! Measurements:"
	@gramine-sgx-sigstruct-view verifier.sig

# Generate signing key if it doesn't exist
$(SGX_SIGNING_KEY):
	@echo "Generating SGX signing key..."
	gramine-sgx-gen-private-key $@

# ============================================================================
# Run Targets
# ============================================================================

# Run inside SGX enclave (with mTLS)
run-sgx: all
	@echo ""
	@echo "Running TDX verifier inside SGX enclave (mTLS enabled)..."
	@echo "Target: $(TDX_HOST):$(TDX_PORT)  Method: $(METHOD)"
	@echo "Client Cert: $(CLIENT_CERT)"
	@echo "========================================"
	gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--ca-cert $(CA_CERT) \
		--client-cert $(CLIENT_CERT) \
		--client-key $(CLIENT_KEY) \
		--verbose $(RUNTIME_ARGS)

# Run without SGX (direct mode, with mTLS)
run-direct: verifier.manifest
	@echo ""
	@echo "Running TDX verifier in direct mode (mTLS enabled)..."
	@echo "========================================"
	gramine-direct ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--ca-cert $(CA_CERT) \
		--client-cert $(CLIENT_CERT) \
		--client-key $(CLIENT_KEY) \
		--verbose $(RUNTIME_ARGS)

# Run without Gramine at all (pure Python, for testing)
run-python:
	@echo ""
	@echo "Running TDX verifier in pure Python mode (mTLS enabled)..."
	@echo "============================================"
	PYTHONPATH=$(APP_DIR) python3 sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--ca-cert ../certs/ca.crt \
		--client-cert ../certs/sgx_client.crt \
		--client-key ../certs/sgx_client.key \
		--verbose $(RUNTIME_ARGS)

# Test network connectivity
test-network: all
	@echo ""
	@echo "Testing network connectivity to $(TDX_HOST):$(TDX_PORT)..."
	gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--test-network

# ============================================================================
# Multi-Controller Targets
# ============================================================================

# Run controller inside SGX enclave (long-lived server)
run-controller: all
	@echo ""
	@echo "Starting SGX controller $(CONTROLLER_ID) on port $(CONTROLLER_PORT)..."
	@echo "TDX target: $(TDX_HOST):$(TDX_PORT)  Method: $(METHOD)"
	@echo "========================================"
	gramine-sgx ./verifier /app/sgx-verifier/sgx_controller.py \
		--controller-id $(CONTROLLER_ID) \
		--port $(CONTROLLER_PORT) \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--cert /app/certs/server.crt \
		--key /app/certs/server.key \
		--no-verify-tdx \
		--refresh-interval $(REFRESH_INTERVAL) \
		--verbose $(RUNTIME_ARGS)

# Run controller without Gramine (pure Python, for testing)
run-controller-python:
	@echo ""
	@echo "Starting controller $(CONTROLLER_ID) in pure Python mode..."
	@echo "========================================"
	PYTHONPATH=$(APP_DIR) python3 sgx_controller.py \
		--controller-id $(CONTROLLER_ID) \
		--port $(CONTROLLER_PORT) \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--method $(METHOD) \
		--cert ../certs/server.crt \
		--key ../certs/server.key \
		--no-verify-tdx \
		--refresh-interval $(REFRESH_INTERVAL) \
		--verbose $(RUNTIME_ARGS)

# ============================================================================
# Benchmark Targets
# ============================================================================

# Benchmark configuration
ROUNDS ?= 5
RUNTIME_ROUNDS ?= 10
RUNTIME_INTERVAL ?= 1
MATRIX_BASELINES ?= 10000,50000,100000,200000
MATRIX_DELTAS ?= 100,500,1000,5000,10000,15000
MATRIX_REPEATS ?= 1
MATRIX_ARGS ?= --expected-rtmr3-base auto

bench-matrix-non-optimized: checkpoint-dir
	PYTHONPATH=$(APP_DIR) python3 benchmark_protocol_matrix.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--mode non_optimized \
		--no-verify \
		--baselines $(MATRIX_BASELINES) \
		--deltas $(MATRIX_DELTAS) \
		--repeats $(MATRIX_REPEATS) \
		--output $(BENCHMARK_RESULT_DIR)/results_vtpm_non_optimized.csv \
		$(MATRIX_ARGS)

bench-matrix-python: checkpoint-dir
	PYTHONPATH=$(APP_DIR) python3 benchmark_protocol_matrix.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--mode optimized \
		--no-verify \
		--baselines $(MATRIX_BASELINES) \
		--deltas $(MATRIX_DELTAS) \
		--repeats $(MATRIX_REPEATS) \
		--output $(BENCHMARK_RESULT_DIR)/results_vtpm_optimized_python.csv \
		$(MATRIX_ARGS)

bench-matrix-sgx: all
	gramine-sgx ./verifier \
		/app/sgx-verifier/benchmark_protocol_matrix.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--mode optimized \
		--no-verify \
		--baselines $(MATRIX_BASELINES) \
		--deltas $(MATRIX_DELTAS) \
		--repeats $(MATRIX_REPEATS) \
		--output /app/runtime-state/benchmark-results/results_vtpm_optimized_sgx.csv \
		$(MATRIX_ARGS)

bench-runtime-sgx: all
	gramine-sgx ./verifier /app/sgx-verifier/benchmark_incremental_runtime.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--rounds $(RUNTIME_ROUNDS) \
		--interval $(RUNTIME_INTERVAL) \
		--output /app/runtime-state/benchmark-results/incremental-runtime.csv \
		$(RUNTIME_ARGS)

STRATEGY ?= both
DELTAS ?= 100,500,1000,5000,10000

# Run e2e benchmark inside SGX enclave
bench-sgx: all
	@echo ""
	@echo "Running E2E IMA benchmark inside SGX enclave..."
	@echo "Target: $(TDX_HOST):$(TDX_PORT)  Strategy: $(STRATEGY)  Rounds: $(ROUNDS)"
	@echo "========================================"
	gramine-sgx ./verifier /app/sgx-verifier/benchmark_e2e.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--strategy $(STRATEGY) \
		--no-verify \
		--rounds $(ROUNDS) \
		--output /tmp/benchmark_e2e_sgx.csv

# Run e2e benchmark in pure Python (no SGX, for comparison)
bench-python:
	@echo ""
	@echo "Running E2E IMA benchmark in pure Python (no SGX)..."
	@echo "========================================"
	PYTHONPATH=$(APP_DIR) python3 benchmark_e2e.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--strategy $(STRATEGY) \
		--no-verify \
		--rounds $(ROUNDS) \
		--output benchmark_e2e_python.csv

# Run delta scaling benchmark inside SGX enclave
bench-delta-sgx: all
	@echo ""
	@echo "Running Delta Scaling benchmark inside SGX enclave..."
	@echo "Deltas: $(DELTAS)"
	@echo "========================================"
	gramine-sgx ./verifier /app/sgx-verifier/benchmark_delta_scaling.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--deltas $(DELTAS) \
		--output /tmp/benchmark_delta_sgx.csv

# Run delta scaling benchmark in pure Python (no SGX)
bench-delta-python:
	@echo ""
	@echo "Running Delta Scaling benchmark in pure Python (no SGX)..."
	@echo "========================================"
	PYTHONPATH=$(APP_DIR) python3 benchmark_delta_scaling.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--deltas $(DELTAS) \
		--output benchmark_delta_python.csv

# ============================================================================
# Certificate Generation
# ============================================================================

gen-certs:
	@echo "Generating TLS certificates..."
	cd ../certs && ./generate_certs.sh

# ============================================================================
# Setup Verification
# ============================================================================

check-setup:
	@echo "Checking SGX and Gramine setup..."
	@echo "=================================="
	@echo ""
	@echo "[1] Gramine version:"
	@gramine-sgx --version 2>/dev/null || echo "   ✗ Gramine not found"
	@echo ""
	@echo "[2] SGX device:"
	@ls -la /dev/sgx_enclave 2>/dev/null && echo "   ✓ SGX device available" || echo "   ✗ SGX device not found"
	@echo ""
	@echo "[3] AESM service:"
	@systemctl is-active aesmd 2>/dev/null && echo "   ✓ AESM running" || echo "   ✗ AESM not running"
	@echo ""
	@echo "[4] Signing key:"
	@test -f $(SGX_SIGNING_KEY) && echo "   ✓ Key exists" || echo "   ✗ Key not found"
	@echo ""
	@echo "[5] Python version: $(PYTHON_VERSION)"
	@echo "   Path: $(PYTHON_PATH)"
	@echo ""
	@echo "[6] Application directory:"
	@echo "   $(APP_DIR)"
	@test -f $(APP_DIR)/common/protocol.py && echo "   ✓ Common module found" || echo "   ✗ Common module not found"
	@echo ""
	@echo "[7] Certificates:"
	@test -f ../certs/ca.crt && echo "   ✓ CA certificate found" || echo "   ✗ CA certificate not found (run: make gen-certs)"
	@test -f ../certs/sgx_client.crt && echo "   ✓ SGX client certificate found" || echo "   ✗ SGX client certificate not found (run: make gen-certs)"
	@test -f ../certs/sgx_client.key && echo "   ✓ SGX client key found" || echo "   ✗ SGX client key not found (run: make gen-certs)"
	@echo ""

# ============================================================================
# Cleanup
# ============================================================================

clean:
	rm -f verifier.manifest verifier.manifest.sgx verifier.sig
	rm -rf __pycache__/

distclean: clean
	# Note: Does not remove signing key for safety

# ============================================================================
# View Measurements
# ============================================================================

view-sig: verifier.sig
	@echo "Viewing enclave signature structure..."
	gramine-sgx-sigstruct-view verifier.sig
