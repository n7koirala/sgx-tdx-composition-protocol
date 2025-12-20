# Gramine SGX Remote Attestation Demo - Makefile
#
# This Makefile builds and runs the Python-based SGX attestation demo
# using Gramine Library OS.

# ============================================================================
# Configuration
# ============================================================================

# Detect Python version and paths
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)

# Gramine signing key (use default location or custom)
SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Log level: error, warning, debug, trace, all
LOG_LEVEL ?= error

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean run-sgx run-direct view-quote benchmark check-setup help

# Default target
all: attestation.manifest.sgx attestation.sig

help:
	@echo "Gramine SGX Remote Attestation Demo"
	@echo "===================================="
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the Gramine manifest and sign it"
	@echo "  run-sgx      - Run the demo inside SGX enclave"
	@echo "  run-direct   - Run without SGX (for testing)"
	@echo "  view-quote   - View the generated quote"
	@echo "  benchmark    - Run quote generation benchmark"
	@echo "  check-setup  - Verify SGX and Gramine setup"
	@echo "  clean        - Remove generated files"
	@echo ""
	@echo "Configuration:"
	@echo "  PYTHON_VERSION = $(PYTHON_VERSION)"
	@echo "  PYTHON_PATH    = $(PYTHON_PATH)"
	@echo "  ARCH_LIBDIR    = $(ARCH_LIBDIR)"
	@echo "  SGX_SIGNING_KEY = $(SGX_SIGNING_KEY)"
	@echo "  LOG_LEVEL      = $(LOG_LEVEL)"

# ============================================================================
# Build Steps
# ============================================================================

# Step 1: Generate the manifest from template
# Note: This can take several minutes as Gramine hashes all trusted files
attestation.manifest: attestation.manifest.template attestation_demo.py
	@echo "[1/2] Generating manifest (this may take a few minutes)..."
	@echo "      Gramine is hashing all trusted files..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		$< $@
	@echo "      ✓ Manifest generated ($$(du -h $@ | cut -f1))"

# Step 2: Sign the manifest for SGX
attestation.manifest.sgx attestation.sig: attestation.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing manifest for SGX..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo "      ✓ Manifest signed"
	@echo ""
	@echo "Enclave ready! Measurements:"
	@gramine-sgx-sigstruct-view attestation.sig

# Generate signing key if it doesn't exist
$(SGX_SIGNING_KEY):
	@echo "Generating SGX signing key..."
	gramine-sgx-gen-private-key $@

# ============================================================================
# Run Targets
# ============================================================================

# Run inside SGX enclave
run-sgx: all
	@echo ""
	@echo "Running attestation demo inside SGX enclave..."
	@echo "================================================"
	gramine-sgx ./attestation attestation_demo.py

# Run without SGX (direct mode) - useful for initial testing
run-direct: attestation.manifest
	@echo ""
	@echo "Running attestation demo in direct mode (no SGX)..."
	@echo "===================================================="
	@echo "Note: /dev/attestation won't be available"
	gramine-direct ./attestation attestation_demo.py

# Run with verbose logging
run-sgx-debug: LOG_LEVEL = debug
run-sgx-debug: clean all
	gramine-sgx ./attestation attestation_demo.py

# Run benchmark
benchmark: all
	@echo "Running quote generation benchmark..."
	RUN_BENCHMARK=1 gramine-sgx ./attestation attestation_demo.py

# ============================================================================
# Verification
# ============================================================================

# View the generated quote
view-quote: quote.bin
	@echo "Viewing SGX quote..."
	gramine-sgx-quote-view quote.bin

# Verify the quote with our Python script
verify: quote.bin
	@echo "Verifying SGX quote..."
	python3 verify_quote.py quote.bin

# View enclave measurements
view-sig: attestation.sig
	@echo "Viewing enclave signature structure..."
	gramine-sgx-sigstruct-view attestation.sig

# ============================================================================
# Setup Verification
# ============================================================================

check-setup:
	@echo "Checking SGX and Gramine setup..."
	@echo "=================================="
	@echo ""
	@echo "[1] Gramine version:"
	@gramine-sgx --version || echo "   ✗ Gramine not found"
	@echo ""
	@echo "[2] SGX device:"
	@ls -la /dev/sgx_enclave 2>/dev/null && echo "   ✓ SGX device available" || echo "   ✗ SGX device not found"
	@echo ""
	@echo "[3] AESM service:"
	@systemctl is-active aesmd && echo "   ✓ AESM running" || echo "   ✗ AESM not running"
	@echo ""
	@echo "[4] Signing key:"
	@test -f $(SGX_SIGNING_KEY) && echo "   ✓ Key exists: $(SGX_SIGNING_KEY)" || echo "   ✗ Key not found"
	@echo ""
	@echo "[5] Python version: $(PYTHON_VERSION)"
	@echo "   Python path: $(PYTHON_PATH)"
	@echo ""
	@echo "[6] DCAP libraries:"
	@ldconfig -p | grep -q dcap_quoteverify && echo "   ✓ Quote verify library found" || echo "   ✗ Quote verify library not found"
	@echo ""

# ============================================================================
# Cleanup
# ============================================================================

clean:
	rm -f attestation.manifest attestation.manifest.sgx attestation.sig
	rm -f quote.bin
	rm -rf __pycache__/

distclean: clean
	# Note: Does not remove signing key for safety

# ============================================================================
# Development helpers
# ============================================================================

# Test Python script outside of enclave
test-python:
	python3 attestation_demo.py

# Quick rebuild (if only script changed)
quick: attestation_demo.py
	@echo "Regenerating manifest with updated script..."
	rm -f attestation.manifest attestation.manifest.sgx attestation.sig
	$(MAKE) all
