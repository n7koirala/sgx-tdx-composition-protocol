# Gramine SGX Gateway - Makefile
#
# Builds and runs the SGX Gateway for secure runtime updates.
# Part of the SGX-TDX Runtime Update System.

# =============================================================================
# Configuration
# =============================================================================

# Detect Python version and paths
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)
HOME_DIR := $(HOME)

# Application directory (parent of sgx-gateway)
APP_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../)

# Gramine signing key
SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Log level: error, warning, debug, trace, all
LOG_LEVEL ?= error

# Gateway configuration
GATEWAY_PORT ?= 8445

# TLS/mTLS configuration
CA_CERT ?= /app/certs/ca.crt
SERVER_CERT ?= /app/certs/server.crt
SERVER_KEY ?= /app/certs/server.key

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean run-sgx run-direct help check-setup gen-keys

# Default target
all: gateway.manifest.sgx gateway.sig

help:
	@echo "SGX Gateway - Secure Runtime Update System"
	@echo "==========================================="
	@echo ""
	@echo "Build Targets:"
	@echo "  all           - Build the Gramine manifest and sign it"
	@echo "  clean         - Remove generated files"
	@echo ""
	@echo "Run Targets:"
	@echo "  run-sgx       - Run gateway inside SGX enclave"
	@echo "  run-direct    - Run gateway in direct mode (no SGX)"
	@echo "  run-python    - Run gateway in pure Python mode"
	@echo ""
	@echo "Setup:"
	@echo "  check-setup   - Verify SGX and dependencies"
	@echo "  gen-keys      - Generate enclave signing and SSH keys"
	@echo "  gen-certs     - Generate TLS certificates"
	@echo ""
	@echo "Configuration:"
	@echo "  PYTHON_VERSION = $(PYTHON_VERSION)"
	@echo "  APP_DIR        = $(APP_DIR)"
	@echo "  GATEWAY_PORT   = $(GATEWAY_PORT)"
	@echo ""

# =============================================================================
# Build Steps
# =============================================================================

# Step 1: Generate the manifest from template
gateway.manifest: gateway.manifest.template gateway_server.py command_executor.py audit_logger.py ../common/protocol.py ../common/crypto.py
	@echo "[1/2] Generating manifest..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dapp_dir=$(APP_DIR) \
		-Dhome_dir=$(HOME_DIR) \
		$< $@
	@echo "      ✓ Manifest generated"

# Step 2: Sign the manifest for SGX
gateway.manifest.sgx gateway.sig: gateway.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing manifest for SGX..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo "      ✓ Manifest signed"
	@echo ""
	@echo "Enclave ready! Measurements:"
	@gramine-sgx-sigstruct-view gateway.sig

# Generate signing key if needed
$(SGX_SIGNING_KEY):
	@echo "Generating SGX signing key..."
	gramine-sgx-gen-private-key $@

# =============================================================================
# Run Targets
# =============================================================================

# Run inside SGX enclave
run-sgx: all
	@echo ""
	@echo "Starting SGX Gateway (SGX mode)..."
	@echo "Port: $(GATEWAY_PORT)"
	@echo "=================================="
	gramine-sgx ./gateway /app/sgx-gateway/gateway_server.py \
		--port $(GATEWAY_PORT) \
		--cert $(SERVER_CERT) \
		--key $(SERVER_KEY) \
		--ca-cert $(CA_CERT) \
		--registry /app/config/asp_registry.json \
		--ssh-key /app/certs/enclave_ssh_key \
		--signing-key /app/certs/enclave_signing_key.pem \
		--log-dir /app/logs

# Run in direct mode (no SGX)
run-direct: gateway.manifest
	@echo ""
	@echo "Starting SGX Gateway (direct mode)..."
	@echo "=================================="
	gramine-direct ./gateway /app/sgx-gateway/gateway_server.py \
		--port $(GATEWAY_PORT) \
		--cert $(SERVER_CERT) \
		--key $(SERVER_KEY) \
		--ca-cert $(CA_CERT) \
		--registry /app/config/asp_registry.json \
		--ssh-key /app/certs/enclave_ssh_key \
		--log-dir /app/logs

# Run in pure Python (for testing)
run-python:
	@echo ""
	@echo "Starting SGX Gateway (Python mode)..."
	@echo "======================================"
	PYTHONPATH=$(APP_DIR) python3 gateway_server.py \
		--port $(GATEWAY_PORT) \
		--cert ../certs/server.crt \
		--key ../certs/server.key \
		--ca-cert ../certs/ca.crt \
		--registry ../config/asp_registry.json \
		--ssh-key ../certs/enclave_ssh_key \
		--log-dir ../logs

# =============================================================================
# Key Generation
# =============================================================================

gen-keys:
	@echo "Generating enclave keys..."
	@mkdir -p ../certs
	# SSH key for TDX access
	@if [ ! -f ../certs/enclave_ssh_key ]; then \
		ssh-keygen -t ed25519 -f ../certs/enclave_ssh_key -N "" -C "sgx-gateway-enclave"; \
		echo "  ✓ SSH key generated: enclave_ssh_key"; \
		echo "  Add enclave_ssh_key.pub to TDX VM's authorized_keys"; \
	else \
		echo "  SSH key already exists"; \
	fi
	# Signing key for audit logs
	@if [ ! -f ../certs/enclave_signing_key.pem ]; then \
		openssl genrsa -out ../certs/enclave_signing_key.pem 2048; \
		openssl rsa -in ../certs/enclave_signing_key.pem -pubout -out ../certs/enclave_signing_key_pub.pem; \
		echo "  ✓ Signing key generated: enclave_signing_key.pem"; \
	else \
		echo "  Signing key already exists"; \
	fi

gen-certs:
	@echo "Generating TLS certificates..."
	cd ../certs && ./generate_certs.sh

# =============================================================================
# Setup Verification
# =============================================================================

check-setup:
	@echo "Checking SGX Gateway setup..."
	@echo "=============================="
	@echo ""
	@echo "[1] Gramine:"
	@gramine-sgx --version 2>/dev/null || echo "   ✗ Gramine not found"
	@echo ""
	@echo "[2] SGX device:"
	@ls -la /dev/sgx_enclave 2>/dev/null && echo "   ✓ Available" || echo "   ✗ Not found"
	@echo ""
	@echo "[3] Python: $(PYTHON_VERSION)"
	@echo "[4] App directory: $(APP_DIR)"
	@echo ""
	@echo "[5] Required files:"
	@test -f ../config/asp_registry.json && echo "   ✓ ASP registry" || echo "   ✗ ASP registry missing"
	@test -f ../certs/server.crt && echo "   ✓ Server certificate" || echo "   ✗ Server certificate missing"
	@test -f ../certs/enclave_ssh_key && echo "   ✓ SSH key" || echo "   ✗ SSH key missing (run: make gen-keys)"
	@echo ""

# =============================================================================
# Cleanup
# =============================================================================

clean:
	rm -f gateway.manifest gateway.manifest.sgx gateway.sig
	rm -rf __pycache__/

distclean: clean
	rm -rf ../logs/*.jsonl
