# Gramine SGX Controller Makefile (Commissioning Phase)
#
# Builds and runs the SGX Controller Flask server inside an SGX enclave.
# The controller provisions and manages TDX Confidential VMs on GCP.

# ============================================================================
# Configuration
# ============================================================================

# Detect Python version and paths
PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)
HOME_DIR := $(HOME)

# Application directory (parent of commissioning_phase)
APP_DIR := $(realpath ..)

# Gramine signing key
SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Log level: error, warning, debug, trace, all (no "info" in Gramine)
LOG_LEVEL ?= error

# SGX debug mode (true for development, false for production)
SGX_DEBUG ?= true

# Controller configuration
PORT ?= 6037

# Controller IP (optional - for firewall source restriction)
# If not set, will try GCP metadata, then HTTP IP detection
# Example: make run-sgx CONTROLLER_IP=1.2.3.4
CONTROLLER_IP ?=

# Attestation method: dcap (local DCAP) or none
# Note: Both DCAP and ITA are supported - we use DCAP to generate quotes
# ITA verification is done by ASP client, not in the manifest
ATTESTATION_METHOD ?= dcap

# GCP Application Default Credentials path (auto-detected)
GCP_ADC_PATH := $(HOME)/.config/gcloud/application_default_credentials.json

# GCP Service Account Key (from gcp_config.env, can be empty)
GCP_SERVICE_ACCOUNT_KEY := $(shell grep -E '^GCP_SERVICE_ACCOUNT_KEY=' gcp_config.env 2>/dev/null | cut -d'=' -f2 || echo "")

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean run-sgx run-direct check-setup help distclean gen-signing-key

# Default target
all: controller.manifest.sgx controller.sig

help:
	@echo "SGX Controller - CVM Commissioning Phase"
	@echo "========================================="
	@echo ""
	@echo "Build Targets:"
	@echo "  all                 - Build Gramine manifest and sign it for SGX"
	@echo "  clean               - Remove generated manifest files"
	@echo "  distclean           - Remove all generated files (does not delete signing key)"
	@echo ""
	@echo "Run Targets:"
	@echo "  run-sgx             - Run controller inside SGX enclave (PRODUCTION)"
	@echo "  run-direct          - Run controller in direct mode (no SGX, for testing)"
	@echo ""
	@echo "Setup Targets:"
	@echo "  check-setup         - Verify SGX, Gramine, and dependencies are ready"
	@echo "  gen-signing-key     - Generate SGX signing key if it doesn't exist"
	@echo ""
	@echo "Configuration:"
	@echo "  PORT                = $(PORT)"
	@echo "  LOG_LEVEL           = $(LOG_LEVEL)"
	@echo "  SGX_DEBUG           = $(SGX_DEBUG)"
	@echo "  ATTESTATION_METHOD  = $(ATTESTATION_METHOD)"
	@echo "  PYTHON_VERSION      = $(PYTHON_VERSION)"
	@echo "  GCP_ADC_PATH        = $(GCP_ADC_PATH)"
	@echo "  CONTROLLER_IP       = $(CONTROLLER_IP) (optional)"
	@echo ""
	@echo "Examples:"
	@echo "  make all                                - Build the SGX enclave"
	@echo "  make run-sgx                            - Run in SGX mode (auto-detect IP)"
	@echo "  make run-sgx PORT=8080                  - Run on custom port"
	@echo "  make run-sgx CONTROLLER_IP=1.2.3.4      - Run with explicit controller IP"
	@echo "  make run-direct                         - Test without SGX hardware"
	@echo ""

# ============================================================================
# Build Steps
# ============================================================================

# Step 1: Generate the manifest from template
controller.manifest: controller.manifest.template sgx_controller.py gcp_client.py cvm.py ima_verifier.py
	@echo "================================================================================"
	@echo "[1/2] Generating Gramine manifest..."
	@echo "      This may take several minutes as Gramine hashes all trusted files..."
	@echo "================================================================================"
	@echo ""
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dapp_dir=$(APP_DIR) \
		-Dhome_dir=$(HOME_DIR) \
		-Dsgx_debug=$(SGX_DEBUG) \
		-Dattestation_method=$(ATTESTATION_METHOD) \
		-Dgcp_adc_path=$(GCP_ADC_PATH) \
		-Dgcp_service_account_key=$(GCP_SERVICE_ACCOUNT_KEY) \
		$< $@
	@echo ""
	@echo "✓ Manifest generated successfully (size: $$(du -h $@ | cut -f1))"
	@echo ""

# Step 2: Sign the manifest for SGX
controller.manifest.sgx controller.sig: controller.manifest $(SGX_SIGNING_KEY)
	@echo "================================================================================"
	@echo "[2/2] Signing manifest for SGX..."
	@echo "================================================================================"
	@echo ""
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo ""
	@echo "✓ Manifest signed successfully!"
	@echo ""
	@echo "================================================================================"
	@echo "SGX Enclave Measurements:"
	@echo "================================================================================"
	@gramine-sgx-sigstruct-view controller.sig | grep -E "(mr_enclave|mr_signer|isv_prod_id|isv_svn)" || gramine-sgx-sigstruct-view controller.sig
	@echo ""
	@echo "✓ SGX Controller enclave is ready!"
	@echo ""

# Generate signing key if it doesn't exist
$(SGX_SIGNING_KEY):
	@echo "SGX signing key not found. Generating new key..."
	@mkdir -p $(dir $(SGX_SIGNING_KEY))
	gramine-sgx-gen-private-key $@
	@echo "✓ Signing key generated: $@"

gen-signing-key: $(SGX_SIGNING_KEY)

# ============================================================================
# Run Targets
# ============================================================================

# Run inside SGX enclave (PRODUCTION MODE)
run-sgx: all
	@echo ""
	@echo "================================================================================"
	@echo "Starting SGX Controller inside SGX enclave..."
	@echo "================================================================================"
	@echo ""
	@echo "Configuration:"
	@echo "  Port:                $(PORT)"
	@echo "  Log level:           $(LOG_LEVEL)"
	@echo "  SGX debug mode:      $(SGX_DEBUG)"
	@echo "  Attestation method:  $(ATTESTATION_METHOD)"
	@echo "  Application dir:     $(APP_DIR)"
	@echo ""
	@echo "Network access:"
	@echo "  ✓ Incoming: HTTP/HTTPS on port $(PORT) (ASP clients)"
	@echo "  ✓ Outgoing: HTTPS to *.googleapis.com (GCP API)"
	@echo "  ✓ Outgoing: SSH (port 22) to TDX CVMs"
	@echo "  ✓ Outgoing: HTTPS to api.ipify.org (get external IP)"
	@echo ""
	@echo "================================================================================"
	@echo "Starting Flask server... Press Ctrl+C to stop"
	@echo "================================================================================"
	@echo ""
	@if [ -n "$(CONTROLLER_IP)" ]; then \
		echo "Using explicit controller IP: $(CONTROLLER_IP)"; \
		CONTROLLER_IP=$(CONTROLLER_IP) gramine-sgx ./controller -m commissioning_phase.sgx_controller -t sgx -p $(PORT); \
	else \
		echo "Auto-detecting controller IP..."; \
		gramine-sgx ./controller -m commissioning_phase.sgx_controller -t sgx -p $(PORT); \
	fi

# Run without SGX (DEVELOPMENT MODE - for testing without SGX hardware)
run-direct: controller.manifest
	@echo ""
	@echo "================================================================================"
	@echo "Starting SGX Controller in DIRECT mode (no SGX)..."
	@echo "================================================================================"
	@echo ""
	@echo "⚠️  WARNING: Running in direct mode - NO SGX PROTECTION!"
	@echo "   - Private keys are NOT protected by SGX"
	@echo "   - No hardware attestation available"
	@echo "   - Use only for development/testing"
	@echo ""
	@echo "Configuration:"
	@echo "  Port:           $(PORT)"
	@echo "  Log level:      $(LOG_LEVEL)"
	@echo ""
	@echo "================================================================================"
	@echo "Starting Flask server... Press Ctrl+C to stop"
	@echo "================================================================================"
	@echo ""
	gramine-direct ./controller -m commissioning_phase.sgx_controller -t sgx -p $(PORT)

# ============================================================================
# Setup Verification
# ============================================================================

check-setup:
	@echo "================================================================================"
	@echo "Checking SGX Controller Setup..."
	@echo "================================================================================"
	@echo ""
	@echo "[1] Gramine Installation:"
	@gramine-sgx --version 2>/dev/null && echo "   ✓ Gramine installed" || echo "   ✗ Gramine not found - install from https://gramine.readthedocs.io"
	@echo ""
	@echo "[2] SGX Hardware:"
	@if [ -e /dev/sgx_enclave ]; then \
		echo "   ✓ SGX device available: /dev/sgx_enclave"; \
	else \
		echo "   ✗ SGX device not found - check if SGX is enabled in BIOS"; \
	fi
	@echo ""
	@echo "[3] AESM Service (for attestation):"
	@systemctl is-active aesmd 2>/dev/null && echo "   ✓ AESM service running" || echo "   ✗ AESM service not running - needed for attestation"
	@echo ""
	@echo "[4] SGX Signing Key:"
	@if [ -f $(SGX_SIGNING_KEY) ]; then \
		echo "   ✓ Signing key exists: $(SGX_SIGNING_KEY)"; \
	else \
		echo "   ✗ Signing key not found - run 'make gen-signing-key'"; \
	fi
	@echo ""
	@echo "[5] Python Configuration:"
	@echo "   Python version:  $(PYTHON_VERSION)"
	@echo "   Python path:     $(PYTHON_PATH)"
	@echo "   Arch libdir:     $(ARCH_LIBDIR)"
	@echo ""
	@echo "[6] Application Directory:"
	@echo "   App dir:         $(APP_DIR)"
	@test -f $(APP_DIR)/commissioning_phase/sgx_controller.py && echo "   ✓ Controller found" || echo "   ✗ Controller not found"
	@test -f $(APP_DIR)/commissioning_phase/gcp_client.py && echo "   ✓ GCP client found" || echo "   ✗ GCP client not found"
	@test -f $(APP_DIR)/commissioning_phase/ima_verifier.py && echo "   ✓ IMA verifier found" || echo "   ✗ IMA verifier not found"
	@echo ""
	@echo "[7] GCP Configuration:"
	@test -f gcp_config.env && echo "   ✓ GCP config exists" || echo "   ✗ GCP config not found - copy gcp_config.env.template"
	@if [ -f "$(GCP_ADC_PATH)" ]; then \
		echo "   ✓ ADC credentials found: $(GCP_ADC_PATH)"; \
	else \
		echo "   ⚠  ADC credentials not found - run 'gcloud auth application-default login'"; \
	fi
	@if [ -n "$(GCP_SERVICE_ACCOUNT_KEY)" ] && [ -f "$(GCP_SERVICE_ACCOUNT_KEY)" ]; then \
		echo "   ✓ Service account key found: $(GCP_SERVICE_ACCOUNT_KEY)"; \
	else \
		echo "   ⚠  Service account key not configured (ADC will be used)"; \
	fi
	@echo ""
	@echo "[8] Python Dependencies:"
	@python3 -c "import flask" 2>/dev/null && echo "   ✓ flask installed" || echo "   ✗ flask not found - run 'pip install -r requirements.txt'"
	@python3 -c "import paramiko" 2>/dev/null && echo "   ✓ paramiko installed" || echo "   ✗ paramiko not found"
	@python3 -c "import cryptography" 2>/dev/null && echo "   ✓ cryptography installed" || echo "   ✗ cryptography not found"
	@python3 -c "import google.cloud.compute" 2>/dev/null && echo "   ✓ google-cloud-compute installed" || echo "   ✗ google-cloud-compute not found"
	@echo ""
	@echo "[9] ASP Configuration:"
	@test -f asp_pub_keys/asp_private_key.pub && echo "   ✓ ASP public key found" || echo "   ✗ ASP public key not found - run 'python3 generate_asp_keys.py'"
	@echo ""
	@echo "[10] IMA Reference Manifest:"
	@test -f reference_manifest.json && echo "   ✓ IMA manifest exists" || echo "   ⚠  IMA manifest not found - run 'python3 generate_reference_manifest.py'"
	@echo ""
	@echo "================================================================================"
	@echo "Setup check complete!"
	@echo "================================================================================"
	@echo ""

# ============================================================================
# Cleanup
# ============================================================================

clean:
	@echo "Cleaning generated manifest files..."
	rm -f controller.manifest controller.manifest.sgx controller.sig
	rm -rf __pycache__/
	@echo "✓ Clean complete"

distclean: clean
	@echo "Performing deep clean..."
	@echo "Note: Signing key preserved for safety ($(SGX_SIGNING_KEY))"
	@echo "      To remove it manually: rm $(SGX_SIGNING_KEY)"

# ============================================================================
# Debugging and Information
# ============================================================================

view-sig: controller.sig
	@echo "================================================================================"
	@echo "SGX Enclave Signature Structure:"
	@echo "================================================================================"
	@gramine-sgx-sigstruct-view controller.sig

info:
	@echo "================================================================================"
	@echo "SGX Controller Build Information"
	@echo "================================================================================"
	@echo ""
	@echo "Build Configuration:"
	@echo "  PYTHON_VERSION       = $(PYTHON_VERSION)"
	@echo "  PYTHON_PATH          = $(PYTHON_PATH)"
	@echo "  ARCH_LIBDIR          = $(ARCH_LIBDIR)"
	@echo "  APP_DIR              = $(APP_DIR)"
	@echo "  HOME_DIR             = $(HOME_DIR)"
	@echo "  SGX_SIGNING_KEY      = $(SGX_SIGNING_KEY)"
	@echo ""
	@echo "Runtime Configuration:"
	@echo "  PORT                 = $(PORT)"
	@echo "  LOG_LEVEL            = $(LOG_LEVEL)"
	@echo "  SGX_DEBUG            = $(SGX_DEBUG)"
	@echo "  ATTESTATION_METHOD   = $(ATTESTATION_METHOD)"
	@echo ""
	@echo "GCP Configuration:"
	@echo "  GCP_ADC_PATH         = $(GCP_ADC_PATH)"
	@echo "  GCP_SERVICE_ACCOUNT_KEY = $(GCP_SERVICE_ACCOUNT_KEY)"
	@echo ""
