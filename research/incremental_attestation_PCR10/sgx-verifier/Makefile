# Gramine-SGX enclave build for the PCR-10 replay variant of the
# incremental-attestation subscriber.

PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH    := $(shell which python3)
ARCH_LIBDIR    := /lib/$(shell gcc -dumpmachine)

# /app directory is the main sgx-tdx-attestation folder (for common/protocol.py)
APP_DIR   := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../../sgx-tdx-attestation)
# /benchmark directory is the PCR-10 variant bench folder.
BENCH_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)

SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem
LOG_LEVEL       ?= error

.PHONY: all clean
all: verifier.manifest.sgx verifier.sig

verifier.manifest: verifier.manifest.template \
                    $(BENCH_DIR)/benchmark_incremental.py \
                    $(BENCH_DIR)/ima_pcr_verify.py \
                    $(APP_DIR)/common/protocol.py
	@echo "[1/2] Generating PCR-10 verifier manifest..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dapp_dir=$(APP_DIR) \
		-Dbench_dir=$(BENCH_DIR) \
		$< $@
	@echo "      ✓ Manifest generated"

verifier.manifest.sgx verifier.sig: verifier.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing manifest for SGX (hashes all trusted files)..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo "      ✓ Enclave signed"
	@gramine-sgx-sigstruct-view verifier.sig

$(SGX_SIGNING_KEY):
	gramine-sgx-gen-private-key $@

clean:
	rm -f verifier.manifest verifier.manifest.sgx verifier.sig
	rm -rf __pycache__/
