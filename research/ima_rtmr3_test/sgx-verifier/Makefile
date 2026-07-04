# Gramine-SGX wrapper for the isolated IMA -> RTMR[3] WEN verifier.

PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH    := $(shell which python3)
ARCH_LIBDIR    := /lib/$(shell gcc -dumpmachine)

TEST_DIR    := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)
SGX_TDX_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../../sgx-tdx-attestation)

SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem
LOG_LEVEL       ?= error

TDX_HOST ?= localhost
TDX_PORT ?= 9443
RTMR3_BASE ?= auto
RUN_ARGS ?=

.PHONY: all clean run

all: verifier.manifest.sgx verifier.sig

verifier.manifest: verifier.manifest.template \
                   $(TEST_DIR)/wen_rtmr3_verifier.py \
                   $(TEST_DIR)/ima_rtmr3_common.py \
                   $(SGX_TDX_DIR)/common/protocol.py
	@echo "[1/2] Generating IMA-RTMR3 verifier manifest..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dtest_dir=$(TEST_DIR) \
		-Dsgx_tdx_dir=$(SGX_TDX_DIR) \
		$< $@
	@echo "      Manifest generated"

verifier.manifest.sgx verifier.sig: verifier.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing IMA-RTMR3 verifier manifest..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx
	@echo "      Enclave signed"
	@gramine-sgx-sigstruct-view verifier.sig

$(SGX_SIGNING_KEY):
	gramine-sgx-gen-private-key $@

run: all
	gramine-sgx ./verifier /app/wen_rtmr3_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--expected-rtmr3-base $(RTMR3_BASE) \
		$(RUN_ARGS)

clean:
	rm -f verifier.manifest verifier.manifest.sgx verifier.sig
	rm -rf __pycache__/
