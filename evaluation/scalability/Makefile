# Gramine SGX packaging for the enclave-resident Vordr WEN server.

PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH := $(shell which python3)
ARCH_LIBDIR := /lib/$(shell gcc -dumpmachine)
REPO_ROOT := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../..)

SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem
LOG_LEVEL ?= error
APP_NAME := vordr_wen
ENTRYPOINT := /app/evaluation/scalability/vordr_server.py
ARGS ?=

.PHONY: all clean run-sgx run-direct help

all: $(APP_NAME).manifest.sgx $(APP_NAME).sig

help:
	@echo "Vordr scalability WEN inside Gramine/SGX"
	@echo "======================================="
	@echo "Targets:"
	@echo "  all        - build and sign the WEN manifest"
	@echo "  run-direct - run the WEN under gramine-direct"
	@echo "  run-sgx    - run the WEN under gramine-sgx"
	@echo "  clean      - remove generated manifest artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make run-sgx ARGS=\"--listen-host 127.0.0.1 --port 9443 --refresh-backend sgx-verifier --tdx-host <TDX_IP> --tdx-port 8443 --tdx-method dcap --refresh-interval-s 30\""

$(APP_NAME).manifest: $(APP_NAME).manifest.template vordr_server.py scale_common.py Makefile \
	../../research/sgx-tdx-attestation/common/protocol.py \
	../../research/sgx-tdx-attestation/sgx-verifier/sgx_tdx_verifier.py
	@echo "[1/2] Generating Gramine manifest for $(APP_NAME)..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Drepo_root=$(REPO_ROOT) \
		$< $@

$(APP_NAME).manifest.sgx $(APP_NAME).sig: $(APP_NAME).manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing $(APP_NAME) for SGX..."
	gramine-sgx-sign \
		--manifest $< \
		--key $(SGX_SIGNING_KEY) \
		--output $<.sgx

$(SGX_SIGNING_KEY):
	@echo "Generating SGX signing key..."
	gramine-sgx-gen-private-key $@

run-direct: $(APP_NAME).manifest
	gramine-direct ./$(APP_NAME) $(ENTRYPOINT) $(ARGS)

run-sgx: all
	gramine-sgx ./$(APP_NAME) $(ENTRYPOINT) $(ARGS)

clean:
	rm -f $(APP_NAME).manifest $(APP_NAME).manifest.sgx $(APP_NAME).sig
