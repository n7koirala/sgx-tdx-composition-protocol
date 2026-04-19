# DCAP Verification Overhead Microbenchmark — Makefile
#
# Targets:
#   all              Build + sign the Gramine enclave manifest.
#   prepare          Fetch quote + collateral (run once).
#   run-python       Run benchmark in native Python (1000 iters).
#   run-sgx          Run benchmark inside SGX enclave (1000 iters).
#   plot             Generate comparison figures after both CSVs exist.
#   clean            Remove generated manifest + signed enclave.
#
# Configurable:
#   TDX_HOST         CVM host (required for `make prepare` unless --quote-file)
#   TDX_PORT         CVM port (default 8443)
#   ITERS            Iterations per verifier (default 1000)
#   WARMUP           Warmup iterations (default 50)
#   LOG_LEVEL        Gramine log level (default error)

PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_PATH    := $(shell which python3)
ARCH_LIBDIR    := /lib/$(shell gcc -dumpmachine)

BENCH_DIR      := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
RESEARCH_DIR   := $(realpath $(BENCH_DIR)/..)

SGX_SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem
LOG_LEVEL       ?= error

TDX_HOST  ?=
TDX_PORT  ?= 8443
ITERS     ?= 1000
WARMUP    ?= 50
CA_CERT   ?=

.PHONY: all prepare run-python run-sgx plot clean help

help:
	@echo "DCAP Verification Overhead Benchmark"
	@echo "====================================="
	@echo "  make prepare TDX_HOST=<ip>  (once)  — fetch quote + collateral"
	@echo "  make run-python                      — native Python, $(ITERS) iters"
	@echo "  make all                             — build Gramine enclave"
	@echo "  make run-sgx                         — run inside enclave, $(ITERS) iters"
	@echo "  make plot                            — generate comparison figures"
	@echo ""
	@echo "Overrides: TDX_HOST, TDX_PORT, ITERS, WARMUP, CA_CERT, LOG_LEVEL"

# ── Step 1: fetch inputs ───────────────────────────────────────────────────
prepare:
	@test -n "$(TDX_HOST)" || (echo "TDX_HOST is required (or run prepare_inputs.py --quote-file)"; exit 1)
	python3 prepare_inputs.py \
		--tdx-host $(TDX_HOST) --tdx-port $(TDX_PORT) \
		$(if $(CA_CERT),--ca-cert $(CA_CERT),--no-verify)

# ── Step 2a: run in native Python ──────────────────────────────────────────
run-python:
	PYTHONPATH=$(RESEARCH_DIR)/sgx-tdx-attestation:$(RESEARCH_DIR)/tdx-dcap-attestation \
		python3 benchmark.py --iters $(ITERS) --warmup $(WARMUP) --mode python

# ── Step 2b: build + run Gramine-SGX ───────────────────────────────────────
all: verifier.manifest.sgx verifier.sig

verifier.manifest: verifier.manifest.template benchmark.py
	@echo "[1/2] Generating Gramine manifest ..."
	gramine-manifest \
		-Dlog_level=$(LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dpython_path=$(PYTHON_PATH) \
		-Dpython_version=$(PYTHON_VERSION) \
		-Dbench_dir=$(BENCH_DIR) \
		-Dresearch_dir=$(RESEARCH_DIR) \
		$< $@

verifier.manifest.sgx verifier.sig: verifier.manifest $(SGX_SIGNING_KEY)
	@echo "[2/2] Signing manifest for SGX (hashes all trusted files; may take a while) ..."
	gramine-sgx-sign --manifest $< --key $(SGX_SIGNING_KEY) --output $<.sgx
	@echo "      ✓ Enclave signed"
	@gramine-sgx-sigstruct-view verifier.sig

$(SGX_SIGNING_KEY):
	gramine-sgx-gen-private-key $@

# Make sure results CSV/JSON exist as empty files so allowed_files can
# open them for writing. Gramine refuses to create new files under
# allowed_files paths — they must pre-exist.
results_sgx.csv results_sgx_summary.json:
	@touch $@

run-sgx: all results_sgx.csv results_sgx_summary.json
	@echo "Running benchmark inside SGX enclave ..."
	gramine-sgx ./verifier /bench/benchmark.py \
		--iters $(ITERS) --warmup $(WARMUP) --mode sgx \
		--output /bench/results_sgx.csv

# ── Step 3: plot comparison ────────────────────────────────────────────────
plot:
	python3 plot_results.py

clean:
	rm -f verifier.manifest verifier.manifest.sgx verifier.sig
	rm -rf __pycache__/
