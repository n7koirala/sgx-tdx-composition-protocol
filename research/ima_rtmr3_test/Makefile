# Isolated IMA -> RTMR[3] test harness.

TDX_HOST ?= localhost
TDX_PORT ?= 8443
METHOD ?= dcap
COUNT ?= 10
RTMR3_BASE ?= auto
GOLDEN ?= golden_boot.json

CERT ?= ../sgx-tdx-attestation/certs/server.crt
KEY  ?= ../sgx-tdx-attestation/certs/server.key

.PHONY: help check-cvm agent verify verify-golden save-golden events sgx-build verify-sgx clean

help:
	@echo "IMA -> RTMR[3] isolated test"
	@echo ""
	@echo "CVM-side:"
	@echo "  make check-cvm"
	@echo "  make agent TDX_PORT=8443"
	@echo "  make events COUNT=10"
	@echo ""
	@echo "WEN-side:"
	@echo "  make verify TDX_HOST=<cvm-ip> TDX_PORT=8443"
	@echo "  make save-golden TDX_HOST=<cvm-ip> GOLDEN=golden_boot.json"
	@echo "  make verify-golden TDX_HOST=<cvm-ip> GOLDEN=golden_boot.json"
	@echo "  make sgx-build"
	@echo "  make verify-sgx TDX_HOST=<cvm-ip> GOLDEN=/app/golden_boot.json"

check-cvm:
	sudo python3 cvm_rtmr3_agent.py --test

agent:
	sudo python3 cvm_rtmr3_agent.py \
		--port $(TDX_PORT) \
		--method $(METHOD) \
		--cert $(CERT) \
		--key $(KEY)

verify:
	python3 wen_rtmr3_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--expected-rtmr3-base $(RTMR3_BASE)

save-golden:
	python3 wen_rtmr3_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--expected-rtmr3-base $(RTMR3_BASE) \
		--save-golden $(GOLDEN)

verify-golden:
	python3 wen_rtmr3_verifier.py \
		--tdx-host $(TDX_HOST) \
		--tdx-port $(TDX_PORT) \
		--no-verify \
		--expected-rtmr3-base $(RTMR3_BASE) \
		--golden-file $(GOLDEN) \
		--require-golden

events:
	sudo python3 generate_ima_events.py --count $(COUNT) --label rtmr3

sgx-build:
	$(MAKE) -C sgx-verifier all

verify-sgx:
	$(MAKE) -C sgx-verifier run \
		TDX_HOST=$(TDX_HOST) \
		TDX_PORT=$(TDX_PORT) \
		RTMR3_BASE=$(RTMR3_BASE) \
		GOLDEN=$(GOLDEN)

clean:
	$(MAKE) -C sgx-verifier clean
	rm -f __pycache__/*.pyc
