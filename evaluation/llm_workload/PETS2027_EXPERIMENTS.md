# PETS 2027 Protocol 1.2 LLM Experiments

The scripts in this directory keep the legacy pre-vTPM evaluation intact.
New results are written below:

```text
evaluation/results/llm/pets2027-vtpm/<campaign-id>/
```

The smoke runner assumes that the Protocol 1.2 TDX server and vLLM are
already running on the CVM. It performs an unmeasured full-log baseline,
then starts the LLM load and periodic incremental attestations at one shared
timestamp.

## CVM setup

Use a newly booted CVM for a clean campaign. Start the Protocol 1.2 server
only once after boot because RTMR3 is append-only.

```bash
cd ~/sgx-tdx-composition-protocol
git switch feature/vtpm-rtmr3
git pull --ff-only origin feature/vtpm-rtmr3

cd research/sgx-tdx-attestation/tdx-server
sudo -E python3 tdx_attestation_server.py --test --method dcap
sudo -E python3 tdx_attestation_server.py --port 8443 --method dcap
```

The server banner must report protocol `1.2`, runtime evidence
`ima-rtmr3-vtpm-v2`, and `persistent-fd`.

In a second CVM terminal, start the model:

```bash
cd ~/sgx-tdx-composition-protocol/evaluation/llm_workload
./vllm_server_launch.sh \
  --model-key phi3-mini \
  --port 8000 \
  --via-docker \
  --docker-image vllm-cpu:local \
  --log /tmp/vllm-phi3.log
```

Verify both listeners:

```bash
sudo ss -ltnp | grep -E ':8443|:8000'
curl -s http://127.0.0.1:8000/v1/models | python3 -m json.tool
```

## WEN build

The new driver must be included in a newly generated and signed Gramine
manifest:

```bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
make clean
make all
```

## SGX smoke run

Use one campaign ID for related smoke runs:

```bash
cd ~/sgx-tdx-composition-protocol
export CVM_IP=146.148.46.72
export CAMPAIGN_ID="smoke-vtpm-$(date -u +%Y%m%dT%H%M%SZ)"

./evaluation/llm_workload/run_vtpm_smoke.sh \
  --mode sgx \
  --tdx-host "$CVM_IP" \
  --model-key phi3-mini \
  --rps 0.15 \
  --epoch-sec 15 \
  --duration-sec 90 \
  --campaign-id "$CAMPAIGN_ID" \
  --ssh-user nkoirala \
  --ssh-key "$HOME/.ssh/vordr_id_rsa" \
  --no-verify
```

`--no-verify` is appropriate only for the development smoke test. The paper
campaign should use a CA certificate whose identity matches the CVM endpoint,
plus the configured client certificate/key when mTLS is required.

## Python comparison smoke

Keep the same model, CVM, epoch, rate, and campaign:

```bash
./evaluation/llm_workload/run_vtpm_smoke.sh \
  --mode python \
  --tdx-host "$CVM_IP" \
  --model-key phi3-mini \
  --rps 0.15 \
  --epoch-sec 15 \
  --duration-sec 90 \
  --campaign-id "$CAMPAIGN_ID" \
  --ssh-user nkoirala \
  --ssh-key "$HOME/.ssh/vordr_id_rsa" \
  --no-verify
```

The Python run should report `checkpoint_sealed=False`; that is expected.
The SGX run must report sealed checkpoints.

## Llama smoke

Stop the Phi-3 container and start the Llama 3.1 model:

```bash
docker rm -f vllm-phi3-mini-8000
cd ~/sgx-tdx-composition-protocol/evaluation/llm_workload
./vllm_server_launch.sh \
  --model-key llama31-8b \
  --port 8000 \
  --via-docker \
  --docker-image vllm-cpu:local \
  --log /tmp/vllm-llama31.log
```

Then run an SGX smoke at the calibrated lower request rate:

```bash
cd ~/sgx-tdx-composition-protocol
./evaluation/llm_workload/run_vtpm_smoke.sh \
  --mode sgx \
  --tdx-host "$CVM_IP" \
  --model-key llama31-8b \
  --rps 0.03 \
  --epoch-sec 15 \
  --duration-sec 120 \
  --campaign-id "$CAMPAIGN_ID" \
  --ssh-user nkoirala \
  --ssh-key "$HOME/.ssh/vordr_id_rsa" \
  --no-verify
```

Do not start the full matrix until all smoke validators print
`Validation: OK` and the SGX CSV shows one `full` baseline followed by
`incremental-delta` measurement rounds with a stable `fd_generation`.
