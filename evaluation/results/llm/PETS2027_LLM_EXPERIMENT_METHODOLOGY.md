# VOrdr LLM Experiment Methodology and Data-Collection Plan

## 1. Purpose of This Document

This document describes the end-to-end large language model (LLM) experiment
used to evaluate VOrdr with the current Protocol 1.2 implementation. It
explains:

- why the experiment is being performed;
- what systems and software are involved;
- what the workload represents;
- how VOrdr attestation runs while an LLM serves requests;
- what data is collected;
- how each measurement supports a paper claim;
- which settings are only for smoke testing; and
- what must be tightened before collecting the final PETS 2027 dataset.

The goal is to make the experiment understandable without requiring prior
knowledge of vLLM, ShareGPT, Intel TDX, Intel SGX, IMA, TPM PCRs, or TDX
runtime measurement registers.

## 2. Research Motivation

A confidential virtual machine can protect an LLM workload from the cloud
host by encrypting the VM's memory and using hardware attestation to describe
the VM's initial state. Initial attestation alone is not enough for a
long-running service. After the VM starts, its software can load additional
executables, libraries, scripts, and configuration files. A verifier therefore
needs a way to monitor runtime changes without repeatedly transferring and
replaying the complete measurement history.

VOrdr combines:

1. Intel TDX hardware attestation for the confidential VM;
2. Linux Integrity Measurement Architecture (IMA) measurements for runtime
   software activity;
3. a vTPM quote over PCR 10 to authenticate the kernel-maintained IMA replay
   value;
4. TDX RTMR3 anchoring of the vTPM attestation key and IMA entries;
5. incremental IMA transfer and replay; and
6. a rolling checkpoint maintained and sealed inside the WEN's SGX enclave.

The LLM experiment asks whether this continuous runtime-integrity mechanism
can operate alongside a latency-sensitive application without imposing
unacceptable application overhead.

The experiment is not intended to measure model accuracy, factuality, or
response quality. It measures serving performance and attestation behavior.

## 3. Questions the Experiment Is Designed to Answer

The final experiment should answer the following questions.

### 3.1 Cost of confidential execution

How much throughput and latency change when the same LLM moves from a normal
VM to an Intel TDX confidential VM?

This is measured by comparing the `native` and `tdx-only` conditions.

### 3.2 Additional cost of VOrdr

How much additional overhead is introduced when Protocol 1.2 attestation runs
periodically while the TDX VM serves inference requests?

This is measured by comparing matched `tdx-only` and `tdx-vordr` runs.

### 3.3 Effect of attestation frequency

How does the attestation epoch `T` affect application throughput, tail
latency, and evidence freshness?

Shorter epochs provide fresher integrity evidence but execute attestation more
frequently. Longer epochs reduce attestation frequency but increase the time
between integrity observations.

### 3.4 Benefit of incremental extraction

Does keeping the IMA pseudo-file descriptors open reduce CVM-side extraction
cost when the IMA log is large?

The important distinction is:

- prior incremental designs reduce communication and verifier replay from
  `O(N)` to `O(delta_n)`; and
- VOrdr additionally keeps the CVM's IMA descriptors positioned across
  rounds, reducing attester-side extraction work.

Here, `N` is the total number of IMA entries and `delta_n` is the number of
entries added since the previous successful round.

### 3.5 Cost of SGX-protected verification

Does running the WEN verifier and checkpoint logic inside Gramine SGX add
substantial overhead compared with the same Python verification logic outside
an enclave?

This is evaluated using matched `python` and `sgx` verifier runs.

### 3.6 Protocol component costs

Which parts of a round dominate latency: IMA extraction, RTMR extension, vTPM
quote generation, TDX quote generation, evidence transfer, WEN verification,
or checkpoint sealing?

The Protocol 1.2 driver records these phases separately.

## 4. Terminology

### Confidential VM (CVM)

A VM whose memory and execution are protected from the cloud host by a
hardware confidential-computing technology. The target CVM in this experiment
uses Intel Trust Domain Extensions (TDX).

### Intel TDX

Intel TDX creates a hardware-isolated trust domain for a VM. A TDX quote
contains measurements of the trust domain and is signed through Intel's DCAP
attestation infrastructure.

### Intel SGX

Intel Software Guard Extensions (SGX) creates an enclave inside a process.
Code and data inside the enclave are isolated from the normal operating
system. In this experiment, the WEN verifier runs inside an SGX enclave.

### WEN

The WEN is the trusted, stateful verifier in the protocol. It repeatedly
attests the same CVM and retains a rolling runtime checkpoint. The experiment
compares WEN verification inside SGX with ordinary Python execution.

### Gramine

Gramine is a library operating system that allows an unmodified Linux
application, including the Python verifier, to run inside SGX. Gramine builds
a manifest that identifies trusted files, signs the enclave, and exposes SGX
facilities such as sealing keys to the application.

### IMA

Linux Integrity Measurement Architecture records measurements of files and
other objects used by the running system. Its runtime measurement list is
available through pseudo-files under:

```text
/sys/kernel/security/integrity/ima/
```

The protocol uses both the binary and ASCII runtime measurement interfaces.
The binary form contains the full template data needed for deterministic
replay. The ASCII form provides an independent representation used for
cross-checking counts and template hashes.

### PCR 10

A Platform Configuration Register (PCR) is a TPM register updated using a
one-way hash-extension operation. Linux IMA conventionally extends its
measurement chain into PCR 10. Replaying the IMA log should reproduce the
corresponding PCR 10 value.

### vTPM

A virtual TPM provides TPM operations to the CVM. Protocol 1.2 requests a
nonce-bound vTPM quote over SHA-256 PCR 10. This replaces the earlier design
that trusted a bare PCR value supplied by the agent.

### AK

The Attestation Key (AK) is the vTPM key that signs the PCR 10 quote. VOrdr
hashes the exact serialized AK public key using SHA-384 and extends that digest
into RTMR3 before replaying IMA entries. The verifier confirms that the AK
bound into RTMR3 is the same AK that signed the PCR 10 quote.

### RTMR

TDX Runtime Measurement Registers are SHA-384 extend-only registers included
in TDX attestation evidence. The current implementation uses RTMR3 for the
agent-mediated runtime chain.

### DCAP

Intel Data Center Attestation Primitives (DCAP) allow the verifier to validate
a TDX quote locally using Intel attestation collateral rather than sending
every quote to a remote attestation service.

### Attestation epoch

The epoch `T` is the planned interval between VOrdr attestation rounds. For
example, `T=30` requests one round every 30 seconds.

### TTFT, ITL, and end-to-end latency

- **Time to first token (TTFT):** time from request submission until the first
  generated token is received.
- **Inter-token latency (ITL):** delay between successive generated tokens.
- **End-to-end latency:** time from request submission until the complete
  response is received.

## 5. Experimental Roles and Machines

The complete experiment has three logical roles.

### 5.1 Target machine

The target machine runs the LLM server. Depending on the condition, it is
either a conventional VM or an Intel TDX CVM.

For `tdx-vordr`, the target also runs:

- the Protocol 1.2 TDX attestation server;
- the persistent IMA stream reader;
- the IMA-to-RTMR3 extension loop;
- vTPM PCR 10 quote generation; and
- TDX DCAP quote generation.

### 5.2 WEN

The WEN runs the Protocol 1.2 verifier. In the primary condition it runs
inside a Gramine SGX enclave. A Python condition executes the same verifier
outside SGX to isolate enclave overhead.

### 5.3 Load generator

The load generator sends inference requests to the vLLM server according to
an open-loop arrival process. It records application throughput and latency.
The current scripts run the load generator on the WEN host but outside the
SGX enclave.

## 6. Experimental Conditions

### 6.1 Native

```text
Conventional VM + vLLM
No TDX
No VOrdr attestation
```

This condition measures baseline model-serving performance.

### 6.2 TDX-only

```text
Intel TDX CVM + vLLM
No periodic VOrdr attestation
```

Comparing this condition with Native estimates the cost of confidential
execution.

### 6.3 TDX-VOrdr

```text
Intel TDX CVM + vLLM + Protocol 1.2 agent
Periodic verification by the WEN
```

Comparing TDX-VOrdr with TDX-only estimates the incremental cost of VOrdr.

### 6.4 Python and SGX verifier variants

The Protocol 1.2 verifier can run as:

- `python`: ordinary Python outside SGX; or
- `sgx`: the same Python code inside Gramine SGX.

Only the SGX condition provides enclave isolation and SGX-sealed checkpoints.
The Python condition is an experimental control.

## 7. LLMs Used in the Experiment

### 7.1 Phi-3 Mini

Repository identifier:

```text
microsoft/Phi-3-mini-4k-instruct
```

Phi-3 Mini is the smaller model in the experiment. Its lower compute cost
supports a higher request arrival rate and makes it useful for detecting
latency interference at moderate load.

### 7.2 Llama 3.1 8B

Repository identifier:

```text
hugging-quants/Meta-Llama-3.1-8B-Instruct-AWQ-INT4
```

This is a 4-bit AWQ-quantized Llama 3.1 8B instruction model. Quantization
reduces model memory and computation requirements sufficiently for the
experiment's CPU-serving environment.

The exact model revision must be recorded for the final campaign. A mutable
repository name alone is insufficient for reproducibility.

## 8. What vLLM Is and How It Is Used

vLLM is an LLM inference-serving framework. It exposes an HTTP API compatible
with the OpenAI completion API and schedules multiple generation requests
through one model server.

The target runs:

```text
vLLM OpenAI-compatible server -> model inference -> streamed/generated tokens
```

The repository's `vllm_server_launch.sh` script:

1. selects the requested model;
2. starts vLLM directly or in a Docker container;
3. configures CPU inference and model length;
4. waits for `/v1/models` to report readiness; and
5. stores the server log and process/container identifier.

The current experiment uses vLLM's CPU-serving path. The final paper must
report CPU count, memory, model revision, vLLM version, container digest,
thread count, and key-value cache configuration.

## 9. What ShareGPT Is and How It Is Used

ShareGPT is a dataset of multi-turn conversations. Each conversation contains
alternating user and assistant messages. It is used here as a source of
realistic, variable-length prompts and response-length targets.

The workload does not ask whether the model reproduces the original ShareGPT
answer. Instead, the benchmark uses conversation samples to construct
generation requests with varied input and output token lengths. This avoids a
workload in which every request has the same artificial size.

The current wrapper uses:

```text
ShareGPT_V3_unfiltered_cleaned_split.json
```

and passes it to vLLM's `benchmark_serving.py` with:

```text
--dataset-name sharegpt
```

The dataset is therefore a performance workload, not a privacy-sensitive
application dataset and not a model-quality benchmark. The PETS paper should
either add a clearly privacy-relevant application workload or explicitly
explain how results from this general conversation workload extrapolate to
privacy-sensitive inference.

The public artifact should identify prompts by dataset row and cryptographic
hash where possible. Unredacted user prompts and model outputs should not be
published without checking dataset licensing and privacy implications.

## 10. Request Arrival Process

The load generator uses vLLM's `benchmark_serving.py` in open-loop mode.

Open-loop means requests are scheduled independently of whether earlier
requests have completed. Inter-arrival delays are sampled to approximate a
Poisson arrival process at a configured request rate. This is preferable to a
closed-loop client that sends a new request only after the previous response,
because a closed loop can hide queueing and overload behavior.

Current calibrated rates are:

```text
Phi-3 Mini:  0.15 requests/second
Llama 3.1:   0.03 requests/second
```

The benchmark currently uses random seed:

```text
20260421
```

The same seed, prompt selection, request count, and rate must be reused across
matched Native, TDX-only, TDX-VOrdr, Python, and SGX runs.

`benchmark_serving.py` waits for submitted requests to complete. Therefore,
the observed wall time can exceed the nominal request-arrival window if the
server develops a queue. Both the configured duration and actual benchmark
duration must be retained.

## 11. Protocol 1.2 Operation During the Workload

### 11.1 Agent startup

On a newly booted CVM, the TDX server:

1. loads the vTPM AK;
2. reads the current RTMR3 value;
3. extends `SHA384(serialized AK public key)` into RTMR3;
4. opens persistent binary and ASCII IMA pseudo-file descriptors;
5. parses the existing IMA history;
6. extends canonical SHA-384 mappings of existing entries into RTMR3; and
7. continues monitoring for new entries.

Because RTMR3 is append-only, the server should be started only once per CVM
boot for a clean experiment. Repeated server restarts append another AK bind
and IMA replay onto the existing RTMR3 chain.

### 11.2 Unmeasured baseline

Before model-load measurement begins, the WEN performs one full attestation
from IMA entry zero. This establishes its rolling checkpoint.

The smoke orchestrator waits for this baseline to succeed and only then
releases a shared measurement-start signal. Consequently, the one-time full
replay is recorded but excluded from no-updates application measurements.

### 11.3 Incremental round

For each measured round, the WEN:

1. generates a fresh nonce;
2. sends the nonce and previous checkpoint metadata to the CVM;
3. asks for entries after the previous checkpoint;
4. receives a nonce-bound TDX quote;
5. receives a nonce-bound vTPM PCR 10 quote;
6. receives only the new IMA entries when continuity succeeds;
7. verifies the TDX DCAP quote and nonce;
8. verifies the vTPM quote and nonce;
9. confirms the quoted vTPM AK is the AK bound into RTMR3;
10. replays the new IMA entries into the previous RTMR3 state;
11. replays the signed IMA prefix into the previous PCR 10 state;
12. evaluates all configured policy checks; and
13. seals the next checkpoint when running inside SGX.

### 11.4 Persistent descriptor optimization

The CVM keeps its binary and ASCII IMA pseudo-files open across rounds. It
retains parsing state and reads only newly produced bytes. The experiment
records:

- descriptor generation;
- binary bytes read;
- ASCII bytes read;
- number of newly parsed entries;
- extraction time; and
- whether the no-new-entry count-only fast path was used.

A stable descriptor generation across measured rounds shows that the same
persistent-reader lifecycle was retained.

## 12. Synchronization

The smoke orchestrator uses the following ordering:

```text
Start long-lived WEN verifier
        |
        v
Run full baseline and establish checkpoint
        |
        v
Write ready.json
        |
        v
Orchestrator chooses shared future timestamp t0
        |
        +------ start count-only CVM sampler
        |
        +------ start periodic incremental attestation
        |
        +------ start vLLM request generation
```

This prevents the baseline replay from being mistaken for no-updates
attestation overhead.

## 13. Data Collected from the LLM Workload

The vLLM result file is `vllm.json`.

### 13.1 Throughput

- **Request throughput:** completed inference requests per second.
- **Output-token throughput:** generated output tokens per second.
- **Total-token throughput:** input plus output tokens processed per second,
  when supplied by the installed vLLM benchmark version.

Output-token throughput is the most direct application-capacity metric because
requests can have different output lengths.

### 13.2 Latency

- per-request TTFT;
- per-token ITL values;
- per-request end-to-end latency, if emitted by the vLLM version;
- aggregate mean and median values;
- p95 and p99 tail values derived from per-request arrays.

The final campaign should retain the raw arrays. A quantile-only CSV is not
enough to regenerate an empirical cumulative distribution function.

### 13.3 Request sizes

The vLLM result can include input and output token lengths. These values are
needed to confirm that matched conditions processed comparable workloads.

### 13.4 Current request-trace limitation

The existing vLLM JSON provides latency arrays but does not reliably preserve
an absolute arrival, dispatch, first-token, and completion timestamp for every
request. Therefore, the current smoke data cannot precisely classify which
individual requests overlapped each attestation phase.

Before the full PETS campaign, the load generator should emit a
`requests.jsonl` trace containing these timestamps and a request identifier.

## 14. Data Collected from Each Attestation Round

The compact file is `attestations.csv`. The complete result is retained in
`attestations.jsonl`.

### 14.1 Round identity and scheduling

- campaign and run identifiers;
- baseline or measurement phase;
- round index;
- scheduled, start, and end timestamps;
- schedule lag;
- missed schedule slots;
- configured epoch; and
- conservative effective evidence age.

The recorded evidence-age bound is:

```text
epoch T + measured round completion time
```

It is a conservative comparison metric, not the exact age of every individual
IMA event.

### 14.2 Verdicts and security checks

- boot verdict;
- runtime verdict;
- overall success;
- TDX signature and nonce checks;
- vTPM signature and nonce checks;
- AK-to-RTMR3 consistency;
- AK RTMR extension check;
- RTMR3 replay;
- PCR 10 signed-prefix replay;
- checkpoint continuity;
- binary/ASCII consistency;
- AK certificate policy;
- golden-boot policy; and
- error and warning details.

The JSONL file retains the full check dictionary rather than only a combined
boolean.

### 14.3 IMA and transfer measurements

- total IMA entries;
- wire IMA entries;
- requested wire start index;
- binary and ASCII wire bytes;
- complete response JSON bytes;
- new entries extracted by the agent;
- anchored entry count;
- signed PCR 10 prefix length;
- post-quote IMA drift;
- descriptor generation; and
- count-only fast-path status.

### 14.4 Checkpoint measurements

- checkpoint generation;
- whether the checkpoint was SGX-sealed; and
- checkpoint commit/sealing latency.

### 14.5 Timing breakdown

- nonce generation;
- TLS connection;
- request transmission;
- response wait and transfer;
- CVM IMA extraction;
- CVM RTMR extension;
- vTPM quote generation;
- TDX quote generation;
- WEN DCAP verification;
- WEN runtime-evidence verification; and
- WEN checkpoint commit/sealing.

`response_receive_ms` includes server processing plus network transfer. It is
not a pure network-only timer. Response size should therefore be reported
alongside it, and any paper figure must label the phase accurately.

## 15. System-Level Sampling

The CVM sampler writes `system_cvm.csv` and records:

- wall-clock timestamp;
- aggregate CPU utilization;
- used and available memory;
- IMA runtime measurement count; and
- one-minute load average.

The PETS harness passes `--skip-ima-bytes`. This is deliberate. Computing the
IMA pseudo-file byte length requires reading the complete log and would add an
unrelated `O(N)` workload that could distort the optimization being measured.

The current sampler measures whole-machine CPU and memory. A stronger full
campaign should additionally separate:

- vLLM process/container CPU and memory;
- TDX protocol-agent CPU and memory; and
- WEN verifier CPU and memory.

## 16. Optional Runtime Updates

The earlier matrix includes `no-updates` and `with-updates` conditions.

- `no-updates` allows normal service activity but does not intentionally install
  software during the measurement window.
- `with-updates` injects package-management activity to produce bursts of IMA
  entries.

Update timestamps, command outcomes, and elapsed times are stored in
`updates.csv`. Controlled updates help evaluate nonzero and heavy-tailed
`delta_n` values.

The smoke runner does not currently inject package updates. It validates the
basic serving and attestation path first.

## 17. Result Directory Layout

New Protocol 1.2 results are separated from the legacy pre-vTPM matrices:

```text
evaluation/results/llm/pets2027-vtpm/
  <campaign-id>/
    <model>/
      tdx-vordr/
        sgx/
          T-<epoch>s/
            repeat-<n>/
        python/
          T-<epoch>s/
            repeat-<n>/
```

A run directory contains:

```text
run.json
vllm.json
attestations.csv
attestations.jsonl
attestation_summary.json
system_cvm.csv
attestation_driver.log
benchmark.log
artifact_hashes.sha256
```

### `run.json`

Records condition, update interleaving, model, rate, request count, epoch,
duration, endpoint, policy flags, Git commit, branch, and whether the tree was
dirty. The smoke runner records `no-updates`: normal service activity remains
allowed, but it does not intentionally install software during the measurement
window.

### `artifact_hashes.sha256`

Provides integrity hashes for the primary result artifacts. It is not a
cryptographic attestation of the experiment host; it detects accidental
artifact modification after collection.

## 18. Smoke-Test Success Criteria

A smoke run is valid only if:

1. vLLM completes at least one request;
2. exactly one baseline round is recorded;
3. at least two measured rounds are recorded;
4. every protocol round succeeds;
5. measured rounds use `incremental-delta`;
6. measured rounds transfer fewer entries than the complete IMA count;
7. the IMA descriptor generation remains stable;
8. SGX runs report sealed checkpoints; and
9. the validator prints `Validation: OK`.

Passing these checks establishes that the experimental pipeline works. It
does not provide enough repetitions for a paper result.

## 19. Planned Full Campaign

The intended full matrix uses:

```text
Models:        Phi-3 Mini, Llama 3.1 8B
Conditions:    Native, TDX-only, TDX-VOrdr
WEN modes:     Python control, Gramine SGX
Epochs:        15, 30, 60, 300 seconds
IMA states:    Cold and warm/large
Updates:       No updates and controlled update bursts
Repetitions:   At least 3; preferably 5 independent runs per cell
```

Independent repetition means a separately executed run, not multiple samples
from one long process presented as independent trials.

The final design should randomize condition order, preserve matched prompt
identities and seeds, report all failures, and compute confidence intervals
across independent runs.

## 20. Figures Supported by the Data

### 20.1 Throughput by environment

Native versus TDX-only versus TDX-VOrdr output-token throughput shows the cost
of TDX and the additional cost of VOrdr.

### 20.2 TTFT empirical CDF

Raw TTFT samples show the complete latency distribution rather than only a
mean. A representative epoch such as `T=30 s` can be shown for both models.

### 20.3 Tail latency versus epoch

p50, p95, and p99 TTFT or end-to-end latency versus `T` shows whether frequent
attestation affects tail behavior.

### 20.4 Freshness-performance frontier

Application throughput or p99 latency can be plotted against effective
evidence age. This directly communicates the cost of obtaining fresher
runtime-integrity evidence.

### 20.5 Attestation round-time breakdown

The component timers show the contribution of IMA extraction, RTMR extension,
vTPM quote generation, TDX quote generation, response handling, WEN
verification, and sealing.

### 20.6 Full baseline versus incremental rounds

Separating the unmeasured full baseline from no-updates rounds demonstrates
the one-time checkpoint-establishment cost and the recurring incremental cost.

### 20.7 SGX versus Python verification

Matched Python and SGX runs determine whether enclave protection materially
changes verification or end-to-end application performance.

### 20.8 Delta and extraction behavior

Plots of extraction time, bytes, and round latency against `delta_n` and total
`N` demonstrate whether the persistent-descriptor optimization behaves as
intended.

## 21. How to Interpret the Main Comparisons

### Native versus TDX-only

This comparison estimates confidential-computing overhead. It says nothing
about VOrdr by itself.

### TDX-only versus TDX-VOrdr

This is the primary application-overhead comparison for VOrdr. The hardware,
model, workload, prompt sequence, and request rate must be held constant.

### Python versus SGX WEN

This comparison isolates WEN enclave overhead. It should not be confused with
Native versus TDX execution of the model.

### Full versus incremental attestation

This comparison measures checkpoint and IMA scaling behavior. A full baseline
should not be averaged into no-updates incremental round latency.

## 22. Development Settings Versus Paper Settings

The initial smoke commands use:

```text
--no-verify
--expected-rtmr3-base auto
AK certificate not required
Golden MRTD/RTMR0-2 policy not required
```

These settings are useful for determining whether the mechanism and data
pipeline work, but they weaken the policy enforced by the complete system.

### `--no-verify`

This disables TLS server-certificate verification. It does not disable DCAP
quote-signature or nonce verification, but TLS peer identity is not
authenticated. It must not be described as an authenticated production
channel.

### Automatic RTMR3 base

Accepting the startup base from agent metadata allows mechanism testing. A
stronger deployment should establish an expected base or a policy that derives
it from trusted boot measurements.

### Optional AK certificate policy

The current mechanism proves that:

- one AK signed the vTPM PCR 10 quote; and
- the digest of that same AK was extended into quoted RTMR3.

Without successful certificate-chain validation, this does not independently
prove that the AK is a genuine Google-provisioned vTPM AK. The paper must
distinguish AK-to-CVM binding from AK provenance.

### Optional golden boot policy

Without required golden MRTD and RTMR0-2 values, the verifier reports boot
measurements but does not enforce an approved boot configuration.

The final paper campaign should either enable these policies or state exactly
which checks are assumptions rather than experimentally enforced predicates.

## 23. Communication-Channel Considerations

The Protocol 1.2 server uses TLS. In smoke mode, certificate verification is
disabled for convenience. A final security evaluation should use a certificate
whose identity matches the endpoint and, if the protocol claim requires it,
mutual TLS with the WEN proving possession of its client key.

The current vLLM benchmark URL is:

```text
http://<target>:8000/v1/completions
```

That application endpoint is HTTP, not HTTPS. For a privacy-focused deployment
it must run over a protected private network, an authenticated TLS proxy, or an
HTTPS-capable serving configuration. TDX protects CVM memory but does not
encrypt plaintext application traffic on the network.

## 24. Reproducibility Metadata Required for Final Runs

The final artifact should record:

- Git commit and whether the tree is dirty;
- Protocol and evidence versions;
- exact model and tokenizer revisions;
- ShareGPT file hash and selected row identifiers;
- vLLM version and container digest;
- Linux kernel and IMA policy;
- GCP image, zone, and machine type;
- CPU count, memory, and frequency information;
- TDX/DCAP library and collateral versions;
- TPM tools and `gotpm` versions;
- Gramine version;
- SGX enclave MRENCLAVE and MRSIGNER;
- command lines and environment variables;
- random seeds;
- configured and actual experiment duration;
- initial and final IMA counts; and
- every failed or skipped attestation round.

## 25. Known Gaps Before the Full PETS Dataset

The smoke framework deliberately focuses on correctness of Protocol 1.2
integration. Before starting the full matrix, the following improvements
should be completed:

1. add per-request arrival, dispatch, first-token, and completion timestamps;
2. implement a real warmup phase whose requests are excluded from results;
3. record immutable model, tokenizer, dataset, and container identifiers;
4. add separate CVM agent, vLLM, and WEN resource sampling;
5. enable the intended TLS/mTLS policy;
6. decide and enforce the AK-certificate policy;
7. decide and enforce MRTD/RTMR0-2 and RTMR3-base policies;
8. add Native and TDX-only runners using the same artifact schema;
9. add controlled update injection with exact event records; and
10. run at least three, preferably five, independent repetitions.

## 26. Claims the Smoke Test Can and Cannot Support

### Supported after a successful smoke run

A successful smoke run demonstrates that:

- an LLM can serve requests while Protocol 1.2 runs;
- the WEN validates fresh TDX and vTPM evidence;
- the vTPM AK is consistently bound into RTMR3;
- the signed PCR 10 prefix matches IMA replay;
- RTMR3 matches the AK-plus-IMA replay;
- incremental rounds transfer and verify only new IMA entries;
- the CVM retains a persistent descriptor generation across rounds; and
- the SGX WEN seals rolling checkpoints.

### Not supported by smoke data alone

The smoke test does not establish:

- statistically significant performance overhead;
- behavior across multiple independent CVMs;
- model-quality equivalence;
- authenticated TLS peer identity when `--no-verify` is used;
- Google AK provenance when certificate binding is not required;
- approved boot state when golden measurements are not required;
- a privacy guarantee for plaintext inference traffic; or
- precise causal effects on individual requests without per-request timing
  traces.

Those claims require the stricter configuration and full campaign described
above.
