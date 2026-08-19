# Vordr vTPM Scalability Evaluation Plan

## 1. Purpose

This document defines the paper-grade scalability evaluation for Vordr protocol
version 1.2. The protocol combines:

- TDX DCAP evidence for the confidential VM (CVM);
- an RTMR3 chain containing the vTPM attestation-key binding and canonical IMA
  event measurements;
- a nonce-bound vTPM quote over SHA-256 PCR 10;
- incremental IMA verification using persistent CVM-side IMA descriptors;
- a rolling checkpoint sealed by the WEN inside Intel SGX; and
- a WEN service that can return a compact delegated-attestation result to many
  end users while refreshing the underlying CVM evidence periodically.

The scalability evaluation must distinguish between two different operations:

1. **Underlying CVM attestation refresh:** WEN obtains and verifies fresh TDX,
   vTPM, RTMR3, PCR 10, and IMA evidence.
2. **End-user delegated-attestation response:** WEN answers a user from the most
   recently accepted CVM state and binds the response to the user's nonce.

Vordr is not claiming to generate thousands of fresh hardware quotes per
second. Its scalability benefit comes from moving the expensive composed
attestation refresh off the per-user critical path and securely amortizing one
verified refresh across many end-user responses.

## 2. Interpretation of the Current Preliminary Result

The preliminary SGX-WEN smoke test used 16 zero-think-time client streams for
35 seconds and produced:

- 349,631 successful responses;
- 0 failed responses;
- 9,989.46 aggregate responses/s;
- 1.58 ms mean response latency;
- 1.99 ms p99 response latency; and
- two recurring WEN-to-CVM refreshes during the measured interval.

Each client stream repeatedly executed:

```text
send request -> wait for response -> verify response -> send next request
```

This is a closed-loop concurrency test. It does **not** represent 349,631
distinct users or 9,989 fresh TDX/vTPM attestations per second. The precise
interpretation is:

> With 16 concurrent zero-think-time request streams, one SGX-resident WEN
> served 9,989 cached delegated-attestation responses per second.

The result is internally consistent with Little's Law:

```text
throughput ~= concurrency / response time
           ~= 16 / 0.001581
           ~= 10,120 responses/s.
```

That preliminary fast-path run had limitations that must be stated:

- the load generator and WEN communicate over local TCP;
- the remote CVM network path is exercised by background refreshes, not every
  end-user request;
- the lightweight response is authenticated using HMAC-SHA256 in the
  scalability prototype; and
- the test ran for only 35 seconds, covering two recurring refreshes.

The preliminary result is useful for debugging and estimating capacity, but it
is not yet the final paper-grade scalability result.

The protocol 1.2 harness now adds enclave-held Ed25519 signatures, pinned-key
verification, synchronized burst makespan, open-loop scheduling, verified TLS,
five-run matrix support, and expanded reproducibility metadata.

## 3. Workload Models

No single workload model answers all scalability questions. The final
evaluation should contain the following three complementary tests.

### 3.1 Closed-Loop Concurrency Capacity

In a closed-loop test, each stream sends a new request only after receiving the
previous response. This measures the maximum serving capacity of one WEN and
shows how throughput and latency change as request concurrency increases.

This experiment answers:

- How many delegated-attestation responses can one SGX WEN complete per second?
- At what concurrency does throughput saturate?
- How does queueing affect p95, p99, and p99.9 latency?
- Does a background vTPM/TDX refresh interfere with response serving?

Use the term **concurrent request streams**, rather than distinct end users, in
the figure and paper text.

Recommended matrix:

```text
Concurrent streams: 1, 2, 4, 8, 16, 32, 64, 128, 256
Measured duration:  180 seconds per point
Warm-up:            30 seconds
Repetitions:        at least 5
Refresh period:     15 seconds
```

Run the following variants:

1. Direct fresh TDX attestation, where each request forces quote generation.
2. SGX-WEN compact response authenticated with the current session HMAC.
3. SGX-WEN compact response signed with an enclave-held signing key.
4. SGX-WEN audit response carrying the requested full or delta evidence.

Record:

- completed throughput;
- p50, p95, p99, and p99.9 latency;
- errors and timeouts;
- WEN evidence staleness;
- CPU utilization;
- process and enclave memory usage;
- EPC paging, if available;
- refresh count and refresh latency;
- response size; and
- responses served per underlying CVM refresh (fan-out factor).

### 3.2 One-Request-Per-User Burst

This experiment represents a population of distinct clients that each requests
one attestation result. All clients can be released simultaneously using a
barrier, producing a worst-case epoch-boundary burst.

Recommended populations:

```text
Users:             1, 16, 64, 256, 1K, 5K, 10K
Requests per user: 1
Repetitions:       at least 5
```

Measure two connection models:

1. Users reuse pre-established authenticated sessions.
2. Users establish a new TLS connection before requesting evidence.

Record:

- total burst makespan;
- completed requests/s using the actual makespan;
- p50, p95, p99, and p99.9 completion latency;
- connection failures, request failures, and timeouts;
- peak active connections and queue depth; and
- WEN CPU and memory pressure.

The existing `--requests-per-user 1` option is not sufficient for reporting
burst throughput without modification. The current summary divides successful
requests by the configured test duration, even when all one-shot clients finish
earlier. The harness must record actual burst start, final completion time, and
makespan.

### 3.3 Open-Loop Offered-Load Test

In an open-loop test, arrivals are scheduled independently of prior request
completion. This prevents a slow server from causing the clients to
automatically reduce their offered load, and it exposes queue buildup and tail
latency near saturation.

Start with the following rates, adjusting them after locating the saturation
knee of the signed-response implementation:

```text
Offered rates:     1K, 2.5K, 5K, 7.5K, 9K, 10K, 11K, 12.5K requests/s
Measured duration: 300 seconds per point
Warm-up:           30 seconds
Repetitions:       at least 5
Arrival process:   Poisson, with constant-rate scheduling as a secondary case
Connection pool:   fixed and large enough to avoid serialization by the client
Refresh period:    15 seconds
```

Report offered rate and achieved throughput separately. Define sustainable
capacity before examining the results, for example:

```text
error rate < 0.1% and p99 latency < 10 ms
```

Also divide requests into those that overlap an underlying CVM refresh and
those outside the refresh window. This reveals whether the approximately
hundreds-of-milliseconds composed refresh causes user-visible interference.

Open-loop testing is important because closed-loop clients can exhibit
coordinated omission: when responses slow down, clients submit fewer requests
and may under-sample the resulting latency tail.

## 4. Required Harness Changes

Complete these changes before collecting final paper data.

### 4.1 Enclave-Authenticated Response

The current scalability server uses an HMAC proof derived from a benchmark
secret. The paper describes an enclave-authenticated result. Add an enclave-held
Ed25519 or ECDSA key and sign the nonce-bound compact result for every request.

Benchmark HMAC and signature variants separately:

- HMAC represents an already established session-authenticated channel.
- A digital signature represents an independently verifiable delegated result.

The signing key must be generated or recovered inside the measured WEN enclave,
and its public key must be bound to the WEN attestation or provisioned through
the protocol's established trust path.

### 4.2 Remote TLS Load Generation

The preliminary benchmark uses local TCP between the load generator and WEN.
For paper-grade user-facing measurements:

- run the load generator on a separate machine;
- enable TLS;
- record network placement and round-trip time;
- retain a local-TCP microbenchmark only as a clearly labeled upper-bound
  server-capacity measurement; and
- ensure the load generator retains substantial CPU and network headroom.

### 4.3 One-Shot Makespan

For the burst experiment, add:

- an explicit client barrier;
- actual first-send and final-completion timestamps;
- makespan-based throughput;
- connection-establishment time; and
- separate request service time after connection establishment.

### 4.4 Open-Loop Scheduler

Add a scheduler that assigns intended arrival timestamps independently of
request completion. It must record:

- intended send time;
- actual send time;
- queueing delay at the generator;
- response completion time; and
- end-to-end latency measured from the intended arrival time.

If one load-generator machine cannot sustain the target rate while preserving
CPU headroom, distribute generation across multiple machines and synchronize
their clocks.

### 4.5 Reproducibility Metadata

Every result directory should record:

- Git commit and branch;
- protocol and runtime-evidence versions;
- WEN SGX measurement and debug/production status;
- CVM image, kernel, IMA policy, and baseline IMA count;
- CVM and WEN hardware configuration;
- Gramine, Python, tpm2-tools, gotpm, and DCAP versions;
- transport and certificate-verification policy;
- refresh period;
- response-authentication mode;
- offered-load model;
- load-generator hardware and placement; and
- raw per-request or histogram data.

### 4.6 Implementation Status

As of protocol 1.2, the required harness mechanisms are implemented and locally
validated in `evaluation/scalability`:

- [x] Ed25519 signatures produced with an SGX MRSIGNER-derived sealing key;
- [x] verifier-side signature validation and optional public-key pinning;
- [x] synchronized one-shot bursts with actual makespan accounting;
- [x] Poisson and constant-rate open-loop scheduling;
- [x] intended-arrival, queue-delay, service, and completion measurements;
- [x] CA and hostname verified TLS, plus remote no-spawn load generation;
- [x] per-run protocol, enclave, platform, transport, and tool metadata;
- [x] full-audit responses reuse the exact protocol-1.2 composed evidence
  accepted by the SGX verifier;
- [x] the runtime-evidence digest is covered by each nonce-bound WEN signature;
  and
- [x] local closed-loop, one-shot, and open-loop full-evidence smoke tests.

The Ed25519 key is signer-policy bound and restart-stable. Final experiments
must pin its SHA-256 public-key fingerprint after accepting the WEN SGX identity;
auto-discovery through the unsigned health endpoint is only a smoke-test aid.

Remote TLS code is validated locally. Section 9 step 4 is complete only after a
separate load-generator host validates the actual WEN certificate and route.

## 5. Comparison Systems

Published numbers from other systems must not be placed on an unqualified chart
as if all systems perform the same operation. Hardware, evidence semantics,
freshness, cryptography, and workload generation differ. Use the systems below
to compare methodology and architectural tradeoffs, and present reported values
in a table with explicit qualifications.

### 5.1 OPERA (CCS 2019)

Reference:

- Guoxing Chen, Yinqian Zhang, and Ten-Hwang Lai, "OPERA: Open Remote
  Attestation for Intel's Secure Enclaves," ACM CCS 2019.
- Paper: https://par.nsf.gov/servlets/purl/10134887
- DOI: https://doi.org/10.1145/3319535.3354220

Published evaluation points include:

- 193.32 requests/s with one logical core running an AttestE;
- 878.39 requests/s with eight logical cores running AttestEs;
- 5.17 ms OPERA quote-generation latency;
- 13.81 ms OPERA quote-verification latency;
- 118.18 quotes/s for the paper's `sgx_get_quote()` control; and
- 376.10 ms periodic AttestE revalidation.

OPERA is the canonical comparison for the closed-loop capacity experiment and
for separating per-request serving from periodic trust revalidation. However,
an OPERA request produces an EPID-backed attestation result, whereas Vordr's
fast path serves a nonce-bound statement over a periodically refreshed composed
CVM state. A raw throughput ratio must not be described as a direct
implementation speedup.

### 5.2 Transparent Attested DNS (USENIX Security 2025)

Reference:

- Antoine Delignat-Lavaud et al., "Transparent Attested DNS for Confidential
  Computing Services," USENIX Security 2025.
- Paper: https://www.usenix.org/system/files/usenixsecurity25-delignat-lavaud.pdf

Relevant methodology and results include:

- independent clients issuing a single TCP request;
- approximately 1,350 queries/s at the SGX authoritative aDNS server;
- a separate scalability evaluation using an optimized Bind front end that
  caches signed attestation records;
- attestation-registration and client time-to-first-byte measurements; and
- explicit evaluation of attestation record sizes and cache distribution.

aDNS is the strongest recent top-tier comparison for Vordr's one-shot and
open-loop user-serving experiments. Both systems move expensive attestation
work away from every user request and distribute a reusable trust result. Their
freshness models differ: aDNS relies on registration policy and DNS caching or
TTL behavior, whereas Vordr periodically refreshes runtime IMA, PCR 10, RTMR3,
vTPM, and TDX evidence.

### 5.3 Delegating Verification for Remote Attestation Using TEE (2024)

Reference:

- Takashi Yagawa et al., "Delegating Verification for Remote Attestation using
  TEE," SysTEX/EuroS&P Workshops 2024.
- Paper: https://systex24.github.io/papers/systex24-final34.pdf
- DOI: https://doi.org/10.1109/EuroSPW61312.2024.00025

The system verifies submitted quotes inside SGX and signs verification results
with an enclave-protected delegation key. Its evaluation:

- uses k6 for 10-second measurements;
- varies simultaneous users from 1 to 15;
- reports saturation beginning around the ninth user;
- attributes approximately 4 ms to SGX execution;
- attributes approximately 5 ms to delegation signing; and
- reports approximately 10 ms total delegation overhead.

This is the closest architectural comparison to WEN's SGX-resident delegated
verification, even though it is a workshop paper rather than a flagship
conference paper. It is especially useful when motivating the signed compact
response variant.

### 5.4 SCRAPS (USENIX Security 2022)

Reference:

- Lukas Petzi et al., "SCRAPS: Scalable Collective Remote Attestation for
  Pub-Sub IoT Networks with Untrusted Proxy Verifier," USENIX Security 2022.
- Paper: https://www.usenix.org/system/files/sec22-petzi.pdf

SCRAPS evaluates:

- networks from 100 to 25,000 devices;
- reuse of previously generated attestation evidence;
- warm-up duration, evidence hit percentage, and maximum query rate;
- five 1,200-second runs per main simulation configuration; and
- approximately 70% attestation-overhead reduction at 10,000 devices relative
  to its comparison design.

SCRAPS should be used as a qualitative comparison for evidence reuse, warm-up,
freshness, and fan-out. Its IoT, blockchain, and collective-attestation model
does not permit a direct requests-per-second comparison with a cloud CVM and an
SGX WEN.

## 6. Fair-Comparison Rules

For every system, distinguish:

- whether a fresh hardware quote is generated per user request;
- whether the system returns raw evidence or a delegated result;
- whether each response is digitally signed, MACed, or protected only by TLS;
- whether the result is publicly verifiable;
- how freshness is established;
- whether measurements are local, LAN, or WAN;
- whether connections are persistent or newly established;
- whether workload generation is closed-loop, burst, or open-loop;
- whether the verifier runs inside a TEE;
- hardware generation, core count, and memory; and
- response/evidence size.

Do not report statements such as "Vordr is 11x faster than OPERA" based only on
published peak throughput. A defensible statement is:

> OPERA measures fresh enclave-attestation service throughput, whereas Vordr
> measures the fan-out capacity of a periodically refreshed, SGX-verified CVM
> state. The results demonstrate different points in the freshness-versus-scale
> design space and are therefore compared by operation semantics, latency,
> throughput, and refresh policy rather than by an unqualified speedup ratio.

## 7. Planned Figures and Tables

### Figure A: Closed-Loop Capacity

- X-axis: concurrent request streams.
- Left Y-axis: completed delegated-attestation responses/s.
- Right Y-axis or separate panel: p99 latency.
- Curves: direct fresh TDX, SGX-WEN HMAC, SGX-WEN signature, and SGX-WEN audit.
- Mark the saturation knee for each implementation.

### Figure B: One-Shot Population

- X-axis: number of one-shot users, preferably logarithmic.
- Y-axis: burst makespan or p99 completion latency.
- Separate pre-established-session and new-TLS-session results.
- Include failures and timeouts.

### Figure C: Open-Loop Sustainable Capacity

- X-axis: offered request rate.
- Left Y-axis: achieved request rate.
- Right Y-axis or second panel: p99/p99.9 latency.
- Show the configured SLO and saturation knee.

### Figure D: Refresh Interference

- Compare response latency during a CVM refresh with latency outside refresh
  windows.
- Report WEN refresh latency and evidence staleness.

### Comparison Table

Recommended columns:

```text
System
Venue/year
Attested platform
Per-request operation
Fresh hardware quote per request?
Verifier protected by TEE?
Response authentication
Publicly verifiable?
Freshness mechanism
Workload model
Published scale or throughput
Evidence size
Important qualification
```

Published comparator points should be shown in this table or as clearly marked
annotations, not mixed into a single curve that implies identical hardware and
security semantics.

## 8. Paper Claims Supported by the Final Evaluation

Subject to the final results, the evaluation should support claims of the
following form:

1. A single SGX-resident WEN sustains a measured number of nonce-bound compact
   delegated-attestation responses per second under closed-loop concurrency.
2. The sustainable open-loop rate satisfies a declared error-rate and p99
   latency SLO.
3. A measured population of one-shot users can obtain evidence within a stated
   epoch or completion deadline.
4. Each composed TDX/vTPM/IMA refresh is amortized across a measured number of
   end-user responses without weakening the declared freshness bound.
5. Background refresh has a quantified impact on response latency and
   staleness.
6. Running WEN in SGX and signing or sealing its state introduces a measured
   overhead relative to an unprotected verifier, rather than relying on an
   untested assumption.

The central positioning should remain:

> Vordr does not accelerate hardware quote generation itself. It moves composed
> TDX/vTPM/IMA verification off the per-user critical path and securely
> amortizes each SGX-verified refresh across many nonce-bound end-user
> responses.

## 9. Execution Order

Use this order to avoid collecting a large dataset with an invalid harness:

1. **Done:** implement and unit-test the enclave signature response.
2. **Done:** correct one-shot makespan accounting.
3. **Done:** add and validate the open-loop scheduler.
4. **Local validation done; remote run pending:** verify TLS and remote load generation.
5. Calibrate the load generator and establish CPU/network headroom.
6. **Local synthetic validation done; deployed run pending:** run short smoke
   tests for all three workload models against the protocol-1.2 CVM.
7. Run the five-repetition closed-loop matrix.
8. Run the five-repetition one-shot population matrix.
9. Run the five-repetition open-loop offered-rate matrix.
10. Generate figures, confidence intervals, and the comparison table from raw
    results.
11. Archive configuration, raw data, logs, and plotting scripts with the paper
    artifact.

The next operational action is step 4 on the separate load-generator host,
followed by step 5 calibration. Do not start the five-repetition matrices until
both checks pass.

