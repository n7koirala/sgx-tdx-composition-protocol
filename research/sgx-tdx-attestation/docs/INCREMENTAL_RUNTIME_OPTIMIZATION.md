# Incremental IMA Extraction and Sealed WEN Checkpoints

## Scope

Protocol 1.2 replaces repeated complete IMA reads with persistent binary and
ASCII IMA pseudo-file descriptors. It also replaces full-history replay on
every WEN round with a compact rolling checkpoint.

The initial round remains a complete read and verification. Subsequent rounds
extract, transmit, parse, and replay only newly appended measurements.

## 1. Persistent CVM IMA Streams

The new common/ima_stream.py module owns two descriptors for the lifetime of
the TDX server:

~~~
binary_runtime_measurements fd
ascii_runtime_measurements fd
~~~

The descriptors are opened before startup replay and remain at their logical
end positions. Every synchronization first reads runtime_measurements_count.
If the kernel count equals both retained stream counts, the operation returns
without reading either measurement pseudo-file.

When the count changes, the agent:

1. Reads from the current binary descriptor position until EOF.
2. Reads from the current ASCII descriptor position until EOF.
3. Retains any incomplete trailing binary record or ASCII line.
4. Parses only complete new records.
5. Compares only new binary and ASCII PCR/template-hash fields.
6. Extends only those records into RTMR3.
7. Updates rolling PCR-10 and RTMR3 states.

A binary event can span userspace reads. The incremental parser returns the
number of consumed bytes and retains a partial event for the next call.

Historical records remain cached in CVM memory so the agent can send a full
recovery snapshot without reopening the pseudo-files. Normal synchronization
and RTMR extension do not rescan this history.

## 2. Rolling WEN Verification

After the first full verification, the WEN retains this compact checkpoint:

~~~
checkpoint and evidence format versions
verified IMA entry count
CVM stream epoch
quoted RTMR3 at that count
rolling SHA-256 and SHA-1 PCR-10 states
IMA continuity digest
SHA384(ak_pub)
RTMR3 startup base and post-AK value
MRTD and RTMR0 through RTMR2
checkpoint generation
~~~

The next request carries ima_offset, ima_checkpoint_rtmr3, runtime_epoch, and
stream_action. The CVM accepts the offset only when its software RTMR state at
that entry count equals the WEN checkpoint and the epoch matches. Otherwise it
sends a start-index-zero recovery snapshot.

For a valid delta, the WEN calculates:

~~~
expected RTMR3 = replay(delta, base=checkpoint.rtmr3)
new PCR256     = replay(delta, base=checkpoint.pcr10_sha256)
new PCR1       = replay(delta ASCII, base=checkpoint.pcr10_sha1)
~~~

It does not reconstruct or parse the historical measurement list.

The vTPM quote may cover a prefix of the delta because gotpm can produce later
IMA events. Prefix search starts at the prior PCR checkpoint. RTMR3 still
covers all returned entries.

## 3. SGX-Sealed Persistence

common/sealed_checkpoint.py reads Gramine's MRSIGNER key from:

~~~
/dev/attestation/keys/_sgx_mrsigner
~~~

HKDF derives a distinct checkpoint key, and AES-GCM protects canonical JSON.
Associated data binds the blob to the controller namespace, TDX address, port,
and method. Files are atomically stored below:

~~~
/app/runtime-state/sealed-checkpoints/
~~~

A modified blob fails authentication and causes a safe full replay. A process
or replacement enclave signed by the same key on the same SGX platform can
recover it. SGX sealing keys are platform-specific, so moving the file to a
different SGX machine is not supported without an attested migration service.

The host can delete or replay an older authentic blob. Deletion forces full
replay. Rollback requests a larger delta and is checked against current
TDX/vTPM quotes, so it degrades performance rather than enabling false trust.
Strict rollback prevention needs an external monotonic service.

## 4. Descriptor Control and Recovery

The nonce-bearing request supports:

~~~
continue  use positioned descriptors
reset     reopen descriptors and validate the retained prefix
~~~

Use --reset-cvm-stream only for recovery or testing. Reset is intentionally
expensive. Controlled IMA generation remains a local CVM operation through
generate_ima_entries.py; it is not exposed as an unauthenticated network
command.

## Complexity and seq_file Qualification

The implemented userspace costs are:

~~~
startup extraction              O(N)
normal userspace extraction     O(delta bytes)
normal parsing and replay       O(delta entries)
zero-delta userspace extraction O(1) count check
normal wire transfer            O(delta entries)
normal WEN replay               O(delta entries)
WEN checkpoint storage          O(1)
~~~

A strict claim that all kernel work is always O(delta) is not portable across
seq_file iterators. A later read can walk from the list head to recover its
logical position. The design still removes reopening, userspace prefix
skipping, full materialization, complete parsing, and repeated historical
replay. Report measured read latency instead of assuming hidden iterator
traversal is constant.

Guaranteed properties are count-only zero-delta userspace behavior, appended
bytes only, one descriptor generation across normal rounds, delta-only wire
transfer, and delta-only WEN replay. Kernel iterator traversal is measured.

## Runtime Metrics

Each response reports:

~~~
stream.epoch
stream.requested_start_index
stream.checkpoint_match
stream.start_reason
stream.wire_delta_entries
stream.wire_binary_bytes
stream.wire_ascii_bytes

stream.sync.fd_generation
stream.sync.delta_entries
stream.sync.binary_bytes_read
stream.sync.ascii_bytes_read
stream.sync.binary_read_calls
stream.sync.ascii_read_calls
stream.sync.count_check_ms
stream.sync.binary_read_ms
stream.sync.ascii_read_ms
stream.sync.parse_ms
stream.sync.total_ms
stream.sync.fast_path
~~~

Normal rounds should keep fd_generation at 1, use incremental-delta
verification, and report wire and pseudo-file bytes proportional to the delta.

## Build and Functional Test

Use the same commit on CVM and WEN.

On the CVM:

~~~bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/tdx-server
sudo -E python3 tdx_attestation_server.py --test --method dcap
sudo -E python3 tdx_attestation_server.py --port 8443 --method dcap
~~~

Startup must print persistent descriptors positioned at the current count and
IMA Reader: persistent-fd. Run only one server because RTMR3 is append-only.

On the WEN, rebuild because trusted modules and checkpoint paths changed:

~~~bash
cd ~/sgx-tdx-composition-protocol/research/sgx-tdx-attestation/sgx-verifier
make clean
make all
export CVM_IP=<TDX_VM_EXTERNAL_IP>
~~~

Initial full round:

~~~bash
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
  --tdx-host "$CVM_IP" --tdx-port 8443 \
  --method dcap --no-verify \
  --expected-rtmr3-base auto \
  --reset-checkpoint --verbose
~~~

Expected: Runtime replay: full and WEN checkpoint: sealed, generation=1.

Run again without --reset-checkpoint:

~~~bash
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
  --tdx-host "$CVM_IP" --tdx-port 8443 \
  --method dcap --no-verify \
  --expected-rtmr3-base auto --verbose
~~~

Expected: Recovered sealed runtime checkpoint, incremental-delta, and
generation=2. The CVM should send a nonzero start and not the full list.

## Large-Log Benchmark

Generate the base before starting the server:

~~~bash
sudo python3 generate_ima_entries.py --count 140000 --label base140k
~~~

Start the server and complete one full WEN round. Generate small deltas:

~~~bash
sudo python3 generate_ima_entries.py --count 10 --label delta10
sudo python3 generate_ima_entries.py --count 100 --label delta100
sudo python3 generate_ima_entries.py --count 1000 --label delta1000
~~~

Run the SGX benchmark:

~~~bash
make bench-runtime-sgx \
  TDX_HOST="$CVM_IP" TDX_PORT=8443 \
  RUNTIME_ROUNDS=20 RUNTIME_INTERVAL=1 \
  RUNTIME_ARGS="--expected-rtmr3-base auto"
~~~

CSV output is written to
runtime-state/benchmark-results/incremental-runtime.csv. Later rows should show
incremental-delta, fd_generation=1, a small wire count compared with total IMA
entries, and increasing sealed checkpoint generations.

Directly compare positioned descriptors with full reopen/reparse on the CVM:

~~~bash
sudo -E python3 benchmark_ima_reader.py \
  --rounds 10 --interval 3 --output ima_reader_140k.csv
~~~

Generate small deltas from another terminal during the intervals. Expected:

~~~
fd_generation remains 1
persistent_delta_entries follows newly generated entries
persistent_bytes_read follows appended bytes
zero-delta rounds set persistent_fast_path=True and read zero pseudo-file bytes
full_reopen_ms grows with complete log size
~~~

To test descriptor recovery:

~~~bash
gramine-sgx ./verifier /app/sgx-verifier/sgx_tdx_verifier.py \
  --tdx-host "$CVM_IP" --tdx-port 8443 \
  --method dcap --no-verify --reset-cvm-stream --verbose
~~~

That round increments fd_generation and performs a recovery scan.

## Failure Rules

- Wrong offset, RTMR checkpoint, or epoch: CVM sends a full recovery snapshot.
- Missing WEN checkpoint: WEN requests entry zero.
- Sealed checkpoint authentication failure: WEN warns and fully replays.
- Delta gap, duplicate, boot identity change, AK change, PCR mismatch, or RTMR
  mismatch: WEN rejects and does not commit.
- Descriptor reset with a changed retained prefix: CVM aborts collection.
- Post-quote entries are reported as drift and covered next round.

## Claims Supported by Protocol 1.2

A passing incremental round proves that the fresh TDX quote has the same boot
identity as the sealed checkpoint; the AK remains bound into RTMR3; replaying
only the new canonical events from the prior RTMR state equals quoted RTMR3;
the nonce-bound vTPM PCR-10 equals an exact prefix reached from the prior PCR
state; binary and ASCII deltas agree; and the checkpoint advances only after
all checks pass.

It does not claim cross-platform checkpoint migration, kernel-enforced RTMR3
completeness, strict host rollback prevention, complete Google AK chain
validation, or complete Intel collateral policy.
