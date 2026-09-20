# Checkpoint Traffic Fabric

Open-source, vendor-neutral C++20 runtime for scheduling, isolating, and
governing checkpoint network bursts so durability traffic coexists safely with
latency-sensitive training and inference flows under generation-bound authority.

The question this runtime answers, and the only one it answers:

> When a checkpoint burst is requested, what checkpoint traffic may enter the
> fabric now, at what rate and isolation class, without violating
> serving/training obligations or treating a partially transferred checkpoint as
> durable?

Version 1.0.0. Apache License 2.0. No telemetry: the runtime never transmits
telemetry, usage data, or identifiers anywhere.

## System boundary

**Owned by this runtime**

* checkpoint traffic-session lifecycle (submission, admission, deferral, pause,
  resume, cancellation, supersession, completion);
* burst admission and deferral decisions against current workload obligations;
* bandwidth/rate envelopes, wave planning, and credit granting;
* serving/training isolation classes and their ceilings;
* destination and path-class policy hooks (which destinations may be used, at
  what reserved capacity);
* deadline-aware completion targets;
* correlation of transfer and destination-verification evidence;
* fencing of stale workload-contract, topology, policy, coordinator-epoch,
  checkpoint-generation, and attempt authority;
* explanations and accounting for bytes admitted, deferred, transferred,
  verified, cancelled, wasted, and unproven;
* persistence of exactly the state above, with restart reconciliation.

**Not owned by this runtime**

* checkpoint creation, sharding decisions, or checkpoint content;
* checkpoint storage format, replication, or retention;
* storage durability policy or restore semantics;
* generic bandwidth brokerage or generic routing;
* authentication or authorization of operators (see Limitations);
* the sink's storage backend (the bundled sink writes to a labelled synthetic
  destination).

The authoritative evidence this runtime produces is **network transfer
evidence**. A transferred checkpoint is never reported as a durable checkpoint.
`SessionView::durable_checkpoint_success()` always returns false, and durability is
reported as `DurabilityStatus::NotEstablished` unless an adjacent storage backend supplies
its own assertion, which is then reported as an **external** assertion and still
never converted into this runtime's claim.

## Core model and authority semantics

Identities are strongly typed and distinct: `CheckpointId`,
`CheckpointTrafficSessionId` (`SessionId`), `TransferAttemptId`, `WorkloadId`,
`CommandId`, `ShardIndex`, `WaveIndex`, `PathClassId`. Generations are separate
types and never interchangeable with identities: `CheckpointGeneration`,
`WorkloadContractGeneration`, `TopologyGeneration`, `PolicyGeneration`,
`AttemptSequence`. Authority epoch is a pair,
`CoordinatorEpoch = (IncarnationId, EpochTerm)`, so a restarted coordinator is never
mistaken for the process it replaced.

Four evidence states are kept apart on purpose:

| State | Meaning |
| --- | --- |
| `SOURCE_COMPLETE` | the source declared a shard finished sending |
| `TRANSFERRED` | bytes were acknowledged as arrived at the sink |
| `VERIFIED_AT_DESTINATION` | the destination checked size and digest |
| `TRAFFIC_SESSION_COMPLETE` | the traffic session reached its target under policy |

None of them implies storage durability. An ambiguous sink outcome is a first
class state (`ShardState::Ambiguous`, `ReasonCode::AmbiguousSinkOutcome`) and its bytes
are booked as **unproven**, never as transferred.

Every authoritative command carries a `CommandFence` (epoch, policy, topology,
workload-contract generations, plus optional checkpoint generation and attempt
sequence). A fence is accepted only when every generation is exactly the current
one. Older values are refusals (`StaleEpoch`, `StalePolicyGeneration`, ...), never
silent upgrades; unknown or future values are `ForeignEpoch` / `NotAuthorized`.

Changing policy, topology, or a workload contract moves every active session to
`RevalidationRequired`: a session can never continue with bandwidth authority issued
under generations that no longer hold. Re-establishing authority is an explicit
client call (`revalidate_session`) that re-derives the envelope from current
obligations and advances the envelope sequence, which fences the old envelope.

### Admission decision order

Decisions are deterministic and evaluated in a fixed order, each with a stable
reason code:

1. fence and request-generation agreement (`StaleEpoch`, `StalePolicyGeneration`, ...);
2. command replay and idempotency (`DuplicateCommand`, `ReplayDetected`);
3. workload contract presence and generation (`UnknownWorkload`, `ContractGenerationStale`);
4. manifest integrity and consistency (`ManifestInvalid`, `ManifestMismatch`);
5. isolation class resolution - traffic is never admitted into a class laxer
   than its contract;
6. destination and path-class permission (`DestinationNotPermitted`);
7. existing sessions for the checkpoint: idempotent duplicate, contradictory
   manifest, stale generation, or supersession (`CheckpointGenerationStale`,
   `SupersessionDeniedByPolicy`);
8. size bounds (`CheckpointTooLarge`);
9. capacity: fabric, workload, and class session bounds, then path-class
   reserved capacity (`Defer` with `FabricSessionLimit`, `SessionLimitPerWorkload`,
   `ClassCeilingSaturated`, `PathCapacityUnavailable`);
10. rate plan: `min(requested, class ceiling, workload ceiling, path headroom)`, raised
    toward the deadline-required rate when that is achievable
    (`RequestedRateUnsupported`, `DeadlineUnreachable`);
11. admit with an envelope: rate, burst, wave plan, wave width, path class, and
    an absolute deadline target.

A `Defer` creates no session and books no bytes as admitted; it carries a
deterministic `retry_after`. A `Deny` is permanent for that command.

### Rate isolation

Ceilings are enforced by the fabric, not by the sender. Each isolation class and
each workload has an integer token bucket (bytes, capped at one burst window);
every grant consumes from both, and a grant never exceeds the credit actually
held. The bundled sender must request credit for each chunk, so a sender that
ignores pacing stops making progress instead of exceeding the ceiling. Path
classes additionally carry a reserved-rate admission check. All arithmetic is
integer-only, so a given clock sequence yields identical grants everywhere.

### Accounting

Every authorised byte lands in exactly one bucket:

```
bytes_admitted == bytes_transferred + bytes_wasted + bytes_cancelled
                  + bytes_unproven + granted_outstanding_bytes
```

* `bytes_transferred` - arrived with a sink acknowledgement and counts toward its
  shard target; `bytes_verified` is a subset of it;
* `bytes_wasted` - arrived but cannot count (truncated content that was re-armed, a
  superseded, failed, or cancelled transfer);
* `bytes_cancelled` - authorised and released without arriving;
* `bytes_unproven` - authorised, never proven (a coordinator restart, an ambiguous
  sink outcome, an elapsed deadline);
* `granted_outstanding_bytes` - authorised and neither arrived, wasted, released,
  nor unproven.

A retry after a truncated transfer is a **new authorisation**, so `bytes_admitted`
can exceed the checkpoint size after retries. Accounting returns to baseline
(`at_baseline()`) once every session is terminal and no authority is outstanding;
`check_invariants()` re-derives the identity from per-session buckets on demand.

## Persistence semantics

State is written as a versioned, checksummed record: either a full snapshot
replaced atomically, or an appended journal record. The temporary file is flushed
to the device before it replaces the previous snapshot, and the runtime only
answers a command after the mutation is durable - an acknowledgement never
precedes the durability point it claims.

Write path: plan -> validate authority -> apply to the engine -> append or
persist -> flush -> respond.

Recovery rules:

* malformed, corrupt, truncated, oversized, and version-incompatible files are
  refused, and a snapshot is fully decoded and validated before any of it is
  applied - partial application does not exist;
* the journal is append-only, so a bad record can only be a torn tail; the valid
  prefix is recovered, the discarded bytes are counted, and `LoadReport` reports
  `torn_tail`, `discarded_bytes`, and a note per discarded record;
* journal growth is bounded: crossing the configured byte or record bound
  compacts to a snapshot;
* on load, a non-terminal session returns as `RevalidationRequired`, bytes granted to
  unsettled attempts become **unproven**, those attempts become **ambiguous**,
  in-flight credit is dropped, and bytes that were never granted stay outstanding
  so a retry is charged to the same admission instead of being admitted twice;
* terminal sessions keep their recorded evidence (a verified shard stays
  verified) but carry no authority;
* a configured policy or topology older than the persisted generation is refused
  at startup rather than silently downgrading.

## Process, epoch, and generation behaviour

A coordinator process is an incarnation. First boot is incarnation 1; every
restart increments the incarnation and starts a fresh term, so the previous
process's liveness, freshness, and in-flight credit are fenced off
deterministically. Commands stamped with the old epoch are refused with
`ForeignEpoch` even after the old process is gone.

Each connection is served by its own bounded handler thread, so a long-lived
client can never starve the clients behind it; the bound is
`max(worker_threads, max_pending_connections)` concurrent connections.

Repeated start/stop of the service is supported and tested; shutdown stops
accepting, signals blocked readers through a stop token (sockets are polled so a
blocked reader observes the request), joins every thread, and writes a final
snapshot.

## Protocol and trust boundary

Framed TCP on loopback or a trusted network. Frames are fixed-layout with an
explicit length, a protocol version, a header checksum, and a payload checksum;
the decoder rejects trailing garbage, unsupported versions, oversized payloads,
and either checksum mismatch. Payload decoding is canonical: unknown enum values,
non-canonical booleans, invalid UTF-8, over-long strings, out-of-range numbers,
absurd collection counts, and trailing bytes are refusals, never repairs, and
every failure is coded rather than boolean.

Frame sequence numbers must strictly increase in each direction per connection; a
repeat is `SequenceViolation` and closes the connection. Submission commands carry
an idempotency key: an identical replay is idempotent, a divergent body under the
same key is `ReplayDetected`. Evidence identity is bound from the connection
envelope, not from caller-supplied fields: a verification report is only accepted
from a connection that handshook as a sink, and the verifier identity recorded is
that connection's identity.

## Repository layout

```
include/ctf/     public headers (ids, model, fence, engine, wire, store, net,
                 protocol, client, service, agent, config, report)
src/             implementation of the same modules (plus the private shaper)
apps/            ctf-coordinator, ctf-agent (sender/sink), ctfctl
examples/        three runnable examples against supported paths
tests/           nine suites: unit, protocol, integration, property,
                 concurrency, adversarial, persistence, multiprocess, scale
                 (plus tests/harness: test harness and child-process control)
consumer/        independent downstream find_package consumer
cmake/           package-config template
```

## Public API sketch

```cpp
#include <ctf/engine.hpp>   // deterministic policy and state machine
#include <ctf/service.hpp>  // coordinator process
#include <ctf/client.hpp>   // protocol client
#include <ctf/store.hpp>    // versioned persistence
#include <ctf/agent.hpp>    // sender and synthetic-destination sink roles

ctf::EngineConfig config;                 // policy, topology, contracts, epoch
ctf::ManualClock clock;                   // injected time; SteadyClock in production
ctf::FabricEngine engine(config, clock);

ctf::CommandFence fence = engine.current_fence(workload, checkpoint_generation);
ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
if (decision.ok() && decision.value().admitted()) {
  const ctf::TrafficEnvelope& envelope = decision.value().envelope.value();
  ctf::Result<ctf::WaveOutcome> wave = engine.request_wave(session, shard, fence);
  // send exactly wave.value().grant.value().max_bytes, then report what happened
  engine.report_transfer(evidence, fence);
  engine.report_verification(verification, fence);
}
ctf::AccountingSnapshot accounting = engine.accounting();
ctf::Status invariants = engine.check_invariants();
```

The service and client mirror this over the wire; `ctf::CoordinatorClient` fills fences
from the handshake it performed, so it never invents authority.

## Build

Requirements: CMake 3.20+ and a C++20 compiler (MSVC 19.3x, GCC 11+, or Clang
14+). Windows links `ws2_32`; POSIX links pthreads. No third-party dependencies.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure      # nine suites, no timeouts
```

On Windows with the Visual Studio generator:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Options: `CTF_BUILD_APPS`, `CTF_BUILD_EXAMPLES`, `CTF_BUILD_TESTS`, `CTF_BUILD_SHARED`,
`CTF_WARNINGS_AS_ERRORS` (default ON, `/W4 /WX` on MSVC), `CTF_ENABLE_ASAN` (off by
default; see Limitations).

## Install and consume

```sh
cmake --install build --prefix /opt/ctf
```

The install exports `CheckpointTrafficFabric::ctf` together with headers, the package
config files, and the license and README. An independent downstream consumer
lives in `consumer/`:

```sh
cmake -S consumer -B consumer-build -DCMAKE_PREFIX_PATH=/opt/ctf
cmake --build consumer-build --parallel
./consumer-build/ctf_consumer
```

## Running the runtime

```sh
ctf-coordinator --config examples/coordinator.conf --data-dir /var/lib/ctf
# prints: CTF-READY host=127.0.0.1:PORT port=PORT epoch=1.1 incarnation=1 term=1

ctf-agent sink   --coordinator 127.0.0.1:PORT --directory /tmp/ctf-destination \
                 --port 0 --expect-shards 2
# prints: CTF-SINK-READY port=SINKPORT synthetic_destination=true

ctf-agent sender --coordinator 127.0.0.1:PORT --sink 127.0.0.1:SINKPORT \
                 --workload <uuid> --checkpoint <uuid> --generation 1 \
                 --shards 2 --shard-bytes 262144 --isolation TrainingBulk --json

ctfctl accounting --endpoint 127.0.0.1:PORT --json
ctfctl status     --endpoint 127.0.0.1:PORT --session <uuid>
ctfctl explain    --endpoint 127.0.0.1:PORT --session <uuid>
ctfctl invariants --endpoint 127.0.0.1:PORT
ctfctl cancel     --endpoint 127.0.0.1:PORT --session <uuid>
ctfctl shutdown   --endpoint 127.0.0.1:PORT
```

The CLI prints deterministic reason codes, not booleans. Exit codes: 0 ok,
1 usage, 2 refused, 3 transport failure; for `ctf-agent sender`: 2 denied,
3 deferred, 4 protocol failure, 5 stopped, 6 no credit, 8 truncated, 9 injected
death.

### Configuration

A strict `key = value` file: unknown keys, duplicate keys, malformed numbers, and
missing required keys are refused with the offending line number. See
`examples/coordinator.conf`. `ctfctl config --config <file>` prints the normalized
effective configuration, including which path classes are synthetic.

## Proof surfaces: real, synthetic, and unsupported

**REAL**

* the policy engine, state machine, codec, framing, persistence, and
  coordinator/client/sender/sink implementations in this repository;
* loopback TCP transport between real OS processes (`ctf-coordinator`,
  `ctf-agent sender`, `ctf-agent sink`) in the `multiprocess` and `integration`
  suites, including hard process kills;
* framed, checksummed, versioned wire protocol with adversarial decoder tests;
* versioned, checksummed persistence with torn-tail recovery, restart
  reconciliation, and epoch advancement;
* deterministic admission, deferral, supersession, deadline, and accounting
  behaviour under an injected clock.

**SYNTHETIC (labelled, not physical validation)**

* checkpoint **content**: the sender generates deterministic bytes from a seed
  and the sink verifies digests over those bytes;
* topology and path classes: capacity figures are configured numbers, not
  measured links; every bundled path class is marked `synthetic = true`;
* the bundled sink's destination is a local directory, and the fabric reports it
  as a synthetic lab destination;
* rate behaviour is proven against the fabric's own token bucket, not against a
  physical network's behaviour under congestion.

**UNSUPPORTED on the validation host (stated, not faked)**

* AddressSanitizer: the MSVC installation on the validation host does not ship
  the ASan runtime (`clang_rt.asan_static_runtime_thunk-x86_64.lib` is absent) and no
  Clang is installed. `CTF_ENABLE_ASAN=ON` exists for toolchains that provide it, but
  **no sanitizer coverage is claimed for this release**;
* no multi-host, RDMA, RoCE, InfiniBand, NVLink, SmartNIC/DPU, or programmable
  switch hardware was exercised; those dimensions are represented only as
  synthetic topology and evidence;
* no cryptographic authentication: the transport is trusted-network only;
* no thread sanitizer is available either, so concurrency is exercised by
  deterministic barrier tests and deliberate lock-discipline review rather than
  by a race detector.

## Tests

Nine suites, registered plainly with CTest and run without any timeout
configured:

| Suite | What it proves |
| --- | --- |
| `unit` | identities, checksums, model and authority validation, the fence matrix, the engine state machine, accounting closure |
| `protocol` | framing integrity, canonical decoding, handshake, replay/sequence/unknown-type refusal, connection churn, clean stop |
| `integration` | real sender, sink, and coordinator over loopback: transfer and verification, ceiling enforcement measured over wall clock, supersession, ambiguity, truncation, sink death, cancellation, repeated lifecycle |
| `property` | seeded randomized operation sequences with invariant checks after every step: conservation, ceiling bounds, determinism, supersession, restart properties |
| `concurrency` | concurrent clients, evidence races, duplicate submission storms, start/stop under load, concurrent generation-bound mutation |
| `adversarial` | frame mutation fuzzing, absurd declarations, contradictory metadata, stale and replayed authority, corrupt and truncated persistence, refuse-without-partial-application |
| `persistence` | atomic replacement, torn tails, version and size refusal, compaction bounds, restart revalidation with epoch advancement |
| `multiprocess` | real coordinator, sender, and sink processes; sender killed mid-transfer; sink death after bytes arrive before acknowledgement; truncation; cross-process supersession and stale replay; coordinator crash and restart fencing; repeated restarts advancing the incarnation |
| `scale` | batched submissions and keyed lookups at scale with ratio-based assertions, bounded retention, bounded per-session attempt history |

92 tests across the nine suites pass on the validation host in both the
Release configuration and CTest. Deterministic tests use an injected
`ManualClock`; the harness prints the reproduction
seed on failure. Randomized tests assert invariants after every step and never
rely on timing to be correct.

## Limitations observed

* Connection concurrency is bounded: the coordinator serves one handler thread per
  connection up to `max_pending_connections` (default 64, and never fewer than
  `worker_threads`). Beyond that bound a new connection is accepted and closed
  immediately rather than queued, so a client sees a transport failure instead of
  an unexplained stall. Raise the bound for large fleets.
* Operator commands are not authenticated. Any peer that can reach the listener
  can submit, cancel, or request shutdown; the fence mechanism governs authority
  currency, not identity trust. Deploy on a trusted network or behind an
  authenticating proxy.
* One coordinator process owns a data directory; there is no consensus,
  replication, or leadership election. Two coordinators sharing a directory are
  not supported.
* Durability of the checkpoint itself is out of boundary; this runtime cannot and
  does not report it.
* `bytes_wasted` intentionally double-counts work: a retry after truncation is a
  new authorisation, so a checkpoint that must be re-sent costs more admitted
  bytes than its size.
* The bundled sender is single-checkpoint and synchronous; it exists to exercise
  supported paths and inject faults, not as a production data plane.
* Ambiguous shards are surfaced but not auto-resolved. An operator or an external
  reconciler must cancel, supersede, or revalidate the session; the runtime
  refuses to guess.
* Scale tests use ratio-based assertions with deliberately generous headroom, so
  they detect accidental super-linear behaviour rather than measuring absolute
  performance.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
