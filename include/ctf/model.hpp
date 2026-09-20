#pragma once

// Domain model of the checkpoint traffic fabric.
//
// Boundary: this runtime owns checkpoint *traffic* - which checkpoint traffic
// may enter the fabric, at what rate, under which isolation class, with which
// evidence. It does not own checkpoint creation, checkpoint storage format,
// storage durability, or restore semantics. The authoritative evidence this
// runtime produces is network transfer evidence; a transferred checkpoint is
// explicitly NOT reported as durable.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ctf/hash.hpp"
#include "ctf/ids.hpp"
#include "ctf/status.hpp"
#include "ctf/time.hpp"

namespace ctf {

// ---------------------------------------------------------------------------
// Isolation classes
// ---------------------------------------------------------------------------

/// Closed set: an unrecognized class cannot silently become a laxer one.
enum class IsolationClass : std::uint8_t {
  TrainingCritical = 0,  ///< synchronous training steps; strictest protection
  ServingLatency = 1,    ///< request-serving latency envelope
  TrainingBulk = 2,      ///< asynchronous checkpoint traffic belonging to training
  BestEffort = 3,        ///< opportunistic; preempted first
};

[[nodiscard]] const char* to_string(IsolationClass value) noexcept;
[[nodiscard]] std::optional<IsolationClass> isolation_class_from_string(std::string_view text) noexcept;
/// Lower rank = stricter protection. Used for deterministic preemption order.
[[nodiscard]] std::uint8_t isolation_rank(IsolationClass value) noexcept;

// ---------------------------------------------------------------------------
// Destination and path classes
// ---------------------------------------------------------------------------

enum class DestinationClass : std::uint8_t {
  LocalAttachedStore = 0,  ///< node-local device or filesystem
  RemoteObjectStore = 1,   ///< cluster object storage endpoint
  PeerNodeMemory = 2,      ///< peer node buffer (staging, not durable)
  SyntheticLab = 3,        ///< test/simulation destination; labelled SYNTHETIC
};

[[nodiscard]] const char* to_string(DestinationClass value) noexcept;
[[nodiscard]] std::optional<DestinationClass> destination_class_from_string(std::string_view text) noexcept;

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Ordinal of network evidence strength observed so far. This ordinal says
/// nothing about storage durability: TRAFFIC_SESSION_COMPLETE at
/// VerifiedAtDestination still reports DurabilityStatus::NotEstablished.
enum class EvidenceLevel : std::uint8_t {
  None = 0,
  SourceComplete = 1,
  Transferred = 2,
  VerifiedAtDestination = 3,
};

[[nodiscard]] const char* to_string(EvidenceLevel value) noexcept;

/// Storage durability is outside this runtime's authority. The default is
/// always NotEstablished; ExternallyAsserted can only be recorded when an
/// adjacent storage backend supplies its own flush/verify evidence, and even
/// then the fabric reports it as an external assertion, never as its own.
enum class DurabilityStatus : std::uint8_t {
  NotEstablished = 0,
  ExternallyAsserted = 1,
};

[[nodiscard]] const char* to_string(DurabilityStatus value) noexcept;

struct DurabilityAssertion {
  DurabilityStatus status = DurabilityStatus::NotEstablished;
  std::string backend_identity;  ///< bounded; empty when NotEstablished
  Digest evidence_digest;        ///< backend's own evidence digest
  Nanos observed_at = 0;
};

// ---------------------------------------------------------------------------
// Session and shard lifecycle
// ---------------------------------------------------------------------------

enum class SessionState : std::uint8_t {
  Submitted = 0,
  Deferred = 1,
  Admitted = 2,
  Transferring = 3,
  Paused = 4,
  SourceComplete = 5,
  Transferred = 6,
  VerifiedAtDestination = 7,
  TrafficSessionComplete = 8,
  Cancelled = 9,
  Superseded = 10,
  Failed = 11,
  RevalidationRequired = 12,
};

[[nodiscard]] const char* to_string(SessionState value) noexcept;
[[nodiscard]] bool is_terminal(SessionState value) noexcept;
[[nodiscard]] bool is_active(SessionState value) noexcept;

enum class ShardState : std::uint8_t {
  Pending = 0,
  Granted = 1,
  InFlight = 2,
  Transferred = 3,
  Verified = 4,
  Ambiguous = 5,
  Failed = 6,
  Cancelled = 7,
};

[[nodiscard]] const char* to_string(ShardState value) noexcept;

enum class AttemptOutcome : std::uint8_t {
  Granted = 0,
  InFlight = 1,
  DeliveredUnacked = 2,  ///< bytes observed leaving/arriving without sink ack
  DeliveredAcked = 3,
  Verified = 4,
  Failed = 5,
  Ambiguous = 6,  ///< sink outcome unknown; never treated as success
  Released = 7,
  Superseded = 8,
};

[[nodiscard]] const char* to_string(AttemptOutcome value) noexcept;

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

struct ShardDescriptor {
  ShardIndex index;
  std::uint64_t declared_bytes = 0;
  Digest declared_digest;  ///< producer's integrity claim for the shard content
  PathClassId path_class;  ///< 0 = policy default path

  friend bool operator==(const ShardDescriptor& lhs, const ShardDescriptor& rhs) noexcept {
    return lhs.index == rhs.index && lhs.declared_bytes == rhs.declared_bytes &&
           lhs.declared_digest == rhs.declared_digest && lhs.path_class == rhs.path_class;
  }
};

/// Shard/manifest metadata. Integrity here means the metadata is self-consistent
/// and intact in transit; it is not a claim that the shard content exists.
struct CheckpointManifest {
  CheckpointId checkpoint;
  CheckpointGeneration generation;
  WorkloadId workload;
  WorkloadContractGeneration contract_generation;
  std::uint64_t total_bytes = 0;
  std::vector<ShardDescriptor> shards;
  Digest manifest_digest;  ///< digest over the canonical shard table
  Nanos declared_at = 0;   ///< provenance only; never authority
};

/// Resource bounds applied to every externally supplied collection.
struct Limits {
  std::uint32_t max_shards_per_checkpoint = 4096;
  std::uint64_t max_checkpoint_bytes = 1ULL << 40;  // 1 TiB
  std::uint32_t max_sessions = 65536;
  std::uint32_t max_attempts_in_flight = 8192;
  std::uint32_t max_retained_history = 4096;
  std::uint32_t max_wave_width = 64;
  std::uint32_t max_path_classes = 64;
  std::uint32_t max_sessions_per_workload = 64;
  std::uint32_t max_workloads = 4096;
  std::size_t max_identity_text_bytes = 128;
  std::size_t max_string_bytes = 256;
  std::uint32_t max_supersession_chain = 8;
};

/// Digest over the canonical encoding of a manifest's shard table.
[[nodiscard]] Digest compute_manifest_digest(const CheckpointManifest& manifest);

/// Full validation: bounds, checked arithmetic, strictly increasing shard
/// indices, no duplicate shard keys, and a matching manifest digest.
[[nodiscard]] Status validate_manifest(const CheckpointManifest& manifest, const Limits& limits);

/// Check two manifests describe the same checkpoint generation and content
/// (used for idempotent resubmission).
[[nodiscard]] bool manifests_equivalent(const CheckpointManifest& lhs,
                                        const CheckpointManifest& rhs);

// ---------------------------------------------------------------------------
// Policy, topology, contracts
// ---------------------------------------------------------------------------

struct IsolationEnvelopeConfig {
  IsolationClass isolation = IsolationClass::TrainingBulk;
  std::uint64_t ceiling_bps = 0;       ///< hard class ceiling across all workloads
  std::uint64_t burst_window_ns = kNanosPerSecond / 10;
  std::uint32_t max_in_flight_sessions = 16;
};

struct PolicySnapshot {
  PolicyGeneration generation;
  /// Exactly one envelope per isolation class; missing entries are invalid.
  std::vector<IsolationEnvelopeConfig> envelopes;
  std::uint32_t max_wave_width = 16;
  std::uint64_t max_session_bytes = 1ULL << 38;
  std::uint32_t max_sessions = 4096;
  std::uint32_t max_attempts_in_flight = 1024;
  std::uint32_t retained_history = 256;
  bool require_destination_verification = true;
  Nanos defer_horizon_ns = kNanosPerSecond;      ///< how far ahead DEFER may be scheduled
  Nanos default_deadline_ns = 300 * kNanosPerSecond;
  Nanos minimum_rate_bps_for_admission = 0;      ///< 0 = no minimum
  Limits limits;
};

struct PathClass {
  PathClassId id;
  DestinationClass destination = DestinationClass::LocalAttachedStore;
  std::uint64_t capacity_bps = 0;
  bool synthetic = false;  ///< SYNTHETIC label: no physical hardware validated
  std::string label;       ///< bounded ASCII identifier
};

struct TopologySnapshot {
  TopologyGeneration generation;
  std::vector<PathClass> path_classes;
};

struct WorkloadContract {
  WorkloadId workload;
  WorkloadContractGeneration generation;
  IsolationClass isolation = IsolationClass::TrainingBulk;
  std::uint64_t ceiling_bps = 0;  ///< workload-level ceiling; 0 = class ceiling only
  std::uint64_t floor_bps = 0;    ///< reserved floor honoured for stricter classes
  std::uint32_t max_in_flight_sessions = 8;
  std::uint32_t max_shards_per_wave = 8;
  bool allow_supersession = true;
  Nanos deadline_budget_ns = 300 * kNanosPerSecond;
};

[[nodiscard]] Status validate_policy(const PolicySnapshot& policy, const Limits& limits);
[[nodiscard]] Status validate_topology(const TopologySnapshot& topology, const Limits& limits);
[[nodiscard]] Status validate_contract(const WorkloadContract& contract, const Limits& limits);
[[nodiscard]] const IsolationEnvelopeConfig* find_envelope(const PolicySnapshot& policy,
                                                           IsolationClass isolation) noexcept;
[[nodiscard]] const PathClass* find_path_class(const TopologySnapshot& topology,
                                               PathClassId id) noexcept;
[[nodiscard]] std::optional<PathClassId> default_path_class_for(const TopologySnapshot& topology,
                                                                DestinationClass destination) noexcept;

// ---------------------------------------------------------------------------
// Requests, decisions, envelopes
// ---------------------------------------------------------------------------

struct SessionRequest {
  CommandId command;  ///< idempotency key; replay is refused deterministically
  WorkloadId workload;
  WorkloadContractGeneration contract_generation;
  PolicyGeneration policy_generation;
  TopologyGeneration topology_generation;
  CheckpointId checkpoint;
  CheckpointGeneration checkpoint_generation;
  IsolationClass requested_isolation = IsolationClass::TrainingBulk;
  DestinationClass destination = DestinationClass::LocalAttachedStore;
  std::uint64_t requested_rate_bps = 0;  ///< 0 = policy-derived
  Nanos deadline_horizon_ns = 0;         ///< 0 = contract/policy default
  CheckpointManifest manifest;
};

struct CommandFence {
  CoordinatorEpoch epoch;
  PolicyGeneration policy_generation;
  TopologyGeneration topology_generation;
  WorkloadContractGeneration contract_generation;
  std::optional<CheckpointGeneration> checkpoint_generation;
  std::optional<AttemptSequence> attempt_sequence;
};

enum class DecisionKind : std::uint8_t {
  Admit = 0,
  Defer = 1,
  Deny = 2,
};

[[nodiscard]] const char* to_string(DecisionKind value) noexcept;

enum class ReasonCode : std::uint16_t {
  Admitted = 0,
  DuplicateCommand,       ///< idempotent replay of an identical command
  ClassCeilingSaturated,
  WorkloadCeilingSaturated,
  FabricSessionLimit,
  PathCapacityUnavailable,
  CreditUnavailable,
  UnknownWorkload,
  ContractGenerationStale,
  PolicyGenerationStale,
  TopologyGenerationStale,
  CheckpointGenerationStale,
  SupersessionDeniedByPolicy,
  SessionLimitPerWorkload,
  RequestedRateUnsupported,
  ManifestInvalid,
  ManifestMismatch,
  DestinationNotPermitted,
  CheckpointTooLarge,
  DeadlineUnreachable,
  FabricShuttingDown,
  AuthorityStale,
  AttemptStale,
  VerificationRequired,
  VerificationMismatch,
  EvidenceStale,
  SessionNotFound,
  StateNotResumable,
  AmbiguousSinkOutcome,
  CancelledByOperator,
  SupersededByNewerGeneration,
  ResourceLimit,
  Internal,
};

[[nodiscard]] const char* to_string(ReasonCode value) noexcept;
[[nodiscard]] bool is_fencing_reason(ReasonCode value) noexcept;

struct WavePlan {
  WaveIndex index;
  std::vector<ShardIndex> shards;
  std::uint64_t planned_bytes = 0;
};

/// What the fabric authorised: rate, burst, wave structure, deadline. An
/// envelope is authority to send, never evidence that anything was sent.
struct TrafficEnvelope {
  SessionId session;
  AttemptSequence sequence;  ///< advances on every re-admission/revalidation
  IsolationClass isolation = IsolationClass::TrainingBulk;
  std::uint64_t rate_bps = 0;
  std::uint64_t burst_bytes = 0;
  std::uint32_t wave_width = 0;
  std::vector<WavePlan> waves;
  std::optional<PathClassId> path_class;
  Nanos issued_at = 0;
  Nanos deadline_target = 0;
};

struct AdmissionDecision {
  DecisionKind kind = DecisionKind::Deny;
  ReasonCode reason = ReasonCode::Internal;
  std::string detail;
  SessionId session;
  std::optional<TrafficEnvelope> envelope;
  std::vector<SessionId> superseded;
  std::optional<Nanos> retry_after;
  CoordinatorEpoch epoch;
  Nanos decided_at = 0;

  [[nodiscard]] bool admitted() const noexcept { return kind == DecisionKind::Admit; }
};

struct WaveGrant {
  SessionId session;
  TransferAttemptId attempt;
  AttemptSequence sequence;
  ShardIndex shard;
  WaveIndex wave;
  std::uint64_t max_bytes = 0;
  std::uint64_t rate_bps = 0;
  std::uint64_t burst_bytes = 0;
  Nanos issued_at = 0;
  Nanos expires_at = 0;
  CoordinatorEpoch epoch;
};

/// Outcome of asking the fabric for credit. A deferral is not a failure and
/// not a grant: no bytes may be sent, and the caller may retry at retry_after.
struct WaveOutcome {
  bool granted = false;
  ReasonCode reason = ReasonCode::Admitted;
  std::string detail;
  std::optional<WaveGrant> grant;
  std::optional<Nanos> retry_after;
  Nanos decided_at = 0;
};

// ---------------------------------------------------------------------------
// Evidence supplied by peers
// ---------------------------------------------------------------------------

struct SourceCompleteEvidence {
  SessionId session;
  TransferAttemptId attempt;
  AttemptSequence sequence;
  WaveIndex wave;
  ShardIndex shard;
  std::uint64_t source_bytes = 0;
  Digest source_digest;
  Nanos observed_at = 0;
};

struct TransferEvidence {
  SessionId session;
  TransferAttemptId attempt;
  AttemptSequence sequence;
  ShardIndex shard;
  std::uint64_t arrived_bytes = 0;
  Digest arrived_digest;
  bool sink_acknowledged = false;  ///< false => bytes seen arriving, outcome unconfirmed
  Nanos observed_at = 0;
};

struct VerificationEvidence {
  enum class Outcome : std::uint8_t {
    Verified = 0,
    DigestMismatch = 1,
    Truncated = 2,
    Ambiguous = 3,
    Rejected = 4,
  };
  SessionId session;
  TransferAttemptId attempt;
  AttemptSequence sequence;
  ShardIndex shard;
  std::uint64_t verified_bytes = 0;
  Digest verified_digest;
  Outcome outcome = Outcome::Ambiguous;
  std::string verifier_identity;  ///< bounded; from the session envelope, not caller claims
  Nanos observed_at = 0;
};

[[nodiscard]] const char* to_string(VerificationEvidence::Outcome value) noexcept;

// ---------------------------------------------------------------------------
// Inspection views
// ---------------------------------------------------------------------------

struct ShardProgress {
  ShardIndex index;
  ShardState state = ShardState::Pending;
  std::uint64_t declared_bytes = 0;
  std::uint64_t transferred_bytes = 0;
  std::uint64_t verified_bytes = 0;
  AttemptSequence sequence;
  std::optional<TransferAttemptId> attempt;
  Digest declared_digest;
  std::optional<Digest> observed_digest;
};

struct SessionView {
  SessionId session;
  CheckpointId checkpoint;
  CheckpointGeneration checkpoint_generation;
  WorkloadId workload;
  WorkloadContractGeneration contract_generation;
  IsolationClass isolation = IsolationClass::TrainingBulk;
  DestinationClass destination = DestinationClass::LocalAttachedStore;
  SessionState state = SessionState::Submitted;
  EvidenceLevel evidence = EvidenceLevel::None;
  DurabilityStatus durability = DurabilityStatus::NotEstablished;
  std::uint64_t declared_bytes = 0;
  std::uint64_t transferred_bytes = 0;
  std::uint64_t verified_bytes = 0;
  std::uint32_t shards_total = 0;
  std::uint32_t shards_transferred = 0;
  std::uint32_t shards_verified = 0;
  std::uint32_t shards_ambiguous = 0;
  std::optional<ReasonCode> last_reason;
  std::string last_detail;
  std::string stale_reason;  ///< non-empty when revalidation is required
  std::optional<SessionId> superseded_by;
  std::optional<TrafficEnvelope> envelope;
  std::vector<ShardProgress> shards;
  Nanos created_at = 0;
  Nanos updated_at = 0;
  std::optional<Nanos> deadline_target;

  /// Explicit statement that network evidence is not storage durability.
  [[nodiscard]] bool durable_checkpoint_success() const noexcept { return false; }
};

struct SessionSummary {
  SessionId session;
  CheckpointId checkpoint;
  CheckpointGeneration checkpoint_generation;
  WorkloadId workload;
  SessionState state = SessionState::Submitted;
  EvidenceLevel evidence = EvidenceLevel::None;
  std::uint64_t declared_bytes = 0;
  std::uint64_t transferred_bytes = 0;
  std::uint64_t verified_bytes = 0;
  Nanos updated_at = 0;
};

struct AccountingSnapshot {
  /// Every authorisation the fabric issued, including re-authorisations after a
  /// wasted or truncated attempt: a retry costs additional admitted bytes.
  std::uint64_t bytes_admitted = 0;
  std::uint64_t bytes_transferred = 0;
  std::uint64_t bytes_verified = 0;
  std::uint64_t bytes_cancelled = 0;
  std::uint64_t bytes_wasted = 0;   ///< subset of bytes_transferred that cannot count toward its target
  std::uint64_t bytes_unproven = 0; ///< authorised, possibly transferred, never proven (restart/sink ambiguity)
  std::uint64_t bytes_deferred = 0;
  std::uint64_t granted_outstanding_bytes = 0;
  std::uint64_t sessions_admitted = 0;
  std::uint64_t sessions_deferred = 0;
  std::uint64_t sessions_denied = 0;
  std::uint64_t sessions_completed = 0;
  std::uint64_t sessions_cancelled = 0;
  std::uint64_t sessions_superseded = 0;
  std::uint64_t sessions_failed = 0;
  std::uint64_t commands_processed = 0;
  std::uint32_t active_sessions = 0;
  std::uint32_t active_attempts = 0;

  /// True when nothing is in flight and every session reached a terminal state.
  [[nodiscard]] bool at_baseline() const noexcept {
    return active_sessions == 0 && active_attempts == 0 && granted_outstanding_bytes == 0;
  }

  /// Conservation identity - every authorised byte lands in exactly one bucket:
  ///   bytes_admitted == bytes_transferred + bytes_wasted + bytes_cancelled
  ///                     + bytes_unproven + granted_outstanding_bytes
  /// bytes_verified is a subset of bytes_transferred (bytes that both arrived
  /// and count toward their shard target). bytes_wasted holds bytes that
  /// arrived but cannot count: truncated content, a superseded transfer, or a
  /// failed verification. bytes_unproven is never counted as transferred.
  [[nodiscard]] bool conserves() const noexcept {
    return bytes_admitted == bytes_transferred + bytes_wasted + bytes_cancelled +
                                 bytes_unproven + granted_outstanding_bytes;
  }
};

struct Explanation {
  SessionId session;
  std::string summary;
  std::vector<std::string> timeline;  ///< bounded retained history
};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

enum class EventKind : std::uint8_t {
  SessionSubmitted = 0,
  SessionAdmitted = 1,
  SessionDeferred = 2,
  SessionDenied = 3,
  SessionSuperseded = 4,
  SessionCancelled = 5,
  SessionCompleted = 6,
  WaveGranted = 7,
  TransferObserved = 8,
  VerificationObserved = 9,
  AmbiguityRecorded = 10,
  RevalidationRequired_ = 11,
  FenceRejected = 12,
  Shutdown = 13,
  SourceCompleteObserved = 14,
  SessionPaused = 15,
  SessionResumed = 16,
  DurabilityAsserted = 17,
};

[[nodiscard]] const char* to_string(EventKind value) noexcept;

/// Events are returned by value from engine operations and emitted by callers
/// after internal locks are released; the engine never invokes user code while
/// holding state.
struct FabricEvent {
  EventKind kind = EventKind::SessionSubmitted;
  SessionId session;
  ReasonCode reason = ReasonCode::Internal;
  std::string detail;
  Nanos at = 0;
};

}  // namespace ctf
