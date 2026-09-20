#pragma once

// The deterministic fabric engine.
//
// The engine owns every authoritative decision in this boundary: admission,
// envelope issuance, wave credit, evidence correlation, supersession, and
// cancellation. It is a synchronous, clock-injected state machine: no threads
// of its own, no timers, no callbacks under locks. Events produced by an
// operation are returned through an optional sink and are emitted by the caller
// after the engine call has returned.
//
// All operations are safe to call concurrently; internal state is guarded by a
// single mutex whose critical sections never call out of the engine.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ctf/fence.hpp"
#include "ctf/model.hpp"
#include "ctf/status.hpp"
#include "ctf/time.hpp"

namespace ctf {

using EventSink = std::vector<FabricEvent>;

struct EngineConfig {
  PolicySnapshot policy;
  TopologySnapshot topology;
  std::vector<WorkloadContract> contracts;
  CoordinatorEpoch epoch;
  Limits limits;
  /// Identity stream seed. Fixed by default so deterministic tests reproduce
  /// every session and attempt identity they observe.
  std::uint64_t identity_seed = 0x5DEECE66DULL;
};

// ---------------------------------------------------------------------------
// Persistable state
// ---------------------------------------------------------------------------

struct PersistedShard {
  ShardIndex index;
  ShardState state = ShardState::Pending;
  AttemptSequence sequence;
  std::uint64_t granted_bytes = 0;
  std::uint64_t transferred_bytes = 0;
  std::uint64_t verified_bytes = 0;
  Digest observed_digest;
  bool has_observed_digest = false;
  std::optional<TransferAttemptId> attempt;
  bool source_complete = false;
  std::uint64_t source_bytes = 0;
};

struct PersistedAttempt {
  TransferAttemptId id;
  AttemptSequence sequence;
  ShardIndex shard;
  WaveIndex wave;
  AttemptOutcome outcome = AttemptOutcome::Granted;
  std::uint64_t granted_bytes = 0;
  std::uint64_t delivered_bytes = 0;
  Digest observed_digest;
  bool has_observed_digest = false;
  bool outstanding = false;
  Nanos granted_at = 0;
  Nanos updated_at = 0;
};

struct PersistedSession {
  SessionId session;
  SessionRequest request;
  SessionState state = SessionState::Submitted;
  EvidenceLevel evidence = EvidenceLevel::None;
  TrafficEnvelope envelope;
  std::uint64_t envelope_sequence = 0;
  std::uint64_t attempt_counter = 0;
  std::vector<PersistedShard> shards;
  std::vector<PersistedAttempt> attempts;
  std::vector<std::string> timeline;
  std::uint64_t admitted_bytes = 0;
  std::uint64_t transferred_bytes = 0;
  std::uint64_t verified_bytes = 0;
  std::uint64_t cancelled_bytes = 0;
  std::uint64_t wasted_bytes = 0;
  std::uint64_t unproven_bytes = 0;
  std::uint64_t outstanding_bytes = 0;
  std::uint32_t active_attempts = 0;
  bool source_complete = false;
  bool paused = false;
  Nanos created_at = 0;
  Nanos updated_at = 0;
  ReasonCode last_reason = ReasonCode::Admitted;
  std::string last_detail;
  std::string stale_reason;
  std::optional<SessionId> superseded_by;
};

struct ContractGenerationRecord {
  WorkloadId workload;
  WorkloadContractGeneration generation;
};

struct EngineSnapshot {
  CoordinatorEpoch epoch;
  PolicyGeneration policy_generation;
  TopologyGeneration topology_generation;
  std::vector<ContractGenerationRecord> contract_generations;
  std::vector<PersistedSession> sessions;
  AccountingSnapshot accounting;
  std::uint64_t commands_processed = 0;
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

class FabricEngine {
 public:
  /// The clock must outlive the engine. Config is validated on construction.
  FabricEngine(EngineConfig config, const Clock& clock);
  ~FabricEngine();

  FabricEngine(const FabricEngine&) = delete;
  FabricEngine& operator=(const FabricEngine&) = delete;

  /// Result of validating the initial configuration. A construction that could
  /// not validate its configuration refuses every operation afterwards.
  [[nodiscard]] Status startup_status() const;

  // --- Current authority ---------------------------------------------------
  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] FenceContext fence_context() const;
  [[nodiscard]] PolicySnapshot policy() const;
  [[nodiscard]] TopologySnapshot topology() const;
  [[nodiscard]] Limits limits() const;
  [[nodiscard]] std::optional<WorkloadContract> contract(WorkloadId workload) const;
  [[nodiscard]] std::vector<WorkloadContract> contracts() const;
  /// Fence describing current authority, optionally bound to a workload,
  /// checkpoint generation, and attempt sequence.
  [[nodiscard]] CommandFence current_fence(
      WorkloadId workload, std::optional<CheckpointGeneration> checkpoint_generation = std::nullopt,
      std::optional<AttemptSequence> attempt_sequence = std::nullopt) const;

  // --- Authority changes ---------------------------------------------------
  /// Each authority change must advance its generation; an equal or older
  /// generation is refused. Active sessions are moved to RevalidationRequired
  /// because their envelopes were issued under authority that no longer holds.
  [[nodiscard]] Status apply_policy(PolicySnapshot policy, EventSink* events = nullptr);
  [[nodiscard]] Status apply_topology(TopologySnapshot topology, EventSink* events = nullptr);
  [[nodiscard]] Status upsert_contract(WorkloadContract contract, EventSink* events = nullptr);
  /// Advance to a new coordinator incarnation/term. Every non-terminal session
  /// becomes RevalidationRequired and every unproven grant becomes UNPROVEN
  /// bytes: a restart never resurrects liveness, freshness, or in-flight credit.
  [[nodiscard]] Status advance_epoch(CoordinatorEpoch epoch, EventSink* events = nullptr);
  /// Load persisted state conservatively. Terminal sessions keep their recorded
  /// evidence; non-terminal sessions return as RevalidationRequired, their
  /// outstanding grants become UNPROVEN, and their attempts become AMBIGUOUS.
  [[nodiscard]] Status restore(const EngineSnapshot& snapshot, EventSink* events = nullptr);
  [[nodiscard]] EngineSnapshot export_snapshot() const;

  // --- Client operations ---------------------------------------------------
  [[nodiscard]] Result<AdmissionDecision> submit_session(const SessionRequest& request,
                                                         const CommandFence& fence,
                                                         EventSink* events = nullptr);
  [[nodiscard]] Result<AdmissionDecision> revalidate_session(SessionId session,
                                                             const CommandFence& fence,
                                                             EventSink* events = nullptr);
  [[nodiscard]] Status pause_session(SessionId session, const CommandFence& fence,
                                     std::string reason, EventSink* events = nullptr);
  [[nodiscard]] Status resume_session(SessionId session, const CommandFence& fence,
                                      EventSink* events = nullptr);
  [[nodiscard]] Status cancel_session(SessionId session, const CommandFence& fence,
                                      ReasonCode reason, std::string detail,
                                      EventSink* events = nullptr);
  [[nodiscard]] Result<WaveOutcome> request_wave(SessionId session, ShardIndex shard,
                                                 const CommandFence& fence,
                                                 EventSink* events = nullptr);
  [[nodiscard]] Status report_source_complete(const SourceCompleteEvidence& evidence,
                                              const CommandFence& fence,
                                              EventSink* events = nullptr);
  [[nodiscard]] Status report_transfer(const TransferEvidence& evidence, const CommandFence& fence,
                                       EventSink* events = nullptr);
  [[nodiscard]] Status report_verification(const VerificationEvidence& evidence,
                                           const CommandFence& fence,
                                           EventSink* events = nullptr);
  [[nodiscard]] Status report_ambiguous(SessionId session, TransferAttemptId attempt,
                                        AttemptSequence sequence, std::string cause,
                                        const CommandFence& fence, EventSink* events = nullptr);
  /// Record an adjacent storage backend's durability assertion. This never
  /// converts network evidence into durability: the assertion is stored as an
  /// external claim and is reported as such.
  [[nodiscard]] Status record_durability_assertion(SessionId session,
                                                   DurabilityAssertion assertion,
                                                   const CommandFence& fence,
                                                   EventSink* events = nullptr);

  // --- Inspection ----------------------------------------------------------
  [[nodiscard]] Result<SessionView> view_session(SessionId session) const;
  [[nodiscard]] Result<std::vector<SessionSummary>> list_sessions(
      std::optional<WorkloadId> workload, std::size_t limit) const;
  [[nodiscard]] AccountingSnapshot accounting() const;
  [[nodiscard]] Result<Explanation> explain(SessionId session) const;
  /// Advances the fabric's view of time: fails any session whose checkpoint
  /// deadline has elapsed. Cheap (indexed), and safe to call from a ticker.
  [[nodiscard]] Status poll_deadlines(EventSink* events = nullptr);
  [[nodiscard]] Status check_invariants() const;
  [[nodiscard]] std::size_t session_count() const;
  [[nodiscard]] std::size_t timeline_entries() const;
  [[nodiscard]] std::uint64_t commands_processed() const;

  // --- Shutdown ------------------------------------------------------------
  [[nodiscard]] bool shutting_down() const;
  /// Stop admitting new work. Existing sessions are not silently completed;
  /// they remain inspectable and are released by cancel/supersede or by the
  /// next incarnation's revalidation.
  [[nodiscard]] Status begin_shutdown(EventSink* events = nullptr);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ctf
