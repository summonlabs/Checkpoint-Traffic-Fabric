// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/engine.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ctf/bytes.hpp"
#include "shaper.hpp"

namespace ctf {
namespace {

/// Grant granularity. A grant never exceeds the class burst, so the fabric's
/// own token bucket - not the sender's pacing - bounds admitted traffic.
constexpr std::uint64_t kMinGrantChunk = 16U * 1024U;
constexpr std::uint64_t kMaxGrantChunk = 1U * 1024U * 1024U;

[[nodiscard]] std::uint64_t mix64(std::uint64_t hash, std::uint64_t value) noexcept {
  hash ^= value;
  hash *= 0x100000001B3ULL;
  return hash;
}

struct ShardRecord {
  ShardIndex index;
  std::uint64_t declared_bytes = 0;
  Digest declared_digest;
  PathClassId path_class;
  ShardState state = ShardState::Pending;
  AttemptSequence sequence;
  std::optional<TransferAttemptId> attempt;
  std::uint64_t granted_bytes = 0;
  std::uint64_t transferred_bytes = 0;
  std::uint64_t verified_bytes = 0;
  Digest observed_digest;
  bool has_observed_digest = false;
  bool source_complete = false;
  std::uint64_t source_bytes = 0;
};

struct AttemptRecord {
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

struct SessionRecord {
  SessionId id;
  SessionRequest request;
  SessionState state = SessionState::Admitted;
  EvidenceLevel evidence = EvidenceLevel::None;
  DurabilityAssertion durability;
  TrafficEnvelope envelope;
  std::uint64_t envelope_sequence = 0;
  std::uint64_t attempt_counter = 0;
  std::vector<ShardRecord> shards;
  std::vector<AttemptRecord> attempts;
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
  SessionState paused_from = SessionState::Admitted;
  std::optional<PathClassId> reserved_path;
  std::uint64_t reserved_rate_bps = 0;
  Nanos created_at = 0;
  Nanos updated_at = 0;
  ReasonCode last_reason = ReasonCode::Admitted;
  std::string last_detail;
  std::string stale_reason;
  std::optional<SessionId> superseded_by;
};

struct CommandRecord {
  SessionId session;
  DecisionKind kind = DecisionKind::Admit;
  ReasonCode reason = ReasonCode::Admitted;
  std::uint64_t fingerprint = 0;
  bool has_session = false;
};

[[nodiscard]] std::string bytes_text(std::uint64_t value) {
  static constexpr const char* kSuffix[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  std::uint64_t scaled = value;
  std::size_t unit = 0;
  std::uint64_t remainder = 0;
  while (scaled >= 1024U && unit + 1 < 5) {
    remainder = scaled % 1024U;
    scaled /= 1024U;
    ++unit;
  }
  std::string out = std::to_string(scaled);
  if (unit > 0) {
    const std::uint64_t decimal = (remainder * 10U) / 1024U;
    if (decimal != 0) {
      out.push_back('.');
      out.push_back(static_cast<char>('0' + decimal));
    }
  }
  out += kSuffix[unit];
  return out;
}

}  // namespace

struct FabricEngine::Impl {
  Impl(EngineConfig config, const Clock& clock)
      : clock_(&clock), limits_(config.limits), id_factory_(config.identity_seed) {
    policy_ = std::move(config.policy);
    topology_ = std::move(config.topology);
    epoch_ = config.epoch;
    for (const WorkloadContract& contract : config.contracts) {
      contracts_.emplace(contract.workload, contract);
    }
    config_status_ = validate_policy(policy_, limits_);
    if (config_status_.ok()) {
      config_status_ = validate_topology(topology_, limits_);
    }
    if (config_status_.ok() && contracts_.empty()) {
      config_status_ = Status::error(ErrorCode::InvalidArgument,
                                     "engine requires at least one workload contract");
    }
    if (config_status_.ok()) {
      for (const auto& entry : contracts_) {
        config_status_ = validate_contract(entry.second, limits_);
        if (!config_status_.ok()) {
          break;
        }
      }
    }
    if (config_status_.ok() && (epoch_.incarnation.is_zero() || epoch_.term.is_zero())) {
      config_status_ =
          Status::error(ErrorCode::InvalidArgument, "engine requires a non-zero coordinator epoch");
    }
    if (!config_status_.ok()) {
      shutting_down_ = true;
      return;
    }
    retention_bound_ = std::max<std::size_t>(
        64, std::min<std::size_t>(static_cast<std::size_t>(limits_.max_sessions),
                                  static_cast<std::size_t>(policy_.retained_history) * 8));
    command_index_bound_ =
        std::max<std::size_t>(64, std::min<std::size_t>(timeline_bound() * 4, 4096));
    configure_shaper(clock.now());
  }

  // --- configuration -------------------------------------------------------
  const Clock* clock_;
  Limits limits_;
  PolicySnapshot policy_;
  TopologySnapshot topology_;
  std::unordered_map<WorkloadId, WorkloadContract, StrongIdHash<struct WorkloadIdTag>> contracts_;
  CoordinatorEpoch epoch_;

  // --- live state ----------------------------------------------------------
  detail::RateShaper shaper_;
  std::unordered_map<SessionId, SessionRecord, StrongIdHash<struct CheckpointTrafficSessionIdTag>>
      sessions_;
  std::unordered_map<WorkloadId, std::vector<SessionId>, StrongIdHash<struct WorkloadIdTag>>
      by_workload_;
  std::unordered_map<CheckpointId, std::vector<SessionId>, StrongIdHash<struct CheckpointIdTag>>
      by_checkpoint_;
  std::unordered_map<CommandId, CommandRecord, StrongIdHash<struct CommandIdTag>> command_index_;
  std::deque<CommandId> command_order_;
  std::size_t command_index_bound_ = 256;
  AccountingSnapshot accounting_;
  std::uint64_t commands_processed_ = 0;
  bool shutting_down_ = false;
  mutable std::mutex mutex_;

  // Active-session indexes kept as counters so admission stays O(1) in the
  // number of live sessions instead of scanning the session table.
  std::array<std::uint32_t, 4> class_active_{};
  std::unordered_map<WorkloadId, std::uint32_t, StrongIdHash<struct WorkloadIdTag>> workload_active_;
  // Bounded history: terminal sessions are retained up to retention_bound_ and
  // then evicted oldest-first, keeping aggregate accounting intact.
  std::deque<SessionId> terminal_order_;
  struct PrunedTotals {
    std::uint64_t admitted = 0;
    std::uint64_t transferred = 0;
    std::uint64_t verified = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t wasted = 0;
    std::uint64_t unproven = 0;
  };
  PrunedTotals pruned_;
  std::size_t retention_bound_ = 2048;
  IdFactory id_factory_{0x5DEECE66DULL};
  Status config_status_ = Status::success();

  // --- helpers (lock held) -------------------------------------------------
  [[nodiscard]] Nanos now() const noexcept { return clock_->now(); }

  void configure_shaper(Nanos at) {
    for (const IsolationEnvelopeConfig& envelope : policy_.envelopes) {
      shaper_.configure_class(envelope.isolation, envelope.ceiling_bps, envelope.burst_window_ns, at);
    }
    for (const auto& entry : contracts_) {
      shaper_.configure_workload(entry.first, entry.second.ceiling_bps, kNanosPerMillisecond * 100, at);
    }
  }

  [[nodiscard]] std::size_t timeline_bound() const noexcept {
    const std::size_t bound = static_cast<std::size_t>(policy_.retained_history);
    return bound == 0 ? 1 : bound;
  }

  void append_timeline(SessionRecord& session, Nanos at, std::string text) {
    session.timeline.push_back(std::to_string(at) + " " + std::move(text));
    const std::size_t bound = timeline_bound();
    if (session.timeline.size() > bound) {
      session.timeline.erase(session.timeline.begin(),
                             session.timeline.begin() +
                                 static_cast<std::ptrdiff_t>(session.timeline.size() - bound));
    }
  }

  [[nodiscard]] static std::optional<std::size_t> shard_position(const SessionRecord& session,
                                                                ShardIndex index) {
    std::size_t low = 0;
    std::size_t high = session.shards.size();
    while (low < high) {
      const std::size_t mid = low + (high - low) / 2;
      if (session.shards[mid].index < index) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    if (low < session.shards.size() && session.shards[low].index == index) {
      return low;
    }
    return std::nullopt;
  }

  [[nodiscard]] static std::optional<WaveIndex> wave_for_shard(const TrafficEnvelope& envelope,
                                                              ShardIndex index) {
    for (const WavePlan& plan : envelope.waves) {
      if (std::find(plan.shards.begin(), plan.shards.end(), index) != plan.shards.end()) {
        return plan.index;
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] AttemptRecord* find_attempt(SessionRecord& session, TransferAttemptId id) {
    for (AttemptRecord& attempt : session.attempts) {
      if (attempt.id == id) {
        return &attempt;
      }
    }
    return nullptr;
  }

  void release_path_reservation(SessionRecord& session) {
    if (session.reserved_path.has_value()) {
      shaper_.release_path_rate(session.reserved_path.value(), session.reserved_rate_bps);
      session.reserved_path.reset();
      session.reserved_rate_bps = 0;
    }
  }

  void settle_reason(SessionRecord& session, ReasonCode reason, std::string detail) {
    session.last_reason = reason;
    session.last_detail = std::move(detail);
  }

  /// Bytes authorised but never proven: on restart, deadline failure, or an
  /// ambiguous sink outcome they leave "outstanding" and become UNPROVEN. They
  /// are never counted as transferred.
  void mark_unproven(SessionRecord& session, std::uint64_t bytes) {
    const std::uint64_t bounded = std::min(bytes, session.outstanding_bytes);
    session.outstanding_bytes -= bounded;
    session.unproven_bytes += bounded;
    accounting_.granted_outstanding_bytes -= bounded;
    accounting_.bytes_unproven += bounded;
  }

  void settle_outstanding_as_cancelled(SessionRecord& session) {
    const std::uint64_t remaining = session.outstanding_bytes;
    session.outstanding_bytes = 0;
    session.cancelled_bytes += remaining;
    accounting_.granted_outstanding_bytes -= remaining;
    accounting_.bytes_cancelled += remaining;
  }

  void release_active_attempts(SessionRecord& session, AttemptOutcome outcome) {
    for (AttemptRecord& attempt : session.attempts) {
      if (attempt.outstanding) {
        attempt.outstanding = false;
        attempt.outcome = outcome;
      }
    }
    accounting_.active_attempts -= session.active_attempts;
    session.active_attempts = 0;
  }

  void settle_terminal(SessionRecord& session, SessionState state, ReasonCode reason,
                       std::string detail, Nanos at) {
    release_active_attempts(session, state == SessionState::Superseded ? AttemptOutcome::Superseded
                                                                      : AttemptOutcome::Released);
    // Transferred bytes that can no longer count toward this session's target
    // move from the transferred bucket into the wasted bucket: the byte is
    // accounted exactly once either way.
    if (state == SessionState::Superseded || state == SessionState::Cancelled ||
        state == SessionState::Failed) {
      // Verified bytes stay verified: they are facts about the destination even
      // when this session can no longer count them toward its target. Only the
      // transferred-but-unverified remainder becomes wasted.
      const std::uint64_t unverified = session.transferred_bytes > session.verified_bytes
                                           ? session.transferred_bytes - session.verified_bytes
                                           : 0;
      session.transferred_bytes -= unverified;
      session.wasted_bytes += unverified;
      accounting_.bytes_transferred -= unverified;
      accounting_.bytes_wasted += unverified;
    }
    if (!is_terminal(session.state)) {
      note_terminal(session);
    }
    session.state = state;
    session.paused = false;
    settle_reason(session, reason, std::move(detail));
    session.updated_at = at;
    release_path_reservation(session);
    prune_history();
  }

  void recompute_progress(SessionRecord& session, Nanos at) {
    std::uint32_t verified = 0;
    std::uint32_t settled = 0;
    std::uint32_t ambiguous = 0;
    std::uint32_t in_flight = 0;
    for (const ShardRecord& shard : session.shards) {
      switch (shard.state) {
        case ShardState::Verified:
          ++verified;
          ++settled;
          break;
        case ShardState::Transferred:
          ++settled;
          break;
        case ShardState::InFlight:
        case ShardState::Granted:
          ++in_flight;
          break;
        case ShardState::Ambiguous:
          ++ambiguous;
          break;
        case ShardState::Pending:
        case ShardState::Failed:
        case ShardState::Cancelled:
          break;
      }
    }
    const std::uint32_t total = static_cast<std::uint32_t>(session.shards.size());
    const bool all_verified = verified == total && total > 0;
    const bool all_settled = settled == total && total > 0;

    if (all_verified) {
      session.evidence = EvidenceLevel::VerifiedAtDestination;
    } else if (all_settled) {
      session.evidence = EvidenceLevel::Transferred;
    } else if (session.source_complete) {
      session.evidence = EvidenceLevel::SourceComplete;
    } else {
      session.evidence = EvidenceLevel::None;
    }

    if (!is_terminal(session.state) && session.state != SessionState::RevalidationRequired &&
        session.state != SessionState::Paused && session.state != SessionState::Deferred) {
      if (all_verified) {
        session.state = SessionState::VerifiedAtDestination;
      } else if (all_settled) {
        session.state = SessionState::Transferred;
      } else if (ambiguous > 0 || in_flight > 0) {
        // An unresolved shard keeps the session in Transferring: "the source
        // finished" is not the same statement as "every shard is accounted for".
        session.state = SessionState::Transferring;
      } else if (session.source_complete) {
        session.state = SessionState::SourceComplete;
      } else {
        session.state = SessionState::Admitted;
      }
    }

    const bool complete =
        policy_.require_destination_verification ? all_verified : all_settled;
    if (complete && !is_terminal(session.state)) {
      session.state = SessionState::TrafficSessionComplete;
      session.evidence =
          all_verified ? EvidenceLevel::VerifiedAtDestination : EvidenceLevel::Transferred;
      settle_reason(session, ReasonCode::Admitted,
                    policy_.require_destination_verification
                        ? "all shards verified at destination"
                        : "all shards transferred (destination verification not required by policy)");
      session.updated_at = at;
      release_path_reservation(session);
      ++accounting_.sessions_completed;
      session.outstanding_bytes = 0;
      note_terminal(session);
      prune_history();
    }
  }

  /// Bytes granted to attempts whose fate is unknown. Only these may be booked
  /// as UNPROVEN on a restart: bytes never granted to an attempt stay in the
  /// outstanding pool and fund the retry, so nothing is counted twice.
  [[nodiscard]] static std::uint64_t at_risk_bytes(const SessionRecord& session) {
    std::uint64_t at_risk = 0;
    for (const AttemptRecord& attempt : session.attempts) {
      if (!attempt.outstanding) {
        continue;
      }
      at_risk += attempt.granted_bytes > attempt.delivered_bytes
                     ? attempt.granted_bytes - attempt.delivered_bytes
                     : 0;
    }
    return at_risk;
  }

  static void release_attempts(SessionRecord& session) {
    for (AttemptRecord& attempt : session.attempts) {
      attempt.outstanding = false;
    }
    session.active_attempts = 0;
  }

  [[nodiscard]] std::uint32_t workload_active(WorkloadId workload) const {
    const auto it = workload_active_.find(workload);
    return it == workload_active_.end() ? 0 : it->second;
  }

  [[nodiscard]] std::uint32_t class_active(IsolationClass isolation) const {
    return class_active_[static_cast<std::size_t>(isolation)];
  }

  /// Single place that moves a session between active and terminal bookkeeping.
  void adjust_active(const SessionRecord& session, int delta) {
    const std::size_t class_index = static_cast<std::size_t>(session.envelope.isolation);
    if (delta > 0) {
      ++accounting_.active_sessions;
      if (class_index < class_active_.size()) {
        ++class_active_[class_index];
      }
      ++workload_active_[session.request.workload];
      return;
    }
    if (accounting_.active_sessions > 0) {
      --accounting_.active_sessions;
    }
    if (class_index < class_active_.size() && class_active_[class_index] > 0) {
      --class_active_[class_index];
    }
    const auto it = workload_active_.find(session.request.workload);
    if (it != workload_active_.end()) {
      if (it->second > 0) {
        --it->second;
      }
      if (it->second == 0) {
        workload_active_.erase(it);
      }
    }
  }

  void rebuild_indexes() {
    by_workload_.clear();
    by_checkpoint_.clear();
    for (const auto& entry : sessions_) {
      by_workload_[entry.second.request.workload].push_back(entry.first);
      by_checkpoint_[entry.second.request.checkpoint].push_back(entry.first);
    }
  }

  /// Evict oldest terminal sessions once the retained bound is exceeded. Active
  /// sessions are never evicted; aggregate accounting keeps their bytes so the
  /// conservation identity survives eviction.
  void prune_history() {
    if (sessions_.size() <= retention_bound_) {
      return;
    }
    const std::size_t target = retention_bound_ * 3 / 4;
    bool erased_any = false;
    while (sessions_.size() > target && !terminal_order_.empty()) {
      const SessionId id = terminal_order_.front();
      terminal_order_.pop_front();
      const auto it = sessions_.find(id);
      if (it == sessions_.end() || !is_terminal(it->second.state)) {
        continue;
      }
      const SessionRecord& session = it->second;
      pruned_.admitted += session.admitted_bytes;
      pruned_.transferred += session.transferred_bytes;
      pruned_.verified += session.verified_bytes;
      pruned_.cancelled += session.cancelled_bytes;
      pruned_.wasted += session.wasted_bytes;
      pruned_.unproven += session.unproven_bytes;
      sessions_.erase(it);
      erased_any = true;
    }
    if (erased_any) {
      rebuild_indexes();
    }
  }

  void note_terminal(SessionRecord& session) {
    adjust_active(session, -1);
    terminal_order_.push_back(session.id);
  }

  /// Deadlines live in an ordered index so observing time costs O(expired)
  /// instead of a scan over every session on every command.
  std::map<Nanos, std::vector<SessionId>> deadlines_;

  void index_deadline(const SessionRecord& session) {
    if (session.envelope.deadline_target > 0) {
      deadlines_[session.envelope.deadline_target].push_back(session.id);
    }
  }

  void enforce_deadlines(Nanos at, EventSink* events) {
    while (!deadlines_.empty()) {
      auto first = deadlines_.begin();
      if (first->first > at) {
        break;
      }
      const Nanos deadline = first->first;
      std::vector<SessionId> due = std::move(first->second);
      deadlines_.erase(first);
      for (const SessionId& id : due) {
        const auto it = sessions_.find(id);
        if (it == sessions_.end()) {
          continue;
        }
        SessionRecord& session = it->second;
        if (is_terminal(session.state) || session.envelope.deadline_target != deadline) {
          continue;  // stale index entry: the session completed or was re-fenced
        }
        mark_unproven(session, session.outstanding_bytes);
        settle_terminal(session, SessionState::Failed, ReasonCode::DeadlineUnreachable,
                        "checkpoint deadline elapsed before completion", at);
        ++accounting_.sessions_failed;
        append_timeline(session, at, "failed reason=DeadlineUnreachable");
        if (events != nullptr) {
          events->push_back(FabricEvent{EventKind::SessionDenied, session.id,
                                        ReasonCode::DeadlineUnreachable,
                                        "checkpoint deadline elapsed", at});
        }
      }
    }
  }

  [[nodiscard]] std::uint64_t fingerprint_request(const SessionRequest& request) const {
    std::uint64_t hash = 0xCBF29CE484222325ULL;
    for (const std::uint8_t byte : request.checkpoint.value().bytes()) {
      hash = mix64(hash, byte);
    }
    hash = mix64(hash, request.checkpoint_generation.value());
    for (const std::uint8_t byte : request.workload.value().bytes()) {
      hash = mix64(hash, byte);
    }
    hash = mix64(hash, request.contract_generation.value());
    hash = mix64(hash, request.policy_generation.value());
    hash = mix64(hash, request.topology_generation.value());
    hash = mix64(hash, static_cast<std::uint64_t>(request.requested_isolation));
    hash = mix64(hash, static_cast<std::uint64_t>(request.destination));
    hash = mix64(hash, request.requested_rate_bps);
    hash = mix64(hash, static_cast<std::uint64_t>(request.deadline_horizon_ns));
    hash = mix64(hash, request.manifest.total_bytes);
    hash = mix64(hash, static_cast<std::uint64_t>(request.manifest.shards.size()));
    const Digest manifest_digest = compute_manifest_digest(request.manifest);
    hash = mix64(hash, manifest_digest.crc32c_value());
    hash = mix64(hash, manifest_digest.fnv1a64_value());
    return hash;
  }

  void remember_command(const CommandId& command, const CommandRecord& record) {
    const std::size_t bound =
        std::max<std::size_t>(64, std::min<std::size_t>(timeline_bound() * 4, 4096));
    command_index_bound_ = bound;
    if (command_index_.find(command) == command_index_.end()) {
      command_order_.push_back(command);
      while (command_order_.size() > command_index_bound_) {
        command_index_.erase(command_order_.front());
        command_order_.pop_front();
      }
    }
    command_index_[command] = record;
  }

  [[nodiscard]] AdmissionDecision make_decision(DecisionKind kind, ReasonCode reason,
                                                std::string detail, SessionId session,
                                                Nanos at) const {
    AdmissionDecision decision;
    decision.kind = kind;
    decision.reason = reason;
    decision.detail = std::move(detail);
    decision.session = session;
    decision.epoch = epoch_;
    decision.decided_at = at;
    return decision;
  }

  [[nodiscard]] TrafficEnvelope build_envelope(const SessionRequest& request, SessionId session,
                                               IsolationClass isolation, PathClassId path,
                                               std::uint64_t rate_bps, std::uint64_t burst_bytes,
                                               std::uint32_t wave_width, Nanos now,
                                               Nanos deadline_target,
                                               std::uint64_t envelope_sequence) const {
    TrafficEnvelope envelope;
    envelope.session = session;
    envelope.sequence = AttemptSequence(envelope_sequence);
    envelope.isolation = isolation;
    envelope.rate_bps = rate_bps;
    envelope.burst_bytes = burst_bytes;
    envelope.wave_width = wave_width;
    envelope.path_class = path;
    envelope.issued_at = now;
    envelope.deadline_target = deadline_target;

    WavePlan plan;
    plan.index = WaveIndex(0);
    std::uint32_t in_wave = 0;
    for (const ShardDescriptor& shard : request.manifest.shards) {
      if (in_wave == wave_width) {
        envelope.waves.push_back(plan);
        plan = WavePlan{};
        plan.index = WaveIndex(plan.index.value() + 1);
        in_wave = 0;
      }
      plan.shards.push_back(shard.index);
      plan.planned_bytes += shard.declared_bytes;
      ++in_wave;
    }
    if (!plan.shards.empty()) {
      envelope.waves.push_back(plan);
    }
    return envelope;
  }

  [[nodiscard]] static std::uint64_t ceil_rate(std::uint64_t bytes, Nanos horizon_ns) noexcept {
    if (horizon_ns <= 0) {
      return (std::numeric_limits<std::uint64_t>::max)();
    }
    const std::uint64_t horizon = static_cast<std::uint64_t>(horizon_ns);
    const std::uint64_t whole = bytes / horizon;
    const std::uint64_t remainder = bytes % horizon;
    std::uint64_t rate = whole * static_cast<std::uint64_t>(kNanosPerSecond);
    rate += (remainder * static_cast<std::uint64_t>(kNanosPerSecond) + horizon - 1) / horizon;
    return rate;
  }

  struct RatePlan {
    bool ok = false;
    std::uint64_t rate_bps = 0;
    ReasonCode reason = ReasonCode::Admitted;
    std::string detail;
    std::optional<Nanos> retry_after;
  };

  [[nodiscard]] RatePlan plan_rate(const SessionRequest& request, const WorkloadContract& contract,
                                   const IsolationEnvelopeConfig& envelope,
                                   const PathClass& path, Nanos now) const {
    RatePlan plan;
    const std::uint64_t class_ceiling = envelope.ceiling_bps;
    const std::uint64_t workload_ceiling = contract.ceiling_bps;
    const std::uint64_t hard_ceiling = std::min(class_ceiling, workload_ceiling);
    const std::uint64_t path_reserved = shaper_.reserved_path_rate(path.id);
    const std::uint64_t path_headroom =
        path.capacity_bps > path_reserved ? path.capacity_bps - path_reserved : 0;

    const std::uint64_t requested =
        request.requested_rate_bps == 0 ? hard_ceiling : request.requested_rate_bps;
    if (requested > class_ceiling) {
      plan.reason = ReasonCode::RequestedRateUnsupported;
      plan.detail = "requested rate exceeds the isolation-class ceiling";
      return plan;
    }
    if (requested > workload_ceiling) {
      plan.reason = ReasonCode::RequestedRateUnsupported;
      plan.detail = "requested rate exceeds the workload-contract ceiling";
      return plan;
    }
    const std::uint64_t horizon = request.deadline_horizon_ns > 0
                                      ? request.deadline_horizon_ns
                                      : contract.deadline_budget_ns;
    const std::uint64_t required = ceil_rate(request.manifest.total_bytes, horizon);
    if (required > class_ceiling) {
      plan.reason = ReasonCode::DeadlineUnreachable;
      plan.detail = "deadline cannot be met even at the isolation-class ceiling";
      return plan;
    }
    std::uint64_t rate = std::max(requested, required);
    rate = std::min(rate, hard_ceiling);
    if (rate > path_headroom) {
      plan.reason = ReasonCode::PathCapacityUnavailable;
      plan.detail = "path class has no unreserved capacity for this session";
      plan.retry_after = now + policy_.defer_horizon_ns;
      return plan;
    }
    if (rate == 0) {
      plan.reason = ReasonCode::CreditUnavailable;
      plan.detail = "no rate can be granted under current obligations";
      plan.retry_after = now + policy_.defer_horizon_ns;
      return plan;
    }
    plan.ok = true;
    plan.rate_bps = rate;
    return plan;
  }

  void apply_supersession(SessionRecord& target, SessionId by, Nanos at, EventSink* events,
                          std::vector<SessionId>* superseded_out) {
    mark_unproven(target, target.outstanding_bytes);
    settle_terminal(target, SessionState::Superseded, ReasonCode::SupersededByNewerGeneration,
                    "superseded by checkpoint generation of session " + by.to_string(), at);
    target.superseded_by = by;
    ++accounting_.sessions_superseded;
    append_timeline(target, at, "superseded by=" + by.to_string());
    if (superseded_out != nullptr) {
      superseded_out->push_back(target.id);
    }
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::SessionSuperseded, target.id,
                                    ReasonCode::SupersededByNewerGeneration, by.to_string(), at});
    }
  }

  /// Fabric-wide fence dimensions. The workload-contract generation is
  /// validated separately against the session's contract.
  [[nodiscard]] Status check_fence_status(const CommandFence& fence) const {
    const FenceContext fabric_context{epoch_, policy_.generation, topology_.generation,
                                      fence.contract_generation};
    const FenceVerdict verdict = validate_fence(fence, fabric_context);
    return verdict.status;
  }

  [[nodiscard]] Status validate_workload_fence(const SessionRecord& session,
                                               const CommandFence& fence) const {
    const auto contract_it = contracts_.find(session.request.workload);
    if (contract_it == contracts_.end()) {
      return Status::error(ErrorCode::StaleContractGeneration,
                           "workload contract is no longer configured");
    }
    if (!(fence.contract_generation == contract_it->second.generation)) {
      return Status::error(fence.contract_generation < contract_it->second.generation
                               ? ErrorCode::StaleContractGeneration
                               : ErrorCode::NotAuthorized,
                           "command contract generation is not the active contract generation");
    }
    return Status::success();
  }

  [[nodiscard]] Status validate_checkpoint_generation(const SessionRecord& session,
                                                      const CommandFence& fence) const {
    if (!fence.checkpoint_generation.has_value()) {
      return Status::success();
    }
    if (!(fence.checkpoint_generation.value() == session.request.checkpoint_generation)) {
      return Status::error(ErrorCode::StaleCheckpointGeneration,
                           "command carries a checkpoint generation other than the session's");
    }
    return Status::success();
  }
};

// ---------------------------------------------------------------------------
// Construction and authority
// ---------------------------------------------------------------------------

FabricEngine::FabricEngine(EngineConfig config, const Clock& clock)
    : impl_(std::make_unique<Impl>(std::move(config), clock)) {}

FabricEngine::~FabricEngine() = default;

Status FabricEngine::startup_status() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->config_status_;
}

CoordinatorEpoch FabricEngine::epoch() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->epoch_;
}

FenceContext FabricEngine::fence_context() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return FenceContext{impl_->epoch_, impl_->policy_.generation, impl_->topology_.generation,
                      WorkloadContractGeneration(0)};
}

PolicySnapshot FabricEngine::policy() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->policy_;
}

TopologySnapshot FabricEngine::topology() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->topology_;
}

Limits FabricEngine::limits() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->limits_;
}

std::optional<WorkloadContract> FabricEngine::contract(WorkloadId workload) const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const auto it = impl_->contracts_.find(workload);
  if (it == impl_->contracts_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::vector<WorkloadContract> FabricEngine::contracts() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  std::vector<WorkloadContract> out;
  out.reserve(impl_->contracts_.size());
  for (const auto& entry : impl_->contracts_) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(), [](const WorkloadContract& lhs, const WorkloadContract& rhs) {
    return lhs.workload < rhs.workload;
  });
  return out;
}

CommandFence FabricEngine::current_fence(WorkloadId workload,
                                         std::optional<CheckpointGeneration> checkpoint_generation,
                                         std::optional<AttemptSequence> attempt_sequence) const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  CommandFence fence;
  fence.epoch = impl_->epoch_;
  fence.policy_generation = impl_->policy_.generation;
  fence.topology_generation = impl_->topology_.generation;
  const auto it = impl_->contracts_.find(workload);
  fence.contract_generation = it == impl_->contracts_.end()
                                  ? WorkloadContractGeneration(0)
                                  : it->second.generation;
  fence.checkpoint_generation = checkpoint_generation;
  fence.attempt_sequence = attempt_sequence;
  return fence;
}

Status FabricEngine::apply_policy(PolicySnapshot policy, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  if (!(impl_->policy_.generation < policy.generation)) {
    return Status::error(ErrorCode::StalePolicyGeneration,
                         "new policy generation must be greater than the active generation");
  }
  const Status validation = validate_policy(policy, impl_->limits_);
  if (!validation.ok()) {
    return validation;
  }
  impl_->policy_ = std::move(policy);
  impl_->configure_shaper(impl_->now());
  for (auto& entry : impl_->sessions_) {
    SessionRecord& session = entry.second;
    if (!is_active(session.state) || session.state == SessionState::RevalidationRequired) {
      continue;
    }
    session.state = SessionState::RevalidationRequired;
    session.stale_reason = "policy generation advanced after this envelope was issued";
    session.updated_at = impl_->now();
    impl_->append_timeline(session, impl_->now(), "revalidation required: policy generation");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::RevalidationRequired_, session.id,
                                    ReasonCode::PolicyGenerationStale, session.stale_reason,
                                    impl_->now()});
    }
  }
  return Status::success();
}

Status FabricEngine::apply_topology(TopologySnapshot topology, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  if (!(impl_->topology_.generation < topology.generation)) {
    return Status::error(ErrorCode::StaleTopologyGeneration,
                         "new topology generation must be greater than the active generation");
  }
  const Status validation = validate_topology(topology, impl_->limits_);
  if (!validation.ok()) {
    return validation;
  }
  impl_->topology_ = std::move(topology);
  for (auto& entry : impl_->sessions_) {
    SessionRecord& session = entry.second;
    if (!is_active(session.state) || session.state == SessionState::RevalidationRequired) {
      continue;
    }
    session.state = SessionState::RevalidationRequired;
    session.stale_reason = "topology generation advanced after this envelope was issued";
    session.updated_at = impl_->now();
    impl_->append_timeline(session, impl_->now(), "revalidation required: topology generation");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::RevalidationRequired_, session.id,
                                    ReasonCode::TopologyGenerationStale, session.stale_reason,
                                    impl_->now()});
    }
  }
  return Status::success();
}

Status FabricEngine::upsert_contract(WorkloadContract contract, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const auto existing = impl_->contracts_.find(contract.workload);
  if (existing != impl_->contracts_.end() && !(existing->second.generation < contract.generation)) {
    return Status::error(ErrorCode::StaleContractGeneration,
                         "new contract generation must be greater than the active generation");
  }
  const Status validation = validate_contract(contract, impl_->limits_);
  if (!validation.ok()) {
    return validation;
  }
  if (impl_->contracts_.size() >= impl_->limits_.max_workloads &&
      existing == impl_->contracts_.end()) {
    return Status::error(ErrorCode::ResourceExhausted, "workload contract bound reached");
  }
  const WorkloadId workload = contract.workload;
  const WorkloadContractGeneration generation = contract.generation;
  impl_->shaper_.configure_workload(workload, contract.ceiling_bps, kNanosPerMillisecond * 100,
                                    impl_->now());
  impl_->contracts_[workload] = std::move(contract);
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::RevalidationRequired_, SessionId{},
                                  ReasonCode::ContractGenerationStale,
                                  "workload contract generation " + generation.to_string() +
                                      " applied",
                                  impl_->now()});
  }
  const auto index_it = impl_->by_workload_.find(workload);
  if (index_it != impl_->by_workload_.end()) {
    for (const SessionId& id : index_it->second) {
      const auto session_it = impl_->sessions_.find(id);
      if (session_it == impl_->sessions_.end()) {
        continue;
      }
      SessionRecord& session = session_it->second;
      if (!is_active(session.state) || session.state == SessionState::RevalidationRequired) {
        continue;
      }
      session.state = SessionState::RevalidationRequired;
      session.stale_reason = "workload contract generation advanced after this envelope was issued";
      session.updated_at = impl_->now();
      impl_->append_timeline(session, impl_->now(), "revalidation required: contract generation");
      if (events != nullptr) {
        events->push_back(FabricEvent{EventKind::RevalidationRequired_, session.id,
                                      ReasonCode::ContractGenerationStale, session.stale_reason,
                                      impl_->now()});
      }
    }
  }
  return Status::success();
}

Status FabricEngine::advance_epoch(CoordinatorEpoch epoch, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  if (!(impl_->epoch_ < epoch)) {
    return Status::error(ErrorCode::StaleEpoch,
                         "new epoch must be greater than the active epoch");
  }
  impl_->epoch_ = epoch;
  const Nanos at = impl_->now();
  impl_->deadlines_.clear();
  for (auto& entry : impl_->sessions_) {
    SessionRecord& session = entry.second;
    if (is_terminal(session.state)) {
      continue;
    }
    // Nothing dynamic survives the restart: in-flight grants become UNPROVEN and
    // attempts become AMBIGUOUS. Bytes that were never granted to an attempt stay
    // outstanding so the retry is charged to the same admission.
    impl_->mark_unproven(session, Impl::at_risk_bytes(session));
    for (AttemptRecord& attempt : session.attempts) {
      if (attempt.outcome == AttemptOutcome::Granted || attempt.outcome == AttemptOutcome::InFlight ||
          attempt.outcome == AttemptOutcome::DeliveredUnacked) {
        attempt.outcome = AttemptOutcome::Ambiguous;
        attempt.updated_at = at;
      }
    }
    impl_->accounting_.active_attempts -= session.active_attempts;
    Impl::release_attempts(session);
    for (ShardRecord& shard : session.shards) {
      if (shard.state == ShardState::Granted || shard.state == ShardState::InFlight) {
        shard.state = ShardState::Pending;
        shard.sequence = AttemptSequence(0);
        shard.attempt.reset();
        shard.granted_bytes = 0;
      }
    }
    session.state = SessionState::RevalidationRequired;
    session.paused = false;
    session.stale_reason = "coordinator restarted: authority must be re-established";
    session.updated_at = at;
    impl_->append_timeline(session, at, "revalidation required: coordinator restart");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::RevalidationRequired_, session.id,
                                    ReasonCode::AuthorityStale, session.stale_reason, at});
    }
  }
  return Status::success();
}

Status FabricEngine::restore(const EngineSnapshot& snapshot, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  if (!snapshot.accounting.conserves()) {
    return Status::error(ErrorCode::CorruptState,
                         "persisted accounting does not conserve bytes");
  }
  if (snapshot.policy_generation > impl_->policy_.generation) {
    return Status::error(ErrorCode::StalePolicyGeneration,
                         "configured policy is older than the persisted policy generation");
  }
  if (snapshot.topology_generation > impl_->topology_.generation) {
    return Status::error(ErrorCode::StaleTopologyGeneration,
                         "configured topology is older than the persisted topology generation");
  }
  if (snapshot.sessions.size() > impl_->limits_.max_sessions) {
    return Status::error(ErrorCode::ResourceExhausted,
                         "persisted session count exceeds the configured bound");
  }
  std::unordered_map<SessionId, SessionRecord, StrongIdHash<struct CheckpointTrafficSessionIdTag>>
      restored;
  restored.reserve(snapshot.sessions.size());
  for (const PersistedSession& persisted : snapshot.sessions) {
    if (persisted.session.is_nil()) {
      return Status::error(ErrorCode::CorruptState, "persisted session has a nil identity");
    }
    if (restored.find(persisted.session) != restored.end()) {
      return Status::error(ErrorCode::DuplicateIdentity, "persisted state repeats a session id");
    }
    const Limits& limits = impl_->limits_;
    const Status manifest_status = validate_manifest(persisted.request.manifest, limits);
    if (!manifest_status.ok()) {
      return Status::error(ErrorCode::CorruptState,
                           "persisted session manifest is invalid: " + manifest_status.to_string());
    }
    if (persisted.shards.size() != persisted.request.manifest.shards.size()) {
      return Status::error(ErrorCode::CorruptState,
                           "persisted session shard table does not match its manifest");
    }
    if (is_terminal(persisted.state) && persisted.outstanding_bytes != 0) {
      return Status::error(ErrorCode::CorruptState,
                           "terminal persisted session retains outstanding authority");
    }
    SessionRecord record;
    record.id = persisted.session;
    record.request = persisted.request;
    record.state = persisted.state;
    record.evidence = persisted.evidence;
    record.envelope = persisted.envelope;
    record.envelope_sequence = persisted.envelope_sequence;
    record.attempt_counter = persisted.attempt_counter;
    record.timeline = persisted.timeline;
    record.admitted_bytes = persisted.admitted_bytes;
    record.transferred_bytes = persisted.transferred_bytes;
    record.verified_bytes = persisted.verified_bytes;
    record.cancelled_bytes = persisted.cancelled_bytes;
    record.wasted_bytes = persisted.wasted_bytes;
    record.unproven_bytes = persisted.unproven_bytes;
    record.outstanding_bytes = persisted.outstanding_bytes;
    record.source_complete = persisted.source_complete;
    record.created_at = persisted.created_at;
    record.updated_at = persisted.updated_at;
    record.last_reason = persisted.last_reason;
    record.last_detail = persisted.last_detail;
    record.stale_reason = persisted.stale_reason;
    record.superseded_by = persisted.superseded_by;
    record.shards.reserve(persisted.shards.size());
    for (std::size_t i = 0; i < persisted.shards.size(); ++i) {
      const PersistedShard& shard = persisted.shards[i];
      const ShardDescriptor& descriptor = persisted.request.manifest.shards[i];
      if (!(shard.index == descriptor.index)) {
        return Status::error(ErrorCode::CorruptState,
                             "persisted shard ordering does not match the manifest");
      }
      ShardRecord shard_record;
      shard_record.index = shard.index;
      shard_record.declared_bytes = descriptor.declared_bytes;
      shard_record.declared_digest = descriptor.declared_digest;
      shard_record.path_class = descriptor.path_class;
      shard_record.state = shard.state;
      shard_record.sequence = shard.sequence;
      shard_record.attempt = shard.attempt;
      shard_record.granted_bytes = shard.granted_bytes;
      shard_record.transferred_bytes = shard.transferred_bytes;
      shard_record.verified_bytes = shard.verified_bytes;
      shard_record.observed_digest = shard.observed_digest;
      shard_record.has_observed_digest = shard.has_observed_digest;
      shard_record.source_complete = shard.source_complete;
      shard_record.source_bytes = shard.source_bytes;
      record.shards.push_back(shard_record);
    }
    record.attempts.reserve(persisted.attempts.size());
    for (const PersistedAttempt& attempt : persisted.attempts) {
      AttemptRecord attempt_record;
      attempt_record.id = attempt.id;
      attempt_record.sequence = attempt.sequence;
      attempt_record.shard = attempt.shard;
      attempt_record.wave = attempt.wave;
      attempt_record.outcome = attempt.outcome;
      attempt_record.granted_bytes = attempt.granted_bytes;
      attempt_record.delivered_bytes = attempt.delivered_bytes;
      attempt_record.observed_digest = attempt.observed_digest;
      attempt_record.has_observed_digest = attempt.has_observed_digest;
      attempt_record.granted_at = attempt.granted_at;
      attempt_record.updated_at = attempt.updated_at;
      // Attempts whose outcome was never settled hold the at-risk bytes; the
      // post-pass books exactly those as unproven and releases the rest.
      attempt_record.outstanding =
          attempt_record.outcome == AttemptOutcome::Granted ||
          attempt_record.outcome == AttemptOutcome::InFlight ||
          attempt_record.outcome == AttemptOutcome::DeliveredUnacked;
      if (attempt_record.outstanding) {
        attempt_record.outcome = AttemptOutcome::Ambiguous;
      }
      record.attempts.push_back(attempt_record);
    }
    restored.emplace(record.id, std::move(record));
  }

  impl_->sessions_ = std::move(restored);
  impl_->by_workload_.clear();
  impl_->by_checkpoint_.clear();
  for (auto& entry : impl_->sessions_) {
    impl_->by_workload_[entry.second.request.workload].push_back(entry.first);
    impl_->by_checkpoint_[entry.second.request.checkpoint].push_back(entry.first);
  }
  impl_->accounting_ = snapshot.accounting;
  impl_->commands_processed_ = snapshot.commands_processed;
  impl_->epoch_ = snapshot.epoch;
  impl_->command_index_.clear();
  impl_->command_order_.clear();

  const Nanos at = impl_->now();
  impl_->accounting_.active_attempts = 0;
  for (auto& entry : impl_->sessions_) {
    SessionRecord& session = entry.second;
    if (is_terminal(session.state)) {
      continue;
    }
    impl_->mark_unproven(session, Impl::at_risk_bytes(session));
    Impl::release_attempts(session);
    for (ShardRecord& shard : session.shards) {
      if (shard.state == ShardState::Granted || shard.state == ShardState::InFlight) {
        shard.state = ShardState::Pending;
        shard.sequence = AttemptSequence(0);
        shard.attempt.reset();
        shard.granted_bytes = 0;
      }
    }
    session.state = SessionState::RevalidationRequired;
    session.paused = false;
    if (session.stale_reason.empty()) {
      session.stale_reason = "coordinator restarted: authority must be re-established";
    }
    session.updated_at = at;
    impl_->append_timeline(session, at, "restored: revalidation required");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::RevalidationRequired_, session.id,
                                    ReasonCode::AuthorityStale, session.stale_reason, at});
    }
  }
  // Active-session, class, workload, and outstanding counters are derived from
  // the restored table, never trusted from the file.
  impl_->class_active_.fill(0);
  impl_->workload_active_.clear();
  impl_->terminal_order_.clear();
  impl_->accounting_.active_sessions = 0;
  impl_->accounting_.granted_outstanding_bytes = 0;
  for (auto& entry : impl_->sessions_) {
    SessionRecord& session = entry.second;
    impl_->accounting_.granted_outstanding_bytes += session.outstanding_bytes;
    if (is_active(session.state)) {
      ++impl_->accounting_.active_sessions;
      const std::size_t class_index = static_cast<std::size_t>(session.envelope.isolation);
      if (class_index < impl_->class_active_.size()) {
        ++impl_->class_active_[class_index];
      }
      ++impl_->workload_active_[session.request.workload];
    } else {
      impl_->terminal_order_.push_back(session.id);
    }
  }
  impl_->deadlines_.clear();
  for (const auto& entry : impl_->sessions_) {
    if (!is_terminal(entry.second.state)) {
      impl_->index_deadline(entry.second);
    }
  }
  return Status::success();
}

EngineSnapshot FabricEngine::export_snapshot() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  EngineSnapshot snapshot;
  snapshot.epoch = impl_->epoch_;
  snapshot.policy_generation = impl_->policy_.generation;
  snapshot.topology_generation = impl_->topology_.generation;
  snapshot.sessions.reserve(impl_->sessions_.size());
  std::unordered_set<WorkloadId, StrongIdHash<struct WorkloadIdTag>> seen_workloads;
  for (const auto& entry : impl_->sessions_) {
    const WorkloadId workload = entry.second.request.workload;
    if (seen_workloads.insert(workload).second) {
      snapshot.contract_generations.push_back(
          ContractGenerationRecord{workload, entry.second.request.contract_generation});
    }
  }
  for (const auto& entry : impl_->contracts_) {
    if (seen_workloads.insert(entry.first).second) {
      snapshot.contract_generations.push_back(
          ContractGenerationRecord{entry.first, entry.second.generation});
    }
  }
  for (const auto& entry : impl_->sessions_) {
    const SessionRecord& session = entry.second;
    PersistedSession persisted;
    persisted.session = session.id;
    persisted.request = session.request;
    persisted.state = session.state;
    persisted.evidence = session.evidence;
    persisted.envelope = session.envelope;
    persisted.envelope_sequence = session.envelope_sequence;
    persisted.attempt_counter = session.attempt_counter;
    persisted.timeline = session.timeline;
    persisted.admitted_bytes = session.admitted_bytes;
    persisted.transferred_bytes = session.transferred_bytes;
    persisted.verified_bytes = session.verified_bytes;
    persisted.cancelled_bytes = session.cancelled_bytes;
    persisted.wasted_bytes = session.wasted_bytes;
    persisted.unproven_bytes = session.unproven_bytes;
    persisted.outstanding_bytes = session.outstanding_bytes;
    persisted.active_attempts = session.active_attempts;
    persisted.source_complete = session.source_complete;
    persisted.paused = session.paused;
    persisted.created_at = session.created_at;
    persisted.updated_at = session.updated_at;
    persisted.last_reason = session.last_reason;
    persisted.last_detail = session.last_detail;
    persisted.stale_reason = session.stale_reason;
    persisted.superseded_by = session.superseded_by;
    for (const ShardRecord& shard : session.shards) {
      PersistedShard out;
      out.index = shard.index;
      out.state = shard.state;
      out.sequence = shard.sequence;
      out.granted_bytes = shard.granted_bytes;
      out.transferred_bytes = shard.transferred_bytes;
      out.verified_bytes = shard.verified_bytes;
      out.observed_digest = shard.observed_digest;
      out.has_observed_digest = shard.has_observed_digest;
      out.attempt = shard.attempt;
      out.source_complete = shard.source_complete;
      out.source_bytes = shard.source_bytes;
      persisted.shards.push_back(out);
    }
    for (const AttemptRecord& attempt : session.attempts) {
      PersistedAttempt out;
      out.id = attempt.id;
      out.sequence = attempt.sequence;
      out.shard = attempt.shard;
      out.wave = attempt.wave;
      out.outcome = attempt.outcome;
      out.granted_bytes = attempt.granted_bytes;
      out.delivered_bytes = attempt.delivered_bytes;
      out.observed_digest = attempt.observed_digest;
      out.has_observed_digest = attempt.has_observed_digest;
      out.outstanding = attempt.outstanding;
      out.granted_at = attempt.granted_at;
      out.updated_at = attempt.updated_at;
      persisted.attempts.push_back(out);
    }
    snapshot.sessions.push_back(std::move(persisted));
  }
  snapshot.accounting = impl_->accounting_;
  snapshot.commands_processed = impl_->commands_processed_;
  return snapshot;
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

Result<AdmissionDecision> FabricEngine::submit_session(const SessionRequest& request,
                                                       const CommandFence& fence,
                                                       EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);

  const FenceVerdict fence_verdict =
      validate_fence(fence, FenceContext{impl_->epoch_, impl_->policy_.generation,
                                         impl_->topology_.generation, fence.contract_generation});
  if (!fence_verdict.ok()) {
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::FenceRejected, SessionId{}, fence_verdict.reason,
                                    fence_verdict.status.detail(), at});
    }
    return fence_verdict.status;
  }
  if (!(request.policy_generation == fence.policy_generation)) {
    return Status::error(ErrorCode::StalePolicyGeneration,
                         "request policy generation contradicts the command fence");
  }
  if (!(request.topology_generation == fence.topology_generation)) {
    return Status::error(ErrorCode::StaleTopologyGeneration,
                         "request topology generation contradicts the command fence");
  }
  if (!(request.contract_generation == fence.contract_generation)) {
    return Status::error(ErrorCode::StaleContractGeneration,
                         "request contract generation contradicts the command fence");
  }

  const std::uint64_t fingerprint = impl_->fingerprint_request(request);
  const auto command_it = impl_->command_index_.find(request.command);
  if (command_it != impl_->command_index_.end()) {
    const CommandRecord& record = command_it->second;
    if (record.fingerprint != fingerprint) {
      return Status::error(ErrorCode::ReplayDetected,
                           "command id was used for a different request");
    }
    AdmissionDecision decision = impl_->make_decision(
        record.kind, ReasonCode::DuplicateCommand, "idempotent replay of a decided command",
        record.session, at);
    if (record.has_session) {
      const auto session_it = impl_->sessions_.find(record.session);
      if (session_it != impl_->sessions_.end()) {
        decision.envelope = session_it->second.envelope;
      }
    }
    return decision;
  }

  auto deny = [&](ReasonCode reason, std::string detail) -> Result<AdmissionDecision> {
    ++impl_->accounting_.sessions_denied;
    impl_->remember_command(request.command,
                            CommandRecord{SessionId{}, DecisionKind::Deny, reason, fingerprint, false});
    if (events != nullptr) {
      events->push_back(
          FabricEvent{EventKind::SessionDenied, SessionId{}, reason, detail, at});
    }
    return impl_->make_decision(DecisionKind::Deny, reason, std::move(detail), SessionId{}, at);
  };
  auto defer = [&](ReasonCode reason, std::string detail, Nanos retry_after,
                   std::uint64_t deferred_bytes) -> Result<AdmissionDecision> {
    ++impl_->accounting_.sessions_deferred;
    impl_->accounting_.bytes_deferred += deferred_bytes;
    impl_->remember_command(request.command,
                            CommandRecord{SessionId{}, DecisionKind::Defer, reason, fingerprint, false});
    if (events != nullptr) {
      events->push_back(
          FabricEvent{EventKind::SessionDeferred, SessionId{}, reason, detail, at});
    }
    AdmissionDecision decision =
        impl_->make_decision(DecisionKind::Defer, reason, std::move(detail), SessionId{}, at);
    decision.retry_after = retry_after;
    return decision;
  };

  if (impl_->shutting_down_) {
    return deny(ReasonCode::FabricShuttingDown, "fabric is shutting down");
  }
  const auto contract_it = impl_->contracts_.find(request.workload);
  if (contract_it == impl_->contracts_.end()) {
    return deny(ReasonCode::UnknownWorkload, "workload contract is not configured");
  }
  const WorkloadContract& contract = contract_it->second;
  if (!(request.contract_generation == contract.generation)) {
    return deny(ReasonCode::ContractGenerationStale,
                "request carries a workload-contract generation that is not current");
  }
  const Status manifest_status = validate_manifest(request.manifest, impl_->limits_);
  if (!manifest_status.ok()) {
    return deny(ReasonCode::ManifestInvalid, manifest_status.to_string());
  }
  if (!(request.manifest.checkpoint == request.checkpoint) ||
      !(request.manifest.generation == request.checkpoint_generation) ||
      !(request.manifest.workload == request.workload) ||
      !(request.manifest.contract_generation == request.contract_generation)) {
    return deny(ReasonCode::ManifestMismatch,
                "manifest identity contradicts the request envelope");
  }

  // Isolation: traffic is never admitted into a class laxer than its contract.
  const IsolationClass requested_class = request.requested_isolation;
  const IsolationClass isolation =
      isolation_rank(requested_class) <= isolation_rank(contract.isolation) ? requested_class
                                                                           : contract.isolation;
  const IsolationEnvelopeConfig* envelope_config = find_envelope(impl_->policy_, isolation);
  if (envelope_config == nullptr) {
    return deny(ReasonCode::Internal, "isolation class has no configured envelope");
  }

  const std::optional<PathClassId> default_path =
      default_path_class_for(impl_->topology_, request.destination);
  if (!default_path.has_value()) {
    return deny(ReasonCode::DestinationNotPermitted,
                "topology has no path class for the requested destination");
  }
  PathClassId path_id = default_path.value();
  for (const ShardDescriptor& shard : request.manifest.shards) {
    if (shard.path_class.value() == 0) {
      continue;
    }
    const PathClass* path = find_path_class(impl_->topology_, shard.path_class);
    if (path == nullptr || path->destination != request.destination) {
      return deny(ReasonCode::DestinationNotPermitted,
                  "shard names a path class that is absent or serves another destination");
    }
  }
  const PathClass* path = find_path_class(impl_->topology_, path_id);
  if (path == nullptr) {
    return deny(ReasonCode::DestinationNotPermitted, "topology path class is not resolvable");
  }

  // Existing sessions for this checkpoint: duplicate, stale, or superseded.
  std::vector<SessionRecord*> supersede_targets;
  const auto checkpoint_it = impl_->by_checkpoint_.find(request.checkpoint);
  if (checkpoint_it != impl_->by_checkpoint_.end()) {
    for (const SessionId& id : checkpoint_it->second) {
      const auto session_it = impl_->sessions_.find(id);
      if (session_it == impl_->sessions_.end()) {
        continue;
      }
      SessionRecord& existing = session_it->second;
      // A generation older than one this coordinator has already seen is stale
      // whether or not the newer session is still active: replaying it would
      // re-open authority for superseded checkpoint traffic.
      if (request.checkpoint_generation < existing.request.checkpoint_generation) {
        return deny(ReasonCode::CheckpointGenerationStale,
                    "a newer checkpoint generation has already been admitted for this checkpoint");
      }
      if (!is_active(existing.state)) {
        continue;
      }
      if (existing.request.checkpoint_generation == request.checkpoint_generation) {
        if (manifests_equivalent(existing.request.manifest, request.manifest)) {
          AdmissionDecision decision = impl_->make_decision(
              DecisionKind::Admit, ReasonCode::DuplicateCommand,
              "identical checkpoint generation already has an active session", existing.id, at);
          decision.envelope = existing.envelope;
          impl_->remember_command(request.command, CommandRecord{existing.id, DecisionKind::Admit,
                                                                 ReasonCode::Admitted, fingerprint,
                                                                 true});
          return decision;
        }
        return deny(ReasonCode::ManifestMismatch,
                    "checkpoint generation already has an active session with a different manifest");
      }
      supersede_targets.push_back(&existing);
    }
  }
  if (!supersede_targets.empty() && !contract.allow_supersession) {
    return deny(ReasonCode::SupersessionDeniedByPolicy,
                "workload contract forbids superseding an active checkpoint generation");
  }
  if (supersede_targets.size() > impl_->limits_.max_supersession_chain) {
    return deny(ReasonCode::ResourceLimit, "supersession chain exceeds the configured bound");
  }
  if (request.manifest.total_bytes > impl_->policy_.max_session_bytes) {
    return deny(ReasonCode::CheckpointTooLarge, "checkpoint exceeds the per-session byte bound");
  }

  const std::uint32_t available_slots =
      impl_->accounting_.active_sessions < impl_->policy_.max_sessions
          ? impl_->policy_.max_sessions - impl_->accounting_.active_sessions
          : 0;
  if (available_slots == 0) {
    return defer(ReasonCode::FabricSessionLimit, "fabric session bound reached",
                 at + impl_->policy_.defer_horizon_ns, request.manifest.total_bytes);
  }
  const std::uint32_t workload_active = impl_->workload_active(request.workload);
  if (workload_active >= contract.max_in_flight_sessions) {
    return defer(ReasonCode::SessionLimitPerWorkload,
                 "workload session bound reached", at + impl_->policy_.defer_horizon_ns,
                 request.manifest.total_bytes);
  }
  if (impl_->class_active(isolation) >= envelope_config->max_in_flight_sessions) {
    return defer(ReasonCode::ClassCeilingSaturated, "isolation-class session bound reached",
                 at + impl_->policy_.defer_horizon_ns, request.manifest.total_bytes);
  }

  const Impl::RatePlan rate_plan =
      impl_->plan_rate(request, contract, *envelope_config, *path, at);
  if (!rate_plan.ok) {
    if (rate_plan.reason == ReasonCode::RequestedRateUnsupported ||
        rate_plan.reason == ReasonCode::DeadlineUnreachable) {
      return deny(rate_plan.reason, rate_plan.detail);
    }
    return defer(rate_plan.reason, rate_plan.detail,
                 rate_plan.retry_after.value_or(at + impl_->policy_.defer_horizon_ns),
                 request.manifest.total_bytes);
  }

  const std::uint32_t wave_width = std::max<std::uint32_t>(
      1, std::min<std::uint32_t>(
             std::min(contract.max_shards_per_wave, impl_->policy_.max_wave_width),
             static_cast<std::uint32_t>(request.manifest.shards.size())));
  const Nanos horizon = request.deadline_horizon_ns > 0 ? request.deadline_horizon_ns
                                                        : contract.deadline_budget_ns;
  const Nanos deadline_target = at + horizon;
  const std::uint64_t burst_bytes =
      std::max<std::uint64_t>(rate_plan.rate_bps / 10U, static_cast<std::uint64_t>(64U * 1024U));

  SessionRecord session;
  session.id = SessionId(Uuid128::random(impl_->id_factory_));
  session.request = request;
  session.state = SessionState::Admitted;
  session.envelope_sequence = 1;
  session.envelope = impl_->build_envelope(request, session.id, isolation, path_id,
                                           rate_plan.rate_bps, burst_bytes, wave_width, at,
                                           deadline_target, session.envelope_sequence);
  session.reserved_path = path_id;
  session.reserved_rate_bps = rate_plan.rate_bps;
  session.admitted_bytes = request.manifest.total_bytes;
  session.outstanding_bytes = request.manifest.total_bytes;
  session.created_at = at;
  session.updated_at = at;
  session.last_reason = ReasonCode::Admitted;
  session.last_detail = "admitted";
  session.shards.reserve(request.manifest.shards.size());
  for (const ShardDescriptor& shard : request.manifest.shards) {
    ShardRecord record;
    record.index = shard.index;
    record.declared_bytes = shard.declared_bytes;
    record.declared_digest = shard.declared_digest;
    record.path_class = shard.path_class.value() == 0 ? path_id : shard.path_class;
    session.shards.push_back(record);
  }
  impl_->append_timeline(session, at,
                         "admitted class=" + std::string(to_string(isolation)) +
                             " rate=" + std::to_string(rate_plan.rate_bps) + "B/s waves=" +
                             std::to_string(session.envelope.waves.size()));

  if (!impl_->shaper_.reserve_path_rate(path_id, rate_plan.rate_bps)) {
    return deny(ReasonCode::ResourceLimit, "path class reservation overflow");
  }

  std::vector<SessionId> superseded;
  for (SessionRecord* target : supersede_targets) {
    impl_->apply_supersession(*target, session.id, at, events, &superseded);
  }

  impl_->accounting_.bytes_admitted += request.manifest.total_bytes;
  impl_->accounting_.granted_outstanding_bytes += request.manifest.total_bytes;
  ++impl_->accounting_.sessions_admitted;
  impl_->adjust_active(session, +1);
  impl_->by_workload_[request.workload].push_back(session.id);
  impl_->by_checkpoint_[request.checkpoint].push_back(session.id);
  const SessionId session_id = session.id;
  impl_->index_deadline(session);
  impl_->sessions_.emplace(session_id, std::move(session));
  impl_->remember_command(request.command,
                          CommandRecord{session_id, DecisionKind::Admit, ReasonCode::Admitted,
                                        fingerprint, true});

  AdmissionDecision decision = impl_->make_decision(
      DecisionKind::Admit, ReasonCode::Admitted,
      superseded.empty() ? "admitted" : "admitted; superseded an older checkpoint generation",
      session_id, at);
  decision.envelope = impl_->sessions_[session_id].envelope;
  decision.superseded = superseded;
  if (events != nullptr) {
    events->push_back(
        FabricEvent{EventKind::SessionAdmitted, session_id, ReasonCode::Admitted, "admitted", at});
  }
  return decision;
}

Result<AdmissionDecision> FabricEngine::revalidate_session(SessionId session_id,
                                                           const CommandFence& fence,
                                                           EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);

  const auto session_it = impl_->sessions_.find(session_id);
  if (session_it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known to this incarnation");
  }
  SessionRecord& session = session_it->second;
  const auto contract_it = impl_->contracts_.find(session.request.workload);
  const WorkloadContractGeneration contract_generation =
      contract_it == impl_->contracts_.end() ? WorkloadContractGeneration(0)
                                             : contract_it->second.generation;
  const FenceVerdict fence_verdict =
      validate_fence(fence, FenceContext{impl_->epoch_, impl_->policy_.generation,
                                         impl_->topology_.generation, contract_generation});
  if (!fence_verdict.ok()) {
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::FenceRejected, session_id, fence_verdict.reason,
                                    fence_verdict.status.detail(), at});
    }
    return fence_verdict.status;
  }
  const Status checkpoint_status = impl_->validate_checkpoint_generation(session, fence);
  if (!checkpoint_status.ok()) {
    return checkpoint_status;
  }
  if (session.state != SessionState::RevalidationRequired && session.state != SessionState::Deferred) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "session does not require revalidation");
  }
  if (impl_->shutting_down_) {
    return Status::error(ErrorCode::ShuttingDown, "fabric is shutting down");
  }
  if (contract_it == impl_->contracts_.end()) {
    session.state = SessionState::Failed;
    session.stale_reason.clear();
    impl_->settle_terminal(session, SessionState::Failed, ReasonCode::UnknownWorkload,
                           "workload contract is no longer configured", at);
    ++impl_->accounting_.sessions_failed;
    return impl_->make_decision(DecisionKind::Deny, ReasonCode::UnknownWorkload,
                                "workload contract is no longer configured", session_id, at);
  }

  const IsolationEnvelopeConfig* envelope_config =
      find_envelope(impl_->policy_, session.envelope.isolation);
  const PathClassId path_id = session.envelope.path_class.value_or(PathClassId(0));
  const PathClass* path = find_path_class(impl_->topology_, path_id);
  if (envelope_config == nullptr || path == nullptr) {
    return impl_->make_decision(DecisionKind::Defer, ReasonCode::DestinationNotPermitted,
                                "current topology no longer serves this session's path",
                                session_id, at);
  }
  const Impl::RatePlan rate_plan =
      impl_->plan_rate(session.request, contract_it->second, *envelope_config, *path, at);
  if (!rate_plan.ok) {
    if (rate_plan.reason == ReasonCode::RequestedRateUnsupported ||
        rate_plan.reason == ReasonCode::DeadlineUnreachable) {
      session.state = SessionState::Failed;
      session.stale_reason.clear();
      impl_->mark_unproven(session, session.outstanding_bytes);
      impl_->settle_terminal(session, SessionState::Failed, rate_plan.reason, rate_plan.detail, at);
      ++impl_->accounting_.sessions_failed;
      return impl_->make_decision(DecisionKind::Deny, rate_plan.reason, rate_plan.detail, session_id,
                                  at);
    }
    session.state = SessionState::Deferred;
    session.stale_reason = "revalidation deferred: " + rate_plan.detail;
    session.updated_at = at;
    AdmissionDecision decision = impl_->make_decision(
        DecisionKind::Defer, rate_plan.reason, rate_plan.detail, session_id, at);
    decision.retry_after =
        rate_plan.retry_after.value_or(at + impl_->policy_.defer_horizon_ns);
    return decision;
  }

  impl_->release_path_reservation(session);
  if (!impl_->shaper_.reserve_path_rate(path_id, rate_plan.rate_bps)) {
    return Status::error(ErrorCode::ResourceExhausted, "path class reservation overflow");
  }
  session.reserved_path = path_id;
  session.reserved_rate_bps = rate_plan.rate_bps;
  ++session.envelope_sequence;
  const std::uint32_t wave_width = std::max<std::uint32_t>(
      1, std::min<std::uint32_t>(
             std::min(contract_it->second.max_shards_per_wave, impl_->policy_.max_wave_width),
             static_cast<std::uint32_t>(session.shards.size())));
  const Nanos horizon = session.request.deadline_horizon_ns > 0
                            ? session.request.deadline_horizon_ns
                            : contract_it->second.deadline_budget_ns;
  const std::uint64_t burst_bytes = std::max<std::uint64_t>(
      rate_plan.rate_bps / 10U, static_cast<std::uint64_t>(64U * 1024U));
  session.envelope = impl_->build_envelope(session.request, session.id, session.envelope.isolation,
                                           path_id, rate_plan.rate_bps, burst_bytes, wave_width, at,
                                           at + horizon, session.envelope_sequence);
  session.state = SessionState::Admitted;
  session.paused = false;
  session.stale_reason.clear();
  session.updated_at = at;
  session.last_reason = ReasonCode::Admitted;
  session.last_detail = "revalidated";
  impl_->index_deadline(session);
  impl_->append_timeline(session, at, "revalidated envelope_sequence=" +
                                         std::to_string(session.envelope_sequence));
  AdmissionDecision decision = impl_->make_decision(
      DecisionKind::Admit, ReasonCode::Admitted, "revalidated under current authority", session_id,
      at);
  decision.envelope = session.envelope;
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::SessionAdmitted, session_id, ReasonCode::Admitted,
                                  "revalidated", at});
  }
  return decision;
}

// ---------------------------------------------------------------------------
// Lifecycle operations
// ---------------------------------------------------------------------------

Status FabricEngine::pause_session(SessionId session_id, const CommandFence& fence,
                                   std::string reason, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  const Status workload_status = impl_->validate_workload_fence(session, fence);
  if (!workload_status.ok()) {
    return workload_status;
  }
  if (is_terminal(session.state)) {
    return Status::error(ErrorCode::InvalidStateTransition, "session is already terminal");
  }
  if (session.state == SessionState::RevalidationRequired) {
    return Status::error(ErrorCode::RevalidationRequired,
                         "session must be revalidated before it can be paused");
  }
  if (session.paused) {
    return Status::error(ErrorCode::AlreadyExists, "session is already paused");
  }
  session.paused = true;
  session.paused_from = session.state;
  session.state = SessionState::Paused;
  session.updated_at = at;
  impl_->settle_reason(session, ReasonCode::Admitted, std::move(reason));
  impl_->append_timeline(session, at, "paused");
  if (events != nullptr) {
    events->push_back(
        FabricEvent{EventKind::SessionPaused, session_id, ReasonCode::Admitted, "paused", at});
  }
  return Status::success();
}

Status FabricEngine::resume_session(SessionId session_id, const CommandFence& fence,
                                    EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  const Status workload_status = impl_->validate_workload_fence(session, fence);
  if (!workload_status.ok()) {
    return workload_status;
  }
  if (!session.paused) {
    return Status::error(ErrorCode::InvalidStateTransition, "session is not paused");
  }
  session.paused = false;
  session.state = session.paused_from;
  session.updated_at = at;
  impl_->append_timeline(session, at, "resumed");
  if (events != nullptr) {
    events->push_back(
        FabricEvent{EventKind::SessionResumed, session_id, ReasonCode::Admitted, "resumed", at});
  }
  return Status::success();
}

Status FabricEngine::cancel_session(SessionId session_id, const CommandFence& fence,
                                    ReasonCode reason, std::string detail, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  if (is_terminal(session.state)) {
    return Status::error(ErrorCode::InvalidStateTransition, "session is already terminal");
  }
  impl_->settle_outstanding_as_cancelled(session);
  impl_->settle_terminal(session, SessionState::Cancelled, reason, std::move(detail), at);
  ++impl_->accounting_.sessions_cancelled;
  impl_->append_timeline(session, at, std::string("cancelled reason=") + to_string(reason));
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::SessionCancelled, session_id, reason, "cancelled", at});
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Wave credit
// ---------------------------------------------------------------------------

Result<WaveOutcome> FabricEngine::request_wave(SessionId session_id, ShardIndex shard_index,
                                               const CommandFence& fence, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);

  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  const Status workload_status = impl_->validate_workload_fence(session, fence);
  if (!workload_status.ok()) {
    return workload_status;
  }
  const Status checkpoint_status = impl_->validate_checkpoint_generation(session, fence);
  if (!checkpoint_status.ok()) {
    return checkpoint_status;
  }
  if (session.state == SessionState::RevalidationRequired || session.state == SessionState::Deferred) {
    return Status::error(ErrorCode::RevalidationRequired,
                         "session must be revalidated before requesting credit");
  }
  if (session.paused || session.state == SessionState::Paused) {
    return Status::error(ErrorCode::Deferred, "session is paused");
  }
  if (is_terminal(session.state)) {
    if (session.superseded_by.has_value()) {
      return Status::error(ErrorCode::Superseded,
                           "session was superseded by a newer checkpoint generation");
    }
    return Status::error(ErrorCode::InvalidStateTransition,
                         "session is terminal and cannot be granted credit");
  }
  if (at >= session.envelope.deadline_target) {
    return Status::error(ErrorCode::DeadlineUnreachable, "checkpoint deadline has elapsed");
  }
  if (impl_->accounting_.active_attempts >= impl_->policy_.max_attempts_in_flight) {
    WaveOutcome outcome;
    outcome.reason = ReasonCode::ResourceLimit;
    outcome.detail = "fabric attempt bound reached";
    outcome.retry_after = at + impl_->policy_.defer_horizon_ns;
    outcome.decided_at = at;
    return outcome;
  }
  const std::optional<std::size_t> position = Impl::shard_position(session, shard_index);
  if (!position.has_value()) {
    return Status::error(ErrorCode::NotFound, "session manifest has no such shard");
  }
  ShardRecord& shard = session.shards[position.value()];
  if (shard.state == ShardState::Verified || shard.state == ShardState::Transferred) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "shard already reached its transfer target");
  }
  if (shard.state == ShardState::Ambiguous) {
    return Status::error(ErrorCode::AmbiguousOutcome,
                         "shard outcome is ambiguous; resend the shard is refused until it is "
                         "resolved by verification or cancellation");
  }
  if (fence.attempt_sequence.has_value() && shard.attempt.has_value() &&
      !(fence.attempt_sequence.value() == shard.sequence)) {
    return Status::error(ErrorCode::StaleAttempt,
                         "command carries an attempt sequence older than the shard's attempt");
  }
  // An unsettled attempt still holds authority for this shard. Granting a
  // second attempt on top of it would leave that authority unaccounted for, so
  // the caller must settle it (evidence or an ambiguity report) first.
  if (shard.attempt.has_value()) {
    const AttemptRecord* previous = impl_->find_attempt(session, shard.attempt.value());
    if (previous != nullptr && previous->outstanding) {
      return Status::error(
          ErrorCode::AmbiguousOutcome,
          "shard has an unsettled attempt; report its evidence or mark it ambiguous first");
    }
  }

  const std::uint64_t remaining =
      shard.declared_bytes > shard.transferred_bytes ? shard.declared_bytes - shard.transferred_bytes
                                                     : 0;
  if (remaining == 0) {
    return Status::error(ErrorCode::InvalidStateTransition, "shard has no bytes left to grant");
  }
  // A grant never exceeds the credit the fabric actually holds, so admitted
  // throughput is bounded by the fabric's own token bucket rather than by the
  // sender's willingness to pace itself.
  const std::uint64_t useful = std::min<std::uint64_t>(remaining, kMinGrantChunk);
  const std::uint64_t available =
      impl_->shaper_.class_tokens_at(session.envelope.isolation, at);
  if (available < useful) {
    WaveOutcome outcome;
    outcome.reason = ReasonCode::ClassCeilingSaturated;
    outcome.detail = "isolation-class credit is below the minimum useful grant";
    outcome.retry_after =
        at + impl_->shaper_.class_time_until_at(session.envelope.isolation, useful, at);
    outcome.decided_at = at;
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::SessionDeferred, session_id, outcome.reason,
                                    outcome.detail, at});
    }
    return outcome;
  }
  const std::uint64_t chunk =
      std::min<std::uint64_t>(std::min<std::uint64_t>(remaining, kMaxGrantChunk), available);

  const detail::ShaperVerdict verdict = impl_->shaper_.try_consume(
      session.envelope.isolation, session.request.workload, chunk, at);
  if (!verdict.admitted) {
    WaveOutcome outcome;
    outcome.reason = verdict.reason;
    outcome.detail = verdict.detail;
    outcome.retry_after = verdict.retry_after;
    outcome.decided_at = at;
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::SessionDeferred, session_id, verdict.reason,
                                    verdict.detail, at});
    }
    return outcome;
  }

  WaveGrant grant;
  grant.session = session_id;
  grant.attempt = TransferAttemptId(Uuid128::random(impl_->id_factory_));
  grant.sequence = AttemptSequence(++session.attempt_counter);
  grant.shard = shard_index;
  grant.wave = Impl::wave_for_shard(session.envelope, shard_index).value_or(WaveIndex(0));
  grant.max_bytes = chunk;
  grant.rate_bps = session.envelope.rate_bps;
  grant.burst_bytes = session.envelope.burst_bytes;
  grant.issued_at = at;
  grant.expires_at = at + kNanosPerSecond;
  grant.epoch = impl_->epoch_;

  AttemptRecord attempt;
  attempt.id = grant.attempt;
  attempt.sequence = grant.sequence;
  attempt.shard = shard_index;
  attempt.wave = grant.wave;
  attempt.outcome = AttemptOutcome::InFlight;
  attempt.granted_bytes = chunk;
  attempt.outstanding = true;
  attempt.granted_at = at;
  attempt.updated_at = at;
  session.attempts.push_back(attempt);
  if (session.attempts.size() > impl_->timeline_bound()) {
    session.attempts.erase(session.attempts.begin(),
                           session.attempts.begin() + static_cast<std::ptrdiff_t>(
                                                        session.attempts.size() -
                                                        impl_->timeline_bound()));
  }
  shard.state = ShardState::InFlight;
  shard.sequence = grant.sequence;
  shard.attempt = grant.attempt;
  shard.granted_bytes = chunk;
  ++session.active_attempts;
  ++impl_->accounting_.active_attempts;
  if (session.state == SessionState::Admitted || session.state == SessionState::SourceComplete) {
    session.state = SessionState::Transferring;
  }
  session.updated_at = at;
  impl_->append_timeline(session, at, "grant shard=" + shard_index.to_string() +
                                         " bytes=" + std::to_string(chunk) +
                                         " attempt=" + grant.attempt.to_string());

  WaveOutcome outcome;
  outcome.granted = true;
  outcome.grant = grant;
  outcome.decided_at = at;
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::WaveGranted, session_id, ReasonCode::Admitted,
                                  "granted " + std::to_string(chunk) + " bytes", at});
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

Status FabricEngine::report_source_complete(const SourceCompleteEvidence& evidence,
                                            const CommandFence& fence, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(evidence.session);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  const Status workload_status = impl_->validate_workload_fence(session, fence);
  if (!workload_status.ok()) {
    return workload_status;
  }
  if (is_terminal(session.state)) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "session is terminal; source-complete evidence is stale");
  }
  const std::optional<std::size_t> position = Impl::shard_position(session, evidence.shard);
  if (!position.has_value()) {
    return Status::error(ErrorCode::NotFound, "session manifest has no such shard");
  }
  ShardRecord& shard = session.shards[position.value()];
  if (evidence.source_bytes > shard.declared_bytes) {
    return Status::error(ErrorCode::ImpossibleState,
                         "source-complete evidence exceeds the declared shard size");
  }
  if (shard.source_complete && shard.source_bytes != evidence.source_bytes) {
    return Status::error(ErrorCode::ImpossibleState,
                         "source-complete evidence contradicts a previous report");
  }
  shard.source_complete = true;
  shard.source_bytes = evidence.source_bytes;
  if (shard.state == ShardState::Pending || shard.state == ShardState::Granted) {
    shard.state = ShardState::InFlight;
  }
  bool all_source_complete = true;
  for (const ShardRecord& candidate : session.shards) {
    if (!candidate.source_complete) {
      all_source_complete = false;
      break;
    }
  }
  session.source_complete = all_source_complete;
  session.updated_at = at;
  const bool was_terminal = is_terminal(session.state);
  impl_->recompute_progress(session, at);
  if (!was_terminal && session.state == SessionState::TrafficSessionComplete) {
    impl_->append_timeline(session, at, "completed");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::SessionCompleted, session.id, ReasonCode::Admitted,
                                    "traffic session complete", at});
    }
  }
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::SourceCompleteObserved, session.id,
                                  ReasonCode::Admitted,
                                  "source complete for shard " + evidence.shard.to_string(), at});
  }
  return Status::success();
}

Status FabricEngine::report_transfer(const TransferEvidence& evidence, const CommandFence& fence,
                                     EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(evidence.session);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  const Status workload_status = impl_->validate_workload_fence(session, fence);
  if (!workload_status.ok()) {
    return workload_status;
  }
  if (is_terminal(session.state)) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "session is terminal; transfer evidence is stale");
  }
  const std::optional<std::size_t> position = Impl::shard_position(session, evidence.shard);
  if (!position.has_value()) {
    return Status::error(ErrorCode::NotFound, "session manifest has no such shard");
  }
  ShardRecord& shard = session.shards[position.value()];
  if (!shard.attempt.has_value() || !(shard.attempt.value() == evidence.attempt)) {
    return Status::error(ErrorCode::StaleAttempt,
                         "transfer evidence names an attempt that is not current for this shard");
  }
  AttemptRecord* attempt = impl_->find_attempt(session, evidence.attempt);
  if (attempt == nullptr) {
    return Status::error(ErrorCode::NotFound, "attempt is not known");
  }
  if (!(attempt->sequence == evidence.sequence)) {
    return Status::error(ErrorCode::StaleAttempt,
                         "transfer evidence carries a stale attempt sequence");
  }
  switch (attempt->outcome) {
    case AttemptOutcome::Ambiguous:
      return Status::error(ErrorCode::AmbiguousOutcome,
                           "attempt outcome is already recorded as ambiguous");
    case AttemptOutcome::Failed:
      return Status::error(ErrorCode::InvalidStateTransition,
                           "attempt already failed; its evidence is stale");
    case AttemptOutcome::Released:
    case AttemptOutcome::Superseded:
      return Status::error(ErrorCode::StaleEvidence,
                           "attempt was released or superseded; its evidence is stale");
    case AttemptOutcome::Granted:
    case AttemptOutcome::InFlight:
    case AttemptOutcome::DeliveredUnacked:
    case AttemptOutcome::DeliveredAcked:
    case AttemptOutcome::Verified:
      break;
  }
  if (evidence.arrived_bytes > attempt->granted_bytes) {
    return Status::error(ErrorCode::ImpossibleState,
                         "transfer evidence exceeds the granted byte budget");
  }
  if (attempt->delivered_bytes > evidence.arrived_bytes) {
    return Status::error(ErrorCode::ImpossibleState,
                         "transfer evidence would reduce delivered bytes for this attempt");
  }
  const std::uint64_t newly_delivered = evidence.arrived_bytes - attempt->delivered_bytes;
  attempt->delivered_bytes = evidence.arrived_bytes;
  attempt->observed_digest = evidence.arrived_digest;
  attempt->has_observed_digest = true;
  attempt->updated_at = at;
  if (evidence.sink_acknowledged) {
    if (newly_delivered > session.outstanding_bytes) {
      return Status::error(ErrorCode::ImpossibleState,
                           "transfer evidence exceeds the session's outstanding authority");
    }
    attempt->outcome = AttemptOutcome::DeliveredAcked;
    attempt->outstanding = false;
    session.outstanding_bytes =
        newly_delivered > session.outstanding_bytes ? 0 : session.outstanding_bytes - newly_delivered;
    impl_->accounting_.granted_outstanding_bytes -=
        std::min(newly_delivered, impl_->accounting_.granted_outstanding_bytes);
    session.transferred_bytes += newly_delivered;
    impl_->accounting_.bytes_transferred += newly_delivered;
    shard.transferred_bytes += newly_delivered;
    shard.observed_digest = evidence.arrived_digest;
    shard.has_observed_digest = true;
    if (session.active_attempts > 0) {
      --session.active_attempts;
      --impl_->accounting_.active_attempts;
    }
    if (shard.transferred_bytes >= shard.declared_bytes &&
        shard.state != ShardState::Verified) {
      shard.state = ShardState::Transferred;
    }
  } else {
    // Bytes seen arriving without a sink acknowledgement: recorded, but never
    // counted as transferred and never treated as success.
    attempt->outcome = AttemptOutcome::DeliveredUnacked;
  }
  const bool was_terminal = is_terminal(session.state);
  impl_->recompute_progress(session, at);
  if (!was_terminal && session.state == SessionState::TrafficSessionComplete) {
    impl_->append_timeline(session, at, "completed");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::SessionCompleted, session.id, ReasonCode::Admitted,
                                    "traffic session complete", at});
    }
  }
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::TransferObserved, session.id, ReasonCode::Admitted,
                                  evidence.sink_acknowledged
                                      ? "transfer acknowledged by sink"
                                      : "bytes observed without sink acknowledgement",
                                  at});
  }
  return Status::success();
}

Status FabricEngine::report_verification(const VerificationEvidence& evidence,
                                         const CommandFence& fence, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(evidence.session);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  const Status workload_status = impl_->validate_workload_fence(session, fence);
  if (!workload_status.ok()) {
    return workload_status;
  }
  if (is_terminal(session.state)) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "session is terminal; verification evidence is stale");
  }
  const std::optional<std::size_t> position = Impl::shard_position(session, evidence.shard);
  if (!position.has_value()) {
    return Status::error(ErrorCode::NotFound, "session manifest has no such shard");
  }
  ShardRecord& shard = session.shards[position.value()];
  if (!shard.attempt.has_value() || !(shard.attempt.value() == evidence.attempt)) {
    return Status::error(ErrorCode::StaleAttempt,
                         "verification evidence names an attempt that is not current");
  }
  AttemptRecord* attempt = impl_->find_attempt(session, evidence.attempt);
  if (attempt == nullptr || !(attempt->sequence == evidence.sequence)) {
    return Status::error(ErrorCode::StaleAttempt,
                         "verification evidence carries a stale attempt sequence");
  }
  const bool acked = attempt->outcome == AttemptOutcome::DeliveredAcked ||
                     attempt->outcome == AttemptOutcome::Verified;
  if (!acked && evidence.outcome == VerificationEvidence::Outcome::Verified) {
    return Status::error(ErrorCode::StaleEvidence,
                         "verification claims success for bytes the fabric never saw arrive");
  }

  switch (evidence.outcome) {
    case VerificationEvidence::Outcome::Verified: {
      if (evidence.verified_bytes != shard.declared_bytes) {
        shard.state = ShardState::Failed;
        attempt->outcome = AttemptOutcome::Failed;
        impl_->settle_terminal(session, SessionState::Failed, ReasonCode::VerificationMismatch,
                               "verified byte count does not match the declared shard size", at);
        ++impl_->accounting_.sessions_failed;
        return Status::error(ErrorCode::VerificationMismatch,
                             "verified byte count does not match the declared shard size");
      }
      if (!shard.declared_digest.is_zero() && !(evidence.verified_digest == shard.declared_digest)) {
        shard.state = ShardState::Failed;
        attempt->outcome = AttemptOutcome::Failed;
        impl_->settle_terminal(session, SessionState::Failed, ReasonCode::VerificationMismatch,
                               "destination digest does not match the declared digest", at);
        ++impl_->accounting_.sessions_failed;
        if (events != nullptr) {
          events->push_back(FabricEvent{EventKind::VerificationObserved, session.id,
                                        ReasonCode::VerificationMismatch,
                                        "digest mismatch at destination", at});
        }
        return Status::error(ErrorCode::VerificationMismatch,
                             "destination digest does not match the declared digest");
      }
      const std::uint64_t previously_verified = shard.verified_bytes;
      shard.verified_bytes = evidence.verified_bytes;
      shard.observed_digest = evidence.verified_digest;
      shard.has_observed_digest = true;
      shard.state = ShardState::Verified;
      attempt->outcome = AttemptOutcome::Verified;
      const std::uint64_t delta = evidence.verified_bytes > previously_verified
                                      ? evidence.verified_bytes - previously_verified
                                      : 0;
      session.verified_bytes += delta;
      impl_->accounting_.bytes_verified += delta;
      break;
    }
    case VerificationEvidence::Outcome::DigestMismatch: {
      shard.state = ShardState::Failed;
      attempt->outcome = AttemptOutcome::Failed;
      impl_->settle_terminal(session, SessionState::Failed, ReasonCode::VerificationMismatch,
                             "destination reported a digest mismatch", at);
      ++impl_->accounting_.sessions_failed;
      if (events != nullptr) {
        events->push_back(FabricEvent{EventKind::VerificationObserved, session.id,
                                      ReasonCode::VerificationMismatch, "digest mismatch", at});
      }
      return Status::success();
    }
    case VerificationEvidence::Outcome::Truncated: {
      // The attempt failed; the shard becomes transferable again. Bytes already
      // counted as transferred stay counted as transferred, and are marked
      // wasted because they cannot serve this session's target.
      shard.state = ShardState::Pending;
      shard.sequence = AttemptSequence(0);
      attempt->outcome = AttemptOutcome::Failed;
      if (attempt->outstanding) {
        attempt->outstanding = false;
        if (session.active_attempts > 0) {
          --session.active_attempts;
          --impl_->accounting_.active_attempts;
        }
      }
      // Bytes that already arrived but cannot serve the target become wasted;
      // the shard's authority is re-opened so a retry is charged to the same
      // admission rather than to a new one.
      const std::uint64_t already = shard.transferred_bytes;
      shard.transferred_bytes = 0;
      shard.granted_bytes = 0;
      shard.attempt.reset();
      session.transferred_bytes =
          session.transferred_bytes > already ? session.transferred_bytes - already : 0;
      session.wasted_bytes += already;
      impl_->accounting_.bytes_transferred -= std::min(already, impl_->accounting_.bytes_transferred);
      impl_->accounting_.bytes_wasted += already;
      // The retry is a fresh authorisation: the bytes that were wasted are
      // already accounted, so re-opening authority for the same target must be
      // admitted again rather than counted twice under the original grant.
      session.outstanding_bytes += already;
      session.admitted_bytes += already;
      impl_->accounting_.granted_outstanding_bytes += already;
      impl_->accounting_.bytes_admitted += already;
      session.updated_at = at;
      impl_->append_timeline(session, at, "shard " + evidence.shard.to_string() +
                                             " truncated; retry permitted");
      impl_->recompute_progress(session, at);
      if (events != nullptr) {
        events->push_back(FabricEvent{EventKind::VerificationObserved, session.id,
                                      ReasonCode::VerificationMismatch,
                                      "truncated transfer; shard re-armed", at});
      }
      return Status::success();
    }
    case VerificationEvidence::Outcome::Ambiguous:
    case VerificationEvidence::Outcome::Rejected: {
      shard.state = ShardState::Ambiguous;
      attempt->outcome = AttemptOutcome::Ambiguous;
      attempt->outstanding = false;
      if (session.active_attempts > 0) {
        --session.active_attempts;
        --impl_->accounting_.active_attempts;
      }
      const std::uint64_t unproven =
          attempt->granted_bytes > attempt->delivered_bytes
              ? attempt->granted_bytes - attempt->delivered_bytes
              : 0;
      impl_->mark_unproven(session, unproven);
      session.updated_at = at;
      impl_->settle_reason(session, ReasonCode::AmbiguousSinkOutcome,
                           "destination outcome is ambiguous");
      impl_->append_timeline(session, at, "shard " + evidence.shard.to_string() +
                                             " outcome ambiguous; unproven bytes recorded");
      impl_->recompute_progress(session, at);
      if (events != nullptr) {
        events->push_back(FabricEvent{EventKind::AmbiguityRecorded, session.id,
                                      ReasonCode::AmbiguousSinkOutcome,
                                      "destination outcome is ambiguous", at});
      }
      return Status::success();
    }
  }

  const bool was_terminal = is_terminal(session.state);
  impl_->recompute_progress(session, at);
  if (!was_terminal && session.state == SessionState::TrafficSessionComplete) {
    impl_->append_timeline(session, at, "completed");
    if (events != nullptr) {
      events->push_back(FabricEvent{EventKind::SessionCompleted, session.id, ReasonCode::Admitted,
                                    "traffic session complete", at});
    }
  }
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::VerificationObserved, session.id, ReasonCode::Admitted,
                                  "verification observed for shard " + evidence.shard.to_string(),
                                  at});
  }
  return Status::success();
}

Status FabricEngine::report_ambiguous(SessionId session_id, TransferAttemptId attempt_id,
                                      AttemptSequence sequence, std::string cause,
                                      const CommandFence& fence, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  impl_->enforce_deadlines(at, events);
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  if (is_terminal(session.state)) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "session is terminal; ambiguity report is stale");
  }
  AttemptRecord* attempt = impl_->find_attempt(session, attempt_id);
  if (attempt == nullptr) {
    return Status::error(ErrorCode::NotFound, "attempt is not known");
  }
  if (!(attempt->sequence == sequence)) {
    return Status::error(ErrorCode::StaleAttempt, "ambiguity report carries a stale sequence");
  }
  if (attempt->outstanding) {
    attempt->outstanding = false;
    if (session.active_attempts > 0) {
      --session.active_attempts;
      --impl_->accounting_.active_attempts;
    }
  }
  const std::optional<std::size_t> position = Impl::shard_position(session, attempt->shard);
  if (position.has_value()) {
    ShardRecord& shard = session.shards[position.value()];
    if (shard.state != ShardState::Verified && shard.state != ShardState::Transferred) {
      shard.state = ShardState::Ambiguous;
    }
  }
  attempt->outcome = AttemptOutcome::Ambiguous;
  attempt->updated_at = at;
  const std::uint64_t unproven = attempt->granted_bytes > attempt->delivered_bytes
                                     ? attempt->granted_bytes - attempt->delivered_bytes
                                     : 0;
  impl_->mark_unproven(session, unproven);
  session.updated_at = at;
  impl_->settle_reason(session, ReasonCode::AmbiguousSinkOutcome, cause);
  impl_->append_timeline(session, at, "ambiguity recorded: " + cause);
  impl_->recompute_progress(session, at);
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::AmbiguityRecorded, session_id,
                                  ReasonCode::AmbiguousSinkOutcome, cause, at});
  }
  return Status::success();
}

Status FabricEngine::record_durability_assertion(SessionId session_id,
                                                 DurabilityAssertion assertion,
                                                 const CommandFence& fence, EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const Nanos at = impl_->now();
  ++impl_->commands_processed_;
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  SessionRecord& session = it->second;
  const Status fence_status = impl_->check_fence_status(fence);
  if (!fence_status.ok()) {
    return fence_status;
  }
  if (assertion.status == DurabilityStatus::ExternallyAsserted) {
    if (assertion.backend_identity.empty() ||
        assertion.backend_identity.size() > impl_->limits_.max_string_bytes) {
      return Status::error(ErrorCode::InvalidArgument,
                           "durability assertion must name a bounded backend identity");
    }
    if (session.evidence != EvidenceLevel::VerifiedAtDestination &&
        session.evidence != EvidenceLevel::Transferred) {
      return Status::error(ErrorCode::NotDurable,
                           "durability cannot be asserted before destination evidence exists");
    }
  }
  assertion.observed_at = at;
  session.durability = assertion;
  session.updated_at = at;
  impl_->append_timeline(session, at,
                         std::string("durability assertion recorded: ") +
                             to_string(assertion.status) + " backend=" +
                             assertion.backend_identity);
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::DurabilityAsserted, session_id, ReasonCode::Admitted,
                                  "external durability assertion recorded", at});
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

Result<SessionView> FabricEngine::view_session(SessionId session_id) const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  const SessionRecord& session = it->second;
  SessionView view;
  view.session = session.id;
  view.checkpoint = session.request.checkpoint;
  view.checkpoint_generation = session.request.checkpoint_generation;
  view.workload = session.request.workload;
  view.contract_generation = session.request.contract_generation;
  view.isolation = session.envelope.isolation;
  view.destination = session.request.destination;
  view.state = session.state;
  view.evidence = session.evidence;
  view.durability = session.durability.status;
  view.declared_bytes = session.request.manifest.total_bytes;
  view.transferred_bytes = session.transferred_bytes;
  view.verified_bytes = session.verified_bytes;
  view.shards_total = static_cast<std::uint32_t>(session.shards.size());
  for (const ShardRecord& shard : session.shards) {
    if (shard.state == ShardState::Transferred || shard.state == ShardState::Verified) {
      ++view.shards_transferred;
    }
    if (shard.state == ShardState::Verified) {
      ++view.shards_verified;
    }
    if (shard.state == ShardState::Ambiguous) {
      ++view.shards_ambiguous;
    }
    ShardProgress progress;
    progress.index = shard.index;
    progress.state = shard.state;
    progress.declared_bytes = shard.declared_bytes;
    progress.transferred_bytes = shard.transferred_bytes;
    progress.verified_bytes = shard.verified_bytes;
    progress.sequence = shard.sequence;
    progress.attempt = shard.attempt;
    progress.declared_digest = shard.declared_digest;
    if (shard.has_observed_digest) {
      progress.observed_digest = shard.observed_digest;
    }
    view.shards.push_back(progress);
  }
  view.last_reason = session.last_reason;
  view.last_detail = session.last_detail;
  view.stale_reason = session.stale_reason;
  view.superseded_by = session.superseded_by;
  view.envelope = session.envelope;
  view.created_at = session.created_at;
  view.updated_at = session.updated_at;
  if (session.envelope.deadline_target > 0) {
    view.deadline_target = session.envelope.deadline_target;
  }
  return view;
}

Result<std::vector<SessionSummary>> FabricEngine::list_sessions(std::optional<WorkloadId> workload,
                                                                std::size_t limit) const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  std::vector<SessionSummary> out;
  const std::size_t bound = std::min<std::size_t>(
      limit == 0 ? 64 : limit, static_cast<std::size_t>(impl_->limits_.max_sessions));
  const auto append = [&](const SessionRecord& session) {
    if (out.size() >= bound) {
      return;
    }
    SessionSummary summary;
    summary.session = session.id;
    summary.checkpoint = session.request.checkpoint;
    summary.checkpoint_generation = session.request.checkpoint_generation;
    summary.workload = session.request.workload;
    summary.state = session.state;
    summary.evidence = session.evidence;
    summary.declared_bytes = session.request.manifest.total_bytes;
    summary.transferred_bytes = session.transferred_bytes;
    summary.verified_bytes = session.verified_bytes;
    summary.updated_at = session.updated_at;
    out.push_back(summary);
  };
  if (workload.has_value()) {
    const auto it = impl_->by_workload_.find(workload.value());
    if (it == impl_->by_workload_.end()) {
      return out;
    }
    for (const SessionId& id : it->second) {
      const auto session_it = impl_->sessions_.find(id);
      if (session_it != impl_->sessions_.end()) {
        append(session_it->second);
      }
    }
    return out;
  }
  for (const auto& entry : impl_->sessions_) {
    append(entry.second);
  }
  std::sort(out.begin(), out.end(), [](const SessionSummary& lhs, const SessionSummary& rhs) {
    if (lhs.updated_at != rhs.updated_at) {
      return lhs.updated_at < rhs.updated_at;
    }
    return lhs.session < rhs.session;
  });
  if (out.size() > bound) {
    out.resize(bound);
  }
  return out;
}

AccountingSnapshot FabricEngine::accounting() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->accounting_;
}

Result<Explanation> FabricEngine::explain(SessionId session_id) const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const auto it = impl_->sessions_.find(session_id);
  if (it == impl_->sessions_.end()) {
    return Status::error(ErrorCode::NotFound, "session is not known");
  }
  const SessionRecord& session = it->second;
  Explanation explanation;
  explanation.session = session.id;
  explanation.summary = std::string("state=") + to_string(session.state) +
                        " evidence=" + to_string(session.evidence) +
                        " declared=" + std::to_string(session.request.manifest.total_bytes) +
                        " transferred=" + std::to_string(session.transferred_bytes) +
                        " verified=" + std::to_string(session.verified_bytes) +
                        " outstanding=" + std::to_string(session.outstanding_bytes) +
                        " cancelled=" + std::to_string(session.cancelled_bytes) +
                        " unproven=" + std::to_string(session.unproven_bytes) +
                        " wasted=" + std::to_string(session.wasted_bytes) +
                        " durability=" + to_string(session.durability.status);
  explanation.timeline = session.timeline;
  return explanation;
}

Status FabricEngine::poll_deadlines(EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  impl_->enforce_deadlines(impl_->now(), events);
  return Status::success();
}

std::size_t FabricEngine::session_count() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->sessions_.size();
}

std::size_t FabricEngine::timeline_entries() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  std::size_t total = 0;
  for (const auto& entry : impl_->sessions_) {
    total += entry.second.timeline.size();
    total += entry.second.attempts.size();
  }
  return total;
}

std::uint64_t FabricEngine::commands_processed() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->commands_processed_;
}

bool FabricEngine::shutting_down() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  return impl_->shutting_down_;
}

Status FabricEngine::begin_shutdown(EventSink* events) {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  if (impl_->shutting_down_) {
    return Status::error(ErrorCode::ShuttingDown, "fabric is already shutting down");
  }
  impl_->shutting_down_ = true;
  const Nanos at = impl_->now();
  if (events != nullptr) {
    events->push_back(FabricEvent{EventKind::Shutdown, SessionId{}, ReasonCode::FabricShuttingDown,
                                  "fabric is shutting down", at});
  }
  return Status::success();
}

Status FabricEngine::check_invariants() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex_);
  const AccountingSnapshot& accounting = impl_->accounting_;
  if (!accounting.conserves()) {
    return Status::error(
        ErrorCode::AccountingImbalance,
        "bytes_admitted != transferred + wasted + cancelled + unproven + outstanding");
  }
  std::uint64_t admitted = impl_->pruned_.admitted;
  std::uint64_t transferred = impl_->pruned_.transferred;
  std::uint64_t verified = impl_->pruned_.verified;
  std::uint64_t cancelled = impl_->pruned_.cancelled;
  std::uint64_t wasted = impl_->pruned_.wasted;
  std::uint64_t unproven = impl_->pruned_.unproven;
  std::uint64_t outstanding = 0;
  std::uint32_t active_sessions = 0;
  std::uint32_t active_attempts = 0;
  for (const auto& entry : impl_->sessions_) {
    const SessionRecord& session = entry.second;
    admitted += session.admitted_bytes;
    transferred += session.transferred_bytes;
    verified += session.verified_bytes;
    cancelled += session.cancelled_bytes;
    wasted += session.wasted_bytes;
    unproven += session.unproven_bytes;
    outstanding += session.outstanding_bytes;
    active_attempts += session.active_attempts;
    if (is_active(session.state)) {
      ++active_sessions;
    }
    if (session.shards.size() != session.request.manifest.shards.size()) {
      return Status::error(ErrorCode::CorruptState, "session shard table diverged from its manifest");
    }
    for (std::size_t i = 0; i < session.shards.size(); ++i) {
      if (!(session.shards[i].index == session.request.manifest.shards[i].index)) {
        return Status::error(ErrorCode::CorruptState, "session shard ordering diverged");
      }
    }
    if (session.transferred_bytes > session.admitted_bytes) {
      return Status::error(ErrorCode::AccountingImbalance,
                           "session transferred more bytes than were admitted");
    }
    if (session.verified_bytes > session.transferred_bytes) {
      return Status::error(ErrorCode::AccountingImbalance,
                           "session verified more bytes than were transferred");
    }
    if (session.transferred_bytes + session.wasted_bytes + session.cancelled_bytes +
            session.unproven_bytes + session.outstanding_bytes !=
        session.admitted_bytes) {
      return Status::error(ErrorCode::AccountingImbalance,
                           "session byte buckets do not sum to its admitted bytes");
    }
    if (session.outstanding_bytes > session.admitted_bytes) {
      return Status::error(ErrorCode::AccountingImbalance,
                           "session outstanding exceeds admitted bytes");
    }
    if (session.verified_bytes > session.transferred_bytes) {
      return Status::error(ErrorCode::AccountingImbalance,
                           "session verified more bytes than it currently counts as transferred");
    }
    if (is_terminal(session.state) &&
        (session.outstanding_bytes != 0 || session.active_attempts != 0)) {
      return Status::error(ErrorCode::AccountingImbalance,
                           "terminal session retains outstanding authority");
    }
    if (!session.envelope.session.is_nil() && !(session.envelope.session == session.id)) {
      return Status::error(ErrorCode::CorruptState, "envelope is bound to a different session");
    }
    if (session.evidence == EvidenceLevel::VerifiedAtDestination) {
      for (const ShardRecord& shard : session.shards) {
        if (shard.state != ShardState::Verified) {
          return Status::error(ErrorCode::CorruptState,
                               "session claims verified evidence with an unverified shard");
        }
      }
    }
    if (session.state == SessionState::TrafficSessionComplete &&
        impl_->policy_.require_destination_verification) {
      for (const ShardRecord& shard : session.shards) {
        if (shard.state != ShardState::Verified) {
          return Status::error(ErrorCode::CorruptState,
                               "completed session has an unverified shard");
        }
      }
    }
  }
  if (admitted != accounting.bytes_admitted || transferred != accounting.bytes_transferred ||
      verified != accounting.bytes_verified || cancelled != accounting.bytes_cancelled ||
      wasted != accounting.bytes_wasted || unproven != accounting.bytes_unproven ||
      outstanding != accounting.granted_outstanding_bytes) {
    return Status::error(ErrorCode::AccountingImbalance,
                         "aggregate accounting disagrees with per-session accounting");
  }
  if (active_sessions != accounting.active_sessions || active_attempts != accounting.active_attempts) {
    return Status::error(ErrorCode::AccountingImbalance,
                         "active counters disagree with live session state");
  }
  std::size_t indexed = 0;
  for (const auto& entry : impl_->by_workload_) {
    for (const SessionId& id : entry.second) {
      if (impl_->sessions_.find(id) == impl_->sessions_.end()) {
        return Status::error(ErrorCode::CorruptState, "workload index references an unknown session");
      }
      ++indexed;
    }
  }
  for (const auto& entry : impl_->by_checkpoint_) {
    for (const SessionId& id : entry.second) {
      if (impl_->sessions_.find(id) == impl_->sessions_.end()) {
        return Status::error(ErrorCode::CorruptState,
                             "checkpoint index references an unknown session");
      }
    }
  }
  if (indexed != impl_->sessions_.size()) {
    return Status::error(ErrorCode::CorruptState, "index size disagrees with the session table");
  }
  if (impl_->command_index_.size() > impl_->command_index_bound_) {
    return Status::error(ErrorCode::ResourceExhausted, "command replay index exceeds its bound");
  }
  return Status::success();
}

}  // namespace ctf
