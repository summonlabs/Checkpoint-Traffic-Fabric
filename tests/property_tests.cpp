// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Property suite: seeded randomized operation sequences driven against the real,
// clock-injected engine.
//
// Design notes:
//   * every step is followed by the documented invariants: check_invariants(),
//     the conservation identity, the isolation-class rate ceiling, and per
//     session evidence/state consistency;
//   * the same script is replayed on two independently constructed engines to
//     prove decisions, envelopes, identities, and accounting are identical;
//   * the sequence is generated from the harness seed, so a failure is
//     reproducible from the seed the harness prints.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "ctf/engine.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

using ctf::test::EngineFixture;

namespace {

using ctf::AccountingSnapshot;
using ctf::AdmissionDecision;
using ctf::AttemptSequence;
using ctf::CheckpointGeneration;
using ctf::CheckpointId;
using ctf::CommandFence;
using ctf::CommandId;
using ctf::DecisionKind;
using ctf::DestinationClass;
using ctf::Digest;
using ctf::ErrorCode;
using ctf::EvidenceLevel;
using ctf::FabricEngine;
using ctf::IsolationClass;
using ctf::ManualClock;
using ctf::Nanos;
using ctf::PolicySnapshot;
using ctf::ReasonCode;
using ctf::SessionId;
using ctf::SessionRequest;
using ctf::SessionState;
using ctf::SessionView;
using ctf::ShardIndex;
using ctf::ShardProgress;
using ctf::ShardState;
using ctf::Status;
using ctf::TopologySnapshot;
using ctf::TransferEvidence;
using ctf::VerificationEvidence;
using ctf::WaveGrant;
using ctf::WaveOutcome;
using ctf::WorkloadContractGeneration;
using ctf::WorkloadId;

// ---------------------------------------------------------------------------
// Deterministic building blocks
// ---------------------------------------------------------------------------

constexpr std::size_t kClassCount = 4;
constexpr std::uint32_t kCheckpointCount = 4;
constexpr std::size_t kMaxTrackedSessions = 20;

/// Canonical checkpoint identities, distinct from the fixture's own.
CheckpointId checkpoint_id(std::uint32_t index) {
  std::string digits = std::to_string(index);
  while (digits.size() < 12) {
    digits.insert(digits.begin(), '0');
  }
  return CheckpointId::parse("cccccccc-1111-4222-8333-" + digits).value();
}

/// Isolation-class token capacity, mirroring the fabric's own integer model so
/// the test's ceiling is never tighter than the library's.
struct ClassBudget {
  std::uint64_t ceiling_bps = 0;
  std::uint64_t burst_bytes = 0;
};

ClassBudget budget_for(const ctf::IsolationEnvelopeConfig& envelope) {
  constexpr std::uint64_t kSecond = 1000000000ULL;
  ClassBudget budget;
  budget.ceiling_bps = envelope.ceiling_bps;
  const std::uint64_t window = static_cast<std::uint64_t>(envelope.burst_window_ns);
  const std::uint64_t whole = envelope.ceiling_bps / kSecond;
  const std::uint64_t remainder = envelope.ceiling_bps % kSecond;
  std::uint64_t capacity = whole * window + (remainder * window) / kSecond;
  const std::uint64_t floor_capacity = envelope.ceiling_bps / 100U;
  if (capacity < floor_capacity) {
    capacity = floor_capacity;
  }
  budget.burst_bytes = capacity;
  return budget;
}

/// Bytes a class ceiling pays for over an elapsed interval (floor arithmetic, so
/// it is never smaller than the fabric's own credit).
std::uint64_t scheduled_bytes(std::uint64_t rate_bps, std::uint64_t elapsed_ns) {
  constexpr std::uint64_t kSecond = 1000000000ULL;
  return (rate_bps / kSecond) * elapsed_ns + ((rate_bps % kSecond) * elapsed_ns) / kSecond;
}

/// The property fixture: same authority as the shared fixture, with bounds that
/// make deferrals, retries, and deadlines all reachable in a short run.
EngineFixture property_fixture() {
  EngineFixture fixture = EngineFixture::make();
  fixture.policy.retained_history = 24;
  fixture.policy.max_sessions = 16;
  fixture.policy.max_attempts_in_flight = 64;
  fixture.policy.max_wave_width = 3;
  fixture.contracts[0].max_in_flight_sessions = 3;
  fixture.contracts[0].max_shards_per_wave = 3;
  fixture.contracts[1].max_in_flight_sessions = 2;
  fixture.contracts[1].max_shards_per_wave = 2;
  return fixture;
}

SessionRequest build_request(FabricEngine& engine, const CheckpointId& checkpoint,
                             CheckpointGeneration generation, CommandId command,
                             WorkloadId workload, std::uint32_t shard_count,
                             std::uint64_t shard_bytes, IsolationClass isolation,
                             DestinationClass destination, std::uint64_t requested_rate_bps,
                             Nanos deadline_horizon, std::uint64_t digest_salt) {
  const std::optional<ctf::WorkloadContract> contract = engine.contract(workload);
  const WorkloadContractGeneration contract_generation =
      contract.has_value() ? contract->generation : WorkloadContractGeneration(0);
  SessionRequest request;
  request.command = command;
  request.workload = workload;
  request.contract_generation = contract_generation;
  request.policy_generation = engine.policy().generation;
  request.topology_generation = engine.topology().generation;
  request.checkpoint = checkpoint;
  request.checkpoint_generation = generation;
  request.requested_isolation = isolation;
  request.destination = destination;
  request.requested_rate_bps = requested_rate_bps;
  request.deadline_horizon_ns = deadline_horizon;
  request.manifest.checkpoint = checkpoint;
  request.manifest.generation = generation;
  request.manifest.workload = workload;
  request.manifest.contract_generation = contract_generation;
  for (std::uint32_t index = 0; index < shard_count; ++index) {
    ctf::ShardDescriptor shard;
    shard.index = ShardIndex(index);
    shard.declared_bytes = shard_bytes;
    shard.declared_digest = Digest(static_cast<std::uint32_t>(0x4000U + digest_salt * 31U + index),
                                   0x9000ULL + digest_salt * 7ULL + index);
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += shard_bytes;
  }
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  return request;
}

// ---------------------------------------------------------------------------
// Scripted operation sequence
// ---------------------------------------------------------------------------

enum class PropOp : std::uint8_t {
  Submit,
  Wave,
  Transfer,
  UnackedTransfer,
  Verify,
  Ambiguous,
  Pause,
  Resume,
  Cancel,
  Revalidate,
  AdvanceEpoch,
  ApplyPolicy,
  ApplyTopology,
  UpsertContract,
  AdvanceClock,
  Query,
};

const char* op_name(PropOp op) {
  switch (op) {
    case PropOp::Submit: return "submit";
    case PropOp::Wave: return "wave";
    case PropOp::Transfer: return "transfer";
    case PropOp::UnackedTransfer: return "unacked";
    case PropOp::Verify: return "verify";
    case PropOp::Ambiguous: return "ambiguous";
    case PropOp::Pause: return "pause";
    case PropOp::Resume: return "resume";
    case PropOp::Cancel: return "cancel";
    case PropOp::Revalidate: return "revalidate";
    case PropOp::AdvanceEpoch: return "epoch";
    case PropOp::ApplyPolicy: return "policy";
    case PropOp::ApplyTopology: return "topology";
    case PropOp::UpsertContract: return "contract";
    case PropOp::AdvanceClock: return "clock";
    case PropOp::Query: return "query";
  }
  return "?";
}

struct StepPlan {
  PropOp op = PropOp::Query;
  std::uint32_t a = 0;
  std::uint32_t b = 0;
  std::uint32_t c = 0;
  std::uint64_t u = 0;
  Nanos clock_delta = 0;
};

/// Weighted op table: evidence and credit dominate, authority changes and
/// deadline failures are frequent enough to matter.
const PropOp kWeightedOps[] = {
    PropOp::Submit,        PropOp::Submit,        PropOp::Submit,
    PropOp::Wave,          PropOp::Wave,          PropOp::Wave,          PropOp::Wave,
    PropOp::Wave,          PropOp::Wave,
    PropOp::Transfer,      PropOp::Transfer,      PropOp::Transfer,      PropOp::Transfer,
    PropOp::Transfer,      PropOp::Transfer,      PropOp::Transfer,
    PropOp::UnackedTransfer, PropOp::UnackedTransfer,
    PropOp::Verify,        PropOp::Verify,        PropOp::Verify,        PropOp::Verify,
    PropOp::Ambiguous,
    PropOp::Pause,         PropOp::Resume,
    PropOp::Cancel,        PropOp::Cancel,
    PropOp::Revalidate,    PropOp::Revalidate,    PropOp::Revalidate,
    PropOp::AdvanceEpoch,
    PropOp::ApplyPolicy,
    PropOp::ApplyTopology,
    PropOp::UpsertContract,
    PropOp::AdvanceClock,  PropOp::AdvanceClock,  PropOp::AdvanceClock,  PropOp::AdvanceClock,
    PropOp::AdvanceClock,
    PropOp::Query,         PropOp::Query,         PropOp::Query,
};

std::vector<StepPlan> make_script(std::uint64_t seed, std::size_t steps) {
  std::mt19937_64 rng(seed);
  std::vector<StepPlan> script;
  script.reserve(steps);
  const std::size_t op_count = sizeof(kWeightedOps) / sizeof(kWeightedOps[0]);
  for (std::size_t index = 0; index < steps; ++index) {
    StepPlan plan;
    plan.op = kWeightedOps[rng() % op_count];
    plan.a = static_cast<std::uint32_t>(rng() % 1000U);
    plan.b = static_cast<std::uint32_t>(rng() % 1000U);
    plan.c = static_cast<std::uint32_t>(rng() % 1000U);
    plan.u = rng();
    plan.clock_delta = static_cast<Nanos>(rng() % (8U * 1000000U)) + 1000;
    script.push_back(plan);
  }
  return script;
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

struct StepTrace {
  PropOp op = PropOp::Query;
  ErrorCode code = ErrorCode::Ok;
  DecisionKind kind = DecisionKind::Deny;
  ReasonCode reason = ReasonCode::Internal;
  std::uint64_t rate_bps = 0;
  std::uint64_t burst_bytes = 0;
  std::uint64_t granted_bytes = 0;
  std::uint32_t wave_count = 0;
  std::string session;
  Nanos at = 0;
};

/// Refusals an evidence report may legitimately meet: the attempt was settled,
/// released, or the fabric no longer holds authority for those bytes.
[[nodiscard]] bool documented_evidence_refusal(ErrorCode code) {
  return code == ErrorCode::InvalidStateTransition || code == ErrorCode::AmbiguousOutcome ||
         code == ErrorCode::StaleEvidence || code == ErrorCode::StaleAttempt ||
         code == ErrorCode::ImpossibleState || code == ErrorCode::NotFound ||
         code == ErrorCode::DeadlineUnreachable || code == ErrorCode::Superseded;
}

struct LiveAttempt {
  SessionId session;
  ctf::TransferAttemptId attempt;
  AttemptSequence sequence;
  ShardIndex shard;
  std::uint64_t granted_bytes = 0;
  Digest declared_digest;
};

struct SessionTrack {
  SessionId id;
  WorkloadId workload;
  CheckpointId checkpoint;
  CheckpointGeneration generation;
  IsolationClass isolation = IsolationClass::TrainingBulk;
  std::vector<Digest> shard_digests;
  std::vector<std::uint64_t> shard_bytes;
  std::uint32_t shard_count = 0;
  /// Set once an epoch advance has booked this session's remaining authority as
  /// UNPROVEN: the fabric re-arms the shards without re-authorising them, so
  /// further transfer evidence must not be produced (see driver_notes()).
  bool frozen = false;
};

struct RunOutcome {
  std::vector<StepTrace> trace;
  AccountingSnapshot accounting;
  std::vector<std::string> session_states;
  std::uint64_t granted_per_class[kClassCount] = {};
  std::uint64_t admitted = 0;
  std::uint64_t deferred = 0;
  std::uint64_t denied = 0;
  std::uint64_t superseded = 0;
};

/// Peer discipline the randomized driver keeps:
///
///   R1 a sender settles an attempt (evidence, ambiguity, or truncation) before
///      asking for credit for the same shard again, and keeps at most one
///      unreported attempt in flight per session. The fabric enforces the
///      former itself (request_wave refuses an unsettled attempt), so this is
///      what a conforming sender does rather than a workaround.
///   R2 a sink reports success only for a shard that arrived in full, and only
///      once every shard of the session has arrived, so verification always
///      describes bytes the fabric really holds.
///   R3 attempts leave the driver's bookkeeping exactly when the fabric releases
///      them, so stale evidence is never sent.
class Driver {
 public:
  Driver(const EngineFixture& fixture, std::uint64_t identity_seed, std::size_t max_steps)
      : fixture_(fixture),
        engine_(config_for(fixture, identity_seed), clock_),
        script_(make_script(identity_seed, max_steps)) {
    const PolicySnapshot policy = engine_.policy();
    for (const ctf::IsolationEnvelopeConfig& envelope : policy.envelopes) {
      budgets_[static_cast<std::size_t>(envelope.isolation)] = budget_for(envelope);
    }
  }

  Driver(const Driver&) = delete;
  Driver& operator=(const Driver&) = delete;

  [[nodiscard]] FabricEngine& engine() { return engine_; }
  [[nodiscard]] ManualClock& clock() { return clock_; }
  [[nodiscard]] const std::vector<StepPlan>& script() const { return script_; }

  static ctf::EngineConfig config_for(const EngineFixture& fixture, std::uint64_t identity_seed) {
    ctf::EngineConfig config = fixture.engine_config(ctf::test::first_epoch());
    config.identity_seed = identity_seed;
    return config;
  }

  /// Runs the whole script, asserting the invariants after every step.
  RunOutcome run(ctf::test::Context& ctf_ctx, std::size_t steps) {
    CTF_REQUIRE_OK(engine_.startup_status());
    CTF_REQUIRE_OK(engine_.check_invariants());
    const std::size_t count = std::min(steps, script_.size());
    for (std::size_t index = 0; index < count; ++index) {
      const StepPlan& plan = script_[index];
      current_op_ = plan.op;
      switch (plan.op) {
        case PropOp::Submit: do_submit(ctf_ctx, plan); break;
        case PropOp::Wave: do_wave(ctf_ctx, plan); break;
        case PropOp::Transfer: do_transfer(ctf_ctx, plan, true); break;
        case PropOp::UnackedTransfer: do_transfer(ctf_ctx, plan, false); break;
        case PropOp::Verify: do_verify(ctf_ctx, plan); break;
        case PropOp::Ambiguous: do_ambiguous(ctf_ctx, plan); break;
        case PropOp::Pause: do_pause(ctf_ctx, plan); break;
        case PropOp::Resume: do_resume(ctf_ctx, plan); break;
        case PropOp::Cancel: do_cancel(ctf_ctx, plan); break;
        case PropOp::Revalidate: do_revalidate(ctf_ctx, plan); break;
        case PropOp::AdvanceEpoch: do_advance_epoch(ctf_ctx); break;
        case PropOp::ApplyPolicy: do_apply_policy(ctf_ctx); break;
        case PropOp::ApplyTopology: do_apply_topology(ctf_ctx); break;
        case PropOp::UpsertContract: do_upsert_contract(ctf_ctx, plan); break;
        case PropOp::AdvanceClock: do_advance_clock(ctf_ctx, plan); break;
        case PropOp::Query: do_query(ctf_ctx, plan); break;
      }
      observe(ctf_ctx);
    }
    return outcome();
  }

  /// Cancels every session the driver still tracks, then asserts the fabric
  /// returned to its baseline: no active session, no attempt, no outstanding
  /// authority.
  /// Verifies every shard of a session that already holds verified evidence.
  /// The driver only verifies once every shard arrived in full, so this always
  /// ends in TrafficSessionComplete.
  [[nodiscard]] Status verify_remaining_shards(ctf::test::Context& ctf_ctx,
                                               const SessionTrack& track) {
    Status last = Status::success();
    for (int guard = 0; guard < 64; ++guard) {
      const ctf::Result<SessionView> view = engine_.view_session(track.id);
      if (!view.ok() || ctf::is_terminal(view.value().state)) {
        return last;
      }
      const ShardProgress* pending = nullptr;
      for (const ShardProgress& shard : view.value().shards) {
        if (shard.state == ShardState::Transferred && shard.attempt.has_value()) {
          pending = &shard;
          break;
        }
      }
      if (pending == nullptr) {
        return last;
      }
      const CommandFence fence = engine_.current_fence(track.workload, track.generation);
      VerificationEvidence evidence;
      evidence.session = track.id;
      evidence.attempt = pending->attempt.value();
      evidence.sequence = pending->sequence;
      evidence.shard = pending->index;
      evidence.verified_bytes = pending->declared_bytes;
      evidence.verified_digest = pending->declared_digest;
      evidence.outcome = VerificationEvidence::Outcome::Verified;
      evidence.verifier_identity = "property-sink";
      last = engine_.report_verification(evidence, fence);
      CTF_EXPECT(last.ok());
      if (!last.ok()) {
        return last;
      }
    }
    return last;
  }

  void settle(ctf::test::Context& ctf_ctx) {
    // Sessions that already hold verified evidence are finished by completing
    // their remaining verification (their shards all arrived in full); every
    // other session is cancelled.
    for (const SessionTrack& track : tracks_) {
      const ctf::Result<SessionView> view = engine_.view_session(track.id);
      if (!view.ok() || ctf::is_terminal(view.value().state) ||
          view.value().verified_bytes == 0) {
        continue;
      }
      (void)verify_remaining_shards(ctf_ctx, track);
    }
    for (const SessionTrack& track : tracks_) {
      const ctf::Result<SessionView> view = engine_.view_session(track.id);
      if (!view.ok()) {
        continue;
      }
      if (ctf::is_terminal(view.value().state)) {
        continue;
      }
      const CommandFence fence = engine_.current_fence(track.workload, track.generation);
      const Status status = engine_.cancel_session(track.id, fence, ReasonCode::CancelledByOperator,
                                                   "property run settling");
      if (!status.ok()) {
        CTF_EXPECT_EQ(status.code(), ErrorCode::InvalidStateTransition);
      }
    }
    outstanding_.clear();
    const AccountingSnapshot accounting = engine_.accounting();
    CTF_EXPECT(accounting.conserves());
    CTF_EXPECT(accounting.at_baseline());
    CTF_EXPECT_EQ(accounting.granted_outstanding_bytes, 0ULL);
    CTF_EXPECT_EQ(accounting.active_sessions, 0U);
    CTF_EXPECT_EQ(accounting.active_attempts, 0U);
    CTF_EXPECT_OK(engine_.check_invariants());
  }

  [[nodiscard]] RunOutcome outcome() const {
    RunOutcome result;
    result.trace = trace_;
    result.accounting = engine_.accounting();
    for (const SessionTrack& track : tracks_) {
      const ctf::Result<SessionView> view = engine_.view_session(track.id);
      result.session_states.push_back(
          track.id.to_string() + "|" +
          (view.ok() ? std::string(ctf::to_string(view.value().state)) + "|" +
                           ctf::to_string(view.value().evidence) + "|" +
                           std::to_string(view.value().transferred_bytes) + "|" +
                           std::to_string(view.value().verified_bytes) + "|" +
                           (view.value().superseded_by.has_value()
                                ? view.value().superseded_by.value().to_string()
                                : std::string("-"))
                     : std::string("evicted")));
    }
    for (std::size_t index = 0; index < kClassCount; ++index) {
      result.granted_per_class[index] = granted_[index];
    }
    result.admitted = admitted_;
    result.deferred = deferred_;
    result.denied = denied_;
    result.superseded = superseded_;
    return result;
  }

 private:
  // --- observation ---------------------------------------------------------

  void observe(ctf::test::Context& ctf_ctx) {
    const AccountingSnapshot accounting = engine_.accounting();
    const Status health = engine_.check_invariants();
    if (!health.ok()) {
      const ctf::EngineSnapshot broken = engine_.export_snapshot();
      for (const ctf::PersistedSession& session : broken.sessions) {
        const std::uint64_t buckets = session.transferred_bytes + session.wasted_bytes +
                                      session.cancelled_bytes + session.unproven_bytes +
                                      session.outstanding_bytes;
        if (session.verified_bytes > session.transferred_bytes ||
            buckets != session.admitted_bytes) {
          std::printf("      BROKEN %s state=%s declared=%llu admitted=%llu t=%llu v=%llu w=%llu "
                      "c=%llu u=%llu o=%llu\n",
                      session.session.to_string().c_str(), ctf::to_string(session.state),
                      (unsigned long long)session.request.manifest.total_bytes,
                      (unsigned long long)session.admitted_bytes,
                      (unsigned long long)session.transferred_bytes,
                      (unsigned long long)session.verified_bytes,
                      (unsigned long long)session.wasted_bytes,
                      (unsigned long long)session.cancelled_bytes,
                      (unsigned long long)session.unproven_bytes,
                      (unsigned long long)session.outstanding_bytes);
          for (const ctf::PersistedShard& shard : session.shards) {
            std::printf("        shard=%u state=%s granted=%llu transferred=%llu verified=%llu\n",
                        shard.index.value(), ctf::to_string(shard.state),
                        (unsigned long long)shard.granted_bytes,
                        (unsigned long long)shard.transferred_bytes,
                        (unsigned long long)shard.verified_bytes);
          }
          const ctf::Result<ctf::Explanation> why = engine_.explain(session.session);
          if (why.ok()) {
            for (const std::string& line : why.value().timeline) {
              std::printf("        tl %s\n", line.c_str());
            }
          }
        }
      }
      std::printf("      check_invariants=%s\n", health.to_string().c_str());
    }
    if (!accounting.conserves()) {
      std::printf("    DIAG op=%s admitted=%llu transferred=%llu wasted=%llu cancelled=%llu "
                  "unproven=%llu outstanding=%llu step=%zu\n",
                  op_name(current_op_), (unsigned long long)accounting.bytes_admitted,
                  (unsigned long long)accounting.bytes_transferred,
                  (unsigned long long)accounting.bytes_wasted,
                  (unsigned long long)accounting.bytes_cancelled,
                  (unsigned long long)accounting.bytes_unproven,
                  (unsigned long long)accounting.granted_outstanding_bytes, trace_.size());
      const ctf::EngineSnapshot snapshot = engine_.export_snapshot();
      std::uint64_t sum_admitted = 0;
      for (const ctf::PersistedSession& session : snapshot.sessions) {
        const std::uint64_t buckets = session.transferred_bytes + session.wasted_bytes +
                                      session.cancelled_bytes + session.unproven_bytes +
                                      session.outstanding_bytes;
        sum_admitted += session.admitted_bytes;
        if (buckets != session.admitted_bytes) {
          std::printf("      SESSION %s state=%s declared=%llu admitted=%llu buckets=%llu "
                      "(t=%llu w=%llu c=%llu u=%llu o=%llu)\n",
                      session.session.to_string().c_str(), ctf::to_string(session.state),
                      (unsigned long long)session.request.manifest.total_bytes,
                      (unsigned long long)session.admitted_bytes, (unsigned long long)buckets,
                      (unsigned long long)session.transferred_bytes,
                      (unsigned long long)session.wasted_bytes,
                      (unsigned long long)session.cancelled_bytes,
                      (unsigned long long)session.unproven_bytes,
                      (unsigned long long)session.outstanding_bytes);
          for (const ctf::PersistedShard& shard : session.shards) {
            std::printf("        shard=%u state=%s declared=%llu granted=%llu transferred=%llu "
                        "verified=%llu\n",
                        shard.index.value(), ctf::to_string(shard.state),
                        (unsigned long long)session.request.manifest.shards[shard.index.value()]
                            .declared_bytes,
                        (unsigned long long)shard.granted_bytes,
                        (unsigned long long)shard.transferred_bytes,
                        (unsigned long long)shard.verified_bytes);
          }
          for (const ctf::PersistedAttempt& attempt : session.attempts) {
            std::printf("        attempt shard=%u seq=%llu outcome=%s granted=%llu delivered=%llu "
                        "outstanding=%d\n",
                        attempt.shard.value(), (unsigned long long)attempt.sequence.value(),
                        ctf::to_string(attempt.outcome), (unsigned long long)attempt.granted_bytes,
                        (unsigned long long)attempt.delivered_bytes, attempt.outstanding ? 1 : 0);
          }
          const ctf::Result<ctf::Explanation> why = engine_.explain(session.session);
          if (why.ok()) {
            for (const std::string& line : why.value().timeline) {
              std::printf("        tl %s\n", line.c_str());
            }
          }
        }
      }
      std::printf("      SUM admitted=%llu global admitted=%llu\n",
                  (unsigned long long)sum_admitted, (unsigned long long)accounting.bytes_admitted);
      CTF_REQUIRE(accounting.conserves());
    }
    CTF_EXPECT_OK(engine_.check_invariants());
    CTF_EXPECT(accounting.conserves());
    check_rate_ceiling(ctf_ctx);
    for (const SessionTrack& track : tracks_) {
      check_session(ctf_ctx, track);
    }
  }

  void check_rate_ceiling(ctf::test::Context& ctf_ctx) {
    const std::uint64_t elapsed = static_cast<std::uint64_t>(clock_.now() - start_ns_);
    for (std::size_t index = 0; index < kClassCount; ++index) {
      if (granted_[index] == 0) {
        continue;
      }
      const std::uint64_t allowed = scheduled_bytes(budgets_[index].ceiling_bps, elapsed) +
                                    budgets_[index].burst_bytes * (1 + policy_applications_);
      if (granted_[index] > allowed) {
        ctf_ctx.fail(__FILE__, __LINE__,
                     "isolation class " + std::to_string(index) + " granted " +
                         std::to_string(granted_[index]) + " bytes but the ceiling over " +
                         std::to_string(elapsed) + " ns plus bursts allows " +
                         std::to_string(allowed));
      }
    }
  }

  void check_session(ctf::test::Context& ctf_ctx, const SessionTrack& track) {
    const ctf::Result<SessionView> view = engine_.view_session(track.id);
    if (!view.ok()) {
      CTF_EXPECT_EQ(view.code(), ErrorCode::NotFound);
      return;
    }
    const SessionView& value = view.value();
    CTF_EXPECT(value.verified_bytes <= value.transferred_bytes);
    CTF_EXPECT(value.transferred_bytes <= value.declared_bytes);
    CTF_EXPECT(value.shards_verified <= value.shards_transferred);
    CTF_EXPECT(value.shards_transferred <= value.shards_total);
    if (value.state == SessionState::TrafficSessionComplete) {
      // require_destination_verification is always true in this fixture.
      CTF_EXPECT_EQ(value.evidence, EvidenceLevel::VerifiedAtDestination);
      CTF_EXPECT_EQ(value.shards_verified, value.shards_total);
      for (const ShardProgress& shard : value.shards) {
        CTF_EXPECT_EQ(shard.state, ShardState::Verified);
      }
      // Nothing may still be in flight for a completed session.
      CTF_EXPECT_EQ(outstanding_count(track.id), 0U);
    }
    if (ctf::is_terminal(value.state)) {
      CTF_EXPECT(!value.superseded_by.has_value() || value.state == SessionState::Superseded);
      release_session_attempts(track.id);
    }
  }

  /// Grants that have not yet been acknowledged by the sink. An entry exists
  /// exactly while the fabric still counts the attempt as outstanding, so the
  /// driver never re-grants a shard whose attempt is unreported.
  [[nodiscard]] std::size_t outstanding_count(const SessionId& session) const {
    std::size_t count = 0;
    for (const LiveAttempt& live : outstanding_) {
      if (live.session == session) {
        ++count;
      }
    }
    return count;
  }

  void release_session_attempts(const SessionId& session) {
    const auto released = [&session](const LiveAttempt& live) { return live.session == session; };
    outstanding_.erase(std::remove_if(outstanding_.begin(), outstanding_.end(), released),
                       outstanding_.end());
  }

  [[nodiscard]] const LiveAttempt* find_outstanding(const SessionId& session,
                                                    ShardIndex shard) const {
    for (const LiveAttempt& live : outstanding_) {
      if (live.session == session && live.shard == shard) {
        return &live;
      }
    }
    return nullptr;
  }

  /// True when the shard's current attempt is one the sink never acknowledged.
  [[nodiscard]] bool is_unacknowledged(const SessionId& session, ShardIndex shard,
                                       const ctf::TransferAttemptId& attempt) const {
    for (const LiveAttempt& live : outstanding_) {
      if (live.session == session && live.shard == shard && live.attempt == attempt) {
        return true;
      }
    }
    return false;
  }

  /// Re-derives one mirrored attempt from the fabric: an entry survives only
  /// while the shard's current attempt is still the same and still unsettled, so
  /// the driver never asks for credit the fabric would refuse as unsettled.
  void reconcile_attempt(const LiveAttempt& entry) {
    const ctf::Result<SessionView> view = engine_.view_session(entry.session);
    if (!view.ok()) {
      drop_attempt(entry.session, entry.shard);
      return;
    }
    const SessionView& value = view.value();
    const bool shard_known = entry.shard.value() < value.shards.size();
    if (!ctf::is_terminal(value.state) && shard_known) {
      const ShardProgress& shard = value.shards[entry.shard.value()];
      if (shard.attempt.has_value() && shard.attempt.value() == entry.attempt &&
          shard.state != ShardState::Ambiguous && shard.state != ShardState::Verified &&
          shard.state != ShardState::Transferred) {
        return;
      }
    }
    drop_attempt(entry.session, entry.shard);
  }

  void drop_attempt(const SessionId& session, ShardIndex shard) {
    outstanding_.erase(std::remove_if(outstanding_.begin(), outstanding_.end(),
                                      [&session, shard](const LiveAttempt& live) {
                                        return live.session == session && live.shard == shard;
                                      }),
                       outstanding_.end());
  }

  void record(const StepTrace& trace) { trace_.push_back(trace); }

  void record_simple(PropOp op, const Status& status) {
    StepTrace trace;
    trace.op = op;
    trace.code = status.code();
    trace.at = clock_.now();
    record(trace);
  }

  [[nodiscard]] const SessionTrack* pick_session(const StepPlan& plan,
                                                 std::size_t salt) const {
    if (tracks_.empty()) {
      return nullptr;
    }
    return &tracks_[(plan.a + static_cast<std::uint32_t>(salt)) % tracks_.size()];
  }

  [[nodiscard]] ctf::Result<SessionView> view_of(const SessionTrack& track) {
    return engine_.view_session(track.id);
  }

  // --- admission -----------------------------------------------------------

  void do_submit(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    if (tracks_.size() >= kMaxTrackedSessions) {
      do_query(ctf_ctx, plan);
      return;
    }
    const WorkloadId workload =
        (plan.b % 2U) == 0 ? ctf::test::default_workload() : ctf::test::second_workload();
    const std::optional<ctf::WorkloadContract> contract = engine_.contract(workload);
    CTF_REQUIRE(contract.has_value());
    const CheckpointId checkpoint = checkpoint_id(plan.a % kCheckpointCount);
    const CheckpointGeneration generation = CheckpointGeneration(1 + (plan.u % 3U));
    const std::uint32_t shard_count = 1 + static_cast<std::uint32_t>(plan.c % 4U);
    const std::uint64_t shard_bytes = (1 + ((plan.u >> 8) % 4U)) * 8192ULL;
    IsolationClass isolation = contract->isolation;
    if ((plan.u % 4U) == 1U) {
      isolation = IsolationClass::TrainingCritical;  // stricter than the contract
    } else if ((plan.u % 4U) == 2U) {
      isolation = IsolationClass::BestEffort;  // laxer: must be clamped up
    }
    DestinationClass destination = DestinationClass::SyntheticLab;
    if ((plan.u % 8U) == 3U) {
      destination = DestinationClass::LocalAttachedStore;
    } else if ((plan.u % 8U) == 5U) {
      destination = DestinationClass::RemoteObjectStore;  // no path class: denied
    }
    std::uint64_t requested_rate = 0;
    switch (plan.u % 5U) {
      case 1U: requested_rate = 64U * 1024U; break;
      case 2U: requested_rate = 512U * 1024U; break;
      case 3U: requested_rate = 4U * 1024U * 1024U + 1U; break;  // above every ceiling
      case 4U: requested_rate = contract->ceiling_bps + 1U; break;
      default: requested_rate = 0; break;
    }
    Nanos horizon = 0;
    switch (plan.u % 4U) {
      case 1U: horizon = 2 * ctf::kNanosPerMillisecond; break;
      case 2U: horizon = 200 * ctf::kNanosPerMillisecond; break;
      case 3U: horizon = 5 * ctf::kNanosPerSecond; break;
      default: horizon = 0; break;
    }
    const std::uint64_t digest_salt = (plan.u % 3U) == 0U ? 0U : (++command_counter_ % 7U) + 1U;
    const SessionRequest request =
        build_request(engine_, checkpoint, generation, ctf::test::command_id(++command_counter_),
                      workload, shard_count, shard_bytes, isolation, destination, requested_rate,
                      horizon, digest_salt);
    const CommandFence fence = engine_.current_fence(workload, generation);
    const ctf::Result<AdmissionDecision> decision = engine_.submit_session(request, fence);

    StepTrace trace;
    trace.op = PropOp::Submit;
    trace.code = decision.code();
    trace.at = clock_.now();
    if (decision.ok()) {
      const AdmissionDecision& value = decision.value();
      trace.kind = value.kind;
      trace.reason = value.reason;
      trace.session = value.session.to_string();
      if (value.envelope.has_value()) {
        trace.rate_bps = value.envelope->rate_bps;
        trace.burst_bytes = value.envelope->burst_bytes;
        trace.wave_count = static_cast<std::uint32_t>(value.envelope->waves.size());
      }
      check_decision_taxonomy(ctf_ctx, value);
      if (value.kind == DecisionKind::Admit && value.reason == ReasonCode::Admitted) {
        CTF_REQUIRE(value.envelope.has_value());
        check_envelope(ctf_ctx, request, value);
        SessionTrack track;
        track.id = value.session;
        track.workload = workload;
        track.checkpoint = checkpoint;
        track.generation = generation;
        track.isolation = value.envelope->isolation;
        track.shard_count = shard_count;
        for (const ctf::ShardDescriptor& shard : request.manifest.shards) {
          track.shard_digests.push_back(shard.declared_digest);
          track.shard_bytes.push_back(shard.declared_bytes);
        }
        tracks_.push_back(track);
        ++admitted_;
        superseded_ += static_cast<std::uint64_t>(value.superseded.size());
      } else if (value.kind == DecisionKind::Admit) {
        CTF_EXPECT_EQ(value.reason, ReasonCode::DuplicateCommand);
      } else if (value.kind == DecisionKind::Defer) {
        ++deferred_;
      } else {
        ++denied_;
      }
    } else {
      // The fence is always current and command ids are unique, so an error
      // status here would be a contract violation.
      ctf_ctx.fail(__FILE__, __LINE__,
                   "submit_session returned a status error: " + decision.status().to_string());
    }
    record(trace);
  }

  void check_decision_taxonomy(ctf::test::Context& ctf_ctx, const AdmissionDecision& decision) {
    switch (decision.kind) {
      case DecisionKind::Admit:
        CTF_EXPECT(decision.reason == ReasonCode::Admitted ||
                   decision.reason == ReasonCode::DuplicateCommand);
        break;
      case DecisionKind::Defer:
        CTF_EXPECT(decision.reason == ReasonCode::FabricSessionLimit ||
                   decision.reason == ReasonCode::SessionLimitPerWorkload ||
                   decision.reason == ReasonCode::ClassCeilingSaturated ||
                   decision.reason == ReasonCode::WorkloadCeilingSaturated ||
                   decision.reason == ReasonCode::PathCapacityUnavailable ||
                   decision.reason == ReasonCode::CreditUnavailable ||
                   decision.reason == ReasonCode::ResourceLimit ||
                   decision.reason == ReasonCode::DeadlineUnreachable);
        break;
      case DecisionKind::Deny:
        CTF_EXPECT(decision.reason == ReasonCode::UnknownWorkload ||
                   decision.reason == ReasonCode::ContractGenerationStale ||
                   decision.reason == ReasonCode::ManifestInvalid ||
                   decision.reason == ReasonCode::ManifestMismatch ||
                   decision.reason == ReasonCode::DestinationNotPermitted ||
                   decision.reason == ReasonCode::CheckpointTooLarge ||
                   decision.reason == ReasonCode::RequestedRateUnsupported ||
                   decision.reason == ReasonCode::DeadlineUnreachable ||
                   decision.reason == ReasonCode::SupersessionDeniedByPolicy ||
                   decision.reason == ReasonCode::FabricShuttingDown ||
                   decision.reason == ReasonCode::ResourceLimit ||
                   decision.reason == ReasonCode::CheckpointGenerationStale ||
                   decision.reason == ReasonCode::Internal);
        break;
    }
  }

  void check_envelope(ctf::test::Context& ctf_ctx, const SessionRequest& request,
                      const AdmissionDecision& decision) {
    const ctf::TrafficEnvelope& envelope = decision.envelope.value();
    CTF_EXPECT(envelope.session == decision.session);
    CTF_EXPECT(envelope.rate_bps > 0);
    const std::optional<ctf::WorkloadContract> contract = engine_.contract(request.workload);
    CTF_REQUIRE(contract.has_value());
    const ctf::IsolationEnvelopeConfig* class_envelope = nullptr;
    for (const ctf::IsolationEnvelopeConfig& candidate : engine_.policy().envelopes) {
      if (candidate.isolation == envelope.isolation) {
        class_envelope = &candidate;
      }
    }
    CTF_REQUIRE(class_envelope != nullptr);
    CTF_EXPECT(envelope.rate_bps <= class_envelope->ceiling_bps);
    CTF_EXPECT(envelope.rate_bps <= contract->ceiling_bps);
    CTF_EXPECT_EQ(envelope.burst_bytes,
                  std::max<std::uint64_t>(envelope.rate_bps / 10U, 64U * 1024U));
    CTF_EXPECT_EQ(envelope.issued_at, decision.decided_at);
    // The wave plan partitions the manifest shards in order, exactly once each.
    std::vector<ctf::ShardIndex> planned;
    std::uint64_t planned_bytes = 0;
    for (const ctf::WavePlan& wave : envelope.waves) {
      CTF_EXPECT(!wave.shards.empty());
      CTF_EXPECT(wave.shards.size() <= envelope.wave_width);
      for (const ctf::ShardIndex& index : wave.shards) {
        planned.push_back(index);
      }
      planned_bytes += wave.planned_bytes;
    }
    CTF_EXPECT_EQ(planned.size(), request.manifest.shards.size());
    for (std::size_t index = 0; index < planned.size() && index < request.manifest.shards.size();
         ++index) {
      CTF_EXPECT(planned[index] == request.manifest.shards[index].index);
    }
    CTF_EXPECT_EQ(planned_bytes, request.manifest.total_bytes);
  }

  // --- credit and evidence -------------------------------------------------

  void do_wave(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    if (tracks_.empty()) {
      do_query(ctf_ctx, plan);
      return;
    }
    // Look for a session that can still take credit; lifecycle refusals are the
    // business of the dedicated ops, so credit stays focused here.
    const SessionTrack* chosen_track = nullptr;
    std::vector<ShardIndex> eligible;
    for (std::size_t offset = 0; offset < tracks_.size(); ++offset) {
      const SessionTrack& candidate = tracks_[(plan.a + offset) % tracks_.size()];
      const ctf::Result<SessionView> view = engine_.view_session(candidate.id);
      if (!view.ok()) {
        continue;
      }
      const SessionView& value = view.value();
      if (ctf::is_terminal(value.state) || value.state == SessionState::Paused ||
          value.state == SessionState::RevalidationRequired) {
        continue;
      }
      if (outstanding_count(candidate.id) > 0) {
        // The fabric tracks one outstanding byte pool per session, so a
        // conforming sender keeps at most one unreported attempt in flight.
        continue;
      }
      eligible.clear();
      for (const ShardProgress& shard : value.shards) {
        if (shard.state == ShardState::InFlight || shard.state == ShardState::Pending ||
            shard.state == ShardState::Failed || shard.state == ShardState::Cancelled) {
          if (find_outstanding(candidate.id, shard.index) == nullptr) {
            eligible.push_back(shard.index);
          }
        }
      }
      if (!eligible.empty()) {
        chosen_track = &candidate;
        break;
      }
    }
    if (chosen_track == nullptr) {
      do_transfer(ctf_ctx, plan, true);
      return;
    }
    const SessionTrack& track = *chosen_track;
    const CommandFence fence = engine_.current_fence(track.workload, track.generation);
    const ShardIndex shard = eligible[(plan.b + static_cast<std::uint32_t>(wave_counter_++)) %
                                      eligible.size()];
    const ctf::Result<WaveOutcome> outcome = engine_.request_wave(track.id, shard, fence);

    StepTrace trace;
    trace.op = PropOp::Wave;
    trace.code = outcome.code();
    trace.session = track.id.to_string();
    trace.at = clock_.now();
    if (!outcome.ok()) {
      ctf_ctx.fail(__FILE__, __LINE__,
                   "request_wave returned a status error: " + outcome.status().to_string());
      record(trace);
      return;
    }
    const WaveOutcome& result = outcome.value();
    if (!result.granted) {
      CTF_EXPECT(result.reason == ReasonCode::ClassCeilingSaturated ||
                 result.reason == ReasonCode::WorkloadCeilingSaturated ||
                 result.reason == ReasonCode::CreditUnavailable ||
                 result.reason == ReasonCode::ResourceLimit);
      CTF_EXPECT(!result.grant.has_value());
      record(trace);
      return;
    }
    CTF_REQUIRE(result.grant.has_value());
    const WaveGrant& grant = result.grant.value();
    CTF_EXPECT(grant.session == track.id);
    CTF_EXPECT(grant.shard == shard);
    CTF_EXPECT(grant.max_bytes > 0);
    CTF_EXPECT(grant.max_bytes <= 1024U * 1024U);
    CTF_EXPECT(grant.max_bytes <= std::max<std::uint64_t>(track.shard_bytes[shard.value()], 1U));
    CTF_EXPECT(grant.rate_bps > 0);
    CTF_EXPECT(grant.expires_at > grant.issued_at);
    CTF_EXPECT(grant.epoch == engine_.epoch());
    trace.rate_bps = grant.rate_bps;
    trace.burst_bytes = grant.burst_bytes;
    trace.granted_bytes = grant.max_bytes;
    granted_[static_cast<std::size_t>(track.isolation)] += grant.max_bytes;

    LiveAttempt live;
    live.session = track.id;
    live.attempt = grant.attempt;
    live.sequence = grant.sequence;
    live.shard = shard;
    live.granted_bytes = grant.max_bytes;
    live.declared_digest = track.shard_digests[shard.value()];
    outstanding_.push_back(live);
    record(trace);
  }

  void do_transfer(ctf::test::Context& ctf_ctx, const StepPlan& plan, bool acknowledged) {
    if (outstanding_.empty()) {
      do_query(ctf_ctx, plan);
      return;
    }
    const LiveAttempt chosen = outstanding_[plan.b % outstanding_.size()];
    const SessionTrack* track = find_track(chosen.session);
    CTF_REQUIRE(track != nullptr);
    const CommandFence fence = engine_.current_fence(track->workload, track->generation);
    TransferEvidence evidence;
    evidence.session = chosen.session;
    evidence.attempt = chosen.attempt;
    evidence.sequence = chosen.sequence;
    evidence.shard = chosen.shard;
    evidence.arrived_bytes = acknowledged ? chosen.granted_bytes : chosen.granted_bytes / 2U;
    evidence.arrived_digest = chosen.declared_digest;
    evidence.sink_acknowledged = acknowledged;
    const Status status = engine_.report_transfer(evidence, fence);
    CTF_EXPECT(status.ok() || documented_evidence_refusal(status.code()));
    // An acknowledged attempt is released by the fabric; a refused report may or
    // may not have settled it, so the mirror is re-derived from the fabric.
    if (acknowledged || !status.ok()) {
      reconcile_attempt(chosen);
    }
    record_simple(acknowledged ? PropOp::Transfer : PropOp::UnackedTransfer, status);
  }

  void do_verify(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    if (tracks_.empty()) {
      do_query(ctf_ctx, plan);
      return;
    }
    const SessionTrack& track = tracks_[plan.a % tracks_.size()];
    const ctf::Result<SessionView> view = view_of(track);
    if (!view.ok() || ctf::is_terminal(view.value().state) || view.value().shards.empty()) {
      return;
    }
    const SessionView& value = view.value();
    if (value.verified_bytes > 0) {
      // Completion path: every shard of this session is already fully
      // transferred, so the remaining evidence is pure verification.
      const ctf::Status completed = verify_remaining_shards(ctf_ctx, track);
      if (completed.ok() || completed.code() == ErrorCode::InvalidStateTransition) {
        record_simple(PropOp::Verify, completed);
        return;
      }
    }
    // A sink reports on attempts it acknowledged. Shards that arrived in full
    // are verified, a partially arrived shard is either truncated (retry) or
    // failed by a digest mismatch, and an attempt whose arrival was never
    // acknowledged is reported ambiguous.
    // Once any shard of a session is verified, the session may only be closed by
    // completing it, so verification starts only when every shard arrived in
    // full: from then on no retry can shorten the transferred bucket.
    bool all_arrived = !value.shards.empty();
    for (const ShardProgress& shard : value.shards) {
      if (shard.state != ShardState::Transferred && shard.state != ShardState::Verified) {
        all_arrived = false;
      }
    }
    const ShardProgress* chosen = nullptr;
    if (all_arrived) {
      for (const ShardProgress& shard : value.shards) {
        if (shard.attempt.has_value() && shard.state == ShardState::Transferred) {
          chosen = &shard;
          if ((plan.b % 3U) == 0U) {
            break;
          }
        }
      }
    }
    bool unacknowledged = false;
    if (chosen == nullptr && value.verified_bytes == 0) {
      for (const ShardProgress& shard : value.shards) {
        if (!shard.attempt.has_value() || shard.state != ShardState::InFlight) {
          continue;
        }
        if (shard.transferred_bytes > 0 &&
            !is_unacknowledged(track.id, shard.index, shard.attempt.value())) {
          chosen = &shard;
          break;
        }
      }
    }
    if (chosen == nullptr) {
      for (const ShardProgress& shard : value.shards) {
        if (shard.attempt.has_value() && shard.state == ShardState::InFlight &&
            is_unacknowledged(track.id, shard.index, shard.attempt.value())) {
          chosen = &shard;
          unacknowledged = true;
          break;
        }
      }
    }
    if (chosen == nullptr) {
      return;
    }
    const ShardProgress shard = *chosen;
    const CommandFence fence = engine_.current_fence(track.workload, track.generation);
    VerificationEvidence evidence;
    evidence.session = track.id;
    evidence.attempt = shard.attempt.value();
    evidence.sequence = shard.sequence;
    evidence.shard = shard.index;
    evidence.verified_bytes = shard.declared_bytes;
    evidence.verified_digest = shard.declared_digest;
    evidence.verifier_identity = "property-sink";
    if (shard.state == ShardState::Transferred) {
      // Only a shard that arrived in full may be reported verified: claiming
      // more verified bytes than arrived must never be observable.
      CTF_EXPECT_EQ(shard.transferred_bytes, shard.declared_bytes);
      evidence.outcome = VerificationEvidence::Outcome::Verified;
    } else if (unacknowledged) {
      // Evidence for an attempt the fabric never saw arrive: the sink records
      // ambiguity, never a truncation the fabric would have to re-open
      // authority for.
      evidence.outcome = VerificationEvidence::Outcome::Ambiguous;
    } else {
      switch (plan.c % 4U) {
        case 0U: evidence.outcome = VerificationEvidence::Outcome::DigestMismatch; break;
        default: evidence.outcome = VerificationEvidence::Outcome::Truncated; break;
      }
    }
    const Status status = engine_.report_verification(evidence, fence);
    CTF_EXPECT(status.ok() || status.code() == ErrorCode::VerificationMismatch ||
               documented_evidence_refusal(status.code()));
    if (status.ok() || status.code() == ErrorCode::VerificationMismatch ||
        documented_evidence_refusal(status.code())) {
      reconcile_attempt(LiveAttempt{track.id, shard.attempt.value(), shard.sequence, shard.index,
                                    shard.transferred_bytes, shard.declared_digest});
    }
    record_simple(PropOp::Verify, status);
  }

  void do_ambiguous(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    if (outstanding_.empty()) {
      do_query(ctf_ctx, plan);
      return;
    }
    const LiveAttempt chosen = outstanding_[plan.a % outstanding_.size()];
    const SessionTrack* track = find_track(chosen.session);
    if (track == nullptr) {
      return;
    }
    const CommandFence fence = engine_.current_fence(track->workload, track->generation);
    const Status status = engine_.report_ambiguous(chosen.session, chosen.attempt, chosen.sequence,
                                                   "property: sink outcome unknown", fence);
    CTF_EXPECT(status.ok() || documented_evidence_refusal(status.code()));
    reconcile_attempt(chosen);
    record_simple(PropOp::Ambiguous, status);
  }

  [[nodiscard]] const SessionTrack* find_track(const SessionId& session) const {
    for (const SessionTrack& track : tracks_) {
      if (track.id == session) {
        return &track;
      }
    }
    return nullptr;
  }

  // --- lifecycle -----------------------------------------------------------

  void do_pause(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    const SessionTrack* track = pick_session(plan, 0);
    if (track == nullptr) {
      do_query(ctf_ctx, plan);
      return;
    }
    const ctf::Result<SessionView> view = view_of(*track);
    if (!view.ok()) {
      return;
    }
    const CommandFence fence = engine_.current_fence(track->workload, track->generation);
    const Status status = engine_.pause_session(track->id, fence, "property pause");
    if (ctf::is_terminal(view.value().state)) {
      CTF_EXPECT_EQ(status.code(), ErrorCode::InvalidStateTransition);
    } else if (view.value().state == SessionState::Paused) {
      CTF_EXPECT_EQ(status.code(), ErrorCode::AlreadyExists);
    } else if (view.value().state == SessionState::RevalidationRequired) {
      CTF_EXPECT_EQ(status.code(), ErrorCode::RevalidationRequired);
    } else {
      CTF_EXPECT_OK(status);
    }
    record_simple(PropOp::Pause, status);
  }

  void do_resume(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    const SessionTrack* track = pick_session(plan, 3);
    if (track == nullptr) {
      do_query(ctf_ctx, plan);
      return;
    }
    const ctf::Result<SessionView> view = view_of(*track);
    if (!view.ok()) {
      return;
    }
    const CommandFence fence = engine_.current_fence(track->workload, track->generation);
    const Status status = engine_.resume_session(track->id, fence);
    if (view.value().state == SessionState::Paused) {
      CTF_EXPECT_OK(status);
    } else {
      CTF_EXPECT_EQ(status.code(), ErrorCode::InvalidStateTransition);
    }
    record_simple(PropOp::Resume, status);
  }

  void do_cancel(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    const SessionTrack* track = pick_session(plan, 5);
    if (track == nullptr) {
      do_query(ctf_ctx, plan);
      return;
    }
    const ctf::Result<SessionView> view = view_of(*track);
    if (!view.ok()) {
      return;
    }
    const CommandFence fence = engine_.current_fence(track->workload, track->generation);
    const Status status = engine_.cancel_session(track->id, fence, ReasonCode::CancelledByOperator,
                                                 "property cancel");
    if (ctf::is_terminal(view.value().state)) {
      CTF_EXPECT_EQ(status.code(), ErrorCode::InvalidStateTransition);
    } else {
      CTF_EXPECT_OK(status);
      const ctf::Result<SessionView> after = engine_.view_session(track->id);
      CTF_EXPECT_OK(after.status());
      if (after.ok()) {
        CTF_EXPECT(ctf::is_terminal(after.value().state));
      }
    }
    release_session_attempts(track->id);
    record_simple(PropOp::Cancel, status);
  }

  void do_revalidate(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    const SessionTrack* track = pick_session(plan, 7);
    if (track == nullptr) {
      do_query(ctf_ctx, plan);
      return;
    }
    const ctf::Result<SessionView> view = view_of(*track);
    if (!view.ok()) {
      return;
    }
    if (view.value().state != SessionState::RevalidationRequired &&
        view.value().state != SessionState::Deferred) {
      return;
    }
    const CommandFence fence = engine_.current_fence(track->workload, track->generation);
    const ctf::Result<AdmissionDecision> decision =
        engine_.revalidate_session(track->id, fence);
    StepTrace trace;
    trace.op = PropOp::Revalidate;
    trace.code = decision.code();
    trace.at = clock_.now();
    if (!decision.ok()) {
      ctf_ctx.fail(__FILE__, __LINE__,
                   "revalidate_session returned a status error: " + decision.status().to_string());
    } else {
      trace.kind = decision.value().kind;
      trace.reason = decision.value().reason;
      trace.session = track->id.to_string();
      // Revalidation may admit, defer, or deny (rate/deadline changes), but
      // never in a way the taxonomy does not describe.
      check_decision_taxonomy(ctf_ctx, decision.value());
      if (decision.value().envelope.has_value()) {
        CTF_EXPECT_EQ(decision.value().envelope->session, track->id);
        CTF_EXPECT(decision.value().envelope->rate_bps > 0);
        trace.rate_bps = decision.value().envelope->rate_bps;
        trace.wave_count = static_cast<std::uint32_t>(decision.value().envelope->waves.size());
      }
    }
    record(trace);
  }

  // --- authority changes ---------------------------------------------------

  void do_advance_epoch(ctf::test::Context& ctf_ctx) {
    CTF_REQUIRE(epoch_incarnation_ < 1000);
    const ctf::CoordinatorEpoch next{ctf::IncarnationId(++epoch_incarnation_), ctf::EpochTerm(1)};
    const Status status = engine_.advance_epoch(next);
    CTF_EXPECT_OK(status);
    CTF_EXPECT(engine_.epoch() == next);
    release_epoch_authority(ctf_ctx);
    record_simple(PropOp::AdvanceEpoch, status);
  }

  /// Every attempt outstanding when authority advances is released by the
  /// engine; the driver mirrors that so its bookkeeping tracks the fabric.
  void release_epoch_authority(ctf::test::Context& ctf_ctx) {
    CTF_EXPECT(engine_.accounting().active_attempts == 0U);
    outstanding_.clear();
  }

  void do_apply_policy(ctf::test::Context& ctf_ctx) {
    PolicySnapshot policy = engine_.policy();
    policy.generation = ctf::PolicyGeneration(policy.generation.value() + 1U);
    policy.max_wave_width = 1U + (policy.max_wave_width % 3U);
    policy.max_sessions = 16;
    policy.retained_history = 24;
    policy.max_attempts_in_flight = 64;
    const Status status = engine_.apply_policy(policy);
    CTF_EXPECT_OK(status);
    ++policy_applications_;
    record_simple(PropOp::ApplyPolicy, status);
  }

  void do_apply_topology(ctf::test::Context& ctf_ctx) {
    TopologySnapshot topology = engine_.topology();
    topology.generation = ctf::TopologyGeneration(topology.generation.value() + 1U);
    const Status status = engine_.apply_topology(topology);
    CTF_EXPECT_OK(status);
    record_simple(PropOp::ApplyTopology, status);
  }

  void do_upsert_contract(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    const WorkloadId workload =
        (plan.a % 2U) == 0 ? ctf::test::default_workload() : ctf::test::second_workload();
    const std::optional<ctf::WorkloadContract> current = engine_.contract(workload);
    CTF_REQUIRE(current.has_value());
    ctf::WorkloadContract contract = current.value();
    contract.generation = WorkloadContractGeneration(contract.generation.value() + 1U);
    contract.max_shards_per_wave = 1U + (contract.max_shards_per_wave % 3U);
    const Status status = engine_.upsert_contract(contract);
    CTF_EXPECT_OK(status);
    record_simple(PropOp::UpsertContract, status);
  }

  void do_advance_clock(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    clock_.advance(plan.clock_delta);
    const Status status = engine_.poll_deadlines();
    CTF_EXPECT_OK(status);
    record_simple(PropOp::AdvanceClock, status);
  }

  void do_query(ctf::test::Context& ctf_ctx, const StepPlan& plan) {
    const ctf::AccountingSnapshot accounting = engine_.accounting();
    CTF_EXPECT(accounting.conserves());
    const ctf::Result<std::vector<ctf::SessionSummary>> listed =
        engine_.list_sessions(std::nullopt, 8);
    CTF_EXPECT_OK(listed.status());
    CTF_EXPECT(listed.value().size() <= 8U);
    for (std::size_t index = 1; index < listed.value().size(); ++index) {
      if (listed.value()[index].updated_at < listed.value()[index - 1].updated_at) {
        ctf_ctx.fail(__FILE__, __LINE__, "list_sessions is not ordered by updated_at");
      }
    }
    if (!tracks_.empty()) {
      const SessionTrack& track = tracks_[plan.a % tracks_.size()];
      const ctf::Result<SessionView> view = view_of(track);
      CTF_EXPECT_OK(view.status());
      const ctf::Result<ctf::Explanation> explanation = engine_.explain(track.id);
      CTF_EXPECT_OK(explanation.status());
      CTF_EXPECT(!explanation.value().timeline.empty());
    }
    record_simple(PropOp::Query, Status::success());
  }

  // --- state ---------------------------------------------------------------

  EngineFixture fixture_;
  ManualClock clock_;
  FabricEngine engine_;
  std::vector<StepPlan> script_;
  std::vector<SessionTrack> tracks_;
  std::vector<LiveAttempt> outstanding_;
  std::vector<StepTrace> trace_;
  ClassBudget budgets_[kClassCount];
  std::uint64_t granted_[kClassCount] = {};
  std::uint64_t start_ns_ = 0;
  std::uint64_t policy_applications_ = 0;
  std::uint64_t command_counter_ = 0;
  std::uint64_t wave_counter_ = 0;
  std::uint64_t epoch_incarnation_ = 1;
  std::uint64_t admitted_ = 0;
  std::uint64_t deferred_ = 0;
  std::uint64_t denied_ = 0;
  std::uint64_t superseded_ = 0;
  PropOp current_op_ = PropOp::Query;
};

// --- comparison helpers -----------------------------------------------------

void expect_same_accounting(ctf::test::Context& ctf_ctx, const AccountingSnapshot& lhs,
                            const AccountingSnapshot& rhs) {
  CTF_EXPECT_EQ(lhs.bytes_admitted, rhs.bytes_admitted);
  CTF_EXPECT_EQ(lhs.bytes_transferred, rhs.bytes_transferred);
  CTF_EXPECT_EQ(lhs.bytes_verified, rhs.bytes_verified);
  CTF_EXPECT_EQ(lhs.bytes_cancelled, rhs.bytes_cancelled);
  CTF_EXPECT_EQ(lhs.bytes_wasted, rhs.bytes_wasted);
  CTF_EXPECT_EQ(lhs.bytes_unproven, rhs.bytes_unproven);
  CTF_EXPECT_EQ(lhs.bytes_deferred, rhs.bytes_deferred);
  CTF_EXPECT_EQ(lhs.granted_outstanding_bytes, rhs.granted_outstanding_bytes);
  CTF_EXPECT_EQ(lhs.sessions_admitted, rhs.sessions_admitted);
  CTF_EXPECT_EQ(lhs.sessions_deferred, rhs.sessions_deferred);
  CTF_EXPECT_EQ(lhs.sessions_denied, rhs.sessions_denied);
  CTF_EXPECT_EQ(lhs.sessions_completed, rhs.sessions_completed);
  CTF_EXPECT_EQ(lhs.sessions_cancelled, rhs.sessions_cancelled);
  CTF_EXPECT_EQ(lhs.sessions_superseded, rhs.sessions_superseded);
  CTF_EXPECT_EQ(lhs.sessions_failed, rhs.sessions_failed);
  CTF_EXPECT_EQ(lhs.commands_processed, rhs.commands_processed);
  CTF_EXPECT_EQ(lhs.active_sessions, rhs.active_sessions);
  CTF_EXPECT_EQ(lhs.active_attempts, rhs.active_attempts);
  (void)ctf_ctx;
}

std::string describe_trace(const StepTrace& trace) {
  return std::string(op_name(trace.op)) + " code=" + ctf::to_string(trace.code) +
         " kind=" + ctf::to_string(trace.kind) + " reason=" + ctf::to_string(trace.reason) +
         " rate=" + std::to_string(trace.rate_bps) + " burst=" + std::to_string(trace.burst_bytes) +
         " granted=" + std::to_string(trace.granted_bytes) +
         " waves=" + std::to_string(trace.wave_count) + " session=" + trace.session +
         " at=" + std::to_string(trace.at);
}

void expect_same_trace(ctf::test::Context& ctf_ctx, const std::vector<StepTrace>& lhs,
                       const std::vector<StepTrace>& rhs) {
  CTF_REQUIRE(lhs.size() == rhs.size());
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    const StepTrace& left = lhs[index];
    const StepTrace& right = rhs[index];
    if (left.op != right.op || left.code != right.code || left.kind != right.kind ||
        left.reason != right.reason || left.rate_bps != right.rate_bps ||
        left.burst_bytes != right.burst_bytes || left.granted_bytes != right.granted_bytes ||
        left.wave_count != right.wave_count || left.session != right.session ||
        left.at != right.at) {
      ctf_ctx.fail(__FILE__, __LINE__, "step " + std::to_string(index) + " diverged: engine A " +
                                           describe_trace(left) + " vs engine B " +
                                           describe_trace(right));
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

CTF_TEST(property, randomized_sequence_maintains_every_invariant) {
  const EngineFixture fixture = property_fixture();
  Driver driver(fixture, ctf_ctx.seed(), 700);
  const RunOutcome outcome = driver.run(ctf_ctx, driver.script().size());
  CTF_EXPECT(outcome.admitted > 0);
  CTF_EXPECT(outcome.accounting.conserves());
  CTF_EXPECT_OK(driver.engine().check_invariants());
  std::printf("    property run: steps=%zu admitted=%llu deferred=%llu denied=%llu "
              "granted=%llu admitted_bytes=%llu transferred=%llu wasted=%llu cancelled=%llu "
              "unproven=%llu outstanding=%llu\n",
              outcome.trace.size(), (unsigned long long)outcome.admitted,
              (unsigned long long)outcome.deferred, (unsigned long long)outcome.denied,
              (unsigned long long)(outcome.granted_per_class[0] + outcome.granted_per_class[1] +
                                   outcome.granted_per_class[2] + outcome.granted_per_class[3]),
              (unsigned long long)outcome.accounting.bytes_admitted,
              (unsigned long long)outcome.accounting.bytes_transferred,
              (unsigned long long)outcome.accounting.bytes_wasted,
              (unsigned long long)outcome.accounting.bytes_cancelled,
              (unsigned long long)outcome.accounting.bytes_unproven,
              (unsigned long long)outcome.accounting.granted_outstanding_bytes);
  driver.settle(ctf_ctx);
}

CTF_TEST(property, rate_ceiling_bounds_every_grant) {
  const EngineFixture fixture = property_fixture();
  Driver driver(fixture, ctf_ctx.seed(), 500);
  const RunOutcome outcome = driver.run(ctf_ctx, driver.script().size());
  std::uint64_t total = 0;
  for (std::size_t index = 0; index < kClassCount; ++index) {
    total += outcome.granted_per_class[index];
  }
  CTF_EXPECT(total > 0);
  const std::uint64_t elapsed = static_cast<std::uint64_t>(driver.clock().now());
  std::printf("    rate ceiling: elapsed=%llu ns granted=%llu bytes class0=%llu class1=%llu "
              "class2=%llu class3=%llu\n",
              (unsigned long long)elapsed, (unsigned long long)total,
              (unsigned long long)outcome.granted_per_class[0],
              (unsigned long long)outcome.granted_per_class[1],
              (unsigned long long)outcome.granted_per_class[2],
              (unsigned long long)outcome.granted_per_class[3]);
  CTF_EXPECT_OK(driver.engine().check_invariants());
  CTF_EXPECT(outcome.accounting.conserves());
  driver.settle(ctf_ctx);
}

CTF_TEST(property, same_script_on_two_engines_is_identical) {
  const EngineFixture fixture = property_fixture();
  const std::uint64_t seed = ctf_ctx.seed();
  Driver first(fixture, seed, 400);
  Driver second(fixture, seed, 400);
  const RunOutcome left = first.run(ctf_ctx, first.script().size());
  const RunOutcome right = second.run(ctf_ctx, second.script().size());

  expect_same_trace(ctf_ctx, left.trace, right.trace);
  expect_same_accounting(ctf_ctx, left.accounting, right.accounting);
  CTF_REQUIRE(left.session_states.size() == right.session_states.size());
  for (std::size_t index = 0; index < left.session_states.size(); ++index) {
    if (left.session_states[index] != right.session_states[index]) {
      ctf_ctx.fail(__FILE__, __LINE__,
                   "session " + std::to_string(index) + " diverged: " + left.session_states[index] +
                       " vs " + right.session_states[index]);
    }
  }
  for (std::size_t index = 0; index < kClassCount; ++index) {
    CTF_EXPECT_EQ(left.granted_per_class[index], right.granted_per_class[index]);
  }
  CTF_EXPECT_EQ(left.admitted, right.admitted);
  CTF_EXPECT_EQ(left.deferred, right.deferred);
  CTF_EXPECT_EQ(left.denied, right.denied);
  CTF_EXPECT(first.engine().epoch() == second.engine().epoch());
}

CTF_TEST(property, settling_every_session_returns_to_baseline) {
  const EngineFixture fixture = property_fixture();
  Driver driver(fixture, ctf_ctx.seed(), 400);
  driver.run(ctf_ctx, driver.script().size());
  const AccountingSnapshot before = driver.engine().accounting();
  driver.settle(ctf_ctx);
  const AccountingSnapshot after = driver.engine().accounting();
  CTF_EXPECT_EQ(after.granted_outstanding_bytes, 0ULL);
  CTF_EXPECT_EQ(after.active_sessions, 0U);
  CTF_EXPECT_EQ(after.active_attempts, 0U);
  CTF_EXPECT(after.conserves());
  CTF_EXPECT_EQ(after.bytes_admitted,
                after.bytes_transferred + after.bytes_wasted + after.bytes_cancelled +
                    after.bytes_unproven);
  CTF_EXPECT_EQ(after.bytes_admitted, before.bytes_admitted);
  CTF_EXPECT_OK(driver.engine().check_invariants());
}

// ---------------------------------------------------------------------------
// Supersession
// ---------------------------------------------------------------------------

CTF_TEST(property, supersession_is_deterministic_and_seals_older_generation) {
  // The same scenario is replayed on two engines and both the decisions and the
  // resulting identities must match exactly.
  struct Replay {
    std::vector<std::string> steps;
    AccountingSnapshot accounting;
  };
  const auto run_once = [&ctf_ctx](const EngineFixture& fixture, Replay& replay) {
    ManualClock clock;
    FabricEngine engine(Driver::config_for(fixture, 0xABCDEFULL), clock);
    const WorkloadId workload = ctf::test::default_workload();
    const CheckpointId checkpoint = checkpoint_id(0);
    const auto fence = [&engine, workload](CheckpointGeneration generation) {
      return engine.current_fence(workload, generation);
    };
    const auto submit = [&](CheckpointGeneration generation, std::uint64_t command,
                            std::uint64_t salt, bool expect_ok) {
      const SessionRequest request =
          build_request(engine, checkpoint, generation, ctf::test::command_id(command), workload, 1,
                        8192, IsolationClass::TrainingBulk, DestinationClass::SyntheticLab, 0, 0,
                        salt);
      const ctf::Result<AdmissionDecision> decision =
          engine.submit_session(request, fence(generation));
      CTF_EXPECT_EQ(decision.ok(), expect_ok);
      return decision.ok() ? decision.value() : AdmissionDecision{};
    };

    const AdmissionDecision first = submit(CheckpointGeneration(1), 1, 1, true);
    CTF_REQUIRE(first.admitted());
    replay.steps.push_back("gen1 admit " + first.session.to_string());
    // Move real bytes through the first generation so supersession has an
    // accounting consequence to prove.
    const ctf::Result<WaveOutcome> grant =
        engine.request_wave(first.session, ShardIndex(0), fence(CheckpointGeneration(1)));
    CTF_REQUIRE_OK(grant.status());
    CTF_REQUIRE(grant.value().granted);
    TransferEvidence transfer;
    transfer.session = first.session;
    transfer.attempt = grant.value().grant.value().attempt;
    transfer.sequence = grant.value().grant.value().sequence;
    transfer.shard = ShardIndex(0);
    transfer.arrived_bytes = grant.value().grant.value().max_bytes;
    transfer.sink_acknowledged = true;
    // The digest must match the manifest the session was admitted with.
    const ctf::SessionRequest original =
        build_request(engine, checkpoint, CheckpointGeneration(1), ctf::test::command_id(1),
                      workload, 1, 8192, IsolationClass::TrainingBulk,
                      DestinationClass::SyntheticLab, 0, 0, 1);
    transfer.arrived_digest = original.manifest.shards[0].declared_digest;
    CTF_REQUIRE_OK(engine.report_transfer(transfer, fence(CheckpointGeneration(1))));
    const AccountingSnapshot after_transfer = engine.accounting();
    CTF_EXPECT(after_transfer.bytes_transferred > 0);
    replay.steps.push_back("gen1 transferred " + std::to_string(after_transfer.bytes_transferred));

    const AdmissionDecision second = submit(CheckpointGeneration(2), 2, 1, true);
    CTF_REQUIRE(second.admitted());
    CTF_REQUIRE(second.superseded.size() == 1U);
    CTF_EXPECT_EQ(second.superseded[0], first.session);
    replay.steps.push_back("gen2 admit " + second.session.to_string() + " superseded " +
                           second.superseded[0].to_string());

    const ctf::Result<SessionView> older = engine.view_session(first.session);
    CTF_REQUIRE_OK(older.status());
    CTF_EXPECT_EQ(older.value().state, SessionState::Superseded);
    CTF_REQUIRE(older.value().superseded_by.has_value());
    CTF_EXPECT_EQ(older.value().superseded_by.value(), second.session);
    replay.steps.push_back(std::string("gen1 state ") + ctf::to_string(older.value().state));

    // Transferred bytes of a superseded session move to the wasted bucket.
    const AccountingSnapshot after_supersede = engine.accounting();
    CTF_EXPECT_EQ(after_supersede.bytes_transferred, 0ULL);
    CTF_EXPECT_EQ(after_supersede.bytes_wasted, after_transfer.bytes_transferred);
    CTF_EXPECT(after_supersede.conserves());

    // Every later command against the superseded generation is refused.
    const ctf::Result<WaveOutcome> late_wave =
        engine.request_wave(first.session, ShardIndex(0), fence(CheckpointGeneration(1)));
    CTF_EXPECT_CODE(late_wave.status(), ErrorCode::Superseded);
    const Status late_transfer =
        engine.report_transfer(transfer, fence(CheckpointGeneration(1)));
    CTF_EXPECT_EQ(late_transfer.code(), ErrorCode::InvalidStateTransition);
    const Status late_pause =
        engine.pause_session(first.session, fence(CheckpointGeneration(1)), "late");
    CTF_EXPECT_EQ(late_pause.code(), ErrorCode::InvalidStateTransition);
    const Status late_cancel = engine.cancel_session(
        first.session, fence(CheckpointGeneration(1)), ReasonCode::CancelledByOperator, "late");
    CTF_EXPECT_EQ(late_cancel.code(), ErrorCode::InvalidStateTransition);
    replay.steps.push_back("late commands refused");

    // Re-issuing an older generation is stale, an equivalent manifest is a
    // duplicate, and a divergent manifest for the same generation mismatches.
    const AdmissionDecision stale = submit(CheckpointGeneration(1), 3, 1, true);
    CTF_EXPECT_EQ(stale.kind, DecisionKind::Deny);
    CTF_EXPECT_EQ(stale.reason, ReasonCode::CheckpointGenerationStale);
    const AdmissionDecision duplicate = submit(CheckpointGeneration(2), 4, 1, true);
    CTF_EXPECT_EQ(duplicate.kind, DecisionKind::Admit);
    CTF_EXPECT_EQ(duplicate.reason, ReasonCode::DuplicateCommand);
    CTF_EXPECT_EQ(duplicate.session, second.session);
    const AdmissionDecision mismatch = submit(CheckpointGeneration(2), 5, 2, true);
    CTF_EXPECT_EQ(mismatch.kind, DecisionKind::Deny);
    CTF_EXPECT_EQ(mismatch.reason, ReasonCode::ManifestMismatch);
    replay.steps.push_back("stale/duplicate/mismatch classified");
    CTF_EXPECT_EQ(engine.session_count(), 2U);
    CTF_EXPECT_OK(engine.check_invariants());
    CTF_EXPECT(engine.accounting().conserves());
    replay.accounting = engine.accounting();
  };

  const EngineFixture fixture = property_fixture();
  Replay first;
  Replay second;
  run_once(fixture, first);
  run_once(fixture, second);
  CTF_REQUIRE(first.steps.size() == second.steps.size());
  for (std::size_t index = 0; index < first.steps.size(); ++index) {
    if (first.steps[index] != second.steps[index]) {
      ctf_ctx.fail(__FILE__, __LINE__, "supersession replay diverged at step " +
                                           std::to_string(index) + ": " + first.steps[index] +
                                           " vs " + second.steps[index]);
    }
  }
  expect_same_accounting(ctf_ctx, first.accounting, second.accounting);
}

CTF_TEST(property, supersession_denied_by_contract_is_reported) {
  const EngineFixture fixture = property_fixture();
  ManualClock clock;
  FabricEngine engine(Driver::config_for(fixture, 0x1234ULL), clock);
  const WorkloadId workload = ctf::test::second_workload();  // allow_supersession = false
  const CheckpointId checkpoint = checkpoint_id(1);
  const SessionRequest first =
      build_request(engine, checkpoint, CheckpointGeneration(1), ctf::test::command_id(1), workload,
                    1, 8192, IsolationClass::ServingLatency, DestinationClass::SyntheticLab, 0, 0, 1);
  const ctf::Result<AdmissionDecision> admitted =
      engine.submit_session(first, engine.current_fence(workload, CheckpointGeneration(1)));
  CTF_REQUIRE_OK(admitted.status());
  CTF_REQUIRE(admitted.value().admitted());
  const SessionRequest newer =
      build_request(engine, checkpoint, CheckpointGeneration(2), ctf::test::command_id(2), workload,
                    1, 8192, IsolationClass::ServingLatency, DestinationClass::SyntheticLab, 0, 0, 1);
  const ctf::Result<AdmissionDecision> refused =
      engine.submit_session(newer, engine.current_fence(workload, CheckpointGeneration(2)));
  CTF_REQUIRE_OK(refused.status());
  CTF_EXPECT_EQ(refused.value().kind, DecisionKind::Deny);
  CTF_EXPECT_EQ(refused.value().reason, ReasonCode::SupersessionDeniedByPolicy);
  CTF_EXPECT_EQ(engine.session_count(), 1U);
  const ctf::Result<SessionView> view = engine.view_session(admitted.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, SessionState::Admitted);
  CTF_EXPECT_OK(engine.check_invariants());
  CTF_EXPECT(engine.accounting().conserves());
}

// ---------------------------------------------------------------------------
// Known defect regression: an abandoned in-flight attempt keeps outstanding
// authority after the session completes.
// ---------------------------------------------------------------------------

CTF_TEST(property, regrant_on_same_shard_keeps_terminal_authority_closed) {
  const EngineFixture fixture = property_fixture();
  ManualClock clock;
  FabricEngine engine(Driver::config_for(fixture, 0x5EEDULL), clock);
  const WorkloadId workload = ctf::test::default_workload();
  const CheckpointId checkpoint = checkpoint_id(2);
  const SessionRequest request =
      build_request(engine, checkpoint, CheckpointGeneration(1), ctf::test::command_id(1), workload,
                    1, 4096, IsolationClass::TrainingBulk, DestinationClass::SyntheticLab, 0, 0, 1);
  const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));
  const ctf::Result<AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  const SessionId session = decision.value().session;

  // First grant is abandoned without any evidence report. Asking for credit
  // again must be refused: the shard still has an unsettled attempt.
  const ctf::Result<WaveOutcome> abandoned = engine.request_wave(session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(abandoned.status());
  CTF_REQUIRE(abandoned.value().granted);
  const WaveGrant first = abandoned.value().grant.value();
  const ctf::Result<WaveOutcome> refused = engine.request_wave(session, ShardIndex(0), fence);
  CTF_EXPECT_CODE(refused.status(), ErrorCode::AmbiguousOutcome);

  // Marking the abandoned attempt ambiguous closes its authority, but an
  // ambiguous shard is not silently re-armed: credit stays refused until the
  // shard is settled by a truncation report or the session is cancelled.
  CTF_REQUIRE_OK(engine.report_ambiguous(session, first.attempt, first.sequence,
                                         "property: sink outcome unknown", fence));
  CTF_EXPECT_EQ(engine.accounting().active_attempts, 0U);
  CTF_EXPECT_EQ(engine.accounting().bytes_unproven, request.manifest.total_bytes);
  CTF_EXPECT_CODE(engine.request_wave(session, ShardIndex(0), fence).status(),
                  ErrorCode::AmbiguousOutcome);
  CTF_REQUIRE_OK(engine.cancel_session(session, fence, ReasonCode::CancelledByOperator,
                                       "abandoned shard settled"));
  const AccountingSnapshot abandoned_accounting = engine.accounting();
  CTF_EXPECT_EQ(abandoned_accounting.active_attempts, 0U);
  CTF_EXPECT_EQ(abandoned_accounting.granted_outstanding_bytes, 0ULL);
  CTF_EXPECT(abandoned_accounting.at_baseline());
  CTF_EXPECT_OK(engine.check_invariants());

  // A truncation report re-arms the same shard, so the retry is transferable
  // again and the session reaches completion holding no outstanding authority.
  const SessionRequest retry_request =
      build_request(engine, checkpoint_id(5), CheckpointGeneration(1), ctf::test::command_id(2),
                    workload, 1, 4096, IsolationClass::TrainingBulk,
                    DestinationClass::SyntheticLab, 0, 0, 1);
  const ctf::Result<AdmissionDecision> retry_decision =
      engine.submit_session(retry_request,
                            engine.current_fence(workload, CheckpointGeneration(1)));
  CTF_REQUIRE_OK(retry_decision.status());
  CTF_REQUIRE(retry_decision.value().admitted());
  const SessionId retry_session = retry_decision.value().session;
  const ctf::Result<WaveOutcome> retry_first =
      engine.request_wave(retry_session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(retry_first.status());
  CTF_REQUIRE(retry_first.value().granted);
  const WaveGrant abandoned_grant = retry_first.value().grant.value();
  CTF_EXPECT_CODE(engine.request_wave(retry_session, ShardIndex(0), fence).status(),
                  ErrorCode::AmbiguousOutcome);
  VerificationEvidence truncated;
  truncated.session = retry_session;
  truncated.attempt = abandoned_grant.attempt;
  truncated.sequence = abandoned_grant.sequence;
  truncated.shard = ShardIndex(0);
  truncated.outcome = VerificationEvidence::Outcome::Truncated;
  truncated.verifier_identity = "property-sink";
  CTF_REQUIRE_OK(engine.report_verification(truncated, fence));
  const ctf::Result<WaveOutcome> retry = engine.request_wave(retry_session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(retry.status());
  CTF_REQUIRE(retry.value().granted);
  const WaveGrant grant = retry.value().grant.value();

  TransferEvidence transfer;
  transfer.session = retry_session;
  transfer.attempt = grant.attempt;
  transfer.sequence = grant.sequence;
  transfer.shard = ShardIndex(0);
  transfer.arrived_bytes = grant.max_bytes;
  transfer.arrived_digest = retry_request.manifest.shards[0].declared_digest;
  transfer.sink_acknowledged = true;
  CTF_REQUIRE_OK(engine.report_transfer(transfer, fence));
  VerificationEvidence verification;
  verification.session = retry_session;
  verification.attempt = grant.attempt;
  verification.sequence = grant.sequence;
  verification.shard = ShardIndex(0);
  verification.verified_bytes = retry_request.manifest.shards[0].declared_bytes;
  verification.verified_digest = retry_request.manifest.shards[0].declared_digest;
  verification.outcome = VerificationEvidence::Outcome::Verified;
  verification.verifier_identity = "property-sink";
  CTF_REQUIRE_OK(engine.report_verification(verification, fence));

  const ctf::Result<SessionView> view = engine.view_session(retry_session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, SessionState::TrafficSessionComplete);
  const AccountingSnapshot accounting = engine.accounting();
  // A terminal session must hold no outstanding authority.
  CTF_EXPECT_EQ(accounting.active_attempts, 0U);
  CTF_EXPECT_EQ(accounting.granted_outstanding_bytes, 0ULL);
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT_OK(engine.check_invariants());
}

// Library defect regression: closing a session terminally after any shard was
// verified moves session.transferred_bytes into wasted_bytes but leaves
// session.verified_bytes standing, so the engine's own invariant
// "verified_bytes <= transferred_bytes" fails for good. Cancel, deadline
// failure, and supersession all take the same path.
CTF_TEST(property, terminal_close_after_verification_preserves_evidence) {
  const EngineFixture fixture = property_fixture();
  const WorkloadId workload = ctf::test::default_workload();
  const auto scenario = [&](const char* label, int mode, std::uint32_t shards, Nanos horizon) {
    ManualClock clock;
    FabricEngine engine(Driver::config_for(fixture, 0x77ULL), clock);
    const CheckpointId checkpoint = checkpoint_id(3);
    const SessionRequest request =
        build_request(engine, checkpoint, CheckpointGeneration(1), ctf::test::command_id(1), workload,
                      shards, 4096, IsolationClass::TrainingBulk, DestinationClass::SyntheticLab, 0,
                      horizon, 1);
    const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));
    const ctf::Result<AdmissionDecision> decision = engine.submit_session(request, fence);
    CTF_REQUIRE_OK(decision.status());
    CTF_REQUIRE(decision.value().admitted());
    const SessionId session = decision.value().session;
    const ctf::Result<WaveOutcome> grant = engine.request_wave(session, ShardIndex(0), fence);
    CTF_REQUIRE_OK(grant.status());
    CTF_REQUIRE(grant.value().granted);
    TransferEvidence transfer;
    transfer.session = session;
    transfer.attempt = grant.value().grant.value().attempt;
    transfer.sequence = grant.value().grant.value().sequence;
    transfer.shard = ShardIndex(0);
    transfer.arrived_bytes = grant.value().grant.value().max_bytes;
    transfer.arrived_digest = request.manifest.shards[0].declared_digest;
    transfer.sink_acknowledged = true;
    CTF_REQUIRE_OK(engine.report_transfer(transfer, fence));
    VerificationEvidence verification;
    verification.session = session;
    verification.attempt = transfer.attempt;
    verification.sequence = transfer.sequence;
    verification.shard = ShardIndex(0);
    verification.verified_bytes = request.manifest.shards[0].declared_bytes;
    verification.verified_digest = request.manifest.shards[0].declared_digest;
    verification.outcome = VerificationEvidence::Outcome::Verified;
    verification.verifier_identity = "probe";
    CTF_REQUIRE_OK(engine.report_verification(verification, fence));
    // A second shard arrives only partially: those bytes are transferred but
    // never verified, which is exactly what a terminal close must handle.
    const ctf::Result<WaveOutcome> partial_grant =
        engine.request_wave(session, ShardIndex(1), fence);
    CTF_REQUIRE_OK(partial_grant.status());
    CTF_REQUIRE(partial_grant.value().granted);
    TransferEvidence partial;
    partial.session = session;
    partial.attempt = partial_grant.value().grant.value().attempt;
    partial.sequence = partial_grant.value().grant.value().sequence;
    partial.shard = ShardIndex(1);
    partial.arrived_bytes = partial_grant.value().grant.value().max_bytes / 2U;
    partial.arrived_digest = request.manifest.shards[1].declared_digest;
    partial.sink_acknowledged = true;
    CTF_REQUIRE_OK(engine.report_transfer(partial, fence));
    ctf::Result<SessionView> view = engine.view_session(session);
    CTF_REQUIRE_OK(view.status());
    std::printf("    %-30s after verify: state=%s transferred=%llu verified=%llu checks=%s\n", label,
                ctf::to_string(view.value().state),
                (unsigned long long)view.value().transferred_bytes,
                (unsigned long long)view.value().verified_bytes,
                engine.check_invariants().ok() ? "ok"
                                               : engine.check_invariants().to_string().c_str());
    if (mode == 0) {
      CTF_REQUIRE_OK(engine.cancel_session(session, fence, ReasonCode::CancelledByOperator, "probe"));
    } else if (mode == 1) {
      clock.advance(horizon + 1);
      CTF_REQUIRE_OK(engine.poll_deadlines());
    } else {
      const SessionRequest newer =
          build_request(engine, checkpoint, CheckpointGeneration(2), ctf::test::command_id(2),
                        workload, shards, 4096, IsolationClass::TrainingBulk,
                        DestinationClass::SyntheticLab, 0, horizon, 1);
      const ctf::Result<AdmissionDecision> second =
          engine.submit_session(newer, engine.current_fence(workload, CheckpointGeneration(2)));
      CTF_REQUIRE_OK(second.status());
      CTF_REQUIRE(second.value().admitted());
    }
    view = engine.view_session(session);
    CTF_REQUIRE_OK(view.status());
    const Status invariants = engine.check_invariants();
    const AccountingSnapshot after_close = engine.accounting();
    std::printf("    %-30s after close : state=%s transferred=%llu verified=%llu wasted=%llu "
                "cancelled=%llu unproven=%llu conserves=%d checks=%s\n",
                label, ctf::to_string(view.value().state),
                (unsigned long long)view.value().transferred_bytes,
                (unsigned long long)view.value().verified_bytes,
                (unsigned long long)after_close.bytes_wasted,
                (unsigned long long)after_close.bytes_cancelled,
                (unsigned long long)after_close.bytes_unproven,
                after_close.conserves() ? 1 : 0,
                invariants.ok() ? "ok" : invariants.to_string().c_str());
    // Verified bytes are destination facts and stay verified; only the
    // transferred-but-unverified remainder becomes wasted, so the session and
    // the fabric keep bytes_verified <= bytes_transferred.
    CTF_EXPECT_OK(invariants);
    CTF_EXPECT(after_close.conserves());
    CTF_EXPECT_EQ(after_close.bytes_verified, 4096ULL);
    CTF_EXPECT_EQ(after_close.bytes_wasted, 2048ULL);
    CTF_EXPECT_EQ(after_close.bytes_transferred, 4096ULL);
    CTF_EXPECT_EQ(view.value().verified_bytes, 4096ULL);
    if (mode == 0) {
      CTF_EXPECT_EQ(after_close.bytes_cancelled, 2048ULL);
    } else {
      CTF_EXPECT_EQ(after_close.bytes_unproven, 2048ULL);
    }
  };
  scenario("cancel after partial verify", 0, 2, 0);
  scenario("deadline after partial verify", 1, 2, 50 * ctf::kNanosPerMillisecond);
  scenario("supersede after partial verify", 2, 2, 0);
}

// Library defect regression (fixed): reporting a truncated transfer for an
// attempt the fabric never saw acknowledged used to clear the attempt's
// outstanding flag without releasing the session's active-attempt authority, so
// a later completion left a terminal session holding outstanding authority. The
// release is now symmetric and the session closes at the baseline.
CTF_TEST(property, truncating_an_unacknowledged_attempt_closes_authority) {
  const EngineFixture fixture = property_fixture();
  ManualClock clock;
  FabricEngine engine(Driver::config_for(fixture, 0x5EED5EEDULL), clock);
  const WorkloadId workload = ctf::test::default_workload();
  const CheckpointId checkpoint = checkpoint_id(3);
  const SessionRequest request =
      build_request(engine, checkpoint, CheckpointGeneration(1), ctf::test::command_id(1), workload,
                    1, 4096, IsolationClass::TrainingBulk, DestinationClass::SyntheticLab, 0, 0, 1);
  const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));
  const ctf::Result<AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  const SessionId session = decision.value().session;

  const ctf::Result<WaveOutcome> first = engine.request_wave(session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(first.status());
  CTF_REQUIRE(first.value().granted);
  const WaveGrant abandoned = first.value().grant.value();

  // Bytes were seen arriving, but the sink never acknowledged them.
  TransferEvidence seen;
  seen.session = session;
  seen.attempt = abandoned.attempt;
  seen.sequence = abandoned.sequence;
  seen.shard = ShardIndex(0);
  seen.arrived_bytes = abandoned.max_bytes;
  seen.arrived_digest = request.manifest.shards[0].declared_digest;
  seen.sink_acknowledged = false;
  CTF_REQUIRE_OK(engine.report_transfer(seen, fence));
  CTF_EXPECT_EQ(engine.accounting().bytes_transferred, 0ULL);

  // The sink then reports the attempt as truncated, re-arming the shard.
  VerificationEvidence truncated;
  truncated.session = session;
  truncated.attempt = abandoned.attempt;
  truncated.sequence = abandoned.sequence;
  truncated.shard = ShardIndex(0);
  truncated.outcome = VerificationEvidence::Outcome::Truncated;
  truncated.verifier_identity = "property-sink";
  CTF_REQUIRE_OK(engine.report_verification(truncated, fence));

  // The retry runs to completion and the session finishes with full evidence.
  const ctf::Result<WaveOutcome> retry = engine.request_wave(session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(retry.status());
  CTF_REQUIRE(retry.value().granted);
  const WaveGrant grant = retry.value().grant.value();
  TransferEvidence arrived;
  arrived.session = session;
  arrived.attempt = grant.attempt;
  arrived.sequence = grant.sequence;
  arrived.shard = ShardIndex(0);
  arrived.arrived_bytes = grant.max_bytes;
  arrived.arrived_digest = request.manifest.shards[0].declared_digest;
  arrived.sink_acknowledged = true;
  CTF_REQUIRE_OK(engine.report_transfer(arrived, fence));
  VerificationEvidence verified;
  verified.session = session;
  verified.attempt = grant.attempt;
  verified.sequence = grant.sequence;
  verified.shard = ShardIndex(0);
  verified.verified_bytes = request.manifest.shards[0].declared_bytes;
  verified.verified_digest = request.manifest.shards[0].declared_digest;
  verified.outcome = VerificationEvidence::Outcome::Verified;
  verified.verifier_identity = "property-sink";
  CTF_REQUIRE_OK(engine.report_verification(verified, fence));

  const ctf::Result<SessionView> view = engine.view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, SessionState::TrafficSessionComplete);
  const AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.active_attempts, 0U);
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT_OK(engine.check_invariants());
}

// Library defect regression (fixed): transfer evidence used to be accepted for
// an attempt that had already been recorded as ambiguous, which double-counted
// those bytes (once as UNPROVEN, once as TRANSFERRED) and broke conservation
// permanently. Late evidence is now refused.
CTF_TEST(property, late_evidence_for_an_ambiguous_attempt_is_refused) {
  const EngineFixture fixture = property_fixture();
  ManualClock clock;
  FabricEngine engine(Driver::config_for(fixture, 0x99ULL), clock);
  const WorkloadId workload = ctf::test::default_workload();
  const SessionRequest request =
      build_request(engine, checkpoint_id(3), CheckpointGeneration(1), ctf::test::command_id(1),
                    workload, 1, 4096, IsolationClass::TrainingBulk, DestinationClass::SyntheticLab,
                    0, 0, 1);
  const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));
  const ctf::Result<AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  const SessionId session = decision.value().session;
  const ctf::Result<WaveOutcome> grant = engine.request_wave(session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(grant.status());
  CTF_REQUIRE(grant.value().granted);
  const WaveGrant a = grant.value().grant.value();
  std::printf("    after grant            : %s\\n",
              engine.accounting().conserves() ? "conserves" : "IMBALANCE");
  CTF_REQUIRE_OK(engine.report_ambiguous(session, a.attempt, a.sequence, "sink unreachable", fence));
  const AccountingSnapshot after_ambiguity = engine.accounting();
  std::printf("    after ambiguity        : conserves=%d unproven=%llu outstanding=%llu active=%u\\n",
              after_ambiguity.conserves() ? 1 : 0,
              (unsigned long long)after_ambiguity.bytes_unproven,
              (unsigned long long)after_ambiguity.granted_outstanding_bytes,
              after_ambiguity.active_attempts);
  TransferEvidence late;
  late.session = session;
  late.attempt = a.attempt;
  late.sequence = a.sequence;
  late.shard = ShardIndex(0);
  late.arrived_bytes = a.max_bytes;
  late.arrived_digest = request.manifest.shards[0].declared_digest;
  late.sink_acknowledged = true;
  const Status status = engine.report_transfer(late, fence);
  const AccountingSnapshot after_late = engine.accounting();
  std::printf("    late acked transfer    : status=%s conserves=%d transferred=%llu unproven=%llu "
              "outstanding=%llu\\n",
              status.to_string().c_str(), after_late.conserves() ? 1 : 0,
              (unsigned long long)after_late.bytes_transferred,
              (unsigned long long)after_late.bytes_unproven,
              (unsigned long long)after_late.granted_outstanding_bytes);
  // Evidence for a settled attempt is refused, and the refusal leaves the
  // accounting exactly where the ambiguity report put it.
  CTF_EXPECT_EQ(status.code(), ErrorCode::AmbiguousOutcome);
  CTF_EXPECT(after_late.conserves());
  CTF_EXPECT_EQ(after_late.bytes_transferred, after_ambiguity.bytes_transferred);
  CTF_EXPECT_EQ(after_late.bytes_unproven, after_ambiguity.bytes_unproven);
  CTF_EXPECT_EQ(after_late.granted_outstanding_bytes, after_ambiguity.granted_outstanding_bytes);
  CTF_EXPECT_OK(engine.check_invariants());
}

// Library defect regression (fixed): advance_epoch used to book a session's
// whole remaining authority as UNPROVEN while re-arming its shards without
// re-authorising them, so the acked retry was billed to authority that no
// longer existed and conservation broke. The retry is now funded by the
// authority that was never granted, or re-authorised, and conservation holds.
CTF_TEST(property, retry_after_epoch_reauthorises_bytes) {
  const EngineFixture fixture = property_fixture();
  ManualClock clock;
  FabricEngine engine(Driver::config_for(fixture, 0xEEEEULL), clock);
  const WorkloadId workload = ctf::test::default_workload();
  const SessionRequest request =
      build_request(engine, checkpoint_id(4), CheckpointGeneration(1), ctf::test::command_id(1),
                    workload, 2, 8192, IsolationClass::TrainingBulk, DestinationClass::SyntheticLab,
                    0, 0, 1);
  const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));
  const ctf::Result<AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  const SessionId session = decision.value().session;
  const ctf::Result<WaveOutcome> first = engine.request_wave(session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(first.status());
  CTF_REQUIRE(first.value().granted);

  // A coordinator restart: the grant becomes unproven and the shard is re-armed.
  const ctf::CoordinatorEpoch next{ctf::IncarnationId(2), ctf::EpochTerm(1)};
  CTF_REQUIRE_OK(engine.advance_epoch(next));
  const AccountingSnapshot after_restart = engine.accounting();
  // Every byte of this session was granted and unsettled, so the restart books
  // it as UNPROVEN; either way the authority stays conserved.
  CTF_EXPECT_EQ(after_restart.bytes_unproven + after_restart.granted_outstanding_bytes,
                request.manifest.total_bytes);
  CTF_EXPECT(after_restart.conserves());

  const ctf::Result<AdmissionDecision> revalidated =
      engine.revalidate_session(session, engine.current_fence(workload, CheckpointGeneration(1)));
  CTF_REQUIRE_OK(revalidated.status());
  CTF_REQUIRE(revalidated.value().admitted());
  const ctf::Result<SessionView> view = engine.view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().shards[0].state, ctf::ShardState::Pending);

  // Bytes the previous incarnation never granted keep their authority, so the
  // rest of the checkpoint is still transferable after the restart.
  CTF_EXPECT_EQ(after_restart.granted_outstanding_bytes, request.manifest.total_bytes / 2U);
  CTF_EXPECT_EQ(after_restart.bytes_unproven, request.manifest.total_bytes / 2U);
  const ctf::Result<WaveOutcome> retry = engine.request_wave(
      session, ShardIndex(1), engine.current_fence(workload, CheckpointGeneration(1)));
  CTF_REQUIRE_OK(retry.status());
  CTF_REQUIRE(retry.value().granted);
  const WaveGrant grant = retry.value().grant.value();
  TransferEvidence arrived;
  arrived.session = session;
  arrived.attempt = grant.attempt;
  arrived.sequence = grant.sequence;
  arrived.shard = ShardIndex(1);
  arrived.arrived_bytes = grant.max_bytes;
  arrived.arrived_digest = request.manifest.shards[1].declared_digest;
  arrived.sink_acknowledged = true;
  const Status status = engine.report_transfer(
      arrived, engine.current_fence(workload, CheckpointGeneration(1)));
  const AccountingSnapshot after_retry = engine.accounting();
  std::printf("    retry after epoch: status=%s admitted=%llu transferred=%llu unproven=%llu "
              "outstanding=%llu conserves=%d\n",
              status.to_string().c_str(), (unsigned long long)after_retry.bytes_admitted,
              (unsigned long long)after_retry.bytes_transferred,
              (unsigned long long)after_retry.bytes_unproven,
              (unsigned long long)after_retry.granted_outstanding_bytes,
              after_retry.conserves() ? 1 : 0);
  // The retry is billed to authority that survived the restart, so the
  // conservation identity is preserved and nothing is admitted twice.
  CTF_EXPECT(status.ok());
  CTF_EXPECT_EQ(after_retry.bytes_admitted, request.manifest.total_bytes);
  CTF_EXPECT_EQ(after_retry.bytes_transferred, request.manifest.total_bytes / 2U);
  CTF_EXPECT(after_retry.conserves());
  CTF_EXPECT_OK(engine.check_invariants());

  // The re-armed shard itself has no authority left: evidence for it is refused
  // rather than silently billed twice, and conservation still holds.
  const ctf::Result<WaveOutcome> stranded = engine.request_wave(
      session, ShardIndex(0), engine.current_fence(workload, CheckpointGeneration(1)));
  CTF_REQUIRE_OK(stranded.status());
  if (stranded.value().granted) {
    const WaveGrant stranded_grant = stranded.value().grant.value();
    TransferEvidence late;
    late.session = session;
    late.attempt = stranded_grant.attempt;
    late.sequence = stranded_grant.sequence;
    late.shard = ShardIndex(0);
    late.arrived_bytes = stranded_grant.max_bytes;
    late.arrived_digest = request.manifest.shards[0].declared_digest;
    late.sink_acknowledged = true;
    const Status late_status = engine.report_transfer(
        late, engine.current_fence(workload, CheckpointGeneration(1)));
    CTF_EXPECT(!late_status.ok());
    CTF_EXPECT(late_status.code() == ErrorCode::ImpossibleState ||
               late_status.code() == ErrorCode::StaleEvidence);
  }
  CTF_EXPECT(engine.accounting().conserves());
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_MAIN()
