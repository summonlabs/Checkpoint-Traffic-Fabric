// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Scale suite: proves the engine's cost per operation does not grow with the
// size of the session table, that retention is bounded, and that per-session
// state is bounded. Every assertion is a ratio between two measurements taken
// on the same machine in the same run, so a slow host cannot fail a test and no
// absolute time is ever asserted.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <string>
#include <vector>

#include "ctf/engine.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

namespace {

using ctf::AdmissionDecision;
using ctf::CheckpointGeneration;
using ctf::CheckpointId;
using ctf::CommandFence;
using ctf::DecisionKind;
using ctf::DestinationClass;
using ctf::Digest;
using ctf::FabricEngine;
using ctf::IsolationClass;
using ctf::ManualClock;
using ctf::Nanos;
using ctf::ReasonCode;
using ctf::SessionId;
using ctf::SessionRequest;
using ctf::SessionView;
using ctf::ShardIndex;
using ctf::ShardProgress;
using ctf::WaveOutcome;
using ctf::Status;
using ctf::WorkloadId;

constexpr std::uint32_t kWorkloads = 4;
constexpr std::uint64_t kShardBytes = 4096;
constexpr std::uint64_t kRequestedRate = 64U * 1024U;

/// Wall-clock milliseconds, used only for ratios between measurements.
[[nodiscard]] double millis_since(std::chrono::steady_clock::time_point start) {
  const auto elapsed = std::chrono::steady_clock::now() - start;
  return std::chrono::duration<double, std::milli>(elapsed).count();
}

[[nodiscard]] WorkloadId scale_workload(std::uint32_t index) {
  std::string digits = index < 10 ? std::string("0") + std::to_string(index)
                                  : std::to_string(index);
  const std::string text = "eeeeeeee-3333-4444-8555-6666666666" + digits;
  return WorkloadId::parse(text).value();
}

[[nodiscard]] CheckpointId scale_checkpoint(std::uint64_t index) {
  std::string digits = std::to_string(index);
  while (digits.size() < 12) {
    digits.insert(digits.begin(), '0');
  }
  return CheckpointId::parse("ffffffff-4444-4555-8666-" + digits).value();
}

/// Engine configuration for the scale runs: one workload per submitting batch,
/// enough session slots to hold every session at once, and a path whose rate is
/// large enough that admission is never deferred by reservations.
[[nodiscard]] ctf::EngineConfig scale_config(std::uint32_t retained_history,
                                             std::uint32_t max_sessions) {
  ctf::EngineConfig config;
  config.epoch = ctf::test::first_epoch();
  config.identity_seed = 0x5CA1EULL;
  config.limits = ctf::Limits{};
  config.limits.max_sessions_per_workload = 4096;
  config.limits.max_checkpoint_bytes = 1ULL << 40;

  config.policy.generation = ctf::PolicyGeneration(1);
  config.policy.envelopes = {
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingCritical, 64U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 8192},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::ServingLatency, 64U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 8192},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingBulk, 64U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 8192},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::BestEffort, 64U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 8192},
  };
  config.policy.max_wave_width = 8;
  config.policy.max_session_bytes = 64U * 1024U;
  config.policy.max_sessions = max_sessions;
  config.policy.max_attempts_in_flight = 4096;
  config.policy.retained_history = retained_history;
  config.policy.require_destination_verification = true;
  config.policy.defer_horizon_ns = ctf::kNanosPerMillisecond * 100;
  config.policy.default_deadline_ns = 600 * ctf::kNanosPerSecond;

  config.topology.generation = ctf::TopologyGeneration(1);
  config.topology.path_classes = {
      ctf::PathClass{ctf::PathClassId(1), ctf::DestinationClass::SyntheticLab,
                     1ULL << 40, true, "scale-lab"},
  };
  for (std::uint32_t index = 0; index < kWorkloads; ++index) {
    ctf::WorkloadContract contract;
    contract.workload = scale_workload(index);
    contract.generation = ctf::WorkloadContractGeneration(1);
    contract.isolation = ctf::IsolationClass::TrainingBulk;
    contract.ceiling_bps = 64U * 1024U * 1024U;
    contract.max_in_flight_sessions = 4096;
    contract.max_shards_per_wave = 4;
    contract.allow_supersession = true;
    contract.deadline_budget_ns = 600 * ctf::kNanosPerSecond;
    config.contracts.push_back(contract);
  }
  return config;
}

[[nodiscard]] SessionRequest scale_request(FabricEngine& engine, std::uint32_t workload_index,
                                           std::uint64_t index, std::uint32_t shards) {
  const WorkloadId workload = scale_workload(workload_index);
  const std::optional<ctf::WorkloadContract> contract = engine.contract(workload);
  const ctf::CheckpointGeneration generation(1);
  SessionRequest request;
  request.command = ctf::test::command_id(1 + index);
  request.workload = workload;
  request.contract_generation =
      contract.has_value() ? contract->generation : ctf::WorkloadContractGeneration(0);
  request.policy_generation = engine.policy().generation;
  request.topology_generation = engine.topology().generation;
  request.checkpoint = scale_checkpoint(index);
  request.checkpoint_generation = generation;
  request.requested_isolation = IsolationClass::TrainingBulk;
  request.destination = DestinationClass::SyntheticLab;
  request.requested_rate_bps = kRequestedRate;
  request.manifest.checkpoint = request.checkpoint;
  request.manifest.generation = generation;
  request.manifest.workload = workload;
  request.manifest.contract_generation = request.contract_generation;
  for (std::uint32_t index_in_shard = 0; index_in_shard < shards; ++index_in_shard) {
    ctf::ShardDescriptor shard;
    shard.index = ShardIndex(index_in_shard);
    shard.declared_bytes = kShardBytes;
    shard.declared_digest =
        Digest(static_cast<std::uint32_t>(0xB000U + index + index_in_shard),
               0xC000ULL + index + index_in_shard);
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += kShardBytes;
  }
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  return request;
}

/// Submits one session for a distinct checkpoint and asserts it was admitted.
[[nodiscard]] SessionId submit_one(ctf::test::Context& ctf_ctx, FabricEngine& engine,
                                   std::uint64_t index, std::uint32_t workload_index,
                                   std::uint32_t shards) {
  const SessionRequest request = scale_request(engine, workload_index, index, shards);
  const CommandFence fence =
      engine.current_fence(request.workload, request.checkpoint_generation);
  const ctf::Result<AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  if (decision.value().kind != DecisionKind::Admit) {
    ctf_ctx.fail(__FILE__, __LINE__,
                 "session " + std::to_string(index) + " was not admitted: " +
                     ctf::to_string(decision.value().kind) + " / " +
                     ctf::to_string(decision.value().reason));
    throw ctf::test::TestAbort();
  }
  return decision.value().session;
}

}  // namespace

// ---------------------------------------------------------------------------
// Per-batch submit cost
// ---------------------------------------------------------------------------

CTF_TEST(scale, submit_batches_show_bounded_growth) {
  constexpr std::size_t kBatch = 500;
  constexpr std::size_t kBatches = 8;
  constexpr std::size_t kTotal = kBatch * kBatches;
  ManualClock clock;
  FabricEngine engine(scale_config(/*retained_history=*/256, /*max_sessions=*/8192), clock);

  std::vector<double> batch_ms;
  batch_ms.reserve(kBatches);
  std::uint64_t index = 0;
  const auto total_start = std::chrono::steady_clock::now();
  for (std::size_t batch = 0; batch < kBatches; ++batch) {
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t step = 0; step < kBatch; ++step) {
      // Round-robin over workloads so a per-workload index would be exercised
      // too, and so no single workload index grows without bound.
      (void)submit_one(ctf_ctx, engine, index, static_cast<std::uint32_t>(index % kWorkloads), 1);
      ++index;
    }
    batch_ms.push_back(millis_since(start));
  }
  const double total_ms = millis_since(total_start);
  std::printf("    submit batches (ms):");
  for (const double value : batch_ms) {
    std::printf(" %.2f", value);
  }
  std::printf(" total=%.2f for %zu submits\n", total_ms, kTotal);

  CTF_EXPECT_EQ(engine.session_count(), kTotal);
  // The first batch is also the cold one; a floor keeps scheduler noise from
  // making the ratio meaningless without hiding real growth.
  const double first = std::max(batch_ms.front(), 0.5);
  const double last = batch_ms.back();
  const double ratio = last / first;
  std::printf("    last/first batch ratio = %.2fx (limit 4.00x)\n", ratio);
  CTF_EXPECT(last <= first * 4.0);

  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_EQ(accounting.bytes_admitted, kTotal * kShardBytes);
  CTF_EXPECT_OK(engine.check_invariants());
}

// ---------------------------------------------------------------------------
// Keyed lookup cost
// ---------------------------------------------------------------------------

CTF_TEST(scale, keyed_lookup_cost_is_flat) {
  constexpr std::size_t kLookups = 20000;
  constexpr std::size_t kSmallSessions = 250;
  constexpr std::size_t kLargeSessions = 4000;
  constexpr std::size_t kQuarters = 4;

  const auto measure_lookups = [&ctf_ctx](std::size_t sessions, std::vector<double>* quarters) {
    ManualClock clock;
    FabricEngine engine(scale_config(/*retained_history=*/256, /*max_sessions=*/8192), clock);
    std::vector<SessionId> ids;
    ids.reserve(sessions);
    for (std::size_t index = 0; index < sessions; ++index) {
      ids.push_back(submit_one(ctf_ctx, engine, index,
                               static_cast<std::uint32_t>(index % kWorkloads), 1));
    }
    const std::size_t per_quarter = kLookups / kQuarters;
    double quarter_ms = 0.0;
    std::size_t quarter_index = 0;
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t lookup = 0; lookup < kLookups; ++lookup) {
      const SessionId& id = ids[lookup % ids.size()];
      if ((lookup % 2U) == 0U) {
        const ctf::Result<ctf::SessionView> view = engine.view_session(id);
        CTF_REQUIRE_OK(view.status());
      } else {
        const ctf::Result<ctf::Explanation> explanation = engine.explain(id);
        CTF_REQUIRE_OK(explanation.status());
      }
      if ((lookup + 1) % per_quarter == 0) {
        quarters->push_back(millis_since(start) - quarter_ms);
        quarter_ms = millis_since(start);
        ++quarter_index;
      }
    }
    return millis_since(start);
  };

  std::vector<double> small_quarters;
  std::vector<double> large_quarters;
  const double small_total = measure_lookups(kSmallSessions, &small_quarters);
  const double large_total = measure_lookups(kLargeSessions, &large_quarters);
  const std::size_t per_quarter = kLookups / kQuarters;
  const double small_per_lookup_us = (small_total * 1000.0) / static_cast<double>(kLookups);
  const double large_per_lookup_us = (large_total * 1000.0) / static_cast<double>(kLookups);
  std::printf("    lookups: %zu each; small(%zu sessions)=%.3f ms (%.3f us/lookup), "
              "large(%zu sessions)=%.3f ms (%.3f us/lookup)\n",
              kLookups, kSmallSessions, small_total, small_per_lookup_us, kLargeSessions,
              large_total, large_per_lookup_us);
  std::printf("    large/small cost ratio = %.2fx (limit 4.00x); per-lookup quarters (us):",
              large_per_lookup_us / std::max(small_per_lookup_us, 0.000001));
  for (const double value : large_quarters) {
    std::printf(" %.3f", (value * 1000.0) / static_cast<double>(per_quarter));
  }
  std::printf("\n");

  CTF_EXPECT(small_quarters.size() == kQuarters);
  CTF_EXPECT(large_quarters.size() == kQuarters);
  // A lookup must not become more expensive because the table is bigger: the
  // first and last quarter of the large run are compared, and the large table is
  // compared with a small one.
  const double first_quarter = std::max(large_quarters.front(), 0.01);
  CTF_EXPECT(large_quarters.back() <= first_quarter * 4.0);
  CTF_EXPECT(large_per_lookup_us <= std::max(small_per_lookup_us, 0.001) * 4.0);
}

// ---------------------------------------------------------------------------
// Bounded retention
// ---------------------------------------------------------------------------

CTF_TEST(scale, retention_is_bounded_and_conserves) {
  constexpr std::uint32_t kRetainedHistory = 64;
  constexpr std::size_t kSessions = 3000;
  const std::size_t expected_bound = static_cast<std::size_t>(kRetainedHistory) * 8U;
  ManualClock clock;
  FabricEngine engine(scale_config(kRetainedHistory, /*max_sessions=*/8192), clock);

  std::uint64_t admitted_bytes = 0;
  for (std::size_t index = 0; index < kSessions; ++index) {
    const SessionId session =
        submit_one(ctf_ctx, engine, index, static_cast<std::uint32_t>(index % kWorkloads), 1);
    admitted_bytes += kShardBytes;
    const WorkloadId workload = scale_workload(static_cast<std::uint32_t>(index % kWorkloads));
    const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));
    // The session is cancelled immediately: its bytes are released, never
    // transferred, so eviction must not disturb the aggregate identity.
    CTF_REQUIRE_OK(engine.cancel_session(session, fence, ReasonCode::CancelledByOperator,
                                         "scale retention"));
    CTF_EXPECT(engine.session_count() <= expected_bound);
  }

  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.bytes_admitted, admitted_bytes);
  CTF_EXPECT_EQ(accounting.bytes_cancelled, admitted_bytes);
  CTF_EXPECT_EQ(accounting.bytes_transferred, 0ULL);
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT_OK(engine.check_invariants());
  const std::size_t retained = engine.session_count();
  CTF_EXPECT(retained <= expected_bound);
  CTF_EXPECT(retained > 0);
  std::printf("    retention: created=%zu retained=%zu bound=%zu admitted=%llu cancelled=%llu\n",
              kSessions, retained, expected_bound, (unsigned long long)accounting.bytes_admitted,
              (unsigned long long)accounting.bytes_cancelled);

  // list_sessions honours its limit and returns a deterministic order.
  const ctf::Result<std::vector<ctf::SessionSummary>> limited =
      engine.list_sessions(std::nullopt, 32);
  CTF_REQUIRE_OK(limited.status());
  CTF_EXPECT_EQ(limited.value().size(), static_cast<std::size_t>(32));
  for (std::size_t index = 1; index < limited.value().size(); ++index) {
    const ctf::SessionSummary& previous = limited.value()[index - 1];
    const ctf::SessionSummary& current = limited.value()[index];
    const bool ordered = previous.updated_at < current.updated_at ||
                         (previous.updated_at == current.updated_at &&
                          previous.session < current.session);
    CTF_EXPECT(ordered);
  }
  const ctf::Result<std::vector<ctf::SessionSummary>> repeat =
      engine.list_sessions(std::nullopt, 32);
  CTF_REQUIRE_OK(repeat.status());
  CTF_REQUIRE(repeat.value().size() == limited.value().size());
  for (std::size_t index = 0; index < limited.value().size(); ++index) {
    CTF_EXPECT(limited.value()[index].session == repeat.value()[index].session);
  }
  const ctf::Result<std::vector<ctf::SessionSummary>> unbounded =
      engine.list_sessions(std::nullopt, 100000);
  CTF_REQUIRE_OK(unbounded.status());
  CTF_EXPECT_EQ(unbounded.value().size(), retained);
  const ctf::Result<std::vector<ctf::SessionSummary>> by_workload =
      engine.list_sessions(scale_workload(0), 10);
  CTF_REQUIRE_OK(by_workload.status());
  CTF_EXPECT(by_workload.value().size() <= 10U);
  std::printf("    list_sessions: limit32=%zu repeat=%zu unbounded=%zu workload<=10=%zu\n",
              limited.value().size(), repeat.value().size(), unbounded.value().size(),
              by_workload.value().size());
}

// ---------------------------------------------------------------------------
// Bounded per-session state
// ---------------------------------------------------------------------------

CTF_TEST(scale, per_session_attempt_history_is_bounded) {
  constexpr std::uint32_t kRetainedHistory = 16;
  constexpr std::size_t kGrants = 400;
  ManualClock clock;
  FabricEngine engine(scale_config(kRetainedHistory, /*max_sessions=*/64), clock);
  const SessionId session = submit_one(ctf_ctx, engine, 0, 0, 1);
  const WorkloadId workload = scale_workload(0);
  const CommandFence fence = engine.current_fence(workload, CheckpointGeneration(1));

  std::size_t granted = 0;
  std::uint64_t granted_bytes = 0;
  std::size_t max_retained = 0;
  for (std::size_t step = 0; step < kGrants; ++step) {
    const ctf::Result<ctf::WaveOutcome> outcome =
        engine.request_wave(session, ShardIndex(0), fence);
    CTF_REQUIRE_OK(outcome.status());
    if (!outcome.value().granted) {
      // Deferrals are expected: the fabric, not the sender, paces credit.
      clock.advance(2 * ctf::kNanosPerMillisecond);
      continue;
    }
    CTF_REQUIRE(outcome.value().grant.has_value());
    const ctf::WaveGrant grant = outcome.value().grant.value();
    ++granted;
    granted_bytes += grant.max_bytes;
    // The attempt history must stay bounded while the grants keep coming: the
    // engine reports its retained timeline and attempt entries directly.
    max_retained = std::max(max_retained, engine.timeline_entries());
    CTF_EXPECT(engine.timeline_entries() <= 2U * kRetainedHistory);
    // The sender gives up on this attempt: reporting the truncation re-arms the
    // shard and releases the attempt, which is what allows the next grant.
    ctf::VerificationEvidence truncated;
    truncated.session = session;
    truncated.attempt = grant.attempt;
    truncated.sequence = grant.sequence;
    truncated.shard = ShardIndex(0);
    truncated.outcome = ctf::VerificationEvidence::Outcome::Truncated;
    truncated.verifier_identity = "scale-sink";
    CTF_REQUIRE_OK(engine.report_verification(truncated, fence));
    CTF_EXPECT(engine.timeline_entries() <= 2U * kRetainedHistory);
    clock.advance(2 * ctf::kNanosPerMillisecond);
  }
  CTF_REQUIRE(granted > kRetainedHistory);
  std::printf("    attempts: grants=%zu granted_bytes=%llu timeline_entries=%zu bound=%u\n", granted,
              (unsigned long long)granted_bytes, engine.timeline_entries(), 2U * kRetainedHistory);

  // Transfer evidence for the current attempt still works after the history was
  // bound, and the session then completes with full evidence.
  const ctf::Result<ctf::WaveOutcome> final_wave = engine.request_wave(session, ShardIndex(0), fence);
  CTF_REQUIRE_OK(final_wave.status());
  CTF_REQUIRE(final_wave.value().granted);
  const ctf::WaveGrant final_grant = final_wave.value().grant.value();
  const ctf::Result<ctf::SessionView> view = engine.view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_REQUIRE(!view.value().shards.empty());
  ctf::TransferEvidence transfer;
  transfer.session = session;
  transfer.attempt = final_grant.attempt;
  transfer.sequence = final_grant.sequence;
  transfer.shard = ShardIndex(0);
  transfer.arrived_bytes = view.value().shards[0].declared_bytes;
  transfer.arrived_digest = view.value().shards[0].declared_digest;
  transfer.sink_acknowledged = true;
  CTF_REQUIRE_OK(engine.report_transfer(transfer, fence));
  ctf::VerificationEvidence verified;
  verified.session = session;
  verified.attempt = final_grant.attempt;
  verified.sequence = final_grant.sequence;
  verified.shard = ShardIndex(0);
  verified.verified_bytes = view.value().shards[0].declared_bytes;
  verified.verified_digest = view.value().shards[0].declared_digest;
  verified.outcome = ctf::VerificationEvidence::Outcome::Verified;
  verified.verifier_identity = "scale-sink";
  CTF_REQUIRE_OK(engine.report_verification(verified, fence));
  const ctf::Result<ctf::SessionView> after = engine.view_session(session);
  CTF_REQUIRE_OK(after.status());
  CTF_EXPECT_EQ(after.value().state, ctf::SessionState::TrafficSessionComplete);
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT_OK(engine.check_invariants());
  std::printf("    attempts retained at most %zu entries for one session\n", max_retained);
}

CTF_MAIN()
