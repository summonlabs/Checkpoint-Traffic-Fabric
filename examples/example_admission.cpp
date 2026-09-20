// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic admission and rate shaping against an injected clock.
//
// This example shows the core policy engine with no I/O at all: the same input
// sequence always produces the same decisions, and the fabric's own token bucket
// - not the sender - bounds how many bytes may enter over a window.

#include <cstdio>
#include <string>

#include "ctf/engine.hpp"

namespace {

ctf::EngineConfig make_config() {
  ctf::EngineConfig config;
  config.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(1)};

  config.policy.generation = ctf::PolicyGeneration(1);
  config.policy.envelopes = {
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingCritical, 8U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 4},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::ServingLatency, 8U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 4},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingBulk, 1U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 4},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::BestEffort, 256U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 2},
  };
  config.policy.max_wave_width = 2;
  config.policy.max_sessions = 8;
  config.policy.retained_history = 32;

  config.topology.generation = ctf::TopologyGeneration(1);
  config.topology.path_classes = {ctf::PathClass{ctf::PathClassId(1),
                                                 ctf::DestinationClass::SyntheticLab,
                                                 64U * 1024U * 1024U, true, "example-lab"}};

  ctf::WorkloadContract contract;
  contract.workload = ctf::WorkloadId::parse("11111111-2222-4333-8444-555555555555").value();
  contract.generation = ctf::WorkloadContractGeneration(1);
  contract.isolation = ctf::IsolationClass::TrainingBulk;
  contract.ceiling_bps = 1U * 1024U * 1024U;
  contract.max_in_flight_sessions = 2;
  contract.max_shards_per_wave = 2;
  contract.deadline_budget_ns = 30 * ctf::kNanosPerSecond;
  config.contracts = {contract};
  return config;
}

}  // namespace

int main() {
  ctf::ManualClock clock;
  ctf::FabricEngine engine(make_config(), clock);

  const ctf::WorkloadId workload =
      ctf::WorkloadId::parse("11111111-2222-4333-8444-555555555555").value();
  const ctf::CheckpointId checkpoint =
      ctf::CheckpointId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").value();

  ctf::SessionRequest request;
  request.command = ctf::CommandId(ctf::Uuid128::parse("99999999-0000-4000-8000-000000000001").value());
  request.workload = workload;
  request.contract_generation = ctf::WorkloadContractGeneration(1);
  request.policy_generation = ctf::PolicyGeneration(1);
  request.topology_generation = ctf::TopologyGeneration(1);
  request.checkpoint = checkpoint;
  request.checkpoint_generation = ctf::CheckpointGeneration(1);
  request.requested_isolation = ctf::IsolationClass::TrainingBulk;
  request.destination = ctf::DestinationClass::SyntheticLab;
  request.manifest.checkpoint = checkpoint;
  request.manifest.generation = request.checkpoint_generation;
  request.manifest.workload = workload;
  request.manifest.contract_generation = request.contract_generation;
  for (std::uint32_t i = 0; i < 4; ++i) {
    ctf::ShardDescriptor shard;
    shard.index = ctf::ShardIndex(i);
    shard.declared_bytes = 128U * 1024U;
    shard.declared_digest = ctf::Digest(0x1234U + i, 0x5678ULL + i);
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += shard.declared_bytes;
  }
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);

  const ctf::CommandFence fence = engine.current_fence(workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  if (!decision.ok()) {
    std::printf("admission refused: %s\n", decision.status().to_string().c_str());
    return 1;
  }
  std::printf("decision=%s reason=%s session=%s\n", ctf::to_string(decision.value().kind),
              ctf::to_string(decision.value().reason), decision.value().session.to_string().c_str());
  if (!decision.value().admitted()) {
    return 1;
  }
  const ctf::TrafficEnvelope& envelope = decision.value().envelope.value();
  std::printf("granted rate=%llu B/s burst=%llu bytes waves=%zu\n",
              static_cast<unsigned long long>(envelope.rate_bps),
              static_cast<unsigned long long>(envelope.burst_bytes), envelope.waves.size());

  // Ask for credit as fast as the fabric allows and prove the ceiling holds.
  std::uint64_t granted = 0;
  std::uint64_t deferred = 0;
  const ctf::SessionId session = decision.value().session;
  for (int step = 0; step < 200; ++step) {
    ctf::Result<ctf::WaveOutcome> outcome = engine.request_wave(session, ctf::ShardIndex(0), fence);
    if (!outcome.ok()) {
      std::printf("wave refused: %s\n", outcome.status().to_string().c_str());
      break;
    }
    if (!outcome.value().granted) {
      ++deferred;
      clock.advance(10 * ctf::kNanosPerMillisecond);
      continue;
    }
    granted += outcome.value().grant.value().max_bytes;
    if (granted >= 4U * 128U * 1024U) {
      break;
    }
  }
  const ctf::Nanos elapsed = clock.now();
  const std::uint64_t ceiling = 1U * 1024U * 1024U;
  const std::uint64_t allowed = static_cast<std::uint64_t>(
      (static_cast<double>(ceiling) * static_cast<double>(elapsed)) /
      static_cast<double>(ctf::kNanosPerSecond));
  std::printf("granted=%llu bytes in %lld ns (deferrals=%llu, ceiling allows %llu)\n",
              static_cast<unsigned long long>(granted), static_cast<long long>(elapsed),
              static_cast<unsigned long long>(deferred),
              static_cast<unsigned long long>(allowed));
  const bool within_ceiling = granted <= allowed + envelope.burst_bytes;
  std::printf("within isolation ceiling (burst included): %s\n", within_ceiling ? "yes" : "no");

  const ctf::Status cancelled = engine.cancel_session(session, fence,
                                                      ctf::ReasonCode::CancelledByOperator,
                                                      "example finished");
  if (!cancelled.ok()) {
    std::printf("cancel refused: %s\n", cancelled.to_string().c_str());
    return 1;
  }
  const ctf::AccountingSnapshot accounting = engine.accounting();
  std::printf("accounting admitted=%llu transferred=%llu cancelled=%llu outstanding=%llu "
              "conserves=%s baseline=%s\n",
              static_cast<unsigned long long>(accounting.bytes_admitted),
              static_cast<unsigned long long>(accounting.bytes_transferred),
              static_cast<unsigned long long>(accounting.bytes_cancelled),
              static_cast<unsigned long long>(accounting.granted_outstanding_bytes),
              accounting.conserves() ? "yes" : "no", accounting.at_baseline() ? "yes" : "no");
  const ctf::Status invariants = engine.check_invariants();
  std::printf("invariants: %s\n", invariants.ok() ? "hold" : invariants.to_string().c_str());
  return within_ceiling && invariants.ok() && accounting.conserves() ? 0 : 1;
}
