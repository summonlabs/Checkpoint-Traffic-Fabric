#pragma once

// Shared fixtures for the engine, service, and multiprocess suites.
//
// Every fixture is explicit about the authority it establishes: generations are
// set deliberately so a test can prove that a stale one is refused.

#include <cstdint>
#include <optional>
#include <string>

#include "ctf/config.hpp"
#include "ctf/engine.hpp"
#include "ctf/report.hpp"

namespace ctf::test {

inline constexpr const char* kDefaultWorkloadText = "11111111-2222-4333-8444-555555555555";
inline constexpr const char* kSecondWorkloadText = "22222222-3333-4444-8555-666666666666";
inline constexpr const char* kCheckpointText = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
inline constexpr const char* kSecondCheckpointText = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";

[[nodiscard]] inline WorkloadId default_workload() {
  return WorkloadId::parse(kDefaultWorkloadText).value();
}

[[nodiscard]] inline WorkloadId second_workload() {
  return WorkloadId::parse(kSecondWorkloadText).value();
}

[[nodiscard]] inline CheckpointId default_checkpoint() {
  return CheckpointId::parse(kCheckpointText).value();
}

[[nodiscard]] inline CommandId command_id(std::uint64_t suffix) {
  std::string text = "99999999-0000-4000-8000-";
  std::string digits = std::to_string(suffix);
  while (digits.size() < 12) {
    digits.insert(digits.begin(), '0');
  }
  return CommandId::parse(text + digits).value();
}

struct EngineFixture {
  PolicySnapshot policy;
  TopologySnapshot topology;
  std::vector<WorkloadContract> contracts;
  Limits limits;

  static EngineFixture make() {
    EngineFixture fixture;
    fixture.policy.generation = PolicyGeneration(3);
    fixture.policy.envelopes = {
        IsolationEnvelopeConfig{IsolationClass::TrainingCritical, 4U * 1024U * 1024U,
                                kNanosPerMillisecond * 100, 4},
        IsolationEnvelopeConfig{IsolationClass::ServingLatency, 4U * 1024U * 1024U,
                                kNanosPerMillisecond * 100, 4},
        IsolationEnvelopeConfig{IsolationClass::TrainingBulk, 1U * 1024U * 1024U,
                                kNanosPerMillisecond * 100, 4},
        IsolationEnvelopeConfig{IsolationClass::BestEffort, 256U * 1024U,
                                kNanosPerMillisecond * 100, 2},
    };
    fixture.policy.max_wave_width = 2;
    fixture.policy.max_session_bytes = 8U * 1024U * 1024U;
    fixture.policy.max_sessions = 16;
    fixture.policy.max_attempts_in_flight = 8;
    fixture.policy.retained_history = 32;
    fixture.policy.require_destination_verification = true;
    fixture.policy.defer_horizon_ns = kNanosPerMillisecond * 100;

    fixture.topology.generation = TopologyGeneration(2);
    fixture.topology.path_classes = {
        PathClass{PathClassId(1), DestinationClass::SyntheticLab, 16U * 1024U * 1024U, true,
                  "lab-path"},
        PathClass{PathClassId(2), DestinationClass::LocalAttachedStore, 16U * 1024U * 1024U, true,
                  "local-path"},
    };

    WorkloadContract primary;
    primary.workload = default_workload();
    primary.generation = WorkloadContractGeneration(5);
    primary.isolation = IsolationClass::TrainingBulk;
    primary.ceiling_bps = 1U * 1024U * 1024U;
    primary.floor_bps = 0;
    primary.max_in_flight_sessions = 2;
    primary.max_shards_per_wave = 2;
    primary.allow_supersession = true;
    primary.deadline_budget_ns = 30 * kNanosPerSecond;

    WorkloadContract secondary;
    secondary.workload = second_workload();
    secondary.generation = WorkloadContractGeneration(1);
    secondary.isolation = IsolationClass::ServingLatency;
    secondary.ceiling_bps = 2U * 1024U * 1024U;
    secondary.max_in_flight_sessions = 2;
    secondary.max_shards_per_wave = 2;
    secondary.allow_supersession = false;
    secondary.deadline_budget_ns = 30 * kNanosPerSecond;

    fixture.contracts = {primary, secondary};
    return fixture;
  }

  [[nodiscard]] EngineConfig engine_config(CoordinatorEpoch epoch) const {
    EngineConfig config;
    config.policy = policy;
    config.topology = topology;
    config.contracts = contracts;
    config.epoch = epoch;
    config.limits = limits;
    return config;
  }
};

[[nodiscard]] inline CoordinatorEpoch first_epoch() {
  return CoordinatorEpoch{IncarnationId(1), EpochTerm(1)};
}

/// Builds a request whose generations match the fixture authority.
[[nodiscard]] inline SessionRequest make_request(const EngineFixture& fixture,
                                                const CheckpointId& checkpoint,
                                                CheckpointGeneration checkpoint_generation,
                                                CommandId command,
                                                WorkloadId workload = default_workload(),
                                                std::uint32_t shards = 2,
                                                std::uint64_t shard_bytes = 64U * 1024U,
                                                IsolationClass isolation = IsolationClass::TrainingBulk,
                                                DestinationClass destination =
                                                    DestinationClass::SyntheticLab,
                                                std::uint64_t requested_rate_bps = 0) {
  SessionRequest request;
  request.command = command;
  request.workload = workload;
  request.contract_generation = WorkloadContractGeneration(0);
  for (const WorkloadContract& contract : fixture.contracts) {
    if (contract.workload == workload) {
      request.contract_generation = contract.generation;
      break;
    }
  }
  request.policy_generation = fixture.policy.generation;
  request.topology_generation = fixture.topology.generation;
  request.checkpoint = checkpoint;
  request.checkpoint_generation = checkpoint_generation;
  request.requested_isolation = isolation;
  request.destination = destination;
  request.requested_rate_bps = requested_rate_bps;
  request.manifest.checkpoint = checkpoint;
  request.manifest.generation = checkpoint_generation;
  request.manifest.workload = workload;
  request.manifest.contract_generation = request.contract_generation;
  for (std::uint32_t i = 0; i < shards; ++i) {
    ShardDescriptor shard;
    shard.index = ShardIndex(i);
    shard.declared_bytes = shard_bytes;
    shard.declared_digest = Digest(0x1000U + i, 0x2000ULL + i);
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += shard_bytes;
  }
  request.manifest.manifest_digest = compute_manifest_digest(request.manifest);
  return request;
}

/// Fabric authority as a client would learn it at handshake time. Generations
/// can be overridden to model an authority change the caller has observed.
[[nodiscard]] inline CommandFence fence_for(const EngineFixture& fixture, WorkloadId workload,
                                            std::optional<CheckpointGeneration> checkpoint_generation =
                                                std::nullopt,
                                            std::optional<PolicyGeneration> policy_generation =
                                                std::nullopt,
                                            std::optional<TopologyGeneration> topology_generation =
                                                std::nullopt) {
  CommandFence fence;
  fence.epoch = first_epoch();
  fence.policy_generation = policy_generation.value_or(fixture.policy.generation);
  fence.topology_generation = topology_generation.value_or(fixture.topology.generation);
  for (const WorkloadContract& contract : fixture.contracts) {
    if (contract.workload == workload) {
      fence.contract_generation = contract.generation;
      break;
    }
  }
  fence.checkpoint_generation = checkpoint_generation;
  return fence;
}

[[nodiscard]] inline CoordinatorConfig service_config(bool persist, const std::string& label) {
  CoordinatorConfig config = config::default_coordinator_config();
  config.persist = persist;
  config.worker_threads = 4;
  config.label = label;
  return config;
}

}  // namespace ctf::test
