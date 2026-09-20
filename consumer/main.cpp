// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Downstream consumer of the installed CheckpointTrafficFabric package.
//
// It drives the exported public API only: admission, wave credit, transfer
// evidence, destination verification, accounting, and invariants - and it
// asserts the released evidence boundary (transferred is not durable).

#include <cstdio>
#include <string>

#include <ctf/engine.hpp>
#include <ctf/report.hpp>
#include <ctf/version.hpp>

int main() {
  std::printf("checkpoint traffic fabric version %s (protocol %u, persistence %u)\n",
              std::string(ctf::version_string()).c_str(),
              static_cast<unsigned>(ctf::kProtocolVersion),
              static_cast<unsigned>(ctf::kPersistenceFormatVersion));

  ctf::ManualClock clock;
  ctf::EngineConfig config;
  config.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(1)};
  config.policy.generation = ctf::PolicyGeneration(1);
  config.policy.envelopes = {
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingCritical, 4U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 2},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::ServingLatency, 4U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 2},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingBulk, 1U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 2},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::BestEffort, 256U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 1},
  };
  config.topology.generation = ctf::TopologyGeneration(1);
  config.topology.path_classes = {ctf::PathClass{ctf::PathClassId(1),
                                                 ctf::DestinationClass::SyntheticLab,
                                                 16U * 1024U * 1024U, true, "consumer-lab"}};
  ctf::WorkloadContract contract;
  contract.workload = ctf::WorkloadId::parse("11111111-2222-4333-8444-555555555555").value();
  contract.generation = ctf::WorkloadContractGeneration(1);
  contract.isolation = ctf::IsolationClass::TrainingBulk;
  contract.ceiling_bps = 1U * 1024U * 1024U;
  contract.deadline_budget_ns = 30 * ctf::kNanosPerSecond;
  config.contracts = {contract};

  ctf::FabricEngine engine(config, clock);
  if (!engine.startup_status().ok()) {
    std::printf("engine rejected the configuration: %s\n",
                engine.startup_status().to_string().c_str());
    return 1;
  }

  const ctf::CheckpointId checkpoint =
      ctf::CheckpointId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").value();
  ctf::SessionRequest request;
  request.command = ctf::CommandId(ctf::Uuid128::parse("99999999-0000-4000-8000-000000000001").value());
  request.workload = contract.workload;
  request.contract_generation = contract.generation;
  request.policy_generation = config.policy.generation;
  request.topology_generation = config.topology.generation;
  request.checkpoint = checkpoint;
  request.checkpoint_generation = ctf::CheckpointGeneration(1);
  request.requested_isolation = ctf::IsolationClass::TrainingBulk;
  request.destination = ctf::DestinationClass::SyntheticLab;
  request.manifest.checkpoint = checkpoint;
  request.manifest.generation = request.checkpoint_generation;
  request.manifest.workload = contract.workload;
  request.manifest.contract_generation = contract.generation;
  ctf::ShardDescriptor shard;
  shard.index = ctf::ShardIndex(0);
  shard.declared_bytes = 32U * 1024U;
  shard.declared_digest = ctf::Digest(0xABCDU, 0x12345678ULL);
  request.manifest.shards.push_back(shard);
  request.manifest.total_bytes = shard.declared_bytes;
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);

  const ctf::CommandFence fence =
      engine.current_fence(contract.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  if (!decision.ok() || !decision.value().admitted()) {
    std::printf("admission refused: %s\n",
                decision.ok() ? ctf::to_string(decision.value().reason)
                              : decision.status().to_string().c_str());
    return 1;
  }
  const ctf::SessionId session = decision.value().session;
  std::printf("admitted: %s\n", ctf::report::to_text(decision.value()).c_str());

  std::uint64_t sent = 0;
  while (sent < shard.declared_bytes) {
    ctf::Result<ctf::WaveOutcome> outcome = engine.request_wave(session, shard.index, fence);
    if (!outcome.ok() || !outcome.value().granted) {
      std::printf("no credit available\n");
      return 1;
    }
    const ctf::WaveGrant grant = outcome.value().grant.value();
    ctf::TransferEvidence transfer;
    transfer.session = session;
    transfer.attempt = grant.attempt;
    transfer.sequence = grant.sequence;
    transfer.shard = shard.index;
    transfer.arrived_bytes = grant.max_bytes;
    transfer.arrived_digest = shard.declared_digest;
    transfer.sink_acknowledged = true;
    if (!engine.report_transfer(transfer, fence).ok()) {
      std::printf("transfer evidence refused\n");
      return 1;
    }
    ctf::VerificationEvidence verification;
    verification.session = session;
    verification.attempt = grant.attempt;
    verification.sequence = grant.sequence;
    verification.shard = shard.index;
    verification.verified_bytes = grant.max_bytes;
    verification.verified_digest = shard.declared_digest;
    verification.outcome = ctf::VerificationEvidence::Outcome::Verified;
    verification.verifier_identity = "consumer-sink";
    if (!engine.report_verification(verification, fence).ok()) {
      std::printf("verification refused\n");
      return 1;
    }
    sent += grant.max_bytes;
  }

  ctf::Result<ctf::SessionView> view = engine.view_session(session);
  if (!view.ok()) {
    return 1;
  }
  std::printf("%s", ctf::report::to_text(view.value()).c_str());
  const ctf::AccountingSnapshot accounting = engine.accounting();
  std::printf("accounting: %s\n", ctf::report::to_text(accounting).c_str());

  const bool ok = view.value().state == ctf::SessionState::TrafficSessionComplete &&
                  view.value().evidence == ctf::EvidenceLevel::VerifiedAtDestination &&
                  view.value().durability == ctf::DurabilityStatus::NotEstablished &&
                  !view.value().durable_checkpoint_success() && accounting.conserves() &&
                  accounting.at_baseline() && engine.check_invariants().ok();
  std::printf("consumer result: %s\n", ok ? "verified against the installed package" : "UNEXPECTED");
  return ok ? 0 : 1;
}
