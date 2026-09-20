// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Supersession, stale-generation fencing, and the evidence boundary.
//
// A newer checkpoint generation supersedes an older one deterministically, and
// the older generation's commands are then refused. Transferred bytes are
// reported as transferred - never as durable checkpoint success.

#include <cstdio>
#include <string>

#include "ctf/engine.hpp"
#include "ctf/report.hpp"

namespace {

ctf::SessionRequest make_request(const ctf::CheckpointId& checkpoint,
                                 ctf::CheckpointGeneration generation, ctf::CommandId command,
                                 const ctf::WorkloadId& workload,
                                 ctf::WorkloadContractGeneration contract_generation) {
  ctf::SessionRequest request;
  request.command = command;
  request.workload = workload;
  request.contract_generation = contract_generation;
  request.policy_generation = ctf::PolicyGeneration(1);
  request.topology_generation = ctf::TopologyGeneration(1);
  request.checkpoint = checkpoint;
  request.checkpoint_generation = generation;
  request.requested_isolation = ctf::IsolationClass::TrainingBulk;
  request.destination = ctf::DestinationClass::SyntheticLab;
  request.manifest.checkpoint = checkpoint;
  request.manifest.generation = generation;
  request.manifest.workload = workload;
  request.manifest.contract_generation = contract_generation;
  for (std::uint32_t i = 0; i < 2; ++i) {
    ctf::ShardDescriptor shard;
    shard.index = ctf::ShardIndex(i);
    shard.declared_bytes = 64U * 1024U;
    shard.declared_digest = ctf::Digest(0x11U * (i + 1), 0x22ULL * (i + 1));
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += shard.declared_bytes;
  }
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  return request;
}

}  // namespace

int main() {
  ctf::ManualClock clock;
  ctf::EngineConfig config;
  config.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(1)};
  config.policy.generation = ctf::PolicyGeneration(1);
  config.policy.envelopes = {
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingCritical, 4U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 4},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::ServingLatency, 4U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 4},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::TrainingBulk, 2U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 4},
      ctf::IsolationEnvelopeConfig{ctf::IsolationClass::BestEffort, 1U * 1024U * 1024U,
                                   ctf::kNanosPerMillisecond * 100, 2},
  };
  config.topology.generation = ctf::TopologyGeneration(1);
  config.topology.path_classes = {ctf::PathClass{ctf::PathClassId(1),
                                                 ctf::DestinationClass::SyntheticLab,
                                                 32U * 1024U * 1024U, true, "example-lab"}};
  ctf::WorkloadContract contract;
  contract.workload = ctf::WorkloadId::parse("11111111-2222-4333-8444-555555555555").value();
  contract.generation = ctf::WorkloadContractGeneration(1);
  contract.isolation = ctf::IsolationClass::TrainingBulk;
  contract.ceiling_bps = 2U * 1024U * 1024U;
  contract.allow_supersession = true;
  config.contracts = {contract};

  ctf::FabricEngine engine(config, clock);
  const ctf::WorkloadId workload = contract.workload;
  const ctf::CheckpointId checkpoint =
      ctf::CheckpointId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").value();
  const ctf::CommandFence fence = engine.current_fence(workload, ctf::CheckpointGeneration(1));

  ctf::SessionRequest older = make_request(
      checkpoint, ctf::CheckpointGeneration(1),
      ctf::CommandId(ctf::Uuid128::parse("99999999-0000-4000-8000-00000000000a").value()), workload,
      contract.generation);
  ctf::Result<ctf::AdmissionDecision> first = engine.submit_session(older, fence);
  if (!first.ok() || !first.value().admitted()) {
    std::printf("first submission was not admitted\n");
    return 1;
  }
  std::printf("generation 1 admitted as %s\n", first.value().session.to_string().c_str());

  ctf::SessionRequest newer = make_request(
      checkpoint, ctf::CheckpointGeneration(2),
      ctf::CommandId(ctf::Uuid128::parse("99999999-0000-4000-8000-00000000000b").value()), workload,
      contract.generation);
  ctf::Result<ctf::AdmissionDecision> second = engine.submit_session(newer, fence);
  if (!second.ok()) {
    std::printf("superseding submission refused: %s\n", second.status().to_string().c_str());
    return 1;
  }
  std::printf("generation 2 decision=%s superseded=%zu\n", ctf::to_string(second.value().kind),
              second.value().superseded.size());

  // The superseded generation must now be refused deterministically.
  ctf::Result<ctf::WaveOutcome> stale_wave =
      engine.request_wave(first.value().session, ctf::ShardIndex(0), fence);
  std::printf("stale session wave request: %s\n",
              stale_wave.ok() ? "unexpectedly accepted" : stale_wave.status().to_string().c_str());

  // Transfer everything, then show that "transferred" is not "durable".
  const ctf::SessionId session = second.value().session;
  const ctf::CommandFence session_fence =
      engine.current_fence(workload, ctf::CheckpointGeneration(2));
  for (const ctf::ShardDescriptor& shard : newer.manifest.shards) {
    std::uint64_t sent = 0;
    while (sent < shard.declared_bytes) {
      ctf::Result<ctf::WaveOutcome> outcome =
          engine.request_wave(session, shard.index, session_fence);
      if (!outcome.ok() || !outcome.value().granted) {
        std::printf("no credit: %s\n",
                    outcome.ok() ? ctf::to_string(outcome.value().reason)
                                 : outcome.status().to_string().c_str());
        return 1;
      }
      const ctf::WaveGrant& grant = outcome.value().grant.value();
      ctf::TransferEvidence evidence;
      evidence.session = session;
      evidence.attempt = grant.attempt;
      evidence.sequence = grant.sequence;
      evidence.shard = shard.index;
      evidence.arrived_bytes = grant.max_bytes;
      evidence.arrived_digest = shard.declared_digest;
      evidence.sink_acknowledged = true;
      const ctf::Status reported = engine.report_transfer(evidence, session_fence);
      if (!reported.ok()) {
        std::printf("transfer evidence refused: %s\n", reported.to_string().c_str());
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
      const ctf::Status verified = engine.report_verification(verification, session_fence);
      if (!verified.ok()) {
        std::printf("verification refused: %s\n", verified.to_string().c_str());
        return 1;
      }
      sent += grant.max_bytes;
    }
  }

  ctf::Result<ctf::SessionView> view = engine.view_session(session);
  if (!view.ok()) {
    std::printf("view failed: %s\n", view.status().to_string().c_str());
    return 1;
  }
  std::printf("%s\n", ctf::report::to_text(view.value()).c_str());
  std::printf("durable checkpoint success: %s\n",
              view.value().durable_checkpoint_success() ? "yes" : "no");
  const ctf::AccountingSnapshot accounting = engine.accounting();
  std::printf("accounting: %s\n", ctf::report::to_text(accounting).c_str());
  const bool ok = view.value().state == ctf::SessionState::TrafficSessionComplete &&
                  view.value().durability == ctf::DurabilityStatus::NotEstablished &&
                  !view.value().durable_checkpoint_success() && accounting.conserves() &&
                  !stale_wave.ok();
  std::printf("example result: %s\n", ok ? "as expected" : "UNEXPECTED");
  return ok ? 0 : 1;
}
