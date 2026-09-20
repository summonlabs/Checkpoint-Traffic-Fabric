// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/fence.hpp"

namespace ctf {
namespace {

[[nodiscard]] FenceVerdict reject(ErrorCode code, ReasonCode reason, std::string detail) {
  FenceVerdict verdict;
  verdict.status = Status::error(code, std::move(detail));
  verdict.reason = reason;
  return verdict;
}

}  // namespace

FenceVerdict validate_fence(const CommandFence& fence, const FenceContext& current) {
  // Epoch first: an epoch from another incarnation invalidates everything else.
  if (!(fence.epoch.incarnation == current.epoch.incarnation)) {
    return reject(ErrorCode::ForeignEpoch, ReasonCode::AuthorityStale,
                  "command epoch names a coordinator incarnation that is not current");
  }
  if (fence.epoch.term < current.epoch.term) {
    return reject(ErrorCode::StaleEpoch, ReasonCode::AuthorityStale,
                  "command epoch term is older than the current term");
  }
  if (current.epoch.term < fence.epoch.term) {
    return reject(ErrorCode::ForeignEpoch, ReasonCode::AuthorityStale,
                  "command epoch term was never issued by this coordinator");
  }
  if (fence.policy_generation < current.policy_generation) {
    return reject(ErrorCode::StalePolicyGeneration, ReasonCode::PolicyGenerationStale,
                  "command policy generation is older than the active policy");
  }
  if (current.policy_generation < fence.policy_generation) {
    return reject(ErrorCode::NotAuthorized, ReasonCode::PolicyGenerationStale,
                  "command policy generation is not a policy this coordinator issued");
  }
  if (fence.topology_generation < current.topology_generation) {
    return reject(ErrorCode::StaleTopologyGeneration, ReasonCode::TopologyGenerationStale,
                  "command topology generation is older than the active topology");
  }
  if (current.topology_generation < fence.topology_generation) {
    return reject(ErrorCode::NotAuthorized, ReasonCode::TopologyGenerationStale,
                  "command topology generation is not a topology this coordinator issued");
  }
  if (fence.contract_generation < current.contract_generation) {
    return reject(ErrorCode::StaleContractGeneration, ReasonCode::ContractGenerationStale,
                  "command workload-contract generation is older than the active contract");
  }
  if (current.contract_generation < fence.contract_generation) {
    return reject(ErrorCode::NotAuthorized, ReasonCode::ContractGenerationStale,
                  "command workload-contract generation is not a contract this coordinator issued");
  }
  return FenceVerdict{Status::success(), ReasonCode::Admitted};
}

ReasonCode reason_for_fence_code(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::StalePolicyGeneration:
      return ReasonCode::PolicyGenerationStale;
    case ErrorCode::StaleTopologyGeneration:
      return ReasonCode::TopologyGenerationStale;
    case ErrorCode::StaleContractGeneration:
      return ReasonCode::ContractGenerationStale;
    case ErrorCode::StaleCheckpointGeneration:
      return ReasonCode::CheckpointGenerationStale;
    case ErrorCode::StaleAttempt:
      return ReasonCode::AttemptStale;
    case ErrorCode::StaleEvidence:
      return ReasonCode::EvidenceStale;
    case ErrorCode::StaleEpoch:
    case ErrorCode::ForeignEpoch:
      return ReasonCode::AuthorityStale;
    case ErrorCode::VerificationMismatch:
      return ReasonCode::VerificationMismatch;
    default:
      return ReasonCode::Internal;
  }
}

}  // namespace ctf
