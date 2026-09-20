#pragma once

// Fencing.
//
// Every authoritative operation carries a CommandFence. A fence is accepted
// only when every generation in it is exactly the one the coordinator is
// currently acting under. Older values are refusals, never silent upgrades:
// the caller must re-read authority and reissue the command.

#include <string>

#include "ctf/ids.hpp"
#include "ctf/model.hpp"
#include "ctf/status.hpp"

namespace ctf {

/// The authority the coordinator currently acts under.
struct FenceContext {
  CoordinatorEpoch epoch;
  PolicyGeneration policy_generation;
  TopologyGeneration topology_generation;
  WorkloadContractGeneration contract_generation;

  friend bool operator==(const FenceContext& lhs, const FenceContext& rhs) noexcept {
    return lhs.epoch == rhs.epoch && lhs.policy_generation == rhs.policy_generation &&
           lhs.topology_generation == rhs.topology_generation &&
           lhs.contract_generation == rhs.contract_generation;
  }
};

/// Deterministic refusal classification for a fence.
struct FenceVerdict {
  Status status;
  ReasonCode reason = ReasonCode::Admitted;

  [[nodiscard]] bool ok() const noexcept { return status.ok(); }
};

/// Checks epoch, policy, topology, and workload-contract generations.
/// Session-scoped dimensions (checkpoint generation, attempt sequence) are
/// checked by the engine against live session state.
[[nodiscard]] FenceVerdict validate_fence(const CommandFence& fence, const FenceContext& current);

/// Reason code that corresponds to a fencing ErrorCode.
[[nodiscard]] ReasonCode reason_for_fence_code(ErrorCode code) noexcept;

}  // namespace ctf
