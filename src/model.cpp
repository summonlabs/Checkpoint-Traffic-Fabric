// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/model.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <unordered_set>

namespace ctf {
namespace {

constexpr Limits kHardLimits{
    /*max_shards_per_checkpoint=*/65536,
    /*max_checkpoint_bytes=*/1ULL << 44,
    /*max_sessions=*/1U << 20,
    /*max_attempts_in_flight=*/1U << 16,
    /*max_retained_history=*/4096,
    /*max_wave_width=*/256,
    /*max_path_classes=*/256,
    /*max_sessions_per_workload=*/1024,
    /*max_workloads=*/65536,
    /*max_identity_text_bytes=*/128,
    /*max_string_bytes=*/256,
    /*max_supersession_chain=*/16,
};

void append_u32(DigestBuilder& builder, std::uint32_t value) {
  std::array<std::byte, 4> raw{};
  for (std::size_t i = 0; i < 4; ++i) {
    raw[i] = static_cast<std::byte>((value >> (8U * (3U - static_cast<unsigned>(i)))) & 0xFFU);
  }
  builder.update(ByteSpan(raw.data(), raw.size()));
}

void append_u64(DigestBuilder& builder, std::uint64_t value) {
  std::array<std::byte, 8> raw{};
  for (std::size_t i = 0; i < 8; ++i) {
    raw[i] = static_cast<std::byte>((value >> (8U * (7U - static_cast<unsigned>(i)))) & 0xFFU);
  }
  builder.update(ByteSpan(raw.data(), raw.size()));
}

void append_uuid(DigestBuilder& builder, const Uuid128& id) {
  std::array<std::byte, 16> raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) {
    raw[i] = static_cast<std::byte>(id.bytes()[i]);
  }
  builder.update(ByteSpan(raw.data(), raw.size()));
}

void append_digest(DigestBuilder& builder, const Digest& digest) {
  append_u32(builder, digest.crc32c_value());
  append_u64(builder, digest.fnv1a64_value());
}

[[nodiscard]] bool is_bounded_label(const std::string& text, std::size_t max_bytes) {
  if (text.empty() || text.size() > max_bytes) {
    return false;
  }
  for (const char c : text) {
    const auto value = static_cast<unsigned char>(c);
    const bool allowed = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                         (value >= '0' && value <= '9') || value == '.' || value == '_' ||
                         value == '-' || value == ':';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] Status check_limit(std::uint64_t value, std::uint64_t cap, const char* what) {
  if (value > cap) {
    return Status::error(ErrorCode::OutOfRange, std::string(what) + " exceeds the hard resource cap");
  }
  return Status::success();
}

}  // namespace

const char* to_string(IsolationClass value) noexcept {
  switch (value) {
    case IsolationClass::TrainingCritical:
      return "TrainingCritical";
    case IsolationClass::ServingLatency:
      return "ServingLatency";
    case IsolationClass::TrainingBulk:
      return "TrainingBulk";
    case IsolationClass::BestEffort:
      return "BestEffort";
  }
  return "Unknown";
}

std::optional<IsolationClass> isolation_class_from_string(std::string_view text) noexcept {
  if (text == "TrainingCritical") {
    return IsolationClass::TrainingCritical;
  }
  if (text == "ServingLatency") {
    return IsolationClass::ServingLatency;
  }
  if (text == "TrainingBulk") {
    return IsolationClass::TrainingBulk;
  }
  if (text == "BestEffort") {
    return IsolationClass::BestEffort;
  }
  return std::nullopt;
}

std::uint8_t isolation_rank(IsolationClass value) noexcept {
  return static_cast<std::uint8_t>(value);
}

const char* to_string(DestinationClass value) noexcept {
  switch (value) {
    case DestinationClass::LocalAttachedStore:
      return "LocalAttachedStore";
    case DestinationClass::RemoteObjectStore:
      return "RemoteObjectStore";
    case DestinationClass::PeerNodeMemory:
      return "PeerNodeMemory";
    case DestinationClass::SyntheticLab:
      return "SyntheticLab";
  }
  return "Unknown";
}

std::optional<DestinationClass> destination_class_from_string(std::string_view text) noexcept {
  if (text == "LocalAttachedStore") {
    return DestinationClass::LocalAttachedStore;
  }
  if (text == "RemoteObjectStore") {
    return DestinationClass::RemoteObjectStore;
  }
  if (text == "PeerNodeMemory") {
    return DestinationClass::PeerNodeMemory;
  }
  if (text == "SyntheticLab") {
    return DestinationClass::SyntheticLab;
  }
  return std::nullopt;
}

const char* to_string(EvidenceLevel value) noexcept {
  switch (value) {
    case EvidenceLevel::None:
      return "None";
    case EvidenceLevel::SourceComplete:
      return "SourceComplete";
    case EvidenceLevel::Transferred:
      return "Transferred";
    case EvidenceLevel::VerifiedAtDestination:
      return "VerifiedAtDestination";
  }
  return "Unknown";
}

const char* to_string(DurabilityStatus value) noexcept {
  switch (value) {
    case DurabilityStatus::NotEstablished:
      return "NotEstablished";
    case DurabilityStatus::ExternallyAsserted:
      return "ExternallyAsserted";
  }
  return "Unknown";
}

const char* to_string(SessionState value) noexcept {
  switch (value) {
    case SessionState::Submitted:
      return "Submitted";
    case SessionState::Deferred:
      return "Deferred";
    case SessionState::Admitted:
      return "Admitted";
    case SessionState::Transferring:
      return "Transferring";
    case SessionState::Paused:
      return "Paused";
    case SessionState::SourceComplete:
      return "SourceComplete";
    case SessionState::Transferred:
      return "Transferred";
    case SessionState::VerifiedAtDestination:
      return "VerifiedAtDestination";
    case SessionState::TrafficSessionComplete:
      return "TrafficSessionComplete";
    case SessionState::Cancelled:
      return "Cancelled";
    case SessionState::Superseded:
      return "Superseded";
    case SessionState::Failed:
      return "Failed";
    case SessionState::RevalidationRequired:
      return "RevalidationRequired";
  }
  return "Unknown";
}

bool is_terminal(SessionState value) noexcept {
  switch (value) {
    case SessionState::TrafficSessionComplete:
    case SessionState::Cancelled:
    case SessionState::Superseded:
    case SessionState::Failed:
      return true;
    case SessionState::Submitted:
    case SessionState::Deferred:
    case SessionState::Admitted:
    case SessionState::Transferring:
    case SessionState::Paused:
    case SessionState::SourceComplete:
    case SessionState::Transferred:
    case SessionState::VerifiedAtDestination:
    case SessionState::RevalidationRequired:
      return false;
  }
  return false;
}

bool is_active(SessionState value) noexcept { return !is_terminal(value); }

const char* to_string(ShardState value) noexcept {
  switch (value) {
    case ShardState::Pending:
      return "Pending";
    case ShardState::Granted:
      return "Granted";
    case ShardState::InFlight:
      return "InFlight";
    case ShardState::Transferred:
      return "Transferred";
    case ShardState::Verified:
      return "Verified";
    case ShardState::Ambiguous:
      return "Ambiguous";
    case ShardState::Failed:
      return "Failed";
    case ShardState::Cancelled:
      return "Cancelled";
  }
  return "Unknown";
}

const char* to_string(AttemptOutcome value) noexcept {
  switch (value) {
    case AttemptOutcome::Granted:
      return "Granted";
    case AttemptOutcome::InFlight:
      return "InFlight";
    case AttemptOutcome::DeliveredUnacked:
      return "DeliveredUnacked";
    case AttemptOutcome::DeliveredAcked:
      return "DeliveredAcked";
    case AttemptOutcome::Verified:
      return "Verified";
    case AttemptOutcome::Failed:
      return "Failed";
    case AttemptOutcome::Ambiguous:
      return "Ambiguous";
    case AttemptOutcome::Released:
      return "Released";
    case AttemptOutcome::Superseded:
      return "Superseded";
  }
  return "Unknown";
}

const char* to_string(DecisionKind value) noexcept {
  switch (value) {
    case DecisionKind::Admit:
      return "Admit";
    case DecisionKind::Defer:
      return "Defer";
    case DecisionKind::Deny:
      return "Deny";
  }
  return "Unknown";
}

const char* to_string(ReasonCode value) noexcept {
  switch (value) {
    case ReasonCode::Admitted:
      return "Admitted";
    case ReasonCode::DuplicateCommand:
      return "DuplicateCommand";
    case ReasonCode::ClassCeilingSaturated:
      return "ClassCeilingSaturated";
    case ReasonCode::WorkloadCeilingSaturated:
      return "WorkloadCeilingSaturated";
    case ReasonCode::FabricSessionLimit:
      return "FabricSessionLimit";
    case ReasonCode::PathCapacityUnavailable:
      return "PathCapacityUnavailable";
    case ReasonCode::CreditUnavailable:
      return "CreditUnavailable";
    case ReasonCode::UnknownWorkload:
      return "UnknownWorkload";
    case ReasonCode::ContractGenerationStale:
      return "ContractGenerationStale";
    case ReasonCode::PolicyGenerationStale:
      return "PolicyGenerationStale";
    case ReasonCode::TopologyGenerationStale:
      return "TopologyGenerationStale";
    case ReasonCode::CheckpointGenerationStale:
      return "CheckpointGenerationStale";
    case ReasonCode::SupersessionDeniedByPolicy:
      return "SupersessionDeniedByPolicy";
    case ReasonCode::SessionLimitPerWorkload:
      return "SessionLimitPerWorkload";
    case ReasonCode::RequestedRateUnsupported:
      return "RequestedRateUnsupported";
    case ReasonCode::ManifestInvalid:
      return "ManifestInvalid";
    case ReasonCode::ManifestMismatch:
      return "ManifestMismatch";
    case ReasonCode::DestinationNotPermitted:
      return "DestinationNotPermitted";
    case ReasonCode::CheckpointTooLarge:
      return "CheckpointTooLarge";
    case ReasonCode::DeadlineUnreachable:
      return "DeadlineUnreachable";
    case ReasonCode::FabricShuttingDown:
      return "FabricShuttingDown";
    case ReasonCode::AuthorityStale:
      return "AuthorityStale";
    case ReasonCode::AttemptStale:
      return "AttemptStale";
    case ReasonCode::VerificationRequired:
      return "VerificationRequired";
    case ReasonCode::VerificationMismatch:
      return "VerificationMismatch";
    case ReasonCode::EvidenceStale:
      return "EvidenceStale";
    case ReasonCode::SessionNotFound:
      return "SessionNotFound";
    case ReasonCode::StateNotResumable:
      return "StateNotResumable";
    case ReasonCode::AmbiguousSinkOutcome:
      return "AmbiguousSinkOutcome";
    case ReasonCode::CancelledByOperator:
      return "CancelledByOperator";
    case ReasonCode::SupersededByNewerGeneration:
      return "SupersededByNewerGeneration";
    case ReasonCode::ResourceLimit:
      return "ResourceLimit";
    case ReasonCode::Internal:
      return "Internal";
  }
  return "Unknown";
}

bool is_fencing_reason(ReasonCode value) noexcept {
  switch (value) {
    case ReasonCode::ContractGenerationStale:
    case ReasonCode::PolicyGenerationStale:
    case ReasonCode::TopologyGenerationStale:
    case ReasonCode::CheckpointGenerationStale:
    case ReasonCode::AuthorityStale:
    case ReasonCode::AttemptStale:
    case ReasonCode::EvidenceStale:
    case ReasonCode::DuplicateCommand:
    case ReasonCode::SupersededByNewerGeneration:
      return true;
    default:
      return false;
  }
}

const char* to_string(VerificationEvidence::Outcome value) noexcept {
  switch (value) {
    case VerificationEvidence::Outcome::Verified:
      return "Verified";
    case VerificationEvidence::Outcome::DigestMismatch:
      return "DigestMismatch";
    case VerificationEvidence::Outcome::Truncated:
      return "Truncated";
    case VerificationEvidence::Outcome::Ambiguous:
      return "Ambiguous";
    case VerificationEvidence::Outcome::Rejected:
      return "Rejected";
  }
  return "Unknown";
}

const char* to_string(EventKind value) noexcept {
  switch (value) {
    case EventKind::SessionSubmitted:
      return "SessionSubmitted";
    case EventKind::SessionAdmitted:
      return "SessionAdmitted";
    case EventKind::SessionDeferred:
      return "SessionDeferred";
    case EventKind::SessionDenied:
      return "SessionDenied";
    case EventKind::SessionSuperseded:
      return "SessionSuperseded";
    case EventKind::SessionCancelled:
      return "SessionCancelled";
    case EventKind::SessionCompleted:
      return "SessionCompleted";
    case EventKind::WaveGranted:
      return "WaveGranted";
    case EventKind::TransferObserved:
      return "TransferObserved";
    case EventKind::VerificationObserved:
      return "VerificationObserved";
    case EventKind::AmbiguityRecorded:
      return "AmbiguityRecorded";
    case EventKind::RevalidationRequired_:
      return "RevalidationRequired";
    case EventKind::FenceRejected:
      return "FenceRejected";
    case EventKind::Shutdown:
      return "Shutdown";
    case EventKind::SourceCompleteObserved:
      return "SourceCompleteObserved";
    case EventKind::SessionPaused:
      return "SessionPaused";
    case EventKind::SessionResumed:
      return "SessionResumed";
    case EventKind::DurabilityAsserted:
      return "DurabilityAsserted";
  }
  return "Unknown";
}

Digest compute_manifest_digest(const CheckpointManifest& manifest) {
  DigestBuilder builder;
  append_uuid(builder, manifest.checkpoint.value());
  append_u64(builder, manifest.generation.value());
  append_uuid(builder, manifest.workload.value());
  append_u64(builder, manifest.contract_generation.value());
  append_u64(builder, manifest.total_bytes);
  append_u32(builder, static_cast<std::uint32_t>(manifest.shards.size()));
  for (const ShardDescriptor& shard : manifest.shards) {
    append_u32(builder, shard.index.value());
    append_u64(builder, shard.declared_bytes);
    append_digest(builder, shard.declared_digest);
    append_u32(builder, shard.path_class.value());
  }
  return builder.finish();
}

Status validate_manifest(const CheckpointManifest& manifest, const Limits& limits) {
  if (manifest.checkpoint.is_nil()) {
    return Status::error(ErrorCode::MissingField, "manifest checkpoint identity is nil");
  }
  if (manifest.workload.is_nil()) {
    return Status::error(ErrorCode::MissingField, "manifest workload identity is nil");
  }
  if (manifest.generation.is_zero()) {
    return Status::error(ErrorCode::OutOfRange, "checkpoint generation 0 is not a valid generation");
  }
  if (manifest.contract_generation.is_zero()) {
    return Status::error(ErrorCode::OutOfRange, "contract generation 0 is not a valid generation");
  }
  if (manifest.shards.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "manifest declares no shards");
  }
  if (manifest.shards.size() > limits.max_shards_per_checkpoint) {
    return Status::error(ErrorCode::CollectionTooLarge, "manifest shard count exceeds the configured bound");
  }
  if (manifest.total_bytes == 0) {
    return Status::error(ErrorCode::InvalidArgument, "manifest declares zero total bytes");
  }
  if (manifest.total_bytes > limits.max_checkpoint_bytes) {
    return Status::error(ErrorCode::OutOfRange, "manifest total bytes exceeds the configured bound");
  }

  std::uint64_t sum = 0;
  std::optional<ShardIndex> previous;
  for (const ShardDescriptor& shard : manifest.shards) {
    if (shard.declared_bytes == 0) {
      return Status::error(ErrorCode::InvalidArgument, "manifest contains a zero-byte shard");
    }
    if (previous.has_value() && !(previous.value() < shard.index)) {
      return Status::error(ErrorCode::InvalidArgument,
                           "manifest shard indices must be strictly increasing and unique");
    }
    previous = shard.index;
    if (sum > manifest.total_bytes || shard.declared_bytes > manifest.total_bytes - sum) {
      return Status::error(ErrorCode::ImpossibleState,
                           "manifest shard bytes exceed the declared total");
    }
    sum += shard.declared_bytes;
  }
  if (sum != manifest.total_bytes) {
    return Status::error(ErrorCode::ImpossibleState,
                         "manifest shard bytes do not sum to the declared total");
  }
  if (manifest.manifest_digest != compute_manifest_digest(manifest)) {
    return Status::error(ErrorCode::IntegrityFailure, "manifest digest does not match its shard table");
  }
  return Status::success();
}

bool manifests_equivalent(const CheckpointManifest& lhs, const CheckpointManifest& rhs) {
  if (!(lhs.checkpoint == rhs.checkpoint) || !(lhs.generation == rhs.generation) ||
      !(lhs.workload == rhs.workload) || !(lhs.contract_generation == rhs.contract_generation)) {
    return false;
  }
  if (lhs.total_bytes != rhs.total_bytes || lhs.shards.size() != rhs.shards.size()) {
    return false;
  }
  return std::equal(lhs.shards.begin(), lhs.shards.end(), rhs.shards.begin(),
                    [](const ShardDescriptor& a, const ShardDescriptor& b) { return a == b; });
}

Status validate_policy(const PolicySnapshot& policy, const Limits& limits) {
  (void)limits;  // policy is validated against the hard caps below, not against itself
  if (policy.generation.is_zero()) {
    return Status::error(ErrorCode::OutOfRange, "policy generation 0 is not a valid generation");
  }
  if (policy.envelopes.size() != 4) {
    return Status::error(ErrorCode::InvalidArgument,
                         "policy must define exactly one envelope per isolation class");
  }
  std::array<bool, 4> seen{};
  for (const IsolationEnvelopeConfig& envelope : policy.envelopes) {
    const std::size_t index = static_cast<std::size_t>(envelope.isolation);
    if (index >= seen.size()) {
      return Status::error(ErrorCode::UnsupportedValue, "policy envelope names an unknown isolation class");
    }
    if (seen[index]) {
      return Status::error(ErrorCode::InvalidArgument, "policy defines an isolation class twice");
    }
    seen[index] = true;
    if (envelope.ceiling_bps == 0) {
      return Status::error(ErrorCode::InvalidArgument, "policy envelope ceiling must be positive");
    }
    if (envelope.burst_window_ns <= 0) {
      return Status::error(ErrorCode::InvalidArgument, "policy envelope burst window must be positive");
    }
    if (envelope.max_in_flight_sessions == 0) {
      return Status::error(ErrorCode::InvalidArgument, "policy envelope session bound must be positive");
    }
    Status status = check_limit(envelope.max_in_flight_sessions, kHardLimits.max_sessions,
                                "policy envelope session bound");
    if (!status.ok()) {
      return status;
    }
  }
  const auto missing = std::find(seen.begin(), seen.end(), false);
  if (missing != seen.end()) {
    return Status::error(ErrorCode::InvalidArgument, "policy is missing an isolation class envelope");
  }
  if (policy.max_wave_width == 0) {
    return Status::error(ErrorCode::InvalidArgument, "policy wave width must be positive");
  }
  if (policy.max_session_bytes == 0) {
    return Status::error(ErrorCode::InvalidArgument, "policy session byte bound must be positive");
  }
  if (policy.max_attempts_in_flight == 0) {
    return Status::error(ErrorCode::InvalidArgument, "policy attempt bound must be positive");
  }
  if (policy.retained_history == 0) {
    return Status::error(ErrorCode::InvalidArgument, "policy retained history must be positive");
  }
  if (policy.defer_horizon_ns <= 0) {
    return Status::error(ErrorCode::InvalidArgument, "policy defer horizon must be positive");
  }
  if (policy.default_deadline_ns <= 0) {
    return Status::error(ErrorCode::InvalidArgument, "policy default deadline must be positive");
  }
  Status status = check_limit(policy.max_wave_width, kHardLimits.max_wave_width, "policy wave width");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.max_sessions, kHardLimits.max_sessions, "policy session bound");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.max_attempts_in_flight, kHardLimits.max_attempts_in_flight,
                       "policy attempt bound");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.retained_history, kHardLimits.max_retained_history,
                       "policy retained history");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.max_session_bytes, kHardLimits.max_checkpoint_bytes,
                       "policy session byte bound");
  if (!status.ok()) {
    return status;
  }
  // Nested limits must themselves stay inside the hard caps.
  status = check_limit(policy.limits.max_shards_per_checkpoint, kHardLimits.max_shards_per_checkpoint,
                       "limits.max_shards_per_checkpoint");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_checkpoint_bytes, kHardLimits.max_checkpoint_bytes,
                       "limits.max_checkpoint_bytes");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_sessions, kHardLimits.max_sessions, "limits.max_sessions");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_attempts_in_flight, kHardLimits.max_attempts_in_flight,
                       "limits.max_attempts_in_flight");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_retained_history, kHardLimits.max_retained_history,
                       "limits.max_retained_history");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_wave_width, kHardLimits.max_wave_width, "limits.max_wave_width");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_path_classes, kHardLimits.max_path_classes,
                       "limits.max_path_classes");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_sessions_per_workload, kHardLimits.max_sessions_per_workload,
                       "limits.max_sessions_per_workload");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_workloads, kHardLimits.max_workloads, "limits.max_workloads");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_string_bytes, kHardLimits.max_string_bytes,
                       "limits.max_string_bytes");
  if (!status.ok()) {
    return status;
  }
  status = check_limit(policy.limits.max_supersession_chain, kHardLimits.max_supersession_chain,
                       "limits.max_supersession_chain");
  return status;
}

Status validate_topology(const TopologySnapshot& topology, const Limits& limits) {
  if (topology.generation.is_zero()) {
    return Status::error(ErrorCode::OutOfRange, "topology generation 0 is not a valid generation");
  }
  if (topology.path_classes.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "topology declares no path classes");
  }
  if (topology.path_classes.size() > limits.max_path_classes) {
    return Status::error(ErrorCode::CollectionTooLarge, "topology path class count exceeds the bound");
  }
  std::unordered_set<std::uint32_t> ids;
  for (const PathClass& path : topology.path_classes) {
    if (path.id.value() == 0) {
      return Status::error(ErrorCode::InvalidArgument, "path class id 0 is reserved for the default path");
    }
    if (!ids.insert(path.id.value()).second) {
      return Status::error(ErrorCode::DuplicateIdentity, "topology declares a path class id twice");
    }
    if (path.capacity_bps == 0) {
      return Status::error(ErrorCode::InvalidArgument, "path class capacity must be positive");
    }
    if (!path.label.empty() && !is_bounded_label(path.label, limits.max_string_bytes)) {
      return Status::error(ErrorCode::InvalidSyntax, "path class label is not a bounded identifier");
    }
  }
  return Status::success();
}

Status validate_contract(const WorkloadContract& contract, const Limits& limits) {
  if (contract.workload.is_nil()) {
    return Status::error(ErrorCode::MissingField, "workload contract identity is nil");
  }
  if (contract.generation.is_zero()) {
    return Status::error(ErrorCode::OutOfRange, "contract generation 0 is not a valid generation");
  }
  if (contract.ceiling_bps == 0) {
    return Status::error(ErrorCode::InvalidArgument, "contract ceiling must be positive");
  }
  if (contract.floor_bps > contract.ceiling_bps) {
    return Status::error(ErrorCode::InvalidArgument, "contract floor exceeds the contract ceiling");
  }
  if (contract.max_in_flight_sessions == 0) {
    return Status::error(ErrorCode::InvalidArgument, "contract session bound must be positive");
  }
  if (contract.max_in_flight_sessions > limits.max_sessions_per_workload) {
    return Status::error(ErrorCode::OutOfRange, "contract session bound exceeds the configured cap");
  }
  if (contract.max_shards_per_wave == 0) {
    return Status::error(ErrorCode::InvalidArgument, "contract wave bound must be positive");
  }
  if (contract.max_shards_per_wave > limits.max_shards_per_checkpoint) {
    return Status::error(ErrorCode::OutOfRange, "contract wave bound exceeds the configured cap");
  }
  if (contract.deadline_budget_ns <= 0) {
    return Status::error(ErrorCode::InvalidArgument, "contract deadline budget must be positive");
  }
  return Status::success();
}

const IsolationEnvelopeConfig* find_envelope(const PolicySnapshot& policy,
                                             IsolationClass isolation) noexcept {
  for (const IsolationEnvelopeConfig& envelope : policy.envelopes) {
    if (envelope.isolation == isolation) {
      return &envelope;
    }
  }
  return nullptr;
}

const PathClass* find_path_class(const TopologySnapshot& topology, PathClassId id) noexcept {
  for (const PathClass& path : topology.path_classes) {
    if (path.id == id) {
      return &path;
    }
  }
  return nullptr;
}

std::optional<PathClassId> default_path_class_for(const TopologySnapshot& topology,
                                                  DestinationClass destination) noexcept {
  std::optional<PathClassId> best;
  for (const PathClass& path : topology.path_classes) {
    if (path.destination != destination) {
      continue;
    }
    if (!best.has_value() || path.id < best.value()) {
      best = path.id;
    }
  }
  return best;
}

}  // namespace ctf
