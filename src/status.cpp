// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/status.hpp"

namespace ctf {
namespace {

struct CodeName {
  ErrorCode code;
  const char* name;
};

constexpr CodeName kCodeNames[] = {
    {ErrorCode::Ok, "Ok"},
    {ErrorCode::InvalidArgument, "InvalidArgument"},
    {ErrorCode::InvalidSyntax, "InvalidSyntax"},
    {ErrorCode::OutOfRange, "OutOfRange"},
    {ErrorCode::PayloadTooLarge, "PayloadTooLarge"},
    {ErrorCode::CollectionTooLarge, "CollectionTooLarge"},
    {ErrorCode::StringTooLong, "StringTooLong"},
    {ErrorCode::InvalidUtf8, "InvalidUtf8"},
    {ErrorCode::NonCanonicalEncoding, "NonCanonicalEncoding"},
    {ErrorCode::TrailingGarbage, "TrailingGarbage"},
    {ErrorCode::UnknownMessageType, "UnknownMessageType"},
    {ErrorCode::UnsupportedValue, "UnsupportedValue"},
    {ErrorCode::MissingField, "MissingField"},
    {ErrorCode::DuplicateIdentity, "DuplicateIdentity"},
    {ErrorCode::IntegrityFailure, "IntegrityFailure"},
    {ErrorCode::TruncatedInput, "TruncatedInput"},
    {ErrorCode::VersionIncompatible, "VersionIncompatible"},
    {ErrorCode::CorruptState, "CorruptState"},
    {ErrorCode::ImpossibleState, "ImpossibleState"},
    {ErrorCode::StaleEpoch, "StaleEpoch"},
    {ErrorCode::ForeignEpoch, "ForeignEpoch"},
    {ErrorCode::StalePolicyGeneration, "StalePolicyGeneration"},
    {ErrorCode::StaleTopologyGeneration, "StaleTopologyGeneration"},
    {ErrorCode::StaleContractGeneration, "StaleContractGeneration"},
    {ErrorCode::StaleCheckpointGeneration, "StaleCheckpointGeneration"},
    {ErrorCode::StaleAttempt, "StaleAttempt"},
    {ErrorCode::StaleEvidence, "StaleEvidence"},
    {ErrorCode::Superseded, "Superseded"},
    {ErrorCode::ReplayDetected, "ReplayDetected"},
    {ErrorCode::NotAuthorized, "NotAuthorized"},
    {ErrorCode::RevalidationRequired, "RevalidationRequired"},
    {ErrorCode::SequenceViolation, "SequenceViolation"},
    {ErrorCode::NotFound, "NotFound"},
    {ErrorCode::AlreadyExists, "AlreadyExists"},
    {ErrorCode::InvalidStateTransition, "InvalidStateTransition"},
    {ErrorCode::CapacityExceeded, "CapacityExceeded"},
    {ErrorCode::ResourceExhausted, "ResourceExhausted"},
    {ErrorCode::ShuttingDown, "ShuttingDown"},
    {ErrorCode::NotReady, "NotReady"},
    {ErrorCode::Deferred, "Deferred"},
    {ErrorCode::Denied, "Denied"},
    {ErrorCode::DeadlineUnreachable, "DeadlineUnreachable"},
    {ErrorCode::VerificationMismatch, "VerificationMismatch"},
    {ErrorCode::Cancelled, "Cancelled"},
    {ErrorCode::AmbiguousOutcome, "AmbiguousOutcome"},
    {ErrorCode::EnvelopeExhausted, "EnvelopeExhausted"},
    {ErrorCode::NotDurable, "NotDurable"},
    {ErrorCode::IoFailure, "IoFailure"},
    {ErrorCode::PeerClosed, "PeerClosed"},
    {ErrorCode::ConnectionRefused, "ConnectionRefused"},
    {ErrorCode::Unsupported, "Unsupported"},
    {ErrorCode::Internal, "Internal"},
    {ErrorCode::AccountingImbalance, "AccountingImbalance"},
};

}  // namespace

const char* to_string(ErrorCode code) noexcept {
  for (const CodeName& entry : kCodeNames) {
    if (entry.code == code) {
      return entry.name;
    }
  }
  return "Unknown";
}

bool is_fencing_code(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::StaleEpoch:
    case ErrorCode::ForeignEpoch:
    case ErrorCode::StalePolicyGeneration:
    case ErrorCode::StaleTopologyGeneration:
    case ErrorCode::StaleContractGeneration:
    case ErrorCode::StaleCheckpointGeneration:
    case ErrorCode::StaleAttempt:
    case ErrorCode::StaleEvidence:
    case ErrorCode::Superseded:
    case ErrorCode::ReplayDetected:
    case ErrorCode::NotAuthorized:
    case ErrorCode::SequenceViolation:
      return true;
    default:
      return false;
  }
}

bool requires_revalidation(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::RevalidationRequired:
    case ErrorCode::StaleEpoch:
    case ErrorCode::ForeignEpoch:
    case ErrorCode::AmbiguousOutcome:
      return true;
    default:
      return false;
  }
}

Status Status::error(ErrorCode code, std::string detail) {
  Status status;
  status.code_ = code;
  status.detail_ = std::move(detail);
  return status;
}

std::string Status::to_string() const {
  std::string out = ctf::to_string(code_);
  if (!detail_.empty()) {
    out += ": ";
    out += detail_;
  }
  return out;
}

}  // namespace ctf
