#pragma once

// Deterministic error taxonomy and result plumbing.
//
// The runtime never reports a bare boolean for an authoritative decision: every
// refusal carries a stable code that callers, tests, and the wire protocol can
// branch on. Codes are part of the public contract.

#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <cstdint>

namespace ctf {

enum class ErrorCode : std::uint16_t {
  Ok = 0,

  // --- Input shape and decoding -------------------------------------------
  InvalidArgument = 100,
  InvalidSyntax = 101,
  OutOfRange = 102,
  PayloadTooLarge = 103,
  CollectionTooLarge = 104,
  StringTooLong = 105,
  InvalidUtf8 = 106,
  NonCanonicalEncoding = 107,
  TrailingGarbage = 108,
  UnknownMessageType = 109,
  UnsupportedValue = 110,
  MissingField = 111,
  DuplicateIdentity = 112,

  // --- Integrity, framing, and versioning ---------------------------------
  IntegrityFailure = 200,
  TruncatedInput = 201,
  VersionIncompatible = 202,
  CorruptState = 203,
  ImpossibleState = 204,

  // --- Authority and fencing ----------------------------------------------
  StaleEpoch = 300,
  ForeignEpoch = 301,
  StalePolicyGeneration = 302,
  StaleTopologyGeneration = 303,
  StaleContractGeneration = 304,
  StaleCheckpointGeneration = 305,
  StaleAttempt = 306,
  StaleEvidence = 307,
  Superseded = 308,
  ReplayDetected = 309,
  NotAuthorized = 310,
  RevalidationRequired = 311,
  SequenceViolation = 312,

  // --- Lifecycle and decisions --------------------------------------------
  NotFound = 400,
  AlreadyExists = 401,
  InvalidStateTransition = 402,
  CapacityExceeded = 403,
  ResourceExhausted = 404,
  ShuttingDown = 405,
  NotReady = 406,
  Deferred = 407,
  Denied = 408,
  DeadlineUnreachable = 409,
  VerificationMismatch = 410,
  Cancelled = 411,
  AmbiguousOutcome = 412,
  EnvelopeExhausted = 413,
  NotDurable = 414,

  // --- Environment ---------------------------------------------------------
  IoFailure = 500,
  PeerClosed = 501,
  ConnectionRefused = 502,
  Unsupported = 503,
  Internal = 504,
  AccountingImbalance = 505,
};

/// Stable, human-readable, and non-localized name for a code.
[[nodiscard]] const char* to_string(ErrorCode code) noexcept;

/// True when the code reports that authority carried by a request is no longer
/// current. Fencing refusals are always deterministic and never retried
/// internally with repaired authority.
[[nodiscard]] bool is_fencing_code(ErrorCode code) noexcept;

/// True when the code reports that a peer must re-establish authority (for
/// example after a coordinator restart) before the operation may proceed.
[[nodiscard]] bool requires_revalidation(ErrorCode code) noexcept;

/// Outcome of an operation that has no value.
class Status {
 public:
  Status() noexcept = default;

  [[nodiscard]] static Status success() noexcept { return Status{}; }
  [[nodiscard]] static Status error(ErrorCode code, std::string detail);

  [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::Ok; }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }
  [[nodiscard]] bool is_fencing() const noexcept { return is_fencing_code(code_); }

  /// "code: detail" (detail omitted when empty).
  [[nodiscard]] std::string to_string() const;

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string detail_;
};

/// Outcome of an operation that produces a value. The value is only reachable
/// when the status is Ok; value() precondition-violations are a programming
/// error, not a recoverable condition.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool ok() const noexcept { return status_.ok() && value_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

  [[nodiscard]] const Status& status() const noexcept { return status_; }
  [[nodiscard]] ErrorCode code() const noexcept { return status_.code(); }
  [[nodiscard]] const std::string& detail() const noexcept { return status_.detail(); }

  [[nodiscard]] T& value() & { return *value_; }
  [[nodiscard]] const T& value() const& { return *value_; }
  [[nodiscard]] T&& value() && { return std::move(*value_); }

  [[nodiscard]] const T* operator->() const { return &*value_; }
  [[nodiscard]] const T& operator*() const& { return *value_; }

 private:
  Status status_;
  std::optional<T> value_;
};

}  // namespace ctf
