#pragma once

// Stable identities, generations, and epochs.
//
// Rules encoded here:
//   * an identifier is not a generation - the same checkpoint identity may be
//     re-published under a newer generation, and the older one must be fenced;
//   * an epoch is a (incarnation, term) pair, so a restarted coordinator is
//     never mistaken for the process it replaced;
//   * text forms have exactly one canonical spelling, and parsing rejects
//     everything else instead of repairing it.

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>

#include "ctf/status.hpp"

namespace ctf {

class IdFactory;

/// 128-bit identity. Canonical text form: 8-4-4-4-12 lowercase hex.
class Uuid128 {
 public:
  constexpr Uuid128() noexcept = default;
  explicit constexpr Uuid128(std::array<std::uint8_t, 16> bytes) noexcept : bytes_(bytes) {}

  [[nodiscard]] static constexpr Uuid128 nil() noexcept { return Uuid128{}; }
  [[nodiscard]] static std::optional<Uuid128> parse(std::string_view text) noexcept;
  [[nodiscard]] static Uuid128 random(IdFactory& factory) noexcept;

  [[nodiscard]] constexpr const std::array<std::uint8_t, 16>& bytes() const noexcept {
    return bytes_;
  }
  [[nodiscard]] constexpr bool is_nil() const noexcept {
    for (const std::uint8_t byte : bytes_) {
      if (byte != 0) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] std::string to_string() const;

  friend constexpr bool operator==(const Uuid128& lhs, const Uuid128& rhs) noexcept = default;
  friend constexpr auto operator<=>(const Uuid128& lhs, const Uuid128& rhs) noexcept = default;

 private:
  std::array<std::uint8_t, 16> bytes_{};
};

struct Uuid128Hash {
  [[nodiscard]] std::size_t operator()(const Uuid128& value) const noexcept;
};

/// Deterministic identity source. Seeded explicitly so tests and property runs
/// can reproduce every identity they observed.
class IdFactory {
 public:
  explicit IdFactory(std::uint64_t seed) noexcept : rng_(seed) {}

  [[nodiscard]] Uuid128 next() noexcept;
  [[nodiscard]] std::uint64_t next_u64() noexcept { return rng_(); }

 private:
  std::mt19937_64 rng_;
};

inline Uuid128 Uuid128::random(IdFactory& factory) noexcept { return factory.next(); }

/// Strongly typed wrapper over Uuid128 so distinct identity domains cannot be
/// substituted for one another at compile time.
template <class Tag>
class StrongId {
 public:
  constexpr StrongId() noexcept = default;
  explicit constexpr StrongId(Uuid128 value) noexcept : value_(value) {}

  [[nodiscard]] static std::optional<StrongId> parse(std::string_view text) noexcept {
    const std::optional<Uuid128> parsed = Uuid128::parse(text);
    if (!parsed.has_value()) {
      return std::nullopt;
    }
    return StrongId(*parsed);
  }

  [[nodiscard]] constexpr const Uuid128& value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_nil() const noexcept { return value_.is_nil(); }
  [[nodiscard]] std::string to_string() const { return value_.to_string(); }

  friend constexpr bool operator==(const StrongId& lhs, const StrongId& rhs) noexcept = default;
  friend constexpr auto operator<=>(const StrongId& lhs, const StrongId& rhs) noexcept = default;

 private:
  Uuid128 value_;
};

template <class Tag>
struct StrongIdHash {
  [[nodiscard]] std::size_t operator()(const StrongId<Tag>& id) const noexcept {
    return Uuid128Hash{}(id.value());
  }
};

/// Strongly typed unsigned scalar with canonical decimal text form.
template <class Tag, class T>
class StrongScalar {
 public:
  using value_type = T;
  static_assert(std::numeric_limits<T>::is_integer && !std::numeric_limits<T>::is_signed,
                "StrongScalar requires an unsigned integer type");
  static_assert((std::numeric_limits<T>::max)() >= 9,
                "StrongScalar requires at least one decimal digit");

  constexpr StrongScalar() noexcept = default;
  explicit constexpr StrongScalar(T value) noexcept : value_(value) {}

  [[nodiscard]] constexpr T value() const noexcept { return value_; }
  [[nodiscard]] std::string to_string() const { return std::to_string(value_); }

  /// Canonical decimal parsing: digits only, no sign, no leading zeros, no
  /// whitespace, and no value beyond the representable range.
  [[nodiscard]] static std::optional<StrongScalar> parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    if (text.size() > 1 && text.front() == '0') {
      return std::nullopt;
    }
    const std::uint64_t limit = static_cast<std::uint64_t>((std::numeric_limits<T>::max)());
    std::uint64_t accumulator = 0;
    for (const char c : text) {
      if (c < '0' || c > '9') {
        return std::nullopt;
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
      if (accumulator > (limit - digit) / 10U) {
        return std::nullopt;
      }
      accumulator = accumulator * 10U + digit;
    }
    return StrongScalar(static_cast<T>(accumulator));
  }

  friend constexpr bool operator==(const StrongScalar& lhs, const StrongScalar& rhs) noexcept = default;
  friend constexpr auto operator<=>(const StrongScalar& lhs, const StrongScalar& rhs) noexcept = default;

 private:
  T value_{};
};

template <class Tag, class T>
struct StrongScalarHash {
  [[nodiscard]] std::size_t operator()(const StrongScalar<Tag, T>& value) const noexcept {
    return static_cast<std::size_t>(value.value());
  }
};

/// Monotonic counter for a fenced dimension (checkpoint, contract, topology,
/// policy, attempt, incarnation, term).
template <class Tag>
class Generation {
 public:
  using value_type = std::uint64_t;

  constexpr Generation() noexcept = default;
  explicit constexpr Generation(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }
  [[nodiscard]] std::string to_string() const { return std::to_string(value_); }

  /// Advance by one. Returns false when the counter is exhausted; the value is
  /// left unchanged so a wrapped generation can never be mistaken for a newer
  /// one.
  bool advance() noexcept {
    if (value_ == (std::numeric_limits<std::uint64_t>::max)()) {
      return false;
    }
    ++value_;
    return true;
  }

  /// Successor value. Precondition: the counter is not exhausted (checked by
  /// advance()); callers that cannot prove this must use advance().
  [[nodiscard]] constexpr Generation next() const noexcept { return Generation(value_ + 1U); }

  [[nodiscard]] static std::optional<Generation> parse(std::string_view text) noexcept {
    const std::optional<StrongScalar<struct GenerationDigitsTag, std::uint64_t>> parsed =
        StrongScalar<struct GenerationDigitsTag, std::uint64_t>::parse(text);
    if (!parsed.has_value()) {
      return std::nullopt;
    }
    return Generation(parsed->value());
  }

  friend constexpr bool operator==(const Generation& lhs, const Generation& rhs) noexcept = default;
  friend constexpr auto operator<=>(const Generation& lhs, const Generation& rhs) noexcept = default;

 private:
  std::uint64_t value_{0};
};

template <class Tag>
struct GenerationHash {
  [[nodiscard]] std::size_t operator()(const Generation<Tag>& value) const noexcept {
    return static_cast<std::size_t>(value.value());
  }
};

// --- Domain identities ------------------------------------------------------

using CheckpointId = StrongId<struct CheckpointIdTag>;
using CheckpointTrafficSessionId = StrongId<struct CheckpointTrafficSessionIdTag>;
using SessionId = CheckpointTrafficSessionId;
using TransferAttemptId = StrongId<struct TransferAttemptIdTag>;
using WorkloadId = StrongId<struct WorkloadIdTag>;
using CommandId = StrongId<struct CommandIdTag>;

using ShardIndex = StrongScalar<struct ShardIndexTag, std::uint32_t>;
using WaveIndex = StrongScalar<struct WaveIndexTag, std::uint32_t>;
using PathClassId = StrongScalar<struct PathClassIdTag, std::uint32_t>;

// --- Domain generations -----------------------------------------------------

using CheckpointGeneration = Generation<struct CheckpointGenerationTag>;
using WorkloadContractGeneration = Generation<struct WorkloadContractGenerationTag>;
using TopologyGeneration = Generation<struct TopologyGenerationTag>;
using PolicyGeneration = Generation<struct PolicyGenerationTag>;
using AttemptSequence = Generation<struct AttemptSequenceTag>;
using IncarnationId = Generation<struct IncarnationIdTag>;
using EpochTerm = Generation<struct EpochTermTag>;

/// Coordinator authority epoch: which process incarnation, and which term within
/// that incarnation. Every authoritative decision is bound to one.
struct CoordinatorEpoch {
  IncarnationId incarnation;
  EpochTerm term;

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] static std::optional<CoordinatorEpoch> parse(std::string_view text) noexcept;

  friend constexpr bool operator==(const CoordinatorEpoch& lhs,
                                   const CoordinatorEpoch& rhs) noexcept = default;
  friend constexpr auto operator<=>(const CoordinatorEpoch& lhs,
                                    const CoordinatorEpoch& rhs) noexcept = default;
};

struct CoordinatorEpochHash {
  [[nodiscard]] std::size_t operator()(const CoordinatorEpoch& epoch) const noexcept;
};

}  // namespace ctf
