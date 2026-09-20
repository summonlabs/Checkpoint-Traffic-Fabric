// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Private: deterministic integer rate shaping.
//
// All arithmetic is integer-only so that a given clock sequence always yields
// the same grants on every platform. This header is not installed.

#pragma once

#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>

#include "ctf/ids.hpp"
#include "ctf/model.hpp"
#include "ctf/time.hpp"

namespace ctf::detail {

/// Token bucket in bytes. Tokens accrue at rate_bps and are capped at the
/// burst capacity; a caller that never consumes cannot bank more than a burst.
class TokenBucket {
 public:
  void configure(std::uint64_t rate_bps, std::uint64_t burst_window_ns, Nanos now) noexcept;
  [[nodiscard]] bool configured() const noexcept { return configured_; }
  [[nodiscard]] std::uint64_t rate_bps() const noexcept { return rate_bps_; }
  [[nodiscard]] std::uint64_t capacity_bytes() const noexcept { return capacity_bytes_; }
  [[nodiscard]] std::uint64_t tokens() const noexcept { return tokens_; }

  void refill(Nanos now) noexcept;
  [[nodiscard]] bool try_consume(Nanos now, std::uint64_t bytes) noexcept;
  void release(std::uint64_t bytes) noexcept;
  /// Deterministic estimate of how long until the requested bytes are available.
  [[nodiscard]] Nanos time_until(std::uint64_t bytes) const noexcept;

 private:
  std::uint64_t rate_bps_ = 0;
  std::uint64_t capacity_bytes_ = 0;
  std::uint64_t tokens_ = 0;
  Nanos last_ns_ = 0;
  bool configured_ = false;
};

struct ShaperVerdict {
  bool admitted = false;
  ReasonCode reason = ReasonCode::Admitted;
  Nanos retry_after = 0;
  std::string detail;
};

/// Fabric-wide shaper: per-isolation-class ceilings, per-workload ceilings, and
/// per-path-class rate reservations. Not thread-safe by itself; the engine owns
/// it under its own lock.
class RateShaper {
 public:
  void configure_class(IsolationClass isolation, std::uint64_t ceiling_bps, Nanos burst_window_ns,
                       Nanos now);
  void configure_workload(WorkloadId workload, std::uint64_t ceiling_bps, Nanos burst_window_ns,
                          Nanos now);
  void drop_workload(WorkloadId workload);

  /// Admission-time reservation of a session rate against a path class.
  [[nodiscard]] bool reserve_path_rate(PathClassId path, std::uint64_t rate_bps);
  void release_path_rate(PathClassId path, std::uint64_t rate_bps) noexcept;
  [[nodiscard]] std::uint64_t reserved_path_rate(PathClassId path) const noexcept;

  /// Grant-only consumption across the class and workload buckets.
  [[nodiscard]] ShaperVerdict try_consume(IsolationClass isolation, WorkloadId workload,
                                          std::uint64_t bytes, Nanos now);
  /// Return authorised-but-unused bytes to both buckets.
  void release(IsolationClass isolation, WorkloadId workload, std::uint64_t bytes, Nanos now);

  [[nodiscard]] std::uint64_t class_tokens(IsolationClass isolation) const noexcept;
  [[nodiscard]] std::uint64_t workload_tokens(WorkloadId workload) const noexcept;
  /// Credit observed at "now": refills first, so a caller that has been idle
  /// never reads a stale budget.
  [[nodiscard]] std::uint64_t class_tokens_at(IsolationClass isolation, Nanos now);
  [[nodiscard]] std::uint64_t workload_tokens_at(WorkloadId workload, Nanos now);
  [[nodiscard]] Nanos class_time_until_at(IsolationClass isolation, std::uint64_t bytes, Nanos now);
  [[nodiscard]] std::uint64_t class_rate(IsolationClass isolation) const noexcept;
  [[nodiscard]] std::uint64_t workload_rate(WorkloadId workload) const noexcept;
  [[nodiscard]] Nanos class_time_until(IsolationClass isolation, std::uint64_t bytes) const noexcept;
  [[nodiscard]] Nanos workload_time_until(WorkloadId workload, std::uint64_t bytes) const noexcept;

 private:
  std::unordered_map<std::uint8_t, TokenBucket> classes_;
  std::unordered_map<WorkloadId, TokenBucket, StrongIdHash<struct WorkloadIdTag>> workloads_;
  std::unordered_map<std::uint32_t, std::uint64_t> path_reservations_;
};

}  // namespace ctf::detail
