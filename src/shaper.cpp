// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "shaper.hpp"

#include <algorithm>

namespace ctf::detail {
namespace {

/// Refill amount for an elapsed interval, with the interval clamped so the
/// product never overflows and a stalled process cannot bank unbounded credit.
[[nodiscard]] std::uint64_t refill_bytes(std::uint64_t rate_bps, Nanos elapsed_ns) noexcept {
  if (rate_bps == 0 || elapsed_ns <= 0) {
    return 0;
  }
  const std::uint64_t elapsed =
      static_cast<std::uint64_t>(std::min<Nanos>(elapsed_ns, kNanosPerSecond));
  const std::uint64_t whole = rate_bps / static_cast<std::uint64_t>(kNanosPerSecond);
  const std::uint64_t remainder = rate_bps % static_cast<std::uint64_t>(kNanosPerSecond);
  const std::uint64_t from_whole = whole * elapsed;
  const std::uint64_t from_remainder =
      (remainder * elapsed) / static_cast<std::uint64_t>(kNanosPerSecond);
  return from_whole + from_remainder;
}

[[nodiscard]] std::uint64_t burst_capacity(std::uint64_t rate_bps, Nanos burst_window_ns) noexcept {
  if (rate_bps == 0 || burst_window_ns <= 0) {
    return 0;
  }
  const std::uint64_t window = static_cast<std::uint64_t>(burst_window_ns);
  const std::uint64_t whole = rate_bps / static_cast<std::uint64_t>(kNanosPerSecond);
  const std::uint64_t remainder = rate_bps % static_cast<std::uint64_t>(kNanosPerSecond);
  std::uint64_t capacity =
      whole * window + (remainder * window) / static_cast<std::uint64_t>(kNanosPerSecond);
  const std::uint64_t floor_capacity = rate_bps / 100U;  // at least 10ms worth
  if (capacity < floor_capacity) {
    capacity = floor_capacity;
  }
  return capacity;
}

}  // namespace

void TokenBucket::configure(std::uint64_t rate_bps, std::uint64_t burst_window_ns, Nanos now) noexcept {
  rate_bps_ = rate_bps;
  capacity_bytes_ = burst_capacity(rate_bps, static_cast<Nanos>(burst_window_ns));
  tokens_ = capacity_bytes_;
  last_ns_ = now;
  configured_ = true;
}

void TokenBucket::refill(Nanos now) noexcept {
  if (!configured_ || now <= last_ns_) {
    return;
  }
  const std::uint64_t accrued = refill_bytes(rate_bps_, now - last_ns_);
  last_ns_ = now;
  if (accrued == 0) {
    return;
  }
  if (tokens_ >= capacity_bytes_ || accrued >= capacity_bytes_ - tokens_) {
    tokens_ = capacity_bytes_;
    return;
  }
  tokens_ += accrued;
}

bool TokenBucket::try_consume(Nanos now, std::uint64_t bytes) noexcept {
  refill(now);
  if (bytes > tokens_) {
    return false;
  }
  tokens_ -= bytes;
  return true;
}

void TokenBucket::release(std::uint64_t bytes) noexcept {
  if (tokens_ >= capacity_bytes_ || bytes >= capacity_bytes_ - tokens_) {
    tokens_ = capacity_bytes_;
    return;
  }
  tokens_ += bytes;
}

Nanos TokenBucket::time_until(std::uint64_t bytes) const noexcept {
  if (!configured_ || rate_bps_ == 0) {
    return 0;
  }
  const std::uint64_t missing = bytes > tokens_ ? bytes - tokens_ : 0;
  if (missing == 0) {
    return 0;
  }
  const std::uint64_t nanos =
      (missing * static_cast<std::uint64_t>(kNanosPerSecond)) / rate_bps_;
  return static_cast<Nanos>(nanos) + 1;
}

void RateShaper::configure_class(IsolationClass isolation, std::uint64_t ceiling_bps,
                                 Nanos burst_window_ns, Nanos now) {
  classes_[static_cast<std::uint8_t>(isolation)].configure(
      ceiling_bps, static_cast<std::uint64_t>(burst_window_ns), now);
}

void RateShaper::configure_workload(WorkloadId workload, std::uint64_t ceiling_bps,
                                    Nanos burst_window_ns, Nanos now) {
  workloads_[workload].configure(ceiling_bps, static_cast<std::uint64_t>(burst_window_ns), now);
}

void RateShaper::drop_workload(WorkloadId workload) { workloads_.erase(workload); }

bool RateShaper::reserve_path_rate(PathClassId path, std::uint64_t rate_bps) {
  const auto it = path_reservations_.find(path.value());
  if (it == path_reservations_.end()) {
    path_reservations_.emplace(path.value(), rate_bps);
    return true;
  }
  if (rate_bps > (std::numeric_limits<std::uint64_t>::max)() - it->second) {
    return false;
  }
  it->second += rate_bps;
  return true;
}

void RateShaper::release_path_rate(PathClassId path, std::uint64_t rate_bps) noexcept {
  const auto it = path_reservations_.find(path.value());
  if (it == path_reservations_.end()) {
    return;
  }
  it->second = rate_bps >= it->second ? 0 : it->second - rate_bps;
}

std::uint64_t RateShaper::reserved_path_rate(PathClassId path) const noexcept {
  const auto it = path_reservations_.find(path.value());
  return it == path_reservations_.end() ? 0 : it->second;
}

ShaperVerdict RateShaper::try_consume(IsolationClass isolation, WorkloadId workload,
                                      std::uint64_t bytes, Nanos now) {
  ShaperVerdict verdict;
  const auto class_it = classes_.find(static_cast<std::uint8_t>(isolation));
  if (class_it == classes_.end() || !class_it->second.configured()) {
    verdict.reason = ReasonCode::ClassCeilingSaturated;
    verdict.detail = "no isolation-class envelope is configured";
    return verdict;
  }
  const auto workload_it = workloads_.find(workload);
  if (workload_it == workloads_.end() || !workload_it->second.configured()) {
    verdict.reason = ReasonCode::WorkloadCeilingSaturated;
    verdict.detail = "no workload envelope is configured";
    return verdict;
  }
  class_it->second.refill(now);
  workload_it->second.refill(now);
  if (class_it->second.tokens() < bytes) {
    verdict.reason = ReasonCode::ClassCeilingSaturated;
    verdict.retry_after = now + class_it->second.time_until(bytes);
    verdict.detail = "isolation-class ceiling has no credit";
    return verdict;
  }
  if (workload_it->second.tokens() < bytes) {
    verdict.reason = ReasonCode::WorkloadCeilingSaturated;
    verdict.retry_after = now + workload_it->second.time_until(bytes);
    verdict.detail = "workload ceiling has no credit";
    return verdict;
  }
  const bool class_ok = class_it->second.try_consume(now, bytes);
  const bool workload_ok = workload_it->second.try_consume(now, bytes);
  if (!class_ok || !workload_ok) {
    verdict.reason = ReasonCode::CreditUnavailable;
    verdict.detail = "credit accounting disagreed at consumption time";
    return verdict;
  }
  verdict.admitted = true;
  verdict.reason = ReasonCode::Admitted;
  return verdict;
}

void RateShaper::release(IsolationClass isolation, WorkloadId workload, std::uint64_t bytes,
                         Nanos now) {
  const auto class_it = classes_.find(static_cast<std::uint8_t>(isolation));
  if (class_it != classes_.end()) {
    class_it->second.refill(now);
    class_it->second.release(bytes);
  }
  const auto workload_it = workloads_.find(workload);
  if (workload_it != workloads_.end()) {
    workload_it->second.refill(now);
    workload_it->second.release(bytes);
  }
}

std::uint64_t RateShaper::class_tokens_at(IsolationClass isolation, Nanos now) {
  const auto it = classes_.find(static_cast<std::uint8_t>(isolation));
  if (it == classes_.end()) {
    return 0;
  }
  it->second.refill(now);
  return it->second.tokens();
}

std::uint64_t RateShaper::workload_tokens_at(WorkloadId workload, Nanos now) {
  const auto it = workloads_.find(workload);
  if (it == workloads_.end()) {
    return 0;
  }
  it->second.refill(now);
  return it->second.tokens();
}

Nanos RateShaper::class_time_until_at(IsolationClass isolation, std::uint64_t bytes, Nanos now) {
  const auto it = classes_.find(static_cast<std::uint8_t>(isolation));
  if (it == classes_.end()) {
    return 0;
  }
  it->second.refill(now);
  return it->second.time_until(bytes);
}

std::uint64_t RateShaper::class_tokens(IsolationClass isolation) const noexcept {
  const auto it = classes_.find(static_cast<std::uint8_t>(isolation));
  return it == classes_.end() ? 0 : it->second.tokens();
}

std::uint64_t RateShaper::workload_tokens(WorkloadId workload) const noexcept {
  const auto it = workloads_.find(workload);
  return it == workloads_.end() ? 0 : it->second.tokens();
}

std::uint64_t RateShaper::class_rate(IsolationClass isolation) const noexcept {
  const auto it = classes_.find(static_cast<std::uint8_t>(isolation));
  return it == classes_.end() ? 0 : it->second.rate_bps();
}

std::uint64_t RateShaper::workload_rate(WorkloadId workload) const noexcept {
  const auto it = workloads_.find(workload);
  return it == workloads_.end() ? 0 : it->second.rate_bps();
}

Nanos RateShaper::class_time_until(IsolationClass isolation, std::uint64_t bytes) const noexcept {
  const auto it = classes_.find(static_cast<std::uint8_t>(isolation));
  return it == classes_.end() ? 0 : it->second.time_until(bytes);
}

Nanos RateShaper::workload_time_until(WorkloadId workload, std::uint64_t bytes) const noexcept {
  const auto it = workloads_.find(workload);
  return it == workloads_.end() ? 0 : it->second.time_until(bytes);
}

}  // namespace ctf::detail
