#pragma once

// Time is an injected dependency, never a global.
//
// Deterministic tests drive a ManualClock, so admission, deferral, deadline,
// and envelope decisions are reproducible. Production processes use the
// monotonic SteadyClock. Wall-clock time is deliberately absent: this runtime
// never interprets wall time as authority.

#include <cstdint>
#include <string>

namespace ctf {

using Nanos = std::int64_t;

inline constexpr Nanos kNanosPerMicrosecond = 1000;
inline constexpr Nanos kNanosPerMillisecond = 1000 * kNanosPerMicrosecond;
inline constexpr Nanos kNanosPerSecond = 1000 * kNanosPerMillisecond;

class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  virtual ~Clock();

  /// Monotonic nanoseconds. Never decreases for a given process incarnation.
  [[nodiscard]] virtual Nanos now() const noexcept = 0;
};

/// Monotonic process clock backed by std::chrono::steady_clock.
class SteadyClock final : public Clock {
 public:
  [[nodiscard]] Nanos now() const noexcept override;
};

/// Manually advanced clock for deterministic execution.
class ManualClock final : public Clock {
 public:
  explicit ManualClock(Nanos start = 0) noexcept : now_(start) {}

  [[nodiscard]] Nanos now() const noexcept override { return now_; }
  void advance(Nanos delta) noexcept {
    if (delta > 0) {
      now_ += delta;
    }
  }
  void set(Nanos value) noexcept { now_ = value > 0 ? value : 0; }

 private:
  Nanos now_ = 0;
};

/// "0ns", "12us", "1.250ms", "2.500s" - stable, non-localized.
[[nodiscard]] std::string format_duration(Nanos value);

}  // namespace ctf
