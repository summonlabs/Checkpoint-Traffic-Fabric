// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/time.hpp"

#include <chrono>

namespace ctf {

Clock::~Clock() = default;

Nanos SteadyClock::now() const noexcept {
  return static_cast<Nanos>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

std::string format_duration(Nanos value) {
  const bool negative = value < 0;
  std::uint64_t magnitude = negative ? static_cast<std::uint64_t>(-(value + 1)) + 1U
                                     : static_cast<std::uint64_t>(value);
  std::string out;
  if (negative) {
    out.push_back('-');
  }
  if (magnitude < static_cast<std::uint64_t>(kNanosPerMicrosecond)) {
    out += std::to_string(magnitude);
    out += "ns";
    return out;
  }
  struct Unit {
    std::uint64_t nanos;
    const char* suffix;
    int decimals;
  };
  static constexpr Unit kUnits[] = {
      {static_cast<std::uint64_t>(kNanosPerSecond), "s", 3},
      {static_cast<std::uint64_t>(kNanosPerMillisecond), "ms", 3},
      {static_cast<std::uint64_t>(kNanosPerMicrosecond), "us", 3},
  };
  for (const Unit& unit : kUnits) {
    if (magnitude >= unit.nanos) {
      const std::uint64_t whole = magnitude / unit.nanos;
      std::uint64_t remainder = magnitude % unit.nanos;
      std::string fraction;
      std::uint64_t scale = unit.nanos;
      for (int i = 0; i < unit.decimals; ++i) {
        scale /= 10U;
        fraction.push_back(static_cast<char>('0' + ((remainder / scale) % 10U)));
      }
      remainder %= scale;
      while (!fraction.empty() && fraction.back() == '0') {
        fraction.pop_back();
      }
      out += std::to_string(whole);
      if (!fraction.empty()) {
        out.push_back('.');
        out += fraction;
      }
      out += unit.suffix;
      return out;
    }
  }
  return out;
}

}  // namespace ctf
