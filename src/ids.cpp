// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/ids.hpp"

#include "ctf/bytes.hpp"

namespace ctf {
namespace {

[[nodiscard]] int hex_digit_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

constexpr std::size_t kUuidTextLength = 36;

}  // namespace

std::optional<Uuid128> Uuid128::parse(std::string_view text) noexcept {
  if (text.size() != kUuidTextLength) {
    return std::nullopt;
  }
  std::array<std::uint8_t, 16> bytes{};
  std::size_t byte_index = 0;
  int high = -1;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') {
        return std::nullopt;
      }
      continue;
    }
    const int value = hex_digit_value(c);
    if (value < 0) {
      return std::nullopt;  // uppercase and non-hex characters are not canonical
    }
    if (high < 0) {
      high = value;
      continue;
    }
    if (byte_index >= bytes.size()) {
      return std::nullopt;
    }
    bytes[byte_index] = static_cast<std::uint8_t>((high << 4) | value);
    ++byte_index;
    high = -1;
  }
  if (byte_index != bytes.size()) {
    return std::nullopt;
  }
  return Uuid128(bytes);
}

std::string Uuid128::to_string() const {
  std::string out;
  out.reserve(kUuidTextLength);
  for (std::size_t i = 0; i < bytes_.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      out.push_back('-');
    }
    static constexpr char kDigits[] = "0123456789abcdef";
    out.push_back(kDigits[bytes_[i] >> 4]);
    out.push_back(kDigits[bytes_[i] & 0x0FU]);
  }
  return out;
}

std::size_t Uuid128Hash::operator()(const Uuid128& value) const noexcept {
  // FNV-1a over the raw bytes; independent of the integrity digests so identity
  // hashing never collides with content hashing.
  std::uint64_t hash = 0xCBF29CE484222325ULL;
  for (const std::uint8_t byte : value.bytes()) {
    hash ^= byte;
    hash *= 0x100000001B3ULL;
  }
  return static_cast<std::size_t>(hash);
}

Uuid128 IdFactory::next() noexcept {
  std::array<std::uint8_t, 16> bytes{};
  const std::uint64_t high = rng_();
  const std::uint64_t low = rng_();
  for (std::size_t i = 0; i < 8; ++i) {
    bytes[i] = static_cast<std::uint8_t>((high >> (8U * (7U - i))) & 0xFFU);
    bytes[8 + i] = static_cast<std::uint8_t>((low >> (8U * (7U - i))) & 0xFFU);
  }
  bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0FU) | 0x40U);  // version 4
  bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3FU) | 0x80U);  // RFC 4122 variant
  return Uuid128(bytes);
}

std::string CoordinatorEpoch::to_string() const {
  return incarnation.to_string() + "." + term.to_string();
}

std::optional<CoordinatorEpoch> CoordinatorEpoch::parse(std::string_view text) noexcept {
  const std::size_t dot = text.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 >= text.size()) {
    return std::nullopt;
  }
  if (text.find('.', dot + 1) != std::string_view::npos) {
    return std::nullopt;
  }
  const std::optional<IncarnationId> incarnation = IncarnationId::parse(text.substr(0, dot));
  if (!incarnation.has_value()) {
    return std::nullopt;
  }
  const std::optional<EpochTerm> term = EpochTerm::parse(text.substr(dot + 1));
  if (!term.has_value()) {
    return std::nullopt;
  }
  return CoordinatorEpoch{*incarnation, *term};
}

std::size_t CoordinatorEpochHash::operator()(const CoordinatorEpoch& epoch) const noexcept {
  const std::size_t a = static_cast<std::size_t>(epoch.incarnation.value());
  const std::size_t b = static_cast<std::size_t>(epoch.term.value());
  return a ^ (b + 0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2));
}

}  // namespace ctf
