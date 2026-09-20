// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/hash.hpp"

#include <array>

#include "ctf/bytes.hpp"

namespace ctf {
namespace {

constexpr std::uint32_t kCrc32cPolynomial = 0x82F63B78U;  // reflected 0x1EDC6F41

constexpr std::array<std::uint32_t, 256> make_crc_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t crc = i;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 1U) != 0U ? (crc >> 1) ^ kCrc32cPolynomial : crc >> 1;
    }
    table[i] = crc;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kCrcTable = make_crc_table();

}  // namespace

std::uint32_t crc32c(const std::uint8_t* data, std::size_t length, std::uint32_t seed) noexcept {
  std::uint32_t crc = ~seed;
  for (std::size_t i = 0; i < length; ++i) {
    crc = kCrcTable[(crc ^ data[i]) & 0xFFU] ^ (crc >> 8);
  }
  return ~crc;
}

std::uint32_t crc32c(ByteSpan data, std::uint32_t seed) noexcept {
  return crc32c(reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), seed);
}

std::uint64_t fnv1a64(const std::uint8_t* data, std::size_t length, std::uint64_t seed) noexcept {
  std::uint64_t hash = seed;
  for (std::size_t i = 0; i < length; ++i) {
    hash ^= data[i];
    hash *= 0x100000001B3ULL;
  }
  return hash;
}

std::uint64_t fnv1a64(ByteSpan data, std::uint64_t seed) noexcept {
  return fnv1a64(reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), seed);
}

std::string Digest::to_string() const {
  std::array<std::byte, 12> raw{};
  for (std::size_t i = 0; i < 4; ++i) {
    raw[i] = static_cast<std::byte>((crc_ >> (8U * (3U - i))) & 0xFFU);
  }
  for (std::size_t i = 0; i < 8; ++i) {
    raw[4 + i] = static_cast<std::byte>((fnv_ >> (8U * (7U - i))) & 0xFFU);
  }
  return hex_encode(ByteSpan(raw.data(), raw.size()));
}

std::optional<Digest> Digest::parse(std::string_view text) noexcept {
  if (text.size() != 24) {
    return std::nullopt;
  }
  Result<Bytes> raw = hex_decode(text, 12);
  if (!raw.ok() || raw.value().size() != 12) {
    return std::nullopt;
  }
  const ByteSpan span(raw.value().data(), raw.value().size());
  std::uint32_t crc = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    crc = (crc << 8) | static_cast<std::uint32_t>(span[i]);
  }
  std::uint64_t fnv = 0;
  for (std::size_t i = 4; i < 12; ++i) {
    fnv = (fnv << 8) | static_cast<std::uint64_t>(span[i]);
  }
  return Digest(crc, fnv);
}

}  // namespace ctf
