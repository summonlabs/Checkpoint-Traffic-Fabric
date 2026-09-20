#pragma once

// Integrity primitives.
//
// These are checksums for accidental corruption and framing integrity. They are
// NOT cryptographic and the runtime never claims otherwise: a Digest proves the
// bytes observed are the bytes that were sent, not who sent them.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "ctf/bytes.hpp"

namespace ctf {

/// CRC-32C (Castagnoli), reflected, polynomial 0x1EDC6F41.
[[nodiscard]] std::uint32_t crc32c(const std::uint8_t* data, std::size_t length,
                                   std::uint32_t seed = 0) noexcept;
[[nodiscard]] std::uint32_t crc32c(ByteSpan data, std::uint32_t seed = 0) noexcept;

/// FNV-1a 64-bit.
[[nodiscard]] std::uint64_t fnv1a64(const std::uint8_t* data, std::size_t length,
                                    std::uint64_t seed = 0xCBF29CE484222325ULL) noexcept;
[[nodiscard]] std::uint64_t fnv1a64(ByteSpan data,
                                    std::uint64_t seed = 0xCBF29CE484222325ULL) noexcept;

/// Pair of independent checksums over the same byte stream. Equality of digests
/// is evidence of content equality for integrity purposes only.
class Digest {
 public:
  constexpr Digest() noexcept = default;
  constexpr Digest(std::uint32_t crc, std::uint64_t fnv) noexcept : crc_(crc), fnv_(fnv) {}

  [[nodiscard]] constexpr std::uint32_t crc32c_value() const noexcept { return crc_; }
  [[nodiscard]] constexpr std::uint64_t fnv1a64_value() const noexcept { return fnv_; }

  /// A zero digest is a legitimate value; "no digest observed" is represented by
  /// std::optional<Digest>, never by a zero digest.
  [[nodiscard]] constexpr bool is_zero() const noexcept { return crc_ == 0 && fnv_ == kFnvSeed; }

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] static std::optional<Digest> parse(std::string_view text) noexcept;

  friend constexpr bool operator==(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.crc_ == rhs.crc_ && lhs.fnv_ == rhs.fnv_;
  }
  friend constexpr bool operator!=(const Digest& lhs, const Digest& rhs) noexcept {
    return !(lhs == rhs);
  }

  static constexpr std::uint64_t kFnvSeed = 0xCBF29CE484222325ULL;

 private:
  std::uint32_t crc_ = 0;
  std::uint64_t fnv_ = kFnvSeed;
};

/// Incremental digest over a streamed sequence of bytes.
class DigestBuilder {
 public:
  void update(ByteSpan data) noexcept {
    crc_ = crc32c(data, crc_);
    fnv_ = fnv1a64(data, fnv_);
  }
  [[nodiscard]] Digest finish() const noexcept { return Digest(crc_, fnv_); }
  void reset() noexcept {
    crc_ = 0;
    fnv_ = Digest::kFnvSeed;
  }

 private:
  std::uint32_t crc_ = 0;
  std::uint64_t fnv_ = Digest::kFnvSeed;
};

}  // namespace ctf
