#pragma once

// Byte plumbing shared by the codec, the store, and the transport.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ctf/status.hpp"

namespace ctf {

using Bytes = std::vector<std::byte>;
using ByteSpan = std::span<const std::byte>;
using MutableByteSpan = std::span<std::byte>;

/// Lowercase hex, two characters per byte.
[[nodiscard]] std::string hex_encode(ByteSpan data);

/// Strict hex decoding: even length, lowercase or uppercase, bounded output.
/// Returns InvalidSyntax for bad characters and PayloadTooLarge beyond the cap.
[[nodiscard]] Result<Bytes> hex_decode(std::string_view text, std::size_t max_bytes);

[[nodiscard]] Bytes bytes_from_string(std::string_view text);
[[nodiscard]] std::string string_from_bytes(ByteSpan data);

/// Strict UTF-8 validation: rejects overlong encodings, surrogate code points,
/// values above U+10FFFF, and truncated sequences.
[[nodiscard]] bool is_valid_utf8(ByteSpan data) noexcept;

}  // namespace ctf
