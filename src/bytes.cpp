// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/bytes.hpp"

namespace ctf {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

}  // namespace

std::string hex_encode(ByteSpan data) {
  std::string out;
  out.reserve(data.size() * 2);
  for (const std::byte value : data) {
    const auto byte = static_cast<std::uint8_t>(value);
    out.push_back(kHexDigits[byte >> 4]);
    out.push_back(kHexDigits[byte & 0x0FU]);
  }
  return out;
}

Result<Bytes> hex_decode(std::string_view text, std::size_t max_bytes) {
  if (text.size() % 2 != 0) {
    return Status::error(ErrorCode::InvalidSyntax, "hex text has odd length");
  }
  const std::size_t byte_count = text.size() / 2;
  if (byte_count > max_bytes) {
    return Status::error(ErrorCode::PayloadTooLarge, "hex text exceeds decoding cap");
  }
  Bytes out;
  out.reserve(byte_count);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int high = hex_value(text[i]);
    const int low = hex_value(text[i + 1]);
    if (high < 0 || low < 0) {
      return Status::error(ErrorCode::InvalidSyntax, "hex text contains a non-hex character");
    }
    out.push_back(static_cast<std::byte>((high << 4) | low));
  }
  return out;
}

Bytes bytes_from_string(std::string_view text) {
  Bytes out;
  out.reserve(text.size());
  for (const char c : text) {
    out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  }
  return out;
}

std::string string_from_bytes(ByteSpan data) {
  std::string out;
  out.reserve(data.size());
  for (const std::byte value : data) {
    out.push_back(static_cast<char>(static_cast<unsigned char>(value)));
  }
  return out;
}

bool is_valid_utf8(ByteSpan data) noexcept {
  std::size_t i = 0;
  const std::size_t size = data.size();
  while (i < size) {
    const auto byte = static_cast<std::uint8_t>(data[i]);
    std::uint32_t code_point = 0;
    std::size_t continuation = 0;
    if (byte <= 0x7FU) {
      code_point = byte;
      continuation = 0;
    } else if (byte >= 0xC2U && byte <= 0xDFU) {
      code_point = byte & 0x1FU;
      continuation = 1;
    } else if (byte >= 0xE0U && byte <= 0xEFU) {
      code_point = byte & 0x0FU;
      continuation = 2;
    } else if (byte >= 0xF0U && byte <= 0xF4U) {
      code_point = byte & 0x07U;
      continuation = 3;
    } else {
      return false;  // continuation byte, overlong lead, or invalid lead
    }
    if (i + continuation >= size) {
      return false;  // truncated sequence
    }
    for (std::size_t k = 1; k <= continuation; ++k) {
      const auto next = static_cast<std::uint8_t>(data[i + k]);
      if ((next & 0xC0U) != 0x80U) {
        return false;
      }
      code_point = (code_point << 6) | (next & 0x3FU);
    }
    if (continuation == 2 && code_point < 0x800U) {
      return false;  // overlong
    }
    if (continuation == 3 && code_point < 0x10000U) {
      return false;  // overlong
    }
    if (code_point >= 0xD800U && code_point <= 0xDFFFU) {
      return false;  // surrogate
    }
    if (code_point > 0x10FFFFU) {
      return false;
    }
    i += continuation + 1;
  }
  return true;
}

}  // namespace ctf
