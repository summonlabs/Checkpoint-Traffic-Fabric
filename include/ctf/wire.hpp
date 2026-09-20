#pragma once

// Canonical wire codec and framing.
//
// All wire input is untrusted. The decoder therefore:
//   * rejects rather than repairs - unknown enum values, non-canonical booleans,
//     invalid UTF-8, out-of-range numbers, and over-long strings all fail;
//   * is bounds-checked with checked arithmetic before every allocation;
//   * has a sticky failure state, so a partially decoded message can never be
//     mistaken for a complete one;
//   * validates framing with independent header and payload checksums so a
//     truncated or corrupted frame is refused deterministically.

#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ctf/bytes.hpp"
#include "ctf/hash.hpp"
#include "ctf/ids.hpp"
#include "ctf/model.hpp"
#include "ctf/status.hpp"
#include "ctf/version.hpp"

namespace ctf::wire {

inline constexpr std::uint32_t kFrameMagic = 0x31465443U;  // 'CTF1' little-endian
inline constexpr std::size_t kFrameHeaderBytes = 32;
inline constexpr std::uint32_t kMaxPayloadBytes = 1U << 20;  // 1 MiB
inline constexpr std::uint16_t kMaxStringBytes = 512;
inline constexpr std::uint32_t kMaxCollectionElements = 1U << 20;

struct FrameHeader {
  std::uint16_t protocol_version = kProtocolVersion;
  std::uint16_t message_type = 0;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  std::uint32_t payload_bytes = 0;
  std::uint32_t payload_crc = 0;
};

/// Encodes one frame. Fails (PayloadTooLarge) rather than emitting a frame the
/// peer would have to reject.
[[nodiscard]] Result<Bytes> encode_frame(const FrameHeader& header, ByteSpan payload);
/// Decodes one complete frame. Rejects trailing garbage, bad magic, wrong
/// protocol version, oversized payloads, and either checksum mismatch.
[[nodiscard]] Result<Bytes> decode_frame(ByteSpan frame, FrameHeader* header_out);

/// Maximum frame size accepted from a peer.
inline constexpr std::size_t kMaxFrameBytes = kFrameHeaderBytes + kMaxPayloadBytes;

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

class Encoder {
 public:
  void u8(std::uint8_t value) { raw_.push_back(static_cast<std::byte>(value)); }
  void u16(std::uint16_t value) { integer(value, 2); }
  void u32(std::uint32_t value) { integer(value, 4); }
  void u64(std::uint64_t value) { integer(value, 8); }
  void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }
  void boolean(bool value) { u8(value ? 1U : 0U); }
  void bytes(ByteSpan data);
  void string(std::string_view text);
  void uuid(const Uuid128& id) {
    for (const std::uint8_t byte : id.bytes()) {
      raw_.push_back(static_cast<std::byte>(byte));
    }
  }

  /// Sticky failure state: an encoder that was asked to encode something it
  /// cannot represent faithfully refuses the whole message.
  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }
  void fail(ErrorCode code, std::string detail) {
    if (status_.ok()) {
      status_ = Status::error(code, std::move(detail));
    }
  }

  [[nodiscard]] const Bytes& data() const noexcept { return raw_; }
  [[nodiscard]] Bytes take() && { return std::move(raw_); }
  [[nodiscard]] std::size_t size() const noexcept { return raw_.size(); }

 private:
  void integer(std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) {
      const unsigned shift = static_cast<unsigned>(8U * (width - 1 - i));
      raw_.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
    }
  }

  Bytes raw_;
  Status status_ = Status::success();
};

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

class Decoder {
 public:
  Decoder(ByteSpan data, Limits limits) : data_(data), limits_(limits) {}

  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] bool at_end() const noexcept { return offset_ == data_.size(); }

  /// Records a failure and returns the (sticky) status.
  Status fail(ErrorCode code, std::string detail) {
    if (status_.ok()) {
      status_ = Status::error(code, std::move(detail));
    }
    return status_;
  }

  std::uint8_t u8();
  std::uint16_t u16();
  std::uint32_t u32();
  std::uint64_t u64();
  std::int64_t i64();
  bool boolean();
  Bytes bytes();
  std::string string();
  Uuid128 uuid();

  /// Number of elements in a bounded collection. Validates the bound and that
  /// the remaining bytes could plausibly hold that many elements (each element
  /// is at least one byte on the wire).
  std::uint32_t collection_count();

  /// Requires that no trailing bytes remain.
  Status expect_end();

  [[nodiscard]] const Limits& limits() const noexcept { return limits_; }

 private:
  bool require(std::size_t count) {
    if (remaining() < count) {
      fail(ErrorCode::TruncatedInput, "message ended before the declared length");
      return false;
    }
    return true;
  }

  ByteSpan data_;
  Limits limits_;
  std::size_t offset_ = 0;
  Status status_ = Status::success();
};

// ---------------------------------------------------------------------------
// Enum coding
// ---------------------------------------------------------------------------

/// An enum is encoded as one byte and validated on decode against the name
/// table produced by its to_string overload, so an unrecognized value can never
/// silently become the first enumerator (or a laxer isolation class).
template <class E, const char* (*NameFn)(E) noexcept>
E decode_enum(Decoder& decoder) {
  const std::uint8_t raw = decoder.u8();
  const E value = static_cast<E>(raw);
  if (std::string_view(NameFn(value)) == "Unknown") {
    decoder.fail(ErrorCode::UnsupportedValue, "enum value is not in the supported set");
    return static_cast<E>(0);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Primitive and identity codecs
// ---------------------------------------------------------------------------

inline void encode(Encoder& encoder, std::uint8_t value) { encoder.u8(value); }
inline void encode(Encoder& encoder, std::uint16_t value) { encoder.u16(value); }
inline void encode(Encoder& encoder, std::uint32_t value) { encoder.u32(value); }
inline void encode(Encoder& encoder, std::uint64_t value) { encoder.u64(value); }
inline void encode(Encoder& encoder, std::int64_t value) { encoder.i64(value); }
inline void encode(Encoder& encoder, bool value) { encoder.boolean(value); }
inline void encode(Encoder& encoder, std::string_view value) { encoder.string(value); }

inline void decode(Decoder& decoder, std::uint8_t& value) { value = decoder.u8(); }
inline void decode(Decoder& decoder, std::uint16_t& value) { value = decoder.u16(); }
inline void decode(Decoder& decoder, std::uint32_t& value) { value = decoder.u32(); }
inline void decode(Decoder& decoder, std::uint64_t& value) { value = decoder.u64(); }
inline void decode(Decoder& decoder, std::int64_t& value) { value = decoder.i64(); }
inline void decode(Decoder& decoder, bool& value) { value = decoder.boolean(); }
inline void decode(Decoder& decoder, std::string& value) { value = decoder.string(); }

template <class Tag>
void encode(Encoder& encoder, const StrongId<Tag>& id) {
  encoder.uuid(id.value());
}

template <class Tag>
void decode(Decoder& decoder, StrongId<Tag>& id) {
  id = StrongId<Tag>(decoder.uuid());
}

template <class Tag, class T>
void encode(Encoder& encoder, const StrongScalar<Tag, T>& value) {
  encoder.u64(static_cast<std::uint64_t>(value.value()));
}

template <class Tag, class T>
void decode(Decoder& decoder, StrongScalar<Tag, T>& value) {
  const std::uint64_t raw = decoder.u64();
  if (raw > static_cast<std::uint64_t>((std::numeric_limits<T>::max)())) {
    decoder.fail(ErrorCode::OutOfRange, "scalar value exceeds its declared width");
    value = StrongScalar<Tag, T>{};
    return;
  }
  value = StrongScalar<Tag, T>(static_cast<T>(raw));
}

template <class Tag>
void encode(Encoder& encoder, const Generation<Tag>& value) {
  encoder.u64(value.value());
}

template <class Tag>
void decode(Decoder& decoder, Generation<Tag>& value) {
  value = Generation<Tag>(decoder.u64());
}

void encode(Encoder& encoder, const Digest& digest);
void decode(Decoder& decoder, Digest& digest);
void encode(Encoder& encoder, const CoordinatorEpoch& epoch);
void decode(Decoder& decoder, CoordinatorEpoch& epoch);

// Domain enums.
#define CTF_WIRE_ENUM(Type)                                                              \
  inline void encode(Encoder& encoder, Type value) {                                     \
    encoder.u8(static_cast<std::uint8_t>(value));                                        \
  }                                                                                      \
  inline void decode(Decoder& decoder, Type& value) {                                    \
    value = decode_enum<Type, &to_string>(decoder);                                      \
  }

CTF_WIRE_ENUM(IsolationClass)
CTF_WIRE_ENUM(DestinationClass)
CTF_WIRE_ENUM(EvidenceLevel)
CTF_WIRE_ENUM(DurabilityStatus)
CTF_WIRE_ENUM(SessionState)
CTF_WIRE_ENUM(ShardState)
CTF_WIRE_ENUM(AttemptOutcome)
CTF_WIRE_ENUM(DecisionKind)
CTF_WIRE_ENUM(EventKind)
CTF_WIRE_ENUM(VerificationEvidence::Outcome)
#undef CTF_WIRE_ENUM

inline void encode(Encoder& encoder, ReasonCode value) {
  encoder.u8(static_cast<std::uint8_t>(value));
}
inline void decode(Decoder& decoder, ReasonCode& value) {
  value = decode_enum<ReasonCode, &to_string>(decoder);
}
inline void encode(Encoder& encoder, ErrorCode value) {
  encoder.u16(static_cast<std::uint16_t>(value));
}
inline void decode(Decoder& decoder, ErrorCode& value) {
  const std::uint16_t raw = decoder.u16();
  const ErrorCode candidate = static_cast<ErrorCode>(raw);
  if (std::string_view(to_string(candidate)) == "Unknown") {
    decoder.fail(ErrorCode::UnsupportedValue, "error code is not in the supported set");
    value = ErrorCode::Internal;
    return;
  }
  value = candidate;
}

// ---------------------------------------------------------------------------
// Domain codecs (implemented in src/wire.cpp)
// ---------------------------------------------------------------------------

void encode(Encoder& encoder, const ShardDescriptor& value);
void decode(Decoder& decoder, ShardDescriptor& value);
void encode(Encoder& encoder, const CheckpointManifest& value);
void decode(Decoder& decoder, CheckpointManifest& value);
void encode(Encoder& encoder, const Limits& value);
void decode(Decoder& decoder, Limits& value);
void encode(Encoder& encoder, const IsolationEnvelopeConfig& value);
void decode(Decoder& decoder, IsolationEnvelopeConfig& value);
void encode(Encoder& encoder, const PolicySnapshot& value);
void decode(Decoder& decoder, PolicySnapshot& value);
void encode(Encoder& encoder, const PathClass& value);
void decode(Decoder& decoder, PathClass& value);
void encode(Encoder& encoder, const TopologySnapshot& value);
void decode(Decoder& decoder, TopologySnapshot& value);
void encode(Encoder& encoder, const WorkloadContract& value);
void decode(Decoder& decoder, WorkloadContract& value);
void encode(Encoder& encoder, const SessionRequest& value);
void decode(Decoder& decoder, SessionRequest& value);
void encode(Encoder& encoder, const CommandFence& value);
void decode(Decoder& decoder, CommandFence& value);
void encode(Encoder& encoder, const WavePlan& value);
void decode(Decoder& decoder, WavePlan& value);
void encode(Encoder& encoder, const TrafficEnvelope& value);
void decode(Decoder& decoder, TrafficEnvelope& value);
void encode(Encoder& encoder, const AdmissionDecision& value);
void decode(Decoder& decoder, AdmissionDecision& value);
void encode(Encoder& encoder, const WaveGrant& value);
void decode(Decoder& decoder, WaveGrant& value);
void encode(Encoder& encoder, const WaveOutcome& value);
void decode(Decoder& decoder, WaveOutcome& value);
void encode(Encoder& encoder, const SourceCompleteEvidence& value);
void decode(Decoder& decoder, SourceCompleteEvidence& value);
void encode(Encoder& encoder, const TransferEvidence& value);
void decode(Decoder& decoder, TransferEvidence& value);
void encode(Encoder& encoder, const VerificationEvidence& value);
void decode(Decoder& decoder, VerificationEvidence& value);
void encode(Encoder& encoder, const DurabilityAssertion& value);
void decode(Decoder& decoder, DurabilityAssertion& value);
void encode(Encoder& encoder, const ShardProgress& value);
void decode(Decoder& decoder, ShardProgress& value);
void encode(Encoder& encoder, const SessionView& value);
void decode(Decoder& decoder, SessionView& value);
void encode(Encoder& encoder, const SessionSummary& value);
void decode(Decoder& decoder, SessionSummary& value);
void encode(Encoder& encoder, const AccountingSnapshot& value);
void decode(Decoder& decoder, AccountingSnapshot& value);
void encode(Encoder& encoder, const Explanation& value);
void decode(Decoder& decoder, Explanation& value);
void encode(Encoder& encoder, const FabricEvent& value);
void decode(Decoder& decoder, FabricEvent& value);

}  // namespace ctf::wire
