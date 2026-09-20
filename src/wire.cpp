// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/wire.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace ctf::wire {
namespace {

/// Bytes covered by the header checksum: everything before the checksums.
constexpr std::size_t kHeaderChecksumCoverage = 24;
constexpr std::size_t kMaxEncodedString = kMaxStringBytes;

void put_u16(std::uint8_t* out, std::uint16_t value) {
  out[0] = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
  out[1] = static_cast<std::uint8_t>(value & 0xFFU);
}

void put_u32(std::uint8_t* out, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (8U * (3U - static_cast<unsigned>(i)))) & 0xFFU);
  }
}

void put_u64(std::uint8_t* out, std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (8U * (7U - static_cast<unsigned>(i)))) & 0xFFU);
  }
}

[[nodiscard]] std::uint16_t get_u16(const std::uint8_t* in) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[0]) << 8) |
                                    static_cast<std::uint16_t>(in[1]));
}

[[nodiscard]] std::uint32_t get_u32(const std::uint8_t* in) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value = (value << 8) | static_cast<std::uint32_t>(in[i]);
  }
  return value;
}

[[nodiscard]] std::uint64_t get_u64(const std::uint8_t* in) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value = (value << 8) | static_cast<std::uint64_t>(in[i]);
  }
  return value;
}

}  // namespace

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

void Encoder::bytes(ByteSpan data) {
  if (data.size() > kMaxPayloadBytes) {
    fail(ErrorCode::PayloadTooLarge, "byte field exceeds the maximum payload size");
    return;
  }
  u32(static_cast<std::uint32_t>(data.size()));
  raw_.insert(raw_.end(), data.begin(), data.end());
}

void Encoder::string(std::string_view text) {
  if (text.size() > kMaxEncodedString) {
    fail(ErrorCode::StringTooLong, "string field exceeds the maximum string size");
    return;
  }
  if (!is_valid_utf8(ByteSpan(reinterpret_cast<const std::byte*>(text.data()), text.size()))) {
    fail(ErrorCode::InvalidUtf8, "string field is not valid UTF-8");
    return;
  }
  u16(static_cast<std::uint16_t>(text.size()));
  raw_.insert(raw_.end(), reinterpret_cast<const std::byte*>(text.data()),
              reinterpret_cast<const std::byte*>(text.data()) + text.size());
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

std::uint8_t Decoder::u8() {
  if (!ok() || !require(1)) {
    return 0;
  }
  const auto value = static_cast<std::uint8_t>(data_[offset_]);
  ++offset_;
  return value;
}

std::uint16_t Decoder::u16() {
  if (!ok() || !require(2)) {
    return 0;
  }
  const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(data_.data() + offset_);
  offset_ += 2;
  return get_u16(raw);
}

std::uint32_t Decoder::u32() {
  if (!ok() || !require(4)) {
    return 0;
  }
  const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(data_.data() + offset_);
  offset_ += 4;
  return get_u32(raw);
}

std::uint64_t Decoder::u64() {
  if (!ok() || !require(8)) {
    return 0;
  }
  const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(data_.data() + offset_);
  offset_ += 8;
  return get_u64(raw);
}

std::int64_t Decoder::i64() { return static_cast<std::int64_t>(u64()); }

bool Decoder::boolean() {
  const std::uint8_t raw = u8();
  if (!ok()) {
    return false;
  }
  if (raw > 1U) {
    fail(ErrorCode::NonCanonicalEncoding, "boolean field must be exactly 0 or 1");
    return false;
  }
  return raw == 1U;
}

Bytes Decoder::bytes() {
  const std::uint32_t length = u32();
  if (!ok()) {
    return {};
  }
  if (length > kMaxPayloadBytes) {
    fail(ErrorCode::PayloadTooLarge, "byte field exceeds the maximum payload size");
    return {};
  }
  // A stored snapshot or payload may legitimately exceed the per-field string
  // bound; the collection bound is the payload bound itself.
  if (!require(length)) {
    return {};
  }
  Bytes out(data_.begin() + static_cast<std::ptrdiff_t>(offset_),
            data_.begin() + static_cast<std::ptrdiff_t>(offset_ + length));
  offset_ += length;
  return out;
}

std::string Decoder::string() {
  const std::uint16_t length = u16();
  if (!ok()) {
    return {};
  }
  if (length > kMaxStringBytes) {
    fail(ErrorCode::StringTooLong, "string field exceeds the maximum string size");
    return {};
  }
  if (!require(length)) {
    return {};
  }
  const ByteSpan view(data_.data() + offset_, length);
  if (!is_valid_utf8(view)) {
    fail(ErrorCode::InvalidUtf8, "string field is not valid UTF-8");
    return {};
  }
  std::string out = string_from_bytes(view);
  offset_ += length;
  return out;
}

Uuid128 Decoder::uuid() {
  if (!ok() || !require(16)) {
    return Uuid128{};
  }
  std::array<std::uint8_t, 16> raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) {
    raw[i] = static_cast<std::uint8_t>(data_[offset_ + i]);
  }
  offset_ += 16;
  return Uuid128(raw);
}

std::uint32_t Decoder::collection_count() {
  const std::uint32_t count = u32();
  if (!ok()) {
    return 0;
  }
  if (count > kMaxCollectionElements) {
    fail(ErrorCode::CollectionTooLarge, "collection count exceeds the protocol bound");
    return 0;
  }
  // Every element occupies at least one byte on the wire: reject counts that
  // could not possibly fit before allocating anything.
  if (static_cast<std::size_t>(count) > remaining()) {
    fail(ErrorCode::TruncatedInput, "collection count exceeds the remaining message bytes");
    return 0;
  }
  return count;
}

Status Decoder::expect_end() {
  if (!ok()) {
    return status_;
  }
  if (!at_end()) {
    return fail(ErrorCode::TrailingGarbage, "message has trailing bytes after the payload");
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

Result<Bytes> encode_frame(const FrameHeader& header, ByteSpan payload) {
  if (payload.size() > kMaxPayloadBytes) {
    return Status::error(ErrorCode::PayloadTooLarge, "frame payload exceeds the protocol bound");
  }
  std::array<std::uint8_t, kFrameHeaderBytes> raw{};
  put_u32(raw.data(), kFrameMagic);
  put_u16(raw.data() + 4, header.protocol_version);
  put_u16(raw.data() + 6, header.message_type);
  put_u32(raw.data() + 8, header.flags);
  put_u64(raw.data() + 12, header.sequence);
  put_u32(raw.data() + 20, static_cast<std::uint32_t>(payload.size()));
  put_u32(raw.data() + kHeaderChecksumCoverage,
          crc32c(raw.data(), kHeaderChecksumCoverage));
  put_u32(raw.data() + 28, crc32c(payload));

  Bytes out;
  out.reserve(kFrameHeaderBytes + payload.size());
  for (const std::uint8_t byte : raw) {
    out.push_back(static_cast<std::byte>(byte));
  }
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

Result<Bytes> decode_frame(ByteSpan frame, FrameHeader* header_out) {
  if (frame.size() < kFrameHeaderBytes) {
    return Status::error(ErrorCode::TruncatedInput, "frame is shorter than its header");
  }
  const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(frame.data());
  if (get_u32(raw) != kFrameMagic) {
    return Status::error(ErrorCode::InvalidSyntax, "frame magic does not match");
  }
  const std::uint16_t version = get_u16(raw + 4);
  if (version != kProtocolVersion) {
    return Status::error(ErrorCode::VersionIncompatible, "frame protocol version is not supported");
  }
  const std::uint32_t declared_crc = get_u32(raw + kHeaderChecksumCoverage);
  const std::uint32_t computed_crc = crc32c(raw, kHeaderChecksumCoverage);
  if (declared_crc != computed_crc) {
    return Status::error(ErrorCode::IntegrityFailure, "frame header checksum does not match");
  }
  const std::uint32_t payload_bytes = get_u32(raw + 20);
  if (payload_bytes > kMaxPayloadBytes) {
    return Status::error(ErrorCode::PayloadTooLarge, "frame declares an oversized payload");
  }
  const std::size_t expected = kFrameHeaderBytes + static_cast<std::size_t>(payload_bytes);
  if (frame.size() != expected) {
    return Status::error(frame.size() < expected ? ErrorCode::TruncatedInput
                                                 : ErrorCode::TrailingGarbage,
                         "frame length does not match its declared payload size");
  }
  const ByteSpan payload(frame.data() + kFrameHeaderBytes, payload_bytes);
  if (get_u32(raw + 28) != crc32c(payload)) {
    return Status::error(ErrorCode::IntegrityFailure, "frame payload checksum does not match");
  }
  if (header_out != nullptr) {
    header_out->protocol_version = version;
    header_out->message_type = get_u16(raw + 6);
    header_out->flags = get_u32(raw + 8);
    header_out->sequence = get_u64(raw + 12);
    header_out->payload_bytes = payload_bytes;
    header_out->payload_crc = get_u32(raw + 28);
  }
  return Bytes(payload.begin(), payload.end());
}

// ---------------------------------------------------------------------------
// Domain codecs
// ---------------------------------------------------------------------------

void encode(Encoder& encoder, const Digest& digest) {
  encoder.u32(digest.crc32c_value());
  encoder.u64(digest.fnv1a64_value());
}

void decode(Decoder& decoder, Digest& digest) {
  const std::uint32_t crc = decoder.u32();
  const std::uint64_t fnv = decoder.u64();
  digest = Digest(crc, fnv);
}

void encode(Encoder& encoder, const CoordinatorEpoch& epoch) {
  encode(encoder, epoch.incarnation);
  encode(encoder, epoch.term);
}

void decode(Decoder& decoder, CoordinatorEpoch& epoch) {
  decode(decoder, epoch.incarnation);
  decode(decoder, epoch.term);
}

void encode(Encoder& encoder, const ShardDescriptor& value) {
  encode(encoder, value.index);
  encoder.u64(value.declared_bytes);
  encode(encoder, value.declared_digest);
  encode(encoder, value.path_class);
}

void decode(Decoder& decoder, ShardDescriptor& value) {
  decode(decoder, value.index);
  value.declared_bytes = decoder.u64();
  decode(decoder, value.declared_digest);
  decode(decoder, value.path_class);
}

void encode(Encoder& encoder, const CheckpointManifest& value) {
  encode(encoder, value.checkpoint);
  encode(encoder, value.generation);
  encode(encoder, value.workload);
  encode(encoder, value.contract_generation);
  encoder.u64(value.total_bytes);
  encoder.u32(static_cast<std::uint32_t>(value.shards.size()));
  for (const ShardDescriptor& shard : value.shards) {
    encode(encoder, shard);
  }
  encode(encoder, value.manifest_digest);
  encoder.i64(value.declared_at);
}

void decode(Decoder& decoder, CheckpointManifest& value) {
  decode(decoder, value.checkpoint);
  decode(decoder, value.generation);
  decode(decoder, value.workload);
  decode(decoder, value.contract_generation);
  value.total_bytes = decoder.u64();
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_shards_per_checkpoint) {
    decoder.fail(ErrorCode::CollectionTooLarge, "manifest shard count exceeds the configured bound");
    return;
  }
  value.shards.clear();
  value.shards.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    ShardDescriptor shard;
    decode(decoder, shard);
    if (!decoder.ok()) {
      return;
    }
    value.shards.push_back(shard);
  }
  decode(decoder, value.manifest_digest);
  value.declared_at = decoder.i64();
}

void encode(Encoder& encoder, const Limits& value) {
  encoder.u32(value.max_shards_per_checkpoint);
  encoder.u64(value.max_checkpoint_bytes);
  encoder.u32(value.max_sessions);
  encoder.u32(value.max_attempts_in_flight);
  encoder.u32(value.max_retained_history);
  encoder.u32(value.max_wave_width);
  encoder.u32(value.max_path_classes);
  encoder.u32(value.max_sessions_per_workload);
  encoder.u32(value.max_workloads);
  encoder.u64(static_cast<std::uint64_t>(value.max_identity_text_bytes));
  encoder.u64(static_cast<std::uint64_t>(value.max_string_bytes));
  encoder.u32(value.max_supersession_chain);
}

void decode(Decoder& decoder, Limits& value) {
  value.max_shards_per_checkpoint = decoder.u32();
  value.max_checkpoint_bytes = decoder.u64();
  value.max_sessions = decoder.u32();
  value.max_attempts_in_flight = decoder.u32();
  value.max_retained_history = decoder.u32();
  value.max_wave_width = decoder.u32();
  value.max_path_classes = decoder.u32();
  value.max_sessions_per_workload = decoder.u32();
  value.max_workloads = decoder.u32();
  const std::uint64_t identity_bytes = decoder.u64();
  const std::uint64_t string_bytes = decoder.u64();
  if (!decoder.ok()) {
    return;
  }
  value.max_identity_text_bytes = static_cast<std::size_t>(identity_bytes);
  value.max_string_bytes = static_cast<std::size_t>(string_bytes);
  value.max_supersession_chain = decoder.u32();
}

void encode(Encoder& encoder, const IsolationEnvelopeConfig& value) {
  encode(encoder, value.isolation);
  encoder.u64(value.ceiling_bps);
  encoder.u64(static_cast<std::uint64_t>(value.burst_window_ns));
  encoder.u32(value.max_in_flight_sessions);
}

void decode(Decoder& decoder, IsolationEnvelopeConfig& value) {
  decode(decoder, value.isolation);
  value.ceiling_bps = decoder.u64();
  value.burst_window_ns = static_cast<Nanos>(decoder.u64());
  value.max_in_flight_sessions = decoder.u32();
}

void encode(Encoder& encoder, const PolicySnapshot& value) {
  encode(encoder, value.generation);
  encoder.u32(static_cast<std::uint32_t>(value.envelopes.size()));
  for (const IsolationEnvelopeConfig& envelope : value.envelopes) {
    encode(encoder, envelope);
  }
  encoder.u32(value.max_wave_width);
  encoder.u64(value.max_session_bytes);
  encoder.u32(value.max_sessions);
  encoder.u32(value.max_attempts_in_flight);
  encoder.u32(value.retained_history);
  encoder.boolean(value.require_destination_verification);
  encoder.i64(value.defer_horizon_ns);
  encoder.i64(value.default_deadline_ns);
  encoder.u64(value.minimum_rate_bps_for_admission);
  encode(encoder, value.limits);
}

void decode(Decoder& decoder, PolicySnapshot& value) {
  decode(decoder, value.generation);
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > 8) {
    decoder.fail(ErrorCode::CollectionTooLarge, "policy declares too many isolation envelopes");
    return;
  }
  value.envelopes.clear();
  for (std::uint32_t i = 0; i < count; ++i) {
    IsolationEnvelopeConfig envelope;
    decode(decoder, envelope);
    if (!decoder.ok()) {
      return;
    }
    value.envelopes.push_back(envelope);
  }
  value.max_wave_width = decoder.u32();
  value.max_session_bytes = decoder.u64();
  value.max_sessions = decoder.u32();
  value.max_attempts_in_flight = decoder.u32();
  value.retained_history = decoder.u32();
  value.require_destination_verification = decoder.boolean();
  value.defer_horizon_ns = decoder.i64();
  value.default_deadline_ns = decoder.i64();
  value.minimum_rate_bps_for_admission = decoder.u64();
  decode(decoder, value.limits);
}

void encode(Encoder& encoder, const PathClass& value) {
  encode(encoder, value.id);
  encode(encoder, value.destination);
  encoder.u64(value.capacity_bps);
  encoder.boolean(value.synthetic);
  encoder.string(value.label);
}

void decode(Decoder& decoder, PathClass& value) {
  decode(decoder, value.id);
  decode(decoder, value.destination);
  value.capacity_bps = decoder.u64();
  value.synthetic = decoder.boolean();
  value.label = decoder.string();
}

void encode(Encoder& encoder, const TopologySnapshot& value) {
  encode(encoder, value.generation);
  encoder.u32(static_cast<std::uint32_t>(value.path_classes.size()));
  for (const PathClass& path : value.path_classes) {
    encode(encoder, path);
  }
}

void decode(Decoder& decoder, TopologySnapshot& value) {
  decode(decoder, value.generation);
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_path_classes) {
    decoder.fail(ErrorCode::CollectionTooLarge, "topology declares too many path classes");
    return;
  }
  value.path_classes.clear();
  value.path_classes.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    PathClass path;
    decode(decoder, path);
    if (!decoder.ok()) {
      return;
    }
    value.path_classes.push_back(path);
  }
}

void encode(Encoder& encoder, const WorkloadContract& value) {
  encode(encoder, value.workload);
  encode(encoder, value.generation);
  encode(encoder, value.isolation);
  encoder.u64(value.ceiling_bps);
  encoder.u64(value.floor_bps);
  encoder.u32(value.max_in_flight_sessions);
  encoder.u32(value.max_shards_per_wave);
  encoder.boolean(value.allow_supersession);
  encoder.i64(value.deadline_budget_ns);
}

void decode(Decoder& decoder, WorkloadContract& value) {
  decode(decoder, value.workload);
  decode(decoder, value.generation);
  decode(decoder, value.isolation);
  value.ceiling_bps = decoder.u64();
  value.floor_bps = decoder.u64();
  value.max_in_flight_sessions = decoder.u32();
  value.max_shards_per_wave = decoder.u32();
  value.allow_supersession = decoder.boolean();
  value.deadline_budget_ns = decoder.i64();
}

void encode(Encoder& encoder, const SessionRequest& value) {
  encode(encoder, value.command);
  encode(encoder, value.workload);
  encode(encoder, value.contract_generation);
  encode(encoder, value.policy_generation);
  encode(encoder, value.topology_generation);
  encode(encoder, value.checkpoint);
  encode(encoder, value.checkpoint_generation);
  encode(encoder, value.requested_isolation);
  encode(encoder, value.destination);
  encoder.u64(value.requested_rate_bps);
  encoder.i64(value.deadline_horizon_ns);
  encode(encoder, value.manifest);
}

void decode(Decoder& decoder, SessionRequest& value) {
  decode(decoder, value.command);
  decode(decoder, value.workload);
  decode(decoder, value.contract_generation);
  decode(decoder, value.policy_generation);
  decode(decoder, value.topology_generation);
  decode(decoder, value.checkpoint);
  decode(decoder, value.checkpoint_generation);
  decode(decoder, value.requested_isolation);
  decode(decoder, value.destination);
  value.requested_rate_bps = decoder.u64();
  value.deadline_horizon_ns = decoder.i64();
  decode(decoder, value.manifest);
}

void encode(Encoder& encoder, const CommandFence& value) {
  encode(encoder, value.epoch);
  encode(encoder, value.policy_generation);
  encode(encoder, value.topology_generation);
  encode(encoder, value.contract_generation);
  encoder.boolean(value.checkpoint_generation.has_value());
  if (value.checkpoint_generation.has_value()) {
    encode(encoder, value.checkpoint_generation.value());
  }
  encoder.boolean(value.attempt_sequence.has_value());
  if (value.attempt_sequence.has_value()) {
    encode(encoder, value.attempt_sequence.value());
  }
}

void decode(Decoder& decoder, CommandFence& value) {
  decode(decoder, value.epoch);
  decode(decoder, value.policy_generation);
  decode(decoder, value.topology_generation);
  decode(decoder, value.contract_generation);
  if (decoder.boolean()) {
    CheckpointGeneration generation;
    decode(decoder, generation);
    value.checkpoint_generation = generation;
  } else {
    value.checkpoint_generation.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  if (decoder.boolean()) {
    AttemptSequence sequence;
    decode(decoder, sequence);
    value.attempt_sequence = sequence;
  } else {
    value.attempt_sequence.reset();
  }
}

void encode(Encoder& encoder, const WavePlan& value) {
  encode(encoder, value.index);
  encoder.u32(static_cast<std::uint32_t>(value.shards.size()));
  for (const ShardIndex& shard : value.shards) {
    encode(encoder, shard);
  }
  encoder.u64(value.planned_bytes);
}

void decode(Decoder& decoder, WavePlan& value) {
  decode(decoder, value.index);
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_shards_per_checkpoint) {
    decoder.fail(ErrorCode::CollectionTooLarge, "wave plan declares too many shards");
    return;
  }
  value.shards.clear();
  value.shards.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    ShardIndex shard;
    decode(decoder, shard);
    if (!decoder.ok()) {
      return;
    }
    value.shards.push_back(shard);
  }
  value.planned_bytes = decoder.u64();
}

void encode(Encoder& encoder, const TrafficEnvelope& value) {
  encode(encoder, value.session);
  encode(encoder, value.sequence);
  encode(encoder, value.isolation);
  encoder.u64(value.rate_bps);
  encoder.u64(value.burst_bytes);
  encoder.u32(value.wave_width);
  encoder.u32(static_cast<std::uint32_t>(value.waves.size()));
  for (const WavePlan& plan : value.waves) {
    encode(encoder, plan);
  }
  encoder.boolean(value.path_class.has_value());
  if (value.path_class.has_value()) {
    encode(encoder, value.path_class.value());
  }
  encoder.i64(value.issued_at);
  encoder.i64(value.deadline_target);
}

void decode(Decoder& decoder, TrafficEnvelope& value) {
  decode(decoder, value.session);
  decode(decoder, value.sequence);
  decode(decoder, value.isolation);
  value.rate_bps = decoder.u64();
  value.burst_bytes = decoder.u64();
  value.wave_width = decoder.u32();
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_shards_per_checkpoint) {
    decoder.fail(ErrorCode::CollectionTooLarge, "envelope declares too many waves");
    return;
  }
  value.waves.clear();
  value.waves.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    WavePlan plan;
    decode(decoder, plan);
    if (!decoder.ok()) {
      return;
    }
    value.waves.push_back(plan);
  }
  if (decoder.boolean()) {
    PathClassId path;
    decode(decoder, path);
    value.path_class = path;
  } else {
    value.path_class.reset();
  }
  value.issued_at = decoder.i64();
  value.deadline_target = decoder.i64();
}

void encode(Encoder& encoder, const AdmissionDecision& value) {
  encode(encoder, value.kind);
  encode(encoder, value.reason);
  encoder.string(value.detail);
  encode(encoder, value.session);
  encoder.boolean(value.envelope.has_value());
  if (value.envelope.has_value()) {
    encode(encoder, value.envelope.value());
  }
  encoder.u32(static_cast<std::uint32_t>(value.superseded.size()));
  for (const SessionId& id : value.superseded) {
    encode(encoder, id);
  }
  encoder.boolean(value.retry_after.has_value());
  if (value.retry_after.has_value()) {
    encoder.i64(value.retry_after.value());
  }
  encode(encoder, value.epoch);
  encoder.i64(value.decided_at);
}

void decode(Decoder& decoder, AdmissionDecision& value) {
  decode(decoder, value.kind);
  decode(decoder, value.reason);
  value.detail = decoder.string();
  decode(decoder, value.session);
  if (decoder.boolean()) {
    TrafficEnvelope envelope;
    decode(decoder, envelope);
    value.envelope = envelope;
  } else {
    value.envelope.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_supersession_chain * 8U) {
    decoder.fail(ErrorCode::CollectionTooLarge, "decision lists too many superseded sessions");
    return;
  }
  value.superseded.clear();
  for (std::uint32_t i = 0; i < count; ++i) {
    SessionId id;
    decode(decoder, id);
    if (!decoder.ok()) {
      return;
    }
    value.superseded.push_back(id);
  }
  if (decoder.boolean()) {
    value.retry_after = decoder.i64();
  } else {
    value.retry_after.reset();
  }
  decode(decoder, value.epoch);
  value.decided_at = decoder.i64();
}

void encode(Encoder& encoder, const WaveGrant& value) {
  encode(encoder, value.session);
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encode(encoder, value.shard);
  encode(encoder, value.wave);
  encoder.u64(value.max_bytes);
  encoder.u64(value.rate_bps);
  encoder.u64(value.burst_bytes);
  encoder.i64(value.issued_at);
  encoder.i64(value.expires_at);
  encode(encoder, value.epoch);
}

void decode(Decoder& decoder, WaveGrant& value) {
  decode(decoder, value.session);
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  decode(decoder, value.shard);
  decode(decoder, value.wave);
  value.max_bytes = decoder.u64();
  value.rate_bps = decoder.u64();
  value.burst_bytes = decoder.u64();
  value.issued_at = decoder.i64();
  value.expires_at = decoder.i64();
  decode(decoder, value.epoch);
}

void encode(Encoder& encoder, const WaveOutcome& value) {
  encoder.boolean(value.granted);
  encode(encoder, value.reason);
  encoder.string(value.detail);
  encoder.boolean(value.grant.has_value());
  if (value.grant.has_value()) {
    encode(encoder, value.grant.value());
  }
  encoder.boolean(value.retry_after.has_value());
  if (value.retry_after.has_value()) {
    encoder.i64(value.retry_after.value());
  }
  encoder.i64(value.decided_at);
}

void decode(Decoder& decoder, WaveOutcome& value) {
  value.granted = decoder.boolean();
  decode(decoder, value.reason);
  value.detail = decoder.string();
  if (decoder.boolean()) {
    WaveGrant grant;
    decode(decoder, grant);
    value.grant = grant;
  } else {
    value.grant.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  if (decoder.boolean()) {
    value.retry_after = decoder.i64();
  } else {
    value.retry_after.reset();
  }
  value.decided_at = decoder.i64();
}

void encode(Encoder& encoder, const SourceCompleteEvidence& value) {
  encode(encoder, value.session);
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encode(encoder, value.wave);
  encode(encoder, value.shard);
  encoder.u64(value.source_bytes);
  encode(encoder, value.source_digest);
  encoder.i64(value.observed_at);
}

void decode(Decoder& decoder, SourceCompleteEvidence& value) {
  decode(decoder, value.session);
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  decode(decoder, value.wave);
  decode(decoder, value.shard);
  value.source_bytes = decoder.u64();
  decode(decoder, value.source_digest);
  value.observed_at = decoder.i64();
}

void encode(Encoder& encoder, const TransferEvidence& value) {
  encode(encoder, value.session);
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encode(encoder, value.shard);
  encoder.u64(value.arrived_bytes);
  encode(encoder, value.arrived_digest);
  encoder.boolean(value.sink_acknowledged);
  encoder.i64(value.observed_at);
}

void decode(Decoder& decoder, TransferEvidence& value) {
  decode(decoder, value.session);
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  decode(decoder, value.shard);
  value.arrived_bytes = decoder.u64();
  decode(decoder, value.arrived_digest);
  value.sink_acknowledged = decoder.boolean();
  value.observed_at = decoder.i64();
}

void encode(Encoder& encoder, const VerificationEvidence& value) {
  encode(encoder, value.session);
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encode(encoder, value.shard);
  encoder.u64(value.verified_bytes);
  encode(encoder, value.verified_digest);
  encode(encoder, value.outcome);
  encoder.string(value.verifier_identity);
  encoder.i64(value.observed_at);
}

void decode(Decoder& decoder, VerificationEvidence& value) {
  decode(decoder, value.session);
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  decode(decoder, value.shard);
  value.verified_bytes = decoder.u64();
  decode(decoder, value.verified_digest);
  decode(decoder, value.outcome);
  value.verifier_identity = decoder.string();
  value.observed_at = decoder.i64();
}

void encode(Encoder& encoder, const DurabilityAssertion& value) {
  encode(encoder, value.status);
  encoder.string(value.backend_identity);
  encode(encoder, value.evidence_digest);
  encoder.i64(value.observed_at);
}

void decode(Decoder& decoder, DurabilityAssertion& value) {
  decode(decoder, value.status);
  value.backend_identity = decoder.string();
  decode(decoder, value.evidence_digest);
  value.observed_at = decoder.i64();
}

void encode(Encoder& encoder, const ShardProgress& value) {
  encode(encoder, value.index);
  encode(encoder, value.state);
  encoder.u64(value.declared_bytes);
  encoder.u64(value.transferred_bytes);
  encoder.u64(value.verified_bytes);
  encode(encoder, value.sequence);
  encoder.boolean(value.attempt.has_value());
  if (value.attempt.has_value()) {
    encode(encoder, value.attempt.value());
  }
  encode(encoder, value.declared_digest);
  encoder.boolean(value.observed_digest.has_value());
  if (value.observed_digest.has_value()) {
    encode(encoder, value.observed_digest.value());
  }
}

void decode(Decoder& decoder, ShardProgress& value) {
  decode(decoder, value.index);
  decode(decoder, value.state);
  value.declared_bytes = decoder.u64();
  value.transferred_bytes = decoder.u64();
  value.verified_bytes = decoder.u64();
  decode(decoder, value.sequence);
  if (decoder.boolean()) {
    TransferAttemptId attempt;
    decode(decoder, attempt);
    value.attempt = attempt;
  } else {
    value.attempt.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  decode(decoder, value.declared_digest);
  if (decoder.boolean()) {
    Digest digest;
    decode(decoder, digest);
    value.observed_digest = digest;
  } else {
    value.observed_digest.reset();
  }
}

void encode(Encoder& encoder, const SessionView& value) {
  encode(encoder, value.session);
  encode(encoder, value.checkpoint);
  encode(encoder, value.checkpoint_generation);
  encode(encoder, value.workload);
  encode(encoder, value.contract_generation);
  encode(encoder, value.isolation);
  encode(encoder, value.destination);
  encode(encoder, value.state);
  encode(encoder, value.evidence);
  encode(encoder, value.durability);
  encoder.u64(value.declared_bytes);
  encoder.u64(value.transferred_bytes);
  encoder.u64(value.verified_bytes);
  encoder.u32(value.shards_total);
  encoder.u32(value.shards_transferred);
  encoder.u32(value.shards_verified);
  encoder.u32(value.shards_ambiguous);
  encoder.boolean(value.last_reason.has_value());
  if (value.last_reason.has_value()) {
    encode(encoder, value.last_reason.value());
  }
  encoder.string(value.last_detail);
  encoder.string(value.stale_reason);
  encoder.boolean(value.superseded_by.has_value());
  if (value.superseded_by.has_value()) {
    encode(encoder, value.superseded_by.value());
  }
  encoder.boolean(value.envelope.has_value());
  if (value.envelope.has_value()) {
    encode(encoder, value.envelope.value());
  }
  encoder.u32(static_cast<std::uint32_t>(value.shards.size()));
  for (const ShardProgress& shard : value.shards) {
    encode(encoder, shard);
  }
  encoder.i64(value.created_at);
  encoder.i64(value.updated_at);
  encoder.boolean(value.deadline_target.has_value());
  if (value.deadline_target.has_value()) {
    encoder.i64(value.deadline_target.value());
  }
}

void decode(Decoder& decoder, SessionView& value) {
  decode(decoder, value.session);
  decode(decoder, value.checkpoint);
  decode(decoder, value.checkpoint_generation);
  decode(decoder, value.workload);
  decode(decoder, value.contract_generation);
  decode(decoder, value.isolation);
  decode(decoder, value.destination);
  decode(decoder, value.state);
  decode(decoder, value.evidence);
  decode(decoder, value.durability);
  value.declared_bytes = decoder.u64();
  value.transferred_bytes = decoder.u64();
  value.verified_bytes = decoder.u64();
  value.shards_total = decoder.u32();
  value.shards_transferred = decoder.u32();
  value.shards_verified = decoder.u32();
  value.shards_ambiguous = decoder.u32();
  if (decoder.boolean()) {
    ReasonCode reason = ReasonCode::Internal;
    decode(decoder, reason);
    value.last_reason = reason;
  } else {
    value.last_reason.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  value.last_detail = decoder.string();
  value.stale_reason = decoder.string();
  if (decoder.boolean()) {
    SessionId id;
    decode(decoder, id);
    value.superseded_by = id;
  } else {
    value.superseded_by.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  if (decoder.boolean()) {
    TrafficEnvelope envelope;
    decode(decoder, envelope);
    value.envelope = envelope;
  } else {
    value.envelope.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_shards_per_checkpoint) {
    decoder.fail(ErrorCode::CollectionTooLarge, "session view lists too many shards");
    return;
  }
  value.shards.clear();
  value.shards.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    ShardProgress shard;
    decode(decoder, shard);
    if (!decoder.ok()) {
      return;
    }
    value.shards.push_back(shard);
  }
  value.created_at = decoder.i64();
  value.updated_at = decoder.i64();
  if (decoder.boolean()) {
    value.deadline_target = decoder.i64();
  } else {
    value.deadline_target.reset();
  }
}

void encode(Encoder& encoder, const SessionSummary& value) {
  encode(encoder, value.session);
  encode(encoder, value.checkpoint);
  encode(encoder, value.checkpoint_generation);
  encode(encoder, value.workload);
  encode(encoder, value.state);
  encode(encoder, value.evidence);
  encoder.u64(value.declared_bytes);
  encoder.u64(value.transferred_bytes);
  encoder.u64(value.verified_bytes);
  encoder.i64(value.updated_at);
}

void decode(Decoder& decoder, SessionSummary& value) {
  decode(decoder, value.session);
  decode(decoder, value.checkpoint);
  decode(decoder, value.checkpoint_generation);
  decode(decoder, value.workload);
  decode(decoder, value.state);
  decode(decoder, value.evidence);
  value.declared_bytes = decoder.u64();
  value.transferred_bytes = decoder.u64();
  value.verified_bytes = decoder.u64();
  value.updated_at = decoder.i64();
}

void encode(Encoder& encoder, const AccountingSnapshot& value) {
  encoder.u64(value.bytes_admitted);
  encoder.u64(value.bytes_transferred);
  encoder.u64(value.bytes_verified);
  encoder.u64(value.bytes_cancelled);
  encoder.u64(value.bytes_wasted);
  encoder.u64(value.bytes_unproven);
  encoder.u64(value.bytes_deferred);
  encoder.u64(value.granted_outstanding_bytes);
  encoder.u64(value.sessions_admitted);
  encoder.u64(value.sessions_deferred);
  encoder.u64(value.sessions_denied);
  encoder.u64(value.sessions_completed);
  encoder.u64(value.sessions_cancelled);
  encoder.u64(value.sessions_superseded);
  encoder.u64(value.sessions_failed);
  encoder.u64(value.commands_processed);
  encoder.u32(value.active_sessions);
  encoder.u32(value.active_attempts);
}

void decode(Decoder& decoder, AccountingSnapshot& value) {
  value.bytes_admitted = decoder.u64();
  value.bytes_transferred = decoder.u64();
  value.bytes_verified = decoder.u64();
  value.bytes_cancelled = decoder.u64();
  value.bytes_wasted = decoder.u64();
  value.bytes_unproven = decoder.u64();
  value.bytes_deferred = decoder.u64();
  value.granted_outstanding_bytes = decoder.u64();
  value.sessions_admitted = decoder.u64();
  value.sessions_deferred = decoder.u64();
  value.sessions_denied = decoder.u64();
  value.sessions_completed = decoder.u64();
  value.sessions_cancelled = decoder.u64();
  value.sessions_superseded = decoder.u64();
  value.sessions_failed = decoder.u64();
  value.commands_processed = decoder.u64();
  value.active_sessions = decoder.u32();
  value.active_attempts = decoder.u32();
}

void encode(Encoder& encoder, const Explanation& value) {
  encode(encoder, value.session);
  encoder.string(value.summary);
  encoder.u32(static_cast<std::uint32_t>(value.timeline.size()));
  for (const std::string& line : value.timeline) {
    encoder.string(line);
  }
}

void decode(Decoder& decoder, Explanation& value) {
  decode(decoder, value.session);
  value.summary = decoder.string();
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > 4096U) {
    decoder.fail(ErrorCode::CollectionTooLarge, "explanation lists too many timeline entries");
    return;
  }
  value.timeline.clear();
  value.timeline.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    const std::string line = decoder.string();
    if (!decoder.ok()) {
      return;
    }
    value.timeline.push_back(line);
  }
}

void encode(Encoder& encoder, const FabricEvent& value) {
  encode(encoder, value.kind);
  encode(encoder, value.session);
  encode(encoder, value.reason);
  encoder.string(value.detail);
  encoder.i64(value.at);
}

void decode(Decoder& decoder, FabricEvent& value) {
  decode(decoder, value.kind);
  decode(decoder, value.session);
  decode(decoder, value.reason);
  value.detail = decoder.string();
  value.at = decoder.i64();
}

}  // namespace ctf::wire
