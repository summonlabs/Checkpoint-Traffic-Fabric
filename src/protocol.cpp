// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/protocol.hpp"

#include <array>
#include <cstring>

namespace ctf::wire {
namespace {

[[nodiscard]] bool read_exactly(net::TcpSocket& socket, MutableByteSpan buffer,
                                const net::StopToken& stop, Status* status) {
  std::size_t filled = 0;
  while (filled < buffer.size()) {
    Result<std::size_t> read = socket.read_some(buffer.subspan(filled), stop);
    if (!read.ok()) {
      *status = read.status();
      return false;
    }
    if (read.value() == 0) {
      *status = Status::error(ErrorCode::PeerClosed, "peer closed the connection");
      return false;
    }
    filled += read.value();
  }
  return true;
}

}  // namespace

const char* to_string(MessageType value) noexcept {
  switch (value) {
    case MessageType::HelloRequest:
      return "HelloRequest";
    case MessageType::HelloResponse:
      return "HelloResponse";
    case MessageType::SubmitSession:
      return "SubmitSession";
    case MessageType::DecisionResponse:
      return "DecisionResponse";
    case MessageType::RevalidateSession:
      return "RevalidateSession";
    case MessageType::RequestWave:
      return "RequestWave";
    case MessageType::WaveResponse:
      return "WaveResponse";
    case MessageType::ReportSourceComplete:
      return "ReportSourceComplete";
    case MessageType::ReportTransfer:
      return "ReportTransfer";
    case MessageType::ReportVerification:
      return "ReportVerification";
    case MessageType::ReportAmbiguous:
      return "ReportAmbiguous";
    case MessageType::CancelSession:
      return "CancelSession";
    case MessageType::PauseSession:
      return "PauseSession";
    case MessageType::ResumeSession:
      return "ResumeSession";
    case MessageType::RecordDurability:
      return "RecordDurability";
    case MessageType::QuerySession:
      return "QuerySession";
    case MessageType::SessionViewResponse:
      return "SessionViewResponse";
    case MessageType::QuerySessions:
      return "QuerySessions";
    case MessageType::SessionListResponse:
      return "SessionListResponse";
    case MessageType::QueryAccounting:
      return "QueryAccounting";
    case MessageType::AccountingResponse:
      return "AccountingResponse";
    case MessageType::QueryExplain:
      return "QueryExplain";
    case MessageType::ExplanationResponse:
      return "ExplanationResponse";
    case MessageType::QueryInvariants:
      return "QueryInvariants";
    case MessageType::StatusResponse:
      return "StatusResponse";
    case MessageType::ShutdownRequest:
      return "ShutdownRequest";
    case MessageType::ShardBegin:
      return "ShardBegin";
    case MessageType::ShardData:
      return "ShardData";
    case MessageType::ShardEnd:
      return "ShardEnd";
    case MessageType::ShardAck:
      return "ShardAck";
  }
  return "Unknown";
}

bool is_known_message(MessageType value) noexcept {
  return std::string_view(to_string(value)) != "Unknown";
}

bool is_request(MessageType value) noexcept {
  switch (value) {
    case MessageType::HelloRequest:
    case MessageType::SubmitSession:
    case MessageType::RevalidateSession:
    case MessageType::RequestWave:
    case MessageType::ReportSourceComplete:
    case MessageType::ReportTransfer:
    case MessageType::ReportVerification:
    case MessageType::ReportAmbiguous:
    case MessageType::CancelSession:
    case MessageType::PauseSession:
    case MessageType::ResumeSession:
    case MessageType::RecordDurability:
    case MessageType::QuerySession:
    case MessageType::QuerySessions:
    case MessageType::QueryAccounting:
    case MessageType::QueryExplain:
    case MessageType::QueryInvariants:
    case MessageType::ShutdownRequest:
    case MessageType::ShardBegin:
    case MessageType::ShardData:
    case MessageType::ShardEnd:
      return true;
    case MessageType::ShardAck:
    case MessageType::HelloResponse:
    case MessageType::DecisionResponse:
    case MessageType::WaveResponse:
    case MessageType::SessionViewResponse:
    case MessageType::SessionListResponse:
    case MessageType::AccountingResponse:
    case MessageType::ExplanationResponse:
    case MessageType::StatusResponse:
      return false;
  }
  return false;
}

std::optional<MessageType> response_for(MessageType request) noexcept {
  switch (request) {
    case MessageType::HelloRequest:
      return MessageType::HelloResponse;
    case MessageType::SubmitSession:
    case MessageType::RevalidateSession:
      return MessageType::DecisionResponse;
    case MessageType::RequestWave:
      return MessageType::WaveResponse;
    case MessageType::QuerySession:
      return MessageType::SessionViewResponse;
    case MessageType::QuerySessions:
      return MessageType::SessionListResponse;
    case MessageType::QueryAccounting:
      return MessageType::AccountingResponse;
    case MessageType::QueryExplain:
      return MessageType::ExplanationResponse;
    case MessageType::ReportSourceComplete:
    case MessageType::ReportTransfer:
    case MessageType::ReportVerification:
    case MessageType::ReportAmbiguous:
    case MessageType::CancelSession:
    case MessageType::PauseSession:
    case MessageType::ResumeSession:
    case MessageType::RecordDurability:
    case MessageType::QueryInvariants:
    case MessageType::ShutdownRequest:
      return MessageType::StatusResponse;
    case MessageType::ShardData:
    case MessageType::ShardEnd:
      return MessageType::ShardAck;
    case MessageType::ShardBegin:
    case MessageType::ShardAck:
    case MessageType::HelloResponse:
    case MessageType::DecisionResponse:
    case MessageType::WaveResponse:
    case MessageType::SessionViewResponse:
    case MessageType::SessionListResponse:
    case MessageType::AccountingResponse:
    case MessageType::ExplanationResponse:
    case MessageType::StatusResponse:
      return std::nullopt;
  }
  return std::nullopt;
}

const char* to_string(ClientKind value) noexcept {
  switch (value) {
    case ClientKind::Sender:
      return "Sender";
    case ClientKind::Sink:
      return "Sink";
    case ClientKind::Operator:
      return "Operator";
    case ClientKind::Observer:
      return "Observer";
  }
  return "Unknown";
}

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

void encode(Encoder& encoder, const HelloRequest& value) {
  encode(encoder, static_cast<std::uint8_t>(value.kind));
  encoder.string(value.identity);
}

void decode(Decoder& decoder, HelloRequest& value) {
  const std::uint8_t raw = decoder.u8();
  if (!decoder.ok()) {
    return;
  }
  switch (raw) {
    case 0:
      value.kind = ClientKind::Sender;
      break;
    case 1:
      value.kind = ClientKind::Sink;
      break;
    case 2:
      value.kind = ClientKind::Operator;
      break;
    case 3:
      value.kind = ClientKind::Observer;
      break;
    default:
      decoder.fail(ErrorCode::UnsupportedValue, "client kind is not in the supported set");
      return;
  }
  value.identity = decoder.string();
}

void encode(Encoder& encoder, const HelloResponse& value) {
  encode(encoder, value.epoch);
  encode(encoder, value.policy_generation);
  encode(encoder, value.topology_generation);
  encoder.u32(static_cast<std::uint32_t>(value.contracts.size()));
  for (const ContractGenerationRecord& record : value.contracts) {
    encode(encoder, record.workload);
    encode(encoder, record.generation);
  }
  encode(encoder, value.limits);
  encoder.string(value.server_label);
}

void decode(Decoder& decoder, HelloResponse& value) {
  decode(decoder, value.epoch);
  decode(decoder, value.policy_generation);
  decode(decoder, value.topology_generation);
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_workloads) {
    decoder.fail(ErrorCode::CollectionTooLarge, "hello declares too many contracts");
    return;
  }
  value.contracts.clear();
  value.contracts.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    ContractGenerationRecord record;
    decode(decoder, record.workload);
    decode(decoder, record.generation);
    if (!decoder.ok()) {
      return;
    }
    value.contracts.push_back(record);
  }
  decode(decoder, value.limits);
  value.server_label = decoder.string();
}

void encode(Encoder& encoder, const SubmitRequest& value) {
  encode(encoder, value.request);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, SubmitRequest& value) {
  decode(decoder, value.request);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const SessionQuery& value) { encode(encoder, value.session); }

void decode(Decoder& decoder, SessionQuery& value) { decode(decoder, value.session); }

void encode(Encoder& encoder, const SessionsQuery& value) {
  encoder.boolean(value.has_workload);
  encode(encoder, value.workload);
  encoder.u32(value.limit);
}

void decode(Decoder& decoder, SessionsQuery& value) {
  value.has_workload = decoder.boolean();
  decode(decoder, value.workload);
  value.limit = decoder.u32();
}

void encode(Encoder& encoder, const CancelRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.fence);
  encode(encoder, value.reason);
  encoder.string(value.detail);
}

void decode(Decoder& decoder, CancelRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.fence);
  decode(decoder, value.reason);
  value.detail = decoder.string();
}

void encode(Encoder& encoder, const PauseRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.fence);
  encoder.string(value.reason);
}

void decode(Decoder& decoder, PauseRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.fence);
  value.reason = decoder.string();
}

void encode(Encoder& encoder, const ResumeRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, ResumeRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const RevalidateRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, RevalidateRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const WaveRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.shard);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, WaveRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.shard);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const AmbiguityRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encoder.string(value.cause);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, AmbiguityRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  value.cause = decoder.string();
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const SourceCompleteRequest& value) {
  encode(encoder, value.evidence);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, SourceCompleteRequest& value) {
  decode(decoder, value.evidence);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const TransferReport& value) {
  encode(encoder, value.evidence);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, TransferReport& value) {
  decode(decoder, value.evidence);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const VerificationReport& value) {
  encode(encoder, value.evidence);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, VerificationReport& value) {
  decode(decoder, value.evidence);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const DurabilityRequest& value) {
  encode(encoder, value.session);
  encode(encoder, value.assertion);
  encode(encoder, value.fence);
}

void decode(Decoder& decoder, DurabilityRequest& value) {
  decode(decoder, value.session);
  decode(decoder, value.assertion);
  decode(decoder, value.fence);
}

void encode(Encoder& encoder, const SessionListResponse& value) {
  encoder.u32(static_cast<std::uint32_t>(value.sessions.size()));
  for (const SessionSummary& summary : value.sessions) {
    encode(encoder, summary);
  }
}

void decode(Decoder& decoder, SessionListResponse& value) {
  const std::uint32_t count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (count > decoder.limits().max_sessions) {
    decoder.fail(ErrorCode::CollectionTooLarge, "session list exceeds the configured bound");
    return;
  }
  value.sessions.clear();
  value.sessions.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    SessionSummary summary;
    decode(decoder, summary);
    if (!decoder.ok()) {
      return;
    }
    value.sessions.push_back(summary);
  }
}

void encode(Encoder& encoder, const StatusPayload& value) {
  encode(encoder, value.code);
  encode(encoder, value.reason);
  encoder.string(value.detail);
}

void decode(Decoder& decoder, StatusPayload& value) {
  decode(decoder, value.code);
  decode(decoder, value.reason);
  value.detail = decoder.string();
}

void encode(Encoder& encoder, const ShardBeginPayload& value) {
  encode(encoder, value.session);
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encode(encoder, value.checkpoint);
  encode(encoder, value.checkpoint_generation);
  encode(encoder, value.workload);
  encode(encoder, value.shard);
  encoder.u64(value.declared_bytes);
  encode(encoder, value.declared_digest);
}

void decode(Decoder& decoder, ShardBeginPayload& value) {
  decode(decoder, value.session);
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  decode(decoder, value.checkpoint);
  decode(decoder, value.checkpoint_generation);
  decode(decoder, value.workload);
  decode(decoder, value.shard);
  value.declared_bytes = decoder.u64();
  decode(decoder, value.declared_digest);
}

void encode(Encoder& encoder, const ShardDataPayload& value) {
  encode(encoder, value.attempt);
  encode(encoder, value.sequence);
  encoder.u64(value.offset);
  encoder.bytes(ByteSpan(value.data.data(), value.data.size()));
}

void decode(Decoder& decoder, ShardDataPayload& value) {
  decode(decoder, value.attempt);
  decode(decoder, value.sequence);
  value.offset = decoder.u64();
  value.data = decoder.bytes();
}

void encode(Encoder& encoder, const ShardEndPayload& value) {
  encoder.u64(value.bytes_sent);
  encode(encoder, value.sent_digest);
  encoder.boolean(value.truncated);
}

void decode(Decoder& decoder, ShardEndPayload& value) {
  value.bytes_sent = decoder.u64();
  decode(decoder, value.sent_digest);
  value.truncated = decoder.boolean();
}

void encode(Encoder& encoder, const ShardAckPayload& value) {
  encoder.u64(value.bytes_received);
  encoder.boolean(value.verified);
  encoder.boolean(value.truncated);
  encode(encoder, value.received_digest);
  encoder.string(value.detail);
}

void decode(Decoder& decoder, ShardAckPayload& value) {
  value.bytes_received = decoder.u64();
  value.verified = decoder.boolean();
  value.truncated = decoder.boolean();
  decode(decoder, value.received_digest);
  value.detail = decoder.string();
}

// ---------------------------------------------------------------------------
// MessageChannel
// ---------------------------------------------------------------------------

MessageChannel::MessageChannel(net::TcpSocket socket, net::StopToken stop)
    : socket_(std::move(socket)), stop_(std::move(stop)) {}

Status MessageChannel::send(MessageType type, ByteSpan payload) {
  FrameHeader header;
  header.message_type = static_cast<std::uint16_t>(type);
  header.sequence = ++send_sequence_;
  header.payload_bytes = static_cast<std::uint32_t>(payload.size());
  Result<Bytes> frame = encode_frame(header, payload);
  if (!frame.ok()) {
    return frame.status();
  }
  return socket_.write_all(ByteSpan(frame.value().data(), frame.value().size()), stop_);
}

Result<Message> MessageChannel::receive() {
  std::array<std::byte, kFrameHeaderBytes> header_bytes{};
  Status status = Status::success();
  if (!read_exactly(socket_, MutableByteSpan(header_bytes.data(), header_bytes.size()), stop_,
                    &status)) {
    return status;
  }
  const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(header_bytes.data());
  std::uint32_t magic = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    magic = (magic << 8) | raw[i];
  }
  if (magic != kFrameMagic) {
    return Status::error(ErrorCode::InvalidSyntax, "frame magic does not match");
  }
  std::uint32_t payload_bytes = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    payload_bytes = (payload_bytes << 8) | raw[20 + i];
  }
  if (payload_bytes > kMaxPayloadBytes) {
    return Status::error(ErrorCode::PayloadTooLarge, "peer declared an oversized frame payload");
  }
  Bytes frame(header_bytes.begin(), header_bytes.end());
  if (payload_bytes > 0) {
    const std::size_t offset = frame.size();
    frame.resize(offset + payload_bytes);
    if (!read_exactly(socket_, MutableByteSpan(frame.data() + offset, payload_bytes), stop_,
                      &status)) {
      return status;
    }
  }
  FrameHeader header;
  Result<Bytes> payload = decode_frame(ByteSpan(frame.data(), frame.size()), &header);
  if (!payload.ok()) {
    return payload.status();
  }
  const MessageType type = static_cast<MessageType>(header.message_type);
  if (!is_known_message(type)) {
    return Status::error(ErrorCode::UnknownMessageType, "peer sent an unknown message type");
  }
  if (received_any_ && header.sequence <= last_received_sequence_) {
    return Status::error(ErrorCode::SequenceViolation,
                         "peer repeated or rewound a frame sequence number");
  }
  received_any_ = true;
  last_received_sequence_ = header.sequence;

  Message message;
  message.type = type;
  message.sequence = header.sequence;
  message.payload = std::move(payload).value();
  return message;
}

Status MessageChannel::close() {
  Status status = socket_.shutdown_both();
  socket_.close();
  return status;
}

}  // namespace ctf::wire
