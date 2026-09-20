#pragma once

// Framed request/response protocol.
//
// Every connection begins with Hello, which is how a peer learns the current
// coordinator epoch and generations. Those values are then carried back in
// every CommandFence, so authority travels with the command instead of being
// assumed from connection liveness.
//
// Replay handling: frame sequence numbers must strictly increase in each
// direction on a connection, and every authoritative command carries a fence
// plus (for submissions) an idempotency key.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ctf/engine.hpp"
#include "ctf/net.hpp"
#include "ctf/status.hpp"
#include "ctf/wire.hpp"

namespace ctf::wire {

enum class MessageType : std::uint16_t {
  HelloRequest = 1,
  HelloResponse = 2,
  SubmitSession = 16,
  DecisionResponse = 17,
  RevalidateSession = 18,
  RequestWave = 19,
  WaveResponse = 20,
  ReportSourceComplete = 21,
  ReportTransfer = 22,
  ReportVerification = 23,
  ReportAmbiguous = 24,
  CancelSession = 25,
  PauseSession = 26,
  ResumeSession = 27,
  RecordDurability = 28,
  QuerySession = 32,
  SessionViewResponse = 33,
  QuerySessions = 34,
  SessionListResponse = 35,
  QueryAccounting = 36,
  AccountingResponse = 37,
  QueryExplain = 38,
  ExplanationResponse = 39,
  QueryInvariants = 40,
  StatusResponse = 48,
  ShutdownRequest = 56,
  // Sender -> sink transfer channel.
  ShardBegin = 64,
  ShardData = 65,
  ShardEnd = 66,
  ShardAck = 67,
};

struct ShardBeginPayload {
  SessionId session;
  TransferAttemptId attempt;
  AttemptSequence sequence;
  CheckpointId checkpoint;
  CheckpointGeneration checkpoint_generation;
  WorkloadId workload;
  ShardIndex shard;
  std::uint64_t declared_bytes = 0;
  Digest declared_digest;
};

struct ShardDataPayload {
  TransferAttemptId attempt;
  AttemptSequence sequence;
  std::uint64_t offset = 0;
  Bytes data;
};

struct ShardEndPayload {
  std::uint64_t bytes_sent = 0;
  Digest sent_digest;
  bool truncated = false;
};

struct ShardAckPayload {
  std::uint64_t bytes_received = 0;
  bool verified = false;
  bool truncated = false;
  Digest received_digest;
  std::string detail;
};

void encode(Encoder& encoder, const ShardBeginPayload& value);
void decode(Decoder& decoder, ShardBeginPayload& value);
void encode(Encoder& encoder, const ShardDataPayload& value);
void decode(Decoder& decoder, ShardDataPayload& value);
void encode(Encoder& encoder, const ShardEndPayload& value);
void decode(Decoder& decoder, ShardEndPayload& value);
void encode(Encoder& encoder, const ShardAckPayload& value);
void decode(Decoder& decoder, ShardAckPayload& value);

[[nodiscard]] const char* to_string(MessageType value) noexcept;
[[nodiscard]] bool is_known_message(MessageType value) noexcept;
[[nodiscard]] bool is_request(MessageType value) noexcept;
[[nodiscard]] std::optional<MessageType> response_for(MessageType request) noexcept;

enum class ClientKind : std::uint8_t {
  Sender = 0,
  Sink = 1,
  Operator = 2,
  Observer = 3,
};

[[nodiscard]] const char* to_string(ClientKind value) noexcept;

struct HelloRequest {
  ClientKind kind = ClientKind::Operator;
  std::string identity;
};

struct HelloResponse {
  CoordinatorEpoch epoch;
  PolicyGeneration policy_generation;
  TopologyGeneration topology_generation;
  std::vector<ContractGenerationRecord> contracts;
  Limits limits;
  std::string server_label;
};

struct SubmitRequest {
  SessionRequest request;
  CommandFence fence;
};

struct SessionQuery {
  SessionId session;
};

struct SessionsQuery {
  bool has_workload = false;
  WorkloadId workload;
  std::uint32_t limit = 64;
};

struct CancelRequest {
  SessionId session;
  CommandFence fence;
  ReasonCode reason = ReasonCode::CancelledByOperator;
  std::string detail;
};

struct PauseRequest {
  SessionId session;
  CommandFence fence;
  std::string reason;
};

struct ResumeRequest {
  SessionId session;
  CommandFence fence;
};

struct RevalidateRequest {
  SessionId session;
  CommandFence fence;
};

struct WaveRequest {
  SessionId session;
  ShardIndex shard;
  CommandFence fence;
};

struct AmbiguityRequest {
  SessionId session;
  TransferAttemptId attempt;
  AttemptSequence sequence;
  std::string cause;
  CommandFence fence;
};

struct SourceCompleteRequest {
  SourceCompleteEvidence evidence;
  CommandFence fence;
};

struct TransferReport {
  TransferEvidence evidence;
  CommandFence fence;
};

struct VerificationReport {
  VerificationEvidence evidence;
  CommandFence fence;
};

struct DurabilityRequest {
  SessionId session;
  DurabilityAssertion assertion;
  CommandFence fence;
};

struct SessionListResponse {
  std::vector<SessionSummary> sessions;
};

/// Deterministic status payload used by every command that has no value.
struct StatusPayload {
  ErrorCode code = ErrorCode::Ok;
  ReasonCode reason = ReasonCode::Admitted;
  std::string detail;

  [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::Ok; }
};

// --- Message codecs ---------------------------------------------------------

void encode(Encoder& encoder, const HelloRequest& value);
void decode(Decoder& decoder, HelloRequest& value);
void encode(Encoder& encoder, const HelloResponse& value);
void decode(Decoder& decoder, HelloResponse& value);
void encode(Encoder& encoder, const SubmitRequest& value);
void decode(Decoder& decoder, SubmitRequest& value);
void encode(Encoder& encoder, const SessionQuery& value);
void decode(Decoder& decoder, SessionQuery& value);
void encode(Encoder& encoder, const SessionsQuery& value);
void decode(Decoder& decoder, SessionsQuery& value);
void encode(Encoder& encoder, const CancelRequest& value);
void decode(Decoder& decoder, CancelRequest& value);
void encode(Encoder& encoder, const PauseRequest& value);
void decode(Decoder& decoder, PauseRequest& value);
void encode(Encoder& encoder, const ResumeRequest& value);
void decode(Decoder& decoder, ResumeRequest& value);
void encode(Encoder& encoder, const RevalidateRequest& value);
void decode(Decoder& decoder, RevalidateRequest& value);
void encode(Encoder& encoder, const WaveRequest& value);
void decode(Decoder& decoder, WaveRequest& value);
void encode(Encoder& encoder, const AmbiguityRequest& value);
void decode(Decoder& decoder, AmbiguityRequest& value);
void encode(Encoder& encoder, const SourceCompleteRequest& value);
void decode(Decoder& decoder, SourceCompleteRequest& value);
void encode(Encoder& encoder, const TransferReport& value);
void decode(Decoder& decoder, TransferReport& value);
void encode(Encoder& encoder, const VerificationReport& value);
void decode(Decoder& decoder, VerificationReport& value);
void encode(Encoder& encoder, const DurabilityRequest& value);
void decode(Decoder& decoder, DurabilityRequest& value);
void encode(Encoder& encoder, const SessionListResponse& value);
void decode(Decoder& decoder, SessionListResponse& value);
void encode(Encoder& encoder, const StatusPayload& value);
void decode(Decoder& decoder, StatusPayload& value);

/// Encodes a payload value with no length prefix (framing supplies the length).
template <class T>
[[nodiscard]] Bytes encode_payload(const T& value) {
  Encoder encoder;
  encode(encoder, value);
  return std::move(encoder).take();
}

/// Decodes a payload and rejects trailing bytes.
template <class T>
[[nodiscard]] Result<T> decode_payload(ByteSpan payload, const Limits& limits) {
  Decoder decoder(payload, limits);
  T value{};
  decode(decoder, value);
  if (!decoder.ok()) {
    return decoder.status();
  }
  const Status end = decoder.expect_end();
  if (!end.ok()) {
    return end;
  }
  return value;
}

struct Message {
  MessageType type = MessageType::StatusResponse;
  std::uint64_t sequence = 0;
  Bytes payload;
};

/// Framed message channel over one TCP connection.
class MessageChannel {
 public:
  MessageChannel() = default;
  explicit MessageChannel(net::TcpSocket socket, net::StopToken stop);

  MessageChannel(MessageChannel&& other) noexcept = default;
  MessageChannel& operator=(MessageChannel&& other) noexcept = default;
  MessageChannel(const MessageChannel&) = delete;
  MessageChannel& operator=(const MessageChannel&) = delete;

  [[nodiscard]] Status send(MessageType type, ByteSpan payload);
  [[nodiscard]] Result<Message> receive();

  [[nodiscard]] Status close();
  [[nodiscard]] bool open() const noexcept { return socket_.valid(); }
  [[nodiscard]] std::uint64_t last_received_sequence() const noexcept {
    return last_received_sequence_;
  }
  [[nodiscard]] std::string peer_text() const { return socket_.peer_text(); }

 private:
  net::TcpSocket socket_;
  net::StopToken stop_;
  std::uint64_t send_sequence_ = 0;
  std::uint64_t last_received_sequence_ = 0;
  bool received_any_ = false;
};

}  // namespace ctf::wire
