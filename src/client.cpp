// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/client.hpp"

#include <string>
#include <utility>

namespace ctf {

CoordinatorClient::CoordinatorClient(wire::MessageChannel channel, wire::HelloResponse hello,
                                     std::string identity, Limits limits)
    : channel_(std::move(channel)),
      hello_(std::move(hello)),
      identity_(std::move(identity)),
      limits_(limits) {}

Result<CoordinatorClient> CoordinatorClient::connect(const ClientConfig& config,
                                                     net::StopToken stop) {
  if (config.identity.empty() || config.identity.size() > config.limits.max_string_bytes) {
    return Status::error(ErrorCode::InvalidArgument, "client identity must be a bounded string");
  }
  Result<net::TcpSocket> socket = net::TcpSocket::connect(config.host, config.port, stop);
  if (!socket.ok()) {
    return socket.status();
  }
  wire::MessageChannel channel(std::move(socket).value(), stop);
  wire::HelloRequest request;
  request.kind = config.kind;
  request.identity = config.identity;
  const Bytes payload = wire::encode_payload(request);
  Status sent = channel.send(wire::MessageType::HelloRequest, ByteSpan(payload.data(), payload.size()));
  if (!sent.ok()) {
    return sent;
  }
  Result<wire::Message> response = channel.receive();
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().type == wire::MessageType::StatusResponse) {
    Result<wire::StatusPayload> status =
        wire::decode_payload<wire::StatusPayload>(ByteSpan(response.value().payload.data(),
                                                           response.value().payload.size()),
                                                  config.limits);
    if (!status.ok()) {
      return status.status();
    }
    return Status::error(status.value().code, "handshake refused: " + status.value().detail);
  }
  if (response.value().type != wire::MessageType::HelloResponse) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         "coordinator did not answer the handshake with a hello response");
  }
  Result<wire::HelloResponse> hello = wire::decode_payload<wire::HelloResponse>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), config.limits);
  if (!hello.ok()) {
    return hello.status();
  }
  if (hello.value().epoch.incarnation.is_zero() || hello.value().epoch.term.is_zero()) {
    return Status::error(ErrorCode::CorruptState, "coordinator reported a zero epoch");
  }
  return CoordinatorClient(std::move(channel), std::move(hello).value(), config.identity,
                           hello.value().limits);
}

CommandFence CoordinatorClient::current_fence(
    WorkloadId workload, std::optional<CheckpointGeneration> checkpoint_generation,
    std::optional<AttemptSequence> attempt_sequence) const {
  CommandFence fence;
  fence.epoch = hello_.epoch;
  fence.policy_generation = hello_.policy_generation;
  fence.topology_generation = hello_.topology_generation;
  fence.contract_generation = WorkloadContractGeneration(0);
  for (const ContractGenerationRecord& record : hello_.contracts) {
    if (record.workload == workload) {
      fence.contract_generation = record.generation;
      break;
    }
  }
  fence.checkpoint_generation = checkpoint_generation;
  fence.attempt_sequence = attempt_sequence;
  return fence;
}

Result<wire::Message> CoordinatorClient::round_trip(wire::MessageType type, ByteSpan payload,
                                                    wire::MessageType expected) {
  Status sent = channel_.send(type, payload);
  if (!sent.ok()) {
    return sent;
  }
  Result<wire::Message> response = channel_.receive();
  if (!response.ok()) {
    return response.status();
  }
  if (response.value().type == wire::MessageType::StatusResponse && expected != wire::MessageType::StatusResponse) {
    Result<wire::StatusPayload> status = wire::decode_payload<wire::StatusPayload>(
        ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
    if (!status.ok()) {
      return status.status();
    }
    return Status::error(status.value().code, status.value().detail);
  }
  if (response.value().type != expected) {
    return Status::error(ErrorCode::InvalidStateTransition,
                         std::string("coordinator answered with ") +
                             wire::to_string(response.value().type) + " instead of " +
                             wire::to_string(expected));
  }
  return response;
}

Result<wire::StatusPayload> CoordinatorClient::command(wire::MessageType type, ByteSpan payload) {
  Result<wire::Message> response = round_trip(type, payload, wire::MessageType::StatusResponse);
  if (!response.ok()) {
    return response.status();
  }
  Result<wire::StatusPayload> status = wire::decode_payload<wire::StatusPayload>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
  if (!status.ok()) {
    return status.status();
  }
  if (!status.value().ok()) {
    return Status::error(status.value().code, status.value().detail);
  }
  return status;
}

Result<AdmissionDecision> CoordinatorClient::submit_session(const SessionRequest& request,
                                                            const CommandFence& fence) {
  wire::SubmitRequest payload;
  payload.request = request;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::Message> response =
      round_trip(wire::MessageType::SubmitSession, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::DecisionResponse);
  if (!response.ok()) {
    return response.status();
  }
  return wire::decode_payload<AdmissionDecision>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
}

Result<AdmissionDecision> CoordinatorClient::revalidate_session(SessionId session,
                                                                const CommandFence& fence) {
  wire::RevalidateRequest payload;
  payload.session = session;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::Message> response =
      round_trip(wire::MessageType::RevalidateSession, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::DecisionResponse);
  if (!response.ok()) {
    return response.status();
  }
  return wire::decode_payload<AdmissionDecision>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
}

Result<WaveOutcome> CoordinatorClient::request_wave(SessionId session, ShardIndex shard,
                                                    const CommandFence& fence) {
  wire::WaveRequest payload;
  payload.session = session;
  payload.shard = shard;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::Message> response =
      round_trip(wire::MessageType::RequestWave, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::WaveResponse);
  if (!response.ok()) {
    return response.status();
  }
  return wire::decode_payload<WaveOutcome>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
}

Status CoordinatorClient::report_source_complete(const SourceCompleteEvidence& evidence,
                                                 const CommandFence& fence) {
  wire::SourceCompleteRequest payload;
  payload.evidence = evidence;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status = command(
      wire::MessageType::ReportSourceComplete, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::report_transfer(const TransferEvidence& evidence,
                                          const CommandFence& fence) {
  wire::TransferReport payload;
  payload.evidence = evidence;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::ReportTransfer, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::report_verification(const VerificationEvidence& evidence,
                                              const CommandFence& fence) {
  wire::VerificationReport payload;
  payload.evidence = evidence;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::ReportVerification, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::report_ambiguous(const wire::AmbiguityRequest& request) {
  const Bytes encoded = wire::encode_payload(request);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::ReportAmbiguous, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::cancel_session(SessionId session, const CommandFence& fence,
                                         ReasonCode reason, std::string detail) {
  wire::CancelRequest payload;
  payload.session = session;
  payload.fence = fence;
  payload.reason = reason;
  payload.detail = std::move(detail);
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::CancelSession, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::pause_session(SessionId session, const CommandFence& fence,
                                        std::string reason) {
  wire::PauseRequest payload;
  payload.session = session;
  payload.fence = fence;
  payload.reason = std::move(reason);
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::PauseSession, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::resume_session(SessionId session, const CommandFence& fence) {
  wire::ResumeRequest payload;
  payload.session = session;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::ResumeSession, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::record_durability(SessionId session, const DurabilityAssertion& assertion,
                                            const CommandFence& fence) {
  wire::DurabilityRequest payload;
  payload.session = session;
  payload.assertion = assertion;
  payload.fence = fence;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::StatusPayload> status =
      command(wire::MessageType::RecordDurability, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Result<SessionView> CoordinatorClient::view_session(SessionId session) {
  wire::SessionQuery payload;
  payload.session = session;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::Message> response =
      round_trip(wire::MessageType::QuerySession, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::SessionViewResponse);
  if (!response.ok()) {
    return response.status();
  }
  return wire::decode_payload<SessionView>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
}

Result<std::vector<SessionSummary>> CoordinatorClient::list_sessions(
    std::optional<WorkloadId> workload, std::uint32_t limit) {
  wire::SessionsQuery payload;
  payload.has_workload = workload.has_value();
  payload.workload = workload.value_or(WorkloadId{});
  payload.limit = limit;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::Message> response =
      round_trip(wire::MessageType::QuerySessions, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::SessionListResponse);
  if (!response.ok()) {
    return response.status();
  }
  Result<wire::SessionListResponse> decoded = wire::decode_payload<wire::SessionListResponse>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
  if (!decoded.ok()) {
    return decoded.status();
  }
  return std::move(decoded).value().sessions;
}

Result<AccountingSnapshot> CoordinatorClient::accounting() {
  const Bytes encoded = wire::encode_payload(std::uint8_t{0});
  Result<wire::Message> response =
      round_trip(wire::MessageType::QueryAccounting, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::AccountingResponse);
  if (!response.ok()) {
    return response.status();
  }
  return wire::decode_payload<AccountingSnapshot>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
}

Result<Explanation> CoordinatorClient::explain(SessionId session) {
  wire::SessionQuery payload;
  payload.session = session;
  const Bytes encoded = wire::encode_payload(payload);
  Result<wire::Message> response =
      round_trip(wire::MessageType::QueryExplain, ByteSpan(encoded.data(), encoded.size()),
                 wire::MessageType::ExplanationResponse);
  if (!response.ok()) {
    return response.status();
  }
  return wire::decode_payload<Explanation>(
      ByteSpan(response.value().payload.data(), response.value().payload.size()), limits_);
}

Status CoordinatorClient::check_invariants() {
  const Bytes encoded = wire::encode_payload(std::uint8_t{0});
  Result<wire::StatusPayload> status =
      command(wire::MessageType::QueryInvariants, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::request_shutdown() {
  const Bytes encoded = wire::encode_payload(std::uint8_t{0});
  Result<wire::StatusPayload> status =
      command(wire::MessageType::ShutdownRequest, ByteSpan(encoded.data(), encoded.size()));
  return status.ok() ? Status::success() : status.status();
}

Status CoordinatorClient::close() { return channel_.close(); }

}  // namespace ctf
