// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/agent.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "ctf/protocol.hpp"

namespace ctf {
namespace {

constexpr std::size_t kBlockBytes = 64U * 1024U;
constexpr std::size_t kTransferBufferBytes = 128U * 1024U;

[[nodiscard]] std::uint64_t splitmix64(std::uint64_t value) noexcept {
  value += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = value;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

/// Sleeps in stop-aware slices, never longer than the requested wait.
void sleep_until(Nanos target_ns, const Clock& clock, const net::StopToken& stop) {
  for (;;) {
    if (stop.stop_requested()) {
      return;
    }
    const Nanos now = clock.now();
    if (now >= target_ns) {
      return;
    }
    const Nanos remaining = target_ns - now;
    const Nanos slice = std::min<Nanos>(remaining, 5 * kNanosPerMillisecond);
    std::this_thread::sleep_for(
        std::chrono::nanoseconds(static_cast<std::int64_t>(std::max<Nanos>(slice, 1))));
  }
}

[[nodiscard]] Result<CoordinatorClient> connect_client(const std::string& host, std::uint16_t port,
                                                       wire::ClientKind kind,
                                                       const std::string& identity,
                                                       const Limits& limits,
                                                       const net::StopToken& stop,
                                                       std::uint32_t attempts) {
  Status last = Status::error(ErrorCode::ConnectionRefused, "coordinator was never reachable");
  for (std::uint32_t attempt = 0; attempt < attempts; ++attempt) {
    if (stop.stop_requested()) {
      return Status::error(ErrorCode::ShuttingDown, "connect cancelled before the handshake");
    }
    ClientConfig config;
    config.host = host;
    config.port = port;
    config.kind = kind;
    config.identity = identity;
    config.limits = limits;
    Result<CoordinatorClient> client = CoordinatorClient::connect(config, stop);
    if (client.ok()) {
      return client;
    }
    last = client.status();
    if (last.code() == ErrorCode::ShuttingDown) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return last;
}

}  // namespace

SyntheticCheckpointContent::SyntheticCheckpointContent(std::uint64_t seed, ShardIndex shard) {
  base_ = seed ^ (static_cast<std::uint64_t>(shard.value()) * 0x9E3779B97F4A7C15ULL);
}

void SyntheticCheckpointContent::fill(std::uint64_t offset, MutableByteSpan out) const {
  std::size_t index = 0;
  while (index < out.size()) {
    const std::uint64_t absolute = offset + index;
    const std::uint64_t word_index = absolute / 8U;
    const std::uint64_t word = splitmix64(base_ ^ (word_index * 0xD1B54A32D192ED03ULL));
    const unsigned start_byte = static_cast<unsigned>(absolute % 8U);
    for (unsigned byte = start_byte; byte < 8U && index < out.size(); ++byte, ++index) {
      out[index] = static_cast<std::byte>((word >> (byte * 8U)) & 0xFFU);
    }
  }
}

Digest SyntheticCheckpointContent::digest(std::uint64_t bytes) const {
  DigestBuilder builder;
  std::vector<std::byte> buffer(static_cast<std::size_t>(std::min<std::uint64_t>(bytes, kBlockBytes)));
  if (buffer.empty()) {
    return builder.finish();
  }
  std::uint64_t offset = 0;
  while (offset < bytes) {
    const std::size_t chunk =
        static_cast<std::size_t>(std::min<std::uint64_t>(bytes - offset, buffer.size()));
    fill(offset, MutableByteSpan(buffer.data(), chunk));
    builder.update(ByteSpan(buffer.data(), chunk));
    offset += chunk;
  }
  return builder.finish();
}

CheckpointSender::CheckpointSender(SenderConfig config, const Clock& clock)
    : config_(std::move(config)), clock_(&clock) {}

Result<SenderResult> CheckpointSender::run(net::StopToken stop) {
  SenderResult result;
  if (config_.shard_count == 0 || config_.shard_bytes == 0) {
    return Status::error(ErrorCode::InvalidArgument, "sender needs at least one non-empty shard");
  }
  if (config_.shard_count > config_.limits.max_shards_per_checkpoint) {
    return Status::error(ErrorCode::CollectionTooLarge, "shard count exceeds the configured bound");
  }
  if (static_cast<std::uint64_t>(config_.shard_count) >
      config_.limits.max_checkpoint_bytes / config_.shard_bytes) {
    return Status::error(ErrorCode::OutOfRange, "checkpoint size exceeds the configured bound");
  }

  Result<CoordinatorClient> client_result =
      connect_client(config_.coordinator_host, config_.coordinator_port, wire::ClientKind::Sender,
                     config_.identity, config_.limits, stop, 200);
  if (!client_result.ok()) {
    return client_result.status();
  }
  CoordinatorClient& client = client_result.value();

  CheckpointManifest manifest;
  manifest.checkpoint = config_.checkpoint;
  manifest.generation = config_.checkpoint_generation;
  manifest.workload = config_.workload;
  manifest.contract_generation = client.current_fence(config_.workload).contract_generation;
  manifest.shards.reserve(config_.shard_count);
  for (std::uint32_t i = 0; i < config_.shard_count; ++i) {
    const ShardIndex shard(i);
    SyntheticCheckpointContent content(config_.content_seed, shard);
    ShardDescriptor descriptor;
    descriptor.index = shard;
    descriptor.declared_bytes = config_.shard_bytes;
    descriptor.declared_digest = content.digest(config_.shard_bytes);
    descriptor.path_class = PathClassId(0);
    manifest.shards.push_back(descriptor);
    manifest.total_bytes += config_.shard_bytes;
  }
  manifest.manifest_digest = compute_manifest_digest(manifest);

  // The command identity is derived from the request body: retrying the same
  // request stays idempotent, while a different generation or checkpoint is a
  // different command. Deriving it per process run would collide across senders.
  std::uint64_t command_seed = 0xC0FFEE1234ULL;
  for (const std::uint8_t byte : config_.checkpoint.value().bytes()) {
    command_seed = (command_seed ^ byte) * 0x100000001B3ULL;
  }
  command_seed =
      (command_seed ^ config_.checkpoint_generation.value()) * 0x100000001B3ULL;
  for (const std::uint8_t byte : config_.workload.value().bytes()) {
    command_seed = (command_seed ^ byte) * 0x100000001B3ULL;
  }
  command_seed = (command_seed ^ manifest.manifest_digest.crc32c_value()) * 0x100000001B3ULL;
  command_seed = (command_seed ^ manifest.manifest_digest.fnv1a64_value()) * 0x100000001B3ULL;
  command_seed = (command_seed ^ config_.shard_count) * 0x100000001B3ULL;
  command_seed = (command_seed ^ config_.shard_bytes) * 0x100000001B3ULL;
  command_seed = (command_seed ^ config_.requested_rate_bps) * 0x100000001B3ULL;
  IdFactory command_factory(command_seed);
  SessionRequest request;
  request.command = CommandId(Uuid128::random(command_factory));
  request.workload = config_.workload;
  request.contract_generation = manifest.contract_generation;
  request.policy_generation = client.hello().policy_generation;
  request.topology_generation = client.hello().topology_generation;
  request.checkpoint = config_.checkpoint;
  request.checkpoint_generation = config_.checkpoint_generation;
  request.requested_isolation = config_.isolation;
  request.destination = config_.destination;
  request.requested_rate_bps = config_.requested_rate_bps;
  request.deadline_horizon_ns = config_.deadline_horizon_ns;
  request.manifest = manifest;

  const CommandFence fence =
      client.current_fence(config_.workload, config_.checkpoint_generation);
  Result<AdmissionDecision> decision = client.submit_session(request, fence);
  if (!decision.ok()) {
    result.exit_code = 4;
    result.message = decision.status().to_string();
    return result;
  }
  result.decision = decision.value().kind;
  result.reason = decision.value().reason;
  result.detail = decision.value().detail;
  result.session = decision.value().session;
  if (decision.value().kind != DecisionKind::Admit) {
    result.exit_code = decision.value().kind == DecisionKind::Defer ? 3 : 2;
    result.message = std::string(to_string(decision.value().kind)) + ": " +
                     to_string(decision.value().reason) + " " + decision.value().detail;
    return result;
  }
  if (!decision.value().envelope.has_value()) {
    result.exit_code = 4;
    result.message = "admission reported admit without an envelope";
    return result;
  }
  const SessionId session = decision.value().session;

  Result<net::TcpSocket> sink_socket =
      net::TcpSocket::connect(config_.sink_host, config_.sink_port, stop);
  if (!sink_socket.ok()) {
    result.exit_code = 4;
    result.message = "cannot reach the sink: " + sink_socket.status().to_string();
    return result;
  }
  wire::MessageChannel sink_channel(std::move(sink_socket).value(), stop);

  std::vector<std::byte> buffer(kTransferBufferBytes);
  bool died = false;
  bool truncated = false;
  TransferAttemptId last_attempt;
  AttemptSequence last_sequence;

  for (const ShardDescriptor& descriptor : manifest.shards) {
    const ShardIndex shard = descriptor.index;
    SyntheticCheckpointContent content(config_.content_seed, shard);
    std::uint64_t sent = 0;
    std::uint64_t drop_after =
        config_.truncate_first_shard && shard.value() == 0 ? descriptor.declared_bytes / 2 : 0;
    bool shard_truncated = false;
    bool began = false;

    while (sent < descriptor.declared_bytes) {
      if (stop.stop_requested()) {
        result.exit_code = 5;
        result.message = "stop requested before the transfer completed";
        return result;
      }
      if (drop_after > 0 && sent >= drop_after) {
        // Never request credit that will not be used: an unused grant would
        // leave outstanding authority that no evidence can settle.
        shard_truncated = true;
        break;
      }
      Result<WaveOutcome> outcome = client.request_wave(session, shard, fence);
      if (!outcome.ok()) {
        result.exit_code = 4;
        result.message = "wave request failed: " + outcome.status().to_string();
        return result;
      }
      if (!outcome.value().granted) {
        ++result.deferred_grants;
        if (result.deferred_grants > config_.max_credit_wait_iterations) {
          result.exit_code = 6;
          result.message = "credit never became available";
          return result;
        }
        const Nanos retry =
            outcome.value().retry_after.value_or(clock_->now() + kNanosPerMillisecond);
        sleep_until(retry, *clock_, stop);
        continue;
      }
      const WaveGrant& grant = outcome.value().grant.value();
      const std::uint64_t remaining = descriptor.declared_bytes - sent;
      std::uint64_t chunk = std::min<std::uint64_t>(remaining, grant.max_bytes);
      if (drop_after > 0 && sent + chunk > drop_after) {
        chunk = drop_after > sent ? drop_after - sent : 0;
      }
      if (chunk == 0) {
        shard_truncated = true;
        break;
      }
      const std::size_t amount = static_cast<std::size_t>(
          std::min<std::uint64_t>(chunk, static_cast<std::uint64_t>(buffer.size())));
      content.fill(sent, MutableByteSpan(buffer.data(), amount));

      if (!began) {
        wire::ShardBeginPayload begin;
        begin.session = session;
        begin.attempt = grant.attempt;
        begin.sequence = grant.sequence;
        begin.checkpoint = config_.checkpoint;
        begin.checkpoint_generation = config_.checkpoint_generation;
        begin.workload = config_.workload;
        begin.shard = shard;
        begin.declared_bytes = descriptor.declared_bytes;
        begin.declared_digest = descriptor.declared_digest;
        const Bytes payload = wire::encode_payload(begin);
        const Status begin_status = sink_channel.send(wire::MessageType::ShardBegin,
                                                      ByteSpan(payload.data(), payload.size()));
        if (!begin_status.ok()) {
          result.exit_code = 4;
          result.message = "cannot begin the shard: " + begin_status.to_string();
          return result;
        }
        began = true;
      }

      wire::ShardDataPayload data;
      data.attempt = grant.attempt;
      data.sequence = grant.sequence;
      data.offset = sent;
      data.data.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(amount));
      const Bytes data_payload = wire::encode_payload(data);
      const Status data_status = sink_channel.send(wire::MessageType::ShardData,
                                                   ByteSpan(data_payload.data(), data_payload.size()));
      if (!data_status.ok()) {
        result.exit_code = 4;
        result.message = "sink write failed: " + data_status.to_string();
        return result;
      }
      Result<wire::Message> ack_message = sink_channel.receive();
      if (!ack_message.ok()) {
        result.exit_code = 4;
        result.message = "sink acknowledgement missing: " + ack_message.status().to_string();
        return result;
      }
      if (ack_message.value().type != wire::MessageType::ShardAck) {
        result.exit_code = 4;
        result.message = "sink answered with an unexpected message";
        return result;
      }
      Result<wire::ShardAckPayload> ack = wire::decode_payload<wire::ShardAckPayload>(
          ByteSpan(ack_message.value().payload.data(), ack_message.value().payload.size()),
          config_.limits);
      if (!ack.ok()) {
        result.exit_code = 4;
        result.message = "sink acknowledgement was malformed: " + ack.status().to_string();
        return result;
      }
      if (ack.value().bytes_received != sent + amount) {
        result.exit_code = 4;
        result.message = "sink acknowledged a different cumulative byte count than was sent";
        return result;
      }

      DigestBuilder chunk_digest;
      chunk_digest.update(ByteSpan(buffer.data(), amount));
      TransferEvidence evidence;
      evidence.session = session;
      evidence.attempt = grant.attempt;
      evidence.sequence = grant.sequence;
      evidence.shard = shard;
      evidence.arrived_bytes = amount;
      evidence.arrived_digest = chunk_digest.finish();
      evidence.sink_acknowledged = true;
      const Status reported = client.report_transfer(evidence, fence);
      if (!reported.ok()) {
        result.exit_code = 4;
        result.message = "transfer evidence refused: " + reported.to_string();
        return result;
      }
      last_attempt = grant.attempt;
      last_sequence = grant.sequence;
      sent += amount;
      result.bytes_sent += amount;
      if (config_.die_after_bytes != 0 && result.bytes_sent >= config_.die_after_bytes) {
        died = true;
        break;
      }
    }

    if (died) {
      break;
    }

    wire::ShardEndPayload end;
    end.bytes_sent = sent;
    DigestBuilder shard_digest;
    std::uint64_t offset = 0;
    while (offset < sent) {
      const std::size_t chunk =
          static_cast<std::size_t>(std::min<std::uint64_t>(sent - offset, buffer.size()));
      content.fill(offset, MutableByteSpan(buffer.data(), chunk));
      shard_digest.update(ByteSpan(buffer.data(), chunk));
      offset += chunk;
    }
    end.sent_digest = shard_digest.finish();
    end.truncated = shard_truncated || sent < descriptor.declared_bytes;

    // Source-complete evidence is reported before the shard is closed: the
    // fabric must never observe a verified shard whose source never declared
    // itself finished, and evidence is refused once a session is terminal.
    if (!last_attempt.is_nil()) {
      SourceCompleteEvidence source;
      source.session = session;
      source.attempt = last_attempt;
      source.sequence = last_sequence;
      source.wave = WaveIndex(0);
      source.shard = shard;
      source.source_bytes = sent;
      source.source_digest = end.sent_digest;
      const Status source_status = client.report_source_complete(source, fence);
      if (!source_status.ok()) {
        result.exit_code = 4;
        result.message = "source-complete evidence refused: " + source_status.to_string();
        return result;
      }
    }

    const Bytes end_payload = wire::encode_payload(end);
    const Status end_status = sink_channel.send(wire::MessageType::ShardEnd,
                                                ByteSpan(end_payload.data(), end_payload.size()));
    if (!end_status.ok()) {
      result.exit_code = 4;
      result.message = "cannot finish the shard: " + end_status.to_string();
      return result;
    }
    Result<wire::Message> final_ack = sink_channel.receive();
    if (!final_ack.ok()) {
      result.exit_code = 4;
      result.message = "sink did not answer the shard end: " + final_ack.status().to_string();
      return result;
    }

    if (end.truncated) {
      truncated = true;
    } else {
      ++result.shards_completed;
    }
  }

  if (died) {
    result.exit_code = 9;
    result.message =
        "sender died after " + std::to_string(result.bytes_sent) + " bytes (injected sender death)";
    return result;
  }
  result.exit_code = truncated ? 8 : 0;
  result.message = truncated ? "transfer truncated (injected)" : "checkpoint traffic delivered";
  (void)client.close();
  (void)sink_channel.close();
  return result;
}

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

CheckpointSink::CheckpointSink(SinkConfig config, const Clock& clock)
    : config_(std::move(config)), clock_(&clock), limits_(config_.limits) {}

Status CheckpointSink::start(net::StopToken stop) {
  (void)stop;
  Result<net::TcpListener> listener =
      net::TcpListener::bind(config_.bind_host, config_.port, 16);
  if (!listener.ok()) {
    return listener.status();
  }
  listener_ = std::move(listener).value();
  return Status::success();
}

Result<SinkResult> CheckpointSink::run(net::StopToken stop) {
  SinkResult result;
  if (config_.directory.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "sink requires a destination directory");
  }
  std::error_code error;
  std::filesystem::create_directories(config_.directory, error);
  if (error) {
    return Status::error(ErrorCode::IoFailure, "cannot create sink directory: " + error.message());
  }
  Result<CoordinatorClient> client_result =
      connect_client(config_.coordinator_host, config_.coordinator_port, wire::ClientKind::Sink,
                     config_.identity, limits_, stop, 200);
  if (!client_result.ok()) {
    return client_result.status();
  }
  CoordinatorClient& client = client_result.value();

  while (!stop.stop_requested()) {
    if (config_.expected_shards != 0 && result.shards_received >= config_.expected_shards) {
      break;
    }
    Result<net::TcpSocket> accepted = listener_.accept(stop);
    if (!accepted.ok()) {
      if (stop.stop_requested() || accepted.code() == ErrorCode::ShuttingDown) {
        break;
      }
      continue;
    }
    wire::MessageChannel channel(std::move(accepted).value(), stop);

    bool active = false;
    wire::ShardBeginPayload begin;
    DigestBuilder digest;
    std::uint64_t received = 0;
    std::ofstream file;
    TransferAttemptId last_attempt;
    AttemptSequence last_sequence;
    bool connection_died = false;

    for (;;) {
      Result<wire::Message> message = channel.receive();
      if (!message.ok()) {
        break;  // peer closed or the connection failed mid-transfer
      }
      if (message.value().type == wire::MessageType::ShardBegin) {
        Result<wire::ShardBeginPayload> decoded = wire::decode_payload<wire::ShardBeginPayload>(
            ByteSpan(message.value().payload.data(), message.value().payload.size()), limits_);
        if (!decoded.ok()) {
          break;
        }
        begin = decoded.value();
        digest.reset();
        received = 0;
        last_attempt = begin.attempt;
        last_sequence = begin.sequence;
        active = true;
        const std::string name = begin.session.to_string() + "-shard-" +
                                 begin.shard.to_string() + ".bin";
        file.close();
        file.open(config_.directory / name, std::ios::binary | std::ios::trunc);
        if (!file) {
          return Status::error(ErrorCode::IoFailure, "cannot open the sink destination file");
        }
        continue;
      }
      if (message.value().type == wire::MessageType::ShardData) {
        Result<wire::ShardDataPayload> decoded = wire::decode_payload<wire::ShardDataPayload>(
            ByteSpan(message.value().payload.data(), message.value().payload.size()), limits_);
        if (!decoded.ok() || !active) {
          break;
        }
        if (decoded.value().offset != received) {
          break;  // non-sequential data is refused rather than stitched together
        }
        file.write(reinterpret_cast<const char*>(decoded.value().data.data()),
                   static_cast<std::streamsize>(decoded.value().data.size()));
        if (!file) {
          return Status::error(ErrorCode::IoFailure, "sink destination write failed");
        }
        digest.update(ByteSpan(decoded.value().data.data(), decoded.value().data.size()));
        received += decoded.value().data.size();
        result.bytes_received += decoded.value().data.size();
        last_attempt = decoded.value().attempt;
        last_sequence = decoded.value().sequence;
        if (config_.die_after_bytes != 0 && result.bytes_received >= config_.die_after_bytes) {
          result.exit_code = 9;
          result.message = "sink died after " + std::to_string(result.bytes_received) +
                           " bytes before acknowledging (injected sink death)";
          connection_died = true;
          break;
        }
        wire::ShardAckPayload ack;
        ack.bytes_received = received;
        ack.verified = false;
        ack.truncated = false;
        ack.received_digest = digest.finish();
        ack.detail = "chunk accepted";
        const Bytes payload = wire::encode_payload(ack);
        const Status sent =
            channel.send(wire::MessageType::ShardAck, ByteSpan(payload.data(), payload.size()));
        if (!sent.ok()) {
          break;
        }
        continue;
      }
      if (message.value().type == wire::MessageType::ShardEnd) {
        Result<wire::ShardEndPayload> decoded = wire::decode_payload<wire::ShardEndPayload>(
            ByteSpan(message.value().payload.data(), message.value().payload.size()), limits_);
        if (!decoded.ok() || !active) {
          break;
        }
        file.flush();
        file.close();
        const Digest observed = digest.finish();
        VerificationEvidence::Outcome outcome = VerificationEvidence::Outcome::Verified;
        if (decoded.value().truncated || received != begin.declared_bytes) {
          outcome = VerificationEvidence::Outcome::Truncated;
        } else if (!(decoded.value().sent_digest == observed)) {
          outcome = VerificationEvidence::Outcome::DigestMismatch;
        } else if (!begin.declared_digest.is_zero() && !(begin.declared_digest == observed)) {
          outcome = VerificationEvidence::Outcome::DigestMismatch;
        } else if (!config_.verify) {
          outcome = VerificationEvidence::Outcome::Ambiguous;
        }
        wire::ShardAckPayload ack;
        ack.bytes_received = received;
        ack.verified = outcome == VerificationEvidence::Outcome::Verified;
        ack.truncated = outcome == VerificationEvidence::Outcome::Truncated;
        ack.received_digest = observed;
        ack.detail = to_string(outcome);
        const Bytes payload = wire::encode_payload(ack);
        const Status sent =
            channel.send(wire::MessageType::ShardAck, ByteSpan(payload.data(), payload.size()));
        if (!sent.ok()) {
          break;
        }
        ++result.shards_received;
        switch (outcome) {
          case VerificationEvidence::Outcome::Verified:
            ++result.shards_verified;
            break;
          case VerificationEvidence::Outcome::Truncated:
            ++result.shards_truncated;
            break;
          case VerificationEvidence::Outcome::DigestMismatch:
            ++result.shards_mismatched;
            break;
          case VerificationEvidence::Outcome::Ambiguous:
          case VerificationEvidence::Outcome::Rejected:
            break;
        }
        // Destination verification is reported by the sink itself, bound to the
        // attempt that actually delivered the bytes.
        VerificationEvidence evidence;
        evidence.session = begin.session;
        evidence.attempt = last_attempt;
        evidence.sequence = last_sequence;
        evidence.shard = begin.shard;
        evidence.verified_bytes = received;
        evidence.verified_digest = observed;
        evidence.outcome = outcome;
        evidence.observed_at = clock_->now();
        const CommandFence fence =
            client.current_fence(begin.workload, begin.checkpoint_generation);
        const Status reported = client.report_verification(evidence, fence);
        if (!reported.ok()) {
          result.message = "verification was refused: " + reported.to_string();
        }
        active = false;
        continue;
      }
      // Anything else on a transfer channel is a protocol violation.
      break;
    }
    file.close();
    (void)channel.close();
    if (connection_died) {
      return result;
    }
  }
  (void)client.close();
  if (result.exit_code == 0) {
    result.message = "sink completed " + std::to_string(result.shards_received) + " shard(s)";
  }
  return result;
}

}  // namespace ctf
