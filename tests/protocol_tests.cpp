// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Protocol proofs: framing integrity, canonical decoding, and the real
// coordinator protocol over loopback TCP, including deliberate violations.

#include <array>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "ctf/client.hpp"
#include "ctf/protocol.hpp"
#include "ctf/report.hpp"
#include "ctf/service.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

namespace {

[[nodiscard]] ctf::Bytes make_frame(std::uint16_t type, std::uint64_t sequence,
                                    ctf::ByteSpan payload);

/// Raw framed channel used to drive the protocol by hand, so tests can send
/// frames a well-behaved client would never produce.
class RawChannel {
 public:
  RawChannel(ctf::test::Context& ctf_ctx, std::uint16_t port) : ctf_ctx_(&ctf_ctx) {
    ctf::Result<ctf::net::TcpSocket> socket =
        ctf::net::TcpSocket::connect("127.0.0.1", port, stop_);
    CTF_REQUIRE_OK(socket.status());
    socket_ = std::move(socket).value();
  }

  ctf::Status send(std::uint16_t type, std::uint64_t sequence, ctf::ByteSpan payload) {
    const ctf::Bytes frame = make_frame(type, sequence, payload);
    if (frame.empty()) {
      return ctf::Status::error(ctf::ErrorCode::Internal, "frame could not be encoded");
    }
    return send_raw(frame);
  }

  /// Sends a pre-built frame verbatim (bypasses the channel's sequence counter).
  ctf::Status send_raw(const ctf::Bytes& frame) {
    return socket_.write_all(ctf::ByteSpan(frame.data(), frame.size()), stop_);
  }

  /// Reads exactly one frame, enforcing the same sequence rule a real peer does.
  [[nodiscard]] ctf::Result<ctf::wire::Message> receive() {
    std::array<std::byte, ctf::wire::kFrameHeaderBytes> header_bytes{};
    if (!read_exactly(header_bytes)) {
      return ctf::Status::error(ctf::ErrorCode::PeerClosed, "connection closed while reading");
    }
    const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(header_bytes.data());
    std::uint32_t payload_bytes = 0;
    for (std::size_t i = 0; i < 4; ++i) {
      payload_bytes = (payload_bytes << 8) | raw[20 + i];
    }
    if (payload_bytes > ctf::wire::kMaxPayloadBytes) {
      return ctf::Status::error(ctf::ErrorCode::PayloadTooLarge, "peer declared an oversized frame");
    }
    ctf::Bytes frame(header_bytes.begin(), header_bytes.end());
    if (payload_bytes > 0) {
      const std::size_t offset = frame.size();
      frame.resize(offset + payload_bytes);
      if (!read_exactly(ctf::MutableByteSpan(frame.data() + offset, payload_bytes))) {
        return ctf::Status::error(ctf::ErrorCode::TruncatedInput, "frame payload was incomplete");
      }
    }
    ctf::wire::FrameHeader header;
    ctf::Result<ctf::Bytes> payload =
        ctf::wire::decode_frame(ctf::ByteSpan(frame.data(), frame.size()), &header);
    if (!payload.ok()) {
      return payload.status();
    }
    ctf::wire::Message message;
    message.type = static_cast<ctf::wire::MessageType>(header.message_type);
    message.sequence = header.sequence;
    message.payload = std::move(payload).value();
    return message;
  }

  void close() {
    (void)socket_.shutdown_both();
    socket_.close();
  }

 private:
  [[nodiscard]] bool read_exactly(ctf::MutableByteSpan buffer) {
    std::size_t filled = 0;
    while (filled < buffer.size()) {
      ctf::Result<std::size_t> read = socket_.read_some(buffer.subspan(filled), stop_);
      if (!read.ok() || read.value() == 0) {
        return false;
      }
      filled += read.value();
    }
    return true;
  }

  ctf::test::Context* ctf_ctx_;
  ctf::net::StopToken stop_;
  ctf::net::TcpSocket socket_;
};

[[nodiscard]] ctf::Bytes make_frame(std::uint16_t type, std::uint64_t sequence,
                                    ctf::ByteSpan payload) {
  ctf::wire::FrameHeader header;
  header.message_type = type;
  header.sequence = sequence;
  header.payload_bytes = static_cast<std::uint32_t>(payload.size());
  ctf::Result<ctf::Bytes> frame = ctf::wire::encode_frame(header, payload);
  return frame.ok() ? std::move(frame).value() : ctf::Bytes{};
}

class Service {
 public:
  explicit Service(ctf::test::Context& ctf_ctx) : service_(ctf::test::service_config(false, "protocol-test"), clock_) {
    CTF_REQUIRE_OK(service_.start());
  }
  ~Service() { (void)service_.shutdown(); }
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  [[nodiscard]] std::uint16_t port() const { return service_.port(); }
  [[nodiscard]] ctf::CoordinatorService& service() { return service_; }

 private:
  ctf::SteadyClock clock_;
  ctf::CoordinatorService service_;
};

}  // namespace

CTF_TEST(protocol, frame_round_trip_and_integrity) {
  const ctf::Bytes payload = ctf::bytes_from_string("checkpoint traffic fabric");
  ctf::Bytes frame = make_frame(static_cast<std::uint16_t>(ctf::wire::MessageType::QueryAccounting),
                                7, ctf::ByteSpan(payload.data(), payload.size()));
  CTF_REQUIRE(!frame.empty());
  CTF_EXPECT_EQ(frame.size(), ctf::wire::kFrameHeaderBytes + payload.size());

  ctf::wire::FrameHeader header;
  ctf::Result<ctf::Bytes> decoded =
      ctf::wire::decode_frame(ctf::ByteSpan(frame.data(), frame.size()), &header);
  CTF_REQUIRE_OK(decoded.status());
  CTF_EXPECT_EQ(header.sequence, 7ULL);
  CTF_EXPECT_EQ(header.message_type,
                static_cast<std::uint16_t>(ctf::wire::MessageType::QueryAccounting));
  CTF_EXPECT(decoded.value() == payload);

  const auto decode_status = [](const ctf::Bytes& raw) {
    return ctf::wire::decode_frame(ctf::ByteSpan(raw.data(), raw.size()), nullptr).status();
  };

  // Corrupt one header byte.
  ctf::Bytes corrupt = frame;
  corrupt[8] = static_cast<std::byte>(static_cast<unsigned char>(corrupt[8]) ^ 0xFFU);
  CTF_EXPECT_CODE(decode_status(corrupt), ctf::ErrorCode::IntegrityFailure);

  // Corrupt one payload byte.
  corrupt = frame;
  corrupt[ctf::wire::kFrameHeaderBytes + 3] =
      static_cast<std::byte>(static_cast<unsigned char>(corrupt[ctf::wire::kFrameHeaderBytes + 3]) ^ 0x01U);
  CTF_EXPECT_CODE(decode_status(corrupt), ctf::ErrorCode::IntegrityFailure);

  // Truncate the payload and the header.
  CTF_EXPECT_CODE(
      decode_status(ctf::Bytes(frame.begin(), frame.end() - 1)),
      ctf::ErrorCode::TruncatedInput);
  CTF_EXPECT_CODE(decode_status(ctf::Bytes(frame.begin(), frame.begin() + 8)),
                  ctf::ErrorCode::TruncatedInput);

  // Trailing bytes are refused, not ignored.
  ctf::Bytes trailing = frame;
  trailing.push_back(std::byte{0});
  CTF_EXPECT_CODE(decode_status(trailing), ctf::ErrorCode::TrailingGarbage);

  // Foreign magic and unsupported versions.
  ctf::Bytes magic = frame;
  magic[0] = std::byte{0x00};
  CTF_EXPECT_CODE(decode_status(magic), ctf::ErrorCode::InvalidSyntax);
  ctf::Bytes version = frame;
  version[4] = std::byte{0x00};
  version[5] = std::byte{0x63};
  CTF_EXPECT_CODE(decode_status(version), ctf::ErrorCode::VersionIncompatible);

  // A frame that declares an oversized payload is refused before allocation.
  ctf::wire::FrameHeader oversized;
  oversized.message_type = 1;
  oversized.sequence = 1;
  ctf::Bytes huge(ctf::wire::kMaxPayloadBytes + 1);
  CTF_EXPECT_CODE(ctf::wire::encode_frame(oversized, ctf::ByteSpan(huge.data(), huge.size())).status(),
                  ctf::ErrorCode::PayloadTooLarge);
}

CTF_TEST(protocol, decoder_rejects_non_canonical_input) {
  const ctf::Limits limits;
  const auto decode_with = [&](const ctf::Bytes& raw) {
    ctf::wire::Decoder decoder(ctf::ByteSpan(raw.data(), raw.size()), limits);
    return decoder;
  };

  // A boolean must be exactly 0 or 1.
  {
    ctf::Bytes raw{std::byte{2}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.boolean();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::NonCanonicalEncoding);
  }
  // Strings longer than the cap, and invalid UTF-8, are refused.
  {
    ctf::Bytes raw;
    raw.push_back(std::byte{0xFF});
    raw.push_back(std::byte{0xFF});
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.string();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::StringTooLong);
  }
  {
    ctf::Bytes raw{std::byte{0x00}, std::byte{0x02}, std::byte{0xC3}, std::byte{0x28}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.string();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::InvalidUtf8);
  }
  // Absurd collection counts are refused before any allocation.
  {
    ctf::Bytes raw{std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.collection_count();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::CollectionTooLarge);
  }
  {
    ctf::Bytes raw{std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x40}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.collection_count();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::TruncatedInput);
  }
  // Unknown enum values never silently become the first enumerator.
  {
    ctf::Bytes raw{std::byte{0x7F}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)ctf::wire::decode_enum<ctf::SessionState, &ctf::to_string>(decoder);
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::UnsupportedValue);
  }
  // Trailing garbage after a complete payload is refused.
  {
    ctf::Bytes raw{std::byte{0x01}, std::byte{0x00}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.u8();
    CTF_EXPECT_EQ(decoder.expect_end().code(), ctf::ErrorCode::TrailingGarbage);
  }
  // Truncation is a sticky failure: later reads cannot succeed.
  {
    ctf::Bytes raw{std::byte{0x01}};
    ctf::wire::Decoder decoder = decode_with(raw);
    (void)decoder.u64();
    CTF_EXPECT(!decoder.ok());
    (void)decoder.u8();
    CTF_EXPECT(!decoder.ok());
  }
}

CTF_TEST(protocol, loopback_handshake_queries_and_shutdown) {
  Service service(ctf_ctx);
  ctf::net::StopToken stop;
  ctf::ClientConfig config;
  config.host = "127.0.0.1";
  config.port = service.port();
  config.kind = ctf::wire::ClientKind::Operator;
  config.identity = "protocol-client";
  ctf::Result<ctf::CoordinatorClient> client = ctf::CoordinatorClient::connect(config, stop);
  CTF_REQUIRE_OK(client.status());

  const ctf::wire::HelloResponse& hello = client.value().hello();
  CTF_EXPECT_EQ(hello.epoch.incarnation.value(), 1ULL);
  CTF_EXPECT_EQ(hello.epoch.term.value(), 1ULL);
  CTF_EXPECT_EQ(hello.policy_generation.value(), service.service().engine().policy().generation.value());
  CTF_EXPECT_EQ(hello.topology_generation.value(),
                service.service().engine().topology().generation.value());
  CTF_EXPECT(!hello.contracts.empty());
  CTF_EXPECT(!hello.server_label.empty());

  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT_OK(client.value().check_invariants());
  ctf::Result<std::vector<ctf::SessionSummary>> sessions =
      client.value().list_sessions(std::nullopt, 16);
  CTF_REQUIRE_OK(sessions.status());
  CTF_EXPECT(sessions.value().empty());

  CTF_REQUIRE_OK(client.value().request_shutdown());
  CTF_EXPECT_OK(service.service().wait());
}

CTF_TEST(protocol, handshake_is_required_first) {
  Service service(ctf_ctx);
  RawChannel channel(ctf_ctx, service.port());
  const ctf::Bytes payload = ctf::wire::encode_payload(std::uint8_t{0});
  CTF_REQUIRE_OK(channel.send(static_cast<std::uint16_t>(ctf::wire::MessageType::QueryAccounting),
                              1, ctf::ByteSpan(payload.data(), payload.size())));
  ctf::Result<ctf::wire::Message> response = channel.receive();
  CTF_REQUIRE_OK(response.status());
  CTF_EXPECT_EQ(response.value().type, ctf::wire::MessageType::StatusResponse);
  ctf::Result<ctf::wire::StatusPayload> status = ctf::wire::decode_payload<ctf::wire::StatusPayload>(
      ctf::ByteSpan(response.value().payload.data(), response.value().payload.size()),
      service.service().engine().limits());
  CTF_REQUIRE_OK(status.status());
  CTF_EXPECT_EQ(status.value().code, ctf::ErrorCode::InvalidStateTransition);
  channel.close();

  // The service keeps serving after a protocol violation.
  ctf::net::StopToken stop;
  ctf::ClientConfig config;
  config.host = "127.0.0.1";
  config.port = service.port();
  config.identity = "protocol-after-violation";
  ctf::Result<ctf::CoordinatorClient> client = ctf::CoordinatorClient::connect(config, stop);
  CTF_REQUIRE_OK(client.status());
  CTF_EXPECT_OK(client.value().check_invariants());
  CTF_EXPECT(service.service().stats().protocol_errors > 0);
  CTF_REQUIRE_OK(client.value().request_shutdown());
  CTF_EXPECT_OK(service.service().wait());
}

CTF_TEST(protocol, sequence_replay_and_unknown_types_are_refused) {
  Service service(ctf_ctx);
  const ctf::Limits limits = service.service().engine().limits();

  {
    RawChannel channel(ctf_ctx, service.port());
    ctf::wire::HelloRequest hello;
    hello.kind = ctf::wire::ClientKind::Operator;
    hello.identity = "raw-client";
    const ctf::Bytes hello_payload = ctf::wire::encode_payload(hello);
    CTF_REQUIRE_OK(channel.send(static_cast<std::uint16_t>(ctf::wire::MessageType::HelloRequest), 1,
                                ctf::ByteSpan(hello_payload.data(), hello_payload.size())));
    ctf::Result<ctf::wire::Message> hello_response = channel.receive();
    CTF_REQUIRE_OK(hello_response.status());
    CTF_EXPECT_EQ(hello_response.value().type, ctf::wire::MessageType::HelloResponse);

    const ctf::Bytes query = ctf::wire::encode_payload(std::uint8_t{0});
    CTF_REQUIRE_OK(channel.send(static_cast<std::uint16_t>(ctf::wire::MessageType::QueryAccounting),
                                2, ctf::ByteSpan(query.data(), query.size())));
    ctf::Result<ctf::wire::Message> first = channel.receive();
    CTF_REQUIRE_OK(first.status());
    CTF_EXPECT_EQ(first.value().type, ctf::wire::MessageType::AccountingResponse);

    // A repeated sequence number on the same connection is a replay.
    CTF_REQUIRE_OK(channel.send(static_cast<std::uint16_t>(ctf::wire::MessageType::QueryAccounting),
                                2, ctf::ByteSpan(query.data(), query.size())));
    ctf::Result<ctf::wire::Message> refused = channel.receive();
    CTF_REQUIRE_OK(refused.status());
    CTF_EXPECT_EQ(refused.value().type, ctf::wire::MessageType::StatusResponse);
    ctf::Result<ctf::wire::StatusPayload> status =
        ctf::wire::decode_payload<ctf::wire::StatusPayload>(
            ctf::ByteSpan(refused.value().payload.data(), refused.value().payload.size()), limits);
    CTF_REQUIRE_OK(status.status());
    CTF_EXPECT_EQ(status.value().code, ctf::ErrorCode::SequenceViolation);
    channel.close();
  }

  {
    // An unknown message type is refused rather than ignored.
    RawChannel channel(ctf_ctx, service.port());
    ctf::wire::HelloRequest hello;
    hello.kind = ctf::wire::ClientKind::Operator;
    hello.identity = "raw-client-2";
    const ctf::Bytes hello_payload = ctf::wire::encode_payload(hello);
    CTF_REQUIRE_OK(channel.send(static_cast<std::uint16_t>(ctf::wire::MessageType::HelloRequest), 1,
                                ctf::ByteSpan(hello_payload.data(), hello_payload.size())));
    ctf::Result<ctf::wire::Message> hello_response = channel.receive();
    CTF_REQUIRE_OK(hello_response.status());
    const ctf::Bytes payload{std::byte{0}};
    CTF_REQUIRE_OK(channel.send(0x7FFFU, 2, ctf::ByteSpan(payload.data(), payload.size())));
    ctf::Result<ctf::wire::Message> refused = channel.receive();
    CTF_REQUIRE_OK(refused.status());
    CTF_EXPECT_EQ(refused.value().type, ctf::wire::MessageType::StatusResponse);
    ctf::Result<ctf::wire::StatusPayload> status =
        ctf::wire::decode_payload<ctf::wire::StatusPayload>(
            ctf::ByteSpan(refused.value().payload.data(), refused.value().payload.size()), limits);
    CTF_REQUIRE_OK(status.status());
    CTF_EXPECT_EQ(status.value().code, ctf::ErrorCode::UnknownMessageType);
    channel.close();
  }

  // A frame with a corrupt checksum is dropped without executing the request.
  {
    RawChannel channel(ctf_ctx, service.port());
    ctf::wire::HelloRequest hello;
    hello.kind = ctf::wire::ClientKind::Operator;
    hello.identity = "raw-client-3";
    const ctf::Bytes hello_payload = ctf::wire::encode_payload(hello);
    CTF_REQUIRE_OK(channel.send(static_cast<std::uint16_t>(ctf::wire::MessageType::HelloRequest), 1,
                                ctf::ByteSpan(hello_payload.data(), hello_payload.size())));
    ctf::Result<ctf::wire::Message> hello_response = channel.receive();
    CTF_REQUIRE_OK(hello_response.status());

    ctf::Bytes frame = make_frame(static_cast<std::uint16_t>(ctf::wire::MessageType::QueryInvariants),
                                  2, ctf::ByteSpan(hello_payload.data(), hello_payload.size()));
    frame[ctf::wire::kFrameHeaderBytes] = std::byte{0x7F};
    CTF_REQUIRE_OK(channel.send_raw(frame));
    ctf::Result<ctf::wire::Message> refused = channel.receive();
    CTF_REQUIRE_OK(refused.status());
    CTF_EXPECT_EQ(refused.value().type, ctf::wire::MessageType::StatusResponse);
    ctf::Result<ctf::wire::StatusPayload> status =
        ctf::wire::decode_payload<ctf::wire::StatusPayload>(
            ctf::ByteSpan(refused.value().payload.data(), refused.value().payload.size()), limits);
    CTF_REQUIRE_OK(status.status());
    CTF_EXPECT_EQ(status.value().code, ctf::ErrorCode::IntegrityFailure);
    channel.close();
  }
  CTF_EXPECT(!service.service().engine().shutting_down());
}

CTF_TEST(protocol, stale_authority_is_refused_over_the_wire) {
  Service service(ctf_ctx);
  ctf::net::StopToken stop;
  ctf::ClientConfig config;
  config.host = "127.0.0.1";
  config.port = service.port();
  config.kind = ctf::wire::ClientKind::Sender;
  config.identity = "protocol-sender";
  ctf::Result<ctf::CoordinatorClient> client = ctf::CoordinatorClient::connect(config, stop);
  CTF_REQUIRE_OK(client.status());

  const ctf::test::EngineFixture fixture = ctf::test::EngineFixture::make();
  ctf::SessionRequest request =
      ctf::test::make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                              ctf::test::command_id(900));
  // The live service uses its own default policy; reuse the client's view.
  request.policy_generation = client.value().hello().policy_generation;
  request.topology_generation = client.value().hello().topology_generation;
  request.contract_generation = ctf::WorkloadContractGeneration(1);
  request.workload = ctf::test::default_workload();
  request.manifest.workload = request.workload;
  request.manifest.contract_generation = request.contract_generation;
  request.manifest.checkpoint = request.checkpoint;
  request.manifest.generation = request.checkpoint_generation;
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  request.destination = ctf::DestinationClass::SyntheticLab;

  ctf::CommandFence stale = client.value().current_fence(request.workload, request.checkpoint_generation);
  stale.policy_generation = ctf::PolicyGeneration(stale.policy_generation.value() + 5);
  const ctf::Status refused = client.value().submit_session(request, stale).status();
  CTF_EXPECT_EQ(refused.code(), ctf::ErrorCode::NotAuthorized);

  ctf::CommandFence older = client.value().current_fence(request.workload, request.checkpoint_generation);
  older.topology_generation = ctf::TopologyGeneration(older.topology_generation.value() - 1);
  const ctf::Status stale_topology = client.value().submit_session(request, older).status();
  CTF_EXPECT_EQ(stale_topology.code(), ctf::ErrorCode::StaleTopologyGeneration);

  request.topology_generation = client.value().hello().topology_generation;
  ctf::CommandFence foreign = client.value().current_fence(request.workload, request.checkpoint_generation);
  foreign.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(9), ctf::EpochTerm(1)};
  const ctf::Status foreign_status = client.value().submit_session(request, foreign).status();
  CTF_EXPECT_EQ(foreign_status.code(), ctf::ErrorCode::ForeignEpoch);

  // Nothing was admitted by any of those refusals.
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT_EQ(accounting.value().sessions_admitted, 0ULL);
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT_OK(client.value().check_invariants());
  // This connection handshook as a sender, which may not request shutdown; the
  // operator shutdown path has its own test.
  CTF_EXPECT_EQ(client.value().request_shutdown().code(), ctf::ErrorCode::NotAuthorized);
  CTF_REQUIRE_OK(client.value().close());
  CTF_REQUIRE_OK(service.service().request_stop());
  CTF_EXPECT_OK(service.service().wait());
}

CTF_TEST(protocol, repeated_connect_and_disconnect_is_stable) {
  Service service(ctf_ctx);
  ctf::net::StopToken stop;
  for (int cycle = 0; cycle < 50; ++cycle) {
    ctf::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = service.port();
    config.kind = ctf::wire::ClientKind::Observer;
    config.identity = "protocol-cycle-" + std::to_string(cycle);
    ctf::Result<ctf::CoordinatorClient> client = ctf::CoordinatorClient::connect(config, stop);
    CTF_REQUIRE_OK(client.status());
    ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
    CTF_REQUIRE_OK(accounting.status());
    CTF_REQUIRE_OK(client.value().close());
  }
  CTF_EXPECT(service.service().stats().connections_accepted >= 50ULL);
  CTF_EXPECT_EQ(service.service().stats().connections_rejected, 0ULL);
  CTF_EXPECT_OK(service.service().engine().check_invariants());
  CTF_REQUIRE_OK(service.service().request_stop());
  CTF_EXPECT_OK(service.service().wait());
}

CTF_MAIN()
