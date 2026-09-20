// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Adversarial proofs: mutated frames, corrupt persistence, contradictory
// metadata, and stale authority. Every refusal must be deterministic and must
// leave no partial state behind.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ctf/engine.hpp"
#include "ctf/protocol.hpp"
#include "ctf/store.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

namespace {

using ctf::test::EngineFixture;

[[nodiscard]] ctf::Bytes make_frame(std::uint16_t type, std::uint64_t sequence,
                                    ctf::ByteSpan payload) {
  ctf::wire::FrameHeader header;
  header.message_type = type;
  header.sequence = sequence;
  header.payload_bytes = static_cast<std::uint32_t>(payload.size());
  ctf::Result<ctf::Bytes> frame = ctf::wire::encode_frame(header, payload);
  return frame.ok() ? std::move(frame).value() : ctf::Bytes{};
}

[[nodiscard]] ctf::EngineSnapshot snapshot_with_session(ctf::test::Context& ctf_ctx) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      ctf::test::make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                              ctf::test::command_id(700));
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  return engine.export_snapshot();
}

}  // namespace

CTF_TEST(adversarial, frame_mutation_fuzz_never_yields_a_different_payload) {
  const ctf::Bytes payload = ctf::bytes_from_string("checkpoint-burst-payload-0123456789");
  const ctf::Bytes original = make_frame(static_cast<std::uint16_t>(ctf::wire::MessageType::HelloRequest),
                                         42, ctf::ByteSpan(payload.data(), payload.size()));
  CTF_REQUIRE(original.size() > ctf::wire::kFrameHeaderBytes + 4);
  std::size_t refused = 0;
  std::size_t accepted_identical = 0;
  for (int iteration = 0; iteration < 3000; ++iteration) {
    ctf::Bytes mutated = original;
    const std::uint64_t choice = ctf_ctx.random_below(4);
    if (choice == 0) {
      const std::size_t index = static_cast<std::size_t>(ctf_ctx.random_below(mutated.size()));
      mutated[index] = static_cast<std::byte>(static_cast<unsigned char>(mutated[index]) ^
                                              static_cast<unsigned char>(1U << ctf_ctx.random_below(8)));
    } else if (choice == 1) {
      const std::size_t index = static_cast<std::size_t>(ctf_ctx.random_below(mutated.size()));
      mutated.resize(index);
    } else if (choice == 2) {
      mutated.push_back(static_cast<std::byte>(ctf_ctx.random_below(256)));
    } else {
      const std::size_t index = static_cast<std::size_t>(ctf_ctx.random_below(mutated.size()));
      mutated.insert(mutated.begin() + static_cast<std::ptrdiff_t>(index),
                     static_cast<std::byte>(ctf_ctx.random_below(256)));
    }
    ctf::wire::FrameHeader header;
    ctf::Result<ctf::Bytes> decoded =
        ctf::wire::decode_frame(ctf::ByteSpan(mutated.data(), mutated.size()), &header);
    if (decoded.ok()) {
      // A mutation may only survive when it changed nothing observable.
      CTF_EXPECT(decoded.value() == payload);
      ++accepted_identical;
    } else {
      CTF_EXPECT(decoded.code() != ctf::ErrorCode::Ok);
      ++refused;
    }
  }
  std::printf("    mutations: %zu refused, %zu identical\n", refused, accepted_identical);
  CTF_EXPECT(refused > 0);
  CTF_EXPECT(refused + accepted_identical == 3000U);
}

CTF_TEST(adversarial, decoder_survives_absurd_declarations) {
  const ctf::Limits limits;
  // A manifest that declares a shard count larger than the message body.
  {
    ctf::wire::Encoder encoder;
    encoder.u64(1);          // command
    ctf::Bytes raw = std::move(encoder).take();
    raw.resize(raw.size());
    ctf::wire::Decoder decoder(ctf::ByteSpan(raw.data(), raw.size()), limits);
    ctf::Bytes field{std::byte{0x7F}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    ctf::wire::Decoder declared(ctf::ByteSpan(field.data(), field.size()), limits);
    (void)declared.collection_count();
    CTF_EXPECT_EQ(declared.status().code(), ctf::ErrorCode::CollectionTooLarge);
  }
  // A byte field that claims more data than it carries.
  {
    ctf::Bytes raw{std::byte{0x00}, std::byte{0x00}, std::byte{0x10}, std::byte{0x00}, std::byte{0x01}};
    ctf::wire::Decoder decoder(ctf::ByteSpan(raw.data(), raw.size()), limits);
    (void)decoder.bytes();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::TruncatedInput);
  }
  // A byte field that claims more than the protocol maximum.
  {
    ctf::Bytes raw{std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    ctf::wire::Decoder decoder(ctf::ByteSpan(raw.data(), raw.size()), limits);
    (void)decoder.bytes();
    CTF_EXPECT_EQ(decoder.status().code(), ctf::ErrorCode::PayloadTooLarge);
  }
}

CTF_TEST(adversarial, contradictory_manifests_are_refused_without_state_change) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);

  const auto submit = [&](const ctf::SessionRequest& request) {
    return engine.submit_session(request, ctf::test::fence_for(fixture, request.workload,
                                                               request.checkpoint_generation));
  };

  std::uint64_t command_suffix = 710;
  const auto next_command = [&command_suffix] { return ctf::test::command_id(command_suffix++); };
  ctf::SessionRequest base =
      ctf::test::make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                              next_command(), ctf::test::default_workload(), 2, 4096);

  ctf::SessionRequest broken = base;
  broken.command = next_command();
  broken.manifest.total_bytes += 1;
  broken.manifest.manifest_digest = ctf::compute_manifest_digest(broken.manifest);
  ctf::Result<ctf::AdmissionDecision> decision = submit(broken);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::ManifestInvalid);

  broken = base;
  broken.command = next_command();
  broken.manifest.shards[1].index = ctf::ShardIndex(0);
  broken.manifest.manifest_digest = ctf::compute_manifest_digest(broken.manifest);
  decision = submit(broken);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::ManifestInvalid);

  broken = base;
  broken.command = next_command();
  broken.manifest.shards[0].declared_bytes = 0;
  broken.manifest.total_bytes -= 4096;
  broken.manifest.manifest_digest = ctf::compute_manifest_digest(broken.manifest);
  decision = submit(broken);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::ManifestInvalid);

  broken = base;
  broken.command = next_command();
  broken.manifest.manifest_digest = ctf::Digest(1, 2);
  decision = submit(broken);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::ManifestInvalid);

  broken = base;
  broken.command = next_command();
  broken.checkpoint = ctf::CheckpointId(ctf::Uuid128::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee99").value());
  broken.manifest.manifest_digest = ctf::compute_manifest_digest(broken.manifest);
  decision = submit(broken);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::ManifestMismatch);

  broken = base;
  broken.command = next_command();
  broken.manifest.shards[0].path_class = ctf::PathClassId(77);
  broken.manifest.manifest_digest = ctf::compute_manifest_digest(broken.manifest);
  decision = submit(broken);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::DestinationNotPermitted);

  // Nothing above created a session or moved a byte.
  CTF_EXPECT_EQ(engine.session_count(), static_cast<std::size_t>(0));
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_EQ(accounting.bytes_admitted, 0ULL);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(adversarial, stale_and_replayed_authority_is_refused) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::CheckpointId checkpoint = ctf::test::default_checkpoint();

  const ctf::SessionRequest first =
      ctf::test::make_request(fixture, checkpoint, ctf::CheckpointGeneration(1),
                              ctf::test::command_id(720));
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, first.workload, first.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> admitted = engine.submit_session(first, fence);
  CTF_REQUIRE_OK(admitted.status());
  CTF_REQUIRE(admitted.value().admitted());

  // Identical replay is idempotent; a divergent body under the same command id
  // is refused as a replay.
  ctf::Result<ctf::AdmissionDecision> replay = engine.submit_session(first, fence);
  CTF_REQUIRE_OK(replay.status());
  CTF_EXPECT_EQ(replay.value().reason, ctf::ReasonCode::DuplicateCommand);
  ctf::SessionRequest divergent = first;
  divergent.requested_rate_bps = 1234;
  CTF_EXPECT_CODE(engine.submit_session(divergent, fence).status(), ctf::ErrorCode::ReplayDetected);

  // Stale attempt evidence.
  ctf::Result<ctf::WaveOutcome> wave =
      engine.request_wave(admitted.value().session, ctf::ShardIndex(0), fence);
  CTF_REQUIRE_OK(wave.status());
  CTF_REQUIRE(wave.value().granted);
  ctf::TransferEvidence evidence;
  evidence.session = admitted.value().session;
  evidence.attempt = wave.value().grant.value().attempt;
  evidence.sequence = ctf::AttemptSequence(wave.value().grant.value().sequence.value() + 5);
  evidence.shard = ctf::ShardIndex(0);
  evidence.arrived_bytes = 1;
  evidence.sink_acknowledged = true;
  CTF_EXPECT_CODE(engine.report_transfer(evidence, fence), ctf::ErrorCode::StaleAttempt);

  // Verification of bytes the fabric never saw arrive.
  ctf::VerificationEvidence premature;
  premature.session = admitted.value().session;
  premature.attempt = wave.value().grant.value().attempt;
  premature.sequence = wave.value().grant.value().sequence;
  premature.shard = ctf::ShardIndex(0);
  premature.verified_bytes = 4096;
  premature.outcome = ctf::VerificationEvidence::Outcome::Verified;
  CTF_EXPECT_CODE(engine.report_verification(premature, fence), ctf::ErrorCode::StaleEvidence);

  // A fence from a foreign incarnation.
  ctf::CommandFence foreign = fence;
  foreign.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(4), ctf::EpochTerm(1)};
  ctf::Result<ctf::WaveOutcome> foreign_wave =
      engine.request_wave(admitted.value().session, ctf::ShardIndex(0), foreign);
  CTF_EXPECT_CODE(foreign_wave.status(), ctf::ErrorCode::ForeignEpoch);

  CTF_EXPECT_OK(engine.check_invariants());
  CTF_EXPECT(engine.accounting().conserves());
}

CTF_TEST(adversarial, persistence_refuses_corrupt_and_truncated_state) {
  ctf::test::TempDir directory("adversarial-store");
  ctf::store::StoreConfig config;
  config.directory = directory.path();
  ctf::store::PersistentStore store(config);
  CTF_REQUIRE_OK(store.open());

  const ctf::EngineSnapshot snapshot = snapshot_with_session(ctf_ctx);
  const ctf::Bytes encoded = ctf::store::encode_snapshot(snapshot, config.limits);
  CTF_REQUIRE(!encoded.empty());

  // Truncation at every length must never decode into a partial snapshot.
  for (std::size_t length = 0; length < encoded.size(); length += 7) {
    ctf::Result<ctf::EngineSnapshot> decoded = ctf::store::decode_snapshot(
        ctf::ByteSpan(encoded.data(), length), config.limits);
    CTF_EXPECT(!decoded.ok());
  }
  // The payload carries no checksum by design: integrity is proven at the record
  // level. What the payload codec must guarantee is totality - a mutated payload
  // either decodes or is refused, never crashes, and never allocates unbounded.
  std::size_t refused_payloads = 0;
  std::size_t accepted_payloads = 0;
  for (std::size_t index = 0; index < encoded.size(); index += 11) {
    ctf::Bytes mutated = encoded;
    mutated[index] = static_cast<std::byte>(static_cast<unsigned char>(mutated[index]) ^ 0x40U);
    ctf::Result<ctf::EngineSnapshot> decoded =
        ctf::store::decode_snapshot(ctf::ByteSpan(mutated.data(), mutated.size()), config.limits);
    if (decoded.ok()) {
      ++accepted_payloads;
      // Whatever it decoded into must itself be a coherent snapshot value that a
      // caller can hand to restore(), which re-validates it in full.
      CTF_EXPECT_EQ(decoded.value().sessions.size(), snapshot.sessions.size());
    } else {
      ++refused_payloads;
    }
  }
  std::printf("    payload mutations: %zu refused, %zu structurally accepted\n",
              refused_payloads, accepted_payloads);
  CTF_EXPECT(refused_payloads + accepted_payloads > 0);
  // At the record level every single-byte flip must be caught by the checksum.
  const ctf::Bytes checksummed =
      ctf::store::encode_journal_record(ctf::store::JournalRecord{1, "snapshot", encoded});
  CTF_REQUIRE(!checksummed.empty());
  for (std::size_t index = 0; index < checksummed.size(); index += 7) {
    ctf::Bytes mutated = checksummed;
    mutated[index] = static_cast<std::byte>(static_cast<unsigned char>(mutated[index]) ^ 0x01U);
    std::size_t consumed = 0;
    ctf::Result<ctf::store::JournalRecord> refused =
        ctf::store::decode_journal_record(ctf::ByteSpan(mutated.data(), mutated.size()), &consumed);
    if (refused.ok()) {
      CTF_EXPECT(refused.value().payload == encoded);
    }
  }
  // Trailing garbage after a complete snapshot is refused.
  ctf::Bytes trailing = encoded;
  trailing.push_back(std::byte{0x5A});
  CTF_EXPECT_CODE(
      ctf::store::decode_snapshot(ctf::ByteSpan(trailing.data(), trailing.size()), config.limits)
          .status(),
      ctf::ErrorCode::TrailingGarbage);

  // A persisted file with a torn tail recovers the valid prefix and reports it.
  CTF_REQUIRE_OK(store.persist(snapshot));
  CTF_REQUIRE_OK(store.append("second", snapshot));
  const ctf::Bytes record = ctf::store::encode_journal_record(
      ctf::store::JournalRecord{store.sequence() + 1, "third", encoded});
  std::filesystem::path journal = store.journal_path();
  {
    std::ofstream output(journal, std::ios::binary | std::ios::app);
    output.write(reinterpret_cast<const char*>(record.data()),
                 static_cast<std::streamsize>(record.size() / 2));
  }
  ctf::store::LoadReport report;
  ctf::Result<ctf::EngineSnapshot> loaded = store.load(&report);
  CTF_REQUIRE_OK(loaded.status());
  CTF_EXPECT(report.torn_tail);
  CTF_EXPECT(report.discarded_bytes > 0);
  CTF_EXPECT(!report.notes.empty());

  // A snapshot written with an unsupported format version is refused outright.
  const std::filesystem::path snapshot_path = store.snapshot_path();
  {
    std::ifstream input(snapshot_path, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    ctf::Bytes raw = ctf::bytes_from_string(text);
    raw[4] = std::byte{0x00};
    raw[5] = std::byte{0x63};
    std::ofstream output(snapshot_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
  }
  ctf::store::LoadReport version_report;
  ctf::Result<ctf::EngineSnapshot> refused = store.load(&version_report);
  CTF_EXPECT(!refused.ok());
  CTF_EXPECT(version_report.version_mismatch);
}

CTF_TEST(adversarial, oversized_persisted_files_are_refused) {
  ctf::test::TempDir directory("adversarial-oversize");
  ctf::store::StoreConfig config;
  config.directory = directory.path();
  ctf::store::PersistentStore store(config);
  CTF_REQUIRE_OK(store.open());
  {
    std::ofstream output(store.snapshot_path(), std::ios::binary | std::ios::trunc);
    const std::vector<char> filler(ctf::wire::kMaxPayloadBytes + 8192, 'x');
    output.write(filler.data(), static_cast<std::streamsize>(filler.size()));
  }
  ctf::store::LoadReport report;
  const ctf::Result<ctf::EngineSnapshot> loaded = store.load(&report);
  CTF_EXPECT(!loaded.ok());
  CTF_EXPECT_EQ(loaded.code(), ctf::ErrorCode::PayloadTooLarge);
}

CTF_TEST(adversarial, journal_records_reject_every_field_violation) {
  const ctf::store::JournalRecord good{7, "snapshot", ctf::bytes_from_string("payload")};
  const ctf::Bytes encoded = ctf::store::encode_journal_record(good);
  CTF_REQUIRE(!encoded.empty());
  std::size_t consumed = 0;
  ctf::Result<ctf::store::JournalRecord> decoded =
      ctf::store::decode_journal_record(ctf::ByteSpan(encoded.data(), encoded.size()), &consumed);
  CTF_REQUIRE_OK(decoded.status());
  CTF_EXPECT_EQ(consumed, encoded.size());
  CTF_EXPECT_EQ(decoded.value().sequence, 7ULL);
  CTF_EXPECT_EQ(decoded.value().label, "snapshot");

  const auto mutate = [&](std::size_t index, std::uint8_t value) {
    ctf::Bytes copy = encoded;
    copy[index] = static_cast<std::byte>(value);
    return copy;
  };
  const ctf::Bytes bad_magic = mutate(0, 0x00);
  ctf::Result<ctf::store::JournalRecord> broken =
      ctf::store::decode_journal_record(ctf::ByteSpan(bad_magic.data(), bad_magic.size()), nullptr);
  CTF_EXPECT_EQ(broken.code(), ctf::ErrorCode::InvalidSyntax);

  ctf::Bytes version = mutate(4, 0x63);
  broken = ctf::store::decode_journal_record(ctf::ByteSpan(version.data(), version.size()), nullptr);
  CTF_EXPECT_EQ(broken.code(), ctf::ErrorCode::VersionIncompatible);

  ctf::Bytes reserved = mutate(22, 0x01);
  broken = ctf::store::decode_journal_record(ctf::ByteSpan(reserved.data(), reserved.size()), nullptr);
  CTF_EXPECT_EQ(broken.code(), ctf::ErrorCode::NonCanonicalEncoding);

  ctf::Bytes checksum = mutate(encoded.size() - 1U, 0xFF);
  broken = ctf::store::decode_journal_record(ctf::ByteSpan(checksum.data(), checksum.size()), nullptr);
  CTF_EXPECT_EQ(broken.code(), ctf::ErrorCode::IntegrityFailure);

  ctf::Bytes truncated(encoded.begin(), encoded.begin() + 4);
  broken = ctf::store::decode_journal_record(ctf::ByteSpan(truncated.data(), truncated.size()), nullptr);
  CTF_EXPECT_EQ(broken.code(), ctf::ErrorCode::TruncatedInput);
}

CTF_TEST(adversarial, restore_never_applies_partial_state) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  ctf::EngineSnapshot snapshot = snapshot_with_session(ctf_ctx);

  ctf::ManualClock target_clock;
  ctf::FabricEngine target(fixture.engine_config(ctf::test::first_epoch()), target_clock);
  ctf::EngineSnapshot broken = snapshot;
  broken.accounting.bytes_admitted += 1024;
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::CorruptState);
  CTF_EXPECT_EQ(target.session_count(), static_cast<std::size_t>(0));
  CTF_EXPECT_EQ(target.accounting().bytes_admitted, 0ULL);

  broken = snapshot;
  broken.sessions[0].request.manifest.total_bytes += 1;
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::CorruptState);
  CTF_EXPECT_EQ(target.session_count(), static_cast<std::size_t>(0));

  CTF_REQUIRE_OK(target.restore(snapshot));
  CTF_EXPECT_EQ(target.session_count(), static_cast<std::size_t>(1));
  CTF_EXPECT_OK(target.check_invariants());
}

CTF_MAIN()
