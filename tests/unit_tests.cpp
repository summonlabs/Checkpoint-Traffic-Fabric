// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic unit proofs for identities, integrity, the domain model, the
// fence matrix, and the engine state machine.

#include <string>
#include <vector>

#include "ctf/engine.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

using ctf::test::EngineFixture;
using ctf::test::make_request;

namespace {

ctf::AdmissionDecision admit(ctf::test::Context& ctf_ctx, ctf::FabricEngine& engine,
                             const EngineFixture& fixture,
                             const ctf::SessionRequest& request) {
  const ctf::CommandFence fence = ctf::test::fence_for(fixture, request.workload,
                                                       request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  return decision.value();
}

/// Drives one shard to Verified through the public API.
void transfer_shard(ctf::test::Context& ctf_ctx, ctf::FabricEngine& engine,
                    const EngineFixture& fixture, ctf::SessionId session,
                    ctf::WorkloadId workload, ctf::CheckpointGeneration generation,
                    const ctf::ShardDescriptor& shard) {
  const ctf::CommandFence fence = ctf::test::fence_for(fixture, workload, generation);
  std::uint64_t sent = 0;
  while (sent < shard.declared_bytes) {
    ctf::Result<ctf::WaveOutcome> outcome = engine.request_wave(session, shard.index, fence);
    CTF_REQUIRE_OK(outcome.status());
    CTF_REQUIRE(outcome.value().granted);
    const ctf::WaveGrant& grant = outcome.value().grant.value();
    ctf::TransferEvidence transfer;
    transfer.session = session;
    transfer.attempt = grant.attempt;
    transfer.sequence = grant.sequence;
    transfer.shard = shard.index;
    transfer.arrived_bytes = grant.max_bytes;
    transfer.arrived_digest = shard.declared_digest;
    transfer.sink_acknowledged = true;
    CTF_REQUIRE_OK(engine.report_transfer(transfer, fence));
    ctf::VerificationEvidence verification;
    verification.session = session;
    verification.attempt = grant.attempt;
    verification.sequence = grant.sequence;
    verification.shard = shard.index;
    verification.verified_bytes = grant.max_bytes;
    verification.verified_digest = shard.declared_digest;
    verification.outcome = ctf::VerificationEvidence::Outcome::Verified;
    verification.verifier_identity = "unit-sink";
    CTF_REQUIRE_OK(engine.report_verification(verification, fence));
    sent += grant.max_bytes;
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

CTF_TEST(identities, uuid_round_trip) {
  const std::string text = "0f9c1f2e-4b3a-4c5d-8e7f-0123456789ab";
  const std::optional<ctf::Uuid128> parsed = ctf::Uuid128::parse(text);
  CTF_REQUIRE(parsed.has_value());
  CTF_EXPECT_EQ(parsed->to_string(), text);
  CTF_EXPECT(!parsed->is_nil());

  ctf::IdFactory factory(1234);
  const ctf::Uuid128 generated = ctf::Uuid128::random(factory);
  CTF_EXPECT_EQ(generated.to_string(), ctf::Uuid128::parse(generated.to_string()).value().to_string());
  CTF_EXPECT_EQ(static_cast<int>(generated.bytes()[6] >> 4), 4);   // version 4
  CTF_EXPECT_EQ(static_cast<int>(generated.bytes()[8] >> 6), 2);   // RFC 4122 variant
}

CTF_TEST(identities, uuid_rejects_non_canonical_text) {
  CTF_EXPECT(!ctf::Uuid128::parse("").has_value());
  CTF_EXPECT(!ctf::Uuid128::parse("0f9c1f2e4b3a4c5d8e7f0123456789ab").has_value());
  CTF_EXPECT(!ctf::Uuid128::parse("0F9C1F2E-4B3A-4C5D-8E7F-0123456789AB").has_value());
  CTF_EXPECT(!ctf::Uuid128::parse("0f9c1f2e-4b3a-4c5d-8e7f-0123456789a").has_value());
  CTF_EXPECT(!ctf::Uuid128::parse("0f9c1f2e_4b3a_4c5d_8e7f_0123456789ab").has_value());
  CTF_EXPECT(!ctf::Uuid128::parse("0f9c1f2e-4b3a-4c5d-8e7f-0123456789ag").has_value());
  CTF_EXPECT(!ctf::Uuid128::parse(" 0f9c1f2e-4b3a-4c5d-8e7f-0123456789ab").has_value());
}

CTF_TEST(identities, scalars_and_generations_are_canonical) {
  CTF_EXPECT(ctf::ShardIndex::parse("0").has_value());
  CTF_EXPECT(!ctf::ShardIndex::parse("00").has_value());
  CTF_EXPECT(!ctf::ShardIndex::parse("+1").has_value());
  CTF_EXPECT(!ctf::ShardIndex::parse("-1").has_value());
  CTF_EXPECT(!ctf::ShardIndex::parse("1 ").has_value());
  CTF_EXPECT(!ctf::ShardIndex::parse("4294967296").has_value());  // 2^32
  CTF_EXPECT(ctf::ShardIndex::parse("4294967295").has_value());
  CTF_EXPECT(ctf::ShardIndex::parse("7").value().to_string() == "7");

  ctf::CheckpointGeneration generation(1);
  CTF_EXPECT(generation.advance());
  CTF_EXPECT_EQ(generation.value(), 2ULL);
  CTF_EXPECT_EQ(generation.next().value(), 3ULL);
  ctf::CheckpointGeneration exhausted(0xFFFFFFFFFFFFFFFFULL);
  CTF_EXPECT(!exhausted.advance());
  CTF_EXPECT_EQ(exhausted.value(), 0xFFFFFFFFFFFFFFFFULL);
  CTF_EXPECT(ctf::CheckpointGeneration::parse("18446744073709551615").has_value());
  CTF_EXPECT(!ctf::CheckpointGeneration::parse("18446744073709551616").has_value());
}

CTF_TEST(identities, epoch_is_incarnation_and_term) {
  const ctf::CoordinatorEpoch epoch{ctf::IncarnationId(7), ctf::EpochTerm(3)};
  CTF_EXPECT_EQ(epoch.to_string(), "7.3");
  const std::optional<ctf::CoordinatorEpoch> parsed = ctf::CoordinatorEpoch::parse("7.3");
  CTF_REQUIRE(parsed.has_value());
  CTF_EXPECT(parsed.value() == epoch);
  CTF_EXPECT(!ctf::CoordinatorEpoch::parse("7").has_value());
  CTF_EXPECT(!ctf::CoordinatorEpoch::parse("7.").has_value());
  CTF_EXPECT(!ctf::CoordinatorEpoch::parse(".3").has_value());
  CTF_EXPECT(!ctf::CoordinatorEpoch::parse("7.3.1").has_value());
  const ctf::CoordinatorEpoch earlier{ctf::IncarnationId(1), ctf::EpochTerm(2)};
  const ctf::CoordinatorEpoch later{ctf::IncarnationId(2), ctf::EpochTerm(1)};
  CTF_EXPECT(earlier < later);
}

// ---------------------------------------------------------------------------
// Integrity primitives
// ---------------------------------------------------------------------------

CTF_TEST(integrity, checksum_known_vectors) {
  const std::string check = "123456789";
  const ctf::ByteSpan span(reinterpret_cast<const std::byte*>(check.data()), check.size());
  CTF_EXPECT_EQ(ctf::crc32c(span), 0xE3069283U);
  CTF_EXPECT_EQ(ctf::crc32c(ctf::ByteSpan{}), 0U);
  const std::string single = "a";
  const ctf::ByteSpan single_span(reinterpret_cast<const std::byte*>(single.data()), single.size());
  CTF_EXPECT_EQ(ctf::fnv1a64(single_span), 0xAF63DC4C8601EC8CULL);
  CTF_EXPECT_EQ(ctf::fnv1a64(ctf::ByteSpan{}), 0xCBF29CE484222325ULL);

  ctf::DigestBuilder builder;
  builder.update(span.subspan(0, 4));
  builder.update(span.subspan(4));
  CTF_EXPECT_EQ(builder.finish().crc32c_value(), ctf::crc32c(span));
  CTF_EXPECT_EQ(builder.finish().fnv1a64_value(), ctf::fnv1a64(span));
}

CTF_TEST(integrity, digest_text_round_trip) {
  const ctf::Digest digest(0xDEADBEEFU, 0x0123456789ABCDEFULL);
  const std::string text = digest.to_string();
  CTF_EXPECT_EQ(text.size(), static_cast<std::size_t>(24));
  const std::optional<ctf::Digest> parsed = ctf::Digest::parse(text);
  CTF_REQUIRE(parsed.has_value());
  CTF_EXPECT(parsed.value() == digest);
  CTF_EXPECT(!ctf::Digest::parse("short").has_value());
  CTF_EXPECT(!ctf::Digest::parse(text + "0").has_value());
  CTF_EXPECT(ctf::Digest::parse(std::string(24, 'z')).has_value() == false);
}

CTF_TEST(integrity, utf8_validation_is_strict) {
  const auto valid = [](const std::string& text) {
    return ctf::is_valid_utf8(ctf::ByteSpan(reinterpret_cast<const std::byte*>(text.data()),
                                            text.size()));
  };
  CTF_EXPECT(valid("plain ascii"));
  CTF_EXPECT(valid("\xC3\xA9"));                 // e-acute
  CTF_EXPECT(valid("\xE2\x82\xAC"));             // euro sign
  CTF_EXPECT(valid("\xF0\x9F\x98\x80"));         // emoji
  CTF_EXPECT(!valid("\xC0\xAF"));                // overlong
  CTF_EXPECT(!valid("\xE0\x80\x80"));            // overlong
  CTF_EXPECT(!valid("\xED\xA0\x80"));            // surrogate
  CTF_EXPECT(!valid("\xF5\x80\x80\x80"));        // above U+10FFFF
  CTF_EXPECT(!valid("\xC3"));                    // truncated
  CTF_EXPECT(!valid("\x80"));                    // stray continuation
}

CTF_TEST(integrity, hex_helpers) {
  const ctf::Bytes raw = ctf::bytes_from_string("CTF");
  CTF_EXPECT_EQ(ctf::hex_encode(ctf::ByteSpan(raw.data(), raw.size())), "435446");
  ctf::Result<ctf::Bytes> decoded = ctf::hex_decode("435446", 8);
  CTF_REQUIRE_OK(decoded.status());
  CTF_EXPECT_EQ(ctf::string_from_bytes(ctf::ByteSpan(decoded.value().data(), decoded.value().size())),
                "CTF");
  CTF_EXPECT(decoded.value().size() == raw.size());
  CTF_EXPECT_CODE(ctf::hex_decode("4", 8).status(), ctf::ErrorCode::InvalidSyntax);
  CTF_EXPECT_CODE(ctf::hex_decode("zz", 8).status(), ctf::ErrorCode::InvalidSyntax);
  CTF_EXPECT_CODE(ctf::hex_decode("41424344", 2).status(), ctf::ErrorCode::PayloadTooLarge);
}

// ---------------------------------------------------------------------------
// Manifest and configuration validation
// ---------------------------------------------------------------------------

CTF_TEST(model, manifest_validation_matrix) {
  const ctf::Limits limits;
  ctf::CheckpointManifest manifest;
  manifest.checkpoint = ctf::test::default_checkpoint();
  manifest.generation = ctf::CheckpointGeneration(1);
  manifest.workload = ctf::test::default_workload();
  manifest.contract_generation = ctf::WorkloadContractGeneration(5);
  ctf::ShardDescriptor first;
  first.index = ctf::ShardIndex(0);
  first.declared_bytes = 1024;
  ctf::ShardDescriptor second;
  second.index = ctf::ShardIndex(1);
  second.declared_bytes = 2048;
  manifest.shards = {first, second};
  manifest.total_bytes = 3072;
  manifest.manifest_digest = ctf::compute_manifest_digest(manifest);
  CTF_EXPECT_OK(ctf::validate_manifest(manifest, limits));

  ctf::CheckpointManifest tampered = manifest;
  tampered.total_bytes = 4096;
  CTF_EXPECT_CODE(ctf::validate_manifest(tampered, limits), ctf::ErrorCode::ImpossibleState);

  tampered = manifest;
  tampered.shards[1].index = ctf::ShardIndex(0);
  CTF_EXPECT_CODE(ctf::validate_manifest(tampered, limits), ctf::ErrorCode::InvalidArgument);

  tampered = manifest;
  tampered.shards[0].declared_bytes = 0;
  CTF_EXPECT_CODE(ctf::validate_manifest(tampered, limits), ctf::ErrorCode::InvalidArgument);

  tampered = manifest;
  tampered.shards[0].declared_digest = ctf::Digest(1, 2);
  CTF_EXPECT_CODE(ctf::validate_manifest(tampered, limits), ctf::ErrorCode::IntegrityFailure);

  tampered = manifest;
  tampered.shards.clear();
  CTF_EXPECT_CODE(ctf::validate_manifest(tampered, limits), ctf::ErrorCode::InvalidArgument);

  tampered = manifest;
  tampered.checkpoint = ctf::CheckpointId{};
  CTF_EXPECT_CODE(ctf::validate_manifest(tampered, limits), ctf::ErrorCode::MissingField);

  CTF_EXPECT(ctf::manifests_equivalent(manifest, manifest));
  ctf::CheckpointManifest other = manifest;
  other.generation = ctf::CheckpointGeneration(2);
  CTF_EXPECT(!ctf::manifests_equivalent(manifest, other));
  other = manifest;
  other.shards[1].declared_bytes = 4096;
  CTF_EXPECT(!ctf::manifests_equivalent(manifest, other));

  ctf::Limits tight = limits;
  tight.max_shards_per_checkpoint = 1;
  CTF_EXPECT_CODE(ctf::validate_manifest(manifest, tight), ctf::ErrorCode::CollectionTooLarge);
}

CTF_TEST(model, policy_topology_and_contract_validation) {
  const EngineFixture fixture = EngineFixture::make();
  const ctf::Limits limits;
  CTF_EXPECT_OK(ctf::validate_policy(fixture.policy, limits));
  CTF_EXPECT_OK(ctf::validate_topology(fixture.topology, limits));
  for (const ctf::WorkloadContract& contract : fixture.contracts) {
    CTF_EXPECT_OK(ctf::validate_contract(contract, limits));
  }

  ctf::PolicySnapshot policy = fixture.policy;
  policy.generation = ctf::PolicyGeneration(0);
  CTF_EXPECT_CODE(ctf::validate_policy(policy, limits), ctf::ErrorCode::OutOfRange);

  policy = fixture.policy;
  policy.envelopes.pop_back();
  CTF_EXPECT_CODE(ctf::validate_policy(policy, limits), ctf::ErrorCode::InvalidArgument);

  policy = fixture.policy;
  policy.envelopes[1] = policy.envelopes[0];
  CTF_EXPECT_CODE(ctf::validate_policy(policy, limits), ctf::ErrorCode::InvalidArgument);

  policy = fixture.policy;
  policy.envelopes[0].ceiling_bps = 0;
  CTF_EXPECT_CODE(ctf::validate_policy(policy, limits), ctf::ErrorCode::InvalidArgument);

  policy = fixture.policy;
  policy.max_wave_width = 4096;  // beyond the hard cap
  CTF_EXPECT_CODE(ctf::validate_policy(policy, limits), ctf::ErrorCode::OutOfRange);

  ctf::TopologySnapshot topology = fixture.topology;
  topology.generation = ctf::TopologyGeneration(0);
  CTF_EXPECT_CODE(ctf::validate_topology(topology, limits), ctf::ErrorCode::OutOfRange);

  topology = fixture.topology;
  topology.path_classes[1].id = topology.path_classes[0].id;
  CTF_EXPECT_CODE(ctf::validate_topology(topology, limits), ctf::ErrorCode::DuplicateIdentity);

  topology = fixture.topology;
  topology.path_classes[0].capacity_bps = 0;
  CTF_EXPECT_CODE(ctf::validate_topology(topology, limits), ctf::ErrorCode::InvalidArgument);

  topology = fixture.topology;
  topology.path_classes[0].id = ctf::PathClassId(0);
  CTF_EXPECT_CODE(ctf::validate_topology(topology, limits), ctf::ErrorCode::InvalidArgument);

  ctf::WorkloadContract contract = fixture.contracts[0];
  contract.floor_bps = contract.ceiling_bps + 1;
  CTF_EXPECT_CODE(ctf::validate_contract(contract, limits), ctf::ErrorCode::InvalidArgument);

  CTF_EXPECT(ctf::find_envelope(fixture.policy, ctf::IsolationClass::BestEffort) != nullptr);
  CTF_EXPECT(ctf::find_path_class(fixture.topology, ctf::PathClassId(2)) != nullptr);
  CTF_EXPECT(ctf::find_path_class(fixture.topology, ctf::PathClassId(9)) == nullptr);
  const std::optional<ctf::PathClassId> default_path =
      ctf::default_path_class_for(fixture.topology, ctf::DestinationClass::SyntheticLab);
  CTF_REQUIRE(default_path.has_value());
  CTF_EXPECT_EQ(default_path.value().value(), 1U);
}

CTF_TEST(model, session_state_predicates) {
  CTF_EXPECT(ctf::is_terminal(ctf::SessionState::TrafficSessionComplete));
  CTF_EXPECT(ctf::is_terminal(ctf::SessionState::Cancelled));
  CTF_EXPECT(ctf::is_terminal(ctf::SessionState::Superseded));
  CTF_EXPECT(ctf::is_terminal(ctf::SessionState::Failed));
  CTF_EXPECT(!ctf::is_terminal(ctf::SessionState::Transferred));
  CTF_EXPECT(!ctf::is_terminal(ctf::SessionState::RevalidationRequired));
  CTF_EXPECT(ctf::is_active(ctf::SessionState::Transferred));
  CTF_EXPECT_EQ(std::string(ctf::to_string(ctf::EvidenceLevel::VerifiedAtDestination)),
                "VerifiedAtDestination");
  CTF_EXPECT_EQ(std::string(ctf::to_string(ctf::DurabilityStatus::NotEstablished)),
                "NotEstablished");
  CTF_EXPECT(ctf::isolation_class_from_string("TrainingBulk").has_value());
  CTF_EXPECT(!ctf::isolation_class_from_string("trainingbulk").has_value());
  CTF_EXPECT(ctf::isolation_rank(ctf::IsolationClass::TrainingCritical) <
             ctf::isolation_rank(ctf::IsolationClass::BestEffort));
}

// ---------------------------------------------------------------------------
// Fencing
// ---------------------------------------------------------------------------

CTF_TEST(fence, matrix_is_exact) {
  const EngineFixture fixture = EngineFixture::make();
  const ctf::FenceContext context{ctf::test::first_epoch(), fixture.policy.generation,
                                  fixture.topology.generation,
                                  fixture.contracts[0].generation};
  ctf::CommandFence fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  CTF_EXPECT(ctf::validate_fence(fence, context).ok());

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(2), ctf::EpochTerm(1)};
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(), ctf::ErrorCode::ForeignEpoch);

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(0)};
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(), ctf::ErrorCode::StaleEpoch);

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(4)};
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(), ctf::ErrorCode::ForeignEpoch);

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.policy_generation = ctf::PolicyGeneration(1);
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(),
                ctf::ErrorCode::StalePolicyGeneration);

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.policy_generation = ctf::PolicyGeneration(9);
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(), ctf::ErrorCode::NotAuthorized);

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.topology_generation = ctf::TopologyGeneration(1);
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(),
                ctf::ErrorCode::StaleTopologyGeneration);

  fence = ctf::test::fence_for(fixture, ctf::test::default_workload());
  fence.contract_generation = ctf::WorkloadContractGeneration(1);
  CTF_EXPECT_EQ(ctf::validate_fence(fence, context).status.code(),
                ctf::ErrorCode::StaleContractGeneration);

  CTF_EXPECT(ctf::is_fencing_code(ctf::ErrorCode::StaleEpoch));
  CTF_EXPECT(ctf::is_fencing_code(ctf::ErrorCode::ReplayDetected));
  CTF_EXPECT(!ctf::is_fencing_code(ctf::ErrorCode::NotFound));
  CTF_EXPECT_EQ(ctf::reason_for_fence_code(ctf::ErrorCode::StaleEpoch),
                ctf::ReasonCode::AuthorityStale);
  CTF_EXPECT_EQ(ctf::reason_for_fence_code(ctf::ErrorCode::StaleAttempt),
                ctf::ReasonCode::AttemptStale);
}

// ---------------------------------------------------------------------------
// Engine: admission
// ---------------------------------------------------------------------------

CTF_TEST(engine, admission_grants_an_envelope_that_matches_policy) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  CTF_EXPECT_OK(engine.startup_status());

  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(1), ctf::test::default_workload(), 4, 32U * 1024U);
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT(decision.value().admitted());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::Admitted);
  CTF_REQUIRE(decision.value().envelope.has_value());
  const ctf::TrafficEnvelope& envelope = decision.value().envelope.value();
  CTF_EXPECT_EQ(envelope.isolation, ctf::IsolationClass::TrainingBulk);
  CTF_EXPECT(envelope.rate_bps <= 1U * 1024U * 1024U);
  CTF_EXPECT(envelope.rate_bps > 0);
  CTF_EXPECT_EQ(envelope.wave_width, 2U);
  CTF_EXPECT_EQ(envelope.waves.size(), static_cast<std::size_t>(2));
  CTF_EXPECT_EQ(envelope.waves[0].shards.size(), static_cast<std::size_t>(2));
  CTF_EXPECT_EQ(envelope.sequence.value(), 1ULL);
  CTF_EXPECT(decision.value().epoch == ctf::test::first_epoch());

  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.bytes_admitted, request.manifest.total_bytes);
  CTF_EXPECT_EQ(accounting.granted_outstanding_bytes, request.manifest.total_bytes);
  CTF_EXPECT_EQ(accounting.active_sessions, 1U);
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, admission_refusals_are_specific) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);

  // Unknown workload.
  ctf::WorkloadId unknown = ctf::test::second_workload();
  unknown = ctf::WorkloadId(ctf::Uuid128::parse("33333333-4444-4555-8666-777777777777").value());
  ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(10), unknown);
  ctf::CommandFence fence = ctf::test::fence_for(fixture, unknown);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().kind, ctf::DecisionKind::Deny);
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::UnknownWorkload);

  // Manifest identity contradicting the request.
  request = make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                         ctf::test::command_id(11));
  request.manifest.checkpoint = ctf::test::default_checkpoint();
  request.manifest.generation = ctf::CheckpointGeneration(2);
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  fence = ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::ManifestMismatch);

  // Unpermitted destination.
  request = make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                         ctf::test::command_id(12), ctf::test::default_workload(), 1, 4096,
                         ctf::IsolationClass::TrainingBulk, ctf::DestinationClass::PeerNodeMemory);
  fence = ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::DestinationNotPermitted);

  // Requesting more rate than the class ceiling allows.
  request = make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                         ctf::test::command_id(13), ctf::test::default_workload(), 1, 4096,
                         ctf::IsolationClass::TrainingBulk, ctf::DestinationClass::SyntheticLab,
                         64U * 1024U * 1024U);
  fence = ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::RequestedRateUnsupported);

  CTF_EXPECT_OK(engine.check_invariants());
  CTF_EXPECT_EQ(engine.accounting().active_sessions, 0U);
}

CTF_TEST(engine, admission_defers_at_session_bounds_and_retries_are_deterministic) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);

  // The fixture permits two in-flight sessions per workload.
  for (std::uint64_t index = 0; index < 2; ++index) {
    const ctf::CheckpointId checkpoint =
        ctf::CheckpointId(ctf::Uuid128::parse(index == 0
                                                  ? "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                                                  : "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeef")
                              .value());
    const ctf::SessionRequest request =
        make_request(fixture, checkpoint, ctf::CheckpointGeneration(1),
                     ctf::test::command_id(20 + index));
    const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
    CTF_EXPECT(decision.admitted());
  }
  const ctf::CheckpointId third =
      ctf::CheckpointId(ctf::Uuid128::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeed").value());
  const ctf::SessionRequest request =
      make_request(fixture, third, ctf::CheckpointGeneration(1), ctf::test::command_id(30));
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().kind, ctf::DecisionKind::Defer);
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::SessionLimitPerWorkload);
  CTF_REQUIRE(decision.value().retry_after.has_value());
  CTF_EXPECT(decision.value().retry_after.value() > clock.now());
  CTF_EXPECT_EQ(engine.accounting().sessions_deferred, 1ULL);
  CTF_EXPECT_EQ(engine.accounting().bytes_deferred, request.manifest.total_bytes);
  CTF_EXPECT_EQ(engine.accounting().active_sessions, 2U);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, idempotent_replay_and_divergent_replay) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(40));
  const ctf::AdmissionDecision first = admit(ctf_ctx, engine, fixture, request);
  CTF_EXPECT(first.admitted());

  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> replay = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(replay.status());
  CTF_EXPECT_EQ(replay.value().reason, ctf::ReasonCode::DuplicateCommand);
  CTF_EXPECT(replay.value().session == first.session);
  CTF_EXPECT_EQ(engine.accounting().sessions_admitted, 1ULL);

  ctf::SessionRequest divergent = request;
  divergent.requested_rate_bps = 4096;
  ctf::Result<ctf::AdmissionDecision> refused = engine.submit_session(divergent, fence);
  CTF_EXPECT_CODE(refused.status(), ctf::ErrorCode::ReplayDetected);

  // A different command id for the same checkpoint/generation is a duplicate too.
  ctf::SessionRequest duplicate = request;
  duplicate.command = ctf::test::command_id(41);
  ctf::Result<ctf::AdmissionDecision> second = engine.submit_session(duplicate, fence);
  CTF_REQUIRE_OK(second.status());
  CTF_EXPECT_EQ(second.value().reason, ctf::ReasonCode::DuplicateCommand);
  CTF_EXPECT_EQ(second.value().session, first.session);
  CTF_EXPECT_EQ(engine.accounting().sessions_admitted, 1ULL);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, supersession_is_deterministic_and_fences_the_older_generation) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::CheckpointId checkpoint = ctf::test::default_checkpoint();

  const ctf::SessionRequest older =
      make_request(fixture, checkpoint, ctf::CheckpointGeneration(1), ctf::test::command_id(50));
  const ctf::AdmissionDecision first = admit(ctf_ctx, engine, fixture, older);
  CTF_REQUIRE(first.admitted());

  const ctf::SessionRequest newer =
      make_request(fixture, checkpoint, ctf::CheckpointGeneration(2), ctf::test::command_id(51));
  const ctf::AdmissionDecision second = admit(ctf_ctx, engine, fixture, newer);
  CTF_REQUIRE(second.admitted());
  CTF_REQUIRE(second.superseded.size() == 1);
  CTF_EXPECT(second.superseded[0] == first.session);
  CTF_EXPECT_EQ(engine.accounting().sessions_superseded, 1ULL);

  ctf::Result<ctf::SessionView> view = engine.view_session(first.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Superseded);
  CTF_REQUIRE(view.value().superseded_by.has_value());
  CTF_EXPECT(view.value().superseded_by.value() == second.session);

  const ctf::CommandFence stale_fence =
      ctf::test::fence_for(fixture, older.workload, ctf::CheckpointGeneration(1));
  ctf::Result<ctf::WaveOutcome> stale = engine.request_wave(first.session, ctf::ShardIndex(0), stale_fence);
  CTF_EXPECT_CODE(stale.status(), ctf::ErrorCode::Superseded);

  // Re-submitting the superseded generation is refused.
  const ctf::SessionRequest regression =
      make_request(fixture, checkpoint, ctf::CheckpointGeneration(1), ctf::test::command_id(52));
  ctf::Result<ctf::AdmissionDecision> refused =
      engine.submit_session(regression, ctf::test::fence_for(fixture, regression.workload));
  CTF_REQUIRE_OK(refused.status());
  CTF_EXPECT_EQ(refused.value().reason, ctf::ReasonCode::CheckpointGenerationStale);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, supersession_denied_by_contract) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::WorkloadId workload = ctf::test::second_workload();
  const ctf::CheckpointId checkpoint =
      ctf::CheckpointId(ctf::Uuid128::parse("cccccccc-dddd-4eee-8fff-000000000001").value());

  const ctf::SessionRequest older =
      make_request(fixture, checkpoint, ctf::CheckpointGeneration(1), ctf::test::command_id(60),
                   workload, 1, 4096, ctf::IsolationClass::ServingLatency);
  CTF_EXPECT(admit(ctf_ctx, engine, fixture, older).admitted());

  const ctf::SessionRequest newer =
      make_request(fixture, checkpoint, ctf::CheckpointGeneration(2), ctf::test::command_id(61),
                   workload, 1, 4096, ctf::IsolationClass::ServingLatency);
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, workload, newer.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> refused = engine.submit_session(newer, fence);
  CTF_REQUIRE_OK(refused.status());
  CTF_EXPECT_EQ(refused.value().reason, ctf::ReasonCode::SupersessionDeniedByPolicy);
  CTF_EXPECT_OK(engine.check_invariants());
}

// ---------------------------------------------------------------------------
// Engine: lifecycle, evidence, accounting
// ---------------------------------------------------------------------------

CTF_TEST(engine, full_lifecycle_reaches_completion_with_separated_evidence) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(70), ctf::test::default_workload(), 3, 16U * 1024U);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::SessionId session = decision.session;

  ctf::Result<ctf::SessionView> view = engine.view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Admitted);
  CTF_EXPECT_EQ(view.value().evidence, ctf::EvidenceLevel::None);

  for (const ctf::ShardDescriptor& shard : request.manifest.shards) {
    transfer_shard(ctf_ctx, engine, fixture, session, request.workload,
                   request.checkpoint_generation, shard);
  }

  view = engine.view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().evidence, ctf::EvidenceLevel::VerifiedAtDestination);
  CTF_EXPECT_EQ(view.value().durability, ctf::DurabilityStatus::NotEstablished);
  CTF_EXPECT(!view.value().durable_checkpoint_success());
  CTF_EXPECT_EQ(view.value().verified_bytes, request.manifest.total_bytes);
  CTF_EXPECT_EQ(view.value().shards_verified, 3U);

  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.bytes_transferred, request.manifest.total_bytes);
  CTF_EXPECT_EQ(accounting.bytes_verified, request.manifest.total_bytes);
  CTF_EXPECT_EQ(accounting.bytes_wasted, 0ULL);
  CTF_EXPECT_EQ(accounting.sessions_completed, 1ULL);
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, transferred_is_not_complete_and_not_durable) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(80), ctf::test::default_workload(), 1, 8192);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);

  std::uint64_t sent = 0;
  while (sent < request.manifest.total_bytes) {
    ctf::Result<ctf::WaveOutcome> outcome =
        engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
    CTF_REQUIRE_OK(outcome.status());
    CTF_REQUIRE(outcome.value().granted);
    const ctf::WaveGrant& grant = outcome.value().grant.value();
    ctf::TransferEvidence transfer;
    transfer.session = decision.session;
    transfer.attempt = grant.attempt;
    transfer.sequence = grant.sequence;
    transfer.shard = ctf::ShardIndex(0);
    transfer.arrived_bytes = grant.max_bytes;
    transfer.sink_acknowledged = true;
    CTF_REQUIRE_OK(engine.report_transfer(transfer, fence));
    sent += grant.max_bytes;
  }

  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Transferred);
  CTF_EXPECT_EQ(view.value().evidence, ctf::EvidenceLevel::Transferred);
  CTF_EXPECT_EQ(view.value().durability, ctf::DurabilityStatus::NotEstablished);
  CTF_EXPECT(!view.value().durable_checkpoint_success());
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  CTF_EXPECT_EQ(view.value().transferred_bytes, request.manifest.total_bytes);
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.sessions_completed, 0ULL);
  CTF_EXPECT_EQ(accounting.active_sessions, 1U);
  CTF_EXPECT(accounting.conserves());

  // Durability cannot be asserted before destination evidence exists.
  ctf::DurabilityAssertion assertion;
  assertion.status = ctf::DurabilityStatus::ExternallyAsserted;
  assertion.backend_identity = "adjacent-store";
  CTF_EXPECT(engine.record_durability_assertion(decision.session, assertion, fence).ok());
  view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().durability, ctf::DurabilityStatus::ExternallyAsserted);
  CTF_EXPECT(!view.value().durable_checkpoint_success());
}

CTF_TEST(engine, verification_outcomes_are_explicit) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(90), ctf::test::default_workload(), 1, 8192);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  const ctf::ShardDescriptor& shard = request.manifest.shards[0];

  // Verification cannot claim success for bytes the fabric never saw arrive.
  ctf::Result<ctf::WaveOutcome> outcome =
      engine.request_wave(decision.session, shard.index, fence);
  CTF_REQUIRE_OK(outcome.status());
  CTF_REQUIRE(outcome.value().granted);
  const ctf::WaveGrant grant = outcome.value().grant.value();
  ctf::VerificationEvidence premature;
  premature.session = decision.session;
  premature.attempt = grant.attempt;
  premature.sequence = grant.sequence;
  premature.shard = shard.index;
  premature.verified_bytes = shard.declared_bytes;
  premature.outcome = ctf::VerificationEvidence::Outcome::Verified;
  CTF_EXPECT_CODE(engine.report_verification(premature, fence), ctf::ErrorCode::StaleEvidence);

  // Stale attempt evidence is refused.
  ctf::TransferEvidence stale;
  stale.session = decision.session;
  stale.attempt = ctf::TransferAttemptId(
      ctf::Uuid128::parse("12345678-1234-4123-8123-123456789012").value());
  stale.sequence = grant.sequence;
  stale.shard = shard.index;
  stale.arrived_bytes = 1;
  stale.sink_acknowledged = true;
  CTF_EXPECT_CODE(engine.report_transfer(stale, fence), ctf::ErrorCode::StaleAttempt);

  // More delivered bytes than were granted is impossible.
  ctf::TransferEvidence over;
  over.session = decision.session;
  over.attempt = grant.attempt;
  over.sequence = grant.sequence;
  over.shard = shard.index;
  over.arrived_bytes = grant.max_bytes + 1;
  over.sink_acknowledged = true;
  CTF_EXPECT_CODE(engine.report_transfer(over, fence), ctf::ErrorCode::ImpossibleState);

  // A digest mismatch fails the session and marks the bytes as wasted.
  ctf::TransferEvidence good;
  good.session = decision.session;
  good.attempt = grant.attempt;
  good.sequence = grant.sequence;
  good.shard = shard.index;
  good.arrived_bytes = grant.max_bytes;
  good.sink_acknowledged = true;
  CTF_REQUIRE_OK(engine.report_transfer(good, fence));
  ctf::VerificationEvidence mismatch;
  mismatch.session = decision.session;
  mismatch.attempt = grant.attempt;
  mismatch.sequence = grant.sequence;
  mismatch.shard = shard.index;
  mismatch.verified_bytes = shard.declared_bytes;
  mismatch.outcome = ctf::VerificationEvidence::Outcome::DigestMismatch;
  std::uint64_t verified = 0;
  while (verified < shard.declared_bytes) {
    if (verified > 0) {
      ctf::Result<ctf::WaveOutcome> next =
          engine.request_wave(decision.session, shard.index, fence);
      CTF_REQUIRE_OK(next.status());
      CTF_REQUIRE(next.value().granted);
      ctf::TransferEvidence more;
      more.session = decision.session;
      more.attempt = next.value().grant.value().attempt;
      more.sequence = next.value().grant.value().sequence;
      more.shard = shard.index;
      more.arrived_bytes = next.value().grant.value().max_bytes;
      more.sink_acknowledged = true;
      CTF_REQUIRE_OK(engine.report_transfer(more, fence));
      verified += next.value().grant.value().max_bytes;
    } else {
      verified += grant.max_bytes;
    }
  }
  CTF_REQUIRE_OK(engine.report_verification(mismatch, fence));
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Failed);
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.bytes_wasted > 0);
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, truncated_transfer_rearms_the_shard_and_cancel_closes_accounting) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(100), ctf::test::default_workload(), 1, 8192);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  const ctf::ShardDescriptor& shard = request.manifest.shards[0];

  ctf::Result<ctf::WaveOutcome> outcome =
      engine.request_wave(decision.session, shard.index, fence);
  CTF_REQUIRE_OK(outcome.status());
  const ctf::WaveGrant grant = outcome.value().grant.value();
  ctf::TransferEvidence partial;
  partial.session = decision.session;
  partial.attempt = grant.attempt;
  partial.sequence = grant.sequence;
  partial.shard = shard.index;
  partial.arrived_bytes = grant.max_bytes;
  partial.sink_acknowledged = true;
  CTF_REQUIRE_OK(engine.report_transfer(partial, fence));

  ctf::VerificationEvidence truncated;
  truncated.session = decision.session;
  truncated.attempt = grant.attempt;
  truncated.sequence = grant.sequence;
  truncated.shard = shard.index;
  truncated.verified_bytes = 0;
  truncated.outcome = ctf::VerificationEvidence::Outcome::Truncated;
  CTF_REQUIRE_OK(engine.report_verification(truncated, fence));
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Admitted);
  CTF_EXPECT_EQ(view.value().shards[0].state, ctf::ShardState::Pending);
  CTF_EXPECT(engine.accounting().bytes_wasted > 0);
  CTF_EXPECT(engine.accounting().bytes_admitted > request.manifest.total_bytes);
  CTF_EXPECT(engine.accounting().conserves());

  // The shard can be re-granted after the truncation.
  ctf::Result<ctf::WaveOutcome> regrant =
      engine.request_wave(decision.session, shard.index, fence);
  CTF_REQUIRE_OK(regrant.status());
  CTF_EXPECT(regrant.value().granted);

  // Cancelling closes accounting exactly.
  CTF_REQUIRE_OK(engine.cancel_session(decision.session, fence,
                                       ctf::ReasonCode::CancelledByOperator, "unit test"));
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_EQ(accounting.sessions_cancelled, 1ULL);
  CTF_EXPECT_OK(engine.check_invariants());

  // A cancelled session refuses further evidence and credit.
  ctf::Result<ctf::WaveOutcome> after =
      engine.request_wave(decision.session, shard.index, fence);
  CTF_EXPECT_CODE(after.status(), ctf::ErrorCode::InvalidStateTransition);
  ctf::Result<ctf::SessionView> cancelled = engine.view_session(decision.session);
  CTF_REQUIRE_OK(cancelled.status());
  CTF_EXPECT_EQ(cancelled.value().state, ctf::SessionState::Cancelled);
}

CTF_TEST(engine, ambiguous_outcomes_are_recorded_as_unproven_never_success) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(110), ctf::test::default_workload(), 1, 8192);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  const ctf::ShardDescriptor& shard = request.manifest.shards[0];

  ctf::Result<ctf::WaveOutcome> outcome =
      engine.request_wave(decision.session, shard.index, fence);
  CTF_REQUIRE_OK(outcome.status());
  const ctf::WaveGrant grant = outcome.value().grant.value();
  CTF_REQUIRE_OK(engine.report_ambiguous(decision.session, grant.attempt, grant.sequence,
                                         "sink died before acknowledging", fence));
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().shards[0].state, ctf::ShardState::Ambiguous);
  CTF_EXPECT_EQ(view.value().shards_ambiguous, 1U);
  CTF_EXPECT(view.value().transferred_bytes == 0);
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.bytes_unproven > 0);
  CTF_EXPECT_EQ(accounting.bytes_transferred, 0ULL);
  CTF_EXPECT(!accounting.at_baseline());
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
  // Ambiguous shards are not silently re-granted.
  ctf::Result<ctf::WaveOutcome> retry =
      engine.request_wave(decision.session, shard.index, fence);
  CTF_EXPECT_CODE(retry.status(), ctf::ErrorCode::AmbiguousOutcome);
}

CTF_TEST(engine, unacknowledged_bytes_are_not_transferred) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(120), ctf::test::default_workload(), 1, 4096);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::WaveOutcome> outcome =
      engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
  CTF_REQUIRE_OK(outcome.status());
  const ctf::WaveGrant grant = outcome.value().grant.value();
  ctf::TransferEvidence unacked;
  unacked.session = decision.session;
  unacked.attempt = grant.attempt;
  unacked.sequence = grant.sequence;
  unacked.shard = ctf::ShardIndex(0);
  unacked.arrived_bytes = grant.max_bytes;
  unacked.sink_acknowledged = false;
  CTF_REQUIRE_OK(engine.report_transfer(unacked, fence));
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.bytes_transferred, 0ULL);
  CTF_EXPECT_EQ(accounting.granted_outstanding_bytes, request.manifest.total_bytes);
  CTF_EXPECT(accounting.conserves());
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Transferring);
  CTF_EXPECT_EQ(view.value().evidence, ctf::EvidenceLevel::None);
}

CTF_TEST(engine, deadline_failure_is_deterministic_and_closes_accounting) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(130), ctf::test::default_workload(), 1, 4096);
  request.deadline_horizon_ns = 5 * ctf::kNanosPerMillisecond;
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::WaveOutcome> outcome =
      engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
  CTF_REQUIRE_OK(outcome.status());
  CTF_REQUIRE(outcome.value().granted);

  clock.advance(10 * ctf::kNanosPerMillisecond);
  CTF_EXPECT_EQ(engine.accounting().sessions_failed, 0ULL);
  CTF_EXPECT_OK(engine.poll_deadlines());
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.sessions_failed, 1ULL);
  CTF_EXPECT_EQ(accounting.bytes_transferred, 0ULL);
  CTF_EXPECT(accounting.bytes_unproven > 0);
  CTF_EXPECT(accounting.at_baseline());
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Failed);
  CTF_REQUIRE(view.value().last_reason.has_value());
  CTF_EXPECT_EQ(view.value().last_reason.value(), ctf::ReasonCode::DeadlineUnreachable);
}

CTF_TEST(engine, pause_and_resume_gate_credit) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(140), ctf::test::default_workload(), 1, 4096);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);

  CTF_REQUIRE_OK(engine.pause_session(decision.session, fence, "operator pause"));
  ctf::Result<ctf::WaveOutcome> paused =
      engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
  CTF_EXPECT_CODE(paused.status(), ctf::ErrorCode::Deferred);
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Paused);
  CTF_EXPECT_CODE(engine.pause_session(decision.session, fence, "again"), ctf::ErrorCode::AlreadyExists);

  CTF_REQUIRE_OK(engine.resume_session(decision.session, fence));
  ctf::Result<ctf::WaveOutcome> resumed =
      engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
  CTF_REQUIRE_OK(resumed.status());
  CTF_EXPECT(resumed.value().granted);
  CTF_EXPECT_CODE(engine.resume_session(decision.session, fence), ctf::ErrorCode::InvalidStateTransition);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, authority_changes_force_revalidation) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(150), ctf::test::default_workload(), 1, 4096);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());

  ctf::PolicySnapshot policy = fixture.policy;
  policy.generation = ctf::PolicyGeneration(4);
  policy.max_wave_width = 4;
  CTF_EXPECT_CODE(engine.apply_policy(fixture.policy), ctf::ErrorCode::StalePolicyGeneration);
  CTF_REQUIRE_OK(engine.apply_policy(policy));

  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::RevalidationRequired);
  CTF_EXPECT(!view.value().stale_reason.empty());

  const ctf::CommandFence old_fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::WaveOutcome> refused =
      engine.request_wave(decision.session, ctf::ShardIndex(0), old_fence);
  CTF_EXPECT_CODE(refused.status(), ctf::ErrorCode::StalePolicyGeneration);

  ctf::CommandFence new_fence = old_fence;
  new_fence.policy_generation = policy.generation;
  ctf::Result<ctf::AdmissionDecision> revalidated =
      engine.revalidate_session(decision.session, new_fence);
  CTF_REQUIRE_OK(revalidated.status());
  CTF_EXPECT(revalidated.value().admitted());
  CTF_REQUIRE(revalidated.value().envelope.has_value());
  CTF_EXPECT_EQ(revalidated.value().envelope.value().sequence.value(), 2ULL);
  ctf::Result<ctf::WaveOutcome> granted =
      engine.request_wave(decision.session, ctf::ShardIndex(0), new_fence);
  CTF_REQUIRE_OK(granted.status());
  CTF_EXPECT(granted.value().granted);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, topology_and_contract_advance_also_force_revalidation) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);

  const ctf::SessionRequest topology_request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(160), ctf::test::default_workload(), 1, 4096);
  const ctf::AdmissionDecision topology_decision =
      admit(ctf_ctx, engine, fixture, topology_request);
  CTF_REQUIRE(topology_decision.admitted());

  ctf::TopologySnapshot topology = fixture.topology;
  topology.generation = ctf::TopologyGeneration(3);
  CTF_REQUIRE_OK(engine.apply_topology(topology));
  ctf::Result<ctf::SessionView> view = engine.view_session(topology_decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::RevalidationRequired);

  const ctf::CheckpointId second =
      ctf::CheckpointId(ctf::Uuid128::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee1").value());
  ctf::SessionRequest contract_request =
      make_request(fixture, second, ctf::CheckpointGeneration(1), ctf::test::command_id(161));
  contract_request.topology_generation = topology.generation;
  const ctf::CommandFence contract_fence =
      ctf::test::fence_for(fixture, contract_request.workload,
                           contract_request.checkpoint_generation, std::nullopt,
                           topology.generation);
  ctf::Result<ctf::AdmissionDecision> contract_decision =
      engine.submit_session(contract_request, contract_fence);
  CTF_REQUIRE_OK(contract_decision.status());
  CTF_REQUIRE(contract_decision.value().admitted());

  ctf::WorkloadContract contract = fixture.contracts[0];
  contract.generation = ctf::WorkloadContractGeneration(6);
  contract.ceiling_bps = 512U * 1024U;
  CTF_REQUIRE_OK(engine.upsert_contract(contract));
  view = engine.view_session(contract_decision.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::RevalidationRequired);
  CTF_EXPECT_CODE(engine.upsert_contract(fixture.contracts[0]), ctf::ErrorCode::StaleContractGeneration);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, epoch_advance_fences_persisted_style_state) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(170), ctf::test::default_workload(), 1, 4096);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::WaveOutcome> granted =
      engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
  CTF_REQUIRE_OK(granted.status());
  CTF_REQUIRE(granted.value().granted);

  const ctf::CoordinatorEpoch next{ctf::IncarnationId(1), ctf::EpochTerm(2)};
  CTF_EXPECT_CODE(engine.advance_epoch(ctf::test::first_epoch()), ctf::ErrorCode::StaleEpoch);
  CTF_REQUIRE_OK(engine.advance_epoch(next));
  ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::RevalidationRequired);
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.bytes_unproven > 0);
  CTF_EXPECT_EQ(accounting.active_attempts, 0U);
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());

  ctf::Result<ctf::WaveOutcome> stale =
      engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
  CTF_EXPECT_CODE(stale.status(), ctf::ErrorCode::StaleEpoch);
}

CTF_TEST(engine, snapshot_round_trip_preserves_conservative_evidence) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::CheckpointId completed_checkpoint =
      ctf::CheckpointId(ctf::Uuid128::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee01").value());
  const ctf::SessionRequest completed =
      make_request(fixture, completed_checkpoint, ctf::CheckpointGeneration(1),
                   ctf::test::command_id(180), ctf::test::default_workload(), 1, 8192);
  const ctf::AdmissionDecision completed_decision = admit(ctf_ctx, engine, fixture, completed);
  CTF_REQUIRE(completed_decision.admitted());
  transfer_shard(ctf_ctx, engine, fixture, completed_decision.session, completed.workload,
                 completed.checkpoint_generation, completed.manifest.shards[0]);

  const ctf::CheckpointId active_checkpoint =
      ctf::CheckpointId(ctf::Uuid128::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee02").value());
  const ctf::SessionRequest active =
      make_request(fixture, active_checkpoint, ctf::CheckpointGeneration(1),
                   ctf::test::command_id(181), ctf::test::default_workload(), 1, 8192);
  const ctf::AdmissionDecision active_decision = admit(ctf_ctx, engine, fixture, active);
  CTF_REQUIRE(active_decision.admitted());
  const ctf::CommandFence active_fence =
      ctf::test::fence_for(fixture, active.workload, active.checkpoint_generation);
  ctf::Result<ctf::WaveOutcome> granted =
      engine.request_wave(active_decision.session, ctf::ShardIndex(0), active_fence);
  CTF_REQUIRE_OK(granted.status());
  CTF_REQUIRE(granted.value().granted);

  const ctf::EngineSnapshot snapshot = engine.export_snapshot();
  CTF_EXPECT_EQ(snapshot.sessions.size(), static_cast<std::size_t>(2));
  CTF_EXPECT(snapshot.accounting.conserves());

  ctf::ManualClock restarted_clock;
  ctf::FabricEngine restored(fixture.engine_config(ctf::test::first_epoch()), restarted_clock);
  CTF_REQUIRE_OK(restored.restore(snapshot));
  const ctf::CoordinatorEpoch next{ctf::IncarnationId(2), ctf::EpochTerm(1)};
  CTF_REQUIRE_OK(restored.advance_epoch(next));

  ctf::Result<ctf::SessionView> completed_view = restored.view_session(completed_decision.session);
  CTF_REQUIRE_OK(completed_view.status());
  CTF_EXPECT_EQ(completed_view.value().state, ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(completed_view.value().evidence, ctf::EvidenceLevel::VerifiedAtDestination);
  CTF_EXPECT(!completed_view.value().durable_checkpoint_success());

  ctf::Result<ctf::SessionView> active_view = restored.view_session(active_decision.session);
  CTF_REQUIRE_OK(active_view.status());
  CTF_EXPECT_EQ(active_view.value().state, ctf::SessionState::RevalidationRequired);
  CTF_EXPECT_EQ(active_view.value().transferred_bytes, 0ULL);
  CTF_EXPECT(active_view.value().shards[0].state == ctf::ShardState::Pending);
  const ctf::AccountingSnapshot accounting = restored.accounting();
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_EQ(accounting.sessions_completed, 1ULL);
  CTF_EXPECT_OK(restored.check_invariants());

  const ctf::CommandFence new_fence{next, fixture.policy.generation, fixture.topology.generation,
                                    fixture.contracts[0].generation, active.checkpoint_generation,
                                    std::nullopt};
  ctf::Result<ctf::AdmissionDecision> revalidated =
      restored.revalidate_session(active_decision.session, new_fence);
  CTF_REQUIRE_OK(revalidated.status());
  CTF_EXPECT(revalidated.value().admitted());
  CTF_EXPECT_OK(restored.check_invariants());
}

CTF_TEST(engine, restore_refuses_inconsistent_persisted_state) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(190), ctf::test::default_workload(), 1, 4096);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  ctf::EngineSnapshot snapshot = engine.export_snapshot();

  ctf::ManualClock other_clock;
  ctf::FabricEngine target(fixture.engine_config(ctf::test::first_epoch()), other_clock);

  ctf::EngineSnapshot broken = snapshot;
  broken.accounting.bytes_transferred += 1;
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::CorruptState);

  broken = snapshot;
  broken.sessions[0].shards.pop_back();
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::CorruptState);

  broken = snapshot;
  broken.sessions[0].state = ctf::SessionState::TrafficSessionComplete;
  broken.sessions[0].outstanding_bytes = 42;
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::CorruptState);

  broken = snapshot;
  broken.sessions.push_back(broken.sessions[0]);
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::DuplicateIdentity);

  broken = snapshot;
  broken.policy_generation = ctf::PolicyGeneration(99);
  CTF_EXPECT_CODE(target.restore(broken), ctf::ErrorCode::StalePolicyGeneration);

  // The valid snapshot still applies after all those refusals.
  CTF_REQUIRE_OK(target.restore(snapshot));
  CTF_EXPECT_EQ(target.session_count(), static_cast<std::size_t>(1));
  CTF_EXPECT_OK(target.check_invariants());
}

CTF_TEST(engine, shutdown_refuses_new_work) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  CTF_REQUIRE_OK(engine.begin_shutdown());
  CTF_EXPECT(engine.shutting_down());
  CTF_EXPECT_CODE(engine.begin_shutdown(), ctf::ErrorCode::ShuttingDown);

  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(200));
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().kind, ctf::DecisionKind::Deny);
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::FabricShuttingDown);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, resource_bounds_are_enforced) {
  ctf::ManualClock clock;
  EngineFixture fixture = EngineFixture::make();
  fixture.policy.max_session_bytes = 100000;
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);

  const ctf::SessionRequest oversized =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(210), ctf::test::default_workload(), 1, 200000);
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, oversized.workload, oversized.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(oversized, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_EXPECT_EQ(decision.value().reason, ctf::ReasonCode::CheckpointTooLarge);

  fixture.policy.max_session_bytes = 8U * 1024U * 1024U;
  fixture.limits.max_shards_per_checkpoint = 2;
  ctf::FabricEngine bounded(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest too_many_shards =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(211), ctf::test::default_workload(), 3, 4096);
  ctf::Result<ctf::AdmissionDecision> refused =
      bounded.submit_session(too_many_shards, ctf::test::fence_for(fixture, too_many_shards.workload));
  CTF_REQUIRE_OK(refused.status());
  CTF_EXPECT_EQ(refused.value().reason, ctf::ReasonCode::ManifestInvalid);

  // Fabric-wide session bound produces a deferral, not a crash.
  fixture.policy.max_sessions = 1;
  fixture.policy.max_session_bytes = 8U * 1024U * 1024U;
  ctf::FabricEngine tiny(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest first =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(212), ctf::test::default_workload(), 1, 4096);
  CTF_EXPECT(admit(ctf_ctx, tiny, fixture, first).admitted());
  const ctf::CheckpointId other =
      ctf::CheckpointId(ctf::Uuid128::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee77").value());
  const ctf::SessionRequest second =
      make_request(fixture, other, ctf::CheckpointGeneration(1), ctf::test::command_id(213),
                   ctf::test::default_workload(), 1, 4096);
  ctf::Result<ctf::AdmissionDecision> deferred =
      tiny.submit_session(second, ctf::test::fence_for(fixture, second.workload));
  CTF_REQUIRE_OK(deferred.status());
  CTF_EXPECT_EQ(deferred.value().kind, ctf::DecisionKind::Defer);
  CTF_EXPECT_EQ(deferred.value().reason, ctf::ReasonCode::FabricSessionLimit);
  CTF_EXPECT_OK(tiny.check_invariants());
}

CTF_TEST(engine, grants_never_exceed_the_isolation_ceiling) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(220), ctf::test::default_workload(), 1,
                   1024U * 1024U);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);

  const std::uint64_t ceiling = 1U * 1024U * 1024U;  // TrainingBulk class ceiling
  std::uint64_t granted = 0;
  std::uint64_t settled = 0;
  for (int step = 0; step < 600; ++step) {
    ctf::Result<ctf::WaveOutcome> outcome =
        engine.request_wave(decision.session, ctf::ShardIndex(0), fence);
    CTF_REQUIRE_OK(outcome.status());
    if (!outcome.value().granted) {
      clock.advance(5 * ctf::kNanosPerMillisecond);
      continue;
    }
    // Each attempt is settled with evidence before the next one is requested.
    const ctf::WaveGrant grant = outcome.value().grant.value();
    ctf::TransferEvidence evidence;
    evidence.session = decision.session;
    evidence.attempt = grant.attempt;
    evidence.sequence = grant.sequence;
    evidence.shard = ctf::ShardIndex(0);
    evidence.arrived_bytes = grant.max_bytes;
    evidence.sink_acknowledged = true;
    CTF_REQUIRE_OK(engine.report_transfer(evidence, fence));
    settled += grant.max_bytes;
    granted += grant.max_bytes;
    const std::uint64_t elapsed = static_cast<std::uint64_t>(clock.now());
    const std::uint64_t allowed =
        (ceiling / static_cast<std::uint64_t>(ctf::kNanosPerSecond)) * elapsed +
        ((ceiling % static_cast<std::uint64_t>(ctf::kNanosPerSecond)) * elapsed) /
            static_cast<std::uint64_t>(ctf::kNanosPerSecond);
    CTF_EXPECT(granted <= allowed + decision.envelope.value().burst_bytes);
    if (!(granted <= allowed + decision.envelope.value().burst_bytes)) {
      break;
    }
    if (settled >= request.manifest.total_bytes) {
      break;  // the checkpoint itself is finished
    }
  }
  CTF_EXPECT(granted > 0);
  CTF_EXPECT(settled > 0);
  CTF_EXPECT(granted <= request.manifest.total_bytes);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_TEST(engine, repeated_lifecycle_is_stable) {
  for (int iteration = 0; iteration < 8; ++iteration) {
    ctf::ManualClock clock;
    const EngineFixture fixture = EngineFixture::make();
    ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
    const ctf::SessionRequest request =
        make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                     ctf::test::command_id(230), ctf::test::default_workload(), 2, 4096);
    const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
    CTF_REQUIRE(decision.admitted());
    for (const ctf::ShardDescriptor& shard : request.manifest.shards) {
      transfer_shard(ctf_ctx, engine, fixture, decision.session, request.workload,
                     request.checkpoint_generation, shard);
    }
    // The session already completed, so cancellation must be refused rather
    // than silently accepted (which would corrupt accounting closure).
    const ctf::Status cancelled = engine.cancel_session(
        decision.session,
        ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation),
        ctf::ReasonCode::CancelledByOperator, "iteration");
    CTF_EXPECT_EQ(cancelled.code(), ctf::ErrorCode::InvalidStateTransition);
    const ctf::AccountingSnapshot accounting = engine.accounting();
    CTF_EXPECT(accounting.conserves());
    CTF_EXPECT(accounting.at_baseline());
    CTF_EXPECT_OK(engine.check_invariants());
  }
}

CTF_TEST(engine, repeated_grant_and_truncate_cycles_stay_settled) {
  ctf::ManualClock clock;
  EngineFixture fixture = EngineFixture::make();
  fixture.policy.retained_history = 4;  // tiny history: exercise pruning hard
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                   ctf::test::command_id(1000), ctf::test::default_workload(), 1, 64U * 1024U);
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  const ctf::AdmissionDecision decision = admit(ctf_ctx, engine, fixture, request);
  CTF_REQUIRE(decision.admitted());
  const ctf::ShardIndex shard = request.manifest.shards[0].index;
  std::size_t granted = 0;
  for (int step = 0; step < 40; ++step) {
    ctf::Result<ctf::WaveOutcome> outcome = engine.request_wave(decision.session, shard, fence);
    ctf::Result<ctf::SessionView> view = engine.view_session(decision.session);
    const std::string diagnostic =
        " step=" + std::to_string(step) + " state=" + std::to_string(step) +
        " shard_state=" +
        (view.ok() ? ctf::to_string(view.value().shards[0].state) : std::string("?")) +
        " attempts_entries=" + std::to_string(engine.timeline_entries()) +
        " timeline=" + (view.ok() ? std::to_string(view.value().shards.size()) : "?");
    if (!outcome.ok()) {
      ctf_ctx.fail(__FILE__, __LINE__,
                   "request_wave refused:" + diagnostic + " status=" + outcome.status().to_string());
      break;
    }
    if (!outcome.value().granted) {
      // The class ceiling refills at 1 MiB/s; 20 ms of clock is enough for the
      // minimum useful grant, so a retry follows promptly.
      clock.advance(20 * ctf::kNanosPerMillisecond);
      continue;
    }
    ++granted;
    const ctf::WaveGrant grant = outcome.value().grant.value();
    ctf::VerificationEvidence truncated;
    truncated.session = decision.session;
    truncated.attempt = grant.attempt;
    truncated.sequence = grant.sequence;
    truncated.shard = shard;
    truncated.outcome = ctf::VerificationEvidence::Outcome::Truncated;
    const ctf::Status reported = engine.report_verification(truncated, fence);
    if (!reported.ok()) {
      ctf_ctx.fail(__FILE__, __LINE__,
                   "truncation refused:" + diagnostic + " status=" + reported.to_string());
      break;
    }
  }
  CTF_EXPECT(granted >= 8);
  CTF_EXPECT_OK(engine.check_invariants());
}

CTF_MAIN()

