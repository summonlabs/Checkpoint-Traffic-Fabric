// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Persistence proofs: atomic replacement, torn-tail recovery, version and size
// refusal, journal compaction, and restart reconciliation through a real
// coordinator restart on the same data directory.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ctf/client.hpp"
#include "ctf/config.hpp"
#include "ctf/report.hpp"
#include "ctf/service.hpp"
#include "ctf/store.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

namespace {

using ctf::test::EngineFixture;
using ctf::test::TempDir;

struct StoreHarness {
  TempDir directory{"persistence"};
  ctf::store::StoreConfig config;
  ctf::store::PersistentStore store;

  explicit StoreHarness(std::uint64_t max_journal_bytes = 4U << 20)
      : config{[this, max_journal_bytes] {
          ctf::store::StoreConfig value;
          value.directory = directory.path();
          value.max_journal_bytes = max_journal_bytes;
          return value;
        }()},
        store(config) {}
};

/// Builds a snapshot that contains exactly one admitted session.
[[nodiscard]] ctf::EngineSnapshot snapshot_with_admitted_session(ctf::test::Context& ctf_ctx,
                                                                std::uint64_t command_suffix,
                                                                bool transfer_one_chunk) {
  ctf::ManualClock clock;
  const EngineFixture fixture = EngineFixture::make();
  ctf::FabricEngine engine(fixture.engine_config(ctf::test::first_epoch()), clock);
  const ctf::SessionRequest request =
      ctf::test::make_request(fixture, ctf::test::default_checkpoint(), ctf::CheckpointGeneration(1),
                              ctf::test::command_id(command_suffix));
  const ctf::CommandFence fence =
      ctf::test::fence_for(fixture, request.workload, request.checkpoint_generation);
  ctf::Result<ctf::AdmissionDecision> decision = engine.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  if (transfer_one_chunk) {
    ctf::Result<ctf::WaveOutcome> wave =
        engine.request_wave(decision.value().session, ctf::ShardIndex(0), fence);
    CTF_REQUIRE_OK(wave.status());
    CTF_REQUIRE(wave.value().granted);
    ctf::TransferEvidence evidence;
    evidence.session = decision.value().session;
    evidence.attempt = wave.value().grant.value().attempt;
    evidence.sequence = wave.value().grant.value().sequence;
    evidence.shard = ctf::ShardIndex(0);
    evidence.arrived_bytes = wave.value().grant.value().max_bytes;
    evidence.sink_acknowledged = true;
    CTF_REQUIRE_OK(engine.report_transfer(evidence, fence));
  }
  return engine.export_snapshot();
}

[[nodiscard]] std::string render_config(const ctf::CoordinatorConfig& config) {
  return ctf::config::describe_config(config);
}

/// Writes a coordinator configuration file that persists into a directory.
[[nodiscard]] std::filesystem::path write_config(ctf::test::Context& ctf_ctx,
                                                const TempDir& directory, bool persist,
                                                bool require_verification = true,
                                                std::uint64_t policy_generation = 7) {
  (void)ctf_ctx;
  const std::string workload = ctf::test::kDefaultWorkloadText;
  std::ostringstream text;
  text << "label = persistence-coordinator\n";
  text << "bind_host = 127.0.0.1\n";
  text << "port = 0\n";
  text << "data_directory = " << (directory.path() / "data").string() << "\n";
  text << "persist = " << (persist ? "true" : "false") << "\n";
  text << "worker_threads = 4\n";
  text << "policy.generation = " << policy_generation << "\n";
  text << "policy.max_wave_width = 8\n";
  text << "policy.max_sessions = 32\n";
  text << "policy.max_attempts_in_flight = 16\n";
  text << "policy.retained_history = 64\n";
  text << "policy.require_destination_verification = "
       << (require_verification ? "true" : "false") << "\n";
  text << "policy.defer_horizon_ns = 100000000\n";
  text << "policy.default_deadline_ns = 60000000000\n";
  const char* classes[] = {"TrainingCritical", "ServingLatency", "TrainingBulk", "BestEffort"};
  for (const char* name : classes) {
    text << "policy.envelope." << name << ".ceiling_bps = 4194304\n";
    text << "policy.envelope." << name << ".burst_window_ns = 100000000\n";
    text << "policy.envelope." << name << ".max_in_flight_sessions = 4\n";
  }
  text << "topology.generation = 3\n";
  text << "topology.path.1.destination = SyntheticLab\n";
  text << "topology.path.1.capacity_bps = 67108864\n";
  text << "topology.path.1.synthetic = true\n";
  text << "topology.path.1.label = persistence-lab\n";
  text << "contract." << workload << ".generation = 5\n";
  text << "contract." << workload << ".isolation = TrainingBulk\n";
  text << "contract." << workload << ".ceiling_bps = 4194304\n";
  text << "contract." << workload << ".floor_bps = 0\n";
  text << "contract." << workload << ".max_in_flight_sessions = 4\n";
  text << "contract." << workload << ".max_shards_per_wave = 4\n";
  text << "contract." << workload << ".allow_supersession = true\n";
  text << "contract." << workload << ".deadline_budget_ns = 60000000000\n";
  const std::filesystem::path path = directory.path() / "coordinator.conf";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output << text.str();
  output.close();
  CTF_REQUIRE(std::filesystem::exists(path));
  return path;
}

[[nodiscard]] ctf::Result<ctf::CoordinatorClient> connect_client(
    ctf::test::Context& ctf_ctx, std::uint16_t port, const std::string& identity,
    ctf::wire::ClientKind kind = ctf::wire::ClientKind::Operator) {
  (void)ctf_ctx;
  static ctf::net::StopToken stop;
  ctf::ClientConfig config;
  config.host = "127.0.0.1";
  config.port = port;
  config.kind = kind;
  config.identity = identity;
  return ctf::CoordinatorClient::connect(config, stop);
}

/// Builds a submission request that matches the configuration written above.
[[nodiscard]] ctf::SessionRequest make_service_request(ctf::test::Context& ctf_ctx,
                                                      const ctf::wire::HelloResponse& hello,
                                                      ctf::CheckpointGeneration generation,
                                                      std::uint64_t command_suffix,
                                                      std::uint32_t shards = 2,
                                                      std::uint64_t shard_bytes = 32U * 1024U) {
  (void)ctf_ctx;
  ctf::SessionRequest request;
  request.command = ctf::test::command_id(command_suffix);
  request.workload = ctf::test::default_workload();
  request.contract_generation = ctf::WorkloadContractGeneration(0);
  for (const ctf::ContractGenerationRecord& record : hello.contracts) {
    if (record.workload == request.workload) {
      request.contract_generation = record.generation;
    }
  }
  request.policy_generation = hello.policy_generation;
  request.topology_generation = hello.topology_generation;
  request.checkpoint = ctf::test::default_checkpoint();
  request.checkpoint_generation = generation;
  request.requested_isolation = ctf::IsolationClass::TrainingBulk;
  request.destination = ctf::DestinationClass::SyntheticLab;
  request.manifest.checkpoint = request.checkpoint;
  request.manifest.generation = generation;
  request.manifest.workload = request.workload;
  request.manifest.contract_generation = request.contract_generation;
  for (std::uint32_t i = 0; i < shards; ++i) {
    ctf::ShardDescriptor shard;
    shard.index = ctf::ShardIndex(i);
    shard.declared_bytes = shard_bytes;
    shard.declared_digest = ctf::Digest(0x3000U + i, 0x4000ULL + i);
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += shard_bytes;
  }
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  return request;
}

}  // namespace

CTF_TEST(persistence, store_round_trip_and_atomic_replacement) {
  StoreHarness harness;
  CTF_REQUIRE_OK(harness.store.open());
  CTF_EXPECT(!harness.store.has_state());

  const ctf::EngineSnapshot snapshot = snapshot_with_admitted_session(ctf_ctx, 500, false);
  CTF_REQUIRE_OK(harness.store.persist(snapshot));
  CTF_EXPECT(harness.store.has_state());
  CTF_EXPECT(!std::filesystem::exists(harness.store.snapshot_path().string() + ".tmp"));

  ctf::store::LoadReport report;
  ctf::Result<ctf::EngineSnapshot> loaded = harness.store.load(&report);
  CTF_REQUIRE_OK(loaded.status());
  CTF_EXPECT(report.snapshot_present);
  CTF_EXPECT(!report.torn_tail);
  CTF_EXPECT_EQ(loaded.value().sessions.size(), snapshot.sessions.size());
  CTF_EXPECT(loaded.value().accounting.conserves());
  CTF_EXPECT_EQ(loaded.value().accounting.bytes_admitted, snapshot.accounting.bytes_admitted);
  CTF_EXPECT(loaded.value().epoch == snapshot.epoch);

  // A second persist replaces the first atomically and remains readable.
  const ctf::EngineSnapshot second = snapshot_with_admitted_session(ctf_ctx, 501, true);
  CTF_REQUIRE_OK(harness.store.persist(second));
  ctf::store::LoadReport second_report;
  ctf::Result<ctf::EngineSnapshot> reloaded = harness.store.load(&second_report);
  CTF_REQUIRE_OK(reloaded.status());
  CTF_EXPECT_EQ(reloaded.value().sessions.size(), second.sessions.size());
  CTF_EXPECT(reloaded.value().accounting.bytes_transferred > 0);
  CTF_EXPECT(!std::filesystem::exists(harness.store.snapshot_path().string() + ".tmp"));
}

CTF_TEST(persistence, torn_tail_is_recovered_and_reported) {
  StoreHarness harness;
  CTF_REQUIRE_OK(harness.store.open());
  const ctf::EngineSnapshot snapshot = snapshot_with_admitted_session(ctf_ctx, 510, false);
  CTF_REQUIRE_OK(harness.store.persist(snapshot));
  CTF_REQUIRE_OK(harness.store.append("second", snapshot));
  CTF_REQUIRE_OK(harness.store.append("third", snapshot));

  // A record that was half written before the process died.
  const ctf::Bytes partial = ctf::store::encode_journal_record(
      ctf::store::JournalRecord{harness.store.sequence() + 1, "fourth",
                                ctf::store::encode_snapshot(snapshot, harness.config.limits)});
  {
    std::ofstream output(harness.store.journal_path(), std::ios::binary | std::ios::app);
    output.write(reinterpret_cast<const char*>(partial.data()),
                 static_cast<std::streamsize>(partial.size() / 3));
  }
  ctf::store::LoadReport report;
  ctf::Result<ctf::EngineSnapshot> loaded = harness.store.load(&report);
  CTF_REQUIRE_OK(loaded.status());
  CTF_EXPECT(report.torn_tail);
  CTF_EXPECT(report.discarded_bytes > 0);
  CTF_EXPECT(!report.notes.empty());
  CTF_EXPECT_EQ(loaded.value().sessions.size(), snapshot.sessions.size());
  CTF_EXPECT(loaded.value().accounting.conserves());

  // The torn tail is never partially applied: the recovered state equals the
  // last complete record.
  CTF_EXPECT_EQ(loaded.value().accounting.bytes_admitted, snapshot.accounting.bytes_admitted);
}

CTF_TEST(persistence, version_and_size_violations_are_refused) {
  StoreHarness harness;
  CTF_REQUIRE_OK(harness.store.open());
  const ctf::EngineSnapshot snapshot = snapshot_with_admitted_session(ctf_ctx, 520, false);
  CTF_REQUIRE_OK(harness.store.persist(snapshot));

  const std::filesystem::path path = harness.store.snapshot_path();
  std::vector<char> raw;
  {
    std::ifstream input(path, std::ios::binary);
    raw.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  }
  CTF_REQUIRE(raw.size() > 8);
  std::vector<char> version = raw;
  version[4] = 0x63;
  version[5] = 0x00;
  {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(version.data(), static_cast<std::streamsize>(version.size()));
  }
  ctf::store::LoadReport version_report;
  const ctf::Result<ctf::EngineSnapshot> refused = harness.store.load(&version_report);
  CTF_EXPECT(!refused.ok());
  CTF_EXPECT(version_report.version_mismatch);

  std::vector<char> truncated(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(raw.size() / 2));
  {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(truncated.data(), static_cast<std::streamsize>(truncated.size()));
  }
  ctf::store::LoadReport truncated_report;
  CTF_EXPECT(!harness.store.load(&truncated_report).ok());
  CTF_EXPECT(truncated_report.corrupt_prefix);
}

CTF_TEST(persistence, journal_compaction_bounds_growth) {
  StoreHarness harness(64U * 1024U);
  CTF_REQUIRE_OK(harness.store.open());
  const ctf::EngineSnapshot snapshot = snapshot_with_admitted_session(ctf_ctx, 530, false);
  CTF_REQUIRE_OK(harness.store.persist(snapshot));
  for (int i = 0; i < 40; ++i) {
    CTF_REQUIRE_OK(harness.store.append("tick-" + std::to_string(i), snapshot));
  }
  CTF_EXPECT(harness.store.journal_bytes() <= harness.config.max_journal_bytes + (256U * 1024U));
  CTF_EXPECT(harness.store.journal_records() <= harness.config.max_journal_records);
  ctf::store::LoadReport report;
  ctf::Result<ctf::EngineSnapshot> loaded = harness.store.load(&report);
  CTF_REQUIRE_OK(loaded.status());
  CTF_EXPECT_EQ(loaded.value().sessions.size(), snapshot.sessions.size());
}

CTF_TEST(persistence, restart_revalidates_and_advances_the_epoch) {
  TempDir directory("persistence-restart");
  const std::filesystem::path config_path = write_config(ctf_ctx, directory, true);
  ctf::Result<ctf::config::FileConfig> loaded = ctf::config::load_config_file(config_path);
  CTF_REQUIRE_OK(loaded.status());

  ctf::SteadyClock clock;
  ctf::SessionId session;
  {
    ctf::CoordinatorService service(loaded.value().coordinator, clock);
    CTF_REQUIRE_OK(service.start());
    ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, service.port(), "persistence");
    CTF_REQUIRE_OK(client.status());
    CTF_EXPECT_EQ(client.value().hello().epoch.incarnation.value(), 1ULL);
    const ctf::SessionRequest request =
        make_service_request(ctf_ctx, client.value().hello(), ctf::CheckpointGeneration(1), 540);
    const ctf::CommandFence fence =
        client.value().current_fence(request.workload, request.checkpoint_generation);
    ctf::Result<ctf::AdmissionDecision> decision = client.value().submit_session(request, fence);
    CTF_REQUIRE_OK(decision.status());
    CTF_REQUIRE(decision.value().admitted());
    session = decision.value().session;
    // One acknowledged chunk so there is real evidence to reconcile. Credit may
    // only be requested by a connection that handshook as a sender.
    ctf::Result<ctf::CoordinatorClient> sender_client = connect_client(
        ctf_ctx, service.port(), "persistence-sender", ctf::wire::ClientKind::Sender);
    CTF_REQUIRE_OK(sender_client.status());
    ctf::Result<ctf::WaveOutcome> wave =
        sender_client.value().request_wave(session, ctf::ShardIndex(0), fence);
    CTF_REQUIRE_OK(wave.status());
    CTF_REQUIRE(wave.value().granted);
    ctf::TransferEvidence evidence;
    evidence.session = session;
    evidence.attempt = wave.value().grant.value().attempt;
    evidence.sequence = wave.value().grant.value().sequence;
    evidence.shard = ctf::ShardIndex(0);
    evidence.arrived_bytes = wave.value().grant.value().max_bytes;
    evidence.sink_acknowledged = true;
    CTF_REQUIRE_OK(sender_client.value().report_transfer(evidence, fence));
    CTF_REQUIRE_OK(sender_client.value().close());
    CTF_REQUIRE_OK(client.value().close());
    CTF_REQUIRE_OK(service.shutdown());
  }

  {
    ctf::CoordinatorService restarted(loaded.value().coordinator, clock);
    CTF_REQUIRE_OK(restarted.start());
    ctf::Result<ctf::CoordinatorClient> client =
        connect_client(ctf_ctx, restarted.port(), "persistence-after-restart");
    CTF_REQUIRE_OK(client.status());
    // A restart is a new incarnation: no liveness, freshness, or credit survives.
    CTF_EXPECT_EQ(client.value().hello().epoch.incarnation.value(), 2ULL);
    ctf::Result<ctf::SessionView> view = client.value().view_session(session);
    CTF_REQUIRE_OK(view.status());
    CTF_EXPECT_EQ(view.value().state, ctf::SessionState::RevalidationRequired);
    CTF_EXPECT(!view.value().stale_reason.empty());
    ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
    CTF_REQUIRE_OK(accounting.status());
    CTF_EXPECT(accounting.value().conserves());
    CTF_EXPECT_EQ(accounting.value().active_attempts, 0U);
    CTF_EXPECT_OK(client.value().check_invariants());

    // An old-epoch command is refused; a fresh fence revalidates the session.
    const ctf::CommandFence stale_fence =
        client.value().current_fence(view.value().workload, view.value().checkpoint_generation);
    ctf::CommandFence old_epoch = stale_fence;
    old_epoch.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(1)};
    ctf::Result<ctf::CoordinatorClient> sender_client = connect_client(
        ctf_ctx, restarted.port(), "persistence-sender-after-restart",
        ctf::wire::ClientKind::Sender);
    CTF_REQUIRE_OK(sender_client.status());
    ctf::Result<ctf::WaveOutcome> refused =
        sender_client.value().request_wave(session, ctf::ShardIndex(0), old_epoch);
    CTF_EXPECT_EQ(refused.status().code(), ctf::ErrorCode::ForeignEpoch);
    CTF_REQUIRE_OK(sender_client.value().close());

    ctf::Result<ctf::AdmissionDecision> revalidated =
        client.value().revalidate_session(session, stale_fence);
    CTF_REQUIRE_OK(revalidated.status());
    CTF_REQUIRE(revalidated.value().admitted());
    CTF_REQUIRE(revalidated.value().envelope.has_value());
    CTF_EXPECT_EQ(revalidated.value().envelope.value().sequence.value(), 2ULL);
    view = client.value().view_session(session);
    CTF_REQUIRE_OK(view.status());
    CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Admitted);
    CTF_EXPECT_OK(client.value().check_invariants());

    // Cancel so the restart leaves no outstanding authority behind.
    const ctf::CommandFence fence =
        client.value().current_fence(view.value().workload, view.value().checkpoint_generation);
    CTF_REQUIRE_OK(client.value().cancel_session(session, fence,
                                                 ctf::ReasonCode::CancelledByOperator,
                                                 "restart proof complete"));
    accounting = client.value().accounting();
    CTF_REQUIRE_OK(accounting.status());
    CTF_EXPECT(accounting.value().at_baseline());
    CTF_EXPECT(accounting.value().conserves());
    CTF_REQUIRE_OK(client.value().close());
    CTF_REQUIRE_OK(restarted.shutdown());
  }
}

CTF_TEST(persistence, service_starts_over_a_torn_journal_tail) {
  TempDir directory("persistence-torn");
  const std::filesystem::path config_path = write_config(ctf_ctx, directory, true);
  ctf::Result<ctf::config::FileConfig> loaded = ctf::config::load_config_file(config_path);
  CTF_REQUIRE_OK(loaded.status());

  // Produce real persisted state, then damage the tail as a crash would.
  ctf::SteadyClock clock;
  {
    ctf::CoordinatorService service(loaded.value().coordinator, clock);
    CTF_REQUIRE_OK(service.start());
    ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, service.port(), "torn-setup");
    CTF_REQUIRE_OK(client.status());
    const ctf::SessionRequest request =
        make_service_request(ctf_ctx, client.value().hello(), ctf::CheckpointGeneration(1), 550,
                             1, 8192);
    const ctf::CommandFence fence =
        client.value().current_fence(request.workload, request.checkpoint_generation);
    ctf::Result<ctf::AdmissionDecision> decision = client.value().submit_session(request, fence);
    CTF_REQUIRE_OK(decision.status());
    CTF_REQUIRE(decision.value().admitted());
    CTF_REQUIRE_OK(client.value().close());
    CTF_REQUIRE_OK(service.shutdown());
  }
  const std::filesystem::path journal = directory.path() / "data" / "fabric.journal";
  CTF_REQUIRE(std::filesystem::exists(journal));
  {
    std::ofstream output(journal, std::ios::binary | std::ios::app);
    const char garbage[] = {'C', 'T', 'F', 'J', 0x00, 0x01, 0x00, 0x00, 0x00};
    output.write(garbage, static_cast<std::streamsize>(sizeof(garbage)));
  }
  {
    ctf::CoordinatorService recovered(loaded.value().coordinator, clock);
    CTF_REQUIRE_OK(recovered.start());
    CTF_EXPECT(recovered.load_report().torn_tail);
    CTF_EXPECT(recovered.load_report().discarded_bytes > 0);
    ctf::Result<ctf::CoordinatorClient> client =
        connect_client(ctf_ctx, recovered.port(), "torn-recovered");
    CTF_REQUIRE_OK(client.status());
    ctf::Result<std::vector<ctf::SessionSummary>> sessions =
        client.value().list_sessions(std::nullopt, 16);
    CTF_REQUIRE_OK(sessions.status());
    CTF_EXPECT_EQ(sessions.value().size(), static_cast<std::size_t>(1));
    CTF_EXPECT_OK(client.value().check_invariants());
    CTF_REQUIRE_OK(client.value().close());
    CTF_REQUIRE_OK(recovered.shutdown());
  }
}

CTF_MAIN()
