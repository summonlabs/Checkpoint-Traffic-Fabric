// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Multiprocess proofs: real coordinator, sender, and sink OS processes over
// loopback TCP, including abrupt process death and coordinator crash/restart.
//
// Fault injection here is real: processes are terminated with the platform's
// hard kill, so nothing gets a chance to clean up.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "ctf/client.hpp"
#include "ctf/report.hpp"
#include "ctf/service.hpp"
#include "fixtures.hpp"
#include "process.hpp"
#include "test_harness.hpp"

namespace {

using ctf::test::ChildProcess;
using ctf::test::TempDir;

[[nodiscard]] std::filesystem::path write_config(const TempDir& directory, bool persist,
                                                std::uint64_t best_effort_bps) {
  const std::string workload = ctf::test::kDefaultWorkloadText;
  std::ostringstream text;
  text << "label = multiprocess-coordinator\n";
  text << "bind_host = 127.0.0.1\n";
  text << "port = 0\n";
  text << "data_directory = " << (directory.path() / "data").string() << "\n";
  text << "persist = " << (persist ? "true" : "false") << "\n";
  text << "worker_threads = 4\n";
  text << "policy.generation = 11\n";
  text << "policy.max_wave_width = 8\n";
  text << "policy.max_sessions = 32\n";
  text << "policy.max_attempts_in_flight = 16\n";
  text << "policy.retained_history = 64\n";
  text << "policy.require_destination_verification = true\n";
  text << "policy.defer_horizon_ns = 50000000\n";
  text << "policy.default_deadline_ns = 120000000000\n";
  const char* classes[] = {"TrainingCritical", "ServingLatency", "TrainingBulk", "BestEffort"};
  for (const char* name : classes) {
    const std::uint64_t ceiling = std::string(name) == "BestEffort" ? best_effort_bps : 4194304ULL;
    text << "policy.envelope." << name << ".ceiling_bps = " << ceiling << "\n";
    text << "policy.envelope." << name << ".burst_window_ns = 50000000\n";
    text << "policy.envelope." << name << ".max_in_flight_sessions = 4\n";
  }
  text << "topology.generation = 4\n";
  text << "topology.path.1.destination = SyntheticLab\n";
  text << "topology.path.1.capacity_bps = 67108864\n";
  text << "topology.path.1.synthetic = true\n";
  text << "topology.path.1.label = multiprocess-lab\n";
  text << "contract." << workload << ".generation = 9\n";
  text << "contract." << workload << ".isolation = TrainingBulk\n";
  text << "contract." << workload << ".ceiling_bps = 4194304\n";
  text << "contract." << workload << ".floor_bps = 0\n";
  text << "contract." << workload << ".max_in_flight_sessions = 4\n";
  text << "contract." << workload << ".max_shards_per_wave = 4\n";
  text << "contract." << workload << ".allow_supersession = true\n";
  text << "contract." << workload << ".deadline_budget_ns = 120000000000\n";
  const std::filesystem::path path = directory.path() / "coordinator.conf";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output << text.str();
  output.close();
  return path;
}

struct Coordinator {
  ChildProcess process;
  std::uint16_t port = 0;
  std::uint64_t incarnation = 0;
  std::uint64_t term = 0;
};

[[nodiscard]] std::optional<Coordinator> start_coordinator(ctf::test::Context& ctf_ctx,
                                                          const std::filesystem::path& config) {
  std::optional<ChildProcess> process = ChildProcess::start(
      ctf::test::app_path("ctf-coordinator"), {"--config", config.string()},
      config.parent_path() / "coordinator.log");
  CTF_REQUIRE(process.has_value());
  CTF_REQUIRE(process->wait_for_line("CTF-READY"));
  const std::string output = process->output();
  const std::optional<std::string> port = ctf::test::extract_field(output, "port");
  const std::optional<std::string> epoch = ctf::test::extract_field(output, "epoch");
  CTF_REQUIRE(port.has_value());
  CTF_REQUIRE(epoch.has_value());
  const std::optional<ctf::CoordinatorEpoch> parsed = ctf::CoordinatorEpoch::parse(epoch.value());
  CTF_REQUIRE(parsed.has_value());
  Coordinator coordinator;
  coordinator.process = std::move(process).value();
  coordinator.port = static_cast<std::uint16_t>(std::stoul(port.value()));
  coordinator.incarnation = parsed.value().incarnation.value();
  coordinator.term = parsed.value().term.value();
  return coordinator;
}

struct Sink {
  ChildProcess process;
  std::uint16_t port = 0;
};

[[nodiscard]] std::optional<Sink> start_sink(ctf::test::Context& ctf_ctx,
                                            std::uint16_t coordinator_port,
                                            const std::filesystem::path& directory,
                                            std::uint32_t expect_shards,
                                            std::uint64_t die_after_bytes = 0) {
  std::vector<std::string> arguments = {"sink",
                                        "--coordinator",
                                        "127.0.0.1:" + std::to_string(coordinator_port),
                                        "--directory",
                                        directory.string(),
                                        "--port",
                                        "0",
                                        "--expect-shards",
                                        std::to_string(expect_shards),
                                        "--identity",
                                        "multiprocess-sink"};
  if (die_after_bytes != 0) {
    arguments.push_back("--die-after-bytes");
    arguments.push_back(std::to_string(die_after_bytes));
  }
  std::optional<ChildProcess> process = ChildProcess::start(
      ctf::test::app_path("ctf-agent"), arguments,
      directory / ("sink-" + std::to_string(expect_shards) + "-" +
                   std::to_string(die_after_bytes) + ".log"));
  CTF_REQUIRE(process.has_value());
  CTF_REQUIRE(process->wait_for_line("CTF-SINK-READY"));
  const std::optional<std::string> port = ctf::test::extract_field(process->output(), "port");
  CTF_REQUIRE(port.has_value());
  Sink sink;
  sink.process = std::move(process).value();
  sink.port = static_cast<std::uint16_t>(std::stoul(port.value()));
  return sink;
}

[[nodiscard]] std::vector<std::string> sender_arguments(std::uint16_t coordinator_port,
                                                       std::uint16_t sink_port,
                                                       ctf::CheckpointGeneration generation,
                                                       std::uint32_t shards, std::uint64_t shard_bytes,
                                                       const std::string& isolation = "TrainingBulk",
                                                       const std::vector<std::string>& extra = {}) {
  std::vector<std::string> arguments = {
      "sender",
      "--coordinator",
      "127.0.0.1:" + std::to_string(coordinator_port),
      "--sink",
      "127.0.0.1:" + std::to_string(sink_port),
      "--workload",
      ctf::test::kDefaultWorkloadText,
      "--checkpoint",
      ctf::test::kCheckpointText,
      "--generation",
      std::to_string(generation.value()),
      "--shards",
      std::to_string(shards),
      "--shard-bytes",
      std::to_string(shard_bytes),
      "--isolation",
      isolation,
      "--destination",
      "SyntheticLab",
      "--identity",
      "multiprocess-sender",
      "--json"};
  arguments.insert(arguments.end(), extra.begin(), extra.end());
  return arguments;
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

/// Waits until the coordinator reports at least one transferred byte.
[[nodiscard]] bool wait_for_transfer(ctf::test::Context& ctf_ctx, std::uint16_t port,
                                     std::uint32_t max_seconds = 30) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(max_seconds);
  while (std::chrono::steady_clock::now() < deadline) {
    ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, port, "progress-watch");
    if (client.ok()) {
      ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
      if (accounting.ok() && (accounting.value().bytes_transferred > 0 ||
                              accounting.value().sessions_admitted > 0)) {
        (void)client.value().close();
        return true;
      }
      (void)client.value().close();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

[[nodiscard]] ctf::SessionId single_session(ctf::test::Context& ctf_ctx, std::uint16_t port) {
  ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, port, "session-lookup");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<std::vector<ctf::SessionSummary>> sessions = client.value().list_sessions(std::nullopt, 8);
  CTF_REQUIRE_OK(sessions.status());
  CTF_REQUIRE(!sessions.value().empty());
  const ctf::SessionId session = sessions.value().front().session;
  (void)client.value().close();
  return session;
}

}  // namespace

CTF_TEST(multiprocess, real_processes_transfer_verify_and_stop_cleanly) {
  TempDir directory("multiprocess-basic");
  const std::filesystem::path config = write_config(directory, false, 4194304ULL);
  std::optional<Coordinator> coordinator = start_coordinator(ctf_ctx, config);
  CTF_REQUIRE(coordinator.has_value());
  CTF_EXPECT_EQ(coordinator->incarnation, 1ULL);

  std::optional<Sink> sink =
      start_sink(ctf_ctx, coordinator->port, directory.path() / "destination", 2);
  CTF_REQUIRE(sink.has_value());

  std::optional<ChildProcess> sender = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(coordinator->port, sink->port, ctf::CheckpointGeneration(1), 2, 32U * 1024U));
  CTF_REQUIRE(sender.has_value());
  const std::optional<int> exit_code = sender->wait(60);
  CTF_REQUIRE(exit_code.has_value());
  CTF_EXPECT_EQ(exit_code.value(), 0);

  const std::optional<int> sink_exit = sink->process.wait(30);
  CTF_REQUIRE(sink_exit.has_value());
  CTF_EXPECT_EQ(sink_exit.value(), 0);
  CTF_EXPECT(sink->process.output().find("\"shards_verified\":2") != std::string::npos);

  ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, coordinator->port, "observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<std::vector<ctf::SessionSummary>> sessions = client.value().list_sessions(std::nullopt, 8);
  CTF_REQUIRE_OK(sessions.status());
  CTF_REQUIRE_EQ(sessions.value().size(), static_cast<std::size_t>(1));
  ctf::Result<ctf::SessionView> view = client.value().view_session(sessions.value().front().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().evidence, ctf::EvidenceLevel::VerifiedAtDestination);
  CTF_EXPECT_EQ(view.value().durability, ctf::DurabilityStatus::NotEstablished);
  CTF_EXPECT(!view.value().durable_checkpoint_success());
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_OK(client.value().check_invariants());

  // The operator stops the coordinator over the protocol; it must exit cleanly.
  CTF_REQUIRE_OK(client.value().request_shutdown());
  (void)client.value().close();
  const std::optional<int> coordinator_exit = coordinator->process.wait(30);
  CTF_REQUIRE(coordinator_exit.has_value());
  CTF_EXPECT_EQ(coordinator_exit.value(), 0);
  CTF_EXPECT(coordinator->process.output().find("CTF-STOPPED") != std::string::npos);
}

CTF_TEST(multiprocess, sender_killed_mid_transfer_never_reports_success) {
  TempDir directory("multiprocess-sender-death");
  const std::filesystem::path config = write_config(directory, false, 128U * 1024U);
  std::optional<Coordinator> coordinator = start_coordinator(ctf_ctx, config);
  CTF_REQUIRE(coordinator.has_value());
  std::optional<Sink> sink =
      start_sink(ctf_ctx, coordinator->port, directory.path() / "destination", 1);
  CTF_REQUIRE(sink.has_value());

  // 4 MiB of traffic: even at the class ceiling the sender cannot finish before
  // the kill lands, so the fabric is observed mid-transfer.
  std::optional<ChildProcess> sender = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(coordinator->port, sink->port, ctf::CheckpointGeneration(1), 4,
                       1U * 1024U * 1024U, "BestEffort"));
  CTF_REQUIRE(sender.has_value());
  CTF_REQUIRE(wait_for_transfer(ctf_ctx, coordinator->port));
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  const bool killed = sender->kill();
  CTF_EXPECT(killed);

  ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, coordinator->port, "observer");
  CTF_REQUIRE_OK(client.status());
  const ctf::SessionId session = single_session(ctf_ctx, coordinator->port);
  ctf::Result<ctf::SessionView> view = client.value().view_session(session);
  CTF_REQUIRE_OK(view.status());
  // The fabric saw some traffic, but nothing is verified and nothing is complete.
  CTF_EXPECT(view.value().state != ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT(!accounting.value().at_baseline());

  // The coordinator's own view of the killed sender's authority is still exact.
  CTF_EXPECT_OK(client.value().check_invariants());
  const ctf::SessionView snapshot_view = view.value();
  const ctf::CommandFence fence = client.value().current_fence(
      snapshot_view.workload, snapshot_view.checkpoint_generation);
  CTF_REQUIRE_OK(client.value().cancel_session(session, fence, ctf::ReasonCode::CancelledByOperator,
                                               "sender process was killed"));
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_OK(client.value().check_invariants());
  CTF_REQUIRE_OK(client.value().request_shutdown());
  (void)client.value().close();
  (void)sink->process.kill();
  (void)coordinator->process.wait(30);
}

CTF_TEST(multiprocess, sink_death_before_acknowledgement_is_not_success) {
  TempDir directory("multiprocess-sink-death");
  const std::filesystem::path config = write_config(directory, false, 4194304ULL);
  std::optional<Coordinator> coordinator = start_coordinator(ctf_ctx, config);
  CTF_REQUIRE(coordinator.has_value());
  // The sink dies after 16 KiB, before acknowledging anything further.
  std::optional<Sink> sink =
      start_sink(ctf_ctx, coordinator->port, directory.path() / "destination", 1, 16U * 1024U);
  CTF_REQUIRE(sink.has_value());

  std::optional<ChildProcess> sender = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(coordinator->port, sink->port, ctf::CheckpointGeneration(1), 1, 64U * 1024U));
  CTF_REQUIRE(sender.has_value());
  const std::optional<int> sender_exit = sender->wait(60);
  CTF_REQUIRE(sender_exit.has_value());
  CTF_EXPECT(sender_exit.value() != 0);
  const std::optional<int> sink_exit = sink->process.wait(30);
  CTF_REQUIRE(sink_exit.has_value());
  CTF_EXPECT_EQ(sink_exit.value(), 9);
  CTF_EXPECT(sink->process.output().find("died after") != std::string::npos);

  ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, coordinator->port, "observer");
  CTF_REQUIRE_OK(client.status());
  const ctf::SessionId session = single_session(ctf_ctx, coordinator->port);
  ctf::Result<ctf::SessionView> view = client.value().view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT(view.value().state != ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT(accounting.value().bytes_wasted + accounting.value().bytes_unproven +
                 accounting.value().granted_outstanding_bytes >
             0ULL);
  CTF_EXPECT_OK(client.value().check_invariants());

  const ctf::SessionView snapshot_view = view.value();
  const ctf::CommandFence fence = client.value().current_fence(
      snapshot_view.workload, snapshot_view.checkpoint_generation);
  CTF_REQUIRE_OK(client.value().cancel_session(session, fence, ctf::ReasonCode::CancelledByOperator,
                                               "sink died before acknowledging"));
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT_OK(client.value().check_invariants());
  CTF_REQUIRE_OK(client.value().request_shutdown());
  (void)client.value().close();
  (void)coordinator->process.wait(30);
}

CTF_TEST(multiprocess, truncated_transfer_and_supersession_across_processes) {
  TempDir directory("multiprocess-truncate");
  const std::filesystem::path config = write_config(directory, false, 4194304ULL);
  std::optional<Coordinator> coordinator = start_coordinator(ctf_ctx, config);
  CTF_REQUIRE(coordinator.has_value());
  std::optional<Sink> sink =
      start_sink(ctf_ctx, coordinator->port, directory.path() / "destination", 2);
  CTF_REQUIRE(sink.has_value());

  std::optional<ChildProcess> truncated = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(coordinator->port, sink->port, ctf::CheckpointGeneration(1), 1, 64U * 1024U,
                       "TrainingBulk", {"--truncate-first-shard"}));
  CTF_REQUIRE(truncated.has_value());
  const std::optional<int> truncated_exit = truncated->wait(60);
  CTF_REQUIRE(truncated_exit.has_value());
  CTF_EXPECT_EQ(truncated_exit.value(), 8);

  ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, coordinator->port, "observer");
  CTF_REQUIRE_OK(client.status());
  const ctf::SessionId truncated_session = single_session(ctf_ctx, coordinator->port);
  ctf::Result<ctf::SessionView> view = client.value().view_session(truncated_session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT(view.value().state != ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().bytes_wasted > 0);
  CTF_EXPECT(accounting.value().conserves());

  // A newer generation supersedes the unresolved session deterministically.
  std::optional<ChildProcess> newer = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(coordinator->port, sink->port, ctf::CheckpointGeneration(2), 1, 32U * 1024U));
  CTF_REQUIRE(newer.has_value());
  const std::optional<int> newer_exit = newer->wait(60);
  CTF_REQUIRE(newer_exit.has_value());
  CTF_EXPECT_EQ(newer_exit.value(), 0);
  view = client.value().view_session(truncated_session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Superseded);
  CTF_REQUIRE(view.value().superseded_by.has_value());

  // Replaying the superseded generation is refused by the coordinator.
  std::optional<ChildProcess> replay = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(coordinator->port, sink->port, ctf::CheckpointGeneration(1), 1, 32U * 1024U));
  CTF_REQUIRE(replay.has_value());
  const std::optional<int> replay_exit = replay->wait(60);
  CTF_REQUIRE(replay_exit.has_value());
  CTF_EXPECT_EQ(replay_exit.value(), 2);
  CTF_EXPECT(replay->output().find("CheckpointGenerationStale") != std::string::npos);
  CTF_EXPECT_OK(client.value().check_invariants());
  CTF_REQUIRE_OK(client.value().request_shutdown());
  (void)client.value().close();
  (void)sink->process.kill();
  (void)coordinator->process.wait(30);
}

CTF_TEST(multiprocess, coordinator_crash_and_restart_fences_the_old_incarnation) {
  TempDir directory("multiprocess-restart");
  const std::filesystem::path config = write_config(directory, true, 128U * 1024U);
  std::optional<Coordinator> first = start_coordinator(ctf_ctx, config);
  CTF_REQUIRE(first.has_value());
  CTF_EXPECT_EQ(first->incarnation, 1ULL);

  std::optional<Sink> sink =
      start_sink(ctf_ctx, first->port, directory.path() / "destination", 1);
  CTF_REQUIRE(sink.has_value());
  std::optional<ChildProcess> sender = ChildProcess::start(
      ctf::test::app_path("ctf-agent"),
      sender_arguments(first->port, sink->port, ctf::CheckpointGeneration(1), 4,
                       1U * 1024U * 1024U, "BestEffort"));
  CTF_REQUIRE(sender.has_value());
  CTF_REQUIRE(wait_for_transfer(ctf_ctx, first->port));
  const ctf::SessionId session = single_session(ctf_ctx, first->port);

  // Hard kill: no graceful shutdown, no final snapshot.
  CTF_EXPECT(first->process.kill());

  std::optional<Coordinator> second = start_coordinator(ctf_ctx, config);
  CTF_REQUIRE(second.has_value());
  CTF_EXPECT_EQ(second->incarnation, 2ULL);

  ctf::Result<ctf::CoordinatorClient> client = connect_client(ctf_ctx, second->port, "after-crash");
  CTF_REQUIRE_OK(client.status());
  CTF_EXPECT_EQ(client.value().hello().epoch.incarnation.value(), 2ULL);
  ctf::Result<ctf::SessionView> view = client.value().view_session(session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::RevalidationRequired);
  CTF_EXPECT(!view.value().stale_reason.empty());
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_EQ(accounting.value().active_attempts, 0U);
  CTF_EXPECT_OK(client.value().check_invariants());

  // The old incarnation's authority is refused even though the process is gone.
  ctf::CommandFence stale =
      client.value().current_fence(view.value().workload, view.value().checkpoint_generation);
  const ctf::CommandFence fresh = stale;
  stale.epoch = ctf::CoordinatorEpoch{ctf::IncarnationId(1), ctf::EpochTerm(1)};
  // Credit may only be requested by a sender connection, so the stale-epoch probe
  // is issued from one: the refusal must come from the fence, not from the role.
  ctf::Result<ctf::CoordinatorClient> sender_client = connect_client(
      ctf_ctx, second->port, "post-crash-sender", ctf::wire::ClientKind::Sender);
  CTF_REQUIRE_OK(sender_client.status());
  ctf::Result<ctf::WaveOutcome> refused =
      sender_client.value().request_wave(session, ctf::ShardIndex(0), stale);
  CTF_EXPECT_EQ(refused.status().code(), ctf::ErrorCode::ForeignEpoch);
  CTF_REQUIRE_OK(sender_client.value().close());

  // The restarted coordinator can revalidate the session under fresh authority.
  ctf::Result<ctf::AdmissionDecision> revalidated =
      client.value().revalidate_session(session, fresh);
  CTF_REQUIRE_OK(revalidated.status());
  CTF_EXPECT(revalidated.value().admitted());
  CTF_REQUIRE_OK(client.value().cancel_session(
      session, client.value().current_fence(view.value().workload, view.value().checkpoint_generation),
      ctf::ReasonCode::CancelledByOperator, "crash recovery proof complete"));
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_OK(client.value().check_invariants());

  CTF_REQUIRE_OK(client.value().request_shutdown());
  (void)client.value().close();
  (void)sender->kill();
  (void)sink->process.kill();
  (void)second->process.wait(30);
}

CTF_TEST(multiprocess, repeated_restarts_advance_the_incarnation) {
  TempDir directory("multiprocess-incarnations");
  const std::filesystem::path config = write_config(directory, true, 4194304ULL);
  for (std::uint64_t expected = 1; expected <= 3; ++expected) {
    std::optional<Coordinator> coordinator = start_coordinator(ctf_ctx, config);
    CTF_REQUIRE(coordinator.has_value());
    CTF_EXPECT_EQ(coordinator->incarnation, expected);
    ctf::Result<ctf::CoordinatorClient> client =
        connect_client(ctf_ctx, coordinator->port, "incarnation-watch");
    CTF_REQUIRE_OK(client.status());
    CTF_EXPECT_EQ(client.value().hello().epoch.incarnation.value(), expected);
    CTF_EXPECT_OK(client.value().check_invariants());
    (void)client.value().close();
    CTF_EXPECT(coordinator->process.kill());
  }
}

CTF_MAIN()
