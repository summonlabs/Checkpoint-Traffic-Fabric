// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Integration proofs: a real coordinator service, a real sender process role,
// and a real sink role exchanging framed TCP over loopback. Everything here is
// REAL loopback transport with SYNTHETIC checkpoint content and a SYNTHETIC
// destination directory.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>

#include "ctf/agent.hpp"
#include "ctf/client.hpp"
#include "ctf/report.hpp"
#include "ctf/service.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

namespace {

using ctf::test::TempDir;

/// Service plus sink running on background threads for one scenario.
class Scenario {
 public:
  Scenario(ctf::test::Context& ctf_ctx, ctf::CoordinatorConfig config,
           std::uint32_t shard_count, std::uint64_t die_after_bytes = 0, bool verify = true)
      : service_(std::move(config), clock_) {
    CTF_REQUIRE_OK(service_.start());
    sink_.coordinator_host = "127.0.0.1";
    sink_.coordinator_port = service_.port();
    sink_.directory = directory_.path() / "destination";
    sink_.expected_shards = shard_count;
    sink_.die_after_bytes = die_after_bytes;
    sink_.verify = verify;
    sink_.identity = "integration-sink";
    sink_.limits = service_.engine().limits();
    sink_thread_ = std::thread([this] {
      ctf::CheckpointSink sink(sink_, clock_);
      if (!sink.start(sink_stop_).ok()) {
        sink_started_.store(false);
        return;
      }
      sink_port_.store(sink.port());
      sink_started_.store(true);
      ctf::Result<ctf::SinkResult> result = sink.run(sink_stop_);
      sink_result_ = result.ok() ? result.value() : ctf::SinkResult{};
      sink_done_.store(true);
    });
    for (int attempt = 0; attempt < 500 && !sink_started_.load(); ++attempt) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CTF_REQUIRE(sink_started_.load());
  }

  ~Scenario() {
    sink_stop_.request_stop();
    if (sink_thread_.joinable()) {
      sink_thread_.join();
    }
    (void)service_.shutdown();
  }

  Scenario(const Scenario&) = delete;
  Scenario& operator=(const Scenario&) = delete;

  [[nodiscard]] std::uint16_t coordinator_port() const { return service_.port(); }
  [[nodiscard]] std::uint16_t sink_port() const { return sink_port_.load(); }
  [[nodiscard]] ctf::FabricEngine& engine() { return service_.engine(); }
  /// Waits for the sink thread to finish, then reports what it observed.
  [[nodiscard]] ctf::SinkResult wait_for_sink(std::uint32_t max_seconds = 30) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(max_seconds);
    while (std::chrono::steady_clock::now() < deadline && !sink_done_.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    sink_stop_.request_stop();
    if (sink_thread_.joinable()) {
      sink_thread_.join();
    }
    return sink_result_;
  }
  [[nodiscard]] const TempDir& directory() const { return directory_; }

  [[nodiscard]] ctf::Result<ctf::CoordinatorClient> client(const std::string& identity) {
    ctf::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = service_.port();
    config.kind = ctf::wire::ClientKind::Operator;
    config.identity = identity;
    return ctf::CoordinatorClient::connect(config, stop_);
  }

  [[nodiscard]] ctf::SenderConfig sender_config(std::uint32_t shards, std::uint64_t shard_bytes,
                                                ctf::CheckpointGeneration generation,
                                                ctf::IsolationClass isolation =
                                                    ctf::IsolationClass::TrainingBulk,
                                                const std::string& checkpoint =
                                                    ctf::test::kCheckpointText) {
    ctf::SenderConfig config;
    config.coordinator_host = "127.0.0.1";
    config.coordinator_port = service_.port();
    config.sink_host = "127.0.0.1";
    config.sink_port = sink_port_.load();
    config.workload = ctf::test::default_workload();
    config.checkpoint = ctf::CheckpointId::parse(checkpoint).value();
    config.checkpoint_generation = generation;
    config.isolation = isolation;
    config.destination = ctf::DestinationClass::SyntheticLab;
    config.shard_count = shards;
    config.shard_bytes = shard_bytes;
    config.identity = "integration-sender";
    config.limits = service_.engine().limits();
    return config;
  }

  ctf::SteadyClock clock_;
  ctf::net::StopToken stop_;
  ctf::net::StopToken sink_stop_;
  TempDir directory_{"integration"};
  ctf::CoordinatorService service_;
  ctf::SinkConfig sink_;
  std::thread sink_thread_;
  std::atomic<bool> sink_started_{false};
  std::atomic<bool> sink_done_{false};
  std::atomic<std::uint16_t> sink_port_{0};
  ctf::SinkResult sink_result_;
};

[[nodiscard]] ctf::CoordinatorConfig integration_config(bool persist = false,
                                                       std::filesystem::path data_directory = {}) {
  ctf::CoordinatorConfig config = ctf::config::default_coordinator_config();
  config.persist = persist;
  config.data_directory = std::move(data_directory);
  config.worker_threads = 4;
  config.label = "integration-coordinator";
  return config;
}

}  // namespace

CTF_TEST(integration, end_to_end_transfer_and_verification) {
  Scenario scenario(ctf_ctx, integration_config(), 2);
  ctf::CheckpointSender sender(scenario.sender_config(2, 64U * 1024U, ctf::CheckpointGeneration(1)),
                               scenario.clock_);
  ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
  CTF_REQUIRE_OK(result.status());
  CTF_EXPECT_EQ(result.value().exit_code, 0);
  CTF_EXPECT_EQ(result.value().decision, ctf::DecisionKind::Admit);
  CTF_EXPECT_EQ(result.value().shards_completed, 2U);
  CTF_EXPECT_EQ(result.value().bytes_sent, 128U * 1024U);

  const ctf::SinkResult sink = scenario.wait_for_sink();
  CTF_EXPECT_EQ(sink.shards_received, 2U);
  CTF_EXPECT_EQ(sink.shards_verified, 2U);
  CTF_EXPECT_EQ(sink.bytes_received, 128U * 1024U);

  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<ctf::SessionView> view = client.value().view_session(result.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().evidence, ctf::EvidenceLevel::VerifiedAtDestination);
  CTF_EXPECT_EQ(view.value().durability, ctf::DurabilityStatus::NotEstablished);
  CTF_EXPECT(!view.value().durable_checkpoint_success());
  CTF_EXPECT_EQ(view.value().verified_bytes, 128U * 1024U);

  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT_EQ(accounting.value().sessions_completed, 1ULL);
  CTF_EXPECT_EQ(accounting.value().bytes_verified, 128U * 1024U);
  CTF_EXPECT_OK(client.value().check_invariants());
  CTF_EXPECT_OK(client.value().close());
}

CTF_TEST(integration, bulk_traffic_stays_within_the_isolation_ceiling) {
  ctf::CoordinatorConfig config = integration_config();
  // A deliberately small ceiling so a real transfer can be measured by wall clock.
  for (ctf::IsolationEnvelopeConfig& envelope : config.policy.envelopes) {
    if (envelope.isolation == ctf::IsolationClass::BestEffort) {
      envelope.ceiling_bps = 512U * 1024U;
      envelope.burst_window_ns = 100 * ctf::kNanosPerMillisecond;
      envelope.max_in_flight_sessions = 2;
    }
  }
  config.policy.default_deadline_ns = 30 * ctf::kNanosPerSecond;
  for (ctf::WorkloadContract& contract : config.contracts) {
    contract.isolation = ctf::IsolationClass::BestEffort;
    contract.ceiling_bps = 512U * 1024U;
    contract.deadline_budget_ns = 30 * ctf::kNanosPerSecond;
  }
  Scenario scenario(ctf_ctx, config, 4);
  const std::uint64_t total_bytes = 4U * 64U * 1024U;  // 256 KiB: half a second at the ceiling
  ctf::SenderConfig sender_config =
      scenario.sender_config(4, 64U * 1024U, ctf::CheckpointGeneration(1),
                             ctf::IsolationClass::BestEffort);
  ctf::CheckpointSender sender(sender_config, scenario.clock_);
  const std::int64_t started = scenario.clock_.now();
  ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
  const std::int64_t elapsed = scenario.clock_.now() - started;
  CTF_REQUIRE_OK(result.status());
  std::printf("    sender: exit=%d bytes=%llu message=%s\n", result.value().exit_code,
              static_cast<unsigned long long>(result.value().bytes_sent),
              result.value().message.c_str());
  CTF_EXPECT_EQ(result.value().exit_code, 0);
  CTF_EXPECT_EQ(result.value().bytes_sent, total_bytes);

  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT_EQ(accounting.value().bytes_transferred, total_bytes);

  // The fabric authorised at most ceiling * elapsed + one burst. Wall-clock
  // measurement only ever makes the sender slower, so this is an upper bound.
  const std::uint64_t ceiling = 512U * 1024U;
  const std::uint64_t allowed =
      (ceiling / static_cast<std::uint64_t>(ctf::kNanosPerSecond)) * static_cast<std::uint64_t>(elapsed) +
      ((ceiling % static_cast<std::uint64_t>(ctf::kNanosPerSecond)) *
       static_cast<std::uint64_t>(elapsed)) /
          static_cast<std::uint64_t>(ctf::kNanosPerSecond);
  std::printf("    measured: %llu bytes in %.3f s at ceiling %llu B/s\n",
              static_cast<unsigned long long>(total_bytes),
              static_cast<double>(elapsed) / 1.0e9,
              static_cast<unsigned long long>(ceiling));
  const std::uint64_t burst = ceiling / 10U;  // 100 ms burst window
  // Admission authorises the whole checkpoint up front; the ceiling governs the
  // traffic that actually entered the fabric.
  CTF_EXPECT(accounting.value().bytes_transferred <= allowed + burst + (16U * 1024U));
  CTF_EXPECT_OK(client.value().check_invariants());
}

CTF_TEST(integration, newer_generation_supersedes_over_the_wire) {
  Scenario scenario(ctf_ctx, integration_config(), 2);
  // The older generation is admitted and then abandoned mid-transfer, so it is
  // still active when the newer generation arrives.
  ctf::SenderConfig first_config =
      scenario.sender_config(1, 64U * 1024U, ctf::CheckpointGeneration(1));
  first_config.die_after_bytes = 8U * 1024U;
  ctf::CheckpointSender first(first_config, scenario.clock_);
  ctf::Result<ctf::SenderResult> first_result = first.run(scenario.stop_);
  CTF_REQUIRE_OK(first_result.status());
  CTF_EXPECT_EQ(first_result.value().exit_code, 9);

  ctf::CheckpointSender second(scenario.sender_config(1, 32U * 1024U, ctf::CheckpointGeneration(2)),
                               scenario.clock_);
  ctf::Result<ctf::SenderResult> second_result = second.run(scenario.stop_);
  CTF_REQUIRE_OK(second_result.status());
  CTF_EXPECT_EQ(second_result.value().exit_code, 0);

  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<ctf::SessionView> older = client.value().view_session(first_result.value().session);
  CTF_REQUIRE_OK(older.status());
  CTF_EXPECT_EQ(older.value().state, ctf::SessionState::Superseded);
  ctf::Result<ctf::SessionView> newer = client.value().view_session(second_result.value().session);
  CTF_REQUIRE_OK(newer.status());
  CTF_EXPECT_EQ(newer.value().state, ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(newer.value().checkpoint_generation.value(), 2ULL);

  // Replaying the older generation after the newer one completed is refused.
  ctf::CheckpointSender replay(scenario.sender_config(1, 32U * 1024U, ctf::CheckpointGeneration(1)),
                               scenario.clock_);
  ctf::Result<ctf::SenderResult> replay_result = replay.run(scenario.stop_);
  CTF_REQUIRE_OK(replay_result.status());
  CTF_EXPECT_EQ(replay_result.value().decision, ctf::DecisionKind::Deny);
  CTF_EXPECT_EQ(replay_result.value().reason, ctf::ReasonCode::CheckpointGenerationStale);
  CTF_EXPECT_EQ(replay_result.value().exit_code, 2);
  CTF_EXPECT_OK(client.value().check_invariants());
}

CTF_TEST(integration, ambiguous_destination_outcome_is_explicit) {
  // The sink refuses to verify, so it reports an ambiguous outcome.
  Scenario scenario(ctf_ctx, integration_config(), 1, 0, false);
  ctf::CheckpointSender sender(scenario.sender_config(1, 32U * 1024U, ctf::CheckpointGeneration(1)),
                               scenario.clock_);
  ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
  CTF_REQUIRE_OK(result.status());
  CTF_EXPECT_EQ(result.value().exit_code, 0);

  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<ctf::SessionView> view = client.value().view_session(result.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Transferring);
  CTF_EXPECT_EQ(view.value().shards_ambiguous, 1U);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  CTF_EXPECT(!view.value().durable_checkpoint_success());
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT(!accounting.value().at_baseline());
  // Arrival was acknowledged, so those bytes are transferred; they are simply
  // not verified at the destination. Nothing is unproven and nothing is durable.
  CTF_EXPECT_EQ(accounting.value().bytes_transferred, 32U * 1024U);
  CTF_EXPECT_EQ(accounting.value().bytes_unproven, 0ULL);
  CTF_EXPECT_EQ(accounting.value().bytes_verified, 0ULL);

  // Cancelling the unresolved session closes accounting to baseline.
  const ctf::SessionView session = view.value();
  const ctf::CommandFence fence = client.value().current_fence(
      session.workload, session.checkpoint_generation);
  CTF_REQUIRE_OK(client.value().cancel_session(result.value().session, fence,
                                               ctf::ReasonCode::CancelledByOperator,
                                               "ambiguous outcome accepted as unresolved"));
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_OK(client.value().check_invariants());
}

CTF_TEST(integration, truncated_transfer_is_reported_and_never_completes) {
  Scenario scenario(ctf_ctx, integration_config(), 1);
  ctf::SenderConfig sender_config =
      scenario.sender_config(1, 32U * 1024U, ctf::CheckpointGeneration(1));
  sender_config.truncate_first_shard = true;
  ctf::CheckpointSender sender(sender_config, scenario.clock_);
  ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
  CTF_REQUIRE_OK(result.status());
  CTF_EXPECT_EQ(result.value().exit_code, 8);

  const ctf::SinkResult sink = scenario.wait_for_sink();
  CTF_EXPECT_EQ(sink.shards_truncated, 1U);
  CTF_EXPECT_EQ(sink.shards_verified, 0U);

  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<ctf::SessionView> view = client.value().view_session(result.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT(view.value().state != ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  CTF_EXPECT_EQ(view.value().durability, ctf::DurabilityStatus::NotEstablished);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().bytes_wasted > 0);
  CTF_EXPECT(accounting.value().conserves());

  const ctf::SessionView session = view.value();
  CTF_REQUIRE_OK(client.value().cancel_session(
      result.value().session,
      client.value().current_fence(session.workload, session.checkpoint_generation),
      ctf::ReasonCode::CancelledByOperator, "truncated transfer abandoned"));
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT_OK(client.value().check_invariants());
}

CTF_TEST(integration, sink_death_before_acknowledgement_never_becomes_success) {
  Scenario scenario(ctf_ctx, integration_config(), 1, 16U * 1024U);
  ctf::CheckpointSender sender(scenario.sender_config(1, 64U * 1024U, ctf::CheckpointGeneration(1)),
                               scenario.clock_);
  ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
  CTF_REQUIRE_OK(result.status());
  CTF_EXPECT(result.value().exit_code != 0);
  CTF_EXPECT_EQ(scenario.wait_for_sink().exit_code, 9);

  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
  CTF_REQUIRE_OK(client.status());
  ctf::Result<ctf::SessionView> view = client.value().view_session(result.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT(view.value().state != ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT(!accounting.value().at_baseline());

  const ctf::SessionView session = view.value();
  CTF_REQUIRE_OK(client.value().cancel_session(
      result.value().session,
      client.value().current_fence(session.workload, session.checkpoint_generation),
      ctf::ReasonCode::CancelledByOperator, "sink died before acknowledging"));
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_OK(client.value().check_invariants());
}

CTF_TEST(integration, operator_cancellation_closes_accounting) {
  Scenario scenario(ctf_ctx, integration_config(), 1);
  ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-operator");
  CTF_REQUIRE_OK(client.status());

  ctf::SenderConfig sender_config =
      scenario.sender_config(1, 64U * 1024U, ctf::CheckpointGeneration(1));
  sender_config.die_after_bytes = 16U * 1024U;  // stop the sender mid-transfer
  ctf::CheckpointSender sender(sender_config, scenario.clock_);
  ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
  CTF_REQUIRE_OK(result.status());
  CTF_EXPECT_EQ(result.value().exit_code, 9);

  ctf::Result<ctf::SessionView> view = client.value().view_session(result.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT(view.value().state != ctf::SessionState::TrafficSessionComplete);
  CTF_EXPECT_EQ(view.value().verified_bytes, 0ULL);
  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(!accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());

  const ctf::SessionView session = view.value();
  const ctf::CommandFence fence = client.value().current_fence(
      session.workload, session.checkpoint_generation);
  CTF_REQUIRE_OK(client.value().cancel_session(result.value().session, fence,
                                               ctf::ReasonCode::CancelledByOperator,
                                               "operator cancelled a stalled transfer"));
  view = client.value().view_session(result.value().session);
  CTF_REQUIRE_OK(view.status());
  CTF_EXPECT_EQ(view.value().state, ctf::SessionState::Cancelled);
  accounting = client.value().accounting();
  CTF_REQUIRE_OK(accounting.status());
  CTF_EXPECT(accounting.value().at_baseline());
  CTF_EXPECT(accounting.value().conserves());
  CTF_EXPECT_EQ(accounting.value().sessions_cancelled, 1ULL);
  CTF_EXPECT_OK(client.value().check_invariants());

  // A cancelled session refuses further evidence deterministically.
  ctf::wire::AmbiguityRequest ambiguity;
  ambiguity.session = result.value().session;
  ambiguity.cause = "late ambiguity report";
  ambiguity.fence = fence;
  const ctf::Status refused = client.value().report_ambiguous(ambiguity);
  CTF_EXPECT_EQ(refused.code(), ctf::ErrorCode::InvalidStateTransition);
  CTF_EXPECT_OK(client.value().check_invariants());
}

CTF_TEST(integration, repeated_service_lifecycle_is_stable) {
  for (int cycle = 0; cycle < 5; ++cycle) {
    Scenario scenario(ctf_ctx, integration_config(), 1);
    ctf::CheckpointSender sender(
        scenario.sender_config(1, 16U * 1024U, ctf::CheckpointGeneration(1)), scenario.clock_);
    ctf::Result<ctf::SenderResult> result = sender.run(scenario.stop_);
    CTF_REQUIRE_OK(result.status());
    CTF_EXPECT_EQ(result.value().exit_code, 0);
    ctf::Result<ctf::CoordinatorClient> client = scenario.client("integration-observer");
    CTF_REQUIRE_OK(client.status());
    CTF_EXPECT_OK(client.value().check_invariants());
    ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
    CTF_REQUIRE_OK(accounting.status());
    CTF_EXPECT(accounting.value().at_baseline());
    CTF_EXPECT(accounting.value().conserves());
  }
}

CTF_MAIN()
