// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Concurrency suite: real CoordinatorService processes with real framed-TCP
// clients, driven by threads that are released together through
// std::promise/std::shared_future barriers.
//
// Nothing here uses a timeout: threads are released by an explicit barrier and
// joined unconditionally, so a thread that never finishes is a hang to
// diagnose, not something hidden behind a clock.
//
// Worker threads never touch the test harness: they record outcomes in their own
// slot and the main thread asserts on them, so a failure is always reported by
// the thread that owns the Context.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ctf/client.hpp"
#include "ctf/service.hpp"
#include "fixtures.hpp"
#include "test_harness.hpp"

namespace {

using ctf::ErrorCode;
using ctf::ReasonCode;
using ctf::Status;

constexpr std::size_t kClientThreads = 8;

/// Every code a caller may legitimately observe for a command that lost a race,
/// hit a fence, or arrived during shutdown. Anything outside this set is a
/// contract violation, not an interleaving.
[[nodiscard]] bool documented_refusal(ErrorCode code) {
  switch (code) {
    case ErrorCode::ShuttingDown:
    case ErrorCode::PeerClosed:
    case ErrorCode::ConnectionRefused:
    case ErrorCode::InvalidStateTransition:
    case ErrorCode::NotFound:
    case ErrorCode::AlreadyExists:
    case ErrorCode::Superseded:
    case ErrorCode::ReplayDetected:
    case ErrorCode::StaleAttempt:
    case ErrorCode::StaleEvidence:
    case ErrorCode::StaleEpoch:
    case ErrorCode::StaleCheckpointGeneration:
    case ErrorCode::StalePolicyGeneration:
    case ErrorCode::StaleTopologyGeneration:
    case ErrorCode::StaleContractGeneration:
    case ErrorCode::RevalidationRequired:
    case ErrorCode::Deferred:
    case ErrorCode::DeadlineUnreachable:
    case ErrorCode::AmbiguousOutcome:
    case ErrorCode::VerificationMismatch:
    case ErrorCode::CapacityExceeded:
    case ErrorCode::ResourceExhausted:
    case ErrorCode::NotReady:
    case ErrorCode::NotAuthorized:
    case ErrorCode::NotDurable:
    case ErrorCode::SequenceViolation:
    case ErrorCode::IoFailure:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] const char* code_text(ErrorCode code) { return ctf::to_string(code); }

[[nodiscard]] ctf::CheckpointId checkpoint_id(std::uint32_t index) {
  std::string digits = std::to_string(index);
  while (digits.size() < 12) {
    digits.insert(digits.begin(), '0');
  }
  return ctf::CheckpointId::parse("dddddddd-2222-4333-8444-" + digits).value();
}

[[nodiscard]] ctf::CommandId command_id(std::uint64_t suffix) {
  std::string digits = std::to_string(suffix);
  while (digits.size() < 12) {
    digits.insert(digits.begin(), '0');
  }
  return ctf::CommandId::parse("99999999-1111-4222-8333-" + digits).value();
}

/// Service configuration used by every test in this suite: loopback, ephemeral
/// port, four workers, no persistence, generous but real bounds.
[[nodiscard]] ctf::CoordinatorConfig make_service_config() {
  ctf::CoordinatorConfig config = ctf::test::service_config(false, "concurrency-suite");
  config.bind_host = "127.0.0.1";
  config.port = 0;
  config.worker_threads = 4;
  config.persist = false;
  config.identity_seed = 0x5EEDULL;
  config.policy.max_sessions = 256;
  config.policy.max_wave_width = 4;
  config.policy.max_attempts_in_flight = 256;
  config.policy.retained_history = 64;
  config.contracts[0].max_in_flight_sessions = 32;
  config.contracts[0].max_shards_per_wave = 4;
  ctf::WorkloadContract secondary;
  secondary.workload = ctf::test::second_workload();
  secondary.generation = ctf::WorkloadContractGeneration(1);
  secondary.isolation = ctf::IsolationClass::ServingLatency;
  secondary.ceiling_bps = 8ULL * 1024 * 1024;
  secondary.max_in_flight_sessions = 16;
  secondary.max_shards_per_wave = 4;
  secondary.allow_supersession = true;
  secondary.deadline_budget_ns = 120 * ctf::kNanosPerSecond;
  config.contracts.push_back(secondary);
  for (ctf::PathClass& path : config.topology.path_classes) {
    path.capacity_bps = 1ULL << 34;
  }
  return config;
}

[[nodiscard]] ctf::Result<ctf::CoordinatorClient> connect_client(
    const ctf::CoordinatorService& service, const std::string& identity,
    const ctf::net::StopToken& stop) {
  ctf::ClientConfig config;
  config.host = "127.0.0.1";
  config.port = service.port();
  config.kind = ctf::wire::ClientKind::Sender;
  config.identity = identity;
  return ctf::CoordinatorClient::connect(config, stop);
}

[[nodiscard]] ctf::SessionRequest make_request(const ctf::CoordinatorClient& client,
                                               ctf::WorkloadId workload,
                                               const ctf::CheckpointId& checkpoint,
                                               ctf::CheckpointGeneration generation,
                                               ctf::CommandId command, std::uint32_t shards,
                                               std::uint64_t shard_bytes,
                                               std::uint64_t digest_salt) {
  const ctf::CommandFence fence = client.current_fence(workload, generation);
  ctf::SessionRequest request;
  request.command = command;
  request.workload = workload;
  request.contract_generation = fence.contract_generation;
  request.policy_generation = client.hello().policy_generation;
  request.topology_generation = client.hello().topology_generation;
  request.checkpoint = checkpoint;
  request.checkpoint_generation = generation;
  request.requested_isolation = ctf::IsolationClass::TrainingBulk;
  request.destination = ctf::DestinationClass::SyntheticLab;
  request.manifest.checkpoint = checkpoint;
  request.manifest.generation = generation;
  request.manifest.workload = workload;
  request.manifest.contract_generation = fence.contract_generation;
  for (std::uint32_t index = 0; index < shards; ++index) {
    ctf::ShardDescriptor shard;
    shard.index = ctf::ShardIndex(index);
    shard.declared_bytes = shard_bytes;
    shard.declared_digest = ctf::Digest(static_cast<std::uint32_t>(0x7000U + digest_salt + index),
                                        0xA000ULL + digest_salt + index);
    request.manifest.shards.push_back(shard);
    request.manifest.total_bytes += shard_bytes;
  }
  request.manifest.manifest_digest = ctf::compute_manifest_digest(request.manifest);
  return request;
}

/// Everything one worker thread observed. Written only by its owner, read by the
/// main thread after join (which is a happens-before edge).
struct WorkerOutcome {
  bool connected = false;
  std::string connect_error;
  std::vector<ErrorCode> codes;
  std::size_t operations = 0;
  std::size_t admitted = 0;
  std::size_t duplicate = 0;
  std::size_t refusals = 0;
  std::vector<ctf::SessionId> sessions;
  std::uint64_t bytes_admitted = 0;

  void note(const Status& status) {
    ++operations;
    if (!status.ok()) {
      note_code(status.code());
    }
  }

  void note_code(ErrorCode code) {
    codes.push_back(code);
    if (documented_refusal(code)) {
      ++refusals;
    }
  }
};

void expect_documented(ctf::test::Context& ctf_ctx, const WorkerOutcome& outcome,
                       const char* label) {
  for (const ErrorCode code : outcome.codes) {
    if (!documented_refusal(code)) {
      ctf_ctx.fail(__FILE__, __LINE__, std::string(label) + " observed undocumented refusal " +
                                           code_text(code));
    }
  }
}

/// One full client conversation: submit, take credit, move evidence, query.
void run_client_conversation(ctf::CoordinatorService& service, std::size_t index,
                             WorkerOutcome& outcome, const ctf::net::StopToken& stop,
                             std::shared_future<void> barrier) {
  barrier.wait();
  ctf::Result<ctf::CoordinatorClient> client =
      connect_client(service, "client-" + std::to_string(index), stop);
  if (!client.ok()) {
    outcome.connect_error = client.status().to_string();
    outcome.note_code(client.code());
    return;
  }
  outcome.connected = true;
  ctf::CoordinatorClient& connection = client.value();
  const ctf::WorkloadId workload =
      (index % 2U) == 0 ? ctf::test::default_workload() : ctf::test::second_workload();
  const ctf::CheckpointGeneration generation(1);
  const ctf::CheckpointId checkpoint = checkpoint_id(static_cast<std::uint32_t>(index));
  const ctf::SessionRequest request =
      make_request(connection, workload, checkpoint, generation,
                   command_id(1000 + static_cast<std::uint64_t>(index)), 2, 4096, index);
  outcome.bytes_admitted = request.manifest.total_bytes;
  const ctf::CommandFence fence = connection.current_fence(workload, generation);
  ctf::Result<ctf::AdmissionDecision> decision = connection.submit_session(request, fence);
  if (!decision.ok()) {
    outcome.note_code(decision.code());
    return;
  }
  if (decision.value().kind == ctf::DecisionKind::Admit && decision.value().reason == ReasonCode::Admitted) {
    ++outcome.admitted;
  } else if (decision.value().reason == ReasonCode::DuplicateCommand) {
    ++outcome.duplicate;
  }
  if (!decision.value().envelope.has_value()) {
    return;
  }
  const ctf::SessionId session = decision.value().session;
  outcome.sessions.push_back(session);
  for (std::uint32_t shard = 0; shard < 2; ++shard) {
    ctf::Result<ctf::WaveOutcome> wave =
        connection.request_wave(session, ctf::ShardIndex(shard), fence);
    if (!wave.ok()) {
      outcome.note_code(wave.code());
      continue;
    }
    if (!wave.value().granted) {
      continue;  // a documented deferral: no bytes may be sent
    }
    const ctf::WaveGrant grant = wave.value().grant.value();
    ctf::TransferEvidence transfer;
    transfer.session = session;
    transfer.attempt = grant.attempt;
    transfer.sequence = grant.sequence;
    transfer.shard = ctf::ShardIndex(shard);
    transfer.arrived_bytes = grant.max_bytes;
    transfer.arrived_digest = request.manifest.shards[shard].declared_digest;
    transfer.sink_acknowledged = true;
    outcome.note(connection.report_transfer(transfer, fence));
    ctf::Result<ctf::SessionView> view = connection.view_session(session);
    outcome.note(view.status());
    if (view.ok() && view.value().shards.size() > shard &&
        view.value().shards[shard].state == ctf::ShardState::Transferred) {
      ctf::VerificationEvidence verification;
      verification.session = session;
      verification.attempt = grant.attempt;
      verification.sequence = grant.sequence;
      verification.shard = ctf::ShardIndex(shard);
      verification.verified_bytes = request.manifest.shards[shard].declared_bytes;
      verification.verified_digest = request.manifest.shards[shard].declared_digest;
      verification.outcome = ctf::VerificationEvidence::Outcome::Verified;
      verification.verifier_identity = "concurrency-sink";
      outcome.note(connection.report_verification(verification, fence));
    }
  }
  outcome.note(connection.pause_session(session, fence, "concurrency pause"));
  outcome.note(connection.resume_session(session, fence));
  outcome.note(connection.view_session(session).status());
  ctf::Result<ctf::AccountingSnapshot> accounting = connection.accounting();
  outcome.note(accounting.status());
  if (accounting.ok()) {
    if (!accounting.value().conserves()) {
      outcome.note_code(ErrorCode::AccountingImbalance);
    }
  }
  ctf::Result<std::vector<ctf::SessionSummary>> listed = connection.list_sessions(workload, 8);
  outcome.note(listed.status());
  outcome.note(connection.check_invariants());
}

}  // namespace

CTF_TEST(concurrency, eight_clients_share_one_coordinator) {
  ctf::SteadyClock clock;
  ctf::CoordinatorService service(make_service_config(), clock);
  CTF_REQUIRE_OK(service.start());
  CTF_REQUIRE(service.running());
  CTF_REQUIRE(service.port() != 0);

  std::promise<void> released;
  std::shared_future<void> barrier = released.get_future().share();
  std::vector<WorkerOutcome> outcomes(kClientThreads);
  std::vector<ctf::net::StopToken> stops(kClientThreads);
  std::vector<std::thread> threads;
  threads.reserve(kClientThreads);
  for (std::size_t index = 0; index < kClientThreads; ++index) {
    threads.emplace_back([&service, &outcomes, &stops, barrier, index] {
      run_client_conversation(service, index, outcomes[index], stops[index], barrier);
    });
  }
  released.set_value();
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::size_t admitted = 0;
  for (std::size_t index = 0; index < kClientThreads; ++index) {
    CTF_EXPECT(outcomes[index].connected);
    if (!outcomes[index].connected) {
      ctf_ctx.fail(__FILE__, __LINE__, "client " + std::to_string(index) + " failed to connect: " +
                                           outcomes[index].connect_error);
    }
    expect_documented(ctf_ctx, outcomes[index], "client conversation");
    CTF_EXPECT(outcomes[index].operations > 0);
    admitted += outcomes[index].admitted;
  }
  CTF_EXPECT(admitted > 0);

  ctf::FabricEngine& engine = service.engine();
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT(accounting.sessions_admitted >= admitted);
  CTF_EXPECT_OK(engine.check_invariants());
  const ctf::ServiceStats stats = service.stats();
  CTF_EXPECT(stats.connections_accepted >= kClientThreads);
  CTF_EXPECT(stats.messages_processed > 0);
  std::printf("    clients=%zu admitted=%zu messages=%llu connections=%llu sessions=%zu\n",
              kClientThreads, admitted, (unsigned long long)stats.messages_processed,
              (unsigned long long)stats.connections_accepted, engine.session_count());
  CTF_REQUIRE_OK(service.shutdown());
  CTF_EXPECT(!service.running());
}

CTF_TEST(concurrency, identical_commands_admit_at_most_one_session) {
  ctf::SteadyClock clock;
  ctf::CoordinatorService service(make_service_config(), clock);
  CTF_REQUIRE_OK(service.start());

  constexpr std::size_t kThreads = 16;
  const ctf::WorkloadId workload = ctf::test::default_workload();
  const ctf::CheckpointId checkpoint = checkpoint_id(900);
  const ctf::CheckpointGeneration generation(1);
  const ctf::CommandId command = command_id(4242);

  std::promise<void> released;
  std::shared_future<void> barrier = released.get_future().share();
  std::vector<WorkerOutcome> outcomes(kThreads);
  std::vector<ctf::net::StopToken> stops(kThreads);
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&service, &outcomes, &stops, barrier, workload, checkpoint, generation,
                          command, index] {
      WorkerOutcome& outcome = outcomes[index];
      barrier.wait();
      ctf::Result<ctf::CoordinatorClient> client =
          connect_client(service, "same-command-" + std::to_string(index), stops[index]);
      if (!client.ok()) {
        outcome.connect_error = client.status().to_string();
        outcome.note_code(client.code());
        return;
      }
      outcome.connected = true;
      ctf::CoordinatorClient& connection = client.value();
      // Byte-for-byte the same request on every thread: the same command id and
      // the same body.
      const ctf::SessionRequest request =
          make_request(connection, workload, checkpoint, generation, command, 2, 4096, 7);
      const ctf::CommandFence fence = connection.current_fence(workload, generation);
      ctf::Result<ctf::AdmissionDecision> decision = connection.submit_session(request, fence);
      if (!decision.ok()) {
        outcome.note_code(decision.code());
        return;
      }
      ++outcome.operations;
      if (decision.value().kind == ctf::DecisionKind::Admit) {
        if (decision.value().reason == ReasonCode::Admitted) {
          ++outcome.admitted;
        } else if (decision.value().reason == ReasonCode::DuplicateCommand) {
          ++outcome.duplicate;
        }
      }
      if (decision.value().envelope.has_value()) {
        outcome.sessions.push_back(decision.value().session);
      }
    });
  }
  released.set_value();
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::size_t admitted = 0;
  std::size_t duplicates = 0;
  for (std::size_t index = 0; index < kThreads; ++index) {
    CTF_EXPECT(outcomes[index].connected);
    expect_documented(ctf_ctx, outcomes[index], "identical submit");
    admitted += outcomes[index].admitted;
    duplicates += outcomes[index].duplicate;
  }
  CTF_EXPECT_EQ(admitted, static_cast<std::size_t>(1));
  CTF_EXPECT_EQ(duplicates, kThreads - 1);

  ctf::FabricEngine& engine = service.engine();
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.sessions_admitted, 1ULL);
  CTF_EXPECT_EQ(accounting.bytes_admitted, 2ULL * 4096ULL);
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
  const ctf::Result<std::vector<ctf::SessionSummary>> listed =
      engine.list_sessions(workload, 64);
  CTF_REQUIRE_OK(listed.status());
  std::size_t matching = 0;
  for (const ctf::SessionSummary& summary : listed.value()) {
    if (summary.checkpoint == checkpoint && summary.checkpoint_generation == generation) {
      ++matching;
    }
  }
  CTF_EXPECT_EQ(matching, static_cast<std::size_t>(1));
  std::printf("    identical submits=%zu admitted=%zu duplicates=%zu sessions=%zu\n", kThreads,
              admitted, duplicates, matching);
  CTF_REQUIRE_OK(service.shutdown());
}

CTF_TEST(concurrency, races_for_one_checkpoint_generation_bill_once) {
  ctf::SteadyClock clock;
  ctf::CoordinatorService service(make_service_config(), clock);
  CTF_REQUIRE_OK(service.start());

  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kAttempts = 12;
  const ctf::WorkloadId workload = ctf::test::default_workload();
  const ctf::CheckpointId checkpoint = checkpoint_id(901);
  const ctf::CheckpointGeneration generation(2);
  const std::uint64_t total_bytes = 3ULL * 4096ULL;

  std::promise<void> released;
  std::shared_future<void> barrier = released.get_future().share();
  std::vector<WorkerOutcome> outcomes(kThreads);
  std::vector<ctf::net::StopToken> stops(kThreads);
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&service, &outcomes, &stops, barrier, workload, checkpoint, generation,
                          index] {
      WorkerOutcome& outcome = outcomes[index];
      barrier.wait();
      ctf::Result<ctf::CoordinatorClient> client =
          connect_client(service, "race-" + std::to_string(index), stops[index]);
      if (!client.ok()) {
        outcome.connect_error = client.status().to_string();
        outcome.note_code(client.code());
        return;
      }
      outcome.connected = true;
      ctf::CoordinatorClient& connection = client.value();
      for (std::size_t attempt = 0; attempt < kAttempts; ++attempt) {
        // Half the threads reuse one command id (idempotent replay), half use
        // their own; every request describes the same checkpoint content.
        const ctf::CommandId command =
            (index % 2U) == 0 ? command_id(5000) : command_id(6000 + index * kAttempts + attempt);
        const ctf::SessionRequest request =
            make_request(connection, workload, checkpoint, generation, command, 3, 4096, 11);
        const ctf::CommandFence fence = connection.current_fence(workload, generation);
        ctf::Result<ctf::AdmissionDecision> decision = connection.submit_session(request, fence);
        ++outcome.operations;
        if (!decision.ok()) {
          outcome.note_code(decision.code());
          continue;
        }
        if (decision.value().kind == ctf::DecisionKind::Admit) {
          if (decision.value().reason == ReasonCode::Admitted) {
            ++outcome.admitted;
          } else if (decision.value().reason == ReasonCode::DuplicateCommand) {
            ++outcome.duplicate;
          } else {
            ++outcome.refusals;
          }
        } else if (decision.value().reason == ReasonCode::ManifestMismatch ||
                   decision.value().reason == ReasonCode::CheckpointGenerationStale ||
                   decision.value().reason == ReasonCode::SupersessionDeniedByPolicy ||
                   decision.value().reason == ReasonCode::DuplicateCommand) {
          ++outcome.refusals;
        } else {
          outcome.note_code(ErrorCode::Internal);
        }
        if (decision.value().envelope.has_value()) {
          outcome.sessions.push_back(decision.value().session);
        }
      }
    });
  }
  released.set_value();
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::size_t admitted = 0;
  std::size_t duplicates = 0;
  std::size_t refused = 0;
  for (std::size_t index = 0; index < kThreads; ++index) {
    CTF_EXPECT(outcomes[index].connected);
    expect_documented(ctf_ctx, outcomes[index], "checkpoint race");
    admitted += outcomes[index].admitted;
    duplicates += outcomes[index].duplicate;
    refused += outcomes[index].refusals;
  }
  // Exactly one thread created the session; everyone else was told the command
  // was already decided. A second billed session would show up here.
  CTF_EXPECT_EQ(admitted, static_cast<std::size_t>(1));
  CTF_EXPECT_EQ(duplicates + refused, kThreads * kAttempts - 1);

  ctf::FabricEngine& engine = service.engine();
  const ctf::AccountingSnapshot accounting = engine.accounting();
  CTF_EXPECT_EQ(accounting.sessions_admitted, 1ULL);
  CTF_EXPECT_EQ(accounting.bytes_admitted, total_bytes);
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT_OK(engine.check_invariants());
  const ctf::Result<std::vector<ctf::SessionSummary>> listed = engine.list_sessions(workload, 64);
  CTF_REQUIRE_OK(listed.status());
  std::size_t matching = 0;
  for (const ctf::SessionSummary& summary : listed.value()) {
    if (summary.checkpoint == checkpoint && summary.checkpoint_generation == generation) {
      ++matching;
    }
  }
  CTF_EXPECT_EQ(matching, static_cast<std::size_t>(1));
  std::printf("    race submits=%zu admitted=%zu duplicate=%zu refused=%zu sessions=%zu\n",
              kThreads * kAttempts, admitted, duplicates, refused, matching);
  CTF_REQUIRE_OK(service.shutdown());
}

CTF_TEST(concurrency, start_stop_cycles_stay_healthy) {
  constexpr std::size_t kCycles = 5;
  constexpr std::size_t kThreads = 4;
  for (std::size_t cycle = 0; cycle < kCycles; ++cycle) {
    ctf::SteadyClock clock;
    std::unique_ptr<ctf::CoordinatorService> service;
    {
      auto owned = std::make_unique<ctf::CoordinatorService>(make_service_config(), clock);
      CTF_REQUIRE_OK(owned->start());
      CTF_REQUIRE(owned->running());
      const std::uint16_t port = owned->port();
      CTF_EXPECT(port != 0);

      std::promise<void> released;
      std::shared_future<void> barrier = released.get_future().share();
      std::vector<WorkerOutcome> outcomes(kThreads);
      std::vector<ctf::net::StopToken> stops(kThreads);
      std::vector<std::thread> threads;
      threads.reserve(kThreads);
      for (std::size_t index = 0; index < kThreads; ++index) {
        threads.emplace_back([&owned, &outcomes, &stops, barrier, cycle, index] {
          run_client_conversation(*owned, cycle * 10 + index + 1, outcomes[index], stops[index],
                                  barrier);
        });
      }
      released.set_value();
      for (std::thread& thread : threads) {
        thread.join();
      }
      std::size_t exercised = 0;
      for (std::size_t index = 0; index < kThreads; ++index) {
        CTF_EXPECT(outcomes[index].connected);
        expect_documented(ctf_ctx, outcomes[index], "start/stop cycle");
        CTF_EXPECT(outcomes[index].operations > 0);
        exercised += outcomes[index].operations;
      }
      CTF_EXPECT(exercised > 0);
      ctf::FabricEngine& engine = owned->engine();
      const ctf::AccountingSnapshot accounting = engine.accounting();
      CTF_EXPECT(accounting.conserves());
      CTF_EXPECT_OK(engine.check_invariants());
      const ctf::ServiceStats stats = owned->stats();
      CTF_EXPECT(stats.connections_accepted >= kThreads);
      CTF_REQUIRE_OK(owned->shutdown());
      CTF_EXPECT(!owned->running());
      CTF_EXPECT(owned->engine().accounting().conserves());
      std::printf("    cycle=%zu port=%u connections=%llu operations=%zu\n", cycle,
                  static_cast<unsigned>(port),
                  (unsigned long long)stats.connections_accepted, exercised);
      service = std::move(owned);
    }
    // The service object is destroyed here; the next cycle builds a fresh one.
    service.reset();
  }
}

CTF_TEST(concurrency, shutdown_under_load_refuses_deterministically) {
  ctf::SteadyClock clock;
  ctf::CoordinatorService service(make_service_config(), clock);
  CTF_REQUIRE_OK(service.start());

  // A coordinator worker serves one connection until it closes, so this test
  // keeps at most worker_threads persistent clients (the eight-client fan-out is
  // covered by eight_clients_share_one_coordinator, where clients take turns).
  constexpr std::size_t kThreads = 4;
  std::atomic<bool> stopping{false};
  std::promise<void> all_started;
  std::shared_future<void> started = all_started.get_future().share();
  std::atomic<std::size_t> ready{0};
  const auto note_ready = [&ready, &all_started] {
    if (ready.fetch_add(1) + 1 == kThreads) {
      all_started.set_value();
    }
  };
  // Second barrier: released once every client has completed a few rounds, so
  // the shutdown happens while the fabric is genuinely busy. No polling.
  std::promise<void> all_warm;
  std::shared_future<void> warmed = all_warm.get_future().share();
  std::atomic<std::size_t> warm{0};
  const auto note_round = [&warm, &all_warm](std::size_t rounds) {
    if (rounds == 5U && warm.fetch_add(1) + 1 == kThreads) {
      all_warm.set_value();
    }
  };

  std::vector<WorkerOutcome> outcomes(kThreads);
  std::vector<ctf::net::StopToken> stops(kThreads);
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back(
        [&service, &outcomes, &stops, &stopping, started, &note_ready, &note_round, index] {
      WorkerOutcome& outcome = outcomes[index];
      ctf::Result<ctf::CoordinatorClient> client =
          connect_client(service, "load-" + std::to_string(index), stops[index]);
      if (!client.ok()) {
        outcome.connect_error = client.status().to_string();
        outcome.note_code(client.code());
        note_ready();  // a failed client still releases the start barrier
        return;
      }
      outcome.connected = true;
      ctf::CoordinatorClient& connection = client.value();
      const ctf::WorkloadId workload = ctf::test::default_workload();
      const ctf::CheckpointGeneration generation(1);
      const ctf::CommandFence fence = connection.current_fence(workload, generation);
      note_ready();
      std::size_t round = 0;
      while (!stopping.load(std::memory_order_acquire)) {
        const ctf::CheckpointId checkpoint =
            checkpoint_id(static_cast<std::uint32_t>(7000 + index * 100 + (round % 8)));
        const ctf::SessionRequest request =
            make_request(connection, workload, checkpoint, generation,
                         command_id(70000 + index * 1000 + round), 1, 4096, round);
        ctf::Result<ctf::AdmissionDecision> decision = connection.submit_session(request, fence);
        ++outcome.operations;
        if (!decision.ok()) {
          outcome.note_code(decision.code());
          continue;
        }
        if (decision.value().admitted() && decision.value().envelope.has_value()) {
          ++outcome.admitted;
          ctf::Result<ctf::WaveOutcome> wave = connection.request_wave(
              decision.value().session, ctf::ShardIndex(0), fence);
          ++outcome.operations;
          if (!wave.ok()) {
            outcome.note_code(wave.code());
            continue;
          }
          if (!wave.value().granted) {
            continue;
          }
          const ctf::WaveGrant grant = wave.value().grant.value();
          ctf::TransferEvidence transfer;
          transfer.session = decision.value().session;
          transfer.attempt = grant.attempt;
          transfer.sequence = grant.sequence;
          transfer.shard = ctf::ShardIndex(0);
          transfer.arrived_bytes = grant.max_bytes;
          transfer.arrived_digest = request.manifest.shards[0].declared_digest;
          transfer.sink_acknowledged = true;
          outcome.note(connection.report_transfer(transfer, fence));
          outcome.note(connection.accounting().status());
        }
        ++round;
        note_round(round);
      }
    });
  }
  // Wait until every client is connected and running, then pull the fabric out
  // from under them. The barrier is released by the last client to arrive, so
  // there is no polling and no timeout.
  started.wait();
  CTF_EXPECT_EQ(ready.load(), kThreads);
  warmed.wait();
  stopping.store(true, std::memory_order_release);
  // Cancel every client's blocking I/O before the service stops accepting, so a
  // client can never be stranded on a connection the coordinator will not serve.
  for (ctf::net::StopToken& stop : stops) {
    stop.request_stop();
  }
  CTF_REQUIRE_OK(service.shutdown());
  CTF_EXPECT(!service.running());
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::size_t refusals = 0;
  std::size_t operations = 0;
  for (std::size_t index = 0; index < kThreads; ++index) {
    CTF_EXPECT(outcomes[index].connected);
    expect_documented(ctf_ctx, outcomes[index], "shutdown load");
    refusals += outcomes[index].refusals;
    operations += outcomes[index].operations;
  }
  CTF_EXPECT(operations > 0);
  CTF_EXPECT(service.engine().accounting().conserves());
  std::printf("    shutdown under load: threads=%zu operations=%zu refusals=%zu\n", kThreads,
              operations, refusals);
}

CTF_TEST(concurrency, cancel_transfer_and_verification_race_conserves) {
  ctf::SteadyClock clock;
  ctf::CoordinatorService service(make_service_config(), clock);
  CTF_REQUIRE_OK(service.start());

  ctf::Result<ctf::CoordinatorClient> operator_client =
      connect_client(service, "race-operator", ctf::net::StopToken{});
  CTF_REQUIRE_OK(operator_client.status());
  ctf::CoordinatorClient& client = operator_client.value();
  const ctf::WorkloadId workload = ctf::test::default_workload();
  const ctf::CheckpointId checkpoint = checkpoint_id(902);
  const ctf::CheckpointGeneration generation(1);
  const ctf::SessionRequest request =
      make_request(client, workload, checkpoint, generation, command_id(8000), 4, 4096, 3);
  const ctf::CommandFence fence = client.current_fence(workload, generation);
  ctf::Result<ctf::AdmissionDecision> decision = client.submit_session(request, fence);
  CTF_REQUIRE_OK(decision.status());
  CTF_REQUIRE(decision.value().admitted());
  const ctf::SessionId session = decision.value().session;
  ctf::Result<ctf::WaveOutcome> wave = client.request_wave(session, ctf::ShardIndex(0), fence);
  CTF_REQUIRE_OK(wave.status());
  CTF_REQUIRE(wave.value().granted);
  const ctf::WaveGrant grant = wave.value().grant.value();

  constexpr std::size_t kCancellers = 3;
  constexpr std::size_t kTransfers = 4;
  constexpr std::size_t kVerifiers = 3;
  constexpr std::size_t kThreads = kCancellers + kTransfers + kVerifiers;
  std::promise<void> released;
  std::shared_future<void> barrier = released.get_future().share();
  std::vector<WorkerOutcome> outcomes(kThreads);
  std::vector<ctf::net::StopToken> stops(kThreads);
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&service, &outcomes, &stops, barrier, session, fence, workload,
                          generation, grant, request, index] {
      WorkerOutcome& outcome = outcomes[index];
      barrier.wait();
      ctf::Result<ctf::CoordinatorClient> connection =
          connect_client(service, "mutator-" + std::to_string(index), stops[index]);
      if (!connection.ok()) {
        outcome.connect_error = connection.status().to_string();
        outcome.note_code(connection.code());
        return;
      }
      outcome.connected = true;
      if (index < kCancellers) {
        outcome.note(connection.value().cancel_session(session, fence,
                                                       ReasonCode::CancelledByOperator,
                                                       "racing cancel"));
        return;
      }
      if (index < kCancellers + kTransfers) {
        ctf::TransferEvidence transfer;
        transfer.session = session;
        transfer.attempt = grant.attempt;
        transfer.sequence = grant.sequence;
        transfer.shard = ctf::ShardIndex(0);
        transfer.arrived_bytes = grant.max_bytes;
        transfer.arrived_digest = request.manifest.shards[0].declared_digest;
        transfer.sink_acknowledged = true;
        outcome.note(connection.value().report_transfer(transfer, fence));
        return;
      }
      ctf::VerificationEvidence verification;
      verification.session = session;
      verification.attempt = grant.attempt;
      verification.sequence = grant.sequence;
      verification.shard = ctf::ShardIndex(0);
      verification.verified_bytes = request.manifest.shards[0].declared_bytes;
      verification.verified_digest = request.manifest.shards[0].declared_digest;
      verification.outcome = ctf::VerificationEvidence::Outcome::Verified;
      verification.verifier_identity = "racing-sink";
      outcome.note(connection.value().report_verification(verification, fence));
    });
  }
  released.set_value();
  for (std::thread& thread : threads) {
    thread.join();
  }

  for (std::size_t index = 0; index < kThreads; ++index) {
    CTF_EXPECT(outcomes[index].connected);
    expect_documented(ctf_ctx, outcomes[index], "generation-bound mutation");
  }
  ctf::FabricEngine& engine = service.engine();
  const ctf::AccountingSnapshot accounting = engine.accounting();
  // The race may end in any order, but never with double counting or negative
  // authority: every authorised byte lands in exactly one bucket, and the
  // session's buckets sum to its own admission.
  CTF_EXPECT(accounting.conserves());
  CTF_EXPECT(accounting.granted_outstanding_bytes <= accounting.bytes_admitted);
  const ctf::EngineSnapshot snapshot = engine.export_snapshot();
  for (const ctf::PersistedSession& persisted : snapshot.sessions) {
    if (!(persisted.session == session)) {
      continue;
    }
    CTF_EXPECT_EQ(persisted.transferred_bytes + persisted.wasted_bytes + persisted.cancelled_bytes +
                      persisted.unproven_bytes + persisted.outstanding_bytes,
                  persisted.admitted_bytes);
    const bool documented_state =
        persisted.state == ctf::SessionState::Admitted ||
        persisted.state == ctf::SessionState::Transferring ||
        persisted.state == ctf::SessionState::Transferred ||
        persisted.state == ctf::SessionState::VerifiedAtDestination ||
        persisted.state == ctf::SessionState::TrafficSessionComplete ||
        persisted.state == ctf::SessionState::Cancelled ||
        persisted.state == ctf::SessionState::Failed ||
        persisted.state == ctf::SessionState::Superseded ||
        persisted.state == ctf::SessionState::RevalidationRequired;
    CTF_EXPECT(documented_state);
    std::printf("    race outcome: state=%s admitted=%llu transferred=%llu verified=%llu "
                "wasted=%llu outstanding=%llu\n",
                ctf::to_string(persisted.state),
                (unsigned long long)persisted.admitted_bytes,
                (unsigned long long)persisted.transferred_bytes,
                (unsigned long long)persisted.verified_bytes,
                (unsigned long long)persisted.wasted_bytes,
                (unsigned long long)persisted.outstanding_bytes);
  }
  (void)client.close();
  CTF_REQUIRE_OK(service.shutdown());
}

CTF_MAIN()
