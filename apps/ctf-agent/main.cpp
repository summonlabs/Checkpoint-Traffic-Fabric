// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// ctf-agent: the checkpoint sender and synthetic destination sink processes.
//
// The destination used by the sink is a SYNTHETIC lab destination: the fabric
// reports transferred and verified-at-destination evidence for it, and never
// reports storage durability.

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "cli_common.hpp"
#include "ctf/agent.hpp"

namespace {

std::atomic<bool> g_interrupted{false};

#if defined(_WIN32)
BOOL WINAPI console_handler(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
    g_interrupted.store(true);
    return TRUE;
  }
  return FALSE;
}
#else
extern "C" void signal_handler(int) { g_interrupted.store(true); }
#endif

void install_handlers() {
#if defined(_WIN32)
  (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
  (void)std::signal(SIGINT, signal_handler);
  (void)std::signal(SIGTERM, signal_handler);
#endif
}

void print_usage() {
  std::cout <<
      "usage: ctf-agent sink --coordinator <host:port> --directory <dir> [options]\n"
      "       ctf-agent sender --coordinator <host:port> --sink <host:port> "
      "--workload <uuid> --checkpoint <uuid> [options]\n"
      "\n"
      "sink options:\n"
      "  --bind <host>            interface to accept transfers on (default 127.0.0.1)\n"
      "  --port <n>               port to accept transfers on (0 selects an ephemeral port)\n"
      "  --directory <dir>        synthetic destination directory (required)\n"
      "  --expect-shards <n>      stop after n shards (0 = run until signalled)\n"
      "  --die-after-bytes <n>    exit abruptly after n bytes, before acknowledging\n"
      "  --no-verify              report an ambiguous outcome instead of verifying\n"
      "  --identity <text>        client identity bound to evidence\n"
      "\n"
      "sender options:\n"
      "  --sink <host:port>       sink endpoint (required)\n"
      "  --workload <uuid>        workload identity (required)\n"
      "  --checkpoint <uuid>      checkpoint identity (required)\n"
      "  --generation <n>         checkpoint generation (default 1)\n"
      "  --shards <n>             shard count (default 2)\n"
      "  --shard-bytes <n>        bytes per shard (default 262144)\n"
      "  --isolation <class>      TrainingCritical|ServingLatency|TrainingBulk|BestEffort\n"
      "  --destination <class>    LocalAttachedStore|RemoteObjectStore|PeerNodeMemory|SyntheticLab\n"
      "  --rate <bytes/s>         requested rate (0 = policy derived)\n"
      "  --deadline-ms <n>        completion horizon in milliseconds\n"
      "  --die-after-bytes <n>    exit abruptly after n bytes (injected sender death)\n"
      "  --truncate-first-shard   send half of the first shard and end it truncated\n"
      "  --identity <text>        client identity bound to evidence\n"
      "  --json                   print a JSON result line\n"
      "\n"
      "Exit codes: 0 ok, 2 denied, 3 deferred, 4 protocol failure, 5 stopped,\n"
      "            6 no credit, 8 truncated, 9 died (injected fault).\n";
}

}  // namespace

int main(int argc, char** argv) {
  ctf::cli::Arguments args(argc, argv);
  std::string command;
  if (args.empty() || args.has("--help") || !args.command(&command)) {
    print_usage();
    return args.empty() ? ctf::cli::kExitUsage : ctf::cli::kExitOk;
  }
  install_handlers();
  ctf::net::StopToken stop;
  ctf::SteadyClock clock;

  if (command == "sink") {
    const std::optional<std::string> coordinator = args.flag("--coordinator");
    const std::optional<std::string> directory = args.flag("--directory");
    if (!coordinator.has_value() || !directory.has_value()) {
      std::cerr << "sink requires --coordinator and --directory\n";
      return ctf::cli::kExitUsage;
    }
    ctf::Result<ctf::cli::Endpoint> endpoint = ctf::cli::parse_endpoint(coordinator.value());
    if (!endpoint.ok()) {
      std::cerr << endpoint.status().to_string() << "\n";
      return ctf::cli::kExitUsage;
    }
    ctf::SinkConfig config;
    config.coordinator_host = endpoint.value().host;
    config.coordinator_port = endpoint.value().port;
    config.directory = std::filesystem::path(directory.value());
    if (const std::optional<std::string> bind = args.flag("--bind"); bind.has_value()) {
      config.bind_host = *bind;
    }
    if (args.flag("--port").has_value()) {
      ctf::Result<std::uint32_t> port = ctf::cli::parse_u32_flag(args, "--port");
      if (!port.ok() || port.value() > 65535U) {
        std::cerr << "--port must be 0..65535\n";
        return ctf::cli::kExitUsage;
      }
      config.port = static_cast<std::uint16_t>(port.value());
    }
    if (args.flag("--expect-shards").has_value()) {
      ctf::Result<std::uint32_t> count = ctf::cli::parse_u32_flag(args, "--expect-shards");
      if (!count.ok()) {
        std::cerr << count.status().to_string() << "\n";
        return ctf::cli::kExitUsage;
      }
      config.expected_shards = count.value();
    }
    if (args.flag("--die-after-bytes").has_value()) {
      ctf::Result<std::uint64_t> bytes = ctf::cli::parse_u64_flag(args, "--die-after-bytes");
      if (!bytes.ok()) {
        std::cerr << bytes.status().to_string() << "\n";
        return ctf::cli::kExitUsage;
      }
      config.die_after_bytes = bytes.value();
    }
    config.verify = !args.has("--no-verify");
    if (const std::optional<std::string> identity = args.flag("--identity"); identity.has_value()) {
      config.identity = *identity;
    }
    ctf::CheckpointSink sink(std::move(config), clock);
    const ctf::Status started = sink.start(stop);
    if (!started.ok()) {
      std::cerr << "sink refused to start: " << started.to_string() << "\n";
      return ctf::cli::kExitInternal;
    }
    std::cout << "CTF-SINK-READY port=" << sink.port() << " synthetic_destination=true"
              << std::endl;
    ctf::Result<ctf::SinkResult> result = sink.run(stop);
    if (!result.ok()) {
      std::cerr << "sink failed: " << result.status().to_string() << "\n";
      return ctf::cli::kExitInternal;
    }
    const ctf::SinkResult& value = result.value();
    std::cout << "{\"role\":\"sink\",\"shards_received\":" << value.shards_received
              << ",\"shards_verified\":" << value.shards_verified
              << ",\"shards_truncated\":" << value.shards_truncated
              << ",\"shards_mismatched\":" << value.shards_mismatched
              << ",\"bytes_received\":" << value.bytes_received
              << ",\"exit_code\":" << value.exit_code << ",\"message\":\""
              << ctf::report::json_escape(value.message) << "\"}" << std::endl;
    return value.exit_code;
  }

  if (command == "sender") {
    const std::optional<std::string> coordinator = args.flag("--coordinator");
    const std::optional<std::string> sink_endpoint = args.flag("--sink");
    if (!coordinator.has_value() || !sink_endpoint.has_value()) {
      std::cerr << "sender requires --coordinator and --sink\n";
      return ctf::cli::kExitUsage;
    }
    ctf::Result<ctf::cli::Endpoint> coordinator_parsed =
        ctf::cli::parse_endpoint(coordinator.value());
    ctf::Result<ctf::cli::Endpoint> sink_parsed = ctf::cli::parse_endpoint(sink_endpoint.value());
    if (!coordinator_parsed.ok() || !sink_parsed.ok()) {
      std::cerr << "endpoints must be host:port\n";
      return ctf::cli::kExitUsage;
    }
    ctf::SenderConfig config;
    config.coordinator_host = coordinator_parsed.value().host;
    config.coordinator_port = coordinator_parsed.value().port;
    config.sink_host = sink_parsed.value().host;
    config.sink_port = sink_parsed.value().port;
    ctf::Result<std::uint64_t> generation = ctf::cli::parse_u64_flag(args, "--generation");
    if (args.flag("--generation").has_value() && !generation.ok()) {
      std::cerr << generation.status().to_string() << "\n";
      return ctf::cli::kExitUsage;
    }
    config.checkpoint_generation =
        ctf::CheckpointGeneration(args.flag("--generation").has_value() ? generation.value() : 1);
    const std::optional<std::string> workload = args.flag("--workload");
    const std::optional<std::string> checkpoint = args.flag("--checkpoint");
    const std::optional<ctf::WorkloadId> workload_id =
        workload.has_value() ? ctf::WorkloadId::parse(workload.value()) : std::nullopt;
    const std::optional<ctf::CheckpointId> checkpoint_id =
        checkpoint.has_value() ? ctf::CheckpointId::parse(checkpoint.value()) : std::nullopt;
    if (!workload_id.has_value() || !checkpoint_id.has_value()) {
      std::cerr << "--workload and --checkpoint must be canonical uuids\n";
      return ctf::cli::kExitUsage;
    }
    config.workload = workload_id.value();
    config.checkpoint = checkpoint_id.value();
    if (args.flag("--shards").has_value()) {
      ctf::Result<std::uint32_t> shards = ctf::cli::parse_u32_flag(args, "--shards");
      if (!shards.ok() || shards.value() == 0) {
        std::cerr << "--shards must be at least 1\n";
        return ctf::cli::kExitUsage;
      }
      config.shard_count = shards.value();
    }
    if (args.flag("--shard-bytes").has_value()) {
      ctf::Result<std::uint64_t> bytes = ctf::cli::parse_u64_flag(args, "--shard-bytes");
      if (!bytes.ok() || bytes.value() == 0) {
        std::cerr << "--shard-bytes must be at least 1\n";
        return ctf::cli::kExitUsage;
      }
      config.shard_bytes = bytes.value();
    }
    if (const std::optional<std::string> isolation = args.flag("--isolation");
        isolation.has_value()) {
      const std::optional<ctf::IsolationClass> parsed =
          ctf::isolation_class_from_string(isolation.value());
      if (!parsed.has_value()) {
        std::cerr << "--isolation names an unknown class\n";
        return ctf::cli::kExitUsage;
      }
      config.isolation = parsed.value();
    }
    if (const std::optional<std::string> destination = args.flag("--destination");
        destination.has_value()) {
      const std::optional<ctf::DestinationClass> parsed =
          ctf::destination_class_from_string(destination.value());
      if (!parsed.has_value()) {
        std::cerr << "--destination names an unknown class\n";
        return ctf::cli::kExitUsage;
      }
      config.destination = parsed.value();
    }
    if (args.flag("--rate").has_value()) {
      ctf::Result<std::uint64_t> rate = ctf::cli::parse_u64_flag(args, "--rate");
      if (!rate.ok()) {
        std::cerr << rate.status().to_string() << "\n";
        return ctf::cli::kExitUsage;
      }
      config.requested_rate_bps = rate.value();
    }
    if (args.flag("--deadline-ms").has_value()) {
      ctf::Result<std::uint64_t> millis = ctf::cli::parse_u64_flag(args, "--deadline-ms");
      if (!millis.ok()) {
        std::cerr << millis.status().to_string() << "\n";
        return ctf::cli::kExitUsage;
      }
      config.deadline_horizon_ns = static_cast<ctf::Nanos>(millis.value()) * ctf::kNanosPerMillisecond;
    }
    if (args.flag("--die-after-bytes").has_value()) {
      ctf::Result<std::uint64_t> bytes = ctf::cli::parse_u64_flag(args, "--die-after-bytes");
      if (!bytes.ok()) {
        std::cerr << bytes.status().to_string() << "\n";
        return ctf::cli::kExitUsage;
      }
      config.die_after_bytes = bytes.value();
    }
    config.truncate_first_shard = args.has("--truncate-first-shard");
    if (const std::optional<std::string> identity = args.flag("--identity"); identity.has_value()) {
      config.identity = *identity;
    }
    ctf::CheckpointSender sender(std::move(config), clock);
    ctf::Result<ctf::SenderResult> result = sender.run(stop);
    if (!result.ok()) {
      std::cerr << "sender failed: " << result.status().to_string() << "\n";
      return ctf::cli::kExitInternal;
    }
    const ctf::SenderResult& value = result.value();
    if (args.has("--json")) {
      std::cout << "{\"role\":\"sender\",\"decision\":\"" << ctf::to_string(value.decision)
                << "\",\"reason\":\"" << ctf::to_string(value.reason)
                << "\",\"detail\":\"" << ctf::report::json_escape(value.detail)
                << "\",\"session\":\"" << value.session.to_string()
                << "\",\"bytes_sent\":" << value.bytes_sent
                << ",\"shards_completed\":" << value.shards_completed
                << ",\"deferred_grants\":" << value.deferred_grants
                << ",\"exit_code\":" << value.exit_code << ",\"message\":\""
                << ctf::report::json_escape(value.message) << "\"}" << std::endl;
    } else {
      std::cout << "decision=" << ctf::to_string(value.decision)
                << " reason=" << ctf::to_string(value.reason)
                << " session=" << value.session.to_string() << " bytes_sent=" << value.bytes_sent
                << " shards_completed=" << value.shards_completed
                << " deferred_grants=" << value.deferred_grants << " message=\"" << value.message
                << "\"" << std::endl;
    }
    return value.exit_code;
  }

  std::cerr << "unknown command: " << command << "\n";
  print_usage();
  return ctf::cli::kExitUsage;
}
