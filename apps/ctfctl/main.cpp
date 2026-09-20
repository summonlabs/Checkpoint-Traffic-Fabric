// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// ctfctl: inspection and control tool for a running coordinator.

#include <iostream>
#include <string>

#include "cli_common.hpp"
#include "ctf/config.hpp"

namespace {

void print_usage() {
  std::cout <<
      "usage: ctfctl <command> --endpoint <host:port> [options]\n"
      "\n"
      "commands:\n"
      "  ping                 handshake and report coordinator authority\n"
      "  status               session view (--session <uuid>)\n"
      "  list                 list sessions [--workload <uuid>] [--limit <n>]\n"
      "  accounting           byte and session accounting\n"
      "  explain              admission timeline for a session (--session <uuid>)\n"
      "  invariants           ask the coordinator to check its own invariants\n"
      "  cancel               cancel a session (--session <uuid> [--detail <text>])\n"
      "  pause                pause a session (--session <uuid> [--detail <text>])\n"
      "  resume               resume a session (--session <uuid>)\n"
      "  shutdown             ask the coordinator to stop accepting work\n"
      "\n"
      "common options:\n"
      "  --json               machine-readable output\n"
      "  --identity <text>    client identity (default ctfctl)\n"
      "  --config <file>      print the normalized configuration and exit\n"
      "\n"
      "exit codes: 0 ok, 1 usage, 2 refused, 3 transport failure\n";
}

[[nodiscard]] int run_command(const std::string& command, const ctf::cli::Arguments& args) {
  if (command == "config") {
    const std::optional<std::string> path = args.flag("--config");
    if (!path.has_value()) {
      std::cerr << "--config <file> is required\n";
      return ctf::cli::kExitUsage;
    }
    ctf::Result<ctf::config::FileConfig> loaded = ctf::config::load_config_file(path.value());
    if (!loaded.ok()) {
      std::cerr << "configuration refused: " << loaded.status().to_string() << "\n";
      return ctf::cli::kExitUsage;
    }
    std::cout << ctf::config::describe_config(loaded.value().coordinator);
    return ctf::cli::kExitOk;
  }

  ctf::Result<ctf::cli::Endpoint> endpoint = ctf::cli::require_endpoint(args);
  if (!endpoint.ok()) {
    std::cerr << endpoint.status().to_string() << "\n";
    return ctf::cli::kExitUsage;
  }
  const bool json = args.has("--json");
  std::string identity = "ctfctl";
  if (const std::optional<std::string> value = args.flag("--identity"); value.has_value()) {
    identity = *value;
  }
  ctf::net::StopToken stop;
  ctf::ClientConfig client_config = ctf::cli::client_config(
      endpoint.value(), ctf::wire::ClientKind::Operator, identity);
  ctf::Result<ctf::CoordinatorClient> client = ctf::CoordinatorClient::connect(client_config, stop);
  if (!client.ok()) {
    std::cerr << "coordinator unreachable: " << client.status().to_string() << "\n";
    return ctf::cli::kExitTransport;
  }
  ctf::CoordinatorClient& connection = client.value();

  if (command == "ping") {
    if (json) {
      std::cout << ctf::report::to_json(connection.hello()) << "\n";
    } else {
      std::cout << ctf::report::to_text(connection.hello()) << "\n";
    }
    return ctf::cli::kExitOk;
  }
  if (command == "accounting") {
    ctf::Result<ctf::AccountingSnapshot> accounting = connection.accounting();
    if (!accounting.ok()) {
      return ctf::cli::report_refusal(accounting.status());
    }
    std::cout << (json ? ctf::report::to_json(accounting.value())
                       : ctf::report::to_text(accounting.value()))
              << "\n";
    return ctf::cli::kExitOk;
  }
  if (command == "invariants") {
    const ctf::Status status = connection.check_invariants();
    if (!status.ok()) {
      return ctf::cli::report_refusal(status);
    }
    std::cout << "invariants hold\n";
    return ctf::cli::kExitOk;
  }
  if (command == "list") {
    std::optional<ctf::WorkloadId> workload;
    if (const std::optional<std::string> value = args.flag("--workload"); value.has_value()) {
      const std::optional<ctf::WorkloadId> parsed = ctf::WorkloadId::parse(value.value());
      if (!parsed.has_value()) {
        std::cerr << "--workload must be a canonical uuid\n";
        return ctf::cli::kExitUsage;
      }
      workload = parsed.value();
    }
    std::uint32_t limit = 64;
    if (args.flag("--limit").has_value()) {
      ctf::Result<std::uint32_t> parsed = ctf::cli::parse_u32_flag(args, "--limit");
      if (!parsed.ok()) {
        std::cerr << parsed.status().to_string() << "\n";
        return ctf::cli::kExitUsage;
      }
      limit = parsed.value();
    }
    ctf::Result<std::vector<ctf::SessionSummary>> sessions = connection.list_sessions(workload, limit);
    if (!sessions.ok()) {
      return ctf::cli::report_refusal(sessions.status());
    }
    if (json) {
      std::cout << "[";
      for (std::size_t i = 0; i < sessions.value().size(); ++i) {
        if (i != 0) {
          std::cout << ",";
        }
        std::cout << ctf::report::to_json(sessions.value()[i]);
      }
      std::cout << "]\n";
    } else {
      for (const ctf::SessionSummary& summary : sessions.value()) {
        std::cout << ctf::report::to_text(summary) << "\n";
      }
      std::cout << "sessions=" << sessions.value().size() << "\n";
    }
    return ctf::cli::kExitOk;
  }
  if (command == "shutdown") {
    const ctf::Status status = connection.request_shutdown();
    if (!status.ok()) {
      return ctf::cli::report_refusal(status);
    }
    std::cout << "shutdown accepted\n";
    return ctf::cli::kExitOk;
  }

  // Session-scoped commands.
  ctf::Result<ctf::SessionId> session = ctf::cli::require_session(args);
  if (!session.ok()) {
    std::cerr << session.status().to_string() << "\n";
    return ctf::cli::kExitUsage;
  }
  if (command == "status") {
    ctf::Result<ctf::SessionView> view = connection.view_session(session.value());
    if (!view.ok()) {
      return ctf::cli::report_refusal(view.status());
    }
    std::cout << (json ? ctf::report::to_json(view.value()) : ctf::report::to_text(view.value()))
              << "\n";
    return ctf::cli::kExitOk;
  }
  if (command == "explain") {
    ctf::Result<ctf::Explanation> explanation = connection.explain(session.value());
    if (!explanation.ok()) {
      return ctf::cli::report_refusal(explanation.status());
    }
    std::cout << (json ? ctf::report::to_json(explanation.value())
                       : ctf::report::to_text(explanation.value()))
              << "\n";
    return ctf::cli::kExitOk;
  }

  // Commands that mutate need the workload that owns the session.
  ctf::Result<ctf::SessionView> view = connection.view_session(session.value());
  if (!view.ok()) {
    return ctf::cli::report_refusal(view.status());
  }
  const ctf::CommandFence fence =
      connection.current_fence(view.value().workload, view.value().checkpoint_generation);
  std::string detail = "ctfctl";
  if (const std::optional<std::string> value = args.flag("--detail"); value.has_value()) {
    detail = *value;
  }
  ctf::Status status = ctf::Status::error(ctf::ErrorCode::InvalidArgument, "unknown command");
  if (command == "cancel") {
    status = connection.cancel_session(session.value(), fence, ctf::ReasonCode::CancelledByOperator,
                                       detail);
  } else if (command == "pause") {
    status = connection.pause_session(session.value(), fence, detail);
  } else if (command == "resume") {
    status = connection.resume_session(session.value(), fence);
  } else {
    std::cerr << "unknown command: " << command << "\n";
    return ctf::cli::kExitUsage;
  }
  if (!status.ok()) {
    return ctf::cli::report_refusal(status);
  }
  std::cout << command << " accepted for " << session.value().to_string() << "\n";
  return ctf::cli::kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  ctf::cli::Arguments args(argc, argv);
  if (args.empty() || args.has("--help")) {
    print_usage();
    return args.empty() ? ctf::cli::kExitUsage : ctf::cli::kExitOk;
  }
  std::string command;
  if (!args.command(&command)) {
    print_usage();
    return ctf::cli::kExitUsage;
  }
  return run_command(command, args);
}
