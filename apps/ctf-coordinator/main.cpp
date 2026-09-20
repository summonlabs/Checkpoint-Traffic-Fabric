// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// ctf-coordinator: the checkpoint traffic fabric coordinator service process.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "cli_common.hpp"
#include "ctf/config.hpp"
#include "ctf/service.hpp"

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

void print_usage() {
  std::cout <<
      "usage: ctf-coordinator --config <file> [options]\n"
      "\n"
      "  --config <file>     configuration file (required)\n"
      "  --data-dir <dir>    override data_directory for persisted state\n"
      "  --bind <host>       override bind host (default from config)\n"
      "  --port <n>          override bind port (0 selects an ephemeral port)\n"
      "  --workers <n>       override worker thread count\n"
      "  --label <text>      override the server label\n"
      "  --print-config      print the effective configuration and exit\n"
      "  --help              print this text\n"
      "\n"
      "The process prints one CTF-READY line once it is accepting connections:\n"
      "  CTF-READY host=<host> port=<port> epoch=<incarnation>.<term> "
      "policy=<gen> topology=<gen>\n";
}

}  // namespace

int main(int argc, char** argv) {
  ctf::cli::Arguments args(argc, argv);
  if (args.empty() || args.has("--help")) {
    print_usage();
    return args.empty() ? ctf::cli::kExitUsage : ctf::cli::kExitOk;
  }
  const std::optional<std::string> config_path = args.flag("--config");
  if (!config_path.has_value()) {
    std::cerr << "--config <file> is required\n";
    return ctf::cli::kExitUsage;
  }
  ctf::Result<ctf::config::FileConfig> loaded = ctf::config::load_config_file(config_path.value());
  if (!loaded.ok()) {
    std::cerr << "configuration refused: " << loaded.status().to_string() << "\n";
    return ctf::cli::kExitUsage;
  }
  ctf::CoordinatorConfig config = loaded.value().coordinator;
  if (const std::optional<std::string> data_dir = args.flag("--data-dir"); data_dir.has_value()) {
    config.data_directory = *data_dir;
    config.persist = true;
  }
  if (const std::optional<std::string> bind = args.flag("--bind"); bind.has_value()) {
    config.bind_host = *bind;
  }
  if (const std::optional<std::string> port = args.flag("--port"); port.has_value()) {
    ctf::Result<std::uint32_t> parsed = ctf::cli::parse_u32_flag(args, "--port");
    if (!parsed.ok() || parsed.value() > 65535U) {
      std::cerr << "--port must be 0..65535\n";
      return ctf::cli::kExitUsage;
    }
    config.port = static_cast<std::uint16_t>(parsed.value());
  }
  if (const std::optional<std::string> workers = args.flag("--workers"); workers.has_value()) {
    ctf::Result<std::uint32_t> parsed = ctf::cli::parse_u32_flag(args, "--workers");
    if (!parsed.ok() || parsed.value() == 0 || parsed.value() > 256U) {
      std::cerr << "--workers must be 1..256\n";
      return ctf::cli::kExitUsage;
    }
    config.worker_threads = parsed.value();
  }
  if (const std::optional<std::string> label = args.flag("--label"); label.has_value()) {
    config.label = *label;
  }
  if (args.has("--print-config")) {
    std::cout << ctf::config::describe_config(config);
    return ctf::cli::kExitOk;
  }

#if defined(_WIN32)
  (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
  (void)std::signal(SIGINT, signal_handler);
  (void)std::signal(SIGTERM, signal_handler);
#endif

  ctf::SteadyClock clock;
  ctf::CoordinatorService service(std::move(config), clock);
  const ctf::Status started = service.start();
  if (!started.ok()) {
    std::cerr << "coordinator refused to start: " << started.to_string() << "\n";
    return ctf::cli::kExitInternal;
  }
  const ctf::CoordinatorEpoch epoch = service.epoch();
  std::cout << "CTF-READY host=" << service.endpoint_text() << " port=" << service.port()
            << " epoch=" << epoch.to_string() << " incarnation=" << epoch.incarnation.to_string()
            << " term=" << epoch.term.to_string() << std::endl;

  // Stop when a signal arrives or an operator asked the coordinator to stop.
  while (!g_interrupted.load() && !service.stop_requested()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  ctf::Status stopped = service.shutdown();
  std::cout << "CTF-STOPPED " << ctf::report::to_text(service.stats()) << std::endl;
  if (!stopped.ok()) {
    std::cerr << "shutdown reported: " << stopped.to_string() << "\n";
    return ctf::cli::kExitInternal;
  }
  return ctf::cli::kExitOk;
}
