// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A real coordinator on loopback TCP with a real client: handshake, submission,
// inspection, and a clean shutdown. This is a REAL transport path (loopback),
// not a simulation.

#include <cstdio>
#include <string>

#include "ctf/client.hpp"
#include "ctf/config.hpp"
#include "ctf/report.hpp"
#include "ctf/service.hpp"

int main() {
  ctf::SteadyClock clock;
  ctf::CoordinatorConfig config = ctf::config::default_coordinator_config();
  config.persist = false;
  config.worker_threads = 2;

  ctf::CoordinatorService service(std::move(config), clock);
  const ctf::Status started = service.start();
  if (!started.ok()) {
    std::printf("service refused to start: %s\n", started.to_string().c_str());
    return 1;
  }
  std::printf("coordinator listening on 127.0.0.1:%u epoch=%s\n", service.port(),
              service.epoch().to_string().c_str());

  ctf::net::StopToken stop;
  ctf::ClientConfig client_config;
  client_config.host = "127.0.0.1";
  client_config.port = service.port();
  client_config.kind = ctf::wire::ClientKind::Operator;
  client_config.identity = "example-transport";
  ctf::Result<ctf::CoordinatorClient> client = ctf::CoordinatorClient::connect(client_config, stop);
  if (!client.ok()) {
    std::printf("client could not connect: %s\n", client.status().to_string().c_str());
    return 1;
  }
  std::printf("hello: %s\n", ctf::report::to_text(client.value().hello()).c_str());

  ctf::Result<ctf::AccountingSnapshot> accounting = client.value().accounting();
  if (!accounting.ok()) {
    std::printf("accounting query failed: %s\n", accounting.status().to_string().c_str());
    return 1;
  }
  std::printf("accounting: %s\n", ctf::report::to_text(accounting.value()).c_str());

  const ctf::Status invariants = client.value().check_invariants();
  std::printf("coordinator invariants: %s\n",
              invariants.ok() ? "hold" : invariants.to_string().c_str());

  (void)client.value().close();
  const ctf::Status shutdown = service.shutdown();
  std::printf("shutdown: %s\n", shutdown.ok() ? "clean" : shutdown.to_string().c_str());
  std::printf("stats: %s\n", ctf::report::to_text(service.stats()).c_str());
  return invariants.ok() && shutdown.ok() ? 0 : 1;
}
