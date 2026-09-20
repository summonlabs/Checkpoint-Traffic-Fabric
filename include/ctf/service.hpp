#pragma once

// Coordinator service.
//
// Ownership rules the implementation follows deliberately:
//   * the engine owns all authoritative state and is guarded by its own lock;
//   * the service never calls into the engine while holding its own locks, and
//     the engine never calls out while holding its lock;
//   * durability happens between the engine mutation and the response, so an
//     acknowledgement can never precede the durable point it claims;
//   * shutdown stops accepting, wakes blocked readers through the stop token,
//     joins every thread, then writes a final snapshot.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "ctf/engine.hpp"
#include "ctf/net.hpp"
#include "ctf/status.hpp"
#include "ctf/store.hpp"
#include "ctf/time.hpp"

namespace ctf {

struct CoordinatorConfig {
  std::string bind_host = "127.0.0.1";
  std::uint16_t port = 0;
  std::filesystem::path data_directory;
  PolicySnapshot policy;
  TopologySnapshot topology;
  std::vector<WorkloadContract> contracts;
  Limits limits;
  std::size_t worker_threads = 4;
  std::size_t max_pending_connections = 64;
  bool persist = true;
  std::uint64_t identity_seed = 0x5DEECE66DULL;
  std::string label = "ctf-coordinator";
};

struct ServiceStats {
  std::uint64_t connections_accepted = 0;
  std::uint64_t connections_rejected = 0;
  std::uint64_t messages_processed = 0;
  std::uint64_t protocol_errors = 0;
  std::uint64_t durable_writes = 0;
  std::uint64_t durable_write_failures = 0;
  std::uint64_t sessions_served = 0;
};

class CoordinatorService {
 public:
  CoordinatorService(CoordinatorConfig config, const Clock& clock);
  ~CoordinatorService();

  CoordinatorService(const CoordinatorService&) = delete;
  CoordinatorService& operator=(const CoordinatorService&) = delete;

  /// Loads persisted state, advances the epoch, binds, and starts threads.
  [[nodiscard]] Status start();
  /// Blocks until shutdown is requested (by an operator or by request_stop).
  [[nodiscard]] Status wait();
  [[nodiscard]] Status request_stop();
  /// request_stop + wait + final durable snapshot.
  [[nodiscard]] Status shutdown();

  [[nodiscard]] std::uint16_t port() const;
  /// True once shutdown has been requested (by an operator or by request_stop),
  /// whether or not wait() has joined the workers yet.
  [[nodiscard]] bool stop_requested() const;
  [[nodiscard]] bool running() const;
  [[nodiscard]] FabricEngine& engine();
  [[nodiscard]] const store::LoadReport& load_report() const;
  [[nodiscard]] ServiceStats stats() const;
  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] std::string endpoint_text() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ctf
