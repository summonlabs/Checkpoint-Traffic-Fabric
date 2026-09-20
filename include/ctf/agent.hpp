#pragma once

// Real sender and sink processes.
//
// The sender asks the fabric for credit, streams granted bytes to the sink over
// framed TCP, and reports only evidence it actually holds. The sink writes to a
// SYNTHETIC local destination (a lab destination, not a storage backend), hashes
// what it received, and reports destination verification itself.
//
// Fault injection is explicit and honest: a sender or sink can be told to die
// abruptly after a byte count so multiprocess tests can prove that an
// unacknowledged transfer never becomes success.

#include <cstdint>
#include <filesystem>
#include <string>

#include "ctf/client.hpp"
#include "ctf/net.hpp"
#include "ctf/status.hpp"
#include "ctf/time.hpp"

namespace ctf {

/// Deterministic checkpoint content: the same seed, shard, and offset always
/// produce the same bytes, so digests computed locally and at the sink agree.
class SyntheticCheckpointContent {
 public:
  SyntheticCheckpointContent(std::uint64_t seed, ShardIndex shard);

  void fill(std::uint64_t offset, MutableByteSpan out) const;
  [[nodiscard]] Digest digest(std::uint64_t bytes) const;

 private:
  std::uint64_t base_ = 0;
};

struct SenderConfig {
  std::string coordinator_host = "127.0.0.1";
  std::uint16_t coordinator_port = 0;
  std::string sink_host = "127.0.0.1";
  std::uint16_t sink_port = 0;
  WorkloadId workload;
  CheckpointId checkpoint;
  CheckpointGeneration checkpoint_generation{1};
  IsolationClass isolation = IsolationClass::TrainingBulk;
  DestinationClass destination = DestinationClass::LocalAttachedStore;
  std::uint32_t shard_count = 2;
  std::uint64_t shard_bytes = 256U * 1024U;
  std::uint64_t requested_rate_bps = 0;
  Nanos deadline_horizon_ns = 0;
  std::uint64_t die_after_bytes = 0;
  bool truncate_first_shard = false;
  std::string identity = "ctf-sender";
  Limits limits;
  std::uint64_t content_seed = 0x5EED1234ULL;
  std::uint32_t max_credit_wait_iterations = 20000;
};

struct SenderResult {
  DecisionKind decision = DecisionKind::Deny;
  ReasonCode reason = ReasonCode::Internal;
  std::string detail;
  SessionId session;
  std::uint64_t bytes_sent = 0;
  std::uint32_t shards_completed = 0;
  std::uint32_t deferred_grants = 0;
  int exit_code = 0;
  std::string message;
};

class CheckpointSender {
 public:
  CheckpointSender(SenderConfig config, const Clock& clock);

  [[nodiscard]] Result<SenderResult> run(net::StopToken stop);

 private:
  SenderConfig config_;
  const Clock* clock_;
  IdFactory id_factory_{0xA5A5A5A5ULL};
};

struct SinkConfig {
  std::string bind_host = "127.0.0.1";
  std::uint16_t port = 0;
  std::filesystem::path directory;
  std::string coordinator_host = "127.0.0.1";
  std::uint16_t coordinator_port = 0;
  std::uint32_t expected_shards = 0;  ///< 0 = run until stopped
  std::uint64_t die_after_bytes = 0;
  bool verify = true;
  std::string identity = "ctf-sink";
  Limits limits;
};

struct SinkResult {
  std::uint32_t shards_received = 0;
  std::uint32_t shards_verified = 0;
  std::uint32_t shards_truncated = 0;
  std::uint32_t shards_mismatched = 0;
  std::uint64_t bytes_received = 0;
  int exit_code = 0;
  std::string message;
};

class CheckpointSink {
 public:
  CheckpointSink(SinkConfig config, const Clock& clock);

  [[nodiscard]] Status start(net::StopToken stop);
  [[nodiscard]] std::uint16_t port() const { return listener_.port(); }
  [[nodiscard]] Result<SinkResult> run(net::StopToken stop);

 private:
  SinkConfig config_;
  const Clock* clock_;
  net::TcpListener listener_;
  Limits limits_;
};

}  // namespace ctf
