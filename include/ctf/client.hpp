#pragma once

// Client library for the coordinator protocol.
//
// The client keeps the authority it was told at Hello, and stamps every command
// with it. It never invents generations: a fence it cannot build from live
// authority is a fence the coordinator will (correctly) refuse.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ctf/protocol.hpp"
#include "ctf/status.hpp"

namespace ctf {

struct ClientConfig {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  wire::ClientKind kind = wire::ClientKind::Operator;
  std::string identity = "ctf-client";
  Limits limits;
};

class CoordinatorClient {
 public:
  [[nodiscard]] static Result<CoordinatorClient> connect(const ClientConfig& config,
                                                         net::StopToken stop);

  CoordinatorClient(CoordinatorClient&&) noexcept = default;
  CoordinatorClient& operator=(CoordinatorClient&&) noexcept = default;
  CoordinatorClient(const CoordinatorClient&) = delete;
  CoordinatorClient& operator=(const CoordinatorClient&) = delete;

  [[nodiscard]] const wire::HelloResponse& hello() const noexcept { return hello_; }
  [[nodiscard]] const std::string& identity() const noexcept { return identity_; }
  [[nodiscard]] const Limits& limits() const noexcept { return limits_; }
  [[nodiscard]] std::string peer_text() const { return channel_.peer_text(); }
  [[nodiscard]] Limits effective_limits() const noexcept { return limits_; }

  /// Fence built from the authority reported at Hello.
  [[nodiscard]] CommandFence current_fence(
      WorkloadId workload, std::optional<CheckpointGeneration> checkpoint_generation = std::nullopt,
      std::optional<AttemptSequence> attempt_sequence = std::nullopt) const;

  [[nodiscard]] Result<AdmissionDecision> submit_session(const SessionRequest& request,
                                                         const CommandFence& fence);
  [[nodiscard]] Result<AdmissionDecision> revalidate_session(SessionId session,
                                                             const CommandFence& fence);
  [[nodiscard]] Result<WaveOutcome> request_wave(SessionId session, ShardIndex shard,
                                                 const CommandFence& fence);
  [[nodiscard]] Status report_source_complete(const SourceCompleteEvidence& evidence,
                                              const CommandFence& fence);
  [[nodiscard]] Status report_transfer(const TransferEvidence& evidence, const CommandFence& fence);
  [[nodiscard]] Status report_verification(const VerificationEvidence& evidence,
                                           const CommandFence& fence);
  [[nodiscard]] Status report_ambiguous(const wire::AmbiguityRequest& request);
  [[nodiscard]] Status cancel_session(SessionId session, const CommandFence& fence,
                                      ReasonCode reason, std::string detail);
  [[nodiscard]] Status pause_session(SessionId session, const CommandFence& fence,
                                     std::string reason);
  [[nodiscard]] Status resume_session(SessionId session, const CommandFence& fence);
  [[nodiscard]] Status record_durability(SessionId session, const DurabilityAssertion& assertion,
                                         const CommandFence& fence);
  [[nodiscard]] Result<SessionView> view_session(SessionId session);
  [[nodiscard]] Result<std::vector<SessionSummary>> list_sessions(std::optional<WorkloadId> workload,
                                                                  std::uint32_t limit);
  [[nodiscard]] Result<AccountingSnapshot> accounting();
  [[nodiscard]] Result<Explanation> explain(SessionId session);
  [[nodiscard]] Status check_invariants();
  [[nodiscard]] Status request_shutdown();
  [[nodiscard]] Status close();

 private:
  CoordinatorClient(wire::MessageChannel channel, wire::HelloResponse hello, std::string identity,
                    Limits limits);

  [[nodiscard]] Result<wire::Message> round_trip(wire::MessageType type, ByteSpan payload,
                                                 wire::MessageType expected);
  [[nodiscard]] Result<wire::StatusPayload> command(wire::MessageType type, ByteSpan payload);

  wire::MessageChannel channel_;
  wire::HelloResponse hello_;
  std::string identity_;
  Limits limits_;
};

}  // namespace ctf
