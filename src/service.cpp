// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/service.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "ctf/protocol.hpp"

namespace ctf {

struct CoordinatorService::Impl {
  Impl(CoordinatorConfig config, const Clock& clock)
      : config_(std::move(config)), clock_(&clock) {}

  CoordinatorConfig config_;
  const Clock* clock_;
  std::unique_ptr<FabricEngine> engine_;
  std::unique_ptr<store::PersistentStore> store_;
  store::LoadReport load_report_;
  net::TcpListener listener_;
  net::StopToken stop_;
  std::vector<std::thread> workers_;
  struct ConnectionWorker {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
  };
  std::vector<ConnectionWorker> connections_;
  std::mutex connections_mutex_;
  std::atomic<std::size_t> active_connections_{0};
  std::thread accept_thread_;
  std::deque<net::TcpSocket> pending_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::mutex persist_mutex_;
  std::mutex stats_mutex_;
  ServiceStats stats_;
  std::mutex lifecycle_mutex_;
  std::condition_variable lifecycle_cv_;
  bool running_ = false;
  bool stop_requested_ = false;
  std::atomic<bool> peer_shutdown_{false};

  void note_connection_accepted() {
    const std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.connections_accepted;
  }
  void note_connection_rejected() {
    const std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.connections_rejected;
  }
  void note_message() {
    const std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.messages_processed;
  }
  void note_protocol_error() {
    const std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.protocol_errors;
  }
  void note_durable(bool ok) {
    const std::lock_guard<std::mutex> guard(stats_mutex_);
    if (ok) {
      ++stats_.durable_writes;
    } else {
      ++stats_.durable_write_failures;
    }
  }

  /// Durability point. Never called while holding the engine lock.
  [[nodiscard]] Status persist(const std::string& label) {
    if (!config_.persist || store_ == nullptr) {
      return Status::success();
    }
    const std::lock_guard<std::mutex> guard(persist_mutex_);
    const Status status = store_->append(label, engine_->export_snapshot());
    note_durable(status.ok());
    return status;
  }

  void wake_lifecycle() {
    const std::lock_guard<std::mutex> guard(lifecycle_mutex_);
    lifecycle_cv_.notify_all();
  }

  void request_stop() {
    stop_.request_stop();
    listener_.close();
    queue_cv_.notify_all();
    {
      const std::lock_guard<std::mutex> guard(lifecycle_mutex_);
      stop_requested_ = true;
    }
    lifecycle_cv_.notify_all();
  }

  [[nodiscard]] wire::StatusPayload status_payload(const Status& status,
                                                   ReasonCode reason) const {
    wire::StatusPayload payload;
    payload.code = status.code();
    payload.reason = reason;
    payload.detail = status.detail();
    return payload;
  }

  [[nodiscard]] Status respond(wire::MessageChannel& channel, const wire::StatusPayload& payload) {
    const Bytes encoded = wire::encode_payload(payload);
    return channel.send(wire::MessageType::StatusResponse, ByteSpan(encoded.data(), encoded.size()));
  }

  [[nodiscard]] Status fail(wire::MessageChannel& channel, ErrorCode code, std::string detail,
                            ReasonCode reason) {
    note_protocol_error();
    wire::StatusPayload payload;
    payload.code = code;
    payload.reason = reason;
    payload.detail = std::move(detail);
    return respond(channel, payload);
  }

  /// Reaps finished connection threads so the thread list stays bounded.
  void reap_connections() {
    const std::lock_guard<std::mutex> guard(connections_mutex_);
    for (auto it = connections_.begin(); it != connections_.end();) {
      if (it->done->load(std::memory_order_acquire)) {
        if (it->thread.joinable()) {
          it->thread.join();
        }
        it = connections_.erase(it);
      } else {
        ++it;
      }
    }
  }

  /// A connection is served by its own bounded thread. Pinning a pool worker to
  /// one long-lived client would starve every client beyond the pool size, so the
  /// concurrency bound is expressed as a maximum number of live connections.
  void dispatch_connection(net::TcpSocket socket) {
    reap_connections();
    // Connections are served concurrently, one handler thread each, up to the
    // configured connection bound. worker_threads is a floor for handler
    // concurrency, never a cap that could starve the (bound-1)th client.
    const std::size_t connection_bound =
        config_.max_pending_connections == 0 ? 64 : config_.max_pending_connections;
    const std::size_t bound = std::max(connection_bound, config_.worker_threads);
    if (active_connections_.load(std::memory_order_acquire) >= bound) {
      note_connection_rejected();
      (void)socket.shutdown_both();
      socket.close();
      return;
    }
    auto done = std::make_shared<std::atomic<bool>>(false);
    active_connections_.fetch_add(1, std::memory_order_acq_rel);
    std::thread worker([this, socket = std::move(socket), done]() mutable {
      handle_connection(std::move(socket));
      done->store(true, std::memory_order_release);
      active_connections_.fetch_sub(1, std::memory_order_acq_rel);
    });
    const std::lock_guard<std::mutex> guard(connections_mutex_);
    connections_.push_back(ConnectionWorker{std::move(worker), std::move(done)});
  }

  void accept_loop() {
    while (!stop_.stop_requested()) {
      Result<net::TcpSocket> accepted = listener_.accept(stop_);
      if (!accepted.ok()) {
        if (stop_.stop_requested() || accepted.code() == ErrorCode::ShuttingDown) {
          break;
        }
        continue;
      }
      note_connection_accepted();
      dispatch_connection(std::move(accepted).value());
    }
  }

  void handle_connection(net::TcpSocket socket) {
    wire::MessageChannel channel(std::move(socket), stop_);
    Result<wire::Message> first = channel.receive();
    if (!first.ok()) {
      note_protocol_error();
      return;
    }
    if (first.value().type != wire::MessageType::HelloRequest) {
      (void)fail(channel, ErrorCode::InvalidStateTransition,
                 "first message on a connection must be a hello request", ReasonCode::Internal);
      (void)channel.close();
      return;
    }
    Result<wire::HelloRequest> hello = wire::decode_payload<wire::HelloRequest>(
        ByteSpan(first.value().payload.data(), first.value().payload.size()), config_.limits);
    if (!hello.ok()) {
      (void)fail(channel, hello.code(), hello.detail(), ReasonCode::Internal);
      (void)channel.close();
      return;
    }
    const wire::ClientKind kind = hello.value().kind;
    // Identity is bound from the connection envelope: evidence records carry
    // this identity, never a caller-supplied provenance string.
    const std::string identity = hello.value().identity.empty() ? std::string("anonymous")
                                                               : hello.value().identity;
    note_message();

    wire::HelloResponse hello_response;
    hello_response.epoch = engine_->epoch();
    const PolicySnapshot policy = engine_->policy();
    const TopologySnapshot topology = engine_->topology();
    hello_response.policy_generation = policy.generation;
    hello_response.topology_generation = topology.generation;
    for (const WorkloadContract& contract : engine_->contracts()) {
      hello_response.contracts.push_back(
          ContractGenerationRecord{contract.workload, contract.generation});
    }
    hello_response.limits = engine_->limits();
    hello_response.server_label = config_.label;
    const Bytes hello_payload = wire::encode_payload(hello_response);
    Status sent = channel.send(wire::MessageType::HelloResponse,
                               ByteSpan(hello_payload.data(), hello_payload.size()));
    if (!sent.ok()) {
      (void)channel.close();
      return;
    }

    while (!stop_.stop_requested()) {
      Result<wire::Message> message = channel.receive();
      if (!message.ok()) {
        if (message.code() == ErrorCode::PeerClosed || message.code() == ErrorCode::ShuttingDown) {
          break;
        }
        (void)fail(channel, message.code(), message.detail(), ReasonCode::Internal);
        break;
      }
      note_message();
      const Status dispatch_status =
          dispatch(channel, message.value(), kind, identity);
      if (!dispatch_status.ok() && dispatch_status.code() == ErrorCode::ShuttingDown) {
        break;
      }
    }
    (void)channel.close();
  }

  [[nodiscard]] Status dispatch(wire::MessageChannel& channel, const wire::Message& message,
                                wire::ClientKind kind, const std::string& identity) {
    const Limits& limits = config_.limits;
    switch (message.type) {
      case wire::MessageType::HelloRequest:
        return fail(channel, ErrorCode::InvalidStateTransition,
                    "hello was already completed on this connection", ReasonCode::Internal);
      case wire::MessageType::SubmitSession: {
        Result<wire::SubmitRequest> request = wire::decode_payload<wire::SubmitRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        Result<AdmissionDecision> decision =
            engine_->submit_session(request.value().request, request.value().fence);
        if (!decision.ok()) {
          return fail(channel, decision.code(), decision.detail(),
                      reason_for_fence_code(decision.code()));
        }
        const Status durable = persist("submit-session");
        if (!durable.ok()) {
          return fail(channel, durable.code(), durable.detail(), ReasonCode::Internal);
        }
        const Bytes payload = wire::encode_payload(decision.value());
        return channel.send(wire::MessageType::DecisionResponse,
                            ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::RevalidateSession: {
        Result<wire::RevalidateRequest> request = wire::decode_payload<wire::RevalidateRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        Result<AdmissionDecision> decision =
            engine_->revalidate_session(request.value().session, request.value().fence);
        if (!decision.ok()) {
          return fail(channel, decision.code(), decision.detail(),
                      reason_for_fence_code(decision.code()));
        }
        const Status durable = persist("revalidate-session");
        if (!durable.ok()) {
          return fail(channel, durable.code(), durable.detail(), ReasonCode::Internal);
        }
        const Bytes payload = wire::encode_payload(decision.value());
        return channel.send(wire::MessageType::DecisionResponse,
                            ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::RequestWave: {
        Result<wire::WaveRequest> request = wire::decode_payload<wire::WaveRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        if (kind != wire::ClientKind::Sender) {
          return fail(channel, ErrorCode::NotAuthorized,
                      "only a sender may request checkpoint traffic credit",
                      ReasonCode::AuthorityStale);
        }
        Result<WaveOutcome> outcome =
            engine_->request_wave(request.value().session, request.value().shard,
                                  request.value().fence);
        if (!outcome.ok()) {
          return fail(channel, outcome.code(), outcome.detail(),
                      reason_for_fence_code(outcome.code()));
        }
        if (outcome.value().granted) {
          const Status durable = persist("wave-grant");
          if (!durable.ok()) {
            return fail(channel, durable.code(), durable.detail(), ReasonCode::Internal);
          }
        }
        const Bytes payload = wire::encode_payload(outcome.value());
        return channel.send(wire::MessageType::WaveResponse, ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::ReportSourceComplete: {
        Result<wire::SourceCompleteRequest> request =
            wire::decode_payload<wire::SourceCompleteRequest>(
                ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status =
            engine_->report_source_complete(request.value().evidence, request.value().fence);
        return finish_command(channel, status, "source-complete", identity);
      }
      case wire::MessageType::ReportTransfer: {
        Result<wire::TransferReport> request = wire::decode_payload<wire::TransferReport>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status =
            engine_->report_transfer(request.value().evidence, request.value().fence);
        return finish_command(channel, status, "transfer-evidence", identity);
      }
      case wire::MessageType::ReportVerification: {
        Result<wire::VerificationReport> request = wire::decode_payload<wire::VerificationReport>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        if (kind != wire::ClientKind::Sink) {
          return fail(channel, ErrorCode::NotAuthorized,
                      "only a sink may report destination verification evidence",
                      ReasonCode::AuthorityStale);
        }
        VerificationEvidence evidence = request.value().evidence;
        evidence.verifier_identity = identity;  // bound from the connection envelope
        const Status status = engine_->report_verification(evidence, request.value().fence);
        return finish_command(channel, status, "verification-evidence", identity);
      }
      case wire::MessageType::ReportAmbiguous: {
        Result<wire::AmbiguityRequest> request = wire::decode_payload<wire::AmbiguityRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status =
            engine_->report_ambiguous(request.value().session, request.value().attempt,
                                      request.value().sequence, request.value().cause,
                                      request.value().fence);
        return finish_command(channel, status, "ambiguity", identity);
      }
      case wire::MessageType::CancelSession: {
        Result<wire::CancelRequest> request = wire::decode_payload<wire::CancelRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status = engine_->cancel_session(
            request.value().session, request.value().fence, request.value().reason,
            request.value().detail);
        return finish_command(channel, status, "cancel", identity);
      }
      case wire::MessageType::PauseSession: {
        Result<wire::PauseRequest> request = wire::decode_payload<wire::PauseRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status = engine_->pause_session(request.value().session, request.value().fence,
                                                     request.value().reason);
        return finish_command(channel, status, "pause", identity);
      }
      case wire::MessageType::ResumeSession: {
        Result<wire::ResumeRequest> request = wire::decode_payload<wire::ResumeRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status = engine_->resume_session(request.value().session, request.value().fence);
        return finish_command(channel, status, "resume", identity);
      }
      case wire::MessageType::RecordDurability: {
        Result<wire::DurabilityRequest> request = wire::decode_payload<wire::DurabilityRequest>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        const Status status = engine_->record_durability_assertion(
            request.value().session, request.value().assertion, request.value().fence);
        return finish_command(channel, status, "durability-assertion", identity);
      }
      case wire::MessageType::QuerySession: {
        Result<wire::SessionQuery> request = wire::decode_payload<wire::SessionQuery>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        Result<SessionView> view = engine_->view_session(request.value().session);
        if (!view.ok()) {
          return fail(channel, view.code(), view.detail(), ReasonCode::SessionNotFound);
        }
        const Bytes payload = wire::encode_payload(view.value());
        return channel.send(wire::MessageType::SessionViewResponse,
                            ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::QuerySessions: {
        Result<wire::SessionsQuery> request = wire::decode_payload<wire::SessionsQuery>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        std::optional<WorkloadId> workload;
        if (request.value().has_workload) {
          workload = request.value().workload;
        }
        Result<std::vector<SessionSummary>> sessions =
            engine_->list_sessions(workload, request.value().limit);
        if (!sessions.ok()) {
          return fail(channel, sessions.code(), sessions.detail(), ReasonCode::Internal);
        }
        wire::SessionListResponse response;
        response.sessions = std::move(sessions).value();
        const Bytes payload = wire::encode_payload(response);
        return channel.send(wire::MessageType::SessionListResponse,
                            ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::QueryAccounting: {
        AccountingSnapshot accounting = engine_->accounting();
        const Bytes payload = wire::encode_payload(accounting);
        return channel.send(wire::MessageType::AccountingResponse,
                            ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::QueryExplain: {
        Result<wire::SessionQuery> request = wire::decode_payload<wire::SessionQuery>(
            ByteSpan(message.payload.data(), message.payload.size()), limits);
        if (!request.ok()) {
          return fail(channel, request.code(), request.detail(), ReasonCode::Internal);
        }
        Result<Explanation> explanation = engine_->explain(request.value().session);
        if (!explanation.ok()) {
          return fail(channel, explanation.code(), explanation.detail(),
                      ReasonCode::SessionNotFound);
        }
        const Bytes payload = wire::encode_payload(explanation.value());
        return channel.send(wire::MessageType::ExplanationResponse,
                            ByteSpan(payload.data(), payload.size()));
      }
      case wire::MessageType::QueryInvariants: {
        const Status status = engine_->check_invariants();
        const wire::StatusPayload payload = status_payload(status, ReasonCode::Internal);
        return respond(channel, payload);
      }
      case wire::MessageType::ShutdownRequest: {
        if (kind != wire::ClientKind::Operator && kind != wire::ClientKind::Observer) {
          return fail(channel, ErrorCode::NotAuthorized,
                      "only an operator connection may request shutdown", ReasonCode::Internal);
        }
        (void)engine_->begin_shutdown();
        const Status durable = persist("shutdown");
        const wire::StatusPayload payload =
            status_payload(durable, ReasonCode::FabricShuttingDown);
        const Status sent = respond(channel, payload);
        peer_shutdown_.store(true);
        request_stop();
        return sent;
      }
      case wire::MessageType::HelloResponse:
      case wire::MessageType::DecisionResponse:
      case wire::MessageType::WaveResponse:
      case wire::MessageType::SessionViewResponse:
      case wire::MessageType::SessionListResponse:
      case wire::MessageType::AccountingResponse:
      case wire::MessageType::ExplanationResponse:
      case wire::MessageType::StatusResponse:
        return fail(channel, ErrorCode::InvalidStateTransition,
                    "peer sent a response where a request was expected", ReasonCode::Internal);
    }
    return fail(channel, ErrorCode::UnknownMessageType, "message type is not handled",
                ReasonCode::Internal);
  }

  [[nodiscard]] Status finish_command(wire::MessageChannel& channel, const Status& status,
                                      const std::string& label, const std::string& identity) {
    (void)identity;
    if (!status.ok()) {
      return fail(channel, status.code(), status.detail(), reason_for_fence_code(status.code()));
    }
    const Status durable = persist(label);
    if (!durable.ok()) {
      return fail(channel, durable.code(), durable.detail(), ReasonCode::Internal);
    }
    wire::StatusPayload payload;
    payload.code = ErrorCode::Ok;
    payload.reason = ReasonCode::Admitted;
    payload.detail = label + " accepted";
    return respond(channel, payload);
  }
};

CoordinatorService::CoordinatorService(CoordinatorConfig config, const Clock& clock)
    : impl_(std::make_unique<Impl>(std::move(config), clock)) {}

CoordinatorService::~CoordinatorService() {
  if (impl_ != nullptr) {
    (void)request_stop();
    (void)wait();
  }
}

Status CoordinatorService::start() {
  Impl& impl = *impl_;
  {
    const std::lock_guard<std::mutex> guard(impl.lifecycle_mutex_);
    if (impl.running_) {
      return Status::error(ErrorCode::AlreadyExists, "service is already running");
    }
  }
  EngineConfig engine_config;
  engine_config.policy = impl.config_.policy;
  engine_config.topology = impl.config_.topology;
  engine_config.contracts = impl.config_.contracts;
  engine_config.limits = impl.config_.limits;
  engine_config.identity_seed = impl.config_.identity_seed;
  engine_config.epoch = CoordinatorEpoch{IncarnationId(1), EpochTerm(1)};
  impl.engine_ = std::make_unique<FabricEngine>(engine_config, *impl.clock_);
  const Status startup = impl.engine_->startup_status();
  if (!startup.ok()) {
    impl.engine_.reset();
    return startup;
  }

  std::uint64_t previous_incarnation = 0;
  bool restored_state = false;
  if (impl.config_.persist) {
    store::StoreConfig store_config;
    store_config.directory = impl.config_.data_directory;
    store_config.limits = impl.config_.limits;
    impl.store_ = std::make_unique<store::PersistentStore>(store_config);
    const Status opened = impl.store_->open();
    if (!opened.ok()) {
      impl.store_.reset();
      impl.engine_.reset();
      return opened;
    }
    if (impl.store_->has_state()) {
      Result<EngineSnapshot> snapshot = impl.store_->load(&impl.load_report_);
      if (!snapshot.ok()) {
        impl.store_.reset();
        impl.engine_.reset();
        return Status::error(snapshot.code(),
                             "persisted state was refused: " + snapshot.detail());
      }
      previous_incarnation = snapshot.value().epoch.incarnation.value();
      restored_state = true;
      const Status restored = impl.engine_->restore(snapshot.value());
      if (!restored.ok()) {
        impl.store_.reset();
        impl.engine_.reset();
        return Status::error(restored.code(), "restore refused: " + restored.detail());
      }
    }
  }

  // A new process is a new incarnation: the previous incarnation's liveness,
  // freshness, and in-flight credit are all fenced off here. A first boot is
  // incarnation 1; a restart is one incarnation beyond the persisted one.
  if (restored_state) {
    const CoordinatorEpoch epoch{IncarnationId(previous_incarnation + 1), EpochTerm(1)};
    const Status advanced = impl.engine_->advance_epoch(epoch);
    if (!advanced.ok()) {
      return advanced;
    }
  }

  Result<net::TcpListener> listener =
      net::TcpListener::bind(impl.config_.bind_host, impl.config_.port, 64);
  if (!listener.ok()) {
    return listener.status();
  }
  impl.listener_ = std::move(listener).value();

  {
    const std::lock_guard<std::mutex> guard(impl.lifecycle_mutex_);
    impl.running_ = true;
    impl.stop_requested_ = false;
  }
  impl.accept_thread_ = std::thread([&impl] { impl.accept_loop(); });
  if (impl.config_.persist && impl.store_ != nullptr) {
    // A full snapshot at boot: recovery then reads one record instead of
    // replaying the whole journal.
    const std::lock_guard<std::mutex> guard(impl.persist_mutex_);
    const Status durable = impl.store_->persist(impl.engine_->export_snapshot());
    impl.note_durable(durable.ok());
    if (!durable.ok()) {
      (void)request_stop();
      (void)wait();
      return durable;
    }
  }
  return Status::success();
}

Status CoordinatorService::wait() {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.lifecycle_mutex_);
  impl.lifecycle_cv_.wait(lock, [&impl] { return impl.stop_requested_ || !impl.running_; });
  lock.unlock();
  impl.stop_.request_stop();
  impl.listener_.close();
  impl.queue_cv_.notify_all();
  if (impl.accept_thread_.joinable()) {
    impl.accept_thread_.join();
  }
  for (std::thread& worker : impl.workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  impl.workers_.clear();
  {
    // Connection handlers observe the stop token and return; join them all so
    // shutdown leaves no thread behind.
    const std::lock_guard<std::mutex> guard(impl.connections_mutex_);
    for (Impl::ConnectionWorker& connection : impl.connections_) {
      if (connection.thread.joinable()) {
        connection.thread.join();
      }
    }
    impl.connections_.clear();
  }
  {
    const std::lock_guard<std::mutex> queue_guard(impl.queue_mutex_);
    for (net::TcpSocket& socket : impl.pending_) {
      (void)socket.shutdown_both();
      socket.close();
    }
    impl.pending_.clear();
  }
  if (impl.config_.persist && impl.store_ != nullptr && impl.engine_ != nullptr) {
    const std::lock_guard<std::mutex> guard(impl.persist_mutex_);
    const Status status = impl.store_->persist(impl.engine_->export_snapshot());
    impl.note_durable(status.ok());
    if (!status.ok()) {
      return status;
    }
  }
  const std::lock_guard<std::mutex> guard(impl.lifecycle_mutex_);
  impl.running_ = false;
  return Status::success();
}

Status CoordinatorService::request_stop() {
  impl_->request_stop();
  return Status::success();
}

Status CoordinatorService::shutdown() {
  (void)request_stop();
  return wait();
}

std::uint16_t CoordinatorService::port() const { return impl_->listener_.port(); }

bool CoordinatorService::stop_requested() const {
  const std::lock_guard<std::mutex> guard(impl_->lifecycle_mutex_);
  return impl_->stop_requested_;
}

bool CoordinatorService::running() const {
  const std::lock_guard<std::mutex> guard(impl_->lifecycle_mutex_);
  return impl_->running_;
}

FabricEngine& CoordinatorService::engine() { return *impl_->engine_; }

const store::LoadReport& CoordinatorService::load_report() const { return impl_->load_report_; }

ServiceStats CoordinatorService::stats() const {
  const std::lock_guard<std::mutex> guard(impl_->stats_mutex_);
  return impl_->stats_;
}

CoordinatorEpoch CoordinatorService::epoch() const {
  return impl_->engine_ == nullptr ? CoordinatorEpoch{} : impl_->engine_->epoch();
}

std::string CoordinatorService::endpoint_text() const {
  return impl_->config_.bind_host + ":" + std::to_string(impl_->listener_.port());
}

}  // namespace ctf
