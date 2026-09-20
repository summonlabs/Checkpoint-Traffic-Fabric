#pragma once

// Minimal TCP transport.
//
// Deliberately small: blocking sockets with a bounded wait so a reader can
// observe a stop request instead of blocking forever. Shutdown is cooperative
// and never depends on a timeout being "long enough": every wait re-checks the
// stop token, and close() releases the descriptor so a blocked reader returns.

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "ctf/bytes.hpp"
#include "ctf/status.hpp"

namespace ctf::net {

/// Shared cancellation flag. Copies of a token observe the same request.
class StopToken {
 public:
  StopToken() : flag_(std::make_shared<std::atomic<bool>>(false)) {}

  void request_stop() const noexcept { flag_->store(true, std::memory_order_release); }
  [[nodiscard]] bool stop_requested() const noexcept {
    return flag_->load(std::memory_order_acquire);
  }

 private:
  std::shared_ptr<std::atomic<bool>> flag_;
};

/// One-time process-wide socket subsystem initialization.
void ensure_socket_subsystem();

/// Human-readable description of the last socket error on this thread.
[[nodiscard]] std::string last_socket_error_text();

class TcpSocket {
 public:
  TcpSocket() = default;
  ~TcpSocket();
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;

  [[nodiscard]] static Result<TcpSocket> connect(std::string_view host, std::uint16_t port,
                                                 const StopToken& stop);

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
  void close() noexcept;
  /// Half-closes both directions so a blocked peer reader wakes up.
  [[nodiscard]] Status shutdown_both() noexcept;

  /// Returns the number of bytes read, or 0 when the peer closed cleanly.
  [[nodiscard]] Result<std::size_t> read_some(MutableByteSpan buffer, const StopToken& stop);
  [[nodiscard]] Status write_all(ByteSpan data, const StopToken& stop);

  [[nodiscard]] std::string peer_text() const;
  void set_nodelay(bool enabled) noexcept;

  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~0ULL);

 private:
  friend class TcpListener;
  explicit TcpSocket(std::uintptr_t handle) noexcept : handle_(handle) {}
  std::uintptr_t handle_ = kInvalidHandle;
};

class TcpListener {
 public:
  TcpListener() = default;
  ~TcpListener();
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  /// Binds and listens. Port 0 selects an ephemeral port, which port() reports.
  [[nodiscard]] static Result<TcpListener> bind(std::string_view host, std::uint16_t port,
                                                int backlog);
  [[nodiscard]] Result<TcpSocket> accept(const StopToken& stop);

  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] bool valid() const noexcept { return handle_ != TcpSocket::kInvalidHandle; }
  void close() noexcept;

 private:
  std::uintptr_t handle_ = TcpSocket::kInvalidHandle;
  std::uint16_t port_ = 0;
};

}  // namespace ctf::net
