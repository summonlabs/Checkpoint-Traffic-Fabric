// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/net.hpp"

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace ctf::net {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

constexpr int kWaitSliceMillis = 25;

[[nodiscard]] NativeSocket to_native(std::uintptr_t handle) noexcept {
  return static_cast<NativeSocket>(handle);
}

void close_native(NativeSocket socket) noexcept {
  if (socket == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(socket);
#else
  ::close(socket);
#endif
}

enum class WaitOutcome { Ready, TimedOut, Stopped, Failed };

[[nodiscard]] WaitOutcome wait_for(NativeSocket socket, bool want_read, const StopToken& stop) {
  for (;;) {
    if (stop.stop_requested()) {
      return WaitOutcome::Stopped;
    }
    fd_set read_set;
    fd_set write_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    if (want_read) {
      FD_SET(socket, &read_set);
    } else {
      FD_SET(socket, &write_set);
    }
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = kWaitSliceMillis * 1000;
#if defined(_WIN32)
    const int result = ::select(0, &read_set, &write_set, nullptr, &timeout);
#else
    const int result = ::select(socket + 1, &read_set, &write_set, nullptr, &timeout);
#endif
    if (result > 0) {
      return WaitOutcome::Ready;
    }
    if (result == 0) {
      continue;  // slice elapsed; re-check the stop token
    }
    return WaitOutcome::Failed;
  }
}

}  // namespace

void ensure_socket_subsystem() {
#if defined(_WIN32)
  static std::once_flag flag;
  std::call_once(flag, []() {
    WSADATA data{};
    (void)::WSAStartup(MAKEWORD(2, 2), &data);
  });
#endif
}

std::string last_socket_error_text() {
#if defined(_WIN32)
  return "socket error " + std::to_string(::WSAGetLastError());
#else
  return std::string(std::strerror(errno));
#endif
}

TcpSocket::~TcpSocket() { close(); }

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = TcpSocket::kInvalidHandle;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = TcpSocket::kInvalidHandle;
  }
  return *this;
}

void TcpSocket::close() noexcept {
  if (handle_ != kInvalidHandle) {
    close_native(to_native(handle_));
    handle_ = kInvalidHandle;
  }
}

Status TcpSocket::shutdown_both() noexcept {
  if (handle_ == kInvalidHandle) {
    return Status::success();
  }
#if defined(_WIN32)
  if (::shutdown(to_native(handle_), SD_BOTH) != 0) {
    return Status::error(ErrorCode::IoFailure, last_socket_error_text());
  }
#else
  if (::shutdown(to_native(handle_), SHUT_RDWR) != 0) {
    return Status::error(ErrorCode::IoFailure, last_socket_error_text());
  }
#endif
  return Status::success();
}

Result<TcpSocket> TcpSocket::connect(std::string_view host, std::uint16_t port,
                                     const StopToken& stop) {
  ensure_socket_subsystem();
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  const std::string host_text(host);
  const std::string port_text = std::to_string(port);
  addrinfo* results = nullptr;
  const int lookup = ::getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &results);
  if (lookup != 0 || results == nullptr) {
    return Status::error(ErrorCode::ConnectionRefused, "address resolution failed for " + host_text);
  }
  Status last_error = Status::error(ErrorCode::ConnectionRefused, "no address could be reached");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    if (stop.stop_requested()) {
      last_error = Status::error(ErrorCode::ShuttingDown, "connect cancelled");
      break;
    }
    NativeSocket socket =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (socket == kInvalidSocket) {
      last_error = Status::error(ErrorCode::IoFailure, last_socket_error_text());
      continue;
    }
#if defined(_WIN32)
    u_long non_blocking = 1;
    ::ioctlsocket(socket, FIONBIO, &non_blocking);
#else
    const int flags = ::fcntl(socket, F_GETFL, 0);
    (void)::fcntl(socket, F_SETFL, flags | O_NONBLOCK);
#endif
    const int rc = ::connect(socket, candidate->ai_addr,
                             static_cast<int>(candidate->ai_addrlen));
    bool connected = rc == 0;
    if (!connected) {
#if defined(_WIN32)
      const int error = ::WSAGetLastError();
      connected = error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
      connected = errno == EINPROGRESS || errno == EWOULDBLOCK;
#endif
    }
    if (connected && rc != 0) {
      const WaitOutcome outcome = wait_for(socket, false, stop);
      if (outcome == WaitOutcome::Ready) {
        int so_error = 0;
#if defined(_WIN32)
        int length = static_cast<int>(sizeof(so_error));
#else
        socklen_t length = sizeof(so_error);
#endif
        if (::getsockopt(socket, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char*>(&so_error), &length) == 0 &&
            so_error == 0) {
          connected = true;
        } else {
          connected = false;
          last_error = Status::error(ErrorCode::ConnectionRefused, "connection was refused");
        }
      } else {
        connected = false;
        last_error = outcome == WaitOutcome::Stopped
                         ? Status::error(ErrorCode::ShuttingDown, "connect cancelled")
                         : Status::error(ErrorCode::IoFailure, "connect wait failed");
      }
    }
    if (!connected) {
      close_native(socket);
      continue;
    }
#if defined(_WIN32)
    u_long blocking = 0;
    ::ioctlsocket(socket, FIONBIO, &blocking);
#else
    (void)::fcntl(socket, F_SETFL, flags);
#endif
    ::freeaddrinfo(results);
    TcpSocket out(static_cast<std::uintptr_t>(socket));
    out.set_nodelay(true);
    return out;
  }
  ::freeaddrinfo(results);
  return last_error;
}

Result<std::size_t> TcpSocket::read_some(MutableByteSpan buffer, const StopToken& stop) {
  if (!valid()) {
    return Status::error(ErrorCode::NotReady, "socket is not open");
  }
  if (buffer.empty()) {
    return static_cast<std::size_t>(0);
  }
  for (;;) {
    if (stop.stop_requested()) {
      return Status::error(ErrorCode::ShuttingDown, "read cancelled");
    }
    const WaitOutcome outcome = wait_for(to_native(handle_), true, stop);
    if (outcome == WaitOutcome::Stopped) {
      return Status::error(ErrorCode::ShuttingDown, "read cancelled");
    }
    if (outcome == WaitOutcome::Failed) {
      return Status::error(ErrorCode::IoFailure, last_socket_error_text());
    }
    const int received =
        ::recv(to_native(handle_), reinterpret_cast<char*>(buffer.data()),
               static_cast<int>(buffer.size()), 0);
    if (received > 0) {
      return static_cast<std::size_t>(received);
    }
    if (received == 0) {
      return static_cast<std::size_t>(0);  // peer closed cleanly
    }
#if defined(_WIN32)
    const int error = ::WSAGetLastError();
    if (error == WSAEWOULDBLOCK || error == WSAEINTR) {
      continue;
    }
    if (error == WSAECONNRESET || error == WSAECONNABORTED) {
      return static_cast<std::size_t>(0);
    }
#else
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
      continue;
    }
    if (errno == ECONNRESET) {
      return static_cast<std::size_t>(0);
    }
#endif
    return Status::error(ErrorCode::IoFailure, last_socket_error_text());
  }
}

Status TcpSocket::write_all(ByteSpan data, const StopToken& stop) {
  if (!valid()) {
    return Status::error(ErrorCode::NotReady, "socket is not open");
  }
  std::size_t sent = 0;
  while (sent < data.size()) {
    if (stop.stop_requested()) {
      return Status::error(ErrorCode::ShuttingDown, "write cancelled");
    }
    const WaitOutcome outcome = wait_for(to_native(handle_), false, stop);
    if (outcome == WaitOutcome::Stopped) {
      return Status::error(ErrorCode::ShuttingDown, "write cancelled");
    }
    if (outcome == WaitOutcome::Failed) {
      return Status::error(ErrorCode::IoFailure, last_socket_error_text());
    }
    const int written = ::send(to_native(handle_),
                               reinterpret_cast<const char*>(data.data() + sent),
                               static_cast<int>(data.size() - sent), 0);
    if (written > 0) {
      sent += static_cast<std::size_t>(written);
      continue;
    }
#if defined(_WIN32)
    const int error = ::WSAGetLastError();
    if (error == WSAEWOULDBLOCK || error == WSAEINTR) {
      continue;
    }
#else
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
      continue;
    }
#endif
    return Status::error(ErrorCode::IoFailure, last_socket_error_text());
  }
  return Status::success();
}

std::string TcpSocket::peer_text() const {
  if (!valid()) {
    return "<closed>";
  }
  sockaddr_storage address{};
#if defined(_WIN32)
  int length = static_cast<int>(sizeof(address));
#else
  socklen_t length = sizeof(address);
#endif
  if (::getpeername(to_native(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return "<unknown>";
  }
  char host[64] = {};
  char service[16] = {};
  if (::getnameinfo(reinterpret_cast<sockaddr*>(&address), length, host, sizeof(host), service,
                    sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return "<unknown>";
  }
  return std::string(host) + ":" + service;
}

void TcpSocket::set_nodelay(bool enabled) noexcept {
  if (!valid()) {
    return;
  }
  const int value = enabled ? 1 : 0;
  (void)::setsockopt(to_native(handle_), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&value), static_cast<int>(sizeof(value)));
}

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept
    : handle_(other.handle_), port_(other.port_) {
  other.handle_ = TcpSocket::kInvalidHandle;
  other.port_ = 0;
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = TcpSocket::kInvalidHandle;
    other.port_ = 0;
  }
  return *this;
}

void TcpListener::close() noexcept {
  if (handle_ != TcpSocket::kInvalidHandle) {
    close_native(to_native(handle_));
    handle_ = TcpSocket::kInvalidHandle;
  }
}

Result<TcpListener> TcpListener::bind(std::string_view host, std::uint16_t port, int backlog) {
  ensure_socket_subsystem();
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  const std::string host_text(host);
  const std::string port_text = std::to_string(port);
  addrinfo* results = nullptr;
  const int lookup =
      ::getaddrinfo(host_text.empty() ? nullptr : host_text.c_str(), port_text.c_str(), &hints,
                    &results);
  if (lookup != 0 || results == nullptr) {
    return Status::error(ErrorCode::IoFailure, "cannot resolve bind address " + host_text);
  }
  Status last_error = Status::error(ErrorCode::IoFailure, "bind failed");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    NativeSocket socket =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (socket == kInvalidSocket) {
      last_error = Status::error(ErrorCode::IoFailure, last_socket_error_text());
      continue;
    }
    const int reuse = 1;
    (void)::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                       static_cast<int>(sizeof(reuse)));
    if (::bind(socket, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      last_error = Status::error(ErrorCode::IoFailure, "bind failed: " + last_socket_error_text());
      close_native(socket);
      continue;
    }
    if (::listen(socket, backlog) != 0) {
      last_error = Status::error(ErrorCode::IoFailure, "listen failed: " + last_socket_error_text());
      close_native(socket);
      continue;
    }
    sockaddr_storage address{};
#if defined(_WIN32)
    int length = static_cast<int>(sizeof(address));
#else
    socklen_t length = sizeof(address);
#endif
    std::uint16_t bound_port = port;
    if (::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) == 0) {
      if (address.ss_family == AF_INET) {
        bound_port = ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port);
      } else if (address.ss_family == AF_INET6) {
        bound_port = ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port);
      }
    }
    ::freeaddrinfo(results);
    TcpListener listener;
    listener.handle_ = static_cast<std::uintptr_t>(socket);
    listener.port_ = bound_port;
    return listener;
  }
  ::freeaddrinfo(results);
  return last_error;
}

Result<TcpSocket> TcpListener::accept(const StopToken& stop) {
  if (!valid()) {
    return Status::error(ErrorCode::NotReady, "listener is not open");
  }
  for (;;) {
    const WaitOutcome outcome = wait_for(to_native(handle_), true, stop);
    if (outcome == WaitOutcome::Stopped) {
      return Status::error(ErrorCode::ShuttingDown, "accept cancelled");
    }
    if (outcome == WaitOutcome::Failed) {
      return Status::error(ErrorCode::IoFailure, last_socket_error_text());
    }
    sockaddr_storage address{};
#if defined(_WIN32)
    int length = static_cast<int>(sizeof(address));
#else
    socklen_t length = sizeof(address);
#endif
    NativeSocket accepted =
        ::accept(to_native(handle_), reinterpret_cast<sockaddr*>(&address), &length);
    if (accepted == kInvalidSocket) {
#if defined(_WIN32)
      const int error = ::WSAGetLastError();
      if (error == WSAEWOULDBLOCK || error == WSAEINTR) {
        continue;
      }
#else
      if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
        continue;
      }
#endif
      return Status::error(ErrorCode::IoFailure, last_socket_error_text());
    }
    TcpSocket socket(static_cast<std::uintptr_t>(accepted));
    socket.set_nodelay(true);
    return socket;
  }
}

}  // namespace ctf::net
