#pragma once

// Shared command-line plumbing for the runtime tools.
//
// Every tool is explicit about what it could not do: usage errors, refused
// commands, and unreachable coordinators exit with distinct codes, and a
// refusal prints the deterministic code and detail rather than a boolean.

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ctf/client.hpp"
#include "ctf/ids.hpp"
#include "ctf/model.hpp"
#include "ctf/net.hpp"
#include "ctf/report.hpp"
#include "ctf/status.hpp"

namespace ctf::cli {

inline constexpr int kExitOk = 0;
inline constexpr int kExitUsage = 1;
inline constexpr int kExitRefused = 2;
inline constexpr int kExitTransport = 3;
inline constexpr int kExitInternal = 4;

class Arguments {
 public:
  Arguments(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
      tokens_.emplace_back(argv[i]);
    }
  }

  [[nodiscard]] bool empty() const noexcept { return tokens_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return tokens_.size(); }
  [[nodiscard]] const std::string& at(std::size_t index) const { return tokens_[index]; }
  [[nodiscard]] const std::vector<std::string>& tokens() const noexcept { return tokens_; }

  /// Returns the value of --name, or nullopt when the flag is absent.
  [[nodiscard]] std::optional<std::string> flag(std::string_view name) const {
    for (std::size_t i = 0; i + 1 < tokens_.size(); ++i) {
      if (tokens_[i] == name) {
        return tokens_[i + 1];
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] bool has(std::string_view name) const {
    return std::find(tokens_.begin(), tokens_.end(), name) != tokens_.end();
  }

  /// First token that is not a flag value.
  [[nodiscard]] bool command(std::string* out) const {
    for (std::size_t i = 0; i < tokens_.size(); ++i) {
      if (tokens_[i].rfind("--", 0) == 0) {
        ++i;  // skip the flag value
        continue;
      }
      *out = tokens_[i];
      return true;
    }
    return false;
  }

 private:
  std::vector<std::string> tokens_;
};

struct Endpoint {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
};

[[nodiscard]] inline Result<Endpoint> parse_endpoint(const std::string& text) {
  const std::size_t colon = text.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= text.size()) {
    return Status::error(ErrorCode::InvalidSyntax, "endpoint must be host:port");
  }
  const std::string host = text.substr(0, colon);
  const std::optional<ShardIndex> port = ShardIndex::parse(text.substr(colon + 1));
  if (!port.has_value() || port->value() == 0 || port->value() > 65535U) {
    return Status::error(ErrorCode::InvalidSyntax, "endpoint port must be 1..65535");
  }
  Endpoint endpoint;
  endpoint.host = host;
  endpoint.port = static_cast<std::uint16_t>(port->value());
  return endpoint;
}

[[nodiscard]] inline Result<std::uint64_t> parse_u64_flag(const Arguments& args,
                                                          const std::string& name) {
  const std::optional<std::string> raw = args.flag(name);
  if (!raw.has_value()) {
    return Status::error(ErrorCode::MissingField, name + " is required");
  }
  const std::optional<StrongScalar<struct CliNumberTag, std::uint64_t>> parsed =
      StrongScalar<struct CliNumberTag, std::uint64_t>::parse(raw.value());
  if (!parsed.has_value()) {
    return Status::error(ErrorCode::InvalidSyntax, name + " must be an unsigned decimal number");
  }
  return parsed->value();
}

[[nodiscard]] inline Result<std::uint32_t> parse_u32_flag(const Arguments& args,
                                                          const std::string& name) {
  const std::optional<std::string> raw = args.flag(name);
  if (!raw.has_value()) {
    return Status::error(ErrorCode::MissingField, name + " is required");
  }
  const std::optional<ShardIndex> parsed = ShardIndex::parse(raw.value());
  if (!parsed.has_value()) {
    return Status::error(ErrorCode::InvalidSyntax,
                         name + " must be an unsigned 32-bit decimal number");
  }
  return parsed->value();
}

[[nodiscard]] inline Result<Endpoint> require_endpoint(const Arguments& args) {
  const std::optional<std::string> raw = args.flag("--endpoint");
  if (!raw.has_value()) {
    return Status::error(ErrorCode::MissingField, "--endpoint host:port is required");
  }
  return parse_endpoint(raw.value());
}

[[nodiscard]] inline Result<SessionId> require_session(const Arguments& args) {
  const std::optional<std::string> raw = args.flag("--session");
  if (!raw.has_value()) {
    return Status::error(ErrorCode::MissingField, "--session <uuid> is required");
  }
  const std::optional<SessionId> session = SessionId::parse(raw.value());
  if (!session.has_value()) {
    return Status::error(ErrorCode::InvalidSyntax, "--session must be a canonical uuid");
  }
  return session.value();
}

[[nodiscard]] inline int report_refusal(const Status& status) {
  std::cerr << "refused: " << to_string(status.code());
  if (!status.detail().empty()) {
    std::cerr << ": " << status.detail();
  }
  std::cerr << "\n";
  return kExitRefused;
}

[[nodiscard]] inline ClientConfig client_config(const Endpoint& endpoint, wire::ClientKind kind,
                                                const std::string& identity) {
  ClientConfig config;
  config.host = endpoint.host;
  config.port = endpoint.port;
  config.kind = kind;
  config.identity = identity;
  return config;
}

[[nodiscard]] inline std::string join_endpoint(const std::string& host, std::uint16_t port) {
  return host + ":" + std::to_string(port);
}

}  // namespace ctf::cli
