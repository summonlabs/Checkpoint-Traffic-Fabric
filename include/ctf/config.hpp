#pragma once

// Operator configuration.
//
// The format is a strict key = value file: unknown keys, duplicate keys,
// malformed numbers, and missing required keys are all refused with the offending
// line, so a typo cannot silently change fabric behaviour. Values are parsed with
// the same checked arithmetic the wire uses.

#include <filesystem>
#include <string>
#include <string_view>

#include "ctf/service.hpp"
#include "ctf/status.hpp"

namespace ctf::config {

struct FileConfig {
  CoordinatorConfig coordinator;
  std::string source;
};

/// Parses configuration text. Every diagnostic names the offending line.
[[nodiscard]] Result<FileConfig> parse_config(std::string_view text, std::string_view source_label);

[[nodiscard]] Result<FileConfig> load_config_file(const std::filesystem::path& path);

/// Configuration used when no file is supplied: bounded, non-persistent, and
/// deliberately modest so an accidental run cannot saturate a host.
[[nodiscard]] CoordinatorConfig default_coordinator_config();

/// Canonical text form of the effective configuration, for logging and for
/// proving that a restart used the same or a newer generation.
[[nodiscard]] std::string describe_config(const CoordinatorConfig& config);

}  // namespace ctf::config
