// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/config.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace ctf::config {
namespace {

[[nodiscard]] std::string trim(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  const auto is_space = [](char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  while (begin < end && is_space(text[begin])) {
    ++begin;
  }
  while (end > begin && is_space(text[end - 1])) {
    --end;
  }
  return std::string(text.substr(begin, end - begin));
}

[[nodiscard]] Result<std::uint64_t> parse_u64(const std::string& value, const std::string& key,
                                              std::size_t line) {
  const std::optional<StrongScalar<struct ConfigNumberTag, std::uint64_t>> parsed =
      StrongScalar<struct ConfigNumberTag, std::uint64_t>::parse(value);
  if (!parsed.has_value()) {
    return Status::error(ErrorCode::InvalidSyntax,
                         "line " + std::to_string(line) + ": " + key +
                             " must be a canonical unsigned decimal number");
  }
  return parsed->value();
}

[[nodiscard]] Result<std::uint32_t> parse_u32(const std::string& value, const std::string& key,
                                              std::size_t line) {
  const std::optional<ShardIndex> parsed = ShardIndex::parse(value);
  if (!parsed.has_value()) {
    return Status::error(ErrorCode::InvalidSyntax,
                         "line " + std::to_string(line) + ": " + key +
                             " must be an unsigned 32-bit decimal number");
  }
  return parsed->value();
}

[[nodiscard]] Result<bool> parse_bool(const std::string& value, const std::string& key,
                                      std::size_t line) {
  if (value == "true") {
    return true;
  }
  if (value == "false") {
    return false;
  }
  return Status::error(ErrorCode::InvalidSyntax,
                       "line " + std::to_string(line) + ": " + key + " must be true or false");
}

struct EnvelopeDraft {
  bool seen = false;
  IsolationEnvelopeConfig value;
};

}  // namespace

CoordinatorConfig default_coordinator_config() {
  CoordinatorConfig config;
  config.label = "ctf-coordinator";
  config.bind_host = "127.0.0.1";
  config.port = 0;
  config.worker_threads = 4;
  config.max_pending_connections = 64;
  config.persist = false;

  config.policy.generation = PolicyGeneration(1);
  config.policy.envelopes = {
      IsolationEnvelopeConfig{IsolationClass::TrainingCritical, 32ULL * 1024 * 1024, kNanosPerMillisecond * 50, 8},
      IsolationEnvelopeConfig{IsolationClass::ServingLatency, 16ULL * 1024 * 1024, kNanosPerMillisecond * 50, 8},
      IsolationEnvelopeConfig{IsolationClass::TrainingBulk, 8ULL * 1024 * 1024, kNanosPerMillisecond * 100, 4},
      IsolationEnvelopeConfig{IsolationClass::BestEffort, 2ULL * 1024 * 1024, kNanosPerMillisecond * 100, 2},
  };
  config.policy.max_wave_width = 8;
  config.policy.max_session_bytes = 1ULL << 32;
  config.policy.max_sessions = 256;
  config.policy.max_attempts_in_flight = 64;
  config.policy.retained_history = 128;
  config.policy.require_destination_verification = true;
  config.policy.defer_horizon_ns = kNanosPerMillisecond * 250;
  config.policy.default_deadline_ns = 120 * kNanosPerSecond;

  config.topology.generation = TopologyGeneration(1);
  config.topology.path_classes = {
      PathClass{PathClassId(1), DestinationClass::LocalAttachedStore, 64ULL * 1024 * 1024, true,
                "synthetic-local"},
      PathClass{PathClassId(2), DestinationClass::RemoteObjectStore, 32ULL * 1024 * 1024, true,
                "synthetic-remote"},
      PathClass{PathClassId(3), DestinationClass::PeerNodeMemory, 32ULL * 1024 * 1024, true,
                "synthetic-peer"},
      PathClass{PathClassId(4), DestinationClass::SyntheticLab, 64ULL * 1024 * 1024, true,
                "synthetic-lab"},
  };
  // A well-known default workload so a fresh coordinator is usable without a
  // configuration file; operators replace it with their own contracts.
  WorkloadContract contract;
  contract.workload = WorkloadId::parse("11111111-2222-4333-8444-555555555555").value();
  contract.generation = WorkloadContractGeneration(1);
  contract.isolation = IsolationClass::TrainingBulk;
  contract.ceiling_bps = 8ULL * 1024 * 1024;
  contract.floor_bps = 0;
  contract.max_in_flight_sessions = 4;
  contract.max_shards_per_wave = 4;
  contract.allow_supersession = true;
  contract.deadline_budget_ns = 120 * kNanosPerSecond;
  config.contracts = {contract};
  return config;
}

Result<FileConfig> parse_config(std::string_view text, std::string_view source_label) {
  CoordinatorConfig config = default_coordinator_config();
  config.policy.generation = PolicyGeneration(0);
  config.topology.generation = TopologyGeneration(0);
  std::vector<WorkloadContract> contracts;
  std::map<std::string, EnvelopeDraft> envelopes;
  std::map<std::string, PathClass> paths;
  std::map<std::string, WorkloadContract> contract_map;
  std::map<std::string, std::string> seen_keys;
  bool policy_generation_seen = false;
  bool topology_generation_seen = false;

  std::istringstream stream{std::string(text)};
  std::string line_text;
  std::size_t line_number = 0;
  while (std::getline(stream, line_text)) {
    ++line_number;
    const std::size_t comment = line_text.find('#');
    if (comment != std::string::npos) {
      line_text = line_text.substr(0, comment);
    }
    const std::string line = trim(line_text);
    if (line.empty()) {
      continue;
    }
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) {
      return Status::error(ErrorCode::InvalidSyntax,
                           "line " + std::to_string(line_number) + ": expected key = value");
    }
    const std::string key = trim(line.substr(0, equals));
    const std::string value = trim(line.substr(equals + 1));
    if (key.empty() || value.empty()) {
      return Status::error(ErrorCode::InvalidSyntax,
                           "line " + std::to_string(line_number) + ": key and value are required");
    }
    if (seen_keys.find(key) != seen_keys.end()) {
      return Status::error(ErrorCode::DuplicateIdentity,
                           "line " + std::to_string(line_number) + ": duplicate key " + key);
    }
    seen_keys.emplace(key, value);

    const auto fail_key = [&](const std::string& detail) {
      return Status::error(ErrorCode::InvalidArgument,
                           "line " + std::to_string(line_number) + ": " + detail);
    };

    if (key == "label") {
      config.label = value;
    } else if (key == "bind_host") {
      config.bind_host = value;
    } else if (key == "port") {
      Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      if (parsed.value() > 65535U) {
        return fail_key("port must be at most 65535");
      }
      config.port = static_cast<std::uint16_t>(parsed.value());
    } else if (key == "data_directory") {
      config.data_directory = std::filesystem::path(value);
    } else if (key == "worker_threads") {
      Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      config.worker_threads = parsed.value();
    } else if (key == "max_pending_connections") {
      Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      config.max_pending_connections = parsed.value();
    } else if (key == "persist") {
      Result<bool> parsed = parse_bool(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      config.persist = parsed.value();
    } else if (key == "identity_seed") {
      Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      config.identity_seed = parsed.value();
    } else if (key.rfind("policy.envelope.", 0) == 0) {
      const std::string rest = key.substr(std::string("policy.envelope.").size());
      const std::size_t dot = rest.find('.');
      if (dot == std::string::npos) {
        return fail_key("policy envelope keys are policy.envelope.<class>.<field>");
      }
      const std::string class_name = rest.substr(0, dot);
      const std::string field = rest.substr(dot + 1);
      const std::optional<IsolationClass> isolation = isolation_class_from_string(class_name);
      if (!isolation.has_value()) {
        return fail_key("unknown isolation class " + class_name);
      }
      EnvelopeDraft& draft = envelopes[class_name];
      if (!draft.seen) {
        draft.seen = true;
        draft.value.isolation = isolation.value();
      }
      if (field == "ceiling_bps") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        draft.value.ceiling_bps = parsed.value();
      } else if (field == "burst_window_ns") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        draft.value.burst_window_ns = static_cast<Nanos>(parsed.value());
      } else if (field == "max_in_flight_sessions") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        draft.value.max_in_flight_sessions = parsed.value();
      } else {
        return fail_key("unknown policy envelope field " + field);
      }
    } else if (key.rfind("policy.", 0) == 0) {
      const std::string field = key.substr(std::string("policy.").size());
      if (field == "generation") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.generation = PolicyGeneration(parsed.value());
        policy_generation_seen = true;
      } else if (field == "max_wave_width") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.max_wave_width = parsed.value();
      } else if (field == "max_session_bytes") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.max_session_bytes = parsed.value();
      } else if (field == "max_sessions") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.max_sessions = parsed.value();
      } else if (field == "max_attempts_in_flight") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.max_attempts_in_flight = parsed.value();
      } else if (field == "retained_history") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.retained_history = parsed.value();
      } else if (field == "require_destination_verification") {
        Result<bool> parsed = parse_bool(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.require_destination_verification = parsed.value();
      } else if (field == "defer_horizon_ns") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.defer_horizon_ns = static_cast<Nanos>(parsed.value());
      } else if (field == "default_deadline_ns") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        config.policy.default_deadline_ns = static_cast<Nanos>(parsed.value());
      } else {
        return fail_key("unknown policy key " + key);
      }
    } else if (key.rfind("topology.path.", 0) == 0) {
      const std::string rest = key.substr(std::string("topology.path.").size());
      const std::size_t dot = rest.find('.');
      if (dot == std::string::npos) {
        return fail_key("topology path keys are topology.path.<id>.<field>");
      }
      const std::string id_text = rest.substr(0, dot);
      const std::string field = rest.substr(dot + 1);
      const std::optional<PathClassId> id = PathClassId::parse(id_text);
      if (!id.has_value() || id->value() == 0) {
        return fail_key("path class id must be a non-zero decimal number");
      }
      PathClass& path = paths[id_text];
      path.id = id.value();
      if (field == "destination") {
        const std::optional<DestinationClass> destination = destination_class_from_string(value);
        if (!destination.has_value()) {
          return fail_key("unknown destination class " + value);
        }
        path.destination = destination.value();
      } else if (field == "capacity_bps") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        path.capacity_bps = parsed.value();
      } else if (field == "synthetic") {
        Result<bool> parsed = parse_bool(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        path.synthetic = parsed.value();
      } else if (field == "label") {
        path.label = value;
      } else {
        return fail_key("unknown topology path field " + field);
      }
    } else if (key == "topology.generation") {
      Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      config.topology.generation = TopologyGeneration(parsed.value());
      topology_generation_seen = true;
    } else if (key.rfind("contract.", 0) == 0) {
      const std::string rest = key.substr(std::string("contract.").size());
      const std::size_t dot = rest.find('.');
      if (dot == std::string::npos) {
        return fail_key("contract keys are contract.<workload-uuid>.<field>");
      }
      const std::string id_text = rest.substr(0, dot);
      const std::string field = rest.substr(dot + 1);
      const std::optional<WorkloadId> workload = WorkloadId::parse(id_text);
      if (!workload.has_value()) {
        return fail_key("contract key must name a canonical workload identity");
      }
      WorkloadContract& contract = contract_map[id_text];
      contract.workload = workload.value();
      if (field == "generation") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.generation = WorkloadContractGeneration(parsed.value());
      } else if (field == "isolation") {
        const std::optional<IsolationClass> isolation = isolation_class_from_string(value);
        if (!isolation.has_value()) {
          return fail_key("unknown isolation class " + value);
        }
        contract.isolation = isolation.value();
      } else if (field == "ceiling_bps") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.ceiling_bps = parsed.value();
      } else if (field == "floor_bps") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.floor_bps = parsed.value();
      } else if (field == "max_in_flight_sessions") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.max_in_flight_sessions = parsed.value();
      } else if (field == "max_shards_per_wave") {
        Result<std::uint32_t> parsed = parse_u32(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.max_shards_per_wave = parsed.value();
      } else if (field == "allow_supersession") {
        Result<bool> parsed = parse_bool(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.allow_supersession = parsed.value();
      } else if (field == "deadline_budget_ns") {
        Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
        if (!parsed.ok()) {
          return parsed.status();
        }
        contract.deadline_budget_ns = static_cast<Nanos>(parsed.value());
      } else {
        return fail_key("unknown contract field " + field);
      }
    } else if (key.rfind("limits.", 0) == 0) {
      const std::string field = key.substr(std::string("limits.").size());
      Result<std::uint64_t> parsed = parse_u64(value, key, line_number);
      if (!parsed.ok()) {
        return parsed.status();
      }
      const std::uint64_t raw = parsed.value();
      if (field == "max_shards_per_checkpoint") {
        config.limits.max_shards_per_checkpoint = static_cast<std::uint32_t>(raw);
      } else if (field == "max_checkpoint_bytes") {
        config.limits.max_checkpoint_bytes = raw;
      } else if (field == "max_sessions") {
        config.limits.max_sessions = static_cast<std::uint32_t>(raw);
      } else if (field == "max_attempts_in_flight") {
        config.limits.max_attempts_in_flight = static_cast<std::uint32_t>(raw);
      } else if (field == "max_retained_history") {
        config.limits.max_retained_history = static_cast<std::uint32_t>(raw);
      } else if (field == "max_wave_width") {
        config.limits.max_wave_width = static_cast<std::uint32_t>(raw);
      } else if (field == "max_path_classes") {
        config.limits.max_path_classes = static_cast<std::uint32_t>(raw);
      } else if (field == "max_sessions_per_workload") {
        config.limits.max_sessions_per_workload = static_cast<std::uint32_t>(raw);
      } else if (field == "max_workloads") {
        config.limits.max_workloads = static_cast<std::uint32_t>(raw);
      } else if (field == "max_string_bytes") {
        config.limits.max_string_bytes = static_cast<std::size_t>(raw);
      } else if (field == "max_supersession_chain") {
        config.limits.max_supersession_chain = static_cast<std::uint32_t>(raw);
      } else {
        return fail_key("unknown limits field " + field);
      }
    } else {
      return Status::error(ErrorCode::InvalidArgument,
                           "line " + std::to_string(line_number) + ": unknown key " + key);
    }
  }

  if (!policy_generation_seen) {
    return Status::error(ErrorCode::MissingField, "policy.generation is required");
  }
  if (!topology_generation_seen) {
    return Status::error(ErrorCode::MissingField, "topology.generation is required");
  }
  config.policy.envelopes.clear();
  for (const auto& entry : envelopes) {
    config.policy.envelopes.push_back(entry.second.value);
  }
  if (config.policy.envelopes.empty()) {
    return Status::error(ErrorCode::MissingField, "at least one policy envelope is required");
  }
  config.topology.path_classes.clear();
  for (const auto& entry : paths) {
    config.topology.path_classes.push_back(entry.second);
  }
  if (config.topology.path_classes.empty()) {
    return Status::error(ErrorCode::MissingField, "at least one topology path class is required");
  }
  for (const auto& entry : contract_map) {
    contracts.push_back(entry.second);
  }
  if (contracts.empty()) {
    return Status::error(ErrorCode::MissingField, "at least one workload contract is required");
  }
  config.contracts = std::move(contracts);
  if (config.persist && config.data_directory.empty()) {
    return Status::error(ErrorCode::InvalidArgument,
                         "persist = true requires data_directory to be set");
  }
  FileConfig out;
  out.coordinator = std::move(config);
  out.source = std::string(source_label);
  return out;
}

Result<FileConfig> load_config_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return Status::error(ErrorCode::NotFound, "cannot open configuration file " + path.string());
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return parse_config(buffer.str(), path.string());
}

std::string describe_config(const CoordinatorConfig& config) {
  std::ostringstream out;
  out << "label=" << config.label << "\n";
  out << "bind_host=" << config.bind_host << "\n";
  out << "port=" << config.port << "\n";
  out << "data_directory=" << config.data_directory.string() << "\n";
  out << "persist=" << (config.persist ? "true" : "false") << "\n";
  out << "worker_threads=" << config.worker_threads << "\n";
  out << "policy.generation=" << config.policy.generation.value() << "\n";
  out << "policy.max_wave_width=" << config.policy.max_wave_width << "\n";
  out << "policy.max_sessions=" << config.policy.max_sessions << "\n";
  out << "policy.require_destination_verification="
      << (config.policy.require_destination_verification ? "true" : "false") << "\n";
  for (const IsolationEnvelopeConfig& envelope : config.policy.envelopes) {
    out << "policy.envelope." << to_string(envelope.isolation)
        << ".ceiling_bps=" << envelope.ceiling_bps << "\n";
  }
  out << "topology.generation=" << config.topology.generation.value() << "\n";
  for (const PathClass& path : config.topology.path_classes) {
    out << "topology.path." << path.id.value() << ".destination=" << to_string(path.destination)
        << "\n";
    out << "topology.path." << path.id.value() << ".capacity_bps=" << path.capacity_bps << "\n";
    out << "topology.path." << path.id.value() << ".synthetic="
        << (path.synthetic ? "true" : "false") << "\n";
  }
  for (const WorkloadContract& contract : config.contracts) {
    out << "contract." << contract.workload.to_string() << ".generation="
        << contract.generation.value() << "\n";
    out << "contract." << contract.workload.to_string() << ".isolation="
        << to_string(contract.isolation) << "\n";
    out << "contract." << contract.workload.to_string()
        << ".ceiling_bps=" << contract.ceiling_bps << "\n";
  }
  return out.str();
}

}  // namespace ctf::config
