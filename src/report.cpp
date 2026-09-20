// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/report.hpp"

#include <cstdio>
#include <sstream>

namespace ctf::report {
namespace {

[[nodiscard]] std::string hex_byte(std::uint8_t value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.push_back(kDigits[value >> 4]);
  out.push_back(kDigits[value & 0x0FU]);
  return out;
}

[[nodiscard]] std::string quoted(std::string_view text) {
  return "\"" + json_escape(text) + "\"";
}

}  // namespace

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  for (const char c : text) {
    const auto value = static_cast<unsigned char>(c);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (value < 0x20U) {
          out += "\\u00";
          out += hex_byte(value);
        } else {
          out.push_back(c);
        }
        break;
    }
  }
  return out;
}

std::string human_bytes(std::uint64_t bytes) {
  static constexpr const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  std::uint64_t scaled = bytes;
  std::size_t unit = 0;
  std::uint64_t remainder = 0;
  while (scaled >= 1024U && unit + 1 < 5) {
    remainder = scaled % 1024U;
    scaled /= 1024U;
    ++unit;
  }
  std::ostringstream out;
  out << scaled;
  if (unit > 0 && remainder != 0) {
    out << '.' << ((remainder * 10U) / 1024U);
  }
  out << kUnits[unit];
  return out.str();
}

std::string to_text(const AdmissionDecision& decision) {
  std::ostringstream out;
  out << "decision=" << to_string(decision.kind) << " reason=" << to_string(decision.reason);
  if (!decision.detail.empty()) {
    out << " detail=\"" << decision.detail << "\"";
  }
  if (!decision.session.is_nil()) {
    out << " session=" << decision.session.to_string();
  }
  if (decision.envelope.has_value()) {
    const TrafficEnvelope& envelope = decision.envelope.value();
    out << " class=" << to_string(envelope.isolation);
    out << " rate=" << human_bytes(envelope.rate_bps) << "/s";
    out << " burst=" << human_bytes(envelope.burst_bytes);
    out << " waves=" << envelope.waves.size();
    out << " wave_width=" << envelope.wave_width;
  }
  if (decision.retry_after.has_value()) {
    out << " retry_after_ns=" << decision.retry_after.value();
  }
  if (!decision.superseded.empty()) {
    out << " superseded=" << decision.superseded.size();
  }
  return out.str();
}

std::string to_json(const AdmissionDecision& decision) {
  std::ostringstream out;
  out << "{\"decision\":" << quoted(to_string(decision.kind))
      << ",\"reason\":" << quoted(to_string(decision.reason))
      << ",\"detail\":" << quoted(decision.detail)
      << ",\"session\":" << quoted(decision.session.to_string())
      << ",\"epoch\":" << quoted(decision.epoch.to_string())
      << ",\"decided_at_ns\":" << decision.decided_at;
  if (decision.envelope.has_value()) {
    const TrafficEnvelope& envelope = decision.envelope.value();
    out << ",\"envelope\":{\"isolation\":" << quoted(to_string(envelope.isolation))
        << ",\"rate_bps\":" << envelope.rate_bps << ",\"burst_bytes\":" << envelope.burst_bytes
        << ",\"wave_width\":" << envelope.wave_width << ",\"waves\":" << envelope.waves.size()
        << ",\"deadline_target_ns\":" << envelope.deadline_target << "}";
  }
  if (decision.retry_after.has_value()) {
    out << ",\"retry_after_ns\":" << decision.retry_after.value();
  }
  out << ",\"superseded\":[";
  for (std::size_t i = 0; i < decision.superseded.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    out << quoted(decision.superseded[i].to_string());
  }
  out << "]}";
  return out.str();
}

std::string to_text(const WaveOutcome& outcome) {
  std::ostringstream out;
  out << "granted=" << (outcome.granted ? "true" : "false")
      << " reason=" << to_string(outcome.reason);
  if (outcome.grant.has_value()) {
    const WaveGrant& grant = outcome.grant.value();
    out << " shard=" << grant.shard.to_string() << " bytes=" << grant.max_bytes
        << " attempt=" << grant.attempt.to_string() << " sequence=" << grant.sequence.to_string();
  }
  if (outcome.retry_after.has_value()) {
    out << " retry_after_ns=" << outcome.retry_after.value();
  }
  if (!outcome.detail.empty()) {
    out << " detail=\"" << outcome.detail << "\"";
  }
  return out.str();
}

std::string to_json(const WaveOutcome& outcome) {
  std::ostringstream out;
  out << "{\"granted\":" << (outcome.granted ? "true" : "false")
      << ",\"reason\":" << quoted(to_string(outcome.reason))
      << ",\"detail\":" << quoted(outcome.detail);
  if (outcome.grant.has_value()) {
    const WaveGrant& grant = outcome.grant.value();
    out << ",\"grant\":{\"shard\":" << grant.shard.value() << ",\"bytes\":" << grant.max_bytes
        << ",\"attempt\":" << quoted(grant.attempt.to_string())
        << ",\"sequence\":" << grant.sequence.value() << ",\"rate_bps\":" << grant.rate_bps
        << ",\"expires_at_ns\":" << grant.expires_at << "}";
  }
  if (outcome.retry_after.has_value()) {
    out << ",\"retry_after_ns\":" << outcome.retry_after.value();
  }
  out << "}";
  return out.str();
}

std::string to_text(const SessionView& view) {
  std::ostringstream out;
  out << "session=" << view.session.to_string() << "\n";
  out << "checkpoint=" << view.checkpoint.to_string()
      << " generation=" << view.checkpoint_generation.to_string() << "\n";
  out << "workload=" << view.workload.to_string() << "\n";
  out << "state=" << to_string(view.state) << " evidence=" << to_string(view.evidence) << "\n";
  out << "isolation=" << to_string(view.isolation) << " destination=" << to_string(view.destination)
      << "\n";
  out << "declared=" << human_bytes(view.declared_bytes)
      << " transferred=" << human_bytes(view.transferred_bytes)
      << " verified=" << human_bytes(view.verified_bytes) << "\n";
  out << "shards=" << view.shards_total << " transferred=" << view.shards_transferred
      << " verified=" << view.shards_verified << " ambiguous=" << view.shards_ambiguous << "\n";
  out << "durability=" << to_string(view.durability)
      << " (network evidence is not storage durability)\n";
  if (view.last_reason.has_value()) {
    out << "last_reason=" << to_string(view.last_reason.value());
    if (!view.last_detail.empty()) {
      out << " detail=\"" << view.last_detail << "\"";
    }
    out << "\n";
  }
  if (!view.stale_reason.empty()) {
    out << "stale_reason=\"" << view.stale_reason << "\"\n";
  }
  if (view.superseded_by.has_value()) {
    out << "superseded_by=" << view.superseded_by.value().to_string() << "\n";
  }
  if (view.deadline_target.has_value()) {
    out << "deadline_target_ns=" << view.deadline_target.value() << "\n";
  }
  for (const ShardProgress& shard : view.shards) {
    out << "  shard " << shard.index.to_string() << " state=" << to_string(shard.state)
        << " declared=" << shard.declared_bytes << " transferred=" << shard.transferred_bytes
        << " verified=" << shard.verified_bytes;
    if (shard.attempt.has_value()) {
      out << " attempt=" << shard.attempt.value().to_string();
    }
    out << "\n";
  }
  return out.str();
}

std::string to_json(const SessionView& view) {
  std::ostringstream out;
  out << "{\"session\":" << quoted(view.session.to_string())
      << ",\"checkpoint\":" << quoted(view.checkpoint.to_string())
      << ",\"checkpoint_generation\":" << view.checkpoint_generation.value()
      << ",\"workload\":" << quoted(view.workload.to_string())
      << ",\"contract_generation\":" << view.contract_generation.value()
      << ",\"state\":" << quoted(to_string(view.state))
      << ",\"evidence\":" << quoted(to_string(view.evidence))
      << ",\"isolation\":" << quoted(to_string(view.isolation))
      << ",\"destination\":" << quoted(to_string(view.destination))
      << ",\"declared_bytes\":" << view.declared_bytes
      << ",\"transferred_bytes\":" << view.transferred_bytes
      << ",\"verified_bytes\":" << view.verified_bytes
      << ",\"shards_total\":" << view.shards_total
      << ",\"shards_transferred\":" << view.shards_transferred
      << ",\"shards_verified\":" << view.shards_verified
      << ",\"shards_ambiguous\":" << view.shards_ambiguous
      << ",\"durability\":" << quoted(to_string(view.durability))
      << ",\"durable_checkpoint_success\":" << (view.durable_checkpoint_success() ? "true" : "false")
      << ",\"stale_reason\":" << quoted(view.stale_reason)
      << ",\"created_at_ns\":" << view.created_at << ",\"updated_at_ns\":" << view.updated_at;
  if (view.last_reason.has_value()) {
    out << ",\"last_reason\":" << quoted(to_string(view.last_reason.value()))
        << ",\"last_detail\":" << quoted(view.last_detail);
  }
  if (view.deadline_target.has_value()) {
    out << ",\"deadline_target_ns\":" << view.deadline_target.value();
  }
  out << ",\"shards\":[";
  for (std::size_t i = 0; i < view.shards.size(); ++i) {
    const ShardProgress& shard = view.shards[i];
    if (i != 0) {
      out << ',';
    }
    out << "{\"index\":" << shard.index.value() << ",\"state\":" << quoted(to_string(shard.state))
        << ",\"declared_bytes\":" << shard.declared_bytes
        << ",\"transferred_bytes\":" << shard.transferred_bytes
        << ",\"verified_bytes\":" << shard.verified_bytes << "}";
  }
  out << "]}";
  return out.str();
}

std::string to_text(const SessionSummary& summary) {
  std::ostringstream out;
  out << summary.session.to_string() << " checkpoint=" << summary.checkpoint.to_string()
      << " generation=" << summary.checkpoint_generation.to_string()
      << " state=" << to_string(summary.state) << " evidence=" << to_string(summary.evidence)
      << " transferred=" << summary.transferred_bytes << "/" << summary.declared_bytes
      << " verified=" << summary.verified_bytes;
  return out.str();
}

std::string to_json(const SessionSummary& summary) {
  std::ostringstream out;
  out << "{\"session\":" << quoted(summary.session.to_string())
      << ",\"checkpoint\":" << quoted(summary.checkpoint.to_string())
      << ",\"checkpoint_generation\":" << summary.checkpoint_generation.value()
      << ",\"workload\":" << quoted(summary.workload.to_string())
      << ",\"state\":" << quoted(to_string(summary.state))
      << ",\"evidence\":" << quoted(to_string(summary.evidence))
      << ",\"declared_bytes\":" << summary.declared_bytes
      << ",\"transferred_bytes\":" << summary.transferred_bytes
      << ",\"verified_bytes\":" << summary.verified_bytes
      << ",\"updated_at_ns\":" << summary.updated_at << "}";
  return out.str();
}

std::string to_text(const AccountingSnapshot& accounting) {
  std::ostringstream out;
  out << "bytes admitted=" << accounting.bytes_admitted
      << " transferred=" << accounting.bytes_transferred
      << " verified=" << accounting.bytes_verified
      << " cancelled=" << accounting.bytes_cancelled
      << " wasted=" << accounting.bytes_wasted
      << " unproven=" << accounting.bytes_unproven
      << " deferred=" << accounting.bytes_deferred
      << " outstanding=" << accounting.granted_outstanding_bytes << "\n";
  out << "sessions admitted=" << accounting.sessions_admitted
      << " deferred=" << accounting.sessions_deferred << " denied=" << accounting.sessions_denied
      << " completed=" << accounting.sessions_completed
      << " cancelled=" << accounting.sessions_cancelled
      << " superseded=" << accounting.sessions_superseded
      << " failed=" << accounting.sessions_failed << "\n";
  out << "active_sessions=" << accounting.active_sessions
      << " active_attempts=" << accounting.active_attempts
      << " commands_processed=" << accounting.commands_processed << "\n";
  out << "at_baseline=" << (accounting.at_baseline() ? "true" : "false")
      << " conserves=" << (accounting.conserves() ? "true" : "false");
  return out.str();
}

std::string to_json(const AccountingSnapshot& accounting) {
  std::ostringstream out;
  out << "{\"bytes_admitted\":" << accounting.bytes_admitted
      << ",\"bytes_transferred\":" << accounting.bytes_transferred
      << ",\"bytes_verified\":" << accounting.bytes_verified
      << ",\"bytes_cancelled\":" << accounting.bytes_cancelled
      << ",\"bytes_wasted\":" << accounting.bytes_wasted
      << ",\"bytes_unproven\":" << accounting.bytes_unproven
      << ",\"bytes_deferred\":" << accounting.bytes_deferred
      << ",\"granted_outstanding_bytes\":" << accounting.granted_outstanding_bytes
      << ",\"sessions_admitted\":" << accounting.sessions_admitted
      << ",\"sessions_deferred\":" << accounting.sessions_deferred
      << ",\"sessions_denied\":" << accounting.sessions_denied
      << ",\"sessions_completed\":" << accounting.sessions_completed
      << ",\"sessions_cancelled\":" << accounting.sessions_cancelled
      << ",\"sessions_superseded\":" << accounting.sessions_superseded
      << ",\"sessions_failed\":" << accounting.sessions_failed
      << ",\"active_sessions\":" << accounting.active_sessions
      << ",\"active_attempts\":" << accounting.active_attempts
      << ",\"commands_processed\":" << accounting.commands_processed
      << ",\"at_baseline\":" << (accounting.at_baseline() ? "true" : "false")
      << ",\"conserves\":" << (accounting.conserves() ? "true" : "false") << "}";
  return out.str();
}

std::string to_text(const Explanation& explanation) {
  std::ostringstream out;
  out << "session=" << explanation.session.to_string() << "\n";
  out << explanation.summary << "\n";
  for (const std::string& line : explanation.timeline) {
    out << "  " << line << "\n";
  }
  return out.str();
}

std::string to_json(const Explanation& explanation) {
  std::ostringstream out;
  out << "{\"session\":" << quoted(explanation.session.to_string())
      << ",\"summary\":" << quoted(explanation.summary) << ",\"timeline\":[";
  for (std::size_t i = 0; i < explanation.timeline.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    out << quoted(explanation.timeline[i]);
  }
  out << "]}";
  return out.str();
}

std::string to_text(const ServiceStats& stats) {
  std::ostringstream out;
  out << "connections_accepted=" << stats.connections_accepted
      << " connections_rejected=" << stats.connections_rejected
      << " messages_processed=" << stats.messages_processed
      << " protocol_errors=" << stats.protocol_errors
      << " durable_writes=" << stats.durable_writes
      << " durable_write_failures=" << stats.durable_write_failures;
  return out.str();
}

std::string to_json(const ServiceStats& stats) {
  std::ostringstream out;
  out << "{\"connections_accepted\":" << stats.connections_accepted
      << ",\"connections_rejected\":" << stats.connections_rejected
      << ",\"messages_processed\":" << stats.messages_processed
      << ",\"protocol_errors\":" << stats.protocol_errors
      << ",\"durable_writes\":" << stats.durable_writes
      << ",\"durable_write_failures\":" << stats.durable_write_failures << "}";
  return out.str();
}

std::string to_text(const wire::HelloResponse& hello) {
  std::ostringstream out;
  out << "server=" << hello.server_label << " epoch=" << hello.epoch.to_string()
      << " policy_generation=" << hello.policy_generation.value()
      << " topology_generation=" << hello.topology_generation.value()
      << " contracts=" << hello.contracts.size();
  return out.str();
}

std::string to_json(const wire::HelloResponse& hello) {
  std::ostringstream out;
  out << "{\"server\":" << quoted(hello.server_label)
      << ",\"epoch\":" << quoted(hello.epoch.to_string())
      << ",\"incarnation\":" << hello.epoch.incarnation.value()
      << ",\"term\":" << hello.epoch.term.value()
      << ",\"policy_generation\":" << hello.policy_generation.value()
      << ",\"topology_generation\":" << hello.topology_generation.value() << ",\"contracts\":[";
  for (std::size_t i = 0; i < hello.contracts.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    out << "{\"workload\":" << quoted(hello.contracts[i].workload.to_string())
        << ",\"generation\":" << hello.contracts[i].generation.value() << "}";
  }
  out << "]}";
  return out.str();
}

}  // namespace ctf::report
