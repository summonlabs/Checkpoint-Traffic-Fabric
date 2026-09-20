#pragma once

// Deterministic human and machine rendering of fabric state.
//
// Rendering never upgrades evidence: a transferred checkpoint renders as
// transferred, with durability explicitly reported as not established.

#include <string>
#include <string_view>
#include <vector>

#include "ctf/model.hpp"
#include "ctf/protocol.hpp"
#include "ctf/service.hpp"

namespace ctf::report {

[[nodiscard]] std::string json_escape(std::string_view text);
[[nodiscard]] std::string human_bytes(std::uint64_t bytes);

[[nodiscard]] std::string to_text(const AdmissionDecision& decision);
[[nodiscard]] std::string to_json(const AdmissionDecision& decision);
[[nodiscard]] std::string to_text(const WaveOutcome& outcome);
[[nodiscard]] std::string to_json(const WaveOutcome& outcome);
[[nodiscard]] std::string to_text(const SessionView& view);
[[nodiscard]] std::string to_json(const SessionView& view);
[[nodiscard]] std::string to_text(const SessionSummary& summary);
[[nodiscard]] std::string to_json(const SessionSummary& summary);
[[nodiscard]] std::string to_text(const AccountingSnapshot& accounting);
[[nodiscard]] std::string to_json(const AccountingSnapshot& accounting);
[[nodiscard]] std::string to_text(const Explanation& explanation);
[[nodiscard]] std::string to_json(const Explanation& explanation);
[[nodiscard]] std::string to_text(const ServiceStats& stats);
[[nodiscard]] std::string to_json(const ServiceStats& stats);
[[nodiscard]] std::string to_text(const wire::HelloResponse& hello);
[[nodiscard]] std::string to_json(const wire::HelloResponse& hello);

}  // namespace ctf::report
