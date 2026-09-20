#pragma once

// Checkpoint Traffic Fabric - version facts.
//
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <string_view>

#define CTF_VERSION_MAJOR 1
#define CTF_VERSION_MINOR 0
#define CTF_VERSION_PATCH 0
#define CTF_VERSION_STRING "1.0.0"

namespace ctf {

inline constexpr std::uint32_t kVersionMajor = CTF_VERSION_MAJOR;
inline constexpr std::uint32_t kVersionMinor = CTF_VERSION_MINOR;
inline constexpr std::uint32_t kVersionPatch = CTF_VERSION_PATCH;

/// Semantic version of the runtime, e.g. "1.0.0".
[[nodiscard]] std::string_view version_string() noexcept;

/// Protocol revision implemented by this build. Independent of the library
/// version so that the wire format can be frozen while the library evolves.
inline constexpr std::uint16_t kProtocolVersion = 1;

/// Persistence format revision. Loading a file with a different revision is a
/// hard failure (VersionIncompatible), never a partial application.
inline constexpr std::uint16_t kPersistenceFormatVersion = 1;

}  // namespace ctf
