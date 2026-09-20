#pragma once

// Versioned, integrity-checked persistence.
//
// The store writes a full snapshot with atomic replacement, and appends
// integrity-checked journal records between snapshots. Both carry a format
// version and a CRC, so malformed, corrupt, truncated, oversized, incompatible,
// and impossible state is refused without partial application: a snapshot is
// fully decoded and validated before any of it is applied.
//
// Durability semantics: the temporary file is flushed to the device before it
// replaces the previous snapshot, so a returned success means the bytes are on
// disk. A torn tail in the journal is reported as such and discarded - it is
// never partially applied and never silently treated as a valid record.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "ctf/bytes.hpp"
#include "ctf/engine.hpp"
#include "ctf/status.hpp"

namespace ctf::store {

/// What recovery observed while loading. Reported, never hidden.
struct LoadReport {
  bool snapshot_present = false;
  bool journal_present = false;
  bool torn_tail = false;
  bool corrupt_prefix = false;
  bool version_mismatch = false;
  std::uint64_t snapshot_sequence = 0;
  std::uint64_t journal_records_applied = 0;
  std::uint64_t discarded_bytes = 0;
  std::vector<std::string> notes;
};

struct StoreConfig {
  std::filesystem::path directory;
  Limits limits;
  /// Persistent growth bounds: crossing either triggers compaction.
  std::uint64_t max_journal_bytes = 4U << 20;
  std::uint32_t max_journal_records = 2048;
};

class PersistentStore {
 public:
  explicit PersistentStore(StoreConfig config);

  /// Creates the directory if needed and validates the layout.
  [[nodiscard]] Status open();

  [[nodiscard]] bool has_state() const;
  [[nodiscard]] Result<EngineSnapshot> load(LoadReport* report) const;

  /// Writes a full snapshot with atomic replacement, flushing to the device
  /// first, then rotates the journal.
  [[nodiscard]] Status persist(const EngineSnapshot& snapshot);

  /// Appends one journal record and flushes it. Compacts automatically once the
  /// configured growth bounds are crossed.
  [[nodiscard]] Status append(const std::string& label, const EngineSnapshot& snapshot);

  [[nodiscard]] const std::filesystem::path& directory() const noexcept { return config_.directory; }
  [[nodiscard]] std::filesystem::path snapshot_path() const;
  [[nodiscard]] std::filesystem::path journal_path() const;
  [[nodiscard]] std::uint64_t sequence() const noexcept { return sequence_; }
  [[nodiscard]] std::uint32_t journal_records() const noexcept { return journal_records_; }
  [[nodiscard]] std::uint64_t journal_bytes() const noexcept { return journal_bytes_; }

 private:
  StoreConfig config_;
  std::uint64_t sequence_ = 0;
  std::uint32_t journal_records_ = 0;
  std::uint64_t journal_bytes_ = 0;
};

// --- Codecs (also used directly by persistence and protocol tests) ----------

[[nodiscard]] Bytes encode_snapshot(const EngineSnapshot& snapshot, const Limits& limits);
[[nodiscard]] Result<EngineSnapshot> decode_snapshot(ByteSpan data, const Limits& limits);

struct JournalRecord {
  std::uint64_t sequence = 0;
  std::string label;
  Bytes payload;
};

[[nodiscard]] Bytes encode_journal_record(const JournalRecord& record);
/// Decodes one record from the front of the buffer. Returns the record and sets
/// consumed_bytes to the full record size. Truncated or corrupt input is a
/// deterministic error, never a partial record.
[[nodiscard]] Result<JournalRecord> decode_journal_record(ByteSpan data, std::size_t* consumed_bytes);

/// Replaces target with source atomically, flushing source to the device first.
[[nodiscard]] Status atomic_replace(const std::filesystem::path& source,
                                    const std::filesystem::path& target);

[[nodiscard]] Status write_file_flushed(const std::filesystem::path& path, ByteSpan data,
                                        bool append);

}  // namespace ctf::store
