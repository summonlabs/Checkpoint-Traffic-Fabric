// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ctf/store.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <system_error>

#include "ctf/version.hpp"
#include "ctf/wire.hpp"

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace ctf::store {
namespace {

constexpr std::uint32_t kJournalMagic = 0x4A465443U;  // 'CTFJ' little-endian
constexpr std::size_t kJournalHeaderBytes = 28;
constexpr std::uint16_t kMaxLabelBytes = 64;

[[nodiscard]] std::string path_text(const std::filesystem::path& path) {
  return path.string();
}

/// Reads a file with a hard size bound so an oversized or hostile file can
/// never be pulled into memory unchecked.
[[nodiscard]] Result<Bytes> read_file_bytes(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return Status::error(ErrorCode::IoFailure, "cannot size " + path_text(path));
  }
  const std::uintmax_t max_bytes =
      static_cast<std::uintmax_t>(ctf::wire::kMaxPayloadBytes) + 4096U;
  if (size > max_bytes) {
    return Status::error(ErrorCode::PayloadTooLarge,
                         "persisted file exceeds the maximum supported size");
  }
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return Status::error(ErrorCode::IoFailure, "cannot read " + path_text(path));
  }
  Bytes out;
  out.reserve(static_cast<std::size_t>(size));
  char buffer[64 * 1024];
  while (input) {
    input.read(buffer, static_cast<std::streamsize>(sizeof(buffer)));
    const std::streamsize got = input.gcount();
    for (std::streamsize i = 0; i < got; ++i) {
      out.push_back(static_cast<std::byte>(static_cast<unsigned char>(buffer[i])));
    }
  }
  return out;
}

[[nodiscard]] Status flush_file(std::FILE* file, const std::filesystem::path& path) {
  if (std::fflush(file) != 0) {
    return Status::error(ErrorCode::IoFailure, "failed to flush " + path_text(path));
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    return Status::error(ErrorCode::IoFailure, "failed to flush device buffers for " + path_text(path));
  }
#else
  if (::fsync(::fileno(file)) != 0) {
    return Status::error(ErrorCode::IoFailure, "failed to flush device buffers for " + path_text(path));
  }
#endif
  return Status::success();
}

}  // namespace

// ---------------------------------------------------------------------------
// Snapshot and record codecs
// ---------------------------------------------------------------------------

namespace {

void encode(ctf::wire::Encoder& encoder, const PersistedShard& value) {
  ctf::wire::encode(encoder, value.index);
  ctf::wire::encode(encoder, value.state);
  ctf::wire::encode(encoder, value.sequence);
  encoder.u64(value.granted_bytes);
  encoder.u64(value.transferred_bytes);
  encoder.u64(value.verified_bytes);
  ctf::wire::encode(encoder, value.observed_digest);
  encoder.boolean(value.has_observed_digest);
  encoder.boolean(value.attempt.has_value());
  if (value.attempt.has_value()) {
    ctf::wire::encode(encoder, value.attempt.value());
  }
  encoder.boolean(value.source_complete);
  encoder.u64(value.source_bytes);
}

void decode(ctf::wire::Decoder& decoder, PersistedShard& value) {
  ctf::wire::decode(decoder, value.index);
  ctf::wire::decode(decoder, value.state);
  ctf::wire::decode(decoder, value.sequence);
  value.granted_bytes = decoder.u64();
  value.transferred_bytes = decoder.u64();
  value.verified_bytes = decoder.u64();
  ctf::wire::decode(decoder, value.observed_digest);
  value.has_observed_digest = decoder.boolean();
  if (decoder.boolean()) {
    TransferAttemptId attempt;
    ctf::wire::decode(decoder, attempt);
    value.attempt = attempt;
  } else {
    value.attempt.reset();
  }
  if (!decoder.ok()) {
    return;
  }
  value.source_complete = decoder.boolean();
  value.source_bytes = decoder.u64();
}

void encode(ctf::wire::Encoder& encoder, const PersistedAttempt& value) {
  ctf::wire::encode(encoder, value.id);
  ctf::wire::encode(encoder, value.sequence);
  ctf::wire::encode(encoder, value.shard);
  ctf::wire::encode(encoder, value.wave);
  ctf::wire::encode(encoder, value.outcome);
  encoder.u64(value.granted_bytes);
  encoder.u64(value.delivered_bytes);
  ctf::wire::encode(encoder, value.observed_digest);
  encoder.boolean(value.has_observed_digest);
  encoder.boolean(value.outstanding);
  encoder.i64(value.granted_at);
  encoder.i64(value.updated_at);
}

void decode(ctf::wire::Decoder& decoder, PersistedAttempt& value) {
  ctf::wire::decode(decoder, value.id);
  ctf::wire::decode(decoder, value.sequence);
  ctf::wire::decode(decoder, value.shard);
  ctf::wire::decode(decoder, value.wave);
  ctf::wire::decode(decoder, value.outcome);
  value.granted_bytes = decoder.u64();
  value.delivered_bytes = decoder.u64();
  ctf::wire::decode(decoder, value.observed_digest);
  value.has_observed_digest = decoder.boolean();
  value.outstanding = decoder.boolean();
  value.granted_at = decoder.i64();
  value.updated_at = decoder.i64();
}

void encode(ctf::wire::Encoder& encoder, const PersistedSession& value) {
  ctf::wire::encode(encoder, value.session);
  ctf::wire::encode(encoder, value.request);
  ctf::wire::encode(encoder, value.state);
  ctf::wire::encode(encoder, value.evidence);
  ctf::wire::encode(encoder, value.envelope);
  encoder.u64(value.envelope_sequence);
  encoder.u64(value.attempt_counter);
  encoder.u32(static_cast<std::uint32_t>(value.shards.size()));
  for (const PersistedShard& shard : value.shards) {
    encode(encoder, shard);
  }
  encoder.u32(static_cast<std::uint32_t>(value.attempts.size()));
  for (const PersistedAttempt& attempt : value.attempts) {
    encode(encoder, attempt);
  }
  encoder.u32(static_cast<std::uint32_t>(value.timeline.size()));
  for (const std::string& line : value.timeline) {
    encoder.string(line);
  }
  encoder.u64(value.admitted_bytes);
  encoder.u64(value.transferred_bytes);
  encoder.u64(value.verified_bytes);
  encoder.u64(value.cancelled_bytes);
  encoder.u64(value.wasted_bytes);
  encoder.u64(value.unproven_bytes);
  encoder.u64(value.outstanding_bytes);
  encoder.u32(value.active_attempts);
  encoder.boolean(value.source_complete);
  encoder.boolean(value.paused);
  encoder.i64(value.created_at);
  encoder.i64(value.updated_at);
  ctf::wire::encode(encoder, value.last_reason);
  encoder.string(value.last_detail);
  encoder.string(value.stale_reason);
  encoder.boolean(value.superseded_by.has_value());
  if (value.superseded_by.has_value()) {
    ctf::wire::encode(encoder, value.superseded_by.value());
  }
}

void decode(ctf::wire::Decoder& decoder, PersistedSession& value) {
  ctf::wire::decode(decoder, value.session);
  ctf::wire::decode(decoder, value.request);
  ctf::wire::decode(decoder, value.state);
  ctf::wire::decode(decoder, value.evidence);
  ctf::wire::decode(decoder, value.envelope);
  value.envelope_sequence = decoder.u64();
  value.attempt_counter = decoder.u64();
  const std::uint32_t shard_count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (shard_count > decoder.limits().max_shards_per_checkpoint) {
    decoder.fail(ErrorCode::CollectionTooLarge, "persisted session lists too many shards");
    return;
  }
  value.shards.clear();
  value.shards.reserve(shard_count);
  for (std::uint32_t i = 0; i < shard_count; ++i) {
    PersistedShard shard;
    decode(decoder, shard);
    if (!decoder.ok()) {
      return;
    }
    value.shards.push_back(shard);
  }
  const std::uint32_t attempt_count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (attempt_count > decoder.limits().max_retained_history) {
    decoder.fail(ErrorCode::CollectionTooLarge, "persisted session lists too many attempts");
    return;
  }
  value.attempts.clear();
  value.attempts.reserve(attempt_count);
  for (std::uint32_t i = 0; i < attempt_count; ++i) {
    PersistedAttempt attempt;
    decode(decoder, attempt);
    if (!decoder.ok()) {
      return;
    }
    value.attempts.push_back(attempt);
  }
  const std::uint32_t timeline_count = decoder.collection_count();
  if (!decoder.ok()) {
    return;
  }
  if (timeline_count > decoder.limits().max_retained_history) {
    decoder.fail(ErrorCode::CollectionTooLarge, "persisted session lists too many timeline entries");
    return;
  }
  value.timeline.clear();
  value.timeline.reserve(timeline_count);
  for (std::uint32_t i = 0; i < timeline_count; ++i) {
    const std::string line = decoder.string();
    if (!decoder.ok()) {
      return;
    }
    value.timeline.push_back(line);
  }
  value.admitted_bytes = decoder.u64();
  value.transferred_bytes = decoder.u64();
  value.verified_bytes = decoder.u64();
  value.cancelled_bytes = decoder.u64();
  value.wasted_bytes = decoder.u64();
  value.unproven_bytes = decoder.u64();
  value.outstanding_bytes = decoder.u64();
  value.active_attempts = decoder.u32();
  value.source_complete = decoder.boolean();
  value.paused = decoder.boolean();
  value.created_at = decoder.i64();
  value.updated_at = decoder.i64();
  ctf::wire::decode(decoder, value.last_reason);
  value.last_detail = decoder.string();
  value.stale_reason = decoder.string();
  if (decoder.boolean()) {
    SessionId id;
    ctf::wire::decode(decoder, id);
    value.superseded_by = id;
  } else {
    value.superseded_by.reset();
  }
}

}  // namespace

Bytes encode_snapshot(const EngineSnapshot& snapshot, const Limits& limits) {
  (void)limits;
  ctf::wire::Encoder encoder;
  ctf::wire::encode(encoder, snapshot.epoch);
  ctf::wire::encode(encoder, snapshot.policy_generation);
  ctf::wire::encode(encoder, snapshot.topology_generation);
  encoder.u32(static_cast<std::uint32_t>(snapshot.contract_generations.size()));
  for (const ContractGenerationRecord& record : snapshot.contract_generations) {
    ctf::wire::encode(encoder, record.workload);
    ctf::wire::encode(encoder, record.generation);
  }
  encoder.u32(static_cast<std::uint32_t>(snapshot.sessions.size()));
  for (const PersistedSession& session : snapshot.sessions) {
    encode(encoder, session);
  }
  ctf::wire::encode(encoder, snapshot.accounting);
  encoder.u64(snapshot.commands_processed);
  return std::move(encoder).take();
}

Result<EngineSnapshot> decode_snapshot(ByteSpan data, const Limits& limits) {
  ctf::wire::Decoder decoder(data, limits);
  EngineSnapshot snapshot;
  ctf::wire::decode(decoder, snapshot.epoch);
  ctf::wire::decode(decoder, snapshot.policy_generation);
  ctf::wire::decode(decoder, snapshot.topology_generation);
  const std::uint32_t contract_count = decoder.collection_count();
  if (!decoder.ok()) {
    return decoder.status();
  }
  if (contract_count > limits.max_workloads) {
    return Status::error(ErrorCode::CollectionTooLarge, "snapshot declares too many contracts");
  }
  snapshot.contract_generations.reserve(contract_count);
  for (std::uint32_t i = 0; i < contract_count; ++i) {
    ContractGenerationRecord record;
    ctf::wire::decode(decoder, record.workload);
    ctf::wire::decode(decoder, record.generation);
    if (!decoder.ok()) {
      return decoder.status();
    }
    snapshot.contract_generations.push_back(record);
  }
  const std::uint32_t session_count = decoder.collection_count();
  if (!decoder.ok()) {
    return decoder.status();
  }
  if (session_count > limits.max_sessions) {
    return Status::error(ErrorCode::CollectionTooLarge, "snapshot declares too many sessions");
  }
  snapshot.sessions.reserve(session_count);
  for (std::uint32_t i = 0; i < session_count; ++i) {
    PersistedSession session;
    decode(decoder, session);
    if (!decoder.ok()) {
      return decoder.status();
    }
    snapshot.sessions.push_back(std::move(session));
  }
  ctf::wire::decode(decoder, snapshot.accounting);
  snapshot.commands_processed = decoder.u64();
  const Status end_status = decoder.expect_end();
  if (!end_status.ok()) {
    return end_status;
  }
  return snapshot;
}

// ---------------------------------------------------------------------------
// Journal records
// ---------------------------------------------------------------------------

Bytes encode_journal_record(const JournalRecord& record) {
  Bytes out;
  if (record.label.size() > kMaxLabelBytes || record.payload.size() > ctf::wire::kMaxPayloadBytes) {
    return out;
  }
  // Header: magic, version, flags, sequence, payload_len, label_len, reserved, crc.
  std::vector<std::uint8_t> header(kJournalHeaderBytes, 0);
  const std::uint32_t magic = kJournalMagic;
  for (std::size_t i = 0; i < 4; ++i) {
    header[i] = static_cast<std::uint8_t>((magic >> (8U * (3U - static_cast<unsigned>(i)))) & 0xFFU);
  }
  header[4] = static_cast<std::uint8_t>(kPersistenceFormatVersion >> 8);
  header[5] = static_cast<std::uint8_t>(kPersistenceFormatVersion & 0xFFU);
  header[6] = 0;
  header[7] = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    header[8 + i] = static_cast<std::uint8_t>(
        (record.sequence >> (8U * (7U - static_cast<unsigned>(i)))) & 0xFFU);
  }
  const std::uint32_t payload_bytes = static_cast<std::uint32_t>(record.payload.size());
  for (std::size_t i = 0; i < 4; ++i) {
    header[16 + i] = static_cast<std::uint8_t>(
        (payload_bytes >> (8U * (3U - static_cast<unsigned>(i)))) & 0xFFU);
  }
  header[20] = static_cast<std::uint8_t>(record.label.size() >> 8);
  header[21] = static_cast<std::uint8_t>(record.label.size() & 0xFFU);
  header[22] = 0;
  header[23] = 0;

  // CRC covers the header (with the CRC field zeroed) plus label and payload.
  std::uint32_t crc = crc32c(header.data(), 24);
  crc = crc32c(reinterpret_cast<const std::uint8_t*>(record.label.data()), record.label.size(), crc);
  crc = crc32c(reinterpret_cast<const std::uint8_t*>(record.payload.data()), record.payload.size(),
               crc);
  for (std::size_t i = 0; i < 4; ++i) {
    header[24 + i] =
        static_cast<std::uint8_t>((crc >> (8U * (3U - static_cast<unsigned>(i)))) & 0xFFU);
  }

  out.reserve(kJournalHeaderBytes + record.label.size() + record.payload.size());
  for (const std::uint8_t byte : header) {
    out.push_back(static_cast<std::byte>(byte));
  }
  for (const char c : record.label) {
    out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  }
  out.insert(out.end(), record.payload.begin(), record.payload.end());
  return out;
}

Result<JournalRecord> decode_journal_record(ByteSpan data, std::size_t* consumed_bytes) {
  if (data.size() < kJournalHeaderBytes) {
    return Status::error(ErrorCode::TruncatedInput, "journal record header is incomplete");
  }
  const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(data.data());
  std::uint32_t magic = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    magic = (magic << 8) | raw[i];
  }
  if (magic != kJournalMagic) {
    return Status::error(ErrorCode::InvalidSyntax, "journal record magic does not match");
  }
  const std::uint16_t version = static_cast<std::uint16_t>((raw[4] << 8) | raw[5]);
  if (version != kPersistenceFormatVersion) {
    return Status::error(ErrorCode::VersionIncompatible, "journal record version is not supported");
  }
  if (raw[6] != 0 || raw[7] != 0 || raw[22] != 0 || raw[23] != 0) {
    return Status::error(ErrorCode::NonCanonicalEncoding, "journal record reserved fields are non-zero");
  }
  std::uint64_t sequence = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    sequence = (sequence << 8) | raw[8 + i];
  }
  std::uint32_t payload_bytes = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    payload_bytes = (payload_bytes << 8) | raw[16 + i];
  }
  const std::uint16_t label_bytes = static_cast<std::uint16_t>((raw[20] << 8) | raw[21]);
  if (label_bytes > kMaxLabelBytes) {
    return Status::error(ErrorCode::StringTooLong, "journal record label is too long");
  }
  if (payload_bytes > ctf::wire::kMaxPayloadBytes) {
    return Status::error(ErrorCode::PayloadTooLarge, "journal record payload is too large");
  }
  const std::uint64_t total = static_cast<std::uint64_t>(kJournalHeaderBytes) + label_bytes +
                              static_cast<std::uint64_t>(payload_bytes);
  if (total > data.size()) {
    return Status::error(ErrorCode::TruncatedInput, "journal record payload is incomplete");
  }
  std::uint32_t declared_crc = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    declared_crc = (declared_crc << 8) | raw[24 + i];
  }
  std::uint32_t crc = crc32c(raw, 24);
  crc = crc32c(raw + kJournalHeaderBytes, label_bytes, crc);
  crc = crc32c(raw + kJournalHeaderBytes + label_bytes, payload_bytes, crc);
  if (crc != declared_crc) {
    return Status::error(ErrorCode::IntegrityFailure, "journal record checksum does not match");
  }
  JournalRecord record;
  record.sequence = sequence;
  record.label.assign(reinterpret_cast<const char*>(raw + kJournalHeaderBytes), label_bytes);
  record.payload.assign(data.begin() + static_cast<std::ptrdiff_t>(total - payload_bytes),
                        data.begin() + static_cast<std::ptrdiff_t>(total));
  if (consumed_bytes != nullptr) {
    *consumed_bytes = static_cast<std::size_t>(total);
  }
  return record;
}

// ---------------------------------------------------------------------------
// File primitives
// ---------------------------------------------------------------------------

Status write_file_flushed(const std::filesystem::path& path, ByteSpan data, bool append) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  const errno_t error = fopen_s(&file, path_text(path).c_str(), append ? "ab" : "wb");
  if (error != 0 || file == nullptr) {
    return Status::error(ErrorCode::IoFailure, "cannot open " + path_text(path));
  }
#else
  file = std::fopen(path_text(path).c_str(), append ? "ab" : "wb");
  if (file == nullptr) {
    return Status::error(ErrorCode::IoFailure, "cannot open " + path_text(path));
  }
#endif
  bool ok = true;
  if (!data.empty()) {
    ok = std::fwrite(data.data(), 1, data.size(), file) == data.size();
  }
  Status status = ok ? flush_file(file, path)
                     : Status::error(ErrorCode::IoFailure, "short write to " + path_text(path));
  if (std::fclose(file) != 0 && status.ok()) {
    status = Status::error(ErrorCode::IoFailure, "failed to close " + path_text(path));
  }
  return status;
}

Status atomic_replace(const std::filesystem::path& source, const std::filesystem::path& target) {
  std::error_code error;
#if defined(_WIN32)
  if (!MoveFileExW(source.wstring().c_str(), target.wstring().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return Status::error(ErrorCode::IoFailure,
                         "atomic replace failed with error " + std::to_string(GetLastError()));
  }
  (void)error;
  return Status::success();
#else
  std::filesystem::rename(source, target, error);
  if (error) {
    return Status::error(ErrorCode::IoFailure, "atomic replace failed: " + error.message());
  }
  return Status::success();
#endif
}

// ---------------------------------------------------------------------------
// PersistentStore
// ---------------------------------------------------------------------------

PersistentStore::PersistentStore(StoreConfig config) : config_(std::move(config)) {}

std::filesystem::path PersistentStore::snapshot_path() const {
  return config_.directory / "fabric.snapshot";
}

std::filesystem::path PersistentStore::journal_path() const {
  return config_.directory / "fabric.journal";
}

Status PersistentStore::open() {
  if (config_.directory.empty()) {
    return Status::error(ErrorCode::InvalidArgument, "store directory must not be empty");
  }
  std::error_code error;
  std::filesystem::create_directories(config_.directory, error);
  if (error) {
    return Status::error(ErrorCode::IoFailure,
                         "cannot create store directory: " + error.message());
  }
  if (!std::filesystem::is_directory(config_.directory, error) || error) {
    return Status::error(ErrorCode::IoFailure, "store path is not a directory");
  }
  sequence_ = 0;
  journal_records_ = 0;
  journal_bytes_ = 0;
  return Status::success();
}

bool PersistentStore::has_state() const {
  std::error_code error;
  return std::filesystem::exists(snapshot_path(), error) ||
         std::filesystem::exists(journal_path(), error);
}

Result<EngineSnapshot> PersistentStore::load(LoadReport* report) const {
  LoadReport local;
  const std::filesystem::path snapshot = snapshot_path();
  const std::filesystem::path journal = journal_path();
  std::error_code error;
  EngineSnapshot state;

  if (std::filesystem::exists(snapshot, error)) {
    local.snapshot_present = true;
    Result<Bytes> raw_result = read_file_bytes(snapshot);
    if (!raw_result.ok()) {
      return raw_result.status();
    }
    Bytes raw = std::move(raw_result).value();
    std::size_t consumed = 0;
    const Result<JournalRecord> record =
        decode_journal_record(ByteSpan(raw.data(), raw.size()), &consumed);
    if (!record.ok()) {
      local.corrupt_prefix = true;
      local.version_mismatch = record.code() == ErrorCode::VersionIncompatible;
      if (report != nullptr) {
        *report = local;
        report->notes.push_back("snapshot rejected: " + record.status().to_string());
      }
      return record.status();
    }
    if (consumed != raw.size()) {
      local.corrupt_prefix = true;
      if (report != nullptr) {
        *report = local;
        report->notes.push_back("snapshot has trailing bytes after its record");
      }
      return Status::error(ErrorCode::TrailingGarbage, "snapshot has trailing bytes");
    }
    local.snapshot_sequence = record.value().sequence;
    const Result<EngineSnapshot> decoded =
        decode_snapshot(ByteSpan(record.value().payload.data(), record.value().payload.size()),
                        config_.limits);
    if (!decoded.ok()) {
      local.corrupt_prefix = true;
      local.version_mismatch = decoded.code() == ErrorCode::VersionIncompatible;
      if (report != nullptr) {
        *report = local;
        report->notes.push_back("snapshot payload rejected: " + decoded.status().to_string());
      }
      return decoded.status();
    }
    state = decoded.value();
  }

  if (std::filesystem::exists(journal, error)) {
    local.journal_present = true;
    Result<Bytes> raw_result = read_file_bytes(journal);
    if (!raw_result.ok()) {
      return raw_result.status();
    }
    Bytes raw = std::move(raw_result).value();
    std::size_t offset = 0;
    std::uint64_t last_sequence = local.snapshot_sequence;
    bool advanced = false;
    while (offset < raw.size()) {
      std::size_t consumed = 0;
      const Result<JournalRecord> record =
          decode_journal_record(ByteSpan(raw.data() + offset, raw.size() - offset), &consumed);
      if (!record.ok()) {
        // The journal is append-only, so a bad record can only be a torn tail
        // (or corruption that ends the usable prefix). Everything after it is
        // discarded, never partially applied.
        local.torn_tail = true;
        local.discarded_bytes += raw.size() - offset;
        local.notes.push_back("journal tail discarded: " + record.status().to_string());
        break;
      }
      if (record.value().sequence <= last_sequence) {
        local.torn_tail = true;
        local.discarded_bytes += raw.size() - offset;
        local.notes.push_back("journal repeats or rewinds a sequence number; tail discarded");
        break;
      }
      // Every record payload is a complete state version; the label is a
      // diagnostic annotation, never a filter. A record whose payload does not
      // decode ends the usable prefix.
      const Result<EngineSnapshot> decoded = decode_snapshot(
          ByteSpan(record.value().payload.data(), record.value().payload.size()), config_.limits);
      if (!decoded.ok()) {
        local.torn_tail = true;
        local.discarded_bytes += raw.size() - offset;
        local.notes.push_back("journal record '" + record.value().label +
                              "' rejected: " + decoded.status().to_string());
        break;
      }
      state = decoded.value();
      advanced = true;
      last_sequence = record.value().sequence;
      ++local.journal_records_applied;
      offset += consumed;
    }
    (void)advanced;
  }

  if (!local.snapshot_present && !local.journal_present) {
    if (report != nullptr) {
      *report = local;
    }
    return Status::error(ErrorCode::NotFound, "no persisted state");
  }
  if (report != nullptr) {
    *report = local;
  }
  return state;
}

Status PersistentStore::persist(const EngineSnapshot& snapshot) {
  EngineSnapshot copy = snapshot;
  ++sequence_;
  copy.commands_processed = snapshot.commands_processed;
  const JournalRecord record{sequence_, "snapshot", encode_snapshot(snapshot, config_.limits)};
  if (record.payload.empty() && !snapshot.sessions.empty()) {
    return Status::error(ErrorCode::Internal, "snapshot encoding produced an empty payload");
  }
  const Bytes encoded = encode_journal_record(record);
  if (encoded.empty()) {
    return Status::error(ErrorCode::Internal, "journal encoding failed");
  }
  const std::filesystem::path temp = snapshot_path().string() + ".tmp";
  const Status write_status = write_file_flushed(temp, ByteSpan(encoded.data(), encoded.size()), false);
  if (!write_status.ok()) {
    return write_status;
  }
  const Status replace_status = atomic_replace(temp, snapshot_path());
  if (!replace_status.ok()) {
    return replace_status;
  }
  // Rotate the journal so growth stays bounded and the snapshot is the single
  // source of truth from here on. The rotated record carries the next sequence
  // number so recovery sees a strictly increasing prefix rather than a rewind.
  const JournalRecord rotated{++sequence_, "snapshot", record.payload};
  const Bytes rotated_encoded = encode_journal_record(rotated);
  if (rotated_encoded.empty()) {
    return Status::error(ErrorCode::Internal, "journal encoding failed");
  }
  const Status journal_status = write_file_flushed(
      journal_path(), ByteSpan(rotated_encoded.data(), rotated_encoded.size()), false);
  if (!journal_status.ok()) {
    return journal_status;
  }
  journal_records_ = 1;
  journal_bytes_ = rotated_encoded.size();
  return Status::success();
}

Status PersistentStore::append(const std::string& label, const EngineSnapshot& snapshot) {
  const Bytes payload = encode_snapshot(snapshot, config_.limits);
  const JournalRecord record{++sequence_, label, payload};
  const Bytes encoded = encode_journal_record(record);
  if (encoded.empty()) {
    --sequence_;
    return Status::error(ErrorCode::Internal, "journal encoding failed");
  }
  const Status write_status =
      write_file_flushed(journal_path(), ByteSpan(encoded.data(), encoded.size()), true);
  if (!write_status.ok()) {
    return write_status;
  }
  ++journal_records_;
  journal_bytes_ += encoded.size();
  if (journal_bytes_ > config_.max_journal_bytes ||
      journal_records_ > config_.max_journal_records) {
    return persist(snapshot);
  }
  return Status::success();
}

}  // namespace ctf::store
