#include "MemoryScanner.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#if defined(__aarch64__)
#include <arm_neon.h>
#endif

namespace {
constexpr size_t kChunkSize = 1024 * 1024;
constexpr size_t kMaxScanResults = 20'000'000;
constexpr unsigned kMaxScanThreads = 8;

template <typename T>
T LoadUnaligned(const uint8_t* ptr) {
  T value;
  std::memcpy(&value, ptr, sizeof(value));
  return value;
}

uint64_t BitsFromFloat(float value) {
  uint32_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  return static_cast<uint64_t>(bits);
}

uint64_t BitsFromDouble(double value) {
  uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

unsigned ChooseScanThreads(size_t work_items) {
  if (work_items <= 1) {
    return 1;
  }
  const unsigned hw = std::thread::hardware_concurrency();
  unsigned threads = hw == 0 ? 2u : std::max(1u, hw / 2u);
  threads = std::min(threads, kMaxScanThreads);
  threads = std::min<unsigned>(threads, static_cast<unsigned>(work_items));
  return std::max(1u, threads);
}

std::string ToLowerAscii(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

bool ContainsCI(const std::string& text, const char* token) {
  if (!token || !*token) {
    return false;
  }
  const std::string needle = ToLowerAscii(token);
  return ToLowerAscii(text).find(needle) != std::string::npos;
}

bool StartsWithPath(const std::string& path, const char* prefix) {
  if (!prefix) {
    return false;
  }
  const std::string p = ToLowerAscii(path);
  const std::string k = ToLowerAscii(prefix);
  return p.rfind(k, 0) == 0;
}

uint8_t ClassifyGGRegionCode(const SafeMemoryReader::MemoryRegion& region) {
  const std::string path = ToLowerAscii(region.path);
  const bool exec = region.executable;
  const bool writable = region.writable;
  const bool has_path = !path.empty();
  const bool anon = !has_path || path[0] == '[' || ContainsCI(path, "anon");
  const bool file = has_path && path[0] != '[' && !StartsWithPath(path, "/dev");

  if (ContainsCI(path, "ppsspp")) return protocol::GG_REGION_PS;
  if (ContainsCI(path, "dalvik-heap") || ContainsCI(path, "dalvik main") ||
      ContainsCI(path, "zygote space") || ContainsCI(path, "alloc space") ||
      ContainsCI(path, "main space") || ContainsCI(path, "large object")) {
    return protocol::GG_REGION_JH;
  }
  if (ContainsCI(path, "[heap]") || ContainsCI(path, "libc_malloc") ||
      ContainsCI(path, "scudo") || ContainsCI(path, "malloc")) {
    return protocol::GG_REGION_CH;
  }
  if (ContainsCI(path, "alloc")) return protocol::GG_REGION_CA;
  if (anon && writable && !exec && !file) return protocol::GG_REGION_BSS;
  if (ContainsCI(path, "dalvik") || ContainsCI(path, "art") ||
      ContainsCI(path, ".oat") || ContainsCI(path, ".vdex") || ContainsCI(path, ".dex")) {
    return protocol::GG_REGION_J;
  }
  if (ContainsCI(path, "[stack")) return protocol::GG_REGION_S;
  if (ContainsCI(path, "ashmem") || ContainsCI(path, "memfd")) return protocol::GG_REGION_AS;

  const bool is_app = StartsWithPath(path, "/data/app") || StartsWithPath(path, "/data/user") ||
                      StartsWithPath(path, "/data/data") || StartsWithPath(path, "/mnt/asec");
  const bool is_system = StartsWithPath(path, "/system") || StartsWithPath(path, "/apex") ||
                         StartsWithPath(path, "/vendor") || StartsWithPath(path, "/product") ||
                         StartsWithPath(path, "/odm") || StartsWithPath(path, "/system_ext");
  if (exec && is_app) return protocol::GG_REGION_XA;
  if (exec && is_system) return protocol::GG_REGION_XS;

  if (StartsWithPath(path, "/dev") &&
      (ContainsCI(path, "video") || ContainsCI(path, "kgsl") ||
       ContainsCI(path, "gpu") || ContainsCI(path, "graphics"))) {
    return protocol::GG_REGION_V;
  }
  if (anon) return protocol::GG_REGION_A;
  return protocol::GG_REGION_O;
}

struct AllTargetValue {
  bool has_unsigned = false;
  bool has_signed = false;
  bool has_float = false;
  uint64_t unsigned_value = 0;
  int64_t signed_value = 0;
  double float_value = 0.0;
};

std::string TrimAscii(const std::string& text) {
  const char* ws = " \t\r\n";
  const size_t start = text.find_first_not_of(ws);
  if (start == std::string::npos) {
    return "";
  }
  const size_t end = text.find_last_not_of(ws);
  return text.substr(start, end - start + 1);
}

bool ParseAllTarget(const void* value, size_t value_len, AllTargetValue* out) {
  if (!value || value_len == 0 || !out) {
    return false;
  }
  *out = {};
  std::string raw(reinterpret_cast<const char*>(value), value_len);
  raw = TrimAscii(raw);
  if (raw.empty()) {
    return false;
  }
  {
    char* endptr = nullptr;
    const uint64_t v = std::strtoull(raw.c_str(), &endptr, 0);
    if (endptr != raw.c_str() && *endptr == '\0') {
      out->has_unsigned = true;
      out->unsigned_value = v;
    }
  }
  {
    char* endptr = nullptr;
    const int64_t v = std::strtoll(raw.c_str(), &endptr, 0);
    if (endptr != raw.c_str() && *endptr == '\0') {
      out->has_signed = true;
      out->signed_value = v;
    }
  }
  {
    char* endptr = nullptr;
    const double v = std::strtod(raw.c_str(), &endptr);
    if (endptr != raw.c_str() && *endptr == '\0') {
      out->has_float = true;
      out->float_value = v;
    }
  }
  return out->has_unsigned || out->has_signed || out->has_float;
}

struct ScanTask {
  uint64_t read_start = 0;
  uint64_t scan_end = 0;
  uint64_t read_end = 0;
};

#if defined(__aarch64__)
void CollectEqOffsetsU32Neon(const uint8_t* data,
                             size_t limit,
                             uint32_t target,
                             std::vector<size_t>* out_offsets) {
  if (!data || !out_offsets || limit < sizeof(uint32_t)) {
    return;
  }
  const uint32x4_t target_vec = vdupq_n_u32(target);
  const size_t vec_width = 16;
  size_t offset = 0;
  while (offset + vec_width <= limit) {
    const uint32x4_t vals = vld1q_u32(reinterpret_cast<const uint32_t*>(data + offset));
    const uint32x4_t eq = vceqq_u32(vals, target_vec);
    if (vgetq_lane_u32(eq, 0) == UINT32_MAX) {
      out_offsets->push_back(offset);
    }
    if (vgetq_lane_u32(eq, 1) == UINT32_MAX) {
      out_offsets->push_back(offset + 4);
    }
    if (vgetq_lane_u32(eq, 2) == UINT32_MAX) {
      out_offsets->push_back(offset + 8);
    }
    if (vgetq_lane_u32(eq, 3) == UINT32_MAX) {
      out_offsets->push_back(offset + 12);
    }
    offset += vec_width;
  }
  for (; offset + sizeof(uint32_t) <= limit; offset += sizeof(uint32_t)) {
    if (LoadUnaligned<uint32_t>(data + offset) == target) {
      out_offsets->push_back(offset);
    }
  }
}

void CollectEqOffsetsU64Neon(const uint8_t* data,
                             size_t limit,
                             uint64_t target,
                             std::vector<size_t>* out_offsets) {
  if (!data || !out_offsets || limit < sizeof(uint64_t)) {
    return;
  }
  const uint64x2_t target_vec = vdupq_n_u64(target);
  const size_t vec_width = 16;
  size_t offset = 0;
  while (offset + vec_width <= limit) {
    const uint64x2_t vals = vld1q_u64(reinterpret_cast<const uint64_t*>(data + offset));
    const uint64x2_t eq = vceqq_u64(vals, target_vec);
    if (vgetq_lane_u64(eq, 0) == UINT64_MAX) {
      out_offsets->push_back(offset);
    }
    if (vgetq_lane_u64(eq, 1) == UINT64_MAX) {
      out_offsets->push_back(offset + 8);
    }
    offset += vec_width;
  }
  for (; offset + sizeof(uint64_t) <= limit; offset += sizeof(uint64_t)) {
    if (LoadUnaligned<uint64_t>(data + offset) == target) {
      out_offsets->push_back(offset);
    }
  }
}
#endif
} // namespace

MemoryScanner::MemoryScanner(SafeMemoryReader* reader)
    : reader_(reader), scan_start_(0), scan_end_(UINT64_MAX) {}

void MemoryScanner::SetReader(SafeMemoryReader* reader) { reader_ = reader; }

void MemoryScanner::SetUsePvm(bool enable) { use_pvm_ = enable; }

void MemoryScanner::SetAllowNonresident(bool enable) { allow_nonresident_ = enable; }

void MemoryScanner::SetByteStep(bool enable) { byte_step_ = enable; }

void MemoryScanner::SetStrict(bool enable) { strict_ = enable; }

void MemoryScanner::SetRequireWritable(bool enable) { require_writable_ = enable; }

void MemoryScanner::SetRequireExecutable(bool enable) { require_executable_ = enable; }

void MemoryScanner::SetRegionTypeMask(uint8_t mask) { region_type_mask_ = mask; }

void MemoryScanner::SetGGRegionCode(uint8_t code) { gg_region_code_ = code; }

void MemoryScanner::SetScanRange(uint64_t start_addr, uint64_t end_addr) {
  if (end_addr > start_addr) {
    scan_start_ = start_addr;
    scan_end_ = end_addr;
  } else {
    scan_start_ = 0;
    scan_end_ = UINT64_MAX;
  }
}

void MemoryScanner::Clear() {
  results_.clear();
  last_values_.clear();
}

size_t MemoryScanner::ValueSize(protocol::ValueType type) {
  switch (type) {
    case protocol::ValueType::U8:
      return sizeof(uint8_t);
    case protocol::ValueType::U16:
      return sizeof(uint16_t);
    case protocol::ValueType::U32:
      return sizeof(uint32_t);
    case protocol::ValueType::U64:
      return sizeof(uint64_t);
    case protocol::ValueType::FLOAT:
      return sizeof(float);
    case protocol::ValueType::DOUBLE:
      return sizeof(double);
    case protocol::ValueType::S32:
      return sizeof(int32_t);
    case protocol::ValueType::S64:
      return sizeof(int64_t);
    case protocol::ValueType::STRING:
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
    case protocol::ValueType::ALL:
      return sizeof(uint8_t);
    default:
      return 0;
  }
}

bool MemoryScanner::LoadTarget(protocol::ValueType type, const void* value,
                               uint64_t* out_bits, double* out_fp) {
  if (!value) {
    return false;
  }
  if (out_bits) {
    *out_bits = 0;
  }
  if (out_fp) {
    *out_fp = 0.0;
  }

  switch (type) {
    case protocol::ValueType::U8: {
      uint8_t v = 0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    case protocol::ValueType::U16: {
      uint16_t v = 0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    case protocol::ValueType::U32: {
      uint32_t v = 0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    case protocol::ValueType::U64: {
      uint64_t v = 0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = v;
      }
      return true;
    }
    case protocol::ValueType::FLOAT: {
      float v = 0.0f;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = BitsFromFloat(v);
      }
      if (out_fp) {
        *out_fp = static_cast<double>(v);
      }
      return true;
    }
    case protocol::ValueType::DOUBLE: {
      double v = 0.0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = BitsFromDouble(v);
      }
      if (out_fp) {
        *out_fp = v;
      }
      return true;
    }
    case protocol::ValueType::S32: {
      int32_t v = 0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(static_cast<uint32_t>(v));
      }
      return true;
    }
    case protocol::ValueType::S64: {
      int64_t v = 0;
      std::memcpy(&v, value, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    default:
      return false;
  }
}

bool MemoryScanner::CompareInteger(uint64_t actual, uint64_t target,
                                   protocol::ComparisonType condition) {
  switch (condition) {
    case protocol::ComparisonType::EQ:
      return actual == target;
    case protocol::ComparisonType::NE:
      return actual != target;
    case protocol::ComparisonType::GT:
      return actual > target;
    case protocol::ComparisonType::LT:
      return actual < target;
    case protocol::ComparisonType::GE:
      return actual >= target;
    case protocol::ComparisonType::LE:
      return actual <= target;
    default:
      return false;
  }
}

bool MemoryScanner::CompareIntegerSigned(int64_t actual, int64_t target,
                                         protocol::ComparisonType condition) {
  switch (condition) {
    case protocol::ComparisonType::EQ:
      return actual == target;
    case protocol::ComparisonType::NE:
      return actual != target;
    case protocol::ComparisonType::GT:
      return actual > target;
    case protocol::ComparisonType::LT:
      return actual < target;
    case protocol::ComparisonType::GE:
      return actual >= target;
    case protocol::ComparisonType::LE:
      return actual <= target;
    default:
      return false;
  }
}

bool MemoryScanner::CompareFloat(double actual, double target,
                                 protocol::ComparisonType condition) {
  switch (condition) {
    case protocol::ComparisonType::EQ:
      return actual == target;
    case protocol::ComparisonType::NE:
      return actual != target;
    case protocol::ComparisonType::GT:
      return actual > target;
    case protocol::ComparisonType::LT:
      return actual < target;
    case protocol::ComparisonType::GE:
      return actual >= target;
    case protocol::ComparisonType::LE:
      return actual <= target;
    default:
      return false;
  }
}

int64_t MemoryScanner::BitsToSigned(protocol::ValueType type, uint64_t bits) {
  switch (type) {
    case protocol::ValueType::S32:
      return static_cast<int64_t>(static_cast<int32_t>(bits));
    case protocol::ValueType::S64:
      return static_cast<int64_t>(bits);
    default:
      return static_cast<int64_t>(bits);
  }
}

bool MemoryScanner::ReadValue(uint64_t addr, protocol::ValueType type,
                              uint64_t* out_bits, double* out_fp) {
  if (!reader_) {
    return false;
  }
  const size_t value_size = ValueSize(type);
  if (value_size == 0) {
    return false;
  }

  uint8_t buffer[8] = {0};
  SafeMemoryReader::ReadStats stats;
  if (!reader_->ValidateAndReadEx(addr,
                                  buffer,
                                  value_size,
                                  &stats,
                                  allow_nonresident_,
                                  false,
                                  use_pvm_)) {
    return false;
  }
  if (stats.bytes_read < value_size) {
    return false;
  }

  switch (type) {
    case protocol::ValueType::U8: {
      uint8_t v = 0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    case protocol::ValueType::U16: {
      uint16_t v = 0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    case protocol::ValueType::U32: {
      uint32_t v = 0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    case protocol::ValueType::U64: {
      uint64_t v = 0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = v;
      }
      return true;
    }
    case protocol::ValueType::FLOAT: {
      float v = 0.0f;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = BitsFromFloat(v);
      }
      if (out_fp) {
        *out_fp = static_cast<double>(v);
      }
      return true;
    }
    case protocol::ValueType::DOUBLE: {
      double v = 0.0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = BitsFromDouble(v);
      }
      if (out_fp) {
        *out_fp = v;
      }
      return true;
    }
    case protocol::ValueType::S32: {
      int32_t v = 0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(static_cast<uint32_t>(v));
      }
      return true;
    }
    case protocol::ValueType::S64: {
      int64_t v = 0;
      std::memcpy(&v, buffer, sizeof(v));
      if (out_bits) {
        *out_bits = static_cast<uint64_t>(v);
      }
      return true;
    }
    default:
      return false;
  }
}

bool MemoryScanner::FirstScan(protocol::ValueType type,
                              const void* value,
                              size_t value_len,
                              protocol::ComparisonType condition) {
  if (!reader_) {
    return false;
  }

  results_.clear();
  last_values_.clear();

  if (!reader_->RefreshMaps()) {
    return false;
  }

  const size_t value_size = ValueSize(type);
  if (value_size == 0) {
    return false;
  }

  const bool pattern_scan = type == protocol::ValueType::STRING ||
                            type == protocol::ValueType::AOB ||
                            type == protocol::ValueType::BINARY;
  const bool all_scan = type == protocol::ValueType::ALL;

  std::vector<uint8_t> pattern;
  uint64_t target_bits = 0;
  double target_fp = 0.0;
  int64_t target_signed = 0;
  AllTargetValue all_target{};
  if (pattern_scan) {
    if (!value || value_len == 0) {
      return false;
    }
    const auto* bytes = reinterpret_cast<const uint8_t*>(value);
    pattern.assign(bytes, bytes + value_len);
  } else if (all_scan) {
    if (!ParseAllTarget(value, value_len, &all_target)) {
      return false;
    }
  } else {
    if (!LoadTarget(type, value, &target_bits, &target_fp)) {
      return false;
    }
    target_signed = BitsToSigned(type, target_bits);
  }

  const size_t min_match_size = pattern_scan ? pattern.size() : (all_scan ? 1u : value_size);
  if (min_match_size == 0) {
    return false;
  }
  const size_t step = (byte_step_ || pattern_scan || all_scan) ? 1u : value_size;
  uint64_t overlap = 0;
  if (pattern_scan && pattern.size() > 1) {
    overlap = static_cast<uint64_t>(pattern.size() - 1);
  } else if (all_scan) {
    overlap = 7;
  } else if (byte_step_ && value_size > 1) {
    overlap = static_cast<uint64_t>(value_size - 1);
  }
  const bool fast_mode = allow_nonresident_ && !strict_;
  const uint8_t type_mask = region_type_mask_;
  const bool require_type = type_mask != 0;
  std::vector<ScanTask> tasks;
  tasks.reserve(reader_->regions().size() * 4);

  for (const auto& region : reader_->regions()) {
    if (!region.readable) {
      continue;
    }
    if (require_writable_ && !region.writable) {
      continue;
    }
    if (require_executable_ && !region.executable) {
      continue;
    }
    if (require_type) {
      const bool file_backed = !region.path.empty() && region.path[0] != '[';
      uint8_t region_type = 0;
      if (!file_backed) {
        region_type = 1u;  // private/anonymous
      } else if (region.executable) {
        region_type = 2u;  // image
      } else {
        region_type = 4u;  // mapped
      }
      if ((region_type & type_mask) == 0) {
        continue;
      }
    }
    if (gg_region_code_ != protocol::GG_REGION_NONE &&
        ClassifyGGRegionCode(region) != gg_region_code_) {
      continue;
    }
    if (region.end <= region.start) {
      continue;
    }

    const uint64_t region_start = std::max(region.start, scan_start_);
    const uint64_t region_end = std::min(region.end, scan_end_);
    if (region_end <= region_start) {
      continue;
    }

    uint64_t cursor = region_start;
    while (cursor < region_end) {
      const uint64_t remaining = region_end - cursor;
      size_t chunk_len = static_cast<size_t>(std::min<uint64_t>(remaining, kChunkSize));
      if (!byte_step_ && !pattern_scan && !all_scan) {
        chunk_len = (chunk_len / value_size) * value_size;
      }
      if (chunk_len < min_match_size) {
        break;
      }
      const uint64_t chunk_scan_end = cursor + static_cast<uint64_t>(chunk_len);
      const uint64_t chunk_read_end = overlap > 0 ? std::min(region_end, chunk_scan_end + overlap) : chunk_scan_end;
      tasks.push_back({cursor, chunk_scan_end, chunk_read_end});
      cursor = chunk_scan_end;
    }
  }

  if (tasks.empty()) {
    return true;
  }

  struct LocalResult {
    std::vector<uint64_t> addrs;
    std::vector<uint64_t> values;
    std::vector<uint8_t> buffer;
#if defined(__aarch64__)
    std::vector<size_t> neon_offsets;
#endif
  };

  const unsigned thread_count = ChooseScanThreads(tasks.size());
  std::vector<LocalResult> locals(thread_count);
  std::atomic<size_t> task_index{0};
  std::atomic<size_t> total_matches{0};
  std::atomic<bool> stop{false};
  std::atomic<bool> failed{false};
  std::atomic<bool> overflow{false};

  auto append_match = [&](LocalResult& local, uint64_t addr, uint64_t actual_bits) -> bool {
    const size_t prev = total_matches.fetch_add(1, std::memory_order_relaxed);
    if (prev >= kMaxScanResults) {
      overflow.store(true, std::memory_order_relaxed);
      stop.store(true, std::memory_order_relaxed);
      return false;
    }
    local.addrs.push_back(addr);
    local.values.push_back(actual_bits);
    return true;
  };

  auto worker = [&](unsigned id) {
    LocalResult& local = locals[id];
    while (!stop.load(std::memory_order_relaxed)) {
      const size_t task_id = task_index.fetch_add(1, std::memory_order_relaxed);
      if (task_id >= tasks.size()) {
        break;
      }
      const auto& task = tasks[task_id];
      if (task.read_end <= task.read_start || task.scan_end <= task.read_start) {
        continue;
      }

      const size_t chunk_len = static_cast<size_t>(task.read_end - task.read_start);
      local.buffer.resize(chunk_len);
      SafeMemoryReader::ReadStats stats{};
      if (!reader_->ValidateAndReadEx(task.read_start,
                                      local.buffer.data(),
                                      chunk_len,
                                      &stats,
                                      allow_nonresident_,
                                      false,
                                      use_pvm_,
                                      fast_mode)) {
        if (strict_) {
          failed.store(true, std::memory_order_relaxed);
          stop.store(true, std::memory_order_relaxed);
          return;
        }
        continue;
      }
      if (strict_ && stats.bytes_read < chunk_len) {
        failed.store(true, std::memory_order_relaxed);
        stop.store(true, std::memory_order_relaxed);
        return;
      }
      if (stats.bytes_read < min_match_size) {
        continue;
      }

      const size_t scan_limit = static_cast<size_t>(task.scan_end - task.read_start);
      size_t limit = 0;
      if (pattern_scan) {
        if (stats.bytes_read < pattern.size()) {
          continue;
        }
        limit = stats.bytes_read - pattern.size() + 1;
      } else if (all_scan) {
        limit = stats.bytes_read;
      } else {
        if (stats.bytes_read < value_size) {
          continue;
        }
        limit = stats.bytes_read - value_size + 1;
      }
      if (limit > scan_limit) {
        limit = scan_limit;
      }
      if (limit == 0) {
        continue;
      }

#if defined(__aarch64__)
      if (!pattern_scan &&
          !all_scan &&
          condition == protocol::ComparisonType::EQ &&
          !byte_step_ &&
          (type == protocol::ValueType::U32 || type == protocol::ValueType::U64)) {
        local.neon_offsets.clear();
        if (type == protocol::ValueType::U32) {
          CollectEqOffsetsU32Neon(local.buffer.data(),
                                  limit,
                                  static_cast<uint32_t>(target_bits),
                                  &local.neon_offsets);
        } else {
          CollectEqOffsetsU64Neon(local.buffer.data(),
                                  limit,
                                  target_bits,
                                  &local.neon_offsets);
        }
        for (size_t offset : local.neon_offsets) {
          if (!append_match(local, task.read_start + offset, target_bits)) {
            return;
          }
        }
        continue;
      }
#endif

      for (size_t offset = 0; offset < limit; offset += step) {
        const uint8_t* ptr = local.buffer.data() + offset;
        const size_t remain = stats.bytes_read - offset;
        bool match = false;
        uint64_t actual_bits = 0;
        double actual_fp = 0.0;

        if (pattern_scan) {
          if (remain >= pattern.size() &&
              std::memcmp(ptr, pattern.data(), pattern.size()) == 0) {
            match = true;
            const size_t take = std::min<size_t>(pattern.size(), sizeof(uint64_t));
            std::memcpy(&actual_bits, ptr, take);
          }
        } else if (all_scan) {
          auto match_unsigned = [&](uint64_t actual, uint64_t target) {
            return CompareInteger(actual, target, condition);
          };
          auto match_signed = [&](int64_t actual, int64_t target) {
            return CompareIntegerSigned(actual, target, condition);
          };
          auto match_float = [&](double actual, double target) {
            return CompareFloat(actual, target, condition);
          };

          if (all_target.has_unsigned) {
            if (remain >= 1 && match_unsigned(static_cast<uint64_t>(LoadUnaligned<uint8_t>(ptr)),
                                              static_cast<uint64_t>(static_cast<uint8_t>(all_target.unsigned_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 2 &&
                match_unsigned(static_cast<uint64_t>(LoadUnaligned<uint16_t>(ptr)),
                               static_cast<uint64_t>(static_cast<uint16_t>(all_target.unsigned_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 4 &&
                match_unsigned(static_cast<uint64_t>(LoadUnaligned<uint32_t>(ptr)),
                               static_cast<uint64_t>(static_cast<uint32_t>(all_target.unsigned_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 8 &&
                match_unsigned(LoadUnaligned<uint64_t>(ptr), all_target.unsigned_value)) {
              match = true;
            }
          }
          if (!match && all_target.has_signed) {
            if (remain >= 4 &&
                match_signed(static_cast<int64_t>(LoadUnaligned<int32_t>(ptr)),
                             static_cast<int64_t>(static_cast<int32_t>(all_target.signed_value)))) {
              match = true;
            }
            if (!match && remain >= 8 && match_signed(LoadUnaligned<int64_t>(ptr), all_target.signed_value)) {
              match = true;
            }
          }
          if (!match && all_target.has_float) {
            if (remain >= 4 &&
                match_float(static_cast<double>(LoadUnaligned<float>(ptr)), all_target.float_value)) {
              match = true;
            }
            if (!match && remain >= 8 && match_float(LoadUnaligned<double>(ptr), all_target.float_value)) {
              match = true;
            }
          }
          if (match) {
            const size_t take = std::min<size_t>(remain, sizeof(uint64_t));
            std::memcpy(&actual_bits, ptr, take);
          }
        } else {
          switch (type) {
            case protocol::ValueType::U8: {
              const uint8_t v = LoadUnaligned<uint8_t>(ptr);
              actual_bits = static_cast<uint64_t>(v);
              match = CompareInteger(actual_bits, target_bits, condition);
              break;
            }
            case protocol::ValueType::U16: {
              const uint16_t v = LoadUnaligned<uint16_t>(ptr);
              actual_bits = static_cast<uint64_t>(v);
              match = CompareInteger(actual_bits, target_bits, condition);
              break;
            }
            case protocol::ValueType::U32: {
              const uint32_t v = LoadUnaligned<uint32_t>(ptr);
              actual_bits = static_cast<uint64_t>(v);
              match = CompareInteger(actual_bits, target_bits, condition);
              break;
            }
            case protocol::ValueType::U64: {
              const uint64_t v = LoadUnaligned<uint64_t>(ptr);
              actual_bits = v;
              match = CompareInteger(actual_bits, target_bits, condition);
              break;
            }
            case protocol::ValueType::FLOAT: {
              const float v = LoadUnaligned<float>(ptr);
              actual_fp = static_cast<double>(v);
              actual_bits = BitsFromFloat(v);
              match = CompareFloat(actual_fp, target_fp, condition);
              break;
            }
            case protocol::ValueType::DOUBLE: {
              const double v = LoadUnaligned<double>(ptr);
              actual_fp = v;
              actual_bits = BitsFromDouble(v);
              match = CompareFloat(actual_fp, target_fp, condition);
              break;
            }
            case protocol::ValueType::S32: {
              const int32_t v = LoadUnaligned<int32_t>(ptr);
              actual_bits = static_cast<uint64_t>(static_cast<uint32_t>(v));
              match = CompareIntegerSigned(static_cast<int64_t>(v), target_signed, condition);
              break;
            }
            case protocol::ValueType::S64: {
              const int64_t v = LoadUnaligned<int64_t>(ptr);
              actual_bits = static_cast<uint64_t>(v);
              match = CompareIntegerSigned(v, target_signed, condition);
              break;
            }
            default:
              break;
          }
        }

        if (match) {
          if (!append_match(local, task.read_start + offset, actual_bits)) {
            return;
          }
        }
      }
    }
  };

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (unsigned i = 0; i < thread_count; ++i) {
    threads.emplace_back(worker, i);
  }
  for (auto& t : threads) {
    t.join();
  }

  if (failed.load(std::memory_order_relaxed) || overflow.load(std::memory_order_relaxed)) {
    results_.clear();
    last_values_.clear();
    return false;
  }

  size_t total = 0;
  for (const auto& local : locals) {
    total += local.addrs.size();
  }
  if (total > kMaxScanResults) {
    results_.clear();
    last_values_.clear();
    return false;
  }
  results_.reserve(total);
  last_values_.reserve(total);
  for (const auto& local : locals) {
    results_.insert(results_.end(), local.addrs.begin(), local.addrs.end());
    last_values_.insert(last_values_.end(), local.values.begin(), local.values.end());
  }

  return true;
}

bool MemoryScanner::NextScan(protocol::ValueType type,
                             const void* value,
                             size_t value_len,
                             protocol::ComparisonType condition) {
  if (!reader_) {
    return false;
  }
  if (results_.empty()) {
    return true;
  }

  const size_t value_size = ValueSize(type);
  if (value_size == 0) {
    return false;
  }

  const bool pattern_scan = type == protocol::ValueType::STRING ||
                            type == protocol::ValueType::AOB ||
                            type == protocol::ValueType::BINARY;
  const bool all_scan = type == protocol::ValueType::ALL;
  if ((pattern_scan || all_scan) &&
      (condition == protocol::ComparisonType::CHANGED ||
       condition == protocol::ComparisonType::UNCHANGED)) {
    return false;
  }

  std::vector<uint8_t> pattern;
  uint64_t target_bits = 0;
  double target_fp = 0.0;
  int64_t target_signed = 0;
  AllTargetValue all_target{};
  if (pattern_scan) {
    if (!value || value_len == 0) {
      return false;
    }
    const auto* bytes = reinterpret_cast<const uint8_t*>(value);
    pattern.assign(bytes, bytes + value_len);
  } else if (all_scan) {
    if (!ParseAllTarget(value, value_len, &all_target)) {
      return false;
    }
  } else {
    if (!LoadTarget(type, value, &target_bits, &target_fp)) {
      return false;
    }
    target_signed = BitsToSigned(type, target_bits);
  }

  struct NextMatch {
    size_t index = 0;
    uint64_t addr = 0;
    uint64_t value = 0;
  };
  struct LocalNext {
    std::vector<NextMatch> matches;
    std::vector<uint8_t> buffer;
  };

  const unsigned thread_count = ChooseScanThreads(results_.size());
  std::vector<LocalNext> locals(thread_count);
  std::atomic<size_t> index{0};
  std::atomic<size_t> total_matches{0};
  std::atomic<bool> stop{false};
  std::atomic<bool> failed{false};
  constexpr size_t kBatch = 512;

  auto worker = [&](unsigned id) {
    LocalNext& local = locals[id];
    while (!stop.load(std::memory_order_relaxed)) {
      const size_t start = index.fetch_add(kBatch, std::memory_order_relaxed);
      if (start >= results_.size()) {
        break;
      }
      const size_t end = std::min(results_.size(), start + kBatch);
      for (size_t i = start; i < end; ++i) {
        if (stop.load(std::memory_order_relaxed)) {
          break;
        }
        const uint64_t addr = results_[i];
        const uint64_t prev_bits = (i < last_values_.size()) ? last_values_[i] : 0;
        bool match = false;
        uint64_t actual_bits = 0;
        double actual_fp = 0.0;

        if (pattern_scan) {
          local.buffer.assign(pattern.size(), 0);
          SafeMemoryReader::ReadStats stats{};
          if (!reader_->ValidateAndReadEx(addr,
                                          local.buffer.data(),
                                          pattern.size(),
                                          &stats,
                                          allow_nonresident_,
                                          false,
                                          use_pvm_)) {
            if (strict_) {
              failed.store(true, std::memory_order_relaxed);
              stop.store(true, std::memory_order_relaxed);
              return;
            }
            continue;
          }
          const bool equal = stats.bytes_read >= pattern.size() &&
                             std::memcmp(local.buffer.data(), pattern.data(), pattern.size()) == 0;
          if (condition == protocol::ComparisonType::EQ) {
            match = equal;
          } else if (condition == protocol::ComparisonType::NE) {
            match = !equal;
          } else {
            match = false;
          }
          const size_t take = std::min<size_t>(stats.bytes_read, sizeof(uint64_t));
          if (take > 0) {
            std::memcpy(&actual_bits, local.buffer.data(), take);
          }
        } else if (all_scan) {
          local.buffer.assign(8, 0);
          SafeMemoryReader::ReadStats stats{};
          if (!reader_->ValidateAndReadEx(addr,
                                          local.buffer.data(),
                                          local.buffer.size(),
                                          &stats,
                                          allow_nonresident_,
                                          false,
                                          use_pvm_)) {
            if (strict_) {
              failed.store(true, std::memory_order_relaxed);
              stop.store(true, std::memory_order_relaxed);
              return;
            }
            continue;
          }
          const size_t remain = stats.bytes_read;
          auto match_unsigned = [&](uint64_t actual, uint64_t target) {
            return CompareInteger(actual, target, condition);
          };
          auto match_signed = [&](int64_t actual, int64_t target) {
            return CompareIntegerSigned(actual, target, condition);
          };
          auto match_float = [&](double actual, double target) {
            return CompareFloat(actual, target, condition);
          };
          if (all_target.has_unsigned) {
            if (remain >= 1 && match_unsigned(static_cast<uint64_t>(LoadUnaligned<uint8_t>(local.buffer.data())),
                                              static_cast<uint64_t>(static_cast<uint8_t>(all_target.unsigned_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 2 &&
                match_unsigned(static_cast<uint64_t>(LoadUnaligned<uint16_t>(local.buffer.data())),
                               static_cast<uint64_t>(static_cast<uint16_t>(all_target.unsigned_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 4 &&
                match_unsigned(static_cast<uint64_t>(LoadUnaligned<uint32_t>(local.buffer.data())),
                               static_cast<uint64_t>(static_cast<uint32_t>(all_target.unsigned_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 8 &&
                match_unsigned(LoadUnaligned<uint64_t>(local.buffer.data()), all_target.unsigned_value)) {
              match = true;
            }
          }
          if (!match && all_target.has_signed) {
            if (remain >= 4 &&
                match_signed(static_cast<int64_t>(LoadUnaligned<int32_t>(local.buffer.data())),
                             static_cast<int64_t>(static_cast<int32_t>(all_target.signed_value)))) {
              match = true;
            }
            if (!match &&
                remain >= 8 &&
                match_signed(LoadUnaligned<int64_t>(local.buffer.data()), all_target.signed_value)) {
              match = true;
            }
          }
          if (!match && all_target.has_float) {
            if (remain >= 4 &&
                match_float(static_cast<double>(LoadUnaligned<float>(local.buffer.data())),
                            all_target.float_value)) {
              match = true;
            }
            if (!match && remain >= 8 &&
                match_float(LoadUnaligned<double>(local.buffer.data()), all_target.float_value)) {
              match = true;
            }
          }
          const size_t take = std::min<size_t>(remain, sizeof(uint64_t));
          if (take > 0) {
            std::memcpy(&actual_bits, local.buffer.data(), take);
          }
        } else {
          if (!ReadValue(addr, type, &actual_bits, &actual_fp)) {
            if (strict_) {
              failed.store(true, std::memory_order_relaxed);
              stop.store(true, std::memory_order_relaxed);
              return;
            }
            continue;
          }
          if (condition == protocol::ComparisonType::CHANGED) {
            match = (actual_bits != prev_bits);
          } else if (condition == protocol::ComparisonType::UNCHANGED) {
            match = (actual_bits == prev_bits);
          } else if (type == protocol::ValueType::FLOAT || type == protocol::ValueType::DOUBLE) {
            match = CompareFloat(actual_fp, target_fp, condition);
          } else if (type == protocol::ValueType::S32 || type == protocol::ValueType::S64) {
            match = CompareIntegerSigned(BitsToSigned(type, actual_bits), target_signed, condition);
          } else {
            match = CompareInteger(actual_bits, target_bits, condition);
          }
        }

        if (!match) {
          continue;
        }
        const size_t prev = total_matches.fetch_add(1, std::memory_order_relaxed);
        if (prev >= kMaxScanResults) {
          stop.store(true, std::memory_order_relaxed);
          return;
        }
        local.matches.push_back({i, addr, actual_bits});
      }
    }
  };

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (unsigned i = 0; i < thread_count; ++i) {
    threads.emplace_back(worker, i);
  }
  for (auto& t : threads) {
    t.join();
  }

  if (failed.load(std::memory_order_relaxed) || total_matches.load(std::memory_order_relaxed) > kMaxScanResults) {
    return false;
  }

  std::vector<NextMatch> merged;
  merged.reserve(total_matches.load(std::memory_order_relaxed));
  for (auto& local : locals) {
    merged.insert(merged.end(), local.matches.begin(), local.matches.end());
  }
  std::sort(merged.begin(), merged.end(), [](const NextMatch& a, const NextMatch& b) {
    return a.index < b.index;
  });

  std::vector<uint64_t> new_results;
  std::vector<uint64_t> new_values;
  new_results.reserve(merged.size());
  new_values.reserve(merged.size());
  for (const auto& item : merged) {
    new_results.push_back(item.addr);
    new_values.push_back(item.value);
  }

  results_.swap(new_results);
  last_values_.swap(new_values);
  return true;
}
