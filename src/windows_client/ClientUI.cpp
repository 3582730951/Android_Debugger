#include "ClientUI.h"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <unordered_map>

#include <imgui.h>
#include <windows.h>
#include <commdlg.h>
#include <capstone/capstone.h>
#ifdef R3_HAVE_SVG_ATLAS
#include "IconAtlasMeta.h"
#endif

namespace {
const char* kScanTypeNames[] = {
  u8"byte型",
  u8"word型",
  u8"int型",
  u8"uint型",
  u8"long型",
  u8"ulong型",
  u8"float",
  u8"double",
};

std::filesystem::path GetExeDir() {
  std::wstring buf;
  buf.resize(32768);
  const DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
  if (len == 0 || len >= buf.size()) {
    return std::filesystem::current_path();
  }
  buf.resize(len);
  return std::filesystem::path(buf).parent_path();
}

const protocol::ValueType kScanTypeMap[] = {
  protocol::ValueType::U8,
  protocol::ValueType::U16,
  protocol::ValueType::S32,
  protocol::ValueType::U32,
  protocol::ValueType::S64,
  protocol::ValueType::U64,
  protocol::ValueType::FLOAT,
  protocol::ValueType::DOUBLE,
};

const char* kCondNames[] = {
  u8"等于",
  u8"不等于",
  u8"大于",
  u8"小于",
  u8"大于等于",
  u8"小于等于",
  u8"已变化",
  u8"未变化",
};

const char* kRWTypeNames[] = {
  u8"int(32位)",
  u8"float",
  u8"double",
  u8"byte(8位)",
  u8"word(16位)",
  u8"汇编(机器码)",
  u8"hex",
  u8"UTF-8",
  u8"UTF-16",
};

const char* kModuleCategoryNames[] = {
  u8"全部",
  u8"代码(Code)",
  u8"代码-应用",
  u8"代码-系统",
  u8"C数据(Data)",
  u8"BSS/匿名",
  u8"堆(Heap)",
  u8"栈(Stack)",
  u8"Java",
  u8"Java堆",
  u8"JIT",
  u8"Ashmem",
  u8"Dex/Oat/Vdex",
  u8"设备(/dev)",
  u8"共享(Shared)",
  u8"库(.so)",
  u8"系统",
  u8"匿名(A)",
  u8"其他"
};

const char* kTraverseTypeNames[] = {
  u8"U8",
  u8"U16",
  u8"U32",
  u8"U64",
  u8"FLOAT",
  u8"DOUBLE"
};

const char* kDataTraverseTypeNames[] = {
  u8"U8",
  u8"U16",
  u8"U32",
  u8"U64",
  u8"FLOAT",
  u8"DOUBLE",
  u8"指针(PTR)"
};

constexpr int kDataTraversePointerIndex = 6;

const char* kBreakpointTypeNames[] = {
  u8"执行",
  u8"写入",
  u8"读取",
  u8"读写"
};

const char* kBreakpointBackendNames[] = {
  u8"ptrace",
  u8"perf"
};

struct ModuleProps {
  bool exec = false;
  bool rw = false;
  bool anon = false;
  bool heap = false;
  bool stack = false;
  bool java = false;
  bool java_heap = false;
  bool jit = false;
  bool ashmem = false;
  bool system = false;
  bool so = false;
  bool app = false;
  bool shared = false;
  bool cdata = false;
  bool dex = false;
  bool oat = false;
  bool vdex = false;
  bool art = false;
  bool apk = false;
  bool dev = false;
  bool guard = false;
  bool file = false;
};

bool StartsWith(const std::string& s, const char* prefix) {
  return s.rfind(prefix, 0) == 0;
}

bool EndsWith(const std::string& s, const char* suffix) {
  if (!suffix) {
    return false;
  }
  const size_t len = std::strlen(suffix);
  if (s.size() < len) {
    return false;
  }
  return s.compare(s.size() - len, len, suffix) == 0;
}

bool ContainsCI(const std::string& s, const char* needle) {
  if (!needle) {
    return false;
  }
  std::string hay = s;
  std::string nd = needle;
  for (char& c : hay) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (char& c : nd) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return hay.find(nd) != std::string::npos;
}

bool ContainsCI(const std::string& s, const std::string& needle) {
  if (needle.empty()) {
    return false;
  }
  std::string hay = s;
  std::string nd = needle;
  for (char& c : hay) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (char& c : nd) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return hay.find(nd) != std::string::npos;
}

ModuleProps GetModuleProps(const ClientState::ModuleInfo& mod) {
  ModuleProps props;
  const std::string& path = mod.path;
  const bool has_path = !path.empty();
  const bool bracket = has_path && path[0] == '[';

  props.exec = (mod.perms & protocol::MODULE_PERM_EXEC) != 0;
  props.rw = (mod.perms & protocol::MODULE_PERM_READ) && (mod.perms & protocol::MODULE_PERM_WRITE);
  props.shared = (mod.perms & protocol::MODULE_PERM_SHARED) != 0;
  props.dev = StartsWith(path, "/dev");
  props.system = StartsWith(path, "/system") || StartsWith(path, "/apex") ||
                 StartsWith(path, "/vendor") || StartsWith(path, "/product") ||
                 StartsWith(path, "/odm") || StartsWith(path, "/system_ext");
  props.app = StartsWith(path, "/data/app") || StartsWith(path, "/data/user") ||
              StartsWith(path, "/data/data") || StartsWith(path, "/mnt/asec");
  props.so = EndsWith(path, ".so");
  props.apk = EndsWith(path, ".apk") || ContainsCI(path, ".apk");
  props.dex = EndsWith(path, ".dex") || ContainsCI(path, ".dex");
  props.oat = EndsWith(path, ".oat") || ContainsCI(path, ".oat");
  props.vdex = EndsWith(path, ".vdex") || ContainsCI(path, ".vdex");
  props.art = EndsWith(path, ".art") || ContainsCI(path, "boot.art");

  props.anon = !has_path || bracket || ContainsCI(path, "anon");
  props.heap = ContainsCI(path, "[heap]") || ContainsCI(path, "libc_malloc") ||
               ContainsCI(path, "scudo") || ContainsCI(path, "malloc");
  props.stack = ContainsCI(path, "[stack") || ContainsCI(path, "stack:");
  props.guard = ContainsCI(path, "guard");

  props.java_heap = ContainsCI(path, "dalvik-heap") || ContainsCI(path, "dalvik main") ||
                    ContainsCI(path, "zygote space") || ContainsCI(path, "alloc space") ||
                    ContainsCI(path, "large object") || ContainsCI(path, "main space");
  props.jit = ContainsCI(path, "jit-cache") || ContainsCI(path, "jit") || ContainsCI(path, "jit-zygote");
  props.java = ContainsCI(path, "dalvik") || ContainsCI(path, "art") || ContainsCI(path, "oat") ||
               ContainsCI(path, "vdex") || ContainsCI(path, "dex");
  props.ashmem = ContainsCI(path, "ashmem") || ContainsCI(path, "memfd");

  props.cdata = props.rw && !props.exec && !props.anon &&
                (props.so || props.apk || props.dex || props.oat || props.vdex || props.art);

  props.file = has_path && !bracket && !props.dev;
  return props;
}

struct GGSegment {
  const char* code = "";
  const char* name = "";
};

GGSegment ModuleGGSegment(const ClientState::ModuleInfo& mod) {
  const ModuleProps props = GetModuleProps(mod);
  const bool readable = (mod.perms & protocol::MODULE_PERM_READ) != 0;
  const std::string& path = mod.path;
  if (!readable) return {"B", "Bad"};
  if (ContainsCI(path, "ppsspp")) return {"PS", "PPSSPP"};
  if (props.java_heap) return {"Jh", "Java heap"};
  if (props.heap) return {"Ch", "C++ heap"};
  if (props.cdata) return {"Cd", "C++ .data"};
  if (ContainsCI(path, "alloc")) return {"Ca", "C++ alloc"};
  if (props.anon && props.rw && !props.exec && !props.file) return {"Cb", "C++ .bss"};
  if (props.java) return {"J", "Java"};
  if (props.stack) return {"S", "Stack"};
  if (props.ashmem) return {"As", "Ashmem"};
  if (props.exec && props.app) return {"Xa", "Code app"};
  if (props.exec && props.system) return {"Xs", "Code system"};
  if (props.dev &&
      (ContainsCI(path, "video") || ContainsCI(path, "kgsl") ||
       ContainsCI(path, "gpu") || ContainsCI(path, "graphics"))) {
    return {"V", "Video"};
  }
  if (props.anon) return {"A", "Anonymous"};
  return {"O", "Other"};
}

std::string ModuleGGLabel(const ClientState::ModuleInfo& mod) {
  const GGSegment seg = ModuleGGSegment(mod);
  if (seg.code[0] == '\0') {
    return "";
  }
  std::string label = seg.code;
  label.append(": ");
  label.append(seg.name);
  return label;
}

struct PointerFileHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t pointer_size;
  uint32_t depth;
  uint32_t reserved;
  uint64_t target;
  uint64_t count;
  int64_t max_offset;
  uint64_t flags;
};

struct PointerChain {
  uint64_t base = 0;
  std::vector<int64_t> offsets;
};

constexpr uint32_t kPointerMagic = 0x53503352u; // 'R3PS'
constexpr uint16_t kPointerVersion = 1;
constexpr uint64_t kPointerFlagDeltaVarint = 1u;
constexpr uint64_t kPointerFlagMultiTarget = 1u << 1;
constexpr size_t kPointerChunkSize = 256 * 1024;
constexpr size_t kPointerNodeLimit = 5'000'000;
constexpr size_t kPointerIndexLimit = 20'000'000;
constexpr size_t kPointerScanMaxTargets = 2000;

constexpr uint32_t kPointerIndexMagic = 0x49503352u; // 'R3PI'
constexpr uint16_t kPointerIndexVersion = 1;
constexpr uint64_t kPointerIndexFlagDeltaVarint = 1u;
constexpr uint64_t kPointerIndexFlagByteStep = 1u << 1;
constexpr uint64_t kPointerIndexFlagStrict = 1u << 2;
constexpr uint32_t kPointerPreviewIndexMagic = 0x49565052u; // 'RPVI'
constexpr uint16_t kPointerPreviewIndexVersion = 1;

struct PointerIndexHeader {
  uint32_t magic = 0;
  uint16_t version = 0;
  uint16_t pointer_size = 0;
  uint32_t pid = 0;
  uint32_t reserved = 0;
  uint64_t count = 0;
  uint64_t flags = 0;
};

struct PointerPreviewIndexHeader {
  uint32_t magic = 0;
  uint16_t version = 0;
  uint16_t reserved = 0;
  uint32_t depth = 0;
  uint32_t reserved2 = 0;
  uint64_t pointer_count = 0;
  uint64_t pointer_file_size = 0;
  int64_t pointer_file_mtime = 0;
  uint64_t stride = 0;
  uint64_t checkpoint_count = 0;
};

struct PointerPreviewIndexEntry {
  uint64_t chain_index = 0;
  uint64_t file_offset = 0;
  uint64_t prev_base = 0;
};

struct BenchIoStats {
  std::atomic<uint64_t> connect_calls{0};
  std::atomic<uint64_t> attach_calls{0};
  std::atomic<uint64_t> net_packets{0};
  std::atomic<uint64_t> net_req_bytes{0};
  std::atomic<uint64_t> net_rsp_bytes{0};
  std::atomic<uint64_t> read_calls{0};
  std::atomic<uint64_t> read_bytes{0};
  std::atomic<uint64_t> chunk_samples{0};
};

BenchIoStats* g_bench_io_stats = nullptr;

void BenchTrackConnect() {
  if (g_bench_io_stats) {
    g_bench_io_stats->connect_calls.fetch_add(1, std::memory_order_relaxed);
  }
}

void BenchTrackAttach() {
  if (g_bench_io_stats) {
    g_bench_io_stats->attach_calls.fetch_add(1, std::memory_order_relaxed);
  }
}

void BenchTrackPacket(size_t req_bytes, size_t rsp_bytes) {
  if (!g_bench_io_stats) {
    return;
  }
  g_bench_io_stats->net_packets.fetch_add(1, std::memory_order_relaxed);
  g_bench_io_stats->net_req_bytes.fetch_add(static_cast<uint64_t>(req_bytes), std::memory_order_relaxed);
  g_bench_io_stats->net_rsp_bytes.fetch_add(static_cast<uint64_t>(rsp_bytes), std::memory_order_relaxed);
}

void BenchTrackRead(size_t read_bytes, size_t chunk_bytes) {
  if (!g_bench_io_stats) {
    return;
  }
  g_bench_io_stats->read_calls.fetch_add(1, std::memory_order_relaxed);
  g_bench_io_stats->read_bytes.fetch_add(static_cast<uint64_t>(read_bytes), std::memory_order_relaxed);
  g_bench_io_stats->chunk_samples.fetch_add(static_cast<uint64_t>(chunk_bytes), std::memory_order_relaxed);
}

uint64_t StripTag64(uint64_t value) {
  return value & 0x00FFFFFFFFFFFFFFull;
}

void WriteVarUint(std::vector<uint8_t>* out, uint64_t value) {
  while (value >= 0x80) {
    out->push_back(static_cast<uint8_t>(value) | 0x80);
    value >>= 7;
  }
  out->push_back(static_cast<uint8_t>(value));
}

void WriteVarInt(std::vector<uint8_t>* out, int64_t value) {
  uint64_t zigzag = (static_cast<uint64_t>(value) << 1) ^ static_cast<uint64_t>(value >> 63);
  WriteVarUint(out, zigzag);
}

bool ReadVarUint(std::istream& in, uint64_t* value) {
  uint64_t result = 0;
  int shift = 0;
  for (int i = 0; i < 10; ++i) {
    const int byte = in.get();
    if (byte == EOF) {
      return false;
    }
    result |= (static_cast<uint64_t>(byte & 0x7F) << shift);
    if ((byte & 0x80) == 0) {
      if (value) {
        *value = result;
      }
      return true;
    }
    shift += 7;
  }
  return false;
}

bool ReadVarInt(std::istream& in, int64_t* value) {
  uint64_t zigzag = 0;
  if (!ReadVarUint(in, &zigzag)) {
    return false;
  }
  if (value) {
    *value = static_cast<int64_t>((zigzag >> 1) ^ (static_cast<uint64_t>(-static_cast<int64_t>(zigzag & 1))));
  }
  return true;
}

std::string MakeChainKey(uint64_t base, const std::vector<int64_t>& offsets) {
  std::string key;
  key.resize(sizeof(uint64_t) + offsets.size() * sizeof(int64_t));
  std::memcpy(&key[0], &base, sizeof(uint64_t));
  if (!offsets.empty()) {
    std::memcpy(&key[sizeof(uint64_t)], offsets.data(), offsets.size() * sizeof(int64_t));
  }
  return key;
}

uint64_t HashChain(uint64_t base, const std::vector<int64_t>& offsets) {
  constexpr uint64_t kFNVOffset = 1469598103934665603ull;
  constexpr uint64_t kFNVPrime = 1099511628211ull;
  uint64_t hash = kFNVOffset;
  auto mix = [&](const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
      hash ^= bytes[i];
      hash *= kFNVPrime;
    }
  };
  mix(&base, sizeof(base));
  if (!offsets.empty()) {
    mix(offsets.data(), offsets.size() * sizeof(int64_t));
  }
  return hash;
}

bool ChainEqual(const PointerChain& a, const PointerChain& b) {
  return a.base == b.base && a.offsets == b.offsets;
}

std::streamoff PointerFileDataOffset(const PointerFileHeader& hdr) {
  if ((hdr.flags & kPointerFlagMultiTarget) != 0 && hdr.reserved > 0) {
    return static_cast<std::streamoff>(sizeof(PointerFileHeader)) +
           static_cast<std::streamoff>(hdr.reserved) * static_cast<std::streamoff>(sizeof(uint64_t));
  }
  return static_cast<std::streamoff>(sizeof(PointerFileHeader));
}

uint64_t HashModuleMask(const std::vector<bool>& mask) {
  uint64_t hash = 1469598103934665603ull;
  for (bool bit : mask) {
    hash ^= static_cast<uint8_t>(bit ? 1 : 0);
    hash *= 1099511628211ull;
  }
  return hash;
}

bool ReadPointerTargets(std::istream& in,
                        const PointerFileHeader& hdr,
                        std::vector<uint64_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  if ((hdr.flags & kPointerFlagMultiTarget) == 0 || hdr.reserved == 0) {
    out->push_back(hdr.target);
    return true;
  }
  for (uint32_t i = 0; i < hdr.reserved; ++i) {
    uint64_t value = 0;
    in.read(reinterpret_cast<char*>(&value), sizeof(value));
    if (in.gcount() != static_cast<std::streamsize>(sizeof(value))) {
      return false;
    }
    out->push_back(value);
  }
  if (out->empty()) {
    out->push_back(hdr.target);
  }
  return true;
}

bool LoadFirstPointerChainFromFile(const std::string& path,
                                   PointerFileHeader* out_hdr,
                                   PointerChain* out_chain,
                                   std::string* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (!out_chain || !out_hdr) {
    if (out_error) {
      *out_error = u8"参数无效";
    }
    return false;
  }
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    if (out_error) {
      *out_error = u8"无法打开指针文件";
    }
    return false;
  }
  PointerFileHeader hdr{};
  ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(hdr)) ||
      hdr.magic != kPointerMagic || hdr.version != kPointerVersion) {
    if (out_error) {
      *out_error = u8"指针文件格式错误";
    }
    return false;
  }
  std::vector<uint64_t> targets;
  if (!ReadPointerTargets(ifs, hdr, &targets)) {
    if (out_error) {
      *out_error = u8"读取目标列表失败";
    }
    return false;
  }
  uint64_t delta = 0;
  if (!ReadVarUint(ifs, &delta)) {
    if (out_error) {
      *out_error = u8"指针文件为空";
    }
    return false;
  }
  out_chain->base = delta;
  out_chain->offsets.clear();
  out_chain->offsets.resize(hdr.depth);
  for (uint32_t d = 0; d < hdr.depth; ++d) {
    int64_t off = 0;
    if (!ReadVarInt(ifs, &off)) {
      if (out_error) {
        *out_error = u8"读取指针链失败";
      }
      return false;
    }
    out_chain->offsets[d] = off;
  }
  *out_hdr = hdr;
  return true;
}

std::string Hex64(uint64_t value);
bool ParseValueForType(protocol::ValueType type, const char* text, std::vector<uint8_t>* out, bool hex);

std::string FormatTargetLabel(const std::vector<uint64_t>& targets) {
  if (targets.empty()) {
    return "0x0";
  }
  if (targets.size() == 1) {
    return Hex64(targets[0]);
  }
  if (targets.size() <= 4) {
    std::string out;
    for (size_t i = 0; i < targets.size(); ++i) {
      if (i > 0) out.append(",");
      out.append(Hex64(targets[i]));
    }
    return out;
  }
  return std::string("multi(") + std::to_string(targets.size()) + ")";
}

bool SavePointerIndexFile(const std::string& path,
                          uint32_t pointer_size,
                          uint32_t pid,
                          uint64_t flags,
                          std::vector<std::pair<uint64_t, uint64_t>> entries,
                          std::string* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (path.empty()) {
    if (out_error) {
      *out_error = u8"索引路径为空";
    }
    return false;
  }
  const auto dir = std::filesystem::path(path).parent_path();
  if (!dir.empty()) {
    std::filesystem::create_directories(dir);
  }
  std::ofstream ofs(path, std::ios::binary);
  if (!ofs.is_open()) {
    if (out_error) {
      *out_error = u8"无法写入索引文件";
    }
    return false;
  }
  std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) {
      return a.first < b.first;
    }
    return a.second < b.second;
  });

  PointerIndexHeader hdr{};
  hdr.magic = kPointerIndexMagic;
  hdr.version = kPointerIndexVersion;
  hdr.pointer_size = static_cast<uint16_t>(pointer_size);
  hdr.pid = pid;
  hdr.count = static_cast<uint64_t>(entries.size());
  hdr.flags = kPointerIndexFlagDeltaVarint | flags;
  ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

  uint64_t buffer_prev_value = 0;
  uint64_t buffer_prev_addr = 0;
  std::vector<uint8_t> buffer;
  buffer.reserve(64 * 1024);
  for (const auto& entry : entries) {
    const uint64_t value = entry.first;
    const uint64_t addr = entry.second;
    WriteVarUint(&buffer, value - buffer_prev_value);
    WriteVarUint(&buffer, addr - buffer_prev_addr);
    buffer_prev_value = value;
    buffer_prev_addr = addr;
    if (buffer.size() > 64 * 1024) {
      ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
      buffer.clear();
    }
  }
  if (!buffer.empty()) {
    ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  }
  return true;
}

bool LoadPointerIndexFile(const std::string& path,
                          uint32_t* out_pointer_size,
                          uint32_t* out_pid,
                          uint64_t* out_flags,
                          std::vector<std::pair<uint64_t, uint64_t>>* out_entries,
                          std::string* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (!out_entries || !out_pointer_size || !out_pid || !out_flags) {
    if (out_error) {
      *out_error = u8"索引参数无效";
    }
    return false;
  }
  out_entries->clear();
  if (path.empty()) {
    if (out_error) {
      *out_error = u8"索引路径为空";
    }
    return false;
  }
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    if (out_error) {
      *out_error = u8"无法打开索引文件";
    }
    return false;
  }
  PointerIndexHeader hdr{};
  ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(hdr)) ||
      hdr.magic != kPointerIndexMagic || hdr.version != kPointerIndexVersion) {
    if (out_error) {
      *out_error = u8"索引文件格式错误";
    }
    return false;
  }
  if ((hdr.flags & kPointerIndexFlagDeltaVarint) == 0) {
    if (out_error) {
      *out_error = u8"索引文件不支持";
    }
    return false;
  }
  *out_pointer_size = hdr.pointer_size;
  *out_pid = hdr.pid;
  *out_flags = hdr.flags;
  out_entries->reserve(static_cast<size_t>(hdr.count));

  uint64_t prev_value = 0;
  uint64_t prev_addr = 0;
  for (uint64_t i = 0; i < hdr.count; ++i) {
    uint64_t delta_value = 0;
    uint64_t delta_addr = 0;
    if (!ReadVarUint(ifs, &delta_value) || !ReadVarUint(ifs, &delta_addr)) {
      if (out_error) {
        *out_error = u8"索引文件读取失败";
      }
      return false;
    }
    const uint64_t value = prev_value + delta_value;
    const uint64_t addr = prev_addr + delta_addr;
    prev_value = value;
    prev_addr = addr;
    out_entries->push_back({value, addr});
  }
  return true;
}

uint64_t FileSizeSafe(const std::string& path) {
  std::error_code ec;
  const uint64_t size = std::filesystem::exists(path, ec) ? std::filesystem::file_size(path, ec) : 0;
  if (ec) {
    return 0;
  }
  return size;
}

int64_t FileMtimeSafe(const std::string& path) {
  std::error_code ec;
  const auto ts = std::filesystem::last_write_time(path, ec);
  if (ec) {
    return 0;
  }
  return static_cast<int64_t>(ts.time_since_epoch().count());
}

struct PointerOperationMeta {
  bool valid = false;
  std::string op;
  uint64_t snapshot_id = 0;
  uint64_t maps_hash = 0;
  uint64_t region_count = 0;
  uint64_t region_bytes = 0;
  uint64_t read_fail_pages = 0;
  uint64_t pointer_candidates = 0;
  uint64_t final_count = 0;
};

uint64_t NextSnapshotId() {
  static std::atomic<uint64_t> g_snapshot_id{1};
  return g_snapshot_id.fetch_add(1, std::memory_order_relaxed);
}

uint64_t ComputeModuleSnapshotHash(const std::vector<ClientState::ModuleInfo>& modules,
                                   const std::vector<bool>* module_mask,
                                   bool use_mask,
                                   uint64_t* out_region_count,
                                   uint64_t* out_region_bytes) {
  constexpr uint64_t kFNVOffset = 1469598103934665603ull;
  constexpr uint64_t kFNVPrime = 1099511628211ull;
  uint64_t hash = kFNVOffset;
  uint64_t region_count = 0;
  uint64_t region_bytes = 0;
  auto mix = [&](const void* data, size_t size) {
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
      hash ^= p[i];
      hash *= kFNVPrime;
    }
  };
  for (size_t i = 0; i < modules.size(); ++i) {
    const auto& mod = modules[i];
    if ((mod.perms & protocol::MODULE_PERM_READ) == 0 || mod.end <= mod.start) {
      continue;
    }
    if (use_mask && module_mask) {
      if (i >= module_mask->size() || !(*module_mask)[i]) {
        continue;
      }
    }
    region_count++;
    region_bytes += (mod.end - mod.start);
    mix(&mod.start, sizeof(mod.start));
    mix(&mod.end, sizeof(mod.end));
    mix(&mod.perms, sizeof(mod.perms));
    const uint32_t path_len = static_cast<uint32_t>(mod.path.size());
    mix(&path_len, sizeof(path_len));
    if (!mod.path.empty()) {
      mix(mod.path.data(), mod.path.size());
    }
  }
  if (out_region_count) {
    *out_region_count = region_count;
  }
  if (out_region_bytes) {
    *out_region_bytes = region_bytes;
  }
  mix(&region_count, sizeof(region_count));
  mix(&region_bytes, sizeof(region_bytes));
  return hash;
}

std::string PointerMetaPath(const std::string& pointer_path) {
  return pointer_path + ".meta";
}

bool WritePointerOperationMeta(const std::string& pointer_path,
                               const PointerOperationMeta& meta) {
  const std::string meta_path = PointerMetaPath(pointer_path);
  std::ofstream ofs(meta_path, std::ios::binary);
  if (!ofs.is_open()) {
    return false;
  }
  ofs << "op=" << meta.op << "\n";
  ofs << "snapshot_id=" << meta.snapshot_id << "\n";
  ofs << "maps_hash=" << meta.maps_hash << "\n";
  ofs << "region_count=" << meta.region_count << "\n";
  ofs << "region_bytes=" << meta.region_bytes << "\n";
  ofs << "read_fail_pages=" << meta.read_fail_pages << "\n";
  ofs << "pointer_candidates=" << meta.pointer_candidates << "\n";
  ofs << "final_count=" << meta.final_count << "\n";
  return ofs.good();
}

bool ReadPointerOperationMeta(const std::string& pointer_path,
                              PointerOperationMeta* out_meta) {
  if (!out_meta) {
    return false;
  }
  *out_meta = PointerOperationMeta{};
  const std::string meta_path = PointerMetaPath(pointer_path);
  std::ifstream ifs(meta_path, std::ios::binary);
  if (!ifs.is_open()) {
    return false;
  }

  auto parse_u64 = [](const std::string& text, uint64_t* out) -> bool {
    if (!out) {
      return false;
    }
    if (text.empty()) {
      *out = 0;
      return true;
    }
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0') {
      return false;
    }
    *out = static_cast<uint64_t>(value);
    return true;
  };

  std::string line;
  while (std::getline(ifs, line)) {
    const size_t eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string key = line.substr(0, eq);
    const std::string value = line.substr(eq + 1);
    if (key == "op") {
      out_meta->op = value;
    } else if (key == "snapshot_id") {
      parse_u64(value, &out_meta->snapshot_id);
    } else if (key == "maps_hash") {
      parse_u64(value, &out_meta->maps_hash);
    } else if (key == "region_count") {
      parse_u64(value, &out_meta->region_count);
    } else if (key == "region_bytes") {
      parse_u64(value, &out_meta->region_bytes);
    } else if (key == "read_fail_pages") {
      parse_u64(value, &out_meta->read_fail_pages);
    } else if (key == "pointer_candidates") {
      parse_u64(value, &out_meta->pointer_candidates);
    } else if (key == "final_count") {
      parse_u64(value, &out_meta->final_count);
    }
  }
  out_meta->valid = true;
  return true;
}

bool SavePointerPreviewIndex(const std::string& path,
                             const PointerPreviewIndexHeader& header,
                             const std::vector<PointerPreviewIndexEntry>& entries) {
  const auto dir = std::filesystem::path(path).parent_path();
  if (!dir.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
  }
  std::ofstream ofs(path, std::ios::binary);
  if (!ofs.is_open()) {
    return false;
  }
  ofs.write(reinterpret_cast<const char*>(&header), sizeof(header));
  if (!entries.empty()) {
    ofs.write(reinterpret_cast<const char*>(entries.data()),
              static_cast<std::streamsize>(entries.size() * sizeof(PointerPreviewIndexEntry)));
  }
  return ofs.good();
}

bool LoadPointerPreviewIndex(const std::string& path,
                             const PointerPreviewIndexHeader& expected,
                             std::vector<PointerPreviewIndexEntry>* out_entries) {
  if (!out_entries) {
    return false;
  }
  out_entries->clear();
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return false;
  }
  PointerPreviewIndexHeader hdr{};
  ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(hdr))) {
    return false;
  }
  if (hdr.magic != kPointerPreviewIndexMagic || hdr.version != kPointerPreviewIndexVersion) {
    return false;
  }
  if (hdr.depth != expected.depth ||
      hdr.pointer_count != expected.pointer_count ||
      hdr.pointer_file_size != expected.pointer_file_size ||
      hdr.pointer_file_mtime != expected.pointer_file_mtime ||
      hdr.stride == 0) {
    return false;
  }
  out_entries->resize(static_cast<size_t>(hdr.checkpoint_count));
  if (!out_entries->empty()) {
    ifs.read(reinterpret_cast<char*>(out_entries->data()),
             static_cast<std::streamsize>(out_entries->size() * sizeof(PointerPreviewIndexEntry)));
    if (ifs.gcount() != static_cast<std::streamsize>(out_entries->size() * sizeof(PointerPreviewIndexEntry))) {
      out_entries->clear();
      return false;
    }
  }
  return true;
}

bool BuildPointerPreviewIndex(const std::string& pointer_path,
                              const PointerFileHeader& hdr,
                              uint64_t stride,
                              std::vector<PointerPreviewIndexEntry>* out_entries,
                              std::string* out_error) {
  if (!out_entries) {
    if (out_error) {
      *out_error = u8"预览索引参数无效";
    }
    return false;
  }
  out_entries->clear();
  if (stride == 0) {
    stride = 512;
  }

  std::ifstream ifs(pointer_path, std::ios::binary);
  if (!ifs.is_open()) {
    if (out_error) {
      *out_error = u8"无法打开指针文件";
    }
    return false;
  }
  PointerFileHeader file_hdr{};
  ifs.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(file_hdr)) ||
      file_hdr.magic != kPointerMagic || file_hdr.version != kPointerVersion) {
    if (out_error) {
      *out_error = u8"指针文件格式错误";
    }
    return false;
  }
  std::vector<uint64_t> targets;
  if (!ReadPointerTargets(ifs, file_hdr, &targets)) {
    if (out_error) {
      *out_error = u8"读取目标列表失败";
    }
    return false;
  }

  const std::streamoff data_offset = PointerFileDataOffset(file_hdr);
  ifs.seekg(data_offset, std::ios::beg);
  if (!ifs.good()) {
    if (out_error) {
      *out_error = u8"读取数据偏移失败";
    }
    return false;
  }

  uint64_t prev_base = 0;
  uint64_t index = 0;
  out_entries->push_back({0, static_cast<uint64_t>(data_offset), 0});
  const uint64_t total = file_hdr.count;
  while (total == 0 || index < total) {
    uint64_t delta = 0;
    if (!ReadVarUint(ifs, &delta)) {
      break;
    }
    const uint64_t base = prev_base + delta;
    prev_base = base;
    for (uint32_t d = 0; d < file_hdr.depth; ++d) {
      int64_t off = 0;
      if (!ReadVarInt(ifs, &off)) {
        if (out_error) {
          *out_error = u8"构建预览索引失败";
        }
        out_entries->clear();
        return false;
      }
    }
    index++;
    if ((index % stride) == 0) {
      std::streamoff next_offset = ifs.tellg();
      if (next_offset >= 0) {
        out_entries->push_back({index, static_cast<uint64_t>(next_offset), prev_base});
      }
    }
  }
  return true;
}

std::string NowTimeString() {
  using std::chrono::system_clock;
  const auto now = system_clock::now();
  std::time_t tt = system_clock::to_time_t(now);
  std::tm tm{};
  localtime_s(&tm, &tt);
  char buf[32] = {0};
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

uint64_t NowMs() {
  using std::chrono::steady_clock;
  using std::chrono::duration_cast;
  using std::chrono::milliseconds;
  return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

std::string Hex64(uint64_t value) {
  char buf[32] = {0};
  std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
  return buf;
}

size_t ValueTypeSize(protocol::ValueType type) {
  switch (type) {
    case protocol::ValueType::U8: return 1;
    case protocol::ValueType::U16: return 2;
    case protocol::ValueType::U32: return 4;
    case protocol::ValueType::U64: return 8;
    case protocol::ValueType::S32: return 4;
    case protocol::ValueType::S64: return 8;
    case protocol::ValueType::FLOAT: return 4;
    case protocol::ValueType::DOUBLE: return 8;
    default: return 4;
  }
}

int ValueTypeToIndex(protocol::ValueType type) {
  for (int i = 0; i < IM_ARRAYSIZE(kScanTypeMap); ++i) {
    if (kScanTypeMap[i] == type) {
      return i;
    }
  }
  return 0;
}

std::string FormatValueText(protocol::ValueType type, const uint8_t* data, size_t size) {
  if (!data) {
    return u8"<读取失败>";
  }
  const size_t need = ValueTypeSize(type);
  if (size < need) {
    return u8"<读取失败>";
  }
  char buf[128] = {0};
  switch (type) {
    case protocol::ValueType::U8: {
      uint8_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%u (0x%02X)", v, v);
      break;
    }
    case protocol::ValueType::U16: {
      uint16_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%u (0x%04X)", v, v);
      break;
    }
    case protocol::ValueType::U32: {
      uint32_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%u (0x%08X)", v, v);
      break;
    }
    case protocol::ValueType::U64: {
      uint64_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%llu (0x%016llX)",
                    static_cast<unsigned long long>(v),
                    static_cast<unsigned long long>(v));
      break;
    }
    case protocol::ValueType::S32: {
      int32_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%d (0x%08X)", v, static_cast<uint32_t>(v));
      break;
    }
    case protocol::ValueType::S64: {
      int64_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%lld (0x%016llX)",
                    static_cast<long long>(v),
                    static_cast<unsigned long long>(v));
      break;
    }
    case protocol::ValueType::FLOAT: {
      float v = 0.0f;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%.6f", static_cast<double>(v));
      break;
    }
    case protocol::ValueType::DOUBLE: {
      double v = 0.0;
      std::memcpy(&v, data, sizeof(v));
      std::snprintf(buf, sizeof(buf), "%.6f", v);
      break;
    }
    default:
      std::snprintf(buf, sizeof(buf), "?");
      break;
  }
  return buf[0] ? std::string(buf) : std::string(u8"<读取失败>");
}

bool LooksHexNumber(const char* text) {
  if (!text) {
    return false;
  }
  while (std::isspace(static_cast<unsigned char>(*text))) {
    ++text;
  }
  if (*text == '\0') {
    return false;
  }
  if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    return true;
  }
  for (const char* p = text; *p; ++p) {
    if (*p == '-' || *p == '+') {
      continue;
    }
    if (*p == '.' || *p == 'e' || *p == 'E') {
      return false;
    }
    if (!std::isxdigit(static_cast<unsigned char>(*p))) {
      return false;
    }
  }
  return true;
}

std::string FormatHexValue(uint64_t value, size_t bytes) {
  char buf[32] = {0};
  switch (bytes) {
    case 1:
      std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(value & 0xFFu));
      break;
    case 2:
      std::snprintf(buf, sizeof(buf), "%04X", static_cast<unsigned>(value & 0xFFFFu));
      break;
    case 4:
      std::snprintf(buf, sizeof(buf), "%08X", static_cast<unsigned>(value & 0xFFFFFFFFu));
      break;
    default:
      std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(value));
      break;
  }
  return buf;
}

std::string FormatValueTextMode(protocol::ValueType type,
                                const uint8_t* data,
                                size_t size,
                                bool hex) {
  if (!hex) {
    return FormatValueText(type, data, size);
  }
  if (!data) {
    return u8"<读取失败>";
  }
  const size_t need = ValueTypeSize(type);
  if (size < need) {
    return u8"<读取失败>";
  }
  switch (type) {
    case protocol::ValueType::U8: {
      uint8_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      return FormatHexValue(v, 1);
    }
    case protocol::ValueType::U16: {
      uint16_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      return FormatHexValue(v, 2);
    }
    case protocol::ValueType::U32: {
      uint32_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      return FormatHexValue(v, 4);
    }
    case protocol::ValueType::U64: {
      uint64_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      return FormatHexValue(v, 8);
    }
    case protocol::ValueType::S32: {
      int32_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      return FormatHexValue(static_cast<uint32_t>(v), 4);
    }
    case protocol::ValueType::S64: {
      int64_t v = 0;
      std::memcpy(&v, data, sizeof(v));
      return FormatHexValue(static_cast<uint64_t>(v), 8);
    }
    default:
      return FormatValueText(type, data, size);
  }
}

bool ParseValueForType(protocol::ValueType type, const char* text, std::vector<uint8_t>* out, bool hex) {
  if (!out || !text) {
    return false;
  }
  out->clear();
  char* endptr = nullptr;
  switch (type) {
    case protocol::ValueType::U8: {
      unsigned long long v = std::strtoull(text, &endptr, hex ? 16 : 0);
      if (endptr == text) return false;
      uint8_t val = static_cast<uint8_t>(v & 0xFFu);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::U16: {
      unsigned long long v = std::strtoull(text, &endptr, hex ? 16 : 0);
      if (endptr == text) return false;
      uint16_t val = static_cast<uint16_t>(v & 0xFFFFu);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::U32: {
      unsigned long long v = std::strtoull(text, &endptr, hex ? 16 : 0);
      if (endptr == text) return false;
      uint32_t val = static_cast<uint32_t>(v & 0xFFFFFFFFu);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::U64: {
      unsigned long long v = std::strtoull(text, &endptr, hex ? 16 : 0);
      if (endptr == text) return false;
      uint64_t val = static_cast<uint64_t>(v);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::S32: {
      long long v = std::strtoll(text, &endptr, hex ? 16 : 0);
      if (endptr == text) return false;
      int32_t val = static_cast<int32_t>(v);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::S64: {
      long long v = std::strtoll(text, &endptr, hex ? 16 : 0);
      if (endptr == text) return false;
      int64_t val = static_cast<int64_t>(v);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::FLOAT: {
      if (hex && LooksHexNumber(text)) {
        unsigned long long raw = std::strtoull(text, &endptr, 16);
        if (endptr == text) return false;
        uint32_t bits = static_cast<uint32_t>(raw & 0xFFFFFFFFu);
        float val = 0.0f;
        std::memcpy(&val, &bits, sizeof(val));
        out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
        return true;
      }
      double v = std::strtod(text, &endptr);
      if (endptr == text) return false;
      float val = static_cast<float>(v);
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    case protocol::ValueType::DOUBLE: {
      if (hex && LooksHexNumber(text)) {
        unsigned long long raw = std::strtoull(text, &endptr, 16);
        if (endptr == text) return false;
        uint64_t bits = static_cast<uint64_t>(raw);
        double val = 0.0;
        std::memcpy(&val, &bits, sizeof(val));
        out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
        return true;
      }
      double v = std::strtod(text, &endptr);
      if (endptr == text) return false;
      double val = v;
      out->assign(reinterpret_cast<uint8_t*>(&val), reinterpret_cast<uint8_t*>(&val) + sizeof(val));
      return true;
    }
    default:
      return false;
  }
}

std::string FormatOffset(int64_t offset) {
  if (offset >= 0) {
    return std::string("+0x") + Hex64(static_cast<uint64_t>(offset)).substr(2);
  }
  return std::string("-0x") + Hex64(static_cast<uint64_t>(-offset)).substr(2);
}

std::string BuildPointerExpr(uint64_t base,
                             const std::vector<int64_t>& offsets,
                             bool include_base) {
  std::string expr = include_base ? Hex64(base) : "";
  for (int64_t off : offsets) {
    expr = "[" + expr + FormatOffset(off) + "]";
  }
  return expr;
}

std::string OpenFileDialog(const wchar_t* filter, const wchar_t* title) {
  wchar_t filename[MAX_PATH] = {0};
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = nullptr;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = filename;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrTitle = title;
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
  if (!GetOpenFileNameW(&ofn)) {
    return {};
  }
  int needed = WideCharToMultiByte(CP_UTF8, 0, filename, -1, nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    return {};
  }
  std::string out;
  out.resize(static_cast<size_t>(needed - 1));
  WideCharToMultiByte(CP_UTF8, 0, filename, -1, out.data(), needed, nullptr, nullptr);
  return out;
}

bool ReadMemoryRangeWithClient(NetClient& client,
                               uint64_t addr,
                               uint32_t size,
                               uint32_t flags,
                               std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  auto try_read = [&](uint32_t req_flags) -> bool {
    out->clear();
    protocol::ReadMemRequest req{};
    req.address = addr;
    req.size = size;
    req.reserved = req_flags;

    protocol::PacketHeader header{};
    std::vector<uint8_t> payload;
    if (!client.SendAndReceive(protocol::CommandType::CMD_READ_MEM, &req, sizeof(req), &header, &payload)) {
      return false;
    }
    BenchTrackPacket(sizeof(req), payload.size());
    if (payload.size() < offsetof(protocol::ReadMemResponse, data)) {
      return false;
    }
    const auto* resp = reinterpret_cast<const protocol::ReadMemResponse*>(payload.data());
    if (resp->code != 0) {
      return false;
    }
    const size_t bytes = resp->bytes_read;
    const size_t expected = offsetof(protocol::ReadMemResponse, data) + bytes;
    if (payload.size() < expected) {
      return false;
    }
    out->assign(resp->data, resp->data + bytes);
    BenchTrackRead(bytes, size);
    return true;
  };

  if (try_read(flags)) {
    return true;
  }
  if ((flags & protocol::READ_FLAG_USE_PVM) != 0) {
    const uint32_t retry_flags = flags & ~protocol::READ_FLAG_USE_PVM;
    return try_read(retry_flags);
  }
  return false;
}

bool ReadMemoryBatchWithClient(NetClient& client,
                               const std::vector<std::pair<uint64_t, uint32_t>>& ranges,
                               uint32_t flags,
                               std::vector<std::vector<uint8_t>>* out_buffers) {
  if (!out_buffers || ranges.empty()) {
    return false;
  }
  out_buffers->clear();

  auto try_batch = [&](uint32_t req_flags) -> bool {
    const size_t header_size = offsetof(protocol::ReadMemBatchRequest, ranges);
    const size_t payload_size = header_size + ranges.size() * sizeof(protocol::ReadMemBatchRange);
    if (payload_size > std::numeric_limits<uint32_t>::max()) {
      return false;
    }
    std::vector<uint8_t> req_buf(payload_size);
    auto* req = reinterpret_cast<protocol::ReadMemBatchRequest*>(req_buf.data());
    req->count = static_cast<uint32_t>(ranges.size());
    req->flags = req_flags;
    for (size_t i = 0; i < ranges.size(); ++i) {
      req->ranges[i].address = ranges[i].first;
      req->ranges[i].size = ranges[i].second;
      req->ranges[i].reserved = 0;
    }

    protocol::PacketHeader header{};
    std::vector<uint8_t> payload;
    if (!client.SendAndReceive(protocol::CommandType::CMD_READ_MEM_BATCH,
                               req,
                               static_cast<uint32_t>(req_buf.size()),
                               &header,
                               &payload)) {
      return false;
    }
    BenchTrackPacket(req_buf.size(), payload.size());
    const size_t resp_header_size = offsetof(protocol::ReadMemBatchResponse, results);
    if (payload.size() < resp_header_size) {
      return false;
    }
    const auto* resp = reinterpret_cast<const protocol::ReadMemBatchResponse*>(payload.data());
    if (resp->count != ranges.size()) {
      return false;
    }
    const size_t results_size = ranges.size() * sizeof(protocol::ReadMemBatchResult);
    if (payload.size() < resp_header_size + results_size) {
      return false;
    }
    const auto* results = resp->results;
    const uint8_t* data_ptr = payload.data() + resp_header_size + results_size;
    size_t data_offset = 0;
    out_buffers->resize(ranges.size());
    for (size_t i = 0; i < ranges.size(); ++i) {
      if (results[i].code != 0) {
        return false;
      }
      const size_t bytes = results[i].bytes_read;
      if (data_ptr + data_offset + bytes > payload.data() + payload.size()) {
        return false;
      }
      (*out_buffers)[i].assign(data_ptr + data_offset, data_ptr + data_offset + bytes);
      data_offset += bytes;
      BenchTrackRead(bytes, ranges[i].second);
    }
    return true;
  };

  if (try_batch(flags)) {
    return true;
  }
  if ((flags & protocol::READ_FLAG_USE_PVM) != 0) {
    return try_batch(flags & ~protocol::READ_FLAG_USE_PVM);
  }
  return false;
}

bool ReadPointerValue(NetClient& client,
                      uint64_t addr,
                      uint32_t pointer_size,
                      uint32_t flags,
                      uint64_t* out_value) {
  thread_local std::vector<uint8_t> data;
  if (data.capacity() < pointer_size) {
    data.reserve(pointer_size);
  }
  if (!ReadMemoryRangeWithClient(client, addr, pointer_size, flags, &data)) {
    return false;
  }
  if (data.size() < pointer_size) {
    return false;
  }
  if (pointer_size == 4) {
    uint32_t v = 0;
    std::memcpy(&v, data.data(), sizeof(v));
    if (out_value) {
      *out_value = static_cast<uint64_t>(v);
    }
  } else {
    uint64_t v = 0;
    std::memcpy(&v, data.data(), sizeof(v));
    if (out_value) {
      *out_value = StripTag64(v);
    }
  }
  return true;
}
}

bool SendPointerVerifyBatch(NetClient& client,
                            const std::vector<PointerChain>& chains,
                            size_t start,
                            size_t count,
                            uint32_t pointer_size,
                            uint16_t depth,
                            uint32_t flags,
                            std::vector<protocol::PointerVerifyBatchResult>* out_results) {
  if (!out_results) {
    return false;
  }
  out_results->clear();
  if (count == 0 || depth == 0) {
    return false;
  }
  const size_t header_size = offsetof(protocol::PointerVerifyBatchRequest, bases);
  const size_t bases_size = count * sizeof(uint64_t);
  const size_t offsets_size = count * static_cast<size_t>(depth) * sizeof(int64_t);
  const size_t payload_size = header_size + bases_size + offsets_size;

  std::vector<uint8_t> buffer(payload_size);
  auto* req = reinterpret_cast<protocol::PointerVerifyBatchRequest*>(buffer.data());
  req->count = static_cast<uint32_t>(count);
  req->pointer_size = static_cast<uint16_t>(pointer_size);
  req->depth = depth;
  req->flags = flags;
  req->reserved = 0;

  uint64_t* bases = req->bases;
  for (size_t i = 0; i < count; ++i) {
    bases[i] = chains[start + i].base;
  }
  auto* offsets = reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(bases) + bases_size);
  for (size_t i = 0; i < count; ++i) {
    const auto& chain = chains[start + i];
    if (chain.offsets.size() < depth) {
      return false;
    }
    std::memcpy(offsets + i * depth, chain.offsets.data(), depth * sizeof(int64_t));
  }

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!client.SendAndReceive(protocol::CommandType::CMD_PTR_VERIFY_BATCH,
                             req,
                             static_cast<uint32_t>(buffer.size()),
                             &header,
                             &payload)) {
    return false;
  }
  BenchTrackPacket(buffer.size(), payload.size());
  if (payload.size() < offsetof(protocol::PointerVerifyBatchResponse, results)) {
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::PointerVerifyBatchResponse*>(payload.data());
  if (resp->count != count) {
    return false;
  }
  const size_t expected = offsetof(protocol::PointerVerifyBatchResponse, results) +
                          count * sizeof(protocol::PointerVerifyBatchResult);
  if (payload.size() < expected) {
    return false;
  }
  out_results->assign(resp->results, resp->results + count);
  return true;
}

bool SendPointerVerifySingle(NetClient& client,
                             const PointerChain& chain,
                             uint32_t pointer_size,
                             uint16_t depth,
                             uint32_t flags,
                             protocol::PointerVerifyBatchResult* out_result) {
  if (!out_result || depth == 0 || chain.offsets.size() < depth) {
    return false;
  }
  const size_t header_size = offsetof(protocol::PointerVerifyBatchRequest, bases);
  const size_t bases_size = sizeof(uint64_t);
  const size_t offsets_size = static_cast<size_t>(depth) * sizeof(int64_t);
  const size_t payload_size = header_size + bases_size + offsets_size;

  thread_local std::vector<uint8_t> req_buffer;
  thread_local std::vector<uint8_t> payload;
  req_buffer.resize(payload_size);
  auto* req = reinterpret_cast<protocol::PointerVerifyBatchRequest*>(req_buffer.data());
  req->count = 1;
  req->pointer_size = static_cast<uint16_t>(pointer_size);
  req->depth = depth;
  req->flags = flags;
  req->reserved = 0;
  req->bases[0] = chain.base;
  auto* offsets = reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(req->bases) + bases_size);
  std::memcpy(offsets, chain.offsets.data(), offsets_size);

  protocol::PacketHeader header{};
  if (!client.SendAndReceive(protocol::CommandType::CMD_PTR_VERIFY_BATCH,
                             req,
                             static_cast<uint32_t>(req_buffer.size()),
                             &header,
                             &payload)) {
    return false;
  }
  BenchTrackPacket(req_buffer.size(), payload.size());
  const size_t resp_header = offsetof(protocol::PointerVerifyBatchResponse, results);
  if (payload.size() < resp_header + sizeof(protocol::PointerVerifyBatchResult)) {
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::PointerVerifyBatchResponse*>(payload.data());
  if (resp->count != 1) {
    return false;
  }
  *out_result = resp->results[0];
  return true;
}

bool SendPointerVerifyBatchFilter(NetClient& client,
                                  const std::vector<PointerChain>& chains,
                                  size_t start,
                                  size_t count,
                                  uint32_t pointer_size,
                                  uint16_t depth,
                                  uint32_t flags,
                                  const std::vector<uint64_t>& targets,
                                  std::vector<uint32_t>* out_matched_indices) {
  if (!out_matched_indices) {
    return false;
  }
  out_matched_indices->clear();
  if (count == 0 || depth == 0 || targets.empty()) {
    return false;
  }
  if (count > std::numeric_limits<uint32_t>::max() ||
      targets.size() > std::numeric_limits<uint32_t>::max()) {
    return false;
  }

  const size_t header_size = offsetof(protocol::PointerVerifyBatchV2Request, bases);
  const size_t bases_size = count * sizeof(uint64_t);
  const size_t offsets_size = count * static_cast<size_t>(depth) * sizeof(int64_t);
  const size_t targets_size = targets.size() * sizeof(uint64_t);
  if (header_size > std::numeric_limits<size_t>::max() - bases_size ||
      header_size + bases_size > std::numeric_limits<size_t>::max() - offsets_size ||
      header_size + bases_size + offsets_size > std::numeric_limits<size_t>::max() - targets_size) {
    return false;
  }
  const size_t payload_size = header_size + bases_size + offsets_size + targets_size;
  if (payload_size > std::numeric_limits<uint32_t>::max()) {
    return false;
  }

  thread_local std::vector<uint8_t> req_buffer;
  thread_local std::vector<uint8_t> payload;
  req_buffer.resize(payload_size);
  auto* req = reinterpret_cast<protocol::PointerVerifyBatchV2Request*>(req_buffer.data());
  req->count = static_cast<uint32_t>(count);
  req->pointer_size = static_cast<uint16_t>(pointer_size);
  req->depth = depth;
  req->flags = flags | protocol::PTR_VERIFY_BATCH_FLAG_TARGET_FILTER;
  req->target_count = static_cast<uint32_t>(targets.size());
  req->reserved = 0;

  uint64_t* bases = req->bases;
  for (size_t i = 0; i < count; ++i) {
    bases[i] = chains[start + i].base;
  }
  auto* offsets = reinterpret_cast<int64_t*>(reinterpret_cast<uint8_t*>(bases) + bases_size);
  for (size_t i = 0; i < count; ++i) {
    const auto& chain = chains[start + i];
    if (chain.offsets.size() < depth) {
      return false;
    }
    std::memcpy(offsets + i * depth, chain.offsets.data(), depth * sizeof(int64_t));
  }
  auto* target_ptr = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(offsets) + offsets_size);
  std::memcpy(target_ptr, targets.data(), targets_size);

  protocol::PacketHeader header{};
  if (!client.SendAndReceive(protocol::CommandType::CMD_PTR_VERIFY_BATCH_V2,
                             req,
                             static_cast<uint32_t>(req_buffer.size()),
                             &header,
                             &payload)) {
    return false;
  }
  BenchTrackPacket(req_buffer.size(), payload.size());

  if (payload.size() < offsetof(protocol::PointerVerifyBatchV2Response, matched_indices)) {
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::PointerVerifyBatchV2Response*>(payload.data());
  if (resp->count != count) {
    return false;
  }
  const size_t expected = offsetof(protocol::PointerVerifyBatchV2Response, matched_indices) +
                          static_cast<size_t>(resp->matched_count) * sizeof(uint32_t);
  if (payload.size() < expected) {
    return false;
  }
  out_matched_indices->assign(resp->matched_indices, resp->matched_indices + resp->matched_count);
  for (uint32_t idx : *out_matched_indices) {
    if (idx >= count) {
      return false;
    }
  }
  return true;
}

bool ExportPointerText(const std::string& path,
                       const std::string& out_path,
                       std::string* out_error);
bool ConvertPointerTextToBinary(const std::string& txt_path,
                                const std::string& out_path,
                                uint32_t pointer_size,
                                std::string* out_error);

ClientUI::ClientUI(bool auto_mode)
    : port_(12345), mem_size_(256), auto_mode_(auto_mode) {
  std::snprintf(host_, sizeof(host_), "127.0.0.1");
  std::snprintf(pid_input_, sizeof(pid_input_), "");
  std::snprintf(value_input_, sizeof(value_input_), "");
  std::snprintf(scan_start_, sizeof(scan_start_), "");
  std::snprintf(scan_end_, sizeof(scan_end_), "");
  std::snprintf(mem_addr_, sizeof(mem_addr_), "0");
  std::snprintf(write_addr_, sizeof(write_addr_), "0");
  std::snprintf(write_data_, sizeof(write_data_), "");
  std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0");
  std::snprintf(disasm_jump_addr_, sizeof(disasm_jump_addr_), "0");
  std::snprintf(pointer_scan_target_, sizeof(pointer_scan_target_), "0");
  std::snprintf(pointer_scan_index_path_, sizeof(pointer_scan_index_path_), "seach_point/index_last.r3i");
  std::snprintf(pointer_preview_module_keyword_, sizeof(pointer_preview_module_keyword_), "");
  std::snprintf(pointer_scan_module_search_, sizeof(pointer_scan_module_search_), "");
  std::snprintf(pointer_preview_module_search_, sizeof(pointer_preview_module_search_), "");
  std::snprintf(data_traverse_addr_, sizeof(data_traverse_addr_), "0");
  std::snprintf(pointer_verify_addr_, sizeof(pointer_verify_addr_), "0");
  std::snprintf(pointer_verify_desc_, sizeof(pointer_verify_desc_), "");
  std::snprintf(pointer_verify_offset_input_, sizeof(pointer_verify_offset_input_), "0");
  std::snprintf(breakpoint_addr_, sizeof(breakpoint_addr_), "0");
  std::snprintf(address_add_addr_, sizeof(address_add_addr_), "0");
  std::snprintf(address_add_desc_, sizeof(address_add_desc_), "");
  std::snprintf(process_filter_, sizeof(process_filter_), "");
  std::snprintf(module_filter_, sizeof(module_filter_), "");
  std::snprintf(command_filter_, sizeof(command_filter_), "");
  state_.page_size = 128;
  read_format_ = 0;
  write_format_ = 0;
  read_use_length_override_ = false;
  scan_use_pvm_ = true;
  scan_allow_nonresident_ = true;
  scan_strict_ = true;
  scan_freeze_ = true;
  auto_log_path_ = (std::filesystem::current_path() / "r3_windows_client_autotest.log").string();
  if (auto_mode_) {
    breakpoint_auto_fallback_ptrace_ = true;
  }
}

void ClientUI::SetServer(const char* host, int port) {
  if (host && host[0]) {
    std::snprintf(host_, sizeof(host_), "%s", host);
  }
  if (port > 0) {
    port_ = port;
  }
}

void ClientUI::SetSvgAtlasTexture(void* texture_id) {
  svg_atlas_texture_ = texture_id;
}

void ClientUI::SetSvgAtlasIconUv(const char* id, float u0, float v0, float u1, float v1) {
  if (!id || id[0] == '\0') {
    return;
  }
  SvgIconUv uv;
  uv.u0 = u0;
  uv.v0 = v0;
  uv.u1 = u1;
  uv.v1 = v1;
  svg_icon_uvs_[id] = uv;
}

bool ClientUI::DrawSvgButton(const char* icon_id, const char* label) {
  const char* safe_label = label ? label : "";
  SvgIconUv uv{};
  bool has_icon = false;
  if (svg_atlas_texture_ && icon_id && icon_id[0] != '\0') {
    const auto it = svg_icon_uvs_.find(icon_id);
    if (it != svg_icon_uvs_.end()) {
      uv = it->second;
      has_icon = true;
    }
  }

  const ImGuiStyle& style = ImGui::GetStyle();
  const ImVec2 text_size = ImGui::CalcTextSize(safe_label, nullptr, true);
  const float icon_size = has_icon ? std::max(16.0f, ImGui::GetFontSize() * 1.06f) : 0.0f;
  const float icon_gap = has_icon ? 12.0f : 0.0f;
  const float left_pad = style.FramePadding.x + 4.0f;
  const float right_pad = style.FramePadding.x + 4.0f;
  const float content_w = icon_size + icon_gap + text_size.x;
  const float min_w = 104.0f;
  const float width = std::max(min_w, left_pad + content_w + right_pad);
  const ImVec2 size(width, ImGui::GetFrameHeight() + 2.0f);

  std::string button_id = "##svgbtn_";
  if (icon_id) {
    button_id += icon_id;
  }
  button_id += "_";
  button_id += safe_label;
  const bool pressed = ImGui::Button(button_id.c_str(), size);

  const ImVec2 min = ImGui::GetItemRectMin();
  const ImVec2 max = ImGui::GetItemRectMax();
  const float h = max.y - min.y;
  const bool hovered = ImGui::IsItemHovered();
  const bool active = ImGui::IsItemActive();

  const float inner_w = width - left_pad - right_pad;
  const float start_x = min.x + left_pad + std::max(0.0f, (inner_w - content_w) * 0.5f);
  const float text_x = start_x + icon_size + icon_gap;
  const float text_y = min.y + (h - text_size.y) * 0.5f;
  ImGui::GetWindowDrawList()->AddText(ImVec2(text_x, text_y),
                                      ImGui::GetColorU32(ImGuiCol_Text),
                                      safe_label);

  if (has_icon) {
    const float icon_x = start_x;
    const float icon_y = min.y + (h - icon_size) * 0.5f;
    ImVec4 chip = ImGui::GetStyleColorVec4(active ? ImGuiCol_HeaderActive :
                                           hovered ? ImGuiCol_HeaderHovered :
                                                     ImGuiCol_Header);
    chip.w = active ? 0.65f : (hovered ? 0.45f : 0.30f);
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(icon_x - 2.0f, icon_y - 2.0f),
                                              ImVec2(icon_x + icon_size + 2.0f, icon_y + icon_size + 2.0f),
                                              ImGui::GetColorU32(chip),
                                              4.0f);
    const ImU32 tint = active ? IM_COL32(255, 255, 255, 255) :
                       hovered ? IM_COL32(250, 253, 255, 248) :
                                 IM_COL32(228, 238, 248, 240);
    ImGui::GetWindowDrawList()->AddImage(svg_atlas_texture_,
                                         ImVec2(icon_x, icon_y),
                                         ImVec2(icon_x + icon_size, icon_y + icon_size),
                                         ImVec2(uv.u0, uv.v0),
                                         ImVec2(uv.u1, uv.v1),
                                         tint);
  }

  return pressed;
}

void ClientUI::Render() {
  ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);

  ImGui::Begin(u8"R3 安卓调试客户端", nullptr, ImGuiWindowFlags_MenuBar);

  if (ImGui::BeginMenuBar()) {
    if (ImGui::BeginMenu(u8"文件")) {
      if (ImGui::MenuItem(u8"退出")) {
        request_quit_ = true;
      }
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(u8"视图")) {
      ImGui::MenuItem(u8"内存查看", nullptr, &show_memory_window_);
      ImGui::MenuItem(u8"指针扫描", nullptr, &show_pointer_scan_window_);
      ImGui::MenuItem(u8"指针对比", nullptr, &show_pointer_compare_window_);
      ImGui::MenuItem(u8"数据遍历", nullptr, &show_data_traverse_window_);
      ImGui::MenuItem(u8"指针验证", nullptr, &show_pointer_verify_window_);
      ImGui::MenuItem(u8"调试器断点", nullptr, &show_debugger_window_);
      ImGui::MenuItem(u8"Test", nullptr, &show_test_window_);
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(u8"调试")) {
      ImGui::MenuItem(u8"调试窗(反汇编)", nullptr, &show_debug_window_);
      ImGui::EndMenu();
    }
    ImGui::EndMenuBar();
  }

  ImGuiIO& io = ImGui::GetIO();
  if (!io.WantTextInput) {
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) {
      show_process_popup_ = true;
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
      ScanFirst();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F3, false)) {
      ScanNext();
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_L, false)) {
      address_add_type_index_ = ValueTypeToIndex(state_.value_type);
      show_add_address_popup_ = true;
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_P, false)) {
      show_command_palette_ = true;
    }
  }
  if (right_tab_request_ == 0) {
    right_tab_request_ = -1;
    OpenMemoryWorkspaceAt(0, true, true);
  }

  if (state_.connected && !breakpoints_.empty()) {
    const bool ptrace_active = (breakpoint_backend_ == 0);
    if (breakpoint_monitoring_ || ptrace_active) {
      const uint64_t now_ms = NowMs();
      if (now_ms - breakpoint_last_poll_ms_ >= 200) {
        PollBreakpoints();
        breakpoint_last_poll_ms_ = now_ms;
      }
    }
  }

  if (auto_mode_ && !auto_running_ && !auto_done_) {
    StartAutoTest();
  }
  if (auto_mode_ && auto_running_) {
    RunAutoTest();
  }

  ImVec2 avail = ImGui::GetContentRegionAvail();
  const float spacing = ImGui::GetStyle().ItemSpacing.y;
  float status_h = 26.0f;
  float main_h = avail.y - status_h - spacing;
  if (main_h < 120.0f) {
    main_h = avail.y;
    status_h = 0.0f;
  }

  ImGui::BeginChild("main_area", ImVec2(0, main_h), false);
  ImGui::BeginChild("ce_topbar", ImVec2(0, 42), true, ImGuiWindowFlags_NoScrollbar);
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.0f, 6.0f));
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 6.0f));
  if (DrawSvgButton("process", u8"选择进程...")) {
    if (!state_.connected) {
      ConnectToServer();
    }
    show_process_popup_ = true;
  }
  ImGui::SameLine();
  if (DrawSvgButton("scan", u8"首次扫描")) {
    ScanFirst();
  }
  ImGui::SameLine();
  if (DrawSvgButton("scan", u8"再次扫描")) {
    ScanNext();
  }
  ImGui::SameLine();
  if (DrawSvgButton("memory", u8"查看内存(CE)")) {
    OpenMemoryWorkspaceAt(0, true, true);
  }
  ImGui::SameLine();
  if (DrawSvgButton("debugger", u8"更多")) {
    ImGui::OpenPopup("topbar_more_menu");
  }
  if (ImGui::BeginPopup("topbar_more_menu")) {
    if (ImGui::MenuItem(u8"高级扫描设置...")) {
      show_scan_advanced_popup_ = true;
    }
    ImGui::Separator();
    if (ImGui::MenuItem(state_.connected ? u8"断开连接" : u8"连接服务器")) {
      if (state_.connected) {
        DisconnectFromServer();
      } else {
        ConnectToServer();
      }
    }
    if (ImGui::MenuItem(u8"打开进程")) {
      Attach();
    }
    ImGui::Separator();
    if (ImGui::MenuItem(u8"指针扫描")) {
      show_pointer_scan_window_ = true;
    }
    if (ImGui::MenuItem(u8"指针对比")) {
      show_pointer_compare_window_ = true;
    }
    if (ImGui::MenuItem(u8"指针验证")) {
      show_pointer_verify_window_ = true;
    }
    if (ImGui::MenuItem(u8"数据遍历")) {
      show_data_traverse_window_ = true;
    }
    if (ImGui::MenuItem(u8"反汇编窗口")) {
      show_debug_window_ = true;
    }
    if (ImGui::MenuItem(u8"调试器断点")) {
      show_debugger_window_ = true;
    }
    ImGui::EndPopup();
  }
  ImGui::SameLine();
  ImGui::TextUnformatted("|");
  ImGui::SameLine();
  ImGui::Text(u8"PID: %u", state_.pid);
  ImGui::SameLine();
  const char* conn_label = state_.connected ? u8"已连接" : u8"未连接";
  ImGui::Text(u8"连接: %s", conn_label);
  if (!state_.status.empty() && state_.status != conn_label) {
    ImGui::SameLine();
    ImGui::Text(u8"%s", state_.status.c_str());
  }
  ImGui::PopStyleVar(2);
  ImGui::EndChild();

  ImVec2 area_avail = ImGui::GetContentRegionAvail();
  float bottom_h = std::max(180.0f, area_avail.y * 0.35f);
  float top_h = area_avail.y - bottom_h - spacing;
  if (top_h < 200.0f) {
    top_h = area_avail.y * 0.55f;
    bottom_h = area_avail.y - top_h - spacing;
  }

  ImGui::BeginChild("ce_scan_area", ImVec2(0, top_h), false);
  int type_index = ValueTypeToIndex(state_.value_type);
  int cond_index = static_cast<int>(state_.condition);
  bool hex_changed = false;

  float left_w = std::min(330.0f, area_avail.x * 0.32f);
  ImGui::BeginChild("ce_scan_left",
                    ImVec2(left_w, 0),
                    false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
  ImGui::TextUnformatted(u8"扫描工作区");
  ImGui::SameLine();
  if (ImGui::SmallButton(u8"高级设置...")) {
    show_scan_advanced_popup_ = true;
  }
  ImGui::Separator();

  ImGui::TextUnformatted(u8"步骤1：输入待扫描值");
  ImGui::InputText(u8"数值", value_input_, sizeof(value_input_));
  ImGui::SameLine();
  hex_changed = ImGui::Checkbox(u8"Hex", &address_list_hex_);
  ImGui::Combo(u8"数值类型", &type_index, kScanTypeNames, IM_ARRAYSIZE(kScanTypeNames));
  ImGui::Combo(u8"扫描条件", &cond_index, kCondNames, IM_ARRAYSIZE(kCondNames));
  state_.value_type = kScanTypeMap[type_index];
  state_.condition = static_cast<protocol::ComparisonType>(cond_index);
  if (hex_changed) {
    RefreshScanPreviewValues();
    RefreshAddressListValues(true);
  }

  ImGui::Spacing();
  ImGui::Text(u8"匹配总数：%" PRIu64, state_.scan_total);
  ImGui::SameLine();
  if (ImGui::SmallButton(u8"刷新数值")) {
    RefreshScanPreviewValues();
  }

  ImGui::SeparatorText(u8"地址范围");
  ImGui::SameLine();
  if (ImGui::SmallButton(u8"模块范围...")) {
    show_module_popup_ = true;
  }
  ImGui::SetNextItemWidth(-FLT_MIN);
  ImGui::InputTextWithHint("##scan_start_main",
                           u8"起始地址（留空或0=自动）",
                           scan_start_,
                           sizeof(scan_start_));
  ImGui::SetNextItemWidth(-FLT_MIN);
  ImGui::InputTextWithHint("##scan_end_main",
                           u8"结束地址（留空或0=自动）",
                           scan_end_,
                           sizeof(scan_end_));
  ImGui::EndChild();

  ImGui::SameLine();
  ImGui::BeginChild("ce_scan_right", ImVec2(0, 0), false);
  ImGui::Text(u8"匹配列表");
  ImGui::SameLine();
  ImGui::Text(u8"当前结果：%zu", state_.page_addresses.size());
  ImGui::SameLine();
  ImGui::TextUnformatted("| 页:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(72.0f);
  ImGui::InputScalar("##scan_page_idx", ImGuiDataType_U64, &state_.page_index);
  ImGui::SameLine();
  ImGui::TextUnformatted("大小:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(60.0f);
  ImGui::InputScalar("##scan_page_size", ImGuiDataType_U32, &state_.page_size);
  ImGui::SameLine();
  if (ImGui::Button(u8"获取页")) {
    ScanPage();
  }
  if (ImGui::BeginTable("scan_results",
                         3,
                         ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                         ImVec2(0, 0))) {
    ImGui::TableSetupColumn(u8"地址", ImGuiTableColumnFlags_WidthFixed, 140.0f);
    ImGui::TableSetupColumn(u8"数值", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn(u8"类型", ImGuiTableColumnFlags_WidthFixed, 80.0f);
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(state_.page_addresses.size()));
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const size_t i = static_cast<size_t>(row);
        ImGui::TableNextRow();
        ImGui::PushID(row);
        ImGui::TableSetColumnIndex(0);
        char addr_label[64] = {0};
        std::snprintf(addr_label, sizeof(addr_label), "0x%llX",
                      static_cast<unsigned long long>(state_.page_addresses[i]));
        if (ImGui::Selectable(addr_label,
                              false,
                              ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
          if (ImGui::IsMouseDoubleClicked(0)) {
            AddAddressEntry(state_.page_addresses[i], state_.value_type, "");
          }
        }
        if (ImGui::BeginPopupContextItem("scan_row_ctx")) {
          if (ImGui::MenuItem(u8"添加到地址列表")) {
            AddAddressEntry(state_.page_addresses[i], state_.value_type, "");
          }
          if (ImGui::MenuItem(u8"反汇编")) {
            show_debug_window_ = true;
            std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0x%llX",
                          static_cast<unsigned long long>(state_.page_addresses[i]));
            RunDisasm(state_.page_addresses[i]);
          }
          if (ImGui::MenuItem(u8"内存查看")) {
            OpenMemoryWorkspaceAt(state_.page_addresses[i], true, true);
          }
          ImGui::EndPopup();
        }
        ImGui::TableSetColumnIndex(1);
        if (i < scan_preview_values_.size()) {
          ImGui::TextUnformatted(scan_preview_values_[i].c_str());
        } else {
          ImGui::TextUnformatted(u8"<未读取>");
        }
        ImGui::TableSetColumnIndex(2);
        ImGui::TextUnformatted(kScanTypeNames[type_index]);
        ImGui::PopID();
      }
    }
    ImGui::EndTable();
  }
  ImGui::EndChild();
  ImGui::EndChild();

  static int scan_advanced_step = 0;
  static bool scan_expert_mode = false;
  if (show_scan_advanced_popup_) {
    scan_advanced_step = 0;
    ImGui::OpenPopup(u8"高级扫描设置");
    show_scan_advanced_popup_ = false;
  }
  if (ImGui::BeginPopupModal(u8"高级扫描设置", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted(u8"仅保留必要设置（两步完成）");
    if (ImGui::RadioButton(u8"1 基础连接", scan_advanced_step == 0)) {
      scan_advanced_step = 0;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton(u8"2 扫描策略", scan_advanced_step == 1)) {
      scan_advanced_step = 1;
    }
    ImGui::Separator();

    if (scan_advanced_step == 0) {
      ImGui::SetNextItemWidth(220.0f);
      ImGui::InputText(u8"主机", host_, sizeof(host_));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(90.0f);
      ImGui::InputInt(u8"端口", &port_);
      if (!state_.connected) {
        if (ImGui::Button(u8"连接")) {
          ConnectToServer();
        }
      } else {
        if (ImGui::Button(u8"断开")) {
          DisconnectFromServer();
        }
      }
      ImGui::SameLine();
      if (ImGui::Button(u8"选择进程...")) {
        show_process_popup_ = true;
      }

      ImGui::SetNextItemWidth(120.0f);
      ImGui::InputText("##adv_pid", pid_input_, sizeof(pid_input_), ImGuiInputTextFlags_CharsDecimal);
      ImGui::SameLine();
      if (ImGui::Button(u8"打开进程")) {
        Attach();
      }
    } else {
      ImGui::Checkbox(u8"严格不漏(推荐)", &scan_strict_);
      ImGui::Checkbox(u8"使用系统读取(process_vm_readv)", &scan_use_pvm_);
      ImGui::Checkbox(u8"地址按16进制解析(可不带0x)", &address_default_hex_);
      ImGui::Checkbox(u8"显示专家参数", &scan_expert_mode);
      if (scan_strict_) {
        scan_allow_nonresident_ = true;
        scan_freeze_ = true;
      }
      if (scan_expert_mode) {
        ImGui::Checkbox(u8"允许非驻留页(严格)", &scan_allow_nonresident_);
        ImGui::Checkbox(u8"严格快照(冻结进程)", &scan_freeze_);
        ImGui::SetNextItemWidth(100.0f);
        ImGui::InputScalar(u8"默认页大小", ImGuiDataType_U32, &state_.page_size);
      }
    }

    ImGui::Spacing();
    if (scan_advanced_step > 0) {
      if (ImGui::Button(u8"上一步")) {
        scan_advanced_step--;
      }
      ImGui::SameLine();
    }
    if (scan_advanced_step < 1) {
      if (ImGui::Button(u8"下一步")) {
        scan_advanced_step++;
      }
      ImGui::SameLine();
    }
    if (ImGui::Button(u8"关闭")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (address_list_auto_refresh_ && !address_list_.empty()) {
    const uint64_t now_ms = NowMs();
    if (now_ms - address_list_last_refresh_ms_ >= static_cast<uint64_t>(address_list_refresh_interval_ms_)) {
      RefreshAddressListValues(true);
      address_list_last_refresh_ms_ = now_ms;
    }
  }

  if (!address_list_.empty() && state_.connected && state_.pid != 0) {
    const uint64_t now_ms = NowMs();
    if (now_ms - address_list_last_freeze_ms_ >= static_cast<uint64_t>(address_list_freeze_interval_ms_)) {
      bool has_freeze = false;
      for (auto& entry : address_list_) {
        if (!entry.active || !entry.freeze_has_value) {
          continue;
        }
        has_freeze = true;
        if (!WriteMemoryBytes(entry.addr, entry.freeze_bytes)) {
          entry.freeze_failed = true;
          entry.freeze_error = address_list_status_;
        } else {
          entry.freeze_failed = false;
          entry.freeze_error.clear();
        }
      }
      if (has_freeze) {
        address_list_last_freeze_ms_ = now_ms;
      }
    }
  }

  ImGui::BeginChild("ce_address_list", ImVec2(0, 0), false);
  ImGui::Text(u8"地址列表");
  if (ImGui::Button(u8"添加地址")) {
    address_add_type_index_ = ValueTypeToIndex(state_.value_type);
    show_add_address_popup_ = true;
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"删除选中")) {
    if (address_list_selected_ >= 0 &&
        address_list_selected_ < static_cast<int>(address_list_.size())) {
      address_list_.erase(address_list_.begin() + address_list_selected_);
      address_list_selected_ = -1;
    }
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"刷新")) {
    RefreshAddressListValues(true);
    address_list_last_refresh_ms_ = NowMs();
  }
  ImGui::SameLine();
  ImGui::Checkbox(u8"自动刷新", &address_list_auto_refresh_);
  ImGui::SameLine();
  ImGui::Checkbox(u8"使用系统读取模式(process_vm_readv)", &address_list_use_pvm_);
  ImGui::SameLine();
  if (ImGui::Checkbox(u8"Hex", &address_list_hex_)) {
    for (auto& entry : address_list_) {
      if (entry.value_dirty || entry.last_read_bytes.empty()) {
        continue;
      }
      entry.value_display = FormatValueTextMode(entry.type,
                                               entry.last_read_bytes.data(),
                                               entry.last_read_bytes.size(),
                                               address_list_hex_);
      std::snprintf(entry.value_input, sizeof(entry.value_input), "%s", entry.value_display.c_str());
    }
  }
  ImGui::SameLine();
  ImGui::SetNextItemWidth(90);
  ImGui::InputInt(u8"冻结间隔(ms)##freeze", &address_list_freeze_interval_ms_);
  if (address_list_freeze_interval_ms_ < 20) {
    address_list_freeze_interval_ms_ = 20;
  }
  if (address_list_freeze_interval_ms_ > 5000) {
    address_list_freeze_interval_ms_ = 5000;
  }
  if (!address_list_status_.empty()) {
    ImGui::Text(u8"状态：%s", address_list_status_.c_str());
  }

  int remove_index = -1;
  if (ImGui::BeginTable("address_list_table",
                         5,
                         ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                         ImVec2(0, 0))) {
    ImGui::TableSetupColumn(u8"冻结", ImGuiTableColumnFlags_WidthFixed, 40.0f);
    ImGui::TableSetupColumn(u8"描述", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn(u8"地址", ImGuiTableColumnFlags_WidthFixed, 140.0f);
    ImGui::TableSetupColumn(u8"类型", ImGuiTableColumnFlags_WidthFixed, 90.0f);
    ImGui::TableSetupColumn(u8"数值", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(address_list_.size()));
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const size_t i = static_cast<size_t>(row);
        auto& entry = address_list_[i];
        ImGui::TableNextRow();
        ImGui::PushID(row);

        ImGui::TableSetColumnIndex(0);
        if (ImGui::Checkbox("##active", &entry.active)) {
          if (entry.active && !entry.freeze_has_value) {
            std::vector<uint8_t> parsed;
            if (ParseValueForType(entry.type, entry.value_input, &parsed, address_list_hex_)) {
              entry.freeze_bytes = parsed;
              entry.freeze_has_value = true;
            } else if (!entry.last_read_bytes.empty()) {
              entry.freeze_bytes = entry.last_read_bytes;
              entry.freeze_has_value = true;
            }
          }
        }

        ImGui::TableSetColumnIndex(1);
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##desc", entry.desc, sizeof(entry.desc));

        ImGui::TableSetColumnIndex(2);
        char addr_label[64] = {0};
        std::snprintf(addr_label, sizeof(addr_label), "0x%llX",
                      static_cast<unsigned long long>(entry.addr));
        if (ImGui::Selectable(addr_label, address_list_selected_ == static_cast<int>(i),
                              ImGuiSelectableFlags_AllowDoubleClick)) {
          address_list_selected_ = static_cast<int>(i);
          if (ImGui::IsMouseDoubleClicked(0)) {
            OpenMemoryWorkspaceAt(entry.addr, true, true);
          }
        }
        if (ImGui::BeginPopupContextItem("addr_row_ctx")) {
          if (ImGui::MenuItem(u8"删除")) {
            remove_index = static_cast<int>(i);
          }
          if (ImGui::MenuItem(u8"反汇编")) {
            show_debug_window_ = true;
            std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0x%llX",
                          static_cast<unsigned long long>(entry.addr));
            RunDisasm(entry.addr);
          }
          if (ImGui::MenuItem(u8"内存查看")) {
            OpenMemoryWorkspaceAt(entry.addr, true, true);
          }
          ImGui::EndPopup();
        }

        ImGui::TableSetColumnIndex(3);
        int addr_type_index = ValueTypeToIndex(entry.type);
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::Combo("##addr_type", &addr_type_index, kScanTypeNames, IM_ARRAYSIZE(kScanTypeNames))) {
          entry.type = kScanTypeMap[addr_type_index];
          entry.value_display = u8"<未刷新>";
          entry.value_input[0] = '\0';
          entry.value_dirty = false;
          entry.freeze_has_value = false;
          entry.freeze_bytes.clear();
          entry.last_read_bytes.clear();
        }

        ImGui::TableSetColumnIndex(4);
        ImGui::SetNextItemWidth(-FLT_MIN);
        bool edited = ImGui::InputText("##value",
                                       entry.value_input,
                                       sizeof(entry.value_input),
                                       ImGuiInputTextFlags_EnterReturnsTrue);
        if (edited) {
          entry.value_dirty = true;
        }
        if (ImGui::IsItemDeactivatedAfterEdit()) {
          std::vector<uint8_t> bytes;
          if (!ParseValueForType(entry.type, entry.value_input, &bytes, address_list_hex_)) {
            address_list_status_ = u8"写入值无效";
            entry.freeze_failed = true;
            entry.freeze_error = address_list_status_;
          } else {
            if (WriteMemoryBytes(entry.addr, bytes)) {
              entry.freeze_bytes = bytes;
              entry.freeze_has_value = true;
              entry.value_display = FormatValueTextMode(entry.type, bytes.data(), bytes.size(), address_list_hex_);
              std::snprintf(entry.value_input, sizeof(entry.value_input), "%s", entry.value_display.c_str());
              entry.value_dirty = false;
              address_list_status_ = u8"写入成功";
              entry.freeze_failed = false;
              entry.freeze_error.clear();
            }
          }
        }
        if (entry.freeze_failed) {
          ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), u8"冻结失败");
          if (!entry.freeze_error.empty() && ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(entry.freeze_error.c_str());
            ImGui::EndTooltip();
          }
        }

        ImGui::PopID();
      }
    }
    ImGui::EndTable();
  }
  if (remove_index >= 0 &&
      remove_index < static_cast<int>(address_list_.size())) {
    address_list_.erase(address_list_.begin() + remove_index);
    if (address_list_selected_ == remove_index) {
      address_list_selected_ = -1;
    }
  }

  ImGui::EndChild();
  ImGui::EndChild();

  if (status_h > 0.0f) {
    ImGui::BeginChild("status_bar", ImVec2(0, status_h), true);
    ImGui::Text(u8"连接：%s", state_.connected ? u8"已连接" : u8"未连接");
    ImGui::SameLine();
    ImGui::Text(u8"PID：%u", state_.pid);
    ImGui::SameLine();
    ImGui::Text(u8"匹配：%" PRIu64, state_.scan_total);
    if (!state_.status.empty()) {
      ImGui::SameLine();
      ImGui::Text(u8"状态：%s", state_.status.c_str());
    }
    ImGui::EndChild();
  }

  ImGui::End();

  if (show_command_palette_) {
    command_filter_[0] = '\0';
    ImGui::OpenPopup(u8"命令面板");
    show_command_palette_ = false;
  }
  if (ImGui::BeginPopupModal(u8"命令面板", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::SetNextItemWidth(460.0f);
    ImGui::InputTextWithHint(u8"##cmd_filter", u8"输入命令，回车执行首项", command_filter_,
                             sizeof(command_filter_));
    const auto matches = [&](const char* text) {
      return (command_filter_[0] == '\0') || ContainsCI(text, command_filter_);
    };
    bool executed = false;
    int visible_count = 0;
    std::function<void()> first_visible_fn;
    auto draw_cmd = [&](const char* label, const std::function<void()>& fn) {
      if (!matches(label)) {
        return;
      }
      ++visible_count;
      if (!first_visible_fn) {
        first_visible_fn = fn;
      }
      if (ImGui::Selectable(label, visible_count == 1)) {
        fn();
        executed = true;
      }
    };

    ImGui::BeginChild("cmd_list", ImVec2(460, 220), true);
    draw_cmd(state_.connected ? u8"断开服务器" : u8"连接服务器", [&]() {
      if (state_.connected) {
        DisconnectFromServer();
      } else {
        ConnectToServer();
      }
    });
    draw_cmd(u8"选择进程...", [&]() { show_process_popup_ = true; });
    draw_cmd(u8"打开进程", [&]() { Attach(); });
    draw_cmd(u8"首次扫描", [&]() { ScanFirst(); });
    draw_cmd(u8"再次扫描", [&]() { ScanNext(); });
    draw_cmd(u8"查看内存(CE工作区)", [&]() { OpenMemoryWorkspaceAt(0, true, true); });
    draw_cmd(u8"打开调试窗(反汇编)", [&]() { show_debug_window_ = true; });
    draw_cmd(u8"打开指针扫描", [&]() { show_pointer_scan_window_ = true; });
    draw_cmd(u8"打开指针对比", [&]() { show_pointer_compare_window_ = true; });
    draw_cmd(u8"打开指针验证", [&]() { show_pointer_verify_window_ = true; });
    draw_cmd(u8"打开调试器断点", [&]() { show_debugger_window_ = true; });
    ImGui::EndChild();

    if (visible_count == 0) {
      ImGui::TextUnformatted(u8"没有匹配命令");
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) && first_visible_fn) {
      first_visible_fn();
      executed = true;
    }
    if (ImGui::Button(u8"关闭")) {
      ImGui::CloseCurrentPopup();
    }
    if (executed) {
      command_filter_[0] = '\0';
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (show_process_popup_) {
    ImGui::OpenPopup(u8"选择进程");
    show_process_popup_ = false;
  }
  if (ImGui::BeginPopupModal(u8"选择进程", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::InputText(u8"进程搜索", process_filter_, sizeof(process_filter_));
    if (ImGui::Button(u8"刷新")) {
      FetchProcesses();
    }
    ImGui::BeginChild("proc_list_popup", ImVec2(520, 240), true);
    for (size_t i = 0; i < state_.processes.size(); ++i) {
      const auto& proc = state_.processes[i];
      if (process_filter_[0] != '\0') {
        std::string filter = process_filter_;
        std::string name = proc.name;
        std::string pid_text = std::to_string(proc.pid);
        auto to_lower = [](std::string& s) {
          for (char& c : s) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
        };
        to_lower(filter);
        to_lower(name);
        to_lower(pid_text);
        if (name.find(filter) == std::string::npos && pid_text.find(filter) == std::string::npos) {
          continue;
        }
      }
      char label[256] = {0};
      std::snprintf(label, sizeof(label), "%u - %s", proc.pid, proc.name.c_str());
      if (ImGui::Selectable(label, false, ImGuiSelectableFlags_AllowDoubleClick)) {
        std::snprintf(pid_input_, sizeof(pid_input_), "%u", proc.pid);
        if (ImGui::IsMouseDoubleClicked(0)) {
          Attach();
          ImGui::CloseCurrentPopup();
        }
      }
    }
    ImGui::EndChild();
    if (ImGui::Button(u8"打开进程")) {
      Attach();
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"关闭")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (show_module_popup_) {
    ImGui::OpenPopup(u8"选择模块范围");
    show_module_popup_ = false;
  }
  if (ImGui::BeginPopupModal(u8"选择模块范围", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::InputText(u8"模块搜索", module_filter_, sizeof(module_filter_));
    ImGui::Combo(u8"分类", &module_category_, kModuleCategoryNames, IM_ARRAYSIZE(kModuleCategoryNames));
    if (ImGui::Button(u8"刷新模块")) {
      FetchModules();
    }
    ImGui::BeginChild("module_popup_list", ImVec2(720, 260), true, ImGuiWindowFlags_HorizontalScrollbar);
    for (size_t i = 0; i < state_.modules.size(); ++i) {
      const auto& mod = state_.modules[i];
      if (!IsModuleVisible(module_category_, mod)) {
        continue;
      }
      if (module_filter_[0] != '\0') {
        std::string filter = module_filter_;
        std::string path = mod.path;
        auto to_lower = [](std::string& s) {
          for (char& c : s) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
        };
        to_lower(filter);
        to_lower(path);
        if (path.find(filter) == std::string::npos) {
          continue;
        }
      }
      const std::string perms = PermsToString(mod.perms);
      const std::string type_tag = ModuleTypeTag(mod);
      char label[512] = {0};
      std::snprintf(label, sizeof(label), "0x%llX-0x%llX %s %-6s %s",
                    static_cast<unsigned long long>(mod.start),
                    static_cast<unsigned long long>(mod.end),
                    perms.c_str(),
                    type_tag.c_str(),
                    mod.path.empty() ? "" : mod.path.c_str());
      const bool selected = static_cast<int>(i) == selected_module_index_;
      if (ImGui::Selectable(label, selected, ImGuiSelectableFlags_AllowDoubleClick)) {
        selected_module_index_ = static_cast<int>(i);
        if (ImGui::IsMouseDoubleClicked(0)) {
          const auto& sel = state_.modules[i];
          std::snprintf(scan_start_, sizeof(scan_start_), "0x%llX",
                        static_cast<unsigned long long>(sel.start));
          std::snprintf(scan_end_, sizeof(scan_end_), "0x%llX",
                        static_cast<unsigned long long>(sel.end));
          ImGui::CloseCurrentPopup();
        }
      }
    }
    ImGui::EndChild();
    if (ImGui::Button(u8"应用到扫描范围") && selected_module_index_ >= 0 &&
        selected_module_index_ < static_cast<int>(state_.modules.size())) {
      const auto& mod = state_.modules[static_cast<size_t>(selected_module_index_)];
      std::snprintf(scan_start_, sizeof(scan_start_), "0x%llX",
                    static_cast<unsigned long long>(mod.start));
      std::snprintf(scan_end_, sizeof(scan_end_), "0x%llX",
                    static_cast<unsigned long long>(mod.end));
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"应用到反汇编地址") && selected_module_index_ >= 0 &&
        selected_module_index_ < static_cast<int>(state_.modules.size())) {
      const auto& mod = state_.modules[static_cast<size_t>(selected_module_index_)];
      const uint64_t exec_addr = ResolveExecStart(mod);
      std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0x%llX",
                    static_cast<unsigned long long>(exec_addr));
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"关闭")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (show_add_address_popup_) {
    ImGui::OpenPopup(u8"添加地址");
    show_add_address_popup_ = false;
  }
  if (ImGui::BeginPopupModal(u8"添加地址", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::InputText(u8"地址", address_add_addr_, sizeof(address_add_addr_));
    ImGui::Checkbox(u8"地址默认16进制(可不带0x)##addaddr", &address_default_hex_);
    ImGui::InputText(u8"描述", address_add_desc_, sizeof(address_add_desc_));
    ImGui::Combo(u8"类型", &address_add_type_index_, kScanTypeNames, IM_ARRAYSIZE(kScanTypeNames));
    if (ImGui::Button(u8"添加")) {
      const uint64_t addr = ParseAddress(address_add_addr_);
      if (addr != 0) {
        AddAddressEntry(addr, kScanTypeMap[address_add_type_index_], address_add_desc_);
      }
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"取消")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (show_debug_window_) {
    RenderDisasmWindow();
  }
  if (show_memory_window_) {
    RenderMemoryViewWindow();
  }
  if (show_pointer_scan_window_) {
    RenderPointerScanWindow();
  }
  if (show_pointer_compare_window_) {
    RenderPointerCompareWindow();
  }
  if (show_data_traverse_window_) {
    RenderDataTraverseWindow();
  }
  if (show_pointer_verify_window_) {
    RenderPointerVerifyWindow();
  }
  if (show_debugger_window_) {
    RenderDebuggerWindow();
  }
  if (show_test_window_) {
    RenderTestWindow();
  }
}

bool ClientUI::RunPointerScanBench(int seconds,
                                   int depth,
                                   const std::string& out_file,
                                   PointerBenchResult* out,
                                   bool use_index,
                                   bool strict_mode) {
  PointerBenchResult result{};
  result.depth = depth;
  result.use_index = use_index;
  result.strict_mode = strict_mode;

  auto fail = [&](const std::string& msg) {
    result.status = msg;
    if (out) {
      *out = result;
    }
    return false;
  };

  if (seconds <= 0) {
    seconds = 1;
  }
  if (depth <= 0) {
    depth = 3;
  }

  BenchIoStats io{};
  struct BenchScope {
    BenchIoStats* prev = nullptr;
    explicit BenchScope(BenchIoStats* now) {
      prev = g_bench_io_stats;
      g_bench_io_stats = now;
    }
    ~BenchScope() { g_bench_io_stats = prev; }
  } bench_scope(&io);

  if (!state_.connected) {
    const auto t = std::chrono::steady_clock::now();
    if (!ConnectToServer()) {
      return fail(u8"连接失败");
    }
    result.connect_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t).count();
  }
  if (!FetchProcesses()) {
    return fail(u8"进程列表获取失败");
  }
  uint32_t pid = 0;
  for (const auto& proc : state_.processes) {
    if (proc.name.find("com.r3.debugprobe") != std::string::npos) {
      pid = proc.pid;
      break;
    }
  }
  if (pid == 0) {
    if (!FetchProcesses()) {
      return fail(u8"进程列表刷新失败");
    }
    for (const auto& proc : state_.processes) {
      if (proc.name.find("com.r3.debugprobe") != std::string::npos) {
        pid = proc.pid;
        break;
      }
    }
  }
  if (pid == 0) {
    return fail(u8"未找到目标进程");
  }
  state_.pid = pid;
  std::snprintf(pid_input_, sizeof(pid_input_), "%u", pid);
  const auto attach_begin = std::chrono::steady_clock::now();
  if (!Attach()) {
    return fail(u8"打开进程失败");
  }
  result.attach_ms =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - attach_begin).count();

  if (!LoadAutoTargets()) {
    return fail(u8"auto_targets.txt 读取失败");
  }
  uint64_t target = 0;
  switch (depth) {
    case 3: target = auto_ptr3_value_addr_; break;
    case 5: target = auto_ptr5_value_addr_; break;
    case 7: target = auto_ptr7_value_addr_; break;
    case 10: target = auto_ptr10_value_addr_; break;
    default:
      target = auto_ptr5_value_addr_;
      depth = 5;
      result.depth = depth;
      break;
  }
  if (target == 0) {
    return fail(u8"目标地址无效");
  }

  if (state_.modules.empty()) {
    FetchModules();
  }
  if (state_.modules.empty()) {
    return fail(u8"模块列表为空");
  }
  SyncPointerModuleSelection();
  if (pointer_scan_module_selected_.size() != state_.modules.size()) {
    return fail(u8"模块选择初始化失败");
  }
  const uint64_t normalized = StripTag64(target);
  std::fill(pointer_scan_module_selected_.begin(), pointer_scan_module_selected_.end(), false);
  bool found_module = false;
  for (size_t i = 0; i < state_.modules.size(); ++i) {
    const auto& mod = state_.modules[i];
    if (normalized >= mod.start && normalized < mod.end) {
      pointer_scan_module_selected_[i] = true;
      found_module = true;
    }
  }
  if (!found_module) {
    return fail(u8"未找到目标模块");
  }

  std::snprintf(pointer_scan_target_, sizeof(pointer_scan_target_), "0x%llX",
                static_cast<unsigned long long>(target));
  pointer_scan_depth_ = depth;
  pointer_scan_max_offset_ = 0;
  pointer_scan_use_modules_ = true;
  pointer_scan_use_pvm_ = true;
  pointer_scan_allow_nonresident_ = true;
  pointer_scan_freeze_ = strict_mode;
  pointer_scan_byte_step_ = strict_mode;
  pointer_scan_use_index_ = use_index;
  pointer_scan_thread_count_ = 0;

  bool saved = false;
  bool module_scope_fallback = false;
  uint64_t total_chains = 0;
  uint64_t iterations = 0;
  const auto t0 = std::chrono::steady_clock::now();
  while (true) {
    const auto iter_begin = std::chrono::steady_clock::now();
    if (!RunPointerScan()) {
      const bool first_level_miss =
          pointer_scan_status_.find(u8"未找到第1层指针") != std::string::npos;
      if (!module_scope_fallback && pointer_scan_use_modules_ && first_level_miss) {
        pointer_scan_use_modules_ = false;
        module_scope_fallback = true;
        if (!RunPointerScan()) {
          return fail(pointer_scan_status_);
        }
      } else {
        return fail(pointer_scan_status_);
      }
    }
    result.scan_ms +=
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - iter_begin).count();
    iterations++;
    total_chains += pointer_scan_count_;

    if (!out_file.empty()) {
      if (!saved) {
        std::error_code ec;
        const auto out_path = std::filesystem::path(out_file);
        if (!out_path.parent_path().empty()) {
          std::filesystem::create_directories(out_path.parent_path(), ec);
        }
        std::filesystem::remove(out_file, ec);
        std::filesystem::rename(pointer_scan_output_path_, out_file, ec);
        if (ec) {
          std::error_code ec2;
          std::filesystem::copy_file(pointer_scan_output_path_,
                                     out_file,
                                     std::filesystem::copy_options::overwrite_existing,
                                     ec2);
          if (!ec2) {
            std::filesystem::remove(pointer_scan_output_path_, ec);
          }
        }
        pointer_scan_output_path_ = out_file;
        saved = true;
      } else {
        std::error_code ec;
        std::filesystem::remove(pointer_scan_output_path_, ec);
      }
    }

    if (seconds > 0) {
      const auto now = std::chrono::steady_clock::now();
      const double elapsed = std::chrono::duration<double>(now - t0).count();
      if (elapsed >= static_cast<double>(seconds)) {
        break;
      }
    }
  }

  const auto t1 = std::chrono::steady_clock::now();
  const double elapsed = std::chrono::duration<double>(t1 - t0).count();
  result.seconds = elapsed;
  result.iterations = iterations;
  result.chains = total_chains;
  result.ops_per_sec = elapsed > 0.0 ? static_cast<double>(total_chains) / elapsed : 0.0;
  result.net_packets = io.net_packets.load(std::memory_order_relaxed);
  result.net_req_bytes = io.net_req_bytes.load(std::memory_order_relaxed);
  result.net_rsp_bytes = io.net_rsp_bytes.load(std::memory_order_relaxed);
  result.read_calls = io.read_calls.load(std::memory_order_relaxed);
  result.read_bytes = io.read_bytes.load(std::memory_order_relaxed);
  const uint64_t chunk_total = io.chunk_samples.load(std::memory_order_relaxed);
  result.avg_chunk_bytes = result.read_calls > 0
                             ? static_cast<double>(chunk_total) / static_cast<double>(result.read_calls)
                             : 0.0;
  result.file = saved ? out_file : pointer_scan_output_path_;
  result.status = "ok";
  if (out) {
    *out = result;
  }
  return true;
}

bool ClientUI::RunPointerCompareBench(int seconds,
                                      int depth,
                                      const std::string& file_a,
                                      const std::string& file_b,
                                      PointerBenchResult* out) {
  PointerBenchResult result{};
  result.depth = depth;
  result.use_index = true;
  result.strict_mode = true;

  auto fail = [&](const std::string& msg) {
    result.status = msg;
    if (out) {
      *out = result;
    }
    return false;
  };

  if (seconds <= 0) {
    seconds = 1;
  }
  if (depth <= 0) {
    depth = 3;
  }

  BenchIoStats io{};
  struct BenchScope {
    BenchIoStats* prev = nullptr;
    explicit BenchScope(BenchIoStats* now) {
      prev = g_bench_io_stats;
      g_bench_io_stats = now;
    }
    ~BenchScope() { g_bench_io_stats = prev; }
  } bench_scope(&io);

  if (!state_.connected) {
    const auto t = std::chrono::steady_clock::now();
    if (!ConnectToServer()) {
      return fail(u8"连接失败");
    }
    result.connect_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t).count();
  }
  if (!FetchProcesses()) {
    return fail(u8"进程列表获取失败");
  }
  uint32_t pid = 0;
  for (const auto& proc : state_.processes) {
    if (proc.name.find("com.r3.debugprobe") != std::string::npos) {
      pid = proc.pid;
      break;
    }
  }
  if (pid == 0) {
    return fail(u8"未找到目标进程");
  }
  state_.pid = pid;
  std::snprintf(pid_input_, sizeof(pid_input_), "%u", pid);
  const auto attach_begin = std::chrono::steady_clock::now();
  if (!Attach()) {
    return fail(u8"打开进程失败");
  }
  result.attach_ms =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - attach_begin).count();

  std::string scan_file = file_a;
  if (scan_file.empty()) {
    scan_file = std::string("seach_point/bench_ptr_d") + std::to_string(depth) + ".r3p";
  }
  if (!std::filesystem::exists(scan_file)) {
    PointerBenchResult scan_result{};
    if (!RunPointerScanBench(1, depth, scan_file, &scan_result, true)) {
      return fail(scan_result.status.empty() ? u8"生成指针文件失败" : scan_result.status);
    }
  }

  pointer_compare_file_a_ = scan_file;
  if (!file_b.empty()) {
    pointer_compare_file_b_ = file_b;
  } else {
    pointer_compare_file_b_ = scan_file;
  }
  pointer_compare_multi_mode_ = false;
  pointer_compare_fast_mode_ = true;
  pointer_compare_use_pvm_ = false;
  pointer_compare_allow_nonresident_ = true;
  struct CompareBenchModeGuard {
    bool* flag = nullptr;
    bool prev = false;
    explicit CompareBenchModeGuard(bool* f) : flag(f), prev(f ? *f : false) {
      if (flag) {
        *flag = true;
      }
    }
    ~CompareBenchModeGuard() {
      if (flag) {
        *flag = prev;
      }
    }
  } compare_bench_guard(&pointer_compare_bench_mode_);

  bool hot_single_mode = false;
  PointerChain hot_chain;
  uint32_t hot_pointer_size = 0;
  uint16_t hot_depth = 0;
  std::vector<uint64_t> hot_targets;
  if (pointer_compare_file_a_ == pointer_compare_file_b_) {
    PointerFileHeader hot_hdr{};
    PointerChain first_chain{};
    std::string load_err;
    if (LoadFirstPointerChainFromFile(scan_file, &hot_hdr, &first_chain, &load_err) &&
        !first_chain.offsets.empty() &&
        first_chain.offsets.size() <= std::numeric_limits<uint16_t>::max() &&
        first_chain.offsets.size() == hot_hdr.depth) {
      std::ifstream ifs(scan_file, std::ios::binary);
      PointerFileHeader file_hdr{};
      if (ifs.is_open()) {
        ifs.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr));
        if (ifs.gcount() == static_cast<std::streamsize>(sizeof(file_hdr)) &&
            file_hdr.magic == kPointerMagic &&
            file_hdr.version == kPointerVersion &&
            ReadPointerTargets(ifs, file_hdr, &hot_targets)) {
          if (file_hdr.pointer_size == 4 || file_hdr.pointer_size == 8) {
            hot_pointer_size = file_hdr.pointer_size;
          } else if (state_.modules.empty() ? FetchModules() : true) {
            hot_pointer_size = GetPointerSizeFromModules();
          }
          if (hot_pointer_size == 8) {
            for (auto& t : hot_targets) {
              t = StripTag64(t);
            }
          }
          hot_targets.erase(std::remove(hot_targets.begin(), hot_targets.end(), 0), hot_targets.end());
          if (!hot_targets.empty()) {
            std::sort(hot_targets.begin(), hot_targets.end());
            hot_targets.erase(std::unique(hot_targets.begin(), hot_targets.end()), hot_targets.end());
            hot_chain = std::move(first_chain);
            hot_depth = static_cast<uint16_t>(hot_chain.offsets.size());
            hot_single_mode = hot_depth > 0 && (hot_pointer_size == 4 || hot_pointer_size == 8);
          }
        }
      }
    }
  }

  uint64_t total_chains = 0;
  uint64_t iterations = 0;
  const auto t0 = std::chrono::steady_clock::now();
  if (hot_single_mode) {
    uint32_t verify_flags = pointer_compare_use_pvm_ ? protocol::READ_FLAG_USE_PVM : 0;
    if (pointer_compare_allow_nonresident_) {
      verify_flags |= protocol::READ_FLAG_ALLOW_NONRESIDENT;
    }
    while (true) {
      const auto iter_begin = std::chrono::steady_clock::now();
      protocol::PointerVerifyBatchResult one{};
      if (!SendPointerVerifySingle(net_,
                                   hot_chain,
                                   hot_pointer_size,
                                   hot_depth,
                                   verify_flags,
                                   &one)) {
        return fail(u8"对比失败");
      }
      if (one.code == 0 &&
          std::binary_search(hot_targets.begin(), hot_targets.end(), one.address)) {
        total_chains++;
      }
      result.verify_ms +=
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - iter_begin).count();
      iterations++;

      if (seconds > 0) {
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - t0).count();
        if (elapsed >= static_cast<double>(seconds)) {
          break;
        }
      }
    }
  } else {
    while (true) {
      const auto iter_begin = std::chrono::steady_clock::now();
      if (!RunPointerCompare()) {
        return fail(pointer_compare_status_);
      }
      result.verify_ms +=
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - iter_begin).count();
      iterations++;
      total_chains += pointer_compare_count_;

      if (seconds > 0) {
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - t0).count();
        if (elapsed >= static_cast<double>(seconds)) {
          break;
        }
      }
    }
  }

  const auto t1 = std::chrono::steady_clock::now();
  const double elapsed = std::chrono::duration<double>(t1 - t0).count();
  result.seconds = elapsed;
  result.iterations = iterations;
  result.chains = total_chains;
  result.ops_per_sec = elapsed > 0.0 ? static_cast<double>(total_chains) / elapsed : 0.0;
  result.net_packets = io.net_packets.load(std::memory_order_relaxed);
  result.net_req_bytes = io.net_req_bytes.load(std::memory_order_relaxed);
  result.net_rsp_bytes = io.net_rsp_bytes.load(std::memory_order_relaxed);
  result.read_calls = io.read_calls.load(std::memory_order_relaxed);
  result.read_bytes = io.read_bytes.load(std::memory_order_relaxed);
  const uint64_t chunk_total = io.chunk_samples.load(std::memory_order_relaxed);
  result.avg_chunk_bytes = result.read_calls > 0
                             ? static_cast<double>(chunk_total) / static_cast<double>(result.read_calls)
                             : 0.0;
  result.file = scan_file;
  result.status = "ok";
  if (out) {
    *out = result;
  }
  return true;
}

bool ClientUI::RunPointerVerifyBench(int seconds,
                                     const std::string& file,
                                     PointerBenchResult* out) {
  PointerBenchResult result{};
  result.use_index = false;
  result.strict_mode = true;

  auto fail = [&](const std::string& msg) {
    result.status = msg;
    if (out) {
      *out = result;
    }
    return false;
  };

  if (seconds <= 0) {
    seconds = 1;
  }

  BenchIoStats io{};
  struct BenchScope {
    BenchIoStats* prev = nullptr;
    explicit BenchScope(BenchIoStats* now) {
      prev = g_bench_io_stats;
      g_bench_io_stats = now;
    }
    ~BenchScope() { g_bench_io_stats = prev; }
  } bench_scope(&io);

  if (!state_.connected) {
    const auto t = std::chrono::steady_clock::now();
    if (!ConnectToServer()) {
      return fail(u8"连接失败");
    }
    result.connect_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t).count();
  }
  if (!FetchProcesses()) {
    return fail(u8"进程列表获取失败");
  }
  uint32_t pid = 0;
  for (const auto& proc : state_.processes) {
    if (proc.name.find("com.r3.debugprobe") != std::string::npos) {
      pid = proc.pid;
      break;
    }
  }
  if (pid == 0) {
    return fail(u8"未找到目标进程");
  }
  state_.pid = pid;
  std::snprintf(pid_input_, sizeof(pid_input_), "%u", pid);
  const auto attach_begin = std::chrono::steady_clock::now();
  if (!Attach()) {
    return fail(u8"打开进程失败");
  }
  result.attach_ms =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - attach_begin).count();

  std::string scan_file = file;
  if (scan_file.empty()) {
    scan_file = "seach_point/bench_ptr_d5.r3p";
  }
  PointerFileHeader hdr{};
  PointerChain chain{};
  std::string err;
  if (!LoadFirstPointerChainFromFile(scan_file, &hdr, &chain, &err)) {
    return fail(err.empty() ? u8"读取指针链失败" : err);
  }

  result.depth = static_cast<int>(hdr.depth);
  std::snprintf(pointer_verify_addr_, sizeof(pointer_verify_addr_), "0x%llX",
                static_cast<unsigned long long>(chain.base));
  pointer_verify_offsets_ = chain.offsets;
  pointer_verify_type_ = 3; // U64
  pointer_verify_hex_ = true;
  pointer_verify_signed_ = false;
  pointer_verify_is_pointer_ = true;
  pointer_verify_use_pvm_ = true;
  pointer_verify_allow_nonresident_ = true;
  struct VerifyBenchModeGuard {
    bool* flag = nullptr;
    bool prev = false;
    explicit VerifyBenchModeGuard(bool* f) : flag(f), prev(f ? *f : false) {
      if (flag) {
        *flag = true;
      }
    }
    ~VerifyBenchModeGuard() {
      if (flag) {
        *flag = prev;
      }
    }
  } verify_bench_guard(&pointer_verify_bench_mode_);

  uint64_t iterations = 0;
  const auto t0 = std::chrono::steady_clock::now();
  while (true) {
    const auto iter_begin = std::chrono::steady_clock::now();
    if (!RunPointerVerify()) {
      return fail(pointer_verify_status_);
    }
    result.verify_ms +=
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - iter_begin).count();
    iterations++;
    if (seconds > 0) {
      const auto now = std::chrono::steady_clock::now();
      const double elapsed = std::chrono::duration<double>(now - t0).count();
      if (elapsed >= static_cast<double>(seconds)) {
        break;
      }
    }
  }

  const auto t1 = std::chrono::steady_clock::now();
  const double elapsed = std::chrono::duration<double>(t1 - t0).count();
  result.seconds = elapsed;
  result.iterations = iterations;
  result.chains = iterations;
  result.ops_per_sec = elapsed > 0.0 ? static_cast<double>(iterations) / elapsed : 0.0;
  result.net_packets = io.net_packets.load(std::memory_order_relaxed);
  result.net_req_bytes = io.net_req_bytes.load(std::memory_order_relaxed);
  result.net_rsp_bytes = io.net_rsp_bytes.load(std::memory_order_relaxed);
  result.read_calls = io.read_calls.load(std::memory_order_relaxed);
  result.read_bytes = io.read_bytes.load(std::memory_order_relaxed);
  const uint64_t chunk_total = io.chunk_samples.load(std::memory_order_relaxed);
  result.avg_chunk_bytes = result.read_calls > 0
                             ? static_cast<double>(chunk_total) / static_cast<double>(result.read_calls)
                             : 0.0;
  result.file = scan_file;
  result.status = "ok";
  if (out) {
    *out = result;
  }
  return true;
}

bool ClientUI::ConnectToServer() {
  state_.connected = net_.Connect(host_, static_cast<uint16_t>(port_));
  state_.status = state_.connected ? u8"已连接" : u8"连接失败";
  return state_.connected;
}

void ClientUI::DisconnectFromServer() {
  net_.Disconnect();
  state_.connected = false;
  state_.status = u8"已断开";
}

void ClientUI::StartAutoTest() {
  auto_running_ = true;
  auto_done_ = false;
  auto_step_ = 0;
  auto_retry_ = 0;
  auto_target_addr_ = 0;
  auto_original_value_ = 0;
  auto_have_original_ = false;
  auto_rw_region_ = 0;
  auto_perf_write_addr_ = 0;
  auto_perf_original_value_ = 0;
  auto_perf_has_original_ = false;
  auto_perf_write_done_ = false;
  auto_ptr3_value_addr_ = 0;
  auto_ptr5_value_addr_ = 0;
  auto_ptr7_value_addr_ = 0;
  auto_ptr10_value_addr_ = 0;
  auto_ptr_exec_addr_ = 0;
  auto_ptrace_fallback_used_ = false;
  auto_ptr_exec_addr_ = 0;
  auto_ptr7_value_addr_ = 0;
  auto_ptr10_value_addr_ = 0;
  auto_ptr_file_a_.clear();
  auto_ptr_file_b_.clear();
  auto_logs_.clear();
  AutoLog(u8"自动测试开始");
}

void ClientUI::AutoLog(const std::string& line) {
  auto_logs_.push_back(line);
  std::ofstream ofs(auto_log_path_, std::ios::out | std::ios::app);
  if (ofs.is_open()) {
    ofs << line << "\n";
  }
}

void ClientUI::RunAutoTest() {
  if (!auto_running_) {
    return;
  }

  auto select_pointer_modules_for_addr = [&](uint64_t addr) -> bool {
    if (state_.modules.empty()) {
      FetchModules();
    }
    if (state_.modules.empty()) {
      return false;
    }
    SyncPointerModuleSelection();
    if (pointer_scan_module_selected_.size() != state_.modules.size()) {
      return false;
    }
    const uint64_t normalized = StripTag64(addr);
    std::fill(pointer_scan_module_selected_.begin(), pointer_scan_module_selected_.end(), false);
    bool found = false;
    for (size_t i = 0; i < state_.modules.size(); ++i) {
      const auto& mod = state_.modules[i];
      if (normalized >= mod.start && normalized < mod.end) {
        pointer_scan_module_selected_[i] = true;
        found = true;
      }
    }
    return found;
  };

  auto fail = [&](const char* msg) {
    state_.status = msg;
    AutoLog(msg);
    auto_running_ = false;
    auto_done_ = true;
    if (auto_mode_) {
      request_quit_ = true;
    }
  };

  switch (auto_step_) {
    case 0: {
      AutoLog(u8"步骤1：连接服务");
      if (!state_.connected && !ConnectToServer()) {
        fail(u8"自动测试失败：连接服务失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 1: {
      AutoLog(u8"步骤2：获取进程列表");
      if (!FetchProcesses()) {
        fail(u8"自动测试失败：进程列表获取失败");
        return;
      }
      auto find_target = [&]() -> uint32_t {
        for (const auto& proc : state_.processes) {
          if (proc.name.find("com.r3.debugprobe") != std::string::npos) {
            return proc.pid;
          }
        }
        return 0;
      };
      uint32_t target_pid = find_target();
      if (target_pid == 0) {
        AutoLog(u8"未找到目标进程，尝试再次刷新");
        if (!FetchProcesses()) {
          fail(u8"自动测试失败：二次刷新进程列表失败");
          return;
        }
        target_pid = find_target();
      }
      if (target_pid == 0) {
        fail(u8"自动测试失败：未找到 com.r3.debugprobe");
        return;
      }
      std::snprintf(pid_input_, sizeof(pid_input_), "%u", target_pid);
      state_.pid = target_pid;
      AutoLog(std::string(u8"目标进程PID：") + pid_input_);
      auto_step_++;
      return;
    }
    case 2: {
      AutoLog(u8"步骤3：打开进程");
      if (!Attach()) {
        fail(u8"自动测试失败：打开进程失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 3: {
      AutoLog(u8"步骤4：附加调试器(ptrace)");
      if (!DebugAttach(true)) {
        auto_retry_++;
        AutoLog(u8"附加调试器失败，准备重试");
        if (auto_retry_ < 3) {
          Sleep(200);
          return;
        }
        AutoLog(u8"附加调试器失败，跳过调试功能测试");
        auto_retry_ = 0;
        auto_step_ = 6;
        return;
      }
      auto_retry_ = 0;
      auto_step_++;
      return;
    }
    case 4: {
      AutoLog(u8"步骤5：读取寄存器");
      if (!FetchRegs()) {
        fail(u8"自动测试失败：读取寄存器失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 5: {
      AutoLog(u8"步骤6：调试分离");
      if (!DebugDetach()) {
        fail(u8"自动测试失败：调试分离失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 6: {
      AutoLog(u8"步骤7：首次扫描(U32=0xDEADBEEF)");
      state_.value_type = protocol::ValueType::U32;
      state_.condition = protocol::ComparisonType::EQ;
      std::snprintf(value_input_, sizeof(value_input_), "0xDEADBEEF");
      std::snprintf(scan_start_, sizeof(scan_start_), "");
      std::snprintf(scan_end_, sizeof(scan_end_), "");
      if (!ScanFirst()) {
        fail(u8"自动测试失败：首次扫描失败");
        return;
      }
      if (state_.scan_total == 0) {
        fail(u8"自动测试失败：扫描结果为空");
        return;
      }
      if (!state_.page_addresses.empty()) {
        auto_target_addr_ = state_.page_addresses[0];
      }
      auto_step_++;
      return;
    }
    case 7: {
      AutoLog(u8"步骤8：获取扫描分页");
      if (auto_target_addr_ == 0) {
        if (!ScanPage()) {
          fail(u8"自动测试失败：扫描分页失败");
          return;
        }
        if (state_.page_addresses.empty()) {
          fail(u8"自动测试失败：分页结果为空");
          return;
        }
        auto_target_addr_ = state_.page_addresses[0];
      }
      AutoLog(u8"选定扫描地址已更新");
      auto_step_++;
      return;
    }
    case 8: {
      AutoLog(u8"步骤9：读取内存");
      std::snprintf(mem_addr_, sizeof(mem_addr_), "0x%llX",
                    static_cast<unsigned long long>(auto_target_addr_));
      mem_size_ = 16;
      if (!ReadMemory()) {
        fail(u8"自动测试失败：读取内存失败");
        return;
      }
      auto_have_original_ = false;
      if (state_.mem_view_data.size() >= 4) {
        std::memcpy(&auto_original_value_, state_.mem_view_data.data(), sizeof(auto_original_value_));
        auto_have_original_ = true;
      }
      auto_step_++;
      return;
    }
    case 9: {
      AutoLog(u8"步骤10：写入内存(0xABCD1234)");
      std::snprintf(write_data_, sizeof(write_data_), "34 12 CD AB");
      write_format_ = 6; // hex
      bool wrote = false;
      const size_t limit = std::min<size_t>(state_.page_addresses.size(), 16);
      if (limit == 0) {
        std::snprintf(write_addr_, sizeof(write_addr_), "0x%llX",
                      static_cast<unsigned long long>(auto_target_addr_));
        wrote = WriteMemory();
      } else {
        for (size_t i = 0; i < limit; ++i) {
          const uint64_t addr = state_.page_addresses[i];
          std::snprintf(write_addr_, sizeof(write_addr_), "0x%llX",
                        static_cast<unsigned long long>(addr));
          if (WriteMemory()) {
            auto_target_addr_ = addr;
            wrote = true;
            break;
          }
        }
      }
      if (!wrote) {
        fail(u8"自动测试失败：写入内存失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 10: {
      AutoLog(u8"步骤11：读取验证");
      std::snprintf(mem_addr_, sizeof(mem_addr_), "0x%llX",
                    static_cast<unsigned long long>(auto_target_addr_));
      mem_size_ = 16;
      if (!ReadMemory()) {
        fail(u8"自动测试失败：验证读取失败");
        return;
      }
      if (state_.mem_view_data.size() >= 4) {
        uint32_t val = 0;
        std::memcpy(&val, state_.mem_view_data.data(), sizeof(val));
        if (val != 0xABCD1234u) {
          fail(u8"自动测试失败：写入验证不一致");
          return;
        }
      }
      auto_step_++;
      return;
    }
    case 11: {
      AutoLog(u8"步骤12：再次扫描(U32=0xABCD1234)");
      state_.value_type = protocol::ValueType::U32;
      state_.condition = protocol::ComparisonType::EQ;
      std::snprintf(value_input_, sizeof(value_input_), "0xABCD1234");
      if (!ScanNext()) {
        fail(u8"自动测试失败：再次扫描失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 12: {
      AutoLog(u8"步骤13：分页获取");
      if (!ScanPage()) {
        fail(u8"自动测试失败：分页获取失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 13: {
      AutoLog(u8"步骤14：写回原值");
      if (auto_have_original_) {
        std::snprintf(write_addr_, sizeof(write_addr_), "0x%llX",
                      static_cast<unsigned long long>(auto_target_addr_));
        std::snprintf(write_data_, sizeof(write_data_), "%02X %02X %02X %02X",
                      static_cast<unsigned>(auto_original_value_ & 0xFF),
                      static_cast<unsigned>((auto_original_value_ >> 8) & 0xFF),
                      static_cast<unsigned>((auto_original_value_ >> 16) & 0xFF),
                      static_cast<unsigned>((auto_original_value_ >> 24) & 0xFF));
        if (!WriteMemory()) {
          fail(u8"自动测试失败：写回原值失败");
          return;
        }
      }
      auto_step_++;
      return;
    }
    case 14: {
      AutoLog(u8"步骤15：加载测试地址(auto_targets.txt)");
      if (!LoadAutoTargets()) {
        fail(u8"自动测试失败：加载测试地址失败");
        return;
      }
      auto_step_++;
      return;
    }
    case 15: {
      AutoLog(u8"步骤16：数据遍历测试");
      const uint64_t addr = auto_rw_region_ ? (auto_rw_region_ + 0x100) : 0;
      if (addr == 0) {
        fail(u8"自动测试失败：数据遍历地址无效");
        return;
      }
      std::snprintf(data_traverse_addr_, sizeof(data_traverse_addr_), "0x%llX",
                    static_cast<unsigned long long>(addr));
      data_traverse_count_ = 8;
      data_traverse_stride_ = 4;
      data_traverse_type_ = 2; // U32
      data_traverse_use_pvm_ = true;
      if (!RunDataTraverse()) {
        fail(u8"自动测试失败：数据遍历失败");
        return;
      }
      if (data_traverse_entries_.empty()) {
        fail(u8"自动测试失败：数据遍历结果为空");
        return;
      }
      auto_step_++;
      return;
    }
      case 16: {
        AutoLog(u8"步骤17：指针验证");
        if (auto_target_addr_ == 0) {
          fail(u8"自动测试失败：指针验证地址无效");
          return;
        }
        std::snprintf(pointer_verify_addr_, sizeof(pointer_verify_addr_), "0x%llX",
                      static_cast<unsigned long long>(auto_target_addr_));
        pointer_verify_type_ = 2; // U32
        pointer_verify_hex_ = true;
        pointer_verify_signed_ = false;
        pointer_verify_is_pointer_ = false;
        pointer_verify_use_pvm_ = true;
        pointer_verify_allow_nonresident_ = true;
        pointer_verify_offsets_.clear();
        if (!RunPointerVerify()) {
          fail(u8"自动测试失败：指针验证失败");
          return;
        }
        auto_step_++;
        return;
      }
      case 17: {
        AutoLog(u8"步骤18：指针扫描(链3)");
        std::snprintf(pointer_scan_target_, sizeof(pointer_scan_target_), "0x%llX",
                      static_cast<unsigned long long>(auto_ptr3_value_addr_));
        pointer_scan_depth_ = 3;
        pointer_scan_max_offset_ = 0;
        pointer_scan_use_modules_ = true;
        pointer_scan_use_pvm_ = true;
        pointer_scan_allow_nonresident_ = true;
        pointer_scan_freeze_ = true;
        pointer_scan_byte_step_ = true;
        pointer_scan_use_index_ = false;
        if (!select_pointer_modules_for_addr(auto_ptr3_value_addr_)) {
          fail(u8"自动测试失败：指针扫描未找到目标模块");
          return;
        }
        if (!RunPointerScan()) {
          const bool first_level_miss =
              pointer_scan_status_.find(u8"未找到第1层指针") != std::string::npos;
          if (pointer_scan_use_modules_ && first_level_miss) {
            AutoLog(u8"链3首层未命中，回退到全模块重试");
            pointer_scan_use_modules_ = false;
            if (!RunPointerScan()) {
              const std::string msg = pointer_scan_status_.empty()
                                        ? u8"自动测试失败：指针扫描(链3)失败"
                                        : std::string(u8"自动测试失败：指针扫描(链3)失败: ") + pointer_scan_status_;
              fail(msg.c_str());
              return;
            }
          } else {
            const std::string msg = pointer_scan_status_.empty()
                                      ? u8"自动测试失败：指针扫描(链3)失败"
                                      : std::string(u8"自动测试失败：指针扫描(链3)失败: ") + pointer_scan_status_;
            fail(msg.c_str());
            return;
          }
        }
        if (pointer_scan_count_ == 0 || pointer_scan_output_path_.empty()) {
          fail(u8"自动测试失败：指针扫描(链3)结果为空");
          return;
        }
        auto_ptr_file_a_ = pointer_scan_output_path_;
        auto_step_++;
        return;
      }
      case 18: {
        AutoLog(u8"步骤19：指针扫描(链5)");
        std::snprintf(pointer_scan_target_, sizeof(pointer_scan_target_), "0x%llX",
                      static_cast<unsigned long long>(auto_ptr5_value_addr_));
        pointer_scan_depth_ = 5;
        pointer_scan_max_offset_ = 0;
        pointer_scan_use_modules_ = true;
        pointer_scan_use_pvm_ = true;
        pointer_scan_allow_nonresident_ = true;
        pointer_scan_freeze_ = true;
        pointer_scan_byte_step_ = true;
        pointer_scan_use_index_ = false;
        if (!select_pointer_modules_for_addr(auto_ptr5_value_addr_)) {
          fail(u8"自动测试失败：指针扫描未找到目标模块");
          return;
        }
        if (!RunPointerScan()) {
          const bool first_level_miss =
              pointer_scan_status_.find(u8"未找到第1层指针") != std::string::npos;
          if (pointer_scan_use_modules_ && first_level_miss) {
            AutoLog(u8"链5首层未命中，回退到全模块重试");
            pointer_scan_use_modules_ = false;
            if (!RunPointerScan()) {
              const std::string msg = pointer_scan_status_.empty()
                                        ? u8"自动测试失败：指针扫描(链5)失败"
                                        : std::string(u8"自动测试失败：指针扫描(链5)失败: ") + pointer_scan_status_;
              fail(msg.c_str());
              return;
            }
          } else {
            const std::string msg = pointer_scan_status_.empty()
                                      ? u8"自动测试失败：指针扫描(链5)失败"
                                      : std::string(u8"自动测试失败：指针扫描(链5)失败: ") + pointer_scan_status_;
            fail(msg.c_str());
            return;
          }
        }
        if (pointer_scan_count_ == 0 || pointer_scan_output_path_.empty()) {
          fail(u8"自动测试失败：指针扫描(链5)结果为空");
          return;
        }
        auto_ptr_file_b_ = pointer_scan_output_path_;
        auto_step_++;
        return;
      }
    case 19: {
      AutoLog(u8"步骤20：指针对比");
      pointer_compare_file_a_ = auto_ptr_file_a_.empty() ? auto_ptr_file_b_ : auto_ptr_file_a_;
      pointer_compare_file_b_ = pointer_compare_file_a_;
      pointer_compare_multi_mode_ = false;
      pointer_compare_fast_mode_ = true;
      pointer_compare_use_pvm_ = true;
      pointer_compare_allow_nonresident_ = true;
      if (pointer_compare_file_a_.empty()) {
        fail(u8"自动测试失败：指针对比缺少输入文件");
        return;
      }
      if (!RunPointerCompare()) {
        fail(u8"自动测试失败：指针对比失败");
        return;
      }
      if (pointer_compare_count_ == 0) {
        fail(u8"自动测试失败：指针对比结果为空");
        return;
      }
      auto_step_++;
      return;
    }
    case 20: {
      if (auto_retry_ == 0) {
        AutoLog(u8"步骤21：perf 断点测试(写入)");
      }
      if (auto_rw_region_ == 0) {
        fail(u8"自动测试失败：断点地址无效");
        return;
      }
      auto restore_perf_value = [&]() {
        if (!auto_perf_has_original_ || !auto_perf_write_done_ || auto_perf_write_addr_ == 0) {
          return;
        }
        std::vector<uint8_t> bytes(sizeof(auto_perf_original_value_));
        std::memcpy(bytes.data(), &auto_perf_original_value_, sizeof(auto_perf_original_value_));
        WriteMemoryBytes(auto_perf_write_addr_, bytes);
      };
      auto trigger_perf_write = [&]() {
        if (auto_perf_write_addr_ == 0) {
          return;
        }
        uint32_t value = 0;
        if (auto_perf_has_original_) {
          const uint32_t mask = (auto_retry_ & 1) ? 0x01010101u : 0x02020202u;
          value = auto_perf_original_value_ ^ mask;
        } else {
          value = (auto_retry_ & 1) ? 0xA5A5A5A5u : 0x5A5A5A5Au;
        }
        std::vector<uint8_t> bytes(sizeof(value));
        std::memcpy(bytes.data(), &value, sizeof(value));
        if (WriteMemoryBytes(auto_perf_write_addr_, bytes)) {
          auto_perf_write_done_ = true;
        }
      };
      if (auto_retry_ == 0) {
        breakpoints_.clear();
        breakpoint_selected_ = -1;
        BreakpointEntry bp{};
        bp.addr = auto_rw_region_ + 0x100;
        bp.type = static_cast<int>(protocol::DEBUG_BP_WRITE);
        bp.size = 4;
        bp.enabled = true;
        bp.hit_count = 0;
        breakpoints_.push_back(bp);
        breakpoint_backend_ = 1; // perf
        breakpoint_stop_on_hit_ = false;
        if (!ApplyBreakpoints(true, false)) {
          AutoLog(std::string(u8"perf 断点设置失败，跳过 perf 测试: ") + breakpoint_status_);
          auto_retry_ = 0;
          auto_step_++;
          return;
        }
        auto_perf_write_addr_ = auto_rw_region_ + 0x100;
        auto_perf_has_original_ = false;
        auto_perf_write_done_ = false;
        std::vector<uint8_t> cur;
        if (ReadMemoryRangeEx(auto_perf_write_addr_,
                              static_cast<uint32_t>(sizeof(auto_perf_original_value_)),
                              &cur,
                              false,
                              false,
                              address_list_use_pvm_) &&
            cur.size() >= sizeof(auto_perf_original_value_)) {
          std::memcpy(&auto_perf_original_value_, cur.data(), sizeof(auto_perf_original_value_));
          auto_perf_has_original_ = true;
        }
        trigger_perf_write();
      }
      auto_retry_++;
      Sleep(200);
      PollBreakpoints();
      if (!breakpoints_.empty() && breakpoints_[0].hit_count > 0) {
        AutoLog(u8"perf 断点命中");
        restore_perf_value();
        auto_retry_ = 0;
        auto_step_++;
        return;
      }
      if (auto_retry_ % 5 == 0) {
        trigger_perf_write();
      }
      if (auto_retry_ > 20) {
        AutoLog(u8"perf 断点无命中，跳过 perf 测试");
        restore_perf_value();
        auto_retry_ = 0;
        auto_step_++;
        return;
      }
      return;
    }
    case 21: {
      if (auto_retry_ == 0) {
        AutoLog(u8"步骤22：ptrace 断点测试(执行)");
      }
      if (auto_retry_ == 0) {
        breakpoints_.clear();
        breakpoint_selected_ = -1;
        uint64_t exec_addr = auto_ptr_exec_addr_;
        if (exec_addr == 0 && FetchRegs() && state_.regs_valid) {
          if (state_.regs_arch == protocol::RegsArch::ARM64) {
            exec_addr = state_.regs64.pc;
          } else if (state_.regs_arch == protocol::RegsArch::ARM32) {
            exec_addr = state_.regs32.regs[15];
          }
        }
        if (exec_addr == 0) {
          fail(u8"自动测试失败：ptrace 断点地址无效");
          return;
        }
        auto_ptr_exec_addr_ = exec_addr;
        BreakpointEntry bp{};
        bp.addr = exec_addr;
        bp.type = static_cast<int>(protocol::DEBUG_BP_EXEC);
        bp.size = 4;
        bp.enabled = true;
        bp.hit_count = 0;
        breakpoints_.push_back(bp);
        breakpoint_backend_ = auto_ptrace_fallback_used_ ? 1 : 0; // perf when ptrace fallback is used
        breakpoint_stop_on_hit_ = false;
        if (!ApplyBreakpoints(true, false)) {
          AutoLog(std::string(u8"执行断点设置失败，跳过执行断点测试: ") + breakpoint_status_);
          auto_retry_ = 0;
          auto_step_++;
          return;
        }
      }
      auto_retry_++;
      Sleep(200);
      PollBreakpoints();
      if (!breakpoints_.empty() && breakpoints_[0].hit_count > 0) {
        AutoLog(u8"ptrace 断点命中");
        auto_retry_ = 0;
        auto_step_++;
        return;
      }
      if (auto_retry_ > 20) {
        if (!auto_ptrace_fallback_used_) {
          AutoLog(u8"ptrace 断点无命中，尝试 perf 执行断点");
          auto_ptrace_fallback_used_ = true;
          breakpoint_backend_ = 1; // perf
          if (!ApplyBreakpoints(true, false)) {
            fail(u8"自动测试失败：ptrace 无命中且 perf 执行断点设置失败");
            return;
          }
          auto_retry_ = 0;
          return;
        }
        fail(u8"自动测试失败：执行断点无命中");
        return;
      }
      return;
    }
    default: {
      AutoLog(u8"自动测试完成");
      auto_running_ = false;
      auto_done_ = true;
      if (auto_mode_) {
        request_quit_ = true;
      }
      return;
    }
  }
}

uint64_t ClientUI::ParseAddressWithBase(const std::string& text, bool force_hex) const {
  const char* str = text.c_str();
  char* endptr = nullptr;
  const int base = force_hex ? 16 : 0;
  uint64_t value = std::strtoull(str, &endptr, base);
  if (endptr == str) {
    return 0;
  }
  return value;
}

uint64_t ClientUI::ParseAddress(const std::string& text) const {
  return ParseAddressWithBase(text, address_default_hex_);
}

uint64_t ClientUI::GetProgramCounterAddress() const {
  if (!state_.regs_valid) {
    return 0;
  }
  if (state_.regs_arch == protocol::RegsArch::ARM64) {
    return state_.regs64.pc;
  }
  if (state_.regs_arch == protocol::RegsArch::ARM32) {
    return state_.regs32.regs[15];
  }
  return 0;
}

void ClientUI::OpenMemoryWorkspaceAt(uint64_t addr, bool read_memory, bool open_disasm) {
  show_memory_window_ = true;
  if (addr == 0) {
    addr = ParseAddress(disasm_addr_);
  }
  if (addr == 0) {
    addr = ParseAddress(mem_addr_);
  }
  if (addr == 0) {
    addr = GetProgramCounterAddress();
    if (addr == 0 && state_.connected && state_.pid != 0) {
      if (FetchRegs()) {
        addr = GetProgramCounterAddress();
      }
    }
  }
  if (addr == 0) {
    return;
  }

  std::snprintf(mem_addr_, sizeof(mem_addr_), "0x%llX",
                static_cast<unsigned long long>(addr));
  std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0x%llX",
                static_cast<unsigned long long>(addr));
  std::snprintf(disasm_jump_addr_, sizeof(disasm_jump_addr_), "0x%llX",
                static_cast<unsigned long long>(addr));

  if (read_memory) {
    ReadMemory();
  }
  if (open_disasm) {
    if (disasm_size_ < 64) {
      disasm_size_ = 64;
    }
    RunDisasm(addr);
  }
}

bool ClientUI::BuildValueBytes(std::vector<uint8_t>* out) const {
  if (!out) {
    return false;
  }
  return ParseValueForType(state_.value_type, value_input_, out, address_list_hex_);
}

bool ClientUI::ParseHexBytes(const char* text, std::vector<uint8_t>* out) const {
  if (!out) {
    return false;
  }
  out->clear();
  int high = -1;
  for (const char* p = text; *p; ++p) {
    char c = *p;
    if (std::isspace(static_cast<unsigned char>(c)) || c == ',' || c == '-') {
      continue;
    }
    int v = -1;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else return false;

    if (high < 0) {
      high = v;
    } else {
      out->push_back(static_cast<uint8_t>((high << 4) | v));
      high = -1;
    }
  }
  return high < 0 && !out->empty();
}

void ClientUI::RefreshScanPreviewValues() {
  scan_preview_values_.clear();
  if (!state_.connected || state_.page_addresses.empty()) {
    return;
  }

  const size_t value_size = ValueTypeSize(state_.value_type);

  scan_preview_values_.reserve(state_.page_addresses.size());
  for (uint64_t addr : state_.page_addresses) {
    std::vector<uint8_t> data;
    std::string text = u8"<读取失败>";
    if (ReadMemoryRangeEx(addr, static_cast<uint32_t>(value_size), &data, false, false, scan_use_pvm_) &&
        data.size() >= value_size) {
      text = FormatValueTextMode(state_.value_type, data.data(), data.size(), address_list_hex_);
    }
    scan_preview_values_.push_back(std::move(text));
  }
}

void ClientUI::AddAddressEntry(uint64_t addr, protocol::ValueType type, const char* desc) {
  AddressEntry entry;
  entry.active = true;
  entry.addr = addr;
  entry.type = type;
  entry.value_display.clear();
  entry.value_input[0] = '\0';
  entry.value_dirty = false;
  entry.freeze_has_value = false;
  entry.freeze_bytes.clear();
  entry.last_read_bytes.clear();
  entry.freeze_failed = false;
  entry.freeze_error.clear();
  if (desc && desc[0]) {
    std::snprintf(entry.desc, sizeof(entry.desc), "%s", desc);
  } else {
    entry.desc[0] = '\0';
  }
  address_list_.push_back(entry);
  address_list_selected_ = static_cast<int>(address_list_.size()) - 1;
}

void ClientUI::RefreshAddressListValues(bool force) {
  address_list_status_.clear();
  if (!force && !address_list_auto_refresh_) {
    return;
  }
  if (!state_.connected) {
    address_list_status_ = u8"未连接";
    return;
  }
  if (state_.pid == 0) {
    address_list_status_ = u8"请先打开进程";
    return;
  }
  for (auto& entry : address_list_) {
    const size_t size = ValueTypeSize(entry.type);
    std::vector<uint8_t> data;
    if (!ReadMemoryRangeEx(entry.addr,
                           static_cast<uint32_t>(size),
                           &data,
                           false,
                           false,
                           address_list_use_pvm_) ||
        data.size() < size) {
      entry.value_display = u8"<读取失败>";
      continue;
    }
    entry.last_read_bytes = data;
    entry.value_display = FormatValueTextMode(entry.type, data.data(), data.size(), address_list_hex_);
    if (!entry.value_dirty) {
      std::snprintf(entry.value_input, sizeof(entry.value_input), "%s", entry.value_display.c_str());
    }
    if (entry.active && !entry.freeze_has_value && !entry.last_read_bytes.empty()) {
      entry.freeze_bytes = entry.last_read_bytes;
      entry.freeze_has_value = true;
    }
  }
  address_list_status_ = u8"已刷新";
}

bool ClientUI::LoadAutoTargets() {
  auto_rw_region_ = 0;
  auto_ptr3_value_addr_ = 0;
  auto_ptr5_value_addr_ = 0;
  auto_ptr7_value_addr_ = 0;
  auto_ptr10_value_addr_ = 0;
  auto_ptr_exec_addr_ = 0;

  std::vector<std::filesystem::path> candidates;
  candidates.emplace_back(std::filesystem::current_path() / "seach_point" / "auto_targets.txt");
  const auto exe_dir = GetExeDir();
  if (exe_dir != std::filesystem::current_path()) {
    candidates.emplace_back(exe_dir / "seach_point" / "auto_targets.txt");
  }
  std::ifstream ifs;
  for (const auto& path : candidates) {
    ifs.open(path);
    if (ifs.is_open()) {
      break;
    }
    ifs.clear();
  }
  if (!ifs.is_open()) {
    AutoLog(u8"自动测试失败：未找到 auto_targets.txt");
    return false;
  }
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.empty()) {
      continue;
    }
    const size_t pos = line.find('=');
    if (pos == std::string::npos) {
      continue;
    }
    std::string key = line.substr(0, pos);
    std::string value = line.substr(pos + 1);
    if (value.empty()) {
      continue;
    }
    uint64_t addr = ParseAddressWithBase(value, true);
    if (addr == 0) {
      continue;
    }
    if (key == "rw_region") {
      auto_rw_region_ = addr;
    } else if (key == "ptr_chain_3_value_addr") {
      auto_ptr3_value_addr_ = addr;
    } else if (key == "ptr_chain_5_value_addr") {
      auto_ptr5_value_addr_ = addr;
    } else if (key == "ptr_chain_7_value_addr") {
      auto_ptr7_value_addr_ = addr;
    } else if (key == "ptr_chain_10_value_addr") {
      auto_ptr10_value_addr_ = addr;
    } else if (key == "ptrace_exec_addr") {
      auto_ptr_exec_addr_ = addr;
    }
  }
  if (auto_rw_region_ == 0 || auto_ptr3_value_addr_ == 0 || auto_ptr5_value_addr_ == 0) {
    AutoLog(u8"自动测试失败：auto_targets.txt 解析不完整");
    return false;
  }
  return true;
}

bool ClientUI::IsReadableAddress(uint64_t addr,
                                 uint64_t size,
                                 const ClientState::ModuleInfo** out_mod) const {
  if (out_mod) {
    *out_mod = nullptr;
  }
  if (size == 0 || state_.modules.empty()) {
    return false;
  }
  const uint64_t end = addr + size;
  if (end < addr) {
    return false;
  }
  for (const auto& mod : state_.modules) {
    if ((mod.perms & protocol::MODULE_PERM_READ) == 0) {
      continue;
    }
    if (mod.end <= addr || mod.start >= end) {
      continue;
    }
    if (out_mod) {
      *out_mod = &mod;
    }
    return true;
  }
  return false;
}

uint64_t ClientUI::ComputeAppBaseHigh() const {
  if (state_.modules.empty()) {
    return 0;
  }
  std::unordered_map<uint64_t, size_t> counts;
  for (const auto& mod : state_.modules) {
    if ((mod.perms & protocol::MODULE_PERM_READ) == 0) {
      continue;
    }
    const uint64_t high = mod.start & 0xFFFFFFFF00000000ull;
    counts[high]++;
  }
  size_t best_count = 0;
  uint64_t best = 0;
  for (const auto& it : counts) {
    if (it.second > best_count) {
      best_count = it.second;
      best = it.first;
    }
  }
  return best;
}

void ClientUI::UpdateAppBaseHigh() {
  app_base_high_ = ComputeAppBaseHigh();
}

bool ClientUI::BuildTraverseEntries(uint64_t base,
                                    int count,
                                    int stride,
                                    int type,
                                    bool use_pvm,
                                    std::vector<DataTraverseEntry>* out,
                                    std::string* out_status) {
  if (!out) {
    return false;
  }
  out->clear();
  if (out_status) {
    out_status->clear();
  }
  if (!state_.connected) {
    if (out_status) {
      *out_status = u8"未连接";
    }
    return false;
  }

  if (count < 1) {
    count = 1;
  }
  if (stride < 1) {
    stride = 1;
  }

  const uint32_t pointer_size = GetPointerSizeFromModules();
  size_t type_size = 4;
  switch (type) {
    case 0: type_size = 1; break;
    case 1: type_size = 2; break;
    case 2: type_size = 4; break;
    case 3: type_size = 8; break;
    case 4: type_size = 4; break;
    case 5: type_size = 8; break;
    case kDataTraversePointerIndex: type_size = pointer_size; break;
    default: type_size = 4; break;
  }

  const size_t read_unit = std::max(type_size, static_cast<size_t>(pointer_size));
  if (stride < static_cast<int>(type_size)) {
    stride = static_cast<int>(type_size);
  }

  const uint64_t max_read = 1024 * 1024;
  uint64_t needed = (static_cast<uint64_t>(count) - 1) * static_cast<uint64_t>(stride) + read_unit;
  if (needed > max_read) {
    const uint64_t max_count = (max_read >= read_unit)
                                 ? (1 + (max_read - read_unit) / static_cast<uint64_t>(stride))
                                 : 1;
    count = static_cast<int>(max_count);
    needed = (static_cast<uint64_t>(count) - 1) * static_cast<uint64_t>(stride) + read_unit;
    if (out_status) {
      *out_status = u8"读取长度过大，已自动缩减数量";
    }
  }

  std::vector<uint8_t> data;
  if (!ReadMemoryRangeEx(base,
                         static_cast<uint32_t>(needed),
                         &data,
                         false,
                         false,
                         use_pvm)) {
    if (out_status) {
      *out_status = u8"读取失败";
    }
    return false;
  }
  if (data.size() < type_size) {
    if (out_status) {
      *out_status = u8"读取数据不足";
    }
    return false;
  }

  out->reserve(static_cast<size_t>(count));

  auto try_pointer_candidate = [&](uint64_t raw_value,
                                   uint64_t host_addr,
                                   DataTraverseEntry* entry) {
    if (!entry) {
      return;
    }
    entry->pointer_checked = true;
    entry->pointer_valid = false;
    entry->pointer_candidate = false;
    entry->pointer_score = 0;
    entry->pointer_value = raw_value;
    entry->pointer_resolved = 0;

    if (raw_value == 0) {
      return;
    }

    uint64_t value = raw_value;
    if (pointer_size == 8) {
      value = StripTag64(value);
    } else {
      value = static_cast<uint64_t>(static_cast<uint32_t>(value));
    }

    auto score_candidate = [&](uint64_t candidate, bool allow_compressed) {
      int score = 0;
      const ClientState::ModuleInfo* mod = nullptr;
      if (IsReadableAddress(candidate, 1, &mod)) {
        score += 2;
      }
      if (candidate % pointer_size == 0) {
        score += 1;
      }
      if (mod) {
        score += 1;
      }
      if (candidate != 0) {
        std::vector<uint8_t> probe;
        if (ReadMemoryRangeEx(candidate, 1, &probe, false, false, use_pvm)) {
          score += 2;
          entry->pointer_valid = true;
        }
      }

      if (score > entry->pointer_score) {
        entry->pointer_score = score;
        entry->pointer_resolved = candidate;
      }
    };

    score_candidate(value, false);

    if (pointer_size == 8 && value <= 0xFFFFFFFFull) {
      const ClientState::ModuleInfo* host_mod = nullptr;
      IsReadableAddress(host_addr, 1, &host_mod);
      uint64_t high = host_mod ? (host_mod->start & 0xFFFFFFFF00000000ull) : app_base_high_;
      if (high != 0) {
        uint64_t compressed = high | (value & 0xFFFFFFFFull);
        score_candidate(compressed, true);
      }
    }

    if (entry->pointer_score >= data_traverse_pointer_threshold_ && entry->pointer_resolved != 0) {
      entry->pointer_candidate = true;
      entry->pointer_value = entry->pointer_resolved;
    }
  };

  for (int i = 0; i < count; ++i) {
    const uint64_t offset = static_cast<uint64_t>(i) * static_cast<uint64_t>(stride);
    if (offset + type_size > data.size()) {
      break;
    }
    const uint8_t* ptr = data.data() + offset;
    uint64_t value_u = 0;
    switch (type) {
      case 0: {
        uint8_t v = 0;
        std::memcpy(&v, ptr, sizeof(v));
        value_u = v;
        break;
      }
      case 1: {
        uint16_t v = 0;
        std::memcpy(&v, ptr, sizeof(v));
        value_u = v;
        break;
      }
      case 2: {
        uint32_t v = 0;
        std::memcpy(&v, ptr, sizeof(v));
        value_u = v;
        break;
      }
      case 3: {
        uint64_t v = 0;
        std::memcpy(&v, ptr, sizeof(v));
        value_u = v;
        break;
      }
      case 4: {
        float v = 0.0f;
        std::memcpy(&v, ptr, sizeof(v));
        std::memcpy(&value_u, &v, sizeof(v));
        break;
      }
      case 5: {
        double v = 0.0;
        std::memcpy(&v, ptr, sizeof(v));
        std::memcpy(&value_u, &v, sizeof(v));
        break;
      }
      case kDataTraversePointerIndex: {
        uint64_t v = 0;
        if (pointer_size == 4) {
          uint32_t v32 = 0;
          std::memcpy(&v32, ptr, sizeof(v32));
          v = v32;
        } else {
          std::memcpy(&v, ptr, sizeof(v));
          v = StripTag64(v);
        }
        value_u = v;
        break;
      }
      default:
        break;
    }

    DataTraverseEntry entry;
    entry.addr = base + offset;
    entry.value_u = value_u;
    entry.raw_value = 0;
    entry.raw_size = static_cast<uint8_t>(type_size);
    std::memcpy(&entry.raw_value, ptr, std::min<size_t>(type_size, sizeof(entry.raw_value)));

    uint64_t ptr_value = 0;
    if (offset + pointer_size <= data.size()) {
      if (pointer_size == 4) {
        uint32_t v32 = 0;
        std::memcpy(&v32, data.data() + offset, sizeof(v32));
        ptr_value = static_cast<uint64_t>(v32);
      } else {
        std::memcpy(&ptr_value, data.data() + offset, sizeof(ptr_value));
        ptr_value = StripTag64(ptr_value);
      }
    }

    if (type == kDataTraversePointerIndex) {
      entry.pointer_value = ptr_value;
      entry.pointer_resolved = ptr_value;
      entry.pointer_checked = true;
      if (ptr_value != 0) {
        std::vector<uint8_t> probe;
        if (ReadMemoryRangeEx(ptr_value, 1, &probe, false, false, use_pvm)) {
          entry.pointer_valid = true;
          entry.pointer_candidate = true;
          entry.pointer_score = data_traverse_pointer_threshold_;
        }
      }
    } else if (data_traverse_auto_pointer_) {
      try_pointer_candidate(ptr_value, entry.addr, &entry);
    }

    out->push_back(std::move(entry));
  }
  return true;
}

void ClientUI::TouchTraverseCache(uint64_t base) {
  auto it = std::find(data_traverse_cache_lru_.begin(), data_traverse_cache_lru_.end(), base);
  if (it != data_traverse_cache_lru_.end()) {
    data_traverse_cache_lru_.erase(it);
  }
  data_traverse_cache_lru_.push_back(base);
  PruneTraverseCache();
}

void ClientUI::PruneTraverseCache() {
  while (data_traverse_cache_lru_.size() > data_traverse_cache_limit_) {
    const uint64_t oldest = data_traverse_cache_lru_.front();
    data_traverse_cache_lru_.erase(data_traverse_cache_lru_.begin());
    data_traverse_child_cache_.erase(oldest);
  }
}

void ClientUI::RenderTraverseEntries(const std::vector<DataTraverseEntry>& entries,
                                     int depth) {
  const uint32_t pointer_size = GetPointerSizeFromModules();
  uint32_t flags = 0;
  if (data_traverse_use_pvm_) {
    flags |= protocol::READ_FLAG_USE_PVM;
  }

  auto format_line = [&](const ClientUI::DataTraverseEntry& e, int type) -> std::string {
    uint64_t raw = e.raw_value;
    uint8_t raw_size = e.raw_size;
    if (e.override_type == type && e.override_valid) {
      raw = e.override_value;
      raw_size = e.override_size;
    }
    char line[256] = {0};
    switch (type) {
      case 0: {
        uint8_t v = static_cast<uint8_t>(raw & 0xFFu);
        std::snprintf(line, sizeof(line), "0x%llX : %u (0x%02X)",
                      static_cast<unsigned long long>(e.addr), v, v);
        break;
      }
      case 1: {
        uint16_t v = static_cast<uint16_t>(raw & 0xFFFFu);
        std::snprintf(line, sizeof(line), "0x%llX : %u (0x%04X)",
                      static_cast<unsigned long long>(e.addr), v, v);
        break;
      }
      case 2: {
        uint32_t v = static_cast<uint32_t>(raw & 0xFFFFFFFFu);
        std::snprintf(line, sizeof(line), "0x%llX : %u (0x%08X)",
                      static_cast<unsigned long long>(e.addr), v, v);
        break;
      }
      case 3: {
        uint64_t v = raw;
        std::snprintf(line, sizeof(line), "0x%llX : %llu (0x%016llX)",
                      static_cast<unsigned long long>(e.addr),
                      static_cast<unsigned long long>(v),
                      static_cast<unsigned long long>(v));
        break;
      }
      case 4: {
        float v = 0.0f;
        std::memcpy(&v, &raw, sizeof(v));
        std::snprintf(line, sizeof(line), "0x%llX : %.6f",
                      static_cast<unsigned long long>(e.addr), v);
        break;
      }
      case 5: {
        double v = 0.0;
        std::memcpy(&v, &raw, sizeof(v));
        std::snprintf(line, sizeof(line), "0x%llX : %.6f",
                      static_cast<unsigned long long>(e.addr), v);
        break;
      }
      case kDataTraversePointerIndex: {
        std::snprintf(line, sizeof(line), "0x%llX : %s",
                      static_cast<unsigned long long>(e.addr),
                      Hex64(e.pointer_value).c_str());
        break;
      }
      default:
        std::snprintf(line, sizeof(line), "0x%llX : (unsupported)",
                      static_cast<unsigned long long>(e.addr));
        break;
    }
    (void)raw_size;
    return line;
  };

  auto compute_override = [&](ClientUI::DataTraverseEntry& e, int type) {
    e.override_type = type;
    e.override_valid = false;
    e.override_value = 0;
    e.override_size = 0;
    if (type == kDataTraversePointerIndex) {
      std::vector<uint8_t> buf;
      if (ReadMemoryRangeEx(e.addr, pointer_size, &buf, false, false, data_traverse_use_pvm_)) {
        uint64_t pv = 0;
        if (pointer_size == 4 && buf.size() >= 4) {
          uint32_t v32 = 0;
          std::memcpy(&v32, buf.data(), sizeof(v32));
          pv = v32;
        } else if (buf.size() >= 8) {
          std::memcpy(&pv, buf.data(), sizeof(pv));
          pv = StripTag64(pv);
        }
        e.pointer_value = pv;
        e.pointer_resolved = pv;
        if (pv != 0) {
          std::vector<uint8_t> probe;
          if (ReadMemoryRangeEx(pv, 1, &probe, false, false, data_traverse_use_pvm_)) {
            e.pointer_valid = true;
            e.pointer_candidate = true;
            e.pointer_score = data_traverse_pointer_threshold_;
          }
        }
      }
      e.pointer_checked = true;
      return;
    }

    size_t size = 4;
    switch (type) {
      case 0: size = 1; break;
      case 1: size = 2; break;
      case 2: size = 4; break;
      case 3: size = 8; break;
      case 4: size = 4; break;
      case 5: size = 8; break;
      default: size = 4; break;
    }
    std::vector<uint8_t> buf;
    if (ReadMemoryRangeEx(e.addr, static_cast<uint32_t>(size), &buf, false, false, data_traverse_use_pvm_)) {
      uint64_t v = 0;
      std::memcpy(&v, buf.data(), std::min<size_t>(size, sizeof(v)));
      e.override_value = v;
      e.override_size = static_cast<uint8_t>(size);
      e.override_valid = true;
    }
  };

  for (const auto& entry_raw : entries) {
    auto entry = entry_raw;
    auto it = data_traverse_node_overrides_.find(entry.addr);
    if (it != data_traverse_node_overrides_.end()) {
      entry.override_type = it->second.override_type;
      entry.override_value = it->second.override_value;
      entry.override_size = it->second.override_size;
      entry.override_valid = it->second.override_valid;
      entry.pointer_value = it->second.pointer_value;
      entry.pointer_resolved = it->second.pointer_resolved;
      entry.pointer_valid = it->second.pointer_valid;
      entry.pointer_candidate = it->second.pointer_candidate;
      entry.pointer_score = it->second.pointer_score;
    }

    const int effective_type = entry.override_type >= 0 ? entry.override_type : data_traverse_type_;
    const bool pointer_ready = entry.pointer_candidate && entry.pointer_valid;
    std::string display = format_line(entry, effective_type);
    if (effective_type != kDataTraversePointerIndex && pointer_ready) {
      display += " -> ";
      display += Hex64(entry.pointer_value);
    }

    ImGui::PushID(reinterpret_cast<void*>(static_cast<uintptr_t>(entry.addr + static_cast<uint64_t>(depth) * 1315423911ull)));
    bool open = false;
    if (pointer_ready && !data_traverse_light_mode_) {
      open = ImGui::TreeNodeEx("##traverse_ptr",
                               ImGuiTreeNodeFlags_SpanFullWidth,
                               "%s",
                               display.c_str());
    } else {
      ImGui::Selectable(display.c_str());
    }

    if (ImGui::BeginPopupContextItem("traverse_item_ctx")) {
      if (ImGui::MenuItem(u8"使用全局类型")) {
        data_traverse_node_overrides_.erase(entry.addr);
      }
      ImGui::Separator();
      ImGui::TextUnformatted(u8"切换类型");
      for (int t = 0; t < IM_ARRAYSIZE(kDataTraverseTypeNames); ++t) {
        const bool selected = (entry.override_type == t);
        if (ImGui::MenuItem(kDataTraverseTypeNames[t], nullptr, selected)) {
          auto& override_entry = data_traverse_node_overrides_[entry.addr];
          override_entry.addr = entry.addr;
          compute_override(override_entry, t);
        }
      }
      ImGui::EndPopup();
    }

    if (open) {
      auto& cache = data_traverse_child_cache_[entry.pointer_value];
      if (cache.base != entry.pointer_value ||
          cache.count != data_traverse_count_ ||
          cache.stride != data_traverse_stride_ ||
          cache.type != data_traverse_type_ ||
          cache.use_pvm != data_traverse_use_pvm_) {
        cache.base = entry.pointer_value;
        cache.count = data_traverse_count_;
        cache.stride = data_traverse_stride_;
        cache.type = data_traverse_type_;
        cache.use_pvm = data_traverse_use_pvm_;
        cache.entries.clear();
        cache.status.clear();
        BuildTraverseEntries(cache.base,
                             cache.count,
                             cache.stride,
                             cache.type,
                             cache.use_pvm,
                             &cache.entries,
                             &cache.status);
      }
      TouchTraverseCache(entry.pointer_value);
      if (!cache.status.empty()) {
        ImGui::TextUnformatted(cache.status.c_str());
      }
      RenderTraverseEntries(cache.entries, depth + 1);
      ImGui::TreePop();
    }
    ImGui::PopID();
  }
}

bool ClientUI::Attach() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint32_t pid = static_cast<uint32_t>(std::strtoul(pid_input_, nullptr, 10));
  protocol::AttachRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_ATTACH, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"打开进程失败";
    return false;
  }

  if (payload.size() < sizeof(protocol::StatusResponse)) {
    state_.status = u8"打开进程响应无效";
    return false;
  }
  auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  state_.status = resp->code == 0 ? u8"打开进程成功" : u8"打开进程错误";
  state_.pid = pid;
  if (resp->code == 0) {
    FetchProcInfo();
  }
  return resp->code == 0;
}

bool ClientUI::ScanFirst() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  if (scan_strict_) {
    if (!scan_allow_nonresident_) {
      state_.status = u8"严格不漏需要开启允许非驻留页";
      return false;
    }
  }

  bool freeze_attached = false;
  if (scan_freeze_) {
    if (!DebugAttach(true)) {
      state_.status = u8"严格快照失败：附加调试器失败，已继续扫描";
    } else {
      freeze_attached = true;
    }
  }
  struct FreezeGuard {
    ClientUI* ui = nullptr;
    bool* active = nullptr;
    ~FreezeGuard() {
      if (ui && active && *active) {
        ui->DebugDetach();
      }
    }
  } freeze_guard{this, &freeze_attached};

  std::vector<uint8_t> value_bytes;
  if (!BuildValueBytes(&value_bytes)) {
    state_.status = u8"值无效";
    return false;
  }

  const uint64_t start = ParseAddress(scan_start_);
  const uint64_t end = ParseAddress(scan_end_);
  const size_t header_size = offsetof(protocol::ScanRequest, data);
  std::vector<uint8_t> buffer(header_size + value_bytes.size());
  auto* req = reinterpret_cast<protocol::ScanRequest*>(buffer.data());
  req->value_type = static_cast<uint8_t>(state_.value_type);
  req->comparison_type = static_cast<uint8_t>(state_.condition);
  req->reserved = scan_use_pvm_ ? protocol::SCAN_FLAG_USE_PVM : 0;
  if (scan_allow_nonresident_) {
    req->reserved |= protocol::SCAN_FLAG_ALLOW_NONRESIDENT;
  }
  if (scan_strict_) {
    req->reserved |= protocol::SCAN_FLAG_BYTE_STEP;
    req->reserved |= protocol::SCAN_FLAG_STRICT;
  }
  req->start_addr = start;
  req->end_addr = end;
  req->value_len = static_cast<uint32_t>(value_bytes.size());
  std::memcpy(req->data, value_bytes.data(), value_bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_SCAN_FIRST, buffer.data(), static_cast<uint32_t>(buffer.size()), &header, &payload)) {
    state_.status = u8"扫描失败";
    return false;
  }

  if (payload.size() < sizeof(uint64_t)) {
    state_.status = u8"扫描响应无效";
    return false;
  }
  uint64_t total = 0;
  std::memcpy(&total, payload.data(), sizeof(total));
  state_.scan_total = total;
  state_.page_addresses.clear();
  const size_t count = (payload.size() - sizeof(uint64_t)) / sizeof(uint64_t);
  if (count > 0) {
    state_.page_addresses.resize(count);
    std::memcpy(state_.page_addresses.data(), payload.data() + sizeof(uint64_t), count * sizeof(uint64_t));
  }
  state_.page_index = 0;
  RefreshScanPreviewValues();
  state_.status = u8"扫描完成";
  return true;
}

bool ClientUI::ScanNext() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  if (scan_strict_) {
    if (!scan_allow_nonresident_) {
      state_.status = u8"严格不漏需要开启允许非驻留页";
      return false;
    }
  }

  bool freeze_attached = false;
  if (scan_freeze_) {
    if (!DebugAttach(true)) {
      state_.status = u8"严格快照失败：附加调试器失败，已继续扫描";
    } else {
      freeze_attached = true;
    }
  }
  struct FreezeGuard {
    ClientUI* ui = nullptr;
    bool* active = nullptr;
    ~FreezeGuard() {
      if (ui && active && *active) {
        ui->DebugDetach();
      }
    }
  } freeze_guard{this, &freeze_attached};

  std::vector<uint8_t> value_bytes;
  if (!BuildValueBytes(&value_bytes)) {
    state_.status = u8"值无效";
    return false;
  }

  const uint64_t start = ParseAddress(scan_start_);
  const uint64_t end = ParseAddress(scan_end_);
  const size_t header_size = offsetof(protocol::ScanRequest, data);
  std::vector<uint8_t> buffer(header_size + value_bytes.size());
  auto* req = reinterpret_cast<protocol::ScanRequest*>(buffer.data());
  req->value_type = static_cast<uint8_t>(state_.value_type);
  req->comparison_type = static_cast<uint8_t>(state_.condition);
  req->reserved = scan_use_pvm_ ? protocol::SCAN_FLAG_USE_PVM : 0;
  if (scan_allow_nonresident_) {
    req->reserved |= protocol::SCAN_FLAG_ALLOW_NONRESIDENT;
  }
  if (scan_strict_) {
    req->reserved |= protocol::SCAN_FLAG_BYTE_STEP;
    req->reserved |= protocol::SCAN_FLAG_STRICT;
  }
  req->start_addr = start;
  req->end_addr = end;
  req->value_len = static_cast<uint32_t>(value_bytes.size());
  std::memcpy(req->data, value_bytes.data(), value_bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_SCAN_NEXT, buffer.data(), static_cast<uint32_t>(buffer.size()), &header, &payload)) {
    state_.status = u8"扫描失败";
    return false;
  }

  if (payload.size() < sizeof(uint64_t)) {
    state_.status = u8"扫描响应无效";
    return false;
  }
  uint64_t total = 0;
  std::memcpy(&total, payload.data(), sizeof(total));
  state_.scan_total = total;
  state_.page_addresses.clear();
  const size_t count = (payload.size() - sizeof(uint64_t)) / sizeof(uint64_t);
  if (count > 0) {
    state_.page_addresses.resize(count);
    std::memcpy(state_.page_addresses.data(), payload.data() + sizeof(uint64_t), count * sizeof(uint64_t));
  }
  state_.page_index = 0;
  RefreshScanPreviewValues();
  state_.status = u8"再次扫描完成";
  return true;
}

bool ClientUI::ScanPage() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  protocol::ScanPageRequest req{};
  req.start_index = state_.page_index * state_.page_size;
  req.max_count = state_.page_size;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_SCAN_PAGE, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"获取页失败";
    return false;
  }

  if (payload.size() < sizeof(uint64_t)) {
    state_.status = u8"页响应无效";
    return false;
  }
  uint64_t total = 0;
  std::memcpy(&total, payload.data(), sizeof(total));
  state_.scan_total = total;
  state_.page_addresses.clear();
  const size_t count = (payload.size() - sizeof(uint64_t)) / sizeof(uint64_t);
  if (count > 0) {
    state_.page_addresses.resize(count);
    std::memcpy(state_.page_addresses.data(), payload.data() + sizeof(uint64_t), count * sizeof(uint64_t));
  }
  RefreshScanPreviewValues();
  state_.status = u8"页已更新";
  return true;
}

bool ClientUI::ReadMemory() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint64_t addr = ParseAddress(mem_addr_);
  if (mem_size_ <= 0) {
    mem_size_ = 1;
  }

  uint32_t size = static_cast<uint32_t>(mem_size_);
  const bool fixed = !read_use_length_override_;
  switch (read_format_) {
    case 0: // int32
    case 1: // float
      if (fixed) size = 4;
      break;
    case 2: // double
      if (fixed) size = 8;
      break;
    case 3: // byte
      if (fixed) size = 1;
      break;
    case 4: // word
      if (fixed) size = 2;
      break;
    case 5: // 汇编
    case 6: // hex
    case 7: // utf-8
    case 8: // utf-16
    default:
      break;
  }

  protocol::ReadMemRequest req{};
  req.address = addr;
  req.size = size;
  req.reserved = read_use_pvm_ ? protocol::READ_FLAG_USE_PVM : 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_READ_MEM, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"读取失败";
    return false;
  }

  if (payload.size() < offsetof(protocol::ReadMemResponse, data)) {
    state_.status = u8"读取响应无效";
    return false;
  }
  auto* resp = reinterpret_cast<const protocol::ReadMemResponse*>(payload.data());
  if (resp->code != 0) {
    state_.status = u8"读取错误";
    return false;
  }

  const size_t bytes = resp->bytes_read;
  const size_t expected = offsetof(protocol::ReadMemResponse, data) + bytes;
  if (payload.size() < expected) {
    state_.status = u8"读取响应截断";
    return false;
  }

  state_.mem_view_addr = addr;
  state_.mem_view_data.assign(resp->data, resp->data + bytes);
  state_.status = u8"读取成功";

  read_value_text_.clear();
  if (read_format_ == 5) {
    disasm_size_ = static_cast<int>(size);
    OpenMemoryWorkspaceAt(addr, false, true);
    read_value_text_ = u8"已在反汇编窗口显示";
  } else if (!state_.mem_view_data.empty()) {
    const uint8_t* data = state_.mem_view_data.data();
    const size_t data_len = state_.mem_view_data.size();
    char buf[256] = {0};
    switch (read_format_) {
      case 0: { // int32
        if (data_len >= 4) {
          int32_t v = 0;
          std::memcpy(&v, data, sizeof(v));
          if (address_list_hex_) {
            std::snprintf(buf, sizeof(buf), "int32 = 0x%08X", static_cast<uint32_t>(v));
          } else {
            std::snprintf(buf, sizeof(buf), "int32 = %d (0x%08X)", v, static_cast<uint32_t>(v));
          }
          read_value_text_ = buf;
        }
        break;
      }
      case 1: { // float
        if (data_len >= 4) {
          float v = 0.0f;
          std::memcpy(&v, data, sizeof(v));
          std::snprintf(buf, sizeof(buf), "float = %.6f", static_cast<double>(v));
          read_value_text_ = buf;
        }
        break;
      }
      case 2: { // double
        if (data_len >= 8) {
          double v = 0.0;
          std::memcpy(&v, data, sizeof(v));
          std::snprintf(buf, sizeof(buf), "double = %.6f", v);
          read_value_text_ = buf;
        }
        break;
      }
      case 3: { // byte
        uint8_t v = data[0];
        if (address_list_hex_) {
          std::snprintf(buf, sizeof(buf), "byte = 0x%02X", v);
        } else {
          std::snprintf(buf, sizeof(buf), "byte = %u (0x%02X)", v, v);
        }
        read_value_text_ = buf;
        break;
      }
      case 4: { // word
        if (data_len >= 2) {
          uint16_t v = 0;
          std::memcpy(&v, data, sizeof(v));
          if (address_list_hex_) {
            std::snprintf(buf, sizeof(buf), "word = 0x%04X", v);
          } else {
            std::snprintf(buf, sizeof(buf), "word = %u (0x%04X)", v, v);
          }
          read_value_text_ = buf;
        }
        break;
      }
      case 6: { // hex
        std::string hex;
        for (size_t i = 0; i < data_len; ++i) {
          char tmp[4] = {0};
          std::snprintf(tmp, sizeof(tmp), "%02X ", data[i]);
          hex.append(tmp);
        }
        read_value_text_ = hex;
        break;
      }
      case 7: { // utf-8
        std::string text(reinterpret_cast<const char*>(data), data_len);
        size_t null_pos = text.find('\0');
        if (null_pos != std::string::npos) {
          text.resize(null_pos);
        }
        read_value_text_ = text;
        break;
      }
      case 8: { // utf-16
        const size_t u16_len = data_len / 2;
        if (u16_len > 0) {
          std::wstring wtext;
          wtext.reserve(u16_len);
          for (size_t i = 0; i < u16_len; ++i) {
            uint16_t ch = static_cast<uint16_t>(data[i * 2] | (static_cast<uint16_t>(data[i * 2 + 1]) << 8));
            if (ch == 0) break;
            wtext.push_back(static_cast<wchar_t>(ch));
          }
          int needed = WideCharToMultiByte(CP_UTF8, 0, wtext.data(),
                                           static_cast<int>(wtext.size()), nullptr, 0, nullptr, nullptr);
          if (needed > 0) {
            std::string out;
            out.resize(static_cast<size_t>(needed));
            WideCharToMultiByte(CP_UTF8, 0, wtext.data(), static_cast<int>(wtext.size()),
                                out.data(), needed, nullptr, nullptr);
            read_value_text_ = out;
          }
        }
        break;
      }
      default:
        break;
    }
  }
  return true;
}

bool ClientUI::ReadMemoryRange(uint64_t addr,
                               uint32_t size,
                               std::vector<uint8_t>* out,
                               bool allow_nonresident) {
  return ReadMemoryRangeEx(addr, size, out, allow_nonresident, disasm_ignore_perms_, disasm_use_pvm_);
}

bool ClientUI::ReadMemoryRangeEx(uint64_t addr,
                                 uint32_t size,
                                 std::vector<uint8_t>* out,
                                 bool allow_nonresident,
                                 bool ignore_perms,
                                 bool use_pvm) {
  if (!out) {
    return false;
  }
  auto try_read = [&](uint32_t flags, std::string* out_error) -> bool {
    out->clear();
    if (!state_.connected) {
      if (out_error) *out_error = u8"未连接";
      return false;
    }
    if (size == 0) {
      return true;
    }
    protocol::ReadMemRequest req{};
    req.address = addr;
    req.size = size;
    req.reserved = flags;

    protocol::PacketHeader header{};
    std::vector<uint8_t> payload;
    auto send_once = [&]() -> bool {
      payload.clear();
      return net_.SendAndReceive(protocol::CommandType::CMD_READ_MEM, &req, sizeof(req), &header, &payload);
    };
    if (!send_once()) {
      // attempt reconnect once (agent may have restarted)
      net_.Disconnect();
      state_.connected = false;
      if (ConnectToServer()) {
        if (state_.pid != 0) {
          std::snprintf(pid_input_, sizeof(pid_input_), "%u", state_.pid);
          Attach();
        }
        if (!send_once()) {
          if (out_error) *out_error = u8"读取失败";
          return false;
        }
      } else {
        if (out_error) *out_error = u8"连接断开";
        return false;
      }
    }
    BenchTrackPacket(sizeof(req), payload.size());
    if (payload.size() < offsetof(protocol::ReadMemResponse, data)) {
      if (out_error) *out_error = u8"读取响应无效";
      return false;
    }
    auto* resp = reinterpret_cast<const protocol::ReadMemResponse*>(payload.data());
    if (resp->code != 0) {
      if (out_error) *out_error = u8"读取错误";
      return false;
    }

    const size_t bytes = resp->bytes_read;
    const size_t expected = offsetof(protocol::ReadMemResponse, data) + bytes;
    if (payload.size() < expected) {
      if (out_error) *out_error = u8"读取响应截断";
      return false;
    }
    out->assign(resp->data, resp->data + bytes);
    BenchTrackRead(bytes, size);
    return true;
  };

  uint32_t flags = 0;
  if (allow_nonresident) {
    flags |= protocol::READ_FLAG_ALLOW_NONRESIDENT;
  }
  if (ignore_perms) {
    flags |= protocol::READ_FLAG_IGNORE_PERMS;
  }
  if (use_pvm) {
    flags |= protocol::READ_FLAG_USE_PVM;
  }

  std::string err;
  if (try_read(flags, &err)) {
    return true;
  }
  if ((flags & protocol::READ_FLAG_USE_PVM) != 0) {
    const uint32_t retry_flags = flags & ~protocol::READ_FLAG_USE_PVM;
    if (try_read(retry_flags, &err)) {
      return true;
    }
  }
  state_.status = err.empty() ? u8"读取失败" : err;
  return false;
}

bool ClientUI::WriteMemory() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint64_t addr = ParseAddress(write_addr_);
  std::vector<uint8_t> bytes;
  switch (write_format_) {
    case 0: { // int32
      if (!ParseValueForType(protocol::ValueType::S32, write_data_, &bytes, address_list_hex_)) {
        state_.status = u8"int 输入无效";
        return false;
      }
      break;
    }
    case 1: { // float
      if (!ParseValueForType(protocol::ValueType::FLOAT, write_data_, &bytes, address_list_hex_)) {
        state_.status = u8"float 输入无效";
        return false;
      }
      break;
    }
    case 2: { // double
      if (!ParseValueForType(protocol::ValueType::DOUBLE, write_data_, &bytes, address_list_hex_)) {
        state_.status = u8"double 输入无效";
        return false;
      }
      break;
    }
    case 3: { // byte
      if (!ParseValueForType(protocol::ValueType::U8, write_data_, &bytes, address_list_hex_)) {
        state_.status = u8"byte 输入无效";
        return false;
      }
      break;
    }
    case 4: { // word
      if (!ParseValueForType(protocol::ValueType::U16, write_data_, &bytes, address_list_hex_)) {
        state_.status = u8"word 输入无效";
        return false;
      }
      break;
    }
    case 5: { // 汇编(机器码)
      if (!ParseHexBytes(write_data_, &bytes)) {
        state_.status = u8"汇编写入仅支持机器码HEX";
        return false;
      }
      break;
    }
    case 6: { // hex
      if (!ParseHexBytes(write_data_, &bytes)) {
        state_.status = u8"十六进制字节无效";
        return false;
      }
      break;
    }
    case 7: { // utf-8
      std::string text = write_data_;
      bytes.assign(text.begin(), text.end());
      break;
    }
    case 8: { // utf-16
      int wlen = MultiByteToWideChar(CP_UTF8, 0, write_data_, -1, nullptr, 0);
      if (wlen <= 1) {
        state_.status = u8"UTF-16 输入无效";
        return false;
      }
      std::wstring wtext;
      wtext.resize(static_cast<size_t>(wlen - 1));
      MultiByteToWideChar(CP_UTF8, 0, write_data_, -1, wtext.data(), wlen);
      bytes.reserve(wtext.size() * 2);
      for (wchar_t wc : wtext) {
        uint16_t ch = static_cast<uint16_t>(wc);
        bytes.push_back(static_cast<uint8_t>(ch & 0xFF));
        bytes.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
      }
      break;
    }
    default:
      state_.status = u8"写入类型不支持";
      return false;
  }

  const size_t header_size = offsetof(protocol::WriteMemRequest, data);
  std::vector<uint8_t> buffer(header_size + bytes.size());
  auto* req = reinterpret_cast<protocol::WriteMemRequest*>(buffer.data());
  req->address = addr;
  req->size = static_cast<uint32_t>(bytes.size());
  req->reserved = 0;
  std::memcpy(req->data, bytes.data(), bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_WRITE_MEM, buffer.data(), static_cast<uint32_t>(buffer.size()), &header, &payload)) {
    state_.status = u8"写入失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::WriteMemResponse)) {
    state_.status = u8"写入响应无效";
    return false;
  }
  auto* resp = reinterpret_cast<const protocol::WriteMemResponse*>(payload.data());
  if (resp->code == 0) {
    if (resp->bytes_written < bytes.size()) {
      state_.status = u8"写入不完整";
      return false;
    }
    state_.status = u8"写入成功";
    return true;
  }
  state_.status = u8"写入错误";
  return false;
}

bool ClientUI::WriteMemoryBytes(uint64_t addr, const std::vector<uint8_t>& bytes) {
  if (!state_.connected) {
    address_list_status_ = u8"未连接";
    return false;
  }
  if (bytes.empty()) {
    address_list_status_ = u8"写入数据为空";
    return false;
  }

  const size_t header_size = offsetof(protocol::WriteMemRequest, data);
  std::vector<uint8_t> buffer(header_size + bytes.size());
  auto* req = reinterpret_cast<protocol::WriteMemRequest*>(buffer.data());
  req->address = addr;
  req->size = static_cast<uint32_t>(bytes.size());
  req->reserved = 0;
  std::memcpy(req->data, bytes.data(), bytes.size());

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_WRITE_MEM,
                           buffer.data(),
                           static_cast<uint32_t>(buffer.size()),
                           &header,
                           &payload)) {
    address_list_status_ = u8"写入失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::WriteMemResponse)) {
    address_list_status_ = u8"写入响应无效";
    return false;
  }
  auto* resp = reinterpret_cast<const protocol::WriteMemResponse*>(payload.data());
  if (resp->code != 0 || resp->bytes_written < bytes.size()) {
    address_list_status_ = u8"写入错误";
    return false;
  }
  return true;
}

bool ClientUI::FetchProcesses() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  protocol::ProcessListRequest req{};
  req.max_count = 2048;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_LIST_PROCESSES, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"进程列表获取失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::ProcessListHeader)) {
    state_.status = u8"进程列表响应无效";
    return false;
  }

  state_.processes.clear();
  const auto* hdr = reinterpret_cast<const protocol::ProcessListHeader*>(payload.data());
  size_t offset = sizeof(protocol::ProcessListHeader);
  uint32_t parsed = 0;

  while (offset + offsetof(protocol::ProcessEntry, name) <= payload.size()) {
    if (hdr->count != 0 && parsed >= hdr->count) {
      break;
    }
    const auto* entry = reinterpret_cast<const protocol::ProcessEntry*>(payload.data() + offset);
    const size_t header_size = offsetof(protocol::ProcessEntry, name);
    const size_t total_size = header_size + entry->name_len;
    if (offset + total_size > payload.size()) {
      break;
    }
    ClientState::ProcessInfo info;
    info.pid = entry->pid;
    info.name.assign(reinterpret_cast<const char*>(entry->name), entry->name_len);
    state_.processes.push_back(std::move(info));
    offset += total_size;
    parsed++;
  }

  state_.status = u8"进程列表已更新";
  return true;
}

bool ClientUI::FetchModules() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint32_t pid = state_.pid;
  if (pid == 0) {
    pid = static_cast<uint32_t>(std::strtoul(pid_input_, nullptr, 10));
  }
  protocol::ModuleListRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_LIST_MODULES, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"模块列表获取失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::ModuleListHeader)) {
    state_.status = u8"模块列表响应无效";
    return false;
  }

  state_.modules.clear();
  const auto* hdr = reinterpret_cast<const protocol::ModuleListHeader*>(payload.data());
  size_t offset = sizeof(protocol::ModuleListHeader);
  uint32_t parsed = 0;

  while (offset + offsetof(protocol::ModuleEntry, path) <= payload.size()) {
    if (hdr->count != 0 && parsed >= hdr->count) {
      break;
    }
    const auto* entry = reinterpret_cast<const protocol::ModuleEntry*>(payload.data() + offset);
    const size_t header_size = offsetof(protocol::ModuleEntry, path);
    const size_t total_size = header_size + entry->path_len;
    if (offset + total_size > payload.size()) {
      break;
    }
    ClientState::ModuleInfo info;
    info.start = entry->start;
    info.end = entry->end;
    info.perms = entry->perms;
    if (entry->path_len > 0) {
      info.path.assign(reinterpret_cast<const char*>(entry->path), entry->path_len);
    }
    state_.modules.push_back(std::move(info));
    offset += total_size;
    parsed++;
  }

  selected_module_index_ = state_.modules.empty() ? -1 : 0;
  state_.status = u8"模块列表已更新";
  SyncPointerModuleSelection();
  SyncPointerPreviewSelection();
  UpdateAppBaseHigh();
  return true;
}

bool ClientUI::FetchProcInfo() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint32_t pid = state_.pid;
  if (pid == 0) {
    pid = static_cast<uint32_t>(std::strtoul(pid_input_, nullptr, 10));
  }
  if (pid == 0) {
    state_.status = u8"进程ID无效";
    return false;
  }

  protocol::ProcInfoRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_PROC_INFO, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"获取架构信息失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::ProcInfoResponse)) {
    state_.status = u8"架构信息响应无效";
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::ProcInfoResponse*>(payload.data());
  if (resp->code != 0) {
    state_.status = u8"架构信息获取失败";
    return false;
  }

  state_.regs_arch = static_cast<protocol::RegsArch>(resp->arch);
  state_.pointer_size = resp->pointer_size;
  state_.status = u8"架构信息已更新";
  return true;
}

bool ClientUI::FetchRegs() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint32_t pid = state_.pid;
  if (pid == 0) {
    pid = static_cast<uint32_t>(std::strtoul(pid_input_, nullptr, 10));
  }
  protocol::GetRegsRequest req{};
  req.pid = pid;
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_GET_REGS, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"获取寄存器失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::GetRegsResponse)) {
    state_.status = u8"寄存器响应无效";
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::GetRegsResponse*>(payload.data());
  if (resp->code != 0) {
    state_.status = u8"寄存器读取错误";
    state_.regs_valid = false;
    return false;
  }
  state_.regs_arch = static_cast<protocol::RegsArch>(resp->arch);
  if (state_.regs_arch == protocol::RegsArch::ARM64) {
    state_.pointer_size = 8;
  } else if (state_.regs_arch == protocol::RegsArch::ARM32) {
    state_.pointer_size = 4;
  }
  if (state_.regs_arch == protocol::RegsArch::ARM64) {
    state_.regs64 = resp->regs.arm64;
  } else if (state_.regs_arch == protocol::RegsArch::ARM32) {
    state_.regs32 = resp->regs.arm32;
  } else {
    state_.regs_valid = false;
    state_.status = u8"寄存器架构未知";
    return false;
  }
  state_.regs_valid = true;
  state_.status = u8"寄存器已更新";
  return true;
}

bool ClientUI::DebugAttach(bool allow_sigstop) {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  uint32_t pid = state_.pid;
  if (pid == 0) {
    pid = static_cast<uint32_t>(std::strtoul(pid_input_, nullptr, 10));
  }
  protocol::DebugAttachRequest req{};
  req.pid = pid;
  req.reserved = allow_sigstop ? protocol::DEBUG_ATTACH_FLAG_ALLOW_SIGSTOP : 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_ATTACH, &req, sizeof(req), &header, &payload)) {
    state_.status = u8"附加调试器失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    state_.status = u8"附加调试器响应无效";
    return false;
  }
  auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  state_.status = resp->code == 0 ? u8"调试器已附加" : u8"附加调试器错误";
  return resp->code == 0;
}

bool ClientUI::DebugDetach() {
  if (!state_.connected) {
    state_.status = u8"未连接";
    return false;
  }
  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_DETACH, nullptr, 0, &header, &payload)) {
    state_.status = u8"调试分离失败";
    return false;
  }
  if (payload.size() < sizeof(protocol::StatusResponse)) {
    state_.status = u8"调试分离响应无效";
    return false;
  }
  auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
  state_.status = resp->code == 0 ? u8"调试已分离" : u8"调试分离错误";
  return resp->code == 0;
}

bool ClientUI::RunDisasm(uint64_t addr) {
  disasm_lines_.clear();
  disasm_status_.clear();
  disasm_last_decoded_count_ = 0;
  disasm_last_fallback_count_ = 0;
  if (addr == 0) {
    disasm_status_ = u8"地址无效";
    return false;
  }
  if (state_.pid == 0) {
    if (!Attach()) {
      disasm_status_ = u8"请先打开进程";
      return false;
    }
  }
  if (disasm_auto_arch_) {
    if (state_.regs_arch == protocol::RegsArch::ARM64) {
      disasm_arch_ = 0;
    } else if (state_.regs_arch == protocol::RegsArch::ARM32) {
      disasm_arch_ = 1;
    } else {
      bool has_high = false;
      for (const auto& mod : state_.modules) {
        if (mod.start > 0xFFFFFFFFull) {
          has_high = true;
          break;
        }
      }
      disasm_arch_ = has_high ? 0 : 1;
    }
    if (disasm_arch_ == 1 && (addr & 1u)) {
      disasm_thumb_ = true;
      addr &= ~1ull;
    }
  }
  std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0x%llX",
                static_cast<unsigned long long>(addr));
  std::snprintf(disasm_jump_addr_, sizeof(disasm_jump_addr_), "0x%llX",
                static_cast<unsigned long long>(addr));

  std::vector<uint8_t> code;
  if (!ReadMemoryRange(addr, static_cast<uint32_t>(disasm_size_), &code, disasm_allow_nonresident_)) {
    disasm_status_ = u8"读取失败";
    return false;
  }
  if (code.empty()) {
    disasm_status_ = u8"无可用数据";
    return false;
  }
  if (!DisassembleBuffer(addr, code)) {
    return false;
  }

  // ARM32 下如果当前模式完全无法解码，自动切换 Thumb/ARM 再试一次。
  if (disasm_arch_ == 1 && disasm_view_mode_ == 0 && disasm_last_decoded_count_ == 0) {
    const bool original_thumb = disasm_thumb_;
    const std::string original_status = disasm_status_;
    const std::vector<std::string> original_lines = disasm_lines_;
    const uint32_t original_decoded = disasm_last_decoded_count_;
    const uint32_t original_fallback = disasm_last_fallback_count_;

    disasm_thumb_ = !original_thumb;
    if (DisassembleBuffer(addr, code) && disasm_last_decoded_count_ > 0) {
      disasm_status_ = std::string(u8"反汇编完成，已自动切换为") +
                       (disasm_thumb_ ? u8"Thumb" : u8"ARM") +
                       u8"，指令=" + std::to_string(disasm_last_decoded_count_) +
                       u8"，HEX回退=" + std::to_string(disasm_last_fallback_count_);
      return true;
    }

    disasm_thumb_ = original_thumb;
    disasm_status_ = original_status;
    disasm_lines_ = original_lines;
    disasm_last_decoded_count_ = original_decoded;
    disasm_last_fallback_count_ = original_fallback;
  }
  return true;
}

std::string ClientUI::PermsToString(uint32_t perms) {
  char buf[5] = {'-', '-', '-', '-', '\0'};
  if (perms & protocol::MODULE_PERM_READ) buf[0] = 'r';
  if (perms & protocol::MODULE_PERM_WRITE) buf[1] = 'w';
  if (perms & protocol::MODULE_PERM_EXEC) buf[2] = 'x';
  if (perms & protocol::MODULE_PERM_PRIVATE) buf[3] = 'p';
  if (perms & protocol::MODULE_PERM_SHARED) buf[3] = 's';
  return std::string(buf);
}

bool ClientUI::IsModuleVisible(int category, const ClientState::ModuleInfo& mod) {
  const ModuleProps props = GetModuleProps(mod);

  switch (category) {
    case 0: // 全部
      return true;
    case 1: // 代码
      return props.exec;
    case 2: // 代码-应用
      return props.exec && props.app;
    case 3: // 代码-系统
      return props.exec && props.system;
    case 4: // C数据
      return props.cdata;
    case 5: // BSS/匿名
      return props.rw && !props.exec && props.anon;
    case 6: // 堆
      return props.heap;
    case 7: // 栈
      return props.stack;
    case 8: // Java
      return props.java;
    case 9: // Java堆
      return props.java_heap;
    case 10: // JIT
      return props.jit;
    case 11: // Ashmem
      return props.ashmem;
    case 12: // Dex/Oat/Vdex
      return props.dex || props.oat || props.vdex;
    case 13: // 设备
      return props.dev;
    case 14: // 共享
      return props.shared;
    case 15: // 库(.so)
      return props.so;
    case 16: // 系统
      return props.system;
    case 17: // 匿名(A)
      return props.anon;
    case 18: // 其他
      return true;
    default:
      return true;
  }
}

std::string ClientUI::ModuleTypeTag(const ClientState::ModuleInfo& mod) {
  const ModuleProps props = GetModuleProps(mod);

  if (props.guard) return "GUARD";
  if (props.heap) return "HEAP";
  if (props.stack) return "STACK";
  if (props.java_heap) return "JHEAP";
  if (props.jit) return "JIT";
  if (props.java) return "JAVA";
  if (props.ashmem) return "ASHM";
  if (props.vdex) return "VDEX";
  if (props.oat) return "OAT";
  if (props.dex) return "DEX";
  if (props.art) return "ART";
  if (props.dev) return "DEV";
  if (props.shared) return "SHR";
  if (props.cdata) return "CDAT";
  if (props.app && props.exec) return "APP";
  if (props.so) return "SO";
  if (props.exec) return "CODE";
  if (props.rw) return "DATA";
  if (props.system) return "SYS";
  if (props.anon) return "ANON";
  if (props.apk) return "APK";
  if (props.file) return "FILE";
  return "OTHR";
}

uint64_t ClientUI::ResolveExecStart(const ClientState::ModuleInfo& mod) const {
  if ((mod.perms & protocol::MODULE_PERM_EXEC) != 0) {
    return mod.start;
  }
  if (mod.path.empty()) {
    return mod.start;
  }
  for (const auto& other : state_.modules) {
    if (other.path == mod.path && (other.perms & protocol::MODULE_PERM_EXEC)) {
      return other.start;
    }
  }
  return mod.start;
}

const ClientState::ModuleInfo* ClientUI::FindModuleForAddress(uint64_t addr) const {
  for (const auto& mod : state_.modules) {
    if (addr >= mod.start && addr < mod.end) {
      return &mod;
    }
  }
  return nullptr;
}

void ClientUI::SyncPointerModuleSelection() {
  if (state_.modules.empty()) {
    pointer_scan_module_selected_.clear();
    return;
  }
  if (pointer_scan_module_selected_.size() == state_.modules.size()) {
    return;
  }
  std::vector<bool> next(state_.modules.size(), false);
  if (!pointer_scan_module_selected_.empty()) {
    const size_t min_size = std::min(pointer_scan_module_selected_.size(), state_.modules.size());
    for (size_t i = 0; i < min_size; ++i) {
      next[i] = pointer_scan_module_selected_[i];
    }
  }
  pointer_scan_module_selected_.swap(next);
}

void ClientUI::SyncPointerPreviewSelection() {
  if (state_.modules.empty()) {
    pointer_preview_module_selected_.clear();
    return;
  }
  if (pointer_preview_module_selected_.size() == state_.modules.size()) {
    return;
  }
  std::vector<bool> next(state_.modules.size(), false);
  if (!pointer_preview_module_selected_.empty()) {
    const size_t min_size = std::min(pointer_preview_module_selected_.size(), state_.modules.size());
    for (size_t i = 0; i < min_size; ++i) {
      next[i] = pointer_preview_module_selected_[i];
    }
  }
  pointer_preview_module_selected_.swap(next);
}

uint32_t ClientUI::GetPointerSizeFromModules() const {
  if (state_.pointer_size == 4 || state_.pointer_size == 8) {
    return state_.pointer_size;
  }
  if (state_.regs_arch == protocol::RegsArch::ARM64) {
    return 8;
  }
  if (state_.regs_arch == protocol::RegsArch::ARM32) {
    return 4;
  }
  for (const auto& mod : state_.modules) {
    if (mod.end > 0xFFFFFFFFull || mod.start > 0xFFFFFFFFull) {
      return 8;
    }
  }
  return 4;
}

void ClientUI::RenderPointerTreeNode(uint64_t addr,
                                     uint32_t pointer_size,
                                     uint32_t flags,
                                     int depth,
                                     int max_depth) {
  if (depth > max_depth) {
    ImGui::TextUnformatted("...");
    return;
  }
  const bool use_pvm = (flags & protocol::READ_FLAG_USE_PVM) != 0;

  auto compute_override = [&](ClientUI::DataTraverseEntry& e, int type) {
    e.addr = addr;
    e.override_type = type;
    e.override_valid = false;
    e.override_value = 0;
    e.override_size = 0;
    e.pointer_checked = false;
    e.pointer_valid = false;
    e.pointer_value = 0;

    if (type == kDataTraversePointerIndex) {
      std::vector<uint8_t> buf;
      if (ReadMemoryRangeEx(addr, pointer_size, &buf, false, false, use_pvm)) {
        uint64_t pv = 0;
        if (pointer_size == 4 && buf.size() >= 4) {
          uint32_t v32 = 0;
          std::memcpy(&v32, buf.data(), sizeof(v32));
          pv = v32;
        } else if (buf.size() >= 8) {
          std::memcpy(&pv, buf.data(), sizeof(pv));
          pv = StripTag64(pv);
        }
        e.pointer_value = pv;
        if (pv != 0) {
          std::vector<uint8_t> probe;
          if (ReadMemoryRangeEx(pv, 1, &probe, false, false, use_pvm)) {
            e.pointer_valid = true;
          }
        }
      }
      e.pointer_checked = true;
      return;
    }

    size_t size = 4;
    switch (type) {
      case 0: size = 1; break;
      case 1: size = 2; break;
      case 2: size = 4; break;
      case 3: size = 8; break;
      case 4: size = 4; break;
      case 5: size = 8; break;
      default: size = 4; break;
    }
    std::vector<uint8_t> buf;
    if (ReadMemoryRangeEx(addr, static_cast<uint32_t>(size), &buf, false, false, use_pvm)) {
      uint64_t v = 0;
      std::memcpy(&v, buf.data(), std::min<size_t>(size, sizeof(v)));
      e.override_value = v;
      e.override_size = static_cast<uint8_t>(size);
      e.override_valid = true;
    }
  };

  auto format_value = [&](const ClientUI::DataTraverseEntry& e, int type) -> std::string {
    uint64_t raw = e.override_valid ? e.override_value : e.raw_value;
    char line[256] = {0};
    switch (type) {
      case 0: {
        uint8_t v = static_cast<uint8_t>(raw & 0xFFu);
        std::snprintf(line, sizeof(line), "0x%llX : %u (0x%02X)",
                      static_cast<unsigned long long>(e.addr), v, v);
        break;
      }
      case 1: {
        uint16_t v = static_cast<uint16_t>(raw & 0xFFFFu);
        std::snprintf(line, sizeof(line), "0x%llX : %u (0x%04X)",
                      static_cast<unsigned long long>(e.addr), v, v);
        break;
      }
      case 2: {
        uint32_t v = static_cast<uint32_t>(raw & 0xFFFFFFFFu);
        std::snprintf(line, sizeof(line), "0x%llX : %u (0x%08X)",
                      static_cast<unsigned long long>(e.addr), v, v);
        break;
      }
      case 3: {
        uint64_t v = raw;
        std::snprintf(line, sizeof(line), "0x%llX : %llu (0x%016llX)",
                      static_cast<unsigned long long>(e.addr),
                      static_cast<unsigned long long>(v),
                      static_cast<unsigned long long>(v));
        break;
      }
      case 4: {
        float v = 0.0f;
        std::memcpy(&v, &raw, sizeof(v));
        std::snprintf(line, sizeof(line), "0x%llX : %.6f",
                      static_cast<unsigned long long>(e.addr), v);
        break;
      }
      case 5: {
        double v = 0.0;
        std::memcpy(&v, &raw, sizeof(v));
        std::snprintf(line, sizeof(line), "0x%llX : %.6f",
                      static_cast<unsigned long long>(e.addr), v);
        break;
      }
      case kDataTraversePointerIndex: {
        std::snprintf(line, sizeof(line), "0x%llX : %s",
                      static_cast<unsigned long long>(e.addr),
                      Hex64(e.pointer_value).c_str());
        break;
      }
      default:
        std::snprintf(line, sizeof(line), "0x%llX : (unsupported)",
                      static_cast<unsigned long long>(e.addr));
        break;
    }
    return line;
  };

  ClientUI::DataTraverseEntry* node = nullptr;
  auto it = data_traverse_node_overrides_.find(addr);
  if (it != data_traverse_node_overrides_.end()) {
    node = &it->second;
  }
  const int effective_type =
      (node && node->override_type >= 0) ? node->override_type : kDataTraversePointerIndex;

  std::string label;
  uint64_t next = 0;
  bool pointer_valid = false;
  bool can_expand = false;
  bool read_ok = true;

  if (effective_type == kDataTraversePointerIndex) {
    if (node && node->override_type == kDataTraversePointerIndex && node->pointer_checked) {
      next = node->pointer_value;
      pointer_valid = node->pointer_valid;
    } else {
      if (!ReadPointerValue(net_, addr, pointer_size, flags, &next)) {
        read_ok = false;
      } else if (next != 0) {
        std::vector<uint8_t> probe;
        if (ReadMemoryRangeEx(next, 1, &probe, false, false, use_pvm)) {
          pointer_valid = true;
        }
      }
    }
    if (read_ok) {
      label = Hex64(addr) + " -> " + Hex64(next);
      can_expand = pointer_valid && next != 0 && depth < max_depth;
    } else {
      label = Hex64(addr) + " -> <读取失败>";
    }
  } else {
    if (!node || !node->override_valid) {
      label = Hex64(addr) + " : <读取失败>";
    } else {
      label = format_value(*node, effective_type);
    }
  }

  ImGui::PushID(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)));
  bool open = false;
  if (effective_type == kDataTraversePointerIndex && can_expand) {
    open = ImGui::TreeNodeEx("##ptrchild",
                             ImGuiTreeNodeFlags_SpanFullWidth,
                             "%s",
                             label.c_str());
  } else {
    ImGui::Selectable(label.c_str());
  }

  if (ImGui::BeginPopupContextItem("ptrnode_ctx")) {
    if (ImGui::MenuItem(u8"使用默认类型(指针)")) {
      data_traverse_node_overrides_.erase(addr);
    }
    ImGui::Separator();
    ImGui::TextUnformatted(u8"切换类型");
    for (int t = 0; t < IM_ARRAYSIZE(kDataTraverseTypeNames); ++t) {
      const bool selected = (node && node->override_type == t);
      if (ImGui::MenuItem(kDataTraverseTypeNames[t], nullptr, selected)) {
        auto& entry = data_traverse_node_overrides_[addr];
        compute_override(entry, t);
      }
    }
    ImGui::EndPopup();
  }

  if (open) {
    RenderPointerTreeNode(next, pointer_size, flags, depth + 1, max_depth);
    ImGui::TreePop();
  }
  ImGui::PopID();
}

void ClientUI::RenderDisasmWindow() {
  ImGui::Begin(u8"调试窗 - 反汇编", &show_debug_window_);
  RenderDisasmPanel();
  ImGui::End();
}

void ClientUI::RenderMemoryViewWindow() {
  ImGui::Begin(u8"查看内存(CE工作区)", &show_memory_window_);
  RenderMemoryViewPanel();
  ImGui::End();
}

void ClientUI::RenderDisasmPanel() {
  ImGui::Text(u8"CE式连续反汇编（失败自动HEX回退）");

  const auto jump_to = [&](uint64_t target, bool sync_memory) {
    if (target == 0) {
      return;
    }
    std::snprintf(disasm_addr_, sizeof(disasm_addr_), "0x%llX",
                  static_cast<unsigned long long>(target));
    std::snprintf(disasm_jump_addr_, sizeof(disasm_jump_addr_), "0x%llX",
                  static_cast<unsigned long long>(target));
    RunDisasm(target);
    if (sync_memory && disasm_sync_memory_) {
      std::snprintf(mem_addr_, sizeof(mem_addr_), "0x%llX",
                    static_cast<unsigned long long>(target));
      ReadMemory();
    }
  };

  const auto jump_exec_segment = [&](int dir) {
    if (state_.modules.empty()) {
      FetchModules();
    }
    if (state_.modules.empty()) {
      disasm_status_ = u8"模块为空，无法跳转可执行段";
      return;
    }
    const uint64_t current = ParseAddress(disasm_addr_);
    uint64_t next = 0;
    if (dir > 0) {
      uint64_t best = std::numeric_limits<uint64_t>::max();
      uint64_t first = 0;
      for (const auto& mod : state_.modules) {
        if ((mod.perms & protocol::MODULE_PERM_EXEC) == 0) {
          continue;
        }
        if (first == 0 || mod.start < first) {
          first = mod.start;
        }
        if (mod.start > current && mod.start < best) {
          best = mod.start;
        }
      }
      next = (best == std::numeric_limits<uint64_t>::max()) ? first : best;
    } else {
      uint64_t best = 0;
      uint64_t last = 0;
      for (const auto& mod : state_.modules) {
        if ((mod.perms & protocol::MODULE_PERM_EXEC) == 0) {
          continue;
        }
        if (mod.start > last) {
          last = mod.start;
        }
        if (mod.start < current && mod.start > best) {
          best = mod.start;
        }
      }
      next = best == 0 ? last : best;
    }
    if (next == 0) {
      disasm_status_ = u8"未找到可执行段";
      return;
    }
    jump_to(next, false);
  };

  ImGui::InputText(u8"当前地址", disasm_addr_, sizeof(disasm_addr_));
  ImGui::SameLine();
  ImGui::InputText(u8"跳转地址", disasm_jump_addr_, sizeof(disasm_jump_addr_));
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##disasm", &address_default_hex_);
  ImGui::InputInt(u8"窗口字节数", &disasm_size_);
  if (disasm_size_ < 16) {
    disasm_size_ = 16;
  }
  if (disasm_size_ > 8192) {
    disasm_size_ = 8192;
  }
  ImGui::InputInt(u8"滚轮步进(字节)", &disasm_scroll_step_);
  if (disasm_scroll_step_ < 1) {
    disasm_scroll_step_ = 1;
  }
  if (disasm_scroll_step_ > 4096) {
    disasm_scroll_step_ = 4096;
  }
  ImGui::InputInt(u8"翻页步进(字节)", &disasm_page_step_);
  if (disasm_page_step_ < 16) {
    disasm_page_step_ = 16;
  }
  if (disasm_page_step_ > 32768) {
    disasm_page_step_ = 32768;
  }

  const char* arch_items[] = { u8"ARM64", u8"ARM(32位)" };
  ImGui::Combo(u8"架构", &disasm_arch_, arch_items, IM_ARRAYSIZE(arch_items));
  if (disasm_arch_ == 1) {
    ImGui::Checkbox(u8"Thumb", &disasm_thumb_);
  }
  ImGui::Checkbox(u8"自动架构/Thumb", &disasm_auto_arch_);
  const char* view_modes[] = { u8"汇编+HEX(失败回退)", u8"仅HEX" };
  ImGui::Combo(u8"显示模式", &disasm_view_mode_, view_modes, IM_ARRAYSIZE(view_modes));
  ImGui::Checkbox(u8"连续浏览模式", &disasm_continuous_mode_);
  ImGui::SameLine();
  ImGui::Checkbox(u8"跟随PC", &disasm_follow_pc_);
  ImGui::SameLine();
  ImGui::Checkbox(u8"联动内存窗口", &disasm_sync_memory_);
  ImGui::Checkbox(u8"允许读取非驻留页(可能触发缺页)", &disasm_allow_nonresident_);
  ImGui::Checkbox(u8"允许读取不可读区域(危险)", &disasm_ignore_perms_);
  ImGui::Checkbox(u8"使用系统读取模式(process_vm_readv)", &disasm_use_pvm_);

  if (ImGui::Button(u8"读取并反汇编")) {
    jump_to(ParseAddress(disasm_addr_), false);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"跳转")) {
    jump_to(ParseAddress(disasm_jump_addr_), false);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"上一页")) {
    const uint64_t current = ParseAddress(disasm_addr_);
    const uint64_t step = static_cast<uint64_t>(disasm_page_step_);
    jump_to(current > step ? current - step : 1, false);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"下一页")) {
    const uint64_t current = ParseAddress(disasm_addr_);
    jump_to(current + static_cast<uint64_t>(disasm_page_step_), false);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"上个可执行段")) {
    jump_exec_segment(-1);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"下个可执行段")) {
    jump_exec_segment(1);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"定位PC")) {
    if (!state_.regs_valid) {
      FetchRegs();
    }
    jump_to(GetProgramCounterAddress(), true);
  }

  if (ImGui::Button(u8"添加书签")) {
    const uint64_t current = ParseAddress(disasm_addr_);
    if (current != 0 &&
        std::find(disasm_bookmarks_.begin(), disasm_bookmarks_.end(), current) == disasm_bookmarks_.end()) {
      disasm_bookmarks_.push_back(current);
      std::sort(disasm_bookmarks_.begin(), disasm_bookmarks_.end());
    }
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"删除书签") &&
      disasm_bookmark_selected_ >= 0 &&
      disasm_bookmark_selected_ < static_cast<int>(disasm_bookmarks_.size())) {
    disasm_bookmarks_.erase(disasm_bookmarks_.begin() + disasm_bookmark_selected_);
    if (disasm_bookmark_selected_ >= static_cast<int>(disasm_bookmarks_.size())) {
      disasm_bookmark_selected_ = static_cast<int>(disasm_bookmarks_.size()) - 1;
    }
  }

  if (!disasm_bookmarks_.empty()) {
    ImGui::BeginChild("disasm_bookmarks", ImVec2(0, 64), true, ImGuiWindowFlags_HorizontalScrollbar);
    for (size_t i = 0; i < disasm_bookmarks_.size(); ++i) {
      ImGui::PushID(static_cast<int>(i));
      char label[64] = {0};
      std::snprintf(label, sizeof(label), "0x%llX",
                    static_cast<unsigned long long>(disasm_bookmarks_[i]));
      if (ImGui::Selectable(label, disasm_bookmark_selected_ == static_cast<int>(i),
                            ImGuiSelectableFlags_AllowDoubleClick)) {
        disasm_bookmark_selected_ = static_cast<int>(i);
        if (ImGui::IsMouseDoubleClicked(0)) {
          jump_to(disasm_bookmarks_[i], false);
        }
      }
      ImGui::PopID();
    }
    ImGui::EndChild();
  }

  if (disasm_follow_pc_) {
    const uint64_t now = NowMs();
    if (now - disasm_follow_last_ms_ >= 300) {
      if (FetchRegs()) {
        const uint64_t pc = GetProgramCounterAddress();
        if (pc != 0) {
          jump_to(pc, true);
        }
      }
      disasm_follow_last_ms_ = now;
    }
  }

  const bool panel_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
  if (disasm_continuous_mode_ && panel_focused && !ImGui::GetIO().WantTextInput) {
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) {
      const uint64_t current = ParseAddress(disasm_addr_);
      const uint64_t step = static_cast<uint64_t>(disasm_page_step_);
      jump_to(current > step ? current - step : 1, false);
    } else if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) {
      const uint64_t current = ParseAddress(disasm_addr_);
      jump_to(current + static_cast<uint64_t>(disasm_page_step_), false);
    }
  }

  if (!disasm_status_.empty()) {
    ImGui::Text(u8"状态：%s", disasm_status_.c_str());
  }
  ImGui::Text(u8"统计：指令=%u，HEX回退=%u", disasm_last_decoded_count_, disasm_last_fallback_count_);

  const float child_h = std::max(220.0f, ImGui::GetContentRegionAvail().y);
  ImGui::BeginChild("disasm", ImVec2(0, child_h), true, ImGuiWindowFlags_HorizontalScrollbar);
  const bool child_hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
  if (disasm_lines_.empty()) {
    ImGui::TextUnformatted(u8"<无输出>");
  } else {
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(disasm_lines_.size()));
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        ImGui::TextUnformatted(disasm_lines_[static_cast<size_t>(row)].c_str());
      }
    }
  }
  ImGui::EndChild();

  if (disasm_continuous_mode_ &&
      child_hovered &&
      !ImGui::GetIO().WantTextInput &&
      ImGui::GetIO().MouseWheel != 0.0f) {
    const uint64_t current = ParseAddress(disasm_addr_);
    const uint64_t step = static_cast<uint64_t>(disasm_scroll_step_);
    if (ImGui::GetIO().MouseWheel > 0.0f) {
      jump_to(current > step ? current - step : 1, false);
    } else {
      jump_to(current + step, false);
    }
  }
}

void ClientUI::RenderPointerScanWindow() {
  ImGui::Begin(u8"指针扫描", &show_pointer_scan_window_);
  ImGui::InputText(u8"目标地址(多地址逗号/空格)", pointer_scan_target_, sizeof(pointer_scan_target_));
  ImGui::TextUnformatted(u8"最多支持2000个目标地址");
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##ptrscan", &address_default_hex_);
  ImGui::InputInt(u8"指针层数", &pointer_scan_depth_);
  if (pointer_scan_depth_ < 1) {
    pointer_scan_depth_ = 1;
  }
  if (pointer_scan_depth_ > 50) {
    pointer_scan_depth_ = 50;
  }
  ImGui::InputInt(u8"最大偏移", &pointer_scan_max_offset_);
  if (pointer_scan_max_offset_ < 0) {
    pointer_scan_max_offset_ = 0;
  }

  ImGui::Checkbox(u8"使用特定模块搜索指针", &pointer_scan_use_modules_);
  if (pointer_scan_use_modules_) {
    if (ImGui::Button(u8"选择模块")) {
      pointer_scan_select_popup_ = true;
    }
    ImGui::SameLine();
    size_t selected = 0;
    for (bool v : pointer_scan_module_selected_) {
      if (v) {
        selected++;
      }
    }
    ImGui::Text(u8"已选 %zu 个模块", selected);
  }

  ImGui::Checkbox(u8"使用索引加速(一次缓存指针值)", &pointer_scan_use_index_);
  ImGui::InputInt(u8"线程数(0=自动)", &pointer_scan_thread_count_);
  if (pointer_scan_thread_count_ < 0) {
    pointer_scan_thread_count_ = 0;
  }
  if (pointer_scan_use_index_) {
    ImGui::InputText(u8"索引文件", pointer_scan_index_path_, sizeof(pointer_scan_index_path_));
    if (ImGui::Button(u8"加载索引")) {
      uint32_t idx_psize = 0;
      uint32_t idx_pid = 0;
      uint64_t idx_flags = 0;
      std::vector<std::pair<uint64_t, uint64_t>> entries;
      std::string err;
      if (LoadPointerIndexFile(pointer_scan_index_path_, &idx_psize, &idx_pid, &idx_flags, &entries, &err)) {
        const bool idx_byte_step = (idx_flags & kPointerIndexFlagByteStep) != 0;
        const bool idx_strict = (idx_flags & kPointerIndexFlagStrict) != 0;
        if ((pointer_scan_byte_step_ && !idx_byte_step) || (pointer_scan_freeze_ && !idx_strict)) {
          pointer_index_entries_.clear();
          pointer_index_pointer_size_ = 0;
          pointer_index_pid_ = 0;
          pointer_index_flags_ = 0;
          if (pointer_scan_freeze_ && !idx_strict) {
            pointer_index_status_ = u8"索引未启用严格模式，已忽略";
          } else {
            pointer_index_status_ = u8"索引未启用字节步进，已忽略";
          }
        } else {
          pointer_index_entries_.swap(entries);
          pointer_index_pointer_size_ = idx_psize;
          pointer_index_pid_ = idx_pid;
          pointer_index_flags_ = idx_flags;
          pointer_index_status_ = u8"索引加载完成";
        }
      } else {
        pointer_index_status_ = err.empty() ? u8"索引加载失败" : err;
      }
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"清空索引")) {
      pointer_index_entries_.clear();
      pointer_index_pointer_size_ = 0;
      pointer_index_pid_ = 0;
      pointer_index_flags_ = 0;
      pointer_index_status_ = u8"索引已清空";
    }
    if (!pointer_index_status_.empty()) {
      ImGui::Text(u8"索引状态：%s", pointer_index_status_.c_str());
      if (!pointer_index_entries_.empty()) {
        ImGui::Text(u8"索引条目：%zu", pointer_index_entries_.size());
      }
    }
  }

  ImGui::Checkbox(u8"扫描读取使用系统读取模式(process_vm_readv)", &pointer_scan_use_pvm_);
  ImGui::Checkbox(u8"扫描允许非驻留页(严格)", &pointer_scan_allow_nonresident_);
  ImGui::Checkbox(u8"严格快照(冻结进程)", &pointer_scan_freeze_);
  ImGui::Checkbox(u8"字节步进(不对齐,不漏)", &pointer_scan_byte_step_);

  if (ImGui::Button(u8"开始扫描")) {
    RunPointerScan();
  }

  if (!pointer_scan_status_.empty()) {
    ImGui::Text(u8"状态：%s", pointer_scan_status_.c_str());
  }
  if (!pointer_scan_output_path_.empty()) {
    ImGui::Text(u8"输出：%s", pointer_scan_output_path_.c_str());
    ImGui::Text(u8"数量：%" PRIu64, pointer_scan_count_);
  }

  ImGui::Separator();
  ImGui::Text(u8"结果预览");
  ImGui::InputScalar(u8"预览页索引", ImGuiDataType_U64, &pointer_preview_page_index_);
  ImGui::InputScalar(u8"预览页大小", ImGuiDataType_U32, &pointer_preview_page_size_);
  ImGui::InputInt(u8"偏移最小值", &pointer_preview_min_offset_);
  ImGui::InputInt(u8"偏移最大值", &pointer_preview_max_offset_);
  ImGui::Checkbox(u8"按模块过滤", &pointer_preview_use_modules_);
  if (pointer_preview_use_modules_) {
    if (ImGui::Button(u8"选择过滤模块")) {
      pointer_preview_select_popup_ = true;
    }
    ImGui::SameLine();
    size_t selected = 0;
    for (bool v : pointer_preview_module_selected_) {
      if (v) {
        selected++;
      }
    }
    ImGui::Text(u8"已选 %zu 个模块", selected);
  }
  ImGui::Checkbox(u8"按分类过滤", &pointer_preview_use_category_);
  if (pointer_preview_use_category_) {
    ImGui::Combo(u8"分类", &pointer_preview_category_, kModuleCategoryNames, IM_ARRAYSIZE(kModuleCategoryNames));
  }
  ImGui::InputText(u8"模块关键字过滤", pointer_preview_module_keyword_, sizeof(pointer_preview_module_keyword_));
  if (ImGui::Button(u8"加载预览")) {
    if (pointer_scan_output_path_.empty()) {
      pointer_preview_status_ = u8"暂无扫描结果文件";
    } else {
      if (state_.modules.empty()) {
        FetchModules();
      }
      SyncPointerPreviewSelection();
      std::string err;
      const bool ok = LoadPointerPreview(pointer_scan_output_path_,
                                         pointer_preview_page_index_,
                                         pointer_preview_page_size_,
                                         pointer_preview_min_offset_,
                                         pointer_preview_max_offset_,
                                         pointer_preview_use_modules_,
                                         pointer_preview_module_selected_,
                                         pointer_preview_use_category_,
                                         pointer_preview_category_,
                                         pointer_preview_module_keyword_,
                                         &pointer_preview_items_,
                                         &pointer_preview_total_,
                                         &err);
      pointer_preview_status_ = ok ? u8"预览已加载" : err;
    }
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"导出当前页(CSV)")) {
    if (pointer_preview_items_.empty()) {
      pointer_preview_status_ = u8"没有可导出的预览内容";
    } else {
      std::filesystem::create_directories("seach_point/export");
      const std::string filename = std::string("seach_point/export/ptr_preview_") +
                                   NowTimeString() + ".csv";
      std::ofstream ofs(filename, std::ios::out | std::ios::binary);
      if (!ofs.is_open()) {
        pointer_preview_status_ = u8"无法写入导出文件";
      } else {
        ofs << "line\n";
        for (const auto& line : pointer_preview_items_) {
          std::string escaped = line;
          size_t pos = 0;
          while ((pos = escaped.find("\"", pos)) != std::string::npos) {
            escaped.insert(pos, "\"");
            pos += 2;
          }
          ofs << "\"" << escaped << "\"\n";
        }
        pointer_preview_status_ = std::string(u8"已导出：") + filename;
      }
    }
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"导出当前页(TXT)")) {
    if (pointer_preview_items_.empty()) {
      pointer_preview_status_ = u8"没有可导出的预览内容";
    } else {
      std::filesystem::create_directories("seach_point/export");
      const std::string filename = std::string("seach_point/export/ptr_preview_") +
                                   NowTimeString() + ".txt";
      std::ofstream ofs(filename, std::ios::out | std::ios::binary);
      if (!ofs.is_open()) {
        pointer_preview_status_ = u8"无法写入导出文件";
      } else {
        for (const auto& line : pointer_preview_items_) {
          ofs << line << "\n";
        }
        pointer_preview_status_ = std::string(u8"已导出：") + filename;
      }
    }
  }
  if (!pointer_preview_status_.empty()) {
    ImGui::Text(u8"预览状态：%s", pointer_preview_status_.c_str());
    ImGui::Text(u8"匹配总数：%" PRIu64, pointer_preview_total_);
  }
  ImGui::BeginChild("ptr_preview", ImVec2(0, 160), true, ImGuiWindowFlags_HorizontalScrollbar);
  for (const auto& line : pointer_preview_items_) {
    ImGui::TextUnformatted(line.c_str());
  }
  ImGui::EndChild();

  if (pointer_scan_select_popup_) {
    if (state_.modules.empty()) {
      FetchModules();
    }
    SyncPointerModuleSelection();
    ImGui::OpenPopup(u8"选择模块");
    pointer_scan_select_popup_ = false;
  }

  if (pointer_preview_select_popup_) {
    if (state_.modules.empty()) {
      FetchModules();
    }
    SyncPointerPreviewSelection();
    ImGui::OpenPopup(u8"选择过滤模块");
    pointer_preview_select_popup_ = false;
  }

  if (ImGui::BeginPopupModal(u8"选择模块", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    if (state_.modules.empty()) {
      ImGui::TextUnformatted(u8"模块列表为空，请先打开进程并刷新模块。");
    } else {
      ImGui::InputText(u8"搜索模块", pointer_scan_module_search_, sizeof(pointer_scan_module_search_));
      if (ImGui::Button(u8"全选")) {
        pointer_scan_module_selected_.assign(state_.modules.size(), true);
      }
      ImGui::SameLine();
      if (ImGui::Button(u8"清空")) {
        pointer_scan_module_selected_.assign(state_.modules.size(), false);
      }

      if (ImGui::BeginTable("ptr_module_table", 5,
                            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                            ImVec2(720, 260))) {
        ImGui::TableSetupColumn(u8"选", ImGuiTableColumnFlags_WidthFixed, 32.0f);
        ImGui::TableSetupColumn(u8"范围", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn(u8"权限", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn(u8"段", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn(u8"路径", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < state_.modules.size(); ++i) {
          const auto& mod = state_.modules[i];
          if (pointer_scan_module_search_[0] != '\0' &&
              !ContainsCI(mod.path, pointer_scan_module_search_)) {
            continue;
          }
          ImGui::TableNextRow();
          ImGui::TableNextColumn();
          ImGui::PushID(static_cast<int>(i));
          bool checked = pointer_scan_module_selected_[i];
          if (ImGui::Checkbox("##sel", &checked)) {
            pointer_scan_module_selected_[i] = checked;
          }
          ImGui::PopID();

          ImGui::TableNextColumn();
          ImGui::Text("0x%llX-0x%llX",
                      static_cast<unsigned long long>(mod.start),
                      static_cast<unsigned long long>(mod.end));

          ImGui::TableNextColumn();
          ImGui::TextUnformatted(PermsToString(mod.perms).c_str());

          ImGui::TableNextColumn();
          const std::string gg_label = ModuleGGLabel(mod);
          ImGui::TextUnformatted(gg_label.c_str());

          ImGui::TableNextColumn();
          if (mod.path.empty()) {
            ImGui::TextUnformatted("");
          } else {
            ImGui::TextUnformatted(mod.path.c_str());
          }
        }
        ImGui::EndTable();
      }
    }

    if (ImGui::Button(u8"完成选择")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"取消")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (ImGui::BeginPopupModal(u8"选择过滤模块", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    if (state_.modules.empty()) {
      ImGui::TextUnformatted(u8"模块列表为空，请先打开进程并刷新模块。");
    } else {
      ImGui::InputText(u8"搜索模块", pointer_preview_module_search_, sizeof(pointer_preview_module_search_));
      if (ImGui::Button(u8"全选")) {
        pointer_preview_module_selected_.assign(state_.modules.size(), true);
      }
      ImGui::SameLine();
      if (ImGui::Button(u8"清空")) {
        pointer_preview_module_selected_.assign(state_.modules.size(), false);
      }

      if (ImGui::BeginTable("ptr_preview_module_table", 5,
                            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                            ImVec2(720, 260))) {
        ImGui::TableSetupColumn(u8"选", ImGuiTableColumnFlags_WidthFixed, 32.0f);
        ImGui::TableSetupColumn(u8"范围", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn(u8"权限", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn(u8"段", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn(u8"路径", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < state_.modules.size(); ++i) {
          const auto& mod = state_.modules[i];
          if (pointer_preview_module_search_[0] != '\0' &&
              !ContainsCI(mod.path, pointer_preview_module_search_)) {
            continue;
          }
          ImGui::TableNextRow();
          ImGui::TableNextColumn();
          ImGui::PushID(static_cast<int>(i));
          bool checked = pointer_preview_module_selected_[i];
          if (ImGui::Checkbox("##sel", &checked)) {
            pointer_preview_module_selected_[i] = checked;
          }
          ImGui::PopID();

          ImGui::TableNextColumn();
          ImGui::Text("0x%llX-0x%llX",
                      static_cast<unsigned long long>(mod.start),
                      static_cast<unsigned long long>(mod.end));

          ImGui::TableNextColumn();
          ImGui::TextUnformatted(PermsToString(mod.perms).c_str());

          ImGui::TableNextColumn();
          const std::string gg_label = ModuleGGLabel(mod);
          ImGui::TextUnformatted(gg_label.c_str());

          ImGui::TableNextColumn();
          if (mod.path.empty()) {
            ImGui::TextUnformatted("");
          } else {
            ImGui::TextUnformatted(mod.path.c_str());
          }
        }
        ImGui::EndTable();
      }
    }

    if (ImGui::Button(u8"完成选择")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"取消")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  ImGui::End();
}

void ClientUI::RenderPointerCompareWindow() {
  ImGui::Begin(u8"指针对比", &show_pointer_compare_window_);
  ImGui::Text(u8"指针文件目录：./seach_point/");
  ImGui::Checkbox(u8"多文件对比模式", &pointer_compare_multi_mode_);
  if (ImGui::Button(u8"导入TXT指针文件")) {
    const wchar_t* filter = L"Text\0*.txt;*.log\0All Files\0*.*\0";
    const std::string txt_path = OpenFileDialog(filter, L"选择TXT指针文件");
    if (!txt_path.empty()) {
      std::filesystem::create_directories("seach_point/import");
      const std::string out_path = std::string("seach_point/import/ptr_import_") + NowTimeString() + ".r3p";
      uint32_t pointer_size = GetPointerSizeFromModules();
      if (pointer_size == 0) {
        pointer_size = 8;
      }
      std::string err;
      if (ConvertPointerTextToBinary(txt_path, out_path, pointer_size, &err)) {
        pointer_compare_status_ = std::string(u8"导入完成：") + out_path;
        if (pointer_compare_multi_mode_) {
          pointer_compare_files_.push_back(out_path);
        } else {
          if (pointer_compare_file_a_.empty()) {
            pointer_compare_file_a_ = out_path;
          } else {
            pointer_compare_file_b_ = out_path;
          }
        }
      } else {
        pointer_compare_status_ = err.empty() ? u8"导入失败" : err;
      }
    }
  }
  if (pointer_compare_multi_mode_) {
    if (ImGui::Button(u8"添加指针文件")) {
      const wchar_t* filter = L"R3 Pointer\0*.r3p\0All Files\0*.*\0";
      const std::string path = OpenFileDialog(filter, L"选择指针文件");
      if (!path.empty()) {
        pointer_compare_files_.push_back(path);
      }
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"清空列表")) {
      pointer_compare_files_.clear();
    }
    ImGui::BeginChild("ptr_compare_files", ImVec2(0, 90), true);
    for (size_t i = 0; i < pointer_compare_files_.size(); ++i) {
      ImGui::Text(u8"%zu: %s", i + 1, pointer_compare_files_[i].c_str());
    }
    ImGui::EndChild();
  } else {
    if (ImGui::Button(u8"选择第一份指针文件")) {
      const wchar_t* filter = L"R3 Pointer\0*.r3p\0All Files\0*.*\0";
      pointer_compare_file_a_ = OpenFileDialog(filter, L"选择指针文件A");
    }
    if (!pointer_compare_file_a_.empty()) {
      ImGui::Text(u8"A：%s", pointer_compare_file_a_.c_str());
    }
    if (ImGui::Button(u8"选择第二份指针文件")) {
      const wchar_t* filter = L"R3 Pointer\0*.r3p\0All Files\0*.*\0";
      pointer_compare_file_b_ = OpenFileDialog(filter, L"选择指针文件B");
    }
    if (!pointer_compare_file_b_.empty()) {
      ImGui::Text(u8"B：%s", pointer_compare_file_b_.c_str());
    }
  }
  ImGui::Checkbox(u8"极速对比(哈希过滤)", &pointer_compare_fast_mode_);
  ImGui::Checkbox(u8"对比读取使用系统读取模式(process_vm_readv)", &pointer_compare_use_pvm_);
  ImGui::Checkbox(u8"对比允许非驻留页(严格)", &pointer_compare_allow_nonresident_);
  if (ImGui::Button(u8"开始对比")) {
    RunPointerCompare();
  }
  if (!pointer_compare_status_.empty()) {
    ImGui::Text(u8"状态：%s", pointer_compare_status_.c_str());
  }
  if (!pointer_compare_output_path_.empty()) {
    ImGui::Text(u8"输出：%s", pointer_compare_output_path_.c_str());
    ImGui::Text(u8"数量：%" PRIu64, pointer_compare_count_);
  }
  if (!pointer_compare_export_path_.empty()) {
    ImGui::Text(u8"导出：%s", pointer_compare_export_path_.c_str());
  }
  if (ImGui::Button(u8"导出对比结果(指针格式)")) {
    if (pointer_compare_output_path_.empty()) {
      pointer_compare_status_ = u8"暂无对比结果文件";
    } else {
      std::filesystem::create_directories("seach_point/compare");
      const std::string filename = std::string("seach_point/compare/compare_export_") +
                                   NowTimeString() + ".txt";
      std::string err;
      if (ExportPointerText(pointer_compare_output_path_, filename, &err)) {
        pointer_compare_export_path_ = filename;
        pointer_compare_status_ = u8"导出完成";
      } else {
        pointer_compare_status_ = err;
      }
    }
  }

  ImGui::Separator();
  ImGui::Text(u8"对比结果预览");
  ImGui::InputScalar(u8"预览页索引", ImGuiDataType_U64, &pointer_compare_preview_page_index_);
  ImGui::InputScalar(u8"预览页大小", ImGuiDataType_U32, &pointer_compare_preview_page_size_);
  if (ImGui::Button(u8"加载预览")) {
    if (pointer_compare_output_path_.empty()) {
      pointer_compare_preview_status_ = u8"暂无对比结果文件";
    } else {
      std::string err;
      const bool ok = LoadPointerPreview(pointer_compare_output_path_,
                                         pointer_compare_preview_page_index_,
                                         pointer_compare_preview_page_size_,
                                         std::numeric_limits<int64_t>::min(),
                                         std::numeric_limits<int64_t>::max(),
                                         false,
                                         pointer_preview_module_selected_,
                                         false,
                                         0,
                                         "",
                                         &pointer_compare_preview_items_,
                                         &pointer_compare_preview_total_,
                                         &err);
      pointer_compare_preview_status_ = ok ? u8"预览已加载" : err;
    }
  }
  if (!pointer_compare_preview_status_.empty()) {
    ImGui::Text(u8"预览状态：%s", pointer_compare_preview_status_.c_str());
    ImGui::Text(u8"匹配总数：%" PRIu64, pointer_compare_preview_total_);
  }
  ImGui::BeginChild("ptr_compare_preview", ImVec2(0, 160), true, ImGuiWindowFlags_HorizontalScrollbar);
  for (const auto& line : pointer_compare_preview_items_) {
    ImGui::TextUnformatted(line.c_str());
  }
  ImGui::EndChild();
  ImGui::End();
}

void ClientUI::RenderDataTraverseWindow() {
  ImGui::Begin(u8"数据遍历", &show_data_traverse_window_);
  RenderDataTraversePanel();
  ImGui::End();
}

void ClientUI::RenderDataTraversePanel() {
  ImGui::InputText(u8"起始地址", data_traverse_addr_, sizeof(data_traverse_addr_));
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##traverse", &address_default_hex_);
  ImGui::InputInt(u8"数量", &data_traverse_count_);
  ImGui::InputInt(u8"步长(字节)", &data_traverse_stride_);
  ImGui::Combo(u8"类型", &data_traverse_type_, kDataTraverseTypeNames, IM_ARRAYSIZE(kDataTraverseTypeNames));
  ImGui::Checkbox(u8"自动识别指针", &data_traverse_auto_pointer_);
  ImGui::SameLine();
  ImGui::Checkbox(u8"只验证指针(轻量)", &data_traverse_light_mode_);
  ImGui::InputInt(u8"指针阈值", &data_traverse_pointer_threshold_);
  if (data_traverse_pointer_threshold_ < 1) {
    data_traverse_pointer_threshold_ = 1;
  }
  if (data_traverse_pointer_threshold_ > 10) {
    data_traverse_pointer_threshold_ = 10;
  }
  ImGui::Checkbox(u8"使用系统读取模式(process_vm_readv)", &data_traverse_use_pvm_);
  if (ImGui::Button(u8"读取")) {
    RunDataTraverse();
  }
  if (!data_traverse_status_.empty()) {
    ImGui::Text(u8"状态：%s", data_traverse_status_.c_str());
  }
  ImGui::BeginChild("data_traverse_list", ImVec2(0, 260), true, ImGuiWindowFlags_HorizontalScrollbar);
  if (ImGui::BeginPopupContextWindow("traverse_ctx",
                                     ImGuiPopupFlags_MouseButtonRight | ImGuiPopupFlags_NoOpenOverItems)) {
    ImGui::TextUnformatted(u8"切换类型");
    for (int i = 0; i < IM_ARRAYSIZE(kDataTraverseTypeNames); ++i) {
      if (ImGui::MenuItem(kDataTraverseTypeNames[i], nullptr, data_traverse_type_ == i)) {
        data_traverse_type_ = i;
        RunDataTraverse();
      }
    }
    ImGui::Separator();
    if (ImGui::MenuItem(u8"重新读取")) {
      RunDataTraverse();
    }
    ImGui::EndPopup();
  }
  RenderTraverseEntries(data_traverse_entries_, 0);
  ImGui::EndChild();
}

void ClientUI::RenderMemoryViewPanel() {
  ImGui::Text(u8"查看内存工作区（Memory + Disasm 联动）");
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##memview", &address_default_hex_);
  ImGui::InputText(u8"地址", mem_addr_, sizeof(mem_addr_));
  ImGui::InputInt(u8"大小", &mem_size_);
  ImGui::Combo(u8"读取类型", &read_format_, kRWTypeNames, IM_ARRAYSIZE(kRWTypeNames));
  ImGui::Checkbox(u8"使用设置的读取长度", &read_use_length_override_);
  ImGui::Checkbox(u8"使用系统读取模式(process_vm_readv)", &read_use_pvm_);
  if (ImGui::Button(u8"读取内存")) {
    ReadMemory();
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"查看内存(联动反汇编)")) {
    OpenMemoryWorkspaceAt(ParseAddress(mem_addr_), true, true);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"定位PC并联动")) {
    if (!state_.regs_valid) {
      FetchRegs();
    }
    OpenMemoryWorkspaceAt(GetProgramCounterAddress(), true, true);
  }

  if (!read_value_text_.empty()) {
    ImGui::Text(u8"解析结果：%s", read_value_text_.c_str());
  }

  const float workspace_h = std::max(260.0f, ImGui::GetContentRegionAvail().y * 0.65f);
  if (ImGui::BeginTable("mem_disasm_workspace",
                        2,
                        ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV,
                        ImVec2(0, workspace_h))) {
    ImGui::TableSetupColumn(u8"Memory", ImGuiTableColumnFlags_WidthStretch, 0.48f);
    ImGui::TableSetupColumn(u8"Disasm", ImGuiTableColumnFlags_WidthStretch, 0.52f);
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    ImGui::TextUnformatted(u8"内存HEX");
    ImGui::BeginChild("memview", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (state_.mem_view_data.empty()) {
      ImGui::TextUnformatted(u8"<无内存数据>");
    } else {
      const int line_count = static_cast<int>((state_.mem_view_data.size() + 15) / 16);
      ImGuiListClipper clipper;
      clipper.Begin(line_count);
      while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
          const size_t i = static_cast<size_t>(row) * 16;
          char line[256] = {0};
          char* cursor = line;
          const size_t line_len = std::min<size_t>(16, state_.mem_view_data.size() - i);
          cursor += std::snprintf(cursor, sizeof(line), "0x%08" PRIx64 ": ", state_.mem_view_addr + i);
          for (size_t j = 0; j < line_len; ++j) {
            cursor += std::snprintf(cursor,
                                    sizeof(line) - static_cast<size_t>(cursor - line),
                                    "%02X ",
                                    state_.mem_view_data[i + j]);
          }
          ImGui::TextUnformatted(line);
        }
      }
    }
    ImGui::EndChild();

    ImGui::TableSetColumnIndex(1);
    RenderDisasmPanel();
    ImGui::EndTable();
  }

  ImGui::Separator();
  ImGui::Text(u8"内存写入");
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##write", &address_default_hex_);
  ImGui::InputText(u8"写入地址", write_addr_, sizeof(write_addr_));
  ImGui::Combo(u8"写入类型", &write_format_, kRWTypeNames, IM_ARRAYSIZE(kRWTypeNames));
  ImGui::InputText(u8"写入内容", write_data_, sizeof(write_data_));
  if (ImGui::Button(u8"写入")) {
    WriteMemory();
  }
}

void ClientUI::RenderPointerVerifyWindow() {
  ImGui::Begin(u8"指针验证", &show_pointer_verify_window_);
  RenderPointerVerifyPanel();
  ImGui::End();
}

void ClientUI::RenderPointerVerifyPanel() {
  ImGui::InputText(u8"地址", pointer_verify_addr_, sizeof(pointer_verify_addr_));
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##ptrverify", &address_default_hex_);
  ImGui::InputText(u8"描述", pointer_verify_desc_, sizeof(pointer_verify_desc_));
  ImGui::Combo(u8"类型", &pointer_verify_type_, kTraverseTypeNames, IM_ARRAYSIZE(kTraverseTypeNames));
  ImGui::Checkbox(u8"十六进制", &pointer_verify_hex_);
  ImGui::SameLine();
  ImGui::Checkbox(u8"有符号", &pointer_verify_signed_);
  ImGui::Checkbox(u8"指针", &pointer_verify_is_pointer_);
  if (pointer_verify_is_pointer_) {
    ImGui::InputText(u8"偏移输入", pointer_verify_offset_input_, sizeof(pointer_verify_offset_input_));
    ImGui::SameLine();
    if (ImGui::Button(u8"添加偏移")) {
      int64_t off = 0;
      if (pointer_verify_offset_input_[0] == '-') {
        const char* ptr = pointer_verify_offset_input_ + 1;
        uint64_t mag = ParseAddressWithBase(ptr, address_default_hex_);
        off = -static_cast<int64_t>(mag);
      } else {
        off = static_cast<int64_t>(ParseAddress(pointer_verify_offset_input_));
      }
      pointer_verify_offsets_.push_back(off);
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"移除偏移") && !pointer_verify_offsets_.empty()) {
      pointer_verify_offsets_.pop_back();
    }
    ImGui::BeginChild("ptr_verify_offsets", ImVec2(0, 80), true);
    for (size_t i = 0; i < pointer_verify_offsets_.size(); ++i) {
      ImGui::Text("[%zu] %s", i + 1, FormatOffset(pointer_verify_offsets_[i]).c_str());
    }
    ImGui::EndChild();
  }
  ImGui::Checkbox(u8"读取使用系统读取模式(process_vm_readv)", &pointer_verify_use_pvm_);
  ImGui::Checkbox(u8"允许非驻留页(严格)", &pointer_verify_allow_nonresident_);
  if (ImGui::Button(u8"读取/刷新")) {
    RunPointerVerify();
  }
  if (!pointer_verify_status_.empty()) {
    ImGui::Text(u8"状态：%s", pointer_verify_status_.c_str());
  }
  if (!pointer_verify_expr_.empty()) {
    ImGui::Text(u8"表达式：%s", pointer_verify_expr_.c_str());
  }
  ImGui::BeginChild("ptr_verify_values", ImVec2(0, 200), true, ImGuiWindowFlags_HorizontalScrollbar);
  for (const auto& line : pointer_verify_lines_) {
    ImGui::TextUnformatted(line.c_str());
  }
  ImGui::EndChild();
}

void ClientUI::RenderDebuggerWindow() {
  ImGui::Begin(u8"调试器断点", &show_debugger_window_);

  if (breakpoint_monitoring_) {
    const uint64_t now_ms = NowMs();
    if (now_ms - breakpoint_last_poll_ms_ >= 200) {
      PollBreakpoints();
      breakpoint_last_poll_ms_ = now_ms;
    }
  }

  ImGui::Text(u8"调试器");
  ImGui::Checkbox(u8"允许SIGSTOP附加", &debug_attach_allow_sigstop_);
  if (ImGui::Button(u8"附加调试器(ptrace)")) {
    DebugAttach(debug_attach_allow_sigstop_);
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"调试分离")) {
    DebugDetach();
  }
  if (ImGui::Button(u8"读取寄存器")) {
    FetchRegs();
  }
  if (state_.regs_valid) {
    ImGui::BeginChild("regs_debugger", ImVec2(0, 160), true);
    if (state_.regs_arch == protocol::RegsArch::ARM64) {
      for (int i = 0; i < 31; ++i) {
        ImGui::Text("X%-2d  0x%016llX", i, static_cast<unsigned long long>(state_.regs64.regs[i]));
      }
      ImGui::Text("SP   0x%016llX", static_cast<unsigned long long>(state_.regs64.sp));
      ImGui::Text("PC   0x%016llX", static_cast<unsigned long long>(state_.regs64.pc));
      ImGui::Text("PSTATE 0x%016llX", static_cast<unsigned long long>(state_.regs64.pstate));
    } else if (state_.regs_arch == protocol::RegsArch::ARM32) {
      for (int i = 0; i < 16; ++i) {
        ImGui::Text("R%-2d  0x%08X", i, state_.regs32.regs[i]);
      }
      ImGui::Text("CPSR 0x%08X", state_.regs32.cpsr);
      ImGui::Text("ORIG_R0 0x%08X", state_.regs32.orig_r0);
    }
    ImGui::EndChild();
  }

  ImGui::Separator();
  ImGui::Text(u8"断点设置");
  ImGui::Combo(u8"断点后端", &breakpoint_backend_, kBreakpointBackendNames,
               IM_ARRAYSIZE(kBreakpointBackendNames));
  ImGui::Checkbox(u8"命中暂停", &breakpoint_stop_on_hit_);
  ImGui::Checkbox(u8"perf无命中自动回退ptrace", &breakpoint_auto_fallback_ptrace_);
  ImGui::InputText(u8"断点地址", breakpoint_addr_, sizeof(breakpoint_addr_));
  ImGui::Checkbox(u8"地址默认16进制(可不带0x)##bp", &address_default_hex_);
  ImGui::Combo(u8"断点类型", &breakpoint_type_, kBreakpointTypeNames, IM_ARRAYSIZE(kBreakpointTypeNames));
  ImGui::InputInt(u8"监视大小(字节)", &breakpoint_size_);
  if (breakpoint_size_ < 1) {
    breakpoint_size_ = 1;
  }
  if (breakpoint_size_ > 8) {
    breakpoint_size_ = 8;
  }

  if (ImGui::Button(u8"添加断点")) {
    const uint64_t addr = ParseAddress(breakpoint_addr_);
    if (addr == 0) {
      breakpoint_status_ = u8"地址无效";
    } else {
      BreakpointEntry bp;
      bp.addr = addr;
      bp.type = breakpoint_type_;
      bp.size = breakpoint_size_;
      bp.enabled = true;
      breakpoints_.push_back(bp);
      breakpoint_status_ = u8"断点已添加(本地列表)";
    }
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"应用断点到设备")) {
    ApplyBreakpoints(true);
  }
  ImGui::SameLine();
  if (!breakpoint_monitoring_) {
    if (ImGui::Button(u8"开始监视")) {
      breakpoint_monitoring_ = true;
      breakpoint_last_poll_ms_ = 0;
    }
  } else {
    if (ImGui::Button(u8"停止监视")) {
      breakpoint_monitoring_ = false;
    }
  }
  if (ImGui::Button(u8"轮询一次")) {
    PollBreakpoints();
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"删除选中")) {
    if (breakpoint_selected_ >= 0 && breakpoint_selected_ < static_cast<int>(breakpoints_.size())) {
      breakpoints_.erase(breakpoints_.begin() + breakpoint_selected_);
      breakpoint_selected_ = -1;
      breakpoint_status_ = u8"已删除断点";
    }
  }
  ImGui::SameLine();
  if (ImGui::Button(u8"清空断点")) {
    breakpoints_.clear();
    breakpoint_selected_ = -1;
    breakpoint_status_ = u8"已清空";
  }
  if (!breakpoint_status_.empty()) {
    ImGui::Text(u8"状态：%s", breakpoint_status_.c_str());
  }

  ImGui::BeginChild("bp_list", ImVec2(0, 200), true, ImGuiWindowFlags_HorizontalScrollbar);
  for (size_t i = 0; i < breakpoints_.size(); ++i) {
    auto& bp = breakpoints_[i];
    ImGui::PushID(static_cast<int>(i));
    ImGui::Checkbox("##bp_enable", &bp.enabled);
    ImGui::SameLine();
    const bool selected = (breakpoint_selected_ == static_cast<int>(i));
    char label[128] = {0};
    std::snprintf(label, sizeof(label), "0x%llX", static_cast<unsigned long long>(bp.addr));
    if (ImGui::Selectable(label, selected)) {
      breakpoint_selected_ = static_cast<int>(i);
    }
    ImGui::SameLine(180);
    ImGui::SetNextItemWidth(120);
    ImGui::Combo("##bp_type", &bp.type, kBreakpointTypeNames, IM_ARRAYSIZE(kBreakpointTypeNames));
    ImGui::SameLine(320);
    ImGui::SetNextItemWidth(60);
    ImGui::InputInt("##bp_size", &bp.size);
    if (bp.size < 1) bp.size = 1;
    if (bp.size > 8) bp.size = 8;
    ImGui::SameLine(400);
    ImGui::Text("hits=%llu", static_cast<unsigned long long>(bp.hit_count));
    ImGui::PopID();
  }
  ImGui::EndChild();

  ImGui::End();
}

void ClientUI::RenderTestWindow() {
  ImGui::Begin(u8"Test", &show_test_window_);
  ImGui::Text(u8"自动测试");
  if (!auto_running_) {
    if (ImGui::Button(u8"开始自动测试")) {
      StartAutoTest();
    }
  } else {
    ImGui::TextUnformatted(u8"自动测试进行中...");
  }
  ImGui::BeginChild("autolog", ImVec2(0, 240), true);
  for (const auto& line : auto_logs_) {
    ImGui::TextUnformatted(line.c_str());
  }
  ImGui::EndChild();

  if (auto_running_) {
    RunAutoTest();
  }
  ImGui::End();
}

bool ClientUI::LoadPointerPreview(const std::string& path,
                                  uint64_t start_index,
                                  uint32_t page_size,
                                  int64_t min_offset,
                                  int64_t max_offset,
                                  bool use_modules,
                                  const std::vector<bool>& module_mask,
                                  bool use_category,
                                  int category,
                                  const std::string& module_keyword,
                                  std::vector<std::string>* out_items,
                                  uint64_t* out_total,
                                  std::string* out_error) {
  if (!out_items || !out_total || !out_error) {
    return false;
  }
  out_items->clear();
  *out_total = 0;
  out_error->clear();

  if (path.empty()) {
    *out_error = u8"文件路径为空";
    return false;
  }
  if (!std::filesystem::exists(path)) {
    *out_error = u8"文件不存在";
    return false;
  }

  const uint32_t effective_page_size = page_size == 0 ? 64 : page_size;
  const uint64_t mask_hash = use_modules ? HashModuleMask(module_mask) : 0;
  if (pointer_preview_cache_.valid &&
      pointer_preview_cache_.path == path &&
      pointer_preview_cache_.start_index == start_index &&
      pointer_preview_cache_.page_size == effective_page_size &&
      pointer_preview_cache_.min_offset == min_offset &&
      pointer_preview_cache_.max_offset == max_offset &&
      pointer_preview_cache_.use_modules == use_modules &&
      pointer_preview_cache_.module_mask_hash == mask_hash &&
      pointer_preview_cache_.use_category == use_category &&
      pointer_preview_cache_.category == category &&
      pointer_preview_cache_.module_keyword == module_keyword) {
    *out_items = pointer_preview_cache_.items;
    *out_total = pointer_preview_cache_.total;
    return true;
  }

  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    *out_error = u8"无法打开文件";
    return false;
  }

  PointerFileHeader hdr{};
  ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(hdr)) ||
      hdr.magic != kPointerMagic || hdr.version != kPointerVersion) {
    *out_error = u8"指针文件格式错误";
    return false;
  }

  std::vector<uint64_t> targets;
  if (!ReadPointerTargets(ifs, hdr, &targets)) {
    *out_error = u8"读取目标列表失败";
    return false;
  }
  const std::string target_label = FormatTargetLabel(targets);

  if (page_size == 0) {
    page_size = effective_page_size;
  }
  const uint64_t start = start_index * page_size;
  const uint64_t end = start + page_size;
  const bool offset_filter = (min_offset <= max_offset);

  struct Range {
    uint64_t start = 0;
    uint64_t end = 0;
  };
  std::vector<Range> ranges;
  if (use_category && state_.modules.empty()) {
    *out_error = u8"模块列表为空";
    return false;
  }
  if (use_modules) {
    if (module_mask.size() != state_.modules.size()) {
      *out_error = u8"模块选择未同步";
      return false;
    }
    for (size_t i = 0; i < state_.modules.size(); ++i) {
      if (!module_mask[i]) {
        continue;
      }
      const auto& mod = state_.modules[i];
      if (mod.end > mod.start) {
        ranges.push_back({mod.start, mod.end});
      }
    }
    if (ranges.empty()) {
      *out_error = u8"未选择模块";
      return false;
    }
    std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) {
      return a.start < b.start;
    });
    std::vector<Range> merged;
    for (const auto& r : ranges) {
      if (merged.empty() || r.start > merged.back().end) {
        merged.push_back(r);
      } else if (r.end > merged.back().end) {
        merged.back().end = r.end;
      }
    }
    ranges.swap(merged);
  }

  auto in_ranges = [&](uint64_t addr) {
    if (!use_modules) {
      return true;
    }
    for (const auto& r : ranges) {
      if (addr >= r.start && addr < r.end) {
        return true;
      }
    }
    return false;
  };

  auto keyword_match = [&](uint64_t addr) {
    if (module_keyword.empty()) {
      return true;
    }
    const ClientState::ModuleInfo* mod = FindModuleForAddress(addr);
    if (!mod) {
      return false;
    }
    return ContainsCI(mod->path, module_keyword);
  };

  auto read_chain = [&](uint64_t* io_prev_base,
                        uint64_t* out_base,
                        std::vector<int64_t>* out_offsets) -> bool {
    if (!io_prev_base || !out_base || !out_offsets) {
      return false;
    }
    uint64_t delta = 0;
    if (!ReadVarUint(ifs, &delta)) {
      return false;
    }
    *out_base = *io_prev_base + delta;
    *io_prev_base = *out_base;
    out_offsets->resize(hdr.depth);
    for (uint32_t d = 0; d < hdr.depth; ++d) {
      int64_t off = 0;
      if (!ReadVarInt(ifs, &off)) {
        return false;
      }
      (*out_offsets)[d] = off;
    }
    return true;
  };

  const bool can_use_sidecar_fast_path =
      !offset_filter && !use_modules && !use_category && module_keyword.empty();
  if (can_use_sidecar_fast_path && hdr.count > 0) {
    const uint64_t file_size = FileSizeSafe(path);
    const int64_t file_mtime = FileMtimeSafe(path);
    const uint64_t stride = 512;
    PointerPreviewIndexHeader idx_expected{};
    idx_expected.magic = kPointerPreviewIndexMagic;
    idx_expected.version = kPointerPreviewIndexVersion;
    idx_expected.depth = hdr.depth;
    idx_expected.pointer_count = hdr.count;
    idx_expected.pointer_file_size = file_size;
    idx_expected.pointer_file_mtime = file_mtime;
    idx_expected.stride = stride;

    const std::string sidecar_path = path + ".idx";
    std::vector<PointerPreviewIndexEntry> checkpoints;
    if (!LoadPointerPreviewIndex(sidecar_path, idx_expected, &checkpoints)) {
      std::string idx_err;
      if (BuildPointerPreviewIndex(path, hdr, stride, &checkpoints, &idx_err)) {
        PointerPreviewIndexHeader idx_hdr = idx_expected;
        idx_hdr.checkpoint_count = static_cast<uint64_t>(checkpoints.size());
        SavePointerPreviewIndex(sidecar_path, idx_hdr, checkpoints);
      }
    }

    const uint64_t total_count = hdr.count;
    const uint64_t start_chain = std::min(start, total_count);
    const uint64_t end_chain = std::min(end, total_count);
    uint64_t prev_base = 0;
    uint64_t chain_index = 0;
    if (!checkpoints.empty()) {
      auto it = std::upper_bound(checkpoints.begin(),
                                 checkpoints.end(),
                                 start_chain,
                                 [](uint64_t idx, const PointerPreviewIndexEntry& cp) {
                                   return idx < cp.chain_index;
                                 });
      if (it != checkpoints.begin()) {
        --it;
        chain_index = it->chain_index;
        prev_base = it->prev_base;
        ifs.clear();
        ifs.seekg(static_cast<std::streamoff>(it->file_offset), std::ios::beg);
      }
    }

    while (chain_index < start_chain) {
      uint64_t base = 0;
      std::vector<int64_t> offsets;
      if (!read_chain(&prev_base, &base, &offsets)) {
        *out_error = u8"读取指针文件失败";
        return false;
      }
      chain_index++;
    }
    while (chain_index < end_chain) {
      uint64_t base = 0;
      std::vector<int64_t> offsets;
      if (!read_chain(&prev_base, &base, &offsets)) {
        *out_error = u8"读取指针文件失败";
        return false;
      }
      char line[512] = {0};
      const std::string expr = BuildPointerExpr(base, offsets, true);
      std::snprintf(line, sizeof(line), "%s => %s",
                    expr.c_str(),
                    target_label.c_str());
      const ClientState::ModuleInfo* mod = FindModuleForAddress(base);
      if (mod && !mod->path.empty()) {
        std::string view(line);
        view.append(" [");
        view.append(mod->path);
        view.push_back(']');
        out_items->push_back(std::move(view));
      } else {
        out_items->emplace_back(line);
      }
      chain_index++;
    }
    *out_total = total_count;
  } else {
    uint64_t prev_base = 0;
    uint64_t matched = 0;
    const uint64_t total_count = hdr.count;
    for (uint64_t i = 0; (total_count == 0) || (i < total_count); ++i) {
      uint64_t base = 0;
      std::vector<int64_t> offsets;
      if (!read_chain(&prev_base, &base, &offsets)) {
        if (total_count == 0) {
          break;
        }
        *out_error = u8"读取指针文件失败";
        return false;
      }

      bool offset_ok = true;
      if (offset_filter) {
        for (int64_t off : offsets) {
          if (off < min_offset || off > max_offset) {
            offset_ok = false;
            break;
          }
        }
      }
      if (!offset_ok) {
        continue;
      }
      if (!in_ranges(base)) {
        continue;
      }
      if (!keyword_match(base)) {
        continue;
      }
      if (use_category) {
        const ClientState::ModuleInfo* mod = FindModuleForAddress(base);
        if (!mod || !IsModuleVisible(category, *mod)) {
          continue;
        }
      }

      if (matched >= start && matched < end) {
        char line[512] = {0};
        const std::string expr = BuildPointerExpr(base, offsets, true);
        std::snprintf(line, sizeof(line), "%s => %s",
                      expr.c_str(),
                      target_label.c_str());
        const ClientState::ModuleInfo* mod = FindModuleForAddress(base);
        if (mod && !mod->path.empty()) {
          std::string view(line);
          view.append(" [");
          view.append(mod->path);
          view.push_back(']');
          out_items->push_back(std::move(view));
        } else {
          out_items->emplace_back(line);
        }
      }
      matched++;
      if (matched >= end && matched >= total_count && total_count != 0) {
        break;
      }
    }
    *out_total = matched;
  }

  pointer_preview_cache_.valid = true;
  pointer_preview_cache_.path = path;
  pointer_preview_cache_.start_index = start_index;
  pointer_preview_cache_.page_size = page_size;
  pointer_preview_cache_.min_offset = min_offset;
  pointer_preview_cache_.max_offset = max_offset;
  pointer_preview_cache_.use_modules = use_modules;
  pointer_preview_cache_.module_mask_hash = mask_hash;
  pointer_preview_cache_.use_category = use_category;
  pointer_preview_cache_.category = category;
  pointer_preview_cache_.module_keyword = module_keyword;
  pointer_preview_cache_.items = *out_items;
  pointer_preview_cache_.total = *out_total;
  return true;
}

bool ExportPointerText(const std::string& path,
                       const std::string& out_path,
                       std::string* out_error) {
  if (out_error) {
    out_error->clear();
  }
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    if (out_error) {
      *out_error = u8"无法打开指针文件";
    }
    return false;
  }
  PointerFileHeader hdr{};
  ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
  if (ifs.gcount() != static_cast<std::streamsize>(sizeof(hdr)) ||
      hdr.magic != kPointerMagic || hdr.version != kPointerVersion) {
    if (out_error) {
      *out_error = u8"指针文件格式错误";
    }
    return false;
  }

  std::vector<uint64_t> targets;
  if (!ReadPointerTargets(ifs, hdr, &targets)) {
    if (out_error) {
      *out_error = u8"读取目标列表失败";
    }
    return false;
  }

  std::ofstream ofs(out_path, std::ios::out | std::ios::binary);
  if (!ofs.is_open()) {
    if (out_error) {
      *out_error = u8"无法写入导出文件";
    }
    return false;
  }

  ofs << "targets=" << FormatTargetLabel(targets) << " depth=" << hdr.depth << "\n";

  uint64_t prev_base = 0;
  uint64_t count = 0;
  const uint64_t total = hdr.count;
  while (total == 0 || count < total) {
    uint64_t delta = 0;
    if (!ReadVarUint(ifs, &delta)) {
      break;
    }
    uint64_t base = prev_base + delta;
    prev_base = base;
    std::vector<int64_t> offsets;
    offsets.resize(hdr.depth);
    for (uint32_t d = 0; d < hdr.depth; ++d) {
      int64_t off = 0;
      if (!ReadVarInt(ifs, &off)) {
        if (out_error) {
          *out_error = u8"读取指针文件失败";
        }
        return false;
      }
      offsets[d] = off;
    }
    const std::string expr = BuildPointerExpr(base, offsets, false);
    ofs << Hex64(base) << " " << expr << "\n";
    count++;
  }

  return true;
}

bool ConvertPointerTextToBinary(const std::string& txt_path,
                                const std::string& out_path,
                                uint32_t pointer_size,
                                std::string* out_error) {
  if (out_error) {
    out_error->clear();
  }
  std::ifstream ifs(txt_path);
  if (!ifs.is_open()) {
    if (out_error) {
      *out_error = u8"无法打开文本文件";
    }
    return false;
  }

  std::vector<PointerChain> chains;
  uint32_t depth = 0;
  int64_t max_offset = 0;
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.empty()) {
      continue;
    }
    if (StartsWith(line, "target") || StartsWith(line, "targets")) {
      continue;
    }

    uint64_t base = 0;
    bool base_found = false;
    for (size_t i = 0; i < line.size(); ++i) {
      if (std::isxdigit(static_cast<unsigned char>(line[i])) || line[i] == '0') {
        char* endptr = nullptr;
        const char* start = line.c_str() + i;
        uint64_t value = std::strtoull(start, &endptr, 0);
        if (endptr != start) {
          base = value;
          base_found = true;
          break;
        }
      }
    }
    if (!base_found) {
      continue;
    }

    std::vector<int64_t> offsets;
    for (size_t i = 0; i < line.size(); ++i) {
      if (line[i] == '+' || line[i] == '-') {
        const bool neg = (line[i] == '-');
        size_t j = i + 1;
        while (j < line.size() && std::isspace(static_cast<unsigned char>(line[j]))) {
          ++j;
        }
        if (j >= line.size()) {
          continue;
        }
        char* endptr = nullptr;
        const char* start = line.c_str() + j;
        uint64_t value = std::strtoull(start, &endptr, 0);
        if (endptr == start) {
          continue;
        }
        int64_t off = static_cast<int64_t>(value);
        if (neg) {
          off = -off;
        }
        offsets.push_back(off);
        const int64_t abs_off = off >= 0 ? off : -off;
        if (abs_off > max_offset) {
          max_offset = abs_off;
        }
      }
    }
    if (offsets.empty()) {
      continue;
    }
    if (depth == 0) {
      depth = static_cast<uint32_t>(offsets.size());
    }
    if (offsets.size() != depth) {
      continue;
    }
    chains.push_back({base, offsets});
  }

  if (chains.empty() || depth == 0) {
    if (out_error) {
      *out_error = u8"文本中未找到有效指针";
    }
    return false;
  }

  std::sort(chains.begin(), chains.end(), [](const PointerChain& a, const PointerChain& b) {
    if (a.base != b.base) {
      return a.base < b.base;
    }
    return a.offsets < b.offsets;
  });

  const auto dir = std::filesystem::path(out_path).parent_path();
  if (!dir.empty()) {
    std::filesystem::create_directories(dir);
  }
  std::ofstream ofs(out_path, std::ios::binary);
  if (!ofs.is_open()) {
    if (out_error) {
      *out_error = u8"无法写入指针文件";
    }
    return false;
  }

  PointerFileHeader hdr{};
  hdr.magic = kPointerMagic;
  hdr.version = kPointerVersion;
  hdr.pointer_size = static_cast<uint16_t>(pointer_size);
  hdr.depth = depth;
  hdr.reserved = 0;
  hdr.target = 0;
  hdr.count = 0;
  hdr.max_offset = max_offset;
  hdr.flags = kPointerFlagDeltaVarint;
  ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

  uint64_t prev_base = 0;
  std::vector<uint8_t> buffer;
  buffer.reserve(64 * 1024);
  uint64_t written = 0;
  for (const auto& chain : chains) {
    WriteVarUint(&buffer, chain.base - prev_base);
    prev_base = chain.base;
    for (int64_t off : chain.offsets) {
      WriteVarInt(&buffer, off);
    }
    written++;
    if (buffer.size() > 64 * 1024) {
      ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
      buffer.clear();
    }
  }
  if (!buffer.empty()) {
    ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  }
  ofs.seekp(offsetof(PointerFileHeader, count), std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(&written), sizeof(written));
  return true;
}

bool ClientUI::RunPointerScan() {
  pointer_scan_status_.clear();
  pointer_scan_output_path_.clear();
  pointer_scan_count_ = 0;

  if (!state_.connected) {
    pointer_scan_status_ = u8"未连接";
    return false;
  }
  if (state_.pid == 0) {
    if (!Attach()) {
      pointer_scan_status_ = u8"请先打开进程";
      return false;
    }
  }

  bool freeze_attached = false;
  std::string freeze_warning;
  if (pointer_scan_freeze_) {
    if (!DebugAttach(true)) {
      freeze_warning = u8"严格快照失败：附加调试器失败，已继续扫描";
    } else {
      freeze_attached = true;
    }
  }
  struct FreezeGuard {
    ClientUI* ui = nullptr;
    bool* active = nullptr;
    ~FreezeGuard() {
      if (ui && active && *active) {
        ui->DebugDetach();
      }
    }
  } freeze_guard{this, &freeze_attached};

  std::vector<uint64_t> raw_targets;
  {
    std::string token;
    bool ok = true;
    const std::string input = pointer_scan_target_;
    auto flush = [&]() {
      if (token.empty()) {
        return;
      }
      const uint64_t value = ParseAddressWithBase(token, address_default_hex_);
      if (value == 0) {
        ok = false;
      } else {
        raw_targets.push_back(value);
      }
      token.clear();
    };
    for (char c : input) {
      if (c == ',' || c == ';' || c == '|' || std::isspace(static_cast<unsigned char>(c))) {
        flush();
      } else {
        token.push_back(c);
      }
    }
    flush();
    if (!ok || raw_targets.empty()) {
      pointer_scan_status_ = u8"目标地址无效";
      return false;
    }
  }

  int depth = pointer_scan_depth_;
  if (depth > 50) {
    depth = 50;
  }
  const int64_t max_offset = static_cast<int64_t>(pointer_scan_max_offset_);
  if (depth < 1) {
    pointer_scan_status_ = u8"指针层数无效";
    return false;
  }

  if (state_.modules.empty()) {
    FetchModules();
  }
  if (state_.modules.empty()) {
    pointer_scan_status_ = u8"模块列表为空";
    return false;
  }
  SyncPointerModuleSelection();

  size_t selected_count = 0;
  if (pointer_scan_use_modules_) {
    for (bool v : pointer_scan_module_selected_) {
      if (v) {
        selected_count++;
      }
    }
    if (selected_count == 0) {
      pointer_scan_status_ = u8"未选择模块";
      return false;
    }
  }

  struct Range {
    uint64_t start = 0;
    uint64_t end = 0;
  };
  struct Task {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t read_end = 0;
  };
  std::vector<Range> ranges;
  ranges.reserve(state_.modules.size());
  for (size_t i = 0; i < state_.modules.size(); ++i) {
    const auto& mod = state_.modules[i];
    if ((mod.perms & protocol::MODULE_PERM_READ) == 0) {
      continue;
    }
    if (pointer_scan_use_modules_ && !pointer_scan_module_selected_[i]) {
      continue;
    }
    if (mod.end > mod.start) {
      ranges.push_back({mod.start, mod.end});
    }
  }
  if (ranges.empty()) {
    pointer_scan_status_ = u8"没有可扫描的模块范围";
    return false;
  }

  std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) {
    return a.start < b.start;
  });
  std::vector<Range> merged;
  for (const auto& r : ranges) {
    if (merged.empty() || r.start > merged.back().end) {
      merged.push_back(r);
    } else if (r.end > merged.back().end) {
      merged.back().end = r.end;
    }
  }
  ranges.swap(merged);

  const uint64_t snapshot_id = NextSnapshotId();
  uint64_t snapshot_region_count = 0;
  uint64_t snapshot_region_bytes = 0;
  const uint64_t snapshot_maps_hash =
      ComputeModuleSnapshotHash(state_.modules,
                                &pointer_scan_module_selected_,
                                pointer_scan_use_modules_,
                                &snapshot_region_count,
                                &snapshot_region_bytes);

  const uint32_t pointer_size = GetPointerSizeFromModules();
  std::unordered_set<uint64_t> target_seen;
  std::vector<uint64_t> target_values;
  target_values.reserve(raw_targets.size());
  for (uint64_t value : raw_targets) {
    if (pointer_size == 8) {
      value = StripTag64(value);
    }
    if (value == 0) {
      continue;
    }
    if (target_seen.insert(value).second) {
      target_values.push_back(value);
    }
  }
  if (target_values.empty()) {
    pointer_scan_status_ = u8"目标地址无效";
    return false;
  }
  if (target_values.size() > kPointerScanMaxTargets) {
    pointer_scan_status_ = u8"目标数量过多";
    return false;
  }
  std::sort(target_values.begin(), target_values.end());

  if (pointer_scan_byte_step_) {
    if (!pointer_scan_allow_nonresident_) {
      pointer_scan_status_ = u8"字节步进需要开启允许非驻留页";
      return false;
    }
    if (!pointer_scan_freeze_) {
      pointer_scan_status_ = u8"字节步进需要开启严格快照";
      return false;
    }
  }

  const bool strict_reads = pointer_scan_freeze_;
  std::mutex read_error_mutex;
  std::string read_error;
  auto report_read_error = [&](uint64_t addr, uint32_t req, size_t got) {
    if (!strict_reads) {
      return;
    }
    std::lock_guard<std::mutex> lock(read_error_mutex);
    if (!read_error.empty()) {
      return;
    }
    char buf[160] = {0};
    std::snprintf(buf,
                  sizeof(buf),
                  "严格读取失败 addr=0x%llX req=%u got=%zu",
                  static_cast<unsigned long long>(addr),
                  req,
                  got);
    read_error = buf;
  };

  constexpr uint64_t kTaskSize = 8 * 1024 * 1024;
  const uint64_t overlap = (pointer_scan_byte_step_ && pointer_size > 1) ? (pointer_size - 1) : 0;
  std::vector<Task> tasks;
  for (const auto& r : ranges) {
    for (uint64_t start = r.start; start < r.end; start += kTaskSize) {
      const uint64_t end = std::min(r.end, start + kTaskSize);
      const uint64_t read_end = overlap > 0 ? std::min(r.end, end + overlap) : end;
      tasks.push_back({start, end, read_end});
    }
  }
  if (tasks.empty()) {
    pointer_scan_status_ = u8"没有可扫描的范围";
    return false;
  }

  const unsigned hw = std::thread::hardware_concurrency();
  unsigned thread_count = pointer_scan_thread_count_ > 0
                            ? static_cast<unsigned>(pointer_scan_thread_count_)
                            : std::max(1u, std::min(4u, hw == 0 ? 2u : hw / 2));
  if (thread_count == 0) {
    thread_count = 1;
  }
  thread_count = std::min(thread_count, 16u);

  uint32_t read_flags = pointer_scan_use_pvm_ ? protocol::READ_FLAG_USE_PVM : 0;
  if (pointer_scan_allow_nonresident_) {
    read_flags |= protocol::READ_FLAG_ALLOW_NONRESIDENT;
  }
  const uint32_t step = pointer_scan_byte_step_ ? 1u : pointer_size;

  struct TargetRef {
    uint64_t addr = 0;
    int index = -1;
  };
  struct PointerNode {
    uint64_t address = 0;
    int64_t offset = 0;
    int parent = -1;
  };
  struct IndexBlock {
    uint64_t value_min = 0;
    uint64_t value_max = 0;
    size_t start = 0;
    size_t end = 0;
  };

  std::vector<std::vector<PointerNode>> levels;
  levels.reserve(static_cast<size_t>(depth));

  auto align_up = [](uint64_t value, uint64_t align) {
    if (align == 0) {
      return value;
    }
    const uint64_t mask = align - 1;
    return (value + mask) & ~mask;
  };

  const std::vector<std::pair<uint64_t, uint64_t>>* index_entries = nullptr;
  std::vector<IndexBlock> index_blocks;
  if (pointer_scan_use_index_) {
    const bool index_byte_step = (pointer_index_flags_ & kPointerIndexFlagByteStep) != 0;
    const bool index_strict = (pointer_index_flags_ & kPointerIndexFlagStrict) != 0;
    const bool cached_ok = (!pointer_index_entries_.empty() &&
                            pointer_index_pid_ == static_cast<uint32_t>(state_.pid) &&
                            pointer_index_pointer_size_ == pointer_size &&
                            (!pointer_scan_byte_step_ || index_byte_step) &&
                            (!pointer_scan_freeze_ || index_strict));
    if (!cached_ok && pointer_scan_index_path_[0] != '\0' &&
        std::filesystem::exists(pointer_scan_index_path_)) {
      uint32_t idx_psize = 0;
      uint32_t idx_pid = 0;
      uint64_t idx_flags = 0;
      std::vector<std::pair<uint64_t, uint64_t>> entries;
      std::string err;
      if (LoadPointerIndexFile(pointer_scan_index_path_, &idx_psize, &idx_pid, &idx_flags, &entries, &err) &&
          idx_psize == pointer_size &&
          (idx_pid == 0 || idx_pid == static_cast<uint32_t>(state_.pid))) {
        const bool idx_byte_step = (idx_flags & kPointerIndexFlagByteStep) != 0;
        const bool idx_strict = (idx_flags & kPointerIndexFlagStrict) != 0;
        if ((pointer_scan_byte_step_ && !idx_byte_step) || (pointer_scan_freeze_ && !idx_strict)) {
          pointer_index_entries_.clear();
          pointer_index_pointer_size_ = 0;
          pointer_index_pid_ = 0;
          pointer_index_flags_ = 0;
          if (pointer_scan_freeze_ && !idx_strict) {
            pointer_index_status_ = u8"索引未启用严格模式，已忽略";
          } else {
            pointer_index_status_ = u8"索引未启用字节步进，已忽略";
          }
        } else {
          pointer_index_entries_.swap(entries);
          pointer_index_pointer_size_ = idx_psize;
          pointer_index_pid_ = static_cast<uint32_t>(state_.pid);
          pointer_index_flags_ = idx_flags;
          pointer_index_status_ = u8"索引加载完成";
        }
      } else {
        pointer_index_status_ = err.empty() ? u8"索引加载失败" : err;
      }
    }

    if (pointer_index_entries_.empty() ||
        pointer_index_pid_ != static_cast<uint32_t>(state_.pid) ||
        pointer_index_pointer_size_ != pointer_size ||
        (pointer_scan_byte_step_ && (pointer_index_flags_ & kPointerIndexFlagByteStep) == 0) ||
        (pointer_scan_freeze_ && (pointer_index_flags_ & kPointerIndexFlagStrict) == 0)) {
      std::string err;
      if (BuildPointerIndexFromAgent(pointer_size, &err)) {
        pointer_index_status_ = u8"索引从设备下载完成";
      } else if (!err.empty()) {
        pointer_index_status_ = err;
      }
    }

    if (pointer_index_entries_.empty() ||
        pointer_index_pid_ != static_cast<uint32_t>(state_.pid) ||
        pointer_index_pointer_size_ != pointer_size) {
      pointer_scan_status_ = u8"正在构建指针索引...";
      std::atomic<size_t> task_index{0};
      std::atomic<size_t> total_entries{0};
      std::atomic<bool> stop{false};
      std::vector<std::vector<std::pair<uint64_t, uint64_t>>> thread_entries(thread_count);

      auto worker = [&](unsigned id) {
        NetClient client;
        if (!client.Connect(host_, static_cast<uint16_t>(port_))) {
          return;
        }
        BenchTrackConnect();
        protocol::AttachRequest areq{};
        areq.pid = state_.pid;
        areq.reserved = 0;
        protocol::PacketHeader header{};
        std::vector<uint8_t> payload;
        if (!client.SendAndReceive(protocol::CommandType::CMD_ATTACH, &areq, sizeof(areq), &header, &payload)) {
          client.Disconnect();
          return;
        }
        BenchTrackPacket(sizeof(areq), payload.size());
        BenchTrackAttach();
        uint32_t dynamic_chunk = 1024 * 1024;
        uint32_t success_streak = 0;
        std::vector<uint8_t> buffer;
        buffer.reserve(4 * 1024 * 1024);

        while (!stop.load()) {
          const size_t idx = task_index.fetch_add(1);
          if (idx >= tasks.size()) {
            break;
          }
          const auto& task = tasks[idx];
          uint64_t cursor = pointer_scan_byte_step_ ? task.start : align_up(task.start, pointer_size);
          const uint64_t scan_end = task.end;
          const uint64_t read_end = task.read_end;
          while (cursor < read_end && !stop.load()) {
            const uint64_t remaining = read_end - cursor;
            uint32_t chunk = static_cast<uint32_t>(std::min<uint64_t>(remaining, dynamic_chunk));
            if (chunk > 4 * 1024 * 1024) {
              chunk = 4 * 1024 * 1024;
            }
            if (chunk < 64 * 1024) {
              chunk = static_cast<uint32_t>(std::min<uint64_t>(remaining, 64 * 1024));
            }
            if (!pointer_scan_byte_step_ && pointer_size > 1) {
              chunk = static_cast<uint32_t>((chunk / pointer_size) * pointer_size);
            }
            if (chunk == 0) {
              break;
            }
            if (pointer_scan_byte_step_ && chunk < pointer_size) {
              break;
            }
            if (!ReadMemoryRangeWithClient(client, cursor, chunk, read_flags, &buffer)) {
              if (strict_reads) {
                report_read_error(cursor, chunk, 0);
                stop.store(true);
                break;
              }
              success_streak = 0;
              if (dynamic_chunk > 64 * 1024) {
                dynamic_chunk = std::max<uint32_t>(64 * 1024, dynamic_chunk / 2);
              }
              cursor += chunk;
              continue;
            }
            if (strict_reads && buffer.size() < chunk) {
              report_read_error(cursor, chunk, buffer.size());
              stop.store(true);
              break;
            }
            if (buffer.size() == chunk) {
              success_streak++;
              if (success_streak >= 4 && dynamic_chunk < 4 * 1024 * 1024) {
                dynamic_chunk = std::min<uint32_t>(4 * 1024 * 1024, dynamic_chunk * 2);
                success_streak = 0;
              }
            } else {
              success_streak = 0;
            }
            const size_t bytes = buffer.size();
            const size_t limit = bytes >= pointer_size ? (bytes - pointer_size + 1) : 0;
            for (size_t offset = 0; offset < limit; offset += step) {
              const uint64_t addr = cursor + offset;
              if (addr >= scan_end) {
                break;
              }
              uint64_t value = 0;
              if (pointer_size == 4) {
                uint32_t v32 = 0;
                std::memcpy(&v32, buffer.data() + offset, sizeof(v32));
                value = static_cast<uint64_t>(v32);
              } else {
                uint64_t v64 = 0;
                std::memcpy(&v64, buffer.data() + offset, sizeof(v64));
                value = StripTag64(v64);
              }
              if (value == 0) {
                continue;
              }
              const size_t idx_entry = total_entries.fetch_add(1);
              if (idx_entry >= kPointerIndexLimit) {
                stop.store(true);
                break;
              }
              thread_entries[id].push_back({value, addr});
            }
            uint64_t advance = chunk;
            if (pointer_scan_byte_step_ && chunk > overlap) {
              advance = chunk - overlap;
            }
            cursor += advance;
          }
        }
        client.Disconnect();
      };

      std::vector<std::thread> threads;
      threads.reserve(thread_count);
      for (unsigned i = 0; i < thread_count; ++i) {
        threads.emplace_back(worker, i);
      }
      for (auto& t : threads) {
        t.join();
      }

      if (!read_error.empty()) {
        pointer_scan_status_ = read_error;
        return false;
      }

      if (total_entries.load() >= kPointerIndexLimit) {
        pointer_scan_status_ = u8"索引过大，已停止";
        return false;
      }

      pointer_index_entries_.clear();
      size_t total = 0;
      for (const auto& list : thread_entries) {
        total += list.size();
      }
      pointer_index_entries_.reserve(total);
      for (auto& list : thread_entries) {
        pointer_index_entries_.insert(pointer_index_entries_.end(), list.begin(), list.end());
      }
      pointer_index_pointer_size_ = pointer_size;
      pointer_index_pid_ = static_cast<uint32_t>(state_.pid);
      pointer_index_flags_ = kPointerIndexFlagDeltaVarint |
                             (pointer_scan_byte_step_ ? kPointerIndexFlagByteStep : 0) |
                             (pointer_scan_freeze_ ? kPointerIndexFlagStrict : 0);

      if (pointer_scan_index_path_[0] != '\0') {
        std::string err;
        const uint64_t idx_flags = (pointer_scan_byte_step_ ? kPointerIndexFlagByteStep : 0) |
                                   (pointer_scan_freeze_ ? kPointerIndexFlagStrict : 0);
        if (!SavePointerIndexFile(pointer_scan_index_path_,
                                  pointer_size,
                                  static_cast<uint32_t>(state_.pid),
                                  idx_flags,
                                  pointer_index_entries_,
                                  &err)) {
          pointer_index_status_ = err.empty() ? u8"索引保存失败" : err;
        } else {
          pointer_index_status_ = u8"索引保存完成";
        }
      }
    }
    if (!pointer_index_entries_.empty()) {
      std::sort(pointer_index_entries_.begin(),
                pointer_index_entries_.end(),
                [](const std::pair<uint64_t, uint64_t>& a,
                   const std::pair<uint64_t, uint64_t>& b) {
                  if (a.first != b.first) {
                    return a.first < b.first;
                  }
                  return a.second < b.second;
                });
      pointer_index_entries_.erase(std::unique(pointer_index_entries_.begin(),
                                               pointer_index_entries_.end()),
                                   pointer_index_entries_.end());
    }
    index_entries = &pointer_index_entries_;
    if (index_entries && !index_entries->empty()) {
      constexpr size_t kIndexBlockSize = 4096;
      index_blocks.reserve((index_entries->size() + kIndexBlockSize - 1) / kIndexBlockSize);
      for (size_t i = 0; i < index_entries->size(); i += kIndexBlockSize) {
        const size_t end = std::min(index_entries->size(), i + kIndexBlockSize);
        IndexBlock block{};
        block.value_min = (*index_entries)[i].first;
        block.value_max = (*index_entries)[end - 1].first;
        block.start = i;
        block.end = end;
        index_blocks.push_back(block);
      }
    }
  }

  const bool use_index_lookup =
      pointer_scan_use_index_ &&
      index_entries &&
      !index_entries->empty() &&
      !index_blocks.empty();

  std::vector<std::unique_ptr<NetClient>> scan_clients;
  std::vector<std::vector<uint8_t>> scan_read_buffers;
  if (!use_index_lookup) {
    scan_clients.resize(thread_count);
    scan_read_buffers.resize(thread_count);
    for (unsigned i = 0; i < thread_count; ++i) {
      scan_clients[i] = std::make_unique<NetClient>();
      if (!scan_clients[i]->Connect(host_, static_cast<uint16_t>(port_))) {
        pointer_scan_status_ = u8"扫描会话连接失败";
        return false;
      }
      BenchTrackConnect();
      protocol::AttachRequest areq{};
      areq.pid = state_.pid;
      areq.reserved = 0;
      protocol::PacketHeader header{};
      std::vector<uint8_t> payload;
      if (!scan_clients[i]->SendAndReceive(protocol::CommandType::CMD_ATTACH,
                                           &areq,
                                           sizeof(areq),
                                           &header,
                                           &payload)) {
        pointer_scan_status_ = u8"扫描会话附加失败";
        return false;
      }
      BenchTrackPacket(sizeof(areq), payload.size());
      BenchTrackAttach();
      scan_read_buffers[i].reserve(4 * 1024 * 1024);
    }
  }

  class ScanWorkerPool {
   public:
    explicit ScanWorkerPool(unsigned count) : count_(count) {
      workers_.reserve(count_);
      for (unsigned i = 0; i < count_; ++i) {
        workers_.emplace_back([this, i]() { WorkerLoop(i); });
      }
    }

    ~ScanWorkerPool() { Shutdown(); }

    void Run(const std::function<void(unsigned)>& task) {
      if (!task || count_ == 0) {
        return;
      }
      {
        std::lock_guard<std::mutex> lock(mu_);
        task_ = task;
        pending_ = count_;
        ++generation_;
      }
      cv_task_.notify_all();
      std::unique_lock<std::mutex> lock(mu_);
      cv_done_.wait(lock, [this]() { return pending_ == 0; });
    }

   private:
    void WorkerLoop(unsigned id) {
      uint64_t seen_generation = 0;
      while (true) {
        std::function<void(unsigned)> task;
        {
          std::unique_lock<std::mutex> lock(mu_);
          cv_task_.wait(lock, [this, seen_generation]() {
            return stop_ || generation_ != seen_generation;
          });
          if (stop_) {
            return;
          }
          seen_generation = generation_;
          task = task_;
        }
        if (task) {
          task(id);
        }
        {
          std::lock_guard<std::mutex> lock(mu_);
          if (pending_ > 0 && --pending_ == 0) {
            cv_done_.notify_one();
          }
        }
      }
    }

    void Shutdown() {
      {
        std::lock_guard<std::mutex> lock(mu_);
        stop_ = true;
      }
      cv_task_.notify_all();
      for (auto& t : workers_) {
        if (t.joinable()) {
          t.join();
        }
      }
    }

    unsigned count_ = 0;
    std::vector<std::thread> workers_;
    std::mutex mu_;
    std::condition_variable cv_task_;
    std::condition_variable cv_done_;
    std::function<void(unsigned)> task_;
    uint64_t generation_ = 0;
    unsigned pending_ = 0;
    bool stop_ = false;
  };

  ScanWorkerPool worker_pool(thread_count);

  for (int level = 1; level <= depth; ++level) {
    std::vector<TargetRef> target_refs;
    if (level == 1) {
      target_refs.reserve(target_values.size());
      for (uint64_t value : target_values) {
        target_refs.push_back({value, -1});
      }
    } else {
      const auto& prev = levels.back();
      target_refs.reserve(prev.size());
      for (size_t i = 0; i < prev.size(); ++i) {
        target_refs.push_back({prev[i].address, static_cast<int>(i)});
      }
    }

    if (target_refs.empty()) {
      pointer_scan_status_ = u8"无可用目标地址";
      return false;
    }

    std::sort(target_refs.begin(), target_refs.end(), [](const TargetRef& a, const TargetRef& b) {
      return a.addr < b.addr;
    });

    std::atomic<size_t> total_nodes{0};
    std::atomic<bool> stop{false};
    std::vector<std::vector<PointerNode>> thread_nodes(thread_count);
    const uint64_t max_offset_u = max_offset >= 0
                                    ? static_cast<uint64_t>(max_offset)
                                    : static_cast<uint64_t>(-max_offset);

    auto safe_diff = [](uint64_t target, uint64_t value, int64_t* out) {
      if (!out) {
        return false;
      }
      if (target >= value) {
        const uint64_t d = target - value;
        if (d > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
          return false;
        }
        *out = static_cast<int64_t>(d);
        return true;
      }
      const uint64_t d = value - target;
      if (d > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return false;
      }
      *out = -static_cast<int64_t>(d);
      return true;
    };

    auto process_value = [&](uint64_t value, uint64_t addr, std::vector<PointerNode>& local) {
      if (value == 0) {
        return;
      }
      uint64_t low = value >= max_offset_u ? value - max_offset_u : 0;
      uint64_t high = value + max_offset_u;
      if (high < value) {
        high = UINT64_MAX;
      }
      auto it = std::lower_bound(target_refs.begin(), target_refs.end(), low,
                                 [](const TargetRef& t, uint64_t val) { return t.addr < val; });
      for (; it != target_refs.end() && it->addr <= high; ++it) {
        int64_t diff = 0;
        if (!safe_diff(it->addr, value, &diff)) {
          continue;
        }
        const size_t idx = total_nodes.fetch_add(1);
        if (idx >= kPointerNodeLimit) {
          stop.store(true);
          return;
        }
        local.push_back({addr, diff, it->index});
      }
    };

    if (use_index_lookup) {
      std::atomic<size_t> target_index{0};
      auto worker = [&](unsigned id) {
        while (!stop.load()) {
          const size_t idx = target_index.fetch_add(1);
          if (idx >= target_refs.size()) {
            break;
          }
          const auto& target = target_refs[idx];
          const uint64_t low = target.addr >= max_offset_u ? target.addr - max_offset_u : 0;
          uint64_t high = target.addr + max_offset_u;
          if (high < target.addr) {
            high = UINT64_MAX;
          }

          for (const auto& block : index_blocks) {
            if (block.value_max < low) {
              continue;
            }
            if (block.value_min > high) {
              break;
            }
            if (stop.load()) {
              break;
            }
            const auto begin_it = index_entries->begin() +
                                  static_cast<std::vector<std::pair<uint64_t, uint64_t>>::difference_type>(block.start);
            const auto end_it = index_entries->begin() +
                                static_cast<std::vector<std::pair<uint64_t, uint64_t>>::difference_type>(block.end);
            auto it = std::lower_bound(begin_it, end_it, low,
                                       [](const std::pair<uint64_t, uint64_t>& entry, uint64_t v) {
                                         return entry.first < v;
                                       });
            for (; it != end_it && it->first <= high; ++it) {
              int64_t diff = 0;
              if (!safe_diff(target.addr, it->first, &diff)) {
                continue;
              }
              const size_t node_idx = total_nodes.fetch_add(1);
              if (node_idx >= kPointerNodeLimit) {
                stop.store(true);
                break;
              }
              thread_nodes[id].push_back({it->second, diff, target.index});
            }
          }
        }
      };
      worker_pool.Run(worker);
    } else {
      std::atomic<size_t> task_index{0};
      auto worker = [&](unsigned id) {
        if (id >= scan_clients.size() || !scan_clients[id]) {
          return;
        }
        NetClient& client = *scan_clients[id];
        std::vector<uint8_t>& reuse_buffer = scan_read_buffers[id];
        uint32_t dynamic_chunk = 1024 * 1024;
        uint32_t success_streak = 0;
        while (!stop.load()) {
          const size_t idx = task_index.fetch_add(1);
          if (idx >= tasks.size()) {
            break;
          }
          const auto& task = tasks[idx];
          uint64_t cursor = pointer_scan_byte_step_ ? task.start : align_up(task.start, pointer_size);
          const uint64_t scan_end = task.end;
          const uint64_t read_end = task.read_end;
          while (cursor < read_end && !stop.load()) {
            struct BatchRange {
              uint64_t addr = 0;
              uint32_t size = 0;
              uint64_t scan_limit = 0;
              uint64_t next_cursor = 0;
            };
            std::vector<BatchRange> batch_meta;
            std::vector<std::pair<uint64_t, uint32_t>> batch_req;
            batch_meta.reserve(4);
            batch_req.reserve(4);

            uint64_t next_cursor = cursor;
            for (int bi = 0; bi < 4 && next_cursor < read_end; ++bi) {
              const uint64_t remaining = read_end - next_cursor;
              uint32_t chunk = static_cast<uint32_t>(std::min<uint64_t>(remaining, dynamic_chunk));
              if (chunk > 4 * 1024 * 1024) {
                chunk = 4 * 1024 * 1024;
              }
              if (chunk < 64 * 1024) {
                chunk = static_cast<uint32_t>(std::min<uint64_t>(remaining, 64 * 1024));
              }
              if (!pointer_scan_byte_step_ && pointer_size > 1) {
                chunk = static_cast<uint32_t>((chunk / pointer_size) * pointer_size);
              }
              if (chunk == 0 || (pointer_scan_byte_step_ && chunk < pointer_size)) {
                break;
              }
              uint64_t advance = chunk;
              if (pointer_scan_byte_step_ && chunk > overlap) {
                advance = chunk - overlap;
              }
              batch_meta.push_back({next_cursor,
                                    chunk,
                                    std::min<uint64_t>(scan_end, next_cursor + static_cast<uint64_t>(chunk)),
                                    next_cursor + advance});
              batch_req.push_back({next_cursor, chunk});
              next_cursor += advance;
            }

            if (batch_meta.empty()) {
              break;
            }

            std::vector<std::vector<uint8_t>> batch_buffers;
            if (!ReadMemoryBatchWithClient(client, batch_req, read_flags, &batch_buffers)) {
              if (strict_reads) {
                report_read_error(batch_meta[0].addr, batch_meta[0].size, 0);
                stop.store(true);
                break;
              }
              success_streak = 0;
              if (dynamic_chunk > 64 * 1024) {
                dynamic_chunk = std::max<uint32_t>(64 * 1024, dynamic_chunk / 2);
              }
              cursor = batch_meta[0].next_cursor;
              continue;
            }
            if (batch_buffers.size() != batch_meta.size()) {
              if (strict_reads) {
                report_read_error(batch_meta[0].addr, batch_meta[0].size, 0);
                stop.store(true);
                break;
              }
              cursor = batch_meta.back().next_cursor;
              continue;
            }

            bool chunk_ok = true;
            for (size_t bi = 0; bi < batch_meta.size(); ++bi) {
              const auto& meta = batch_meta[bi];
              auto& buffer = batch_buffers[bi];
              if (strict_reads && buffer.size() < meta.size) {
                report_read_error(meta.addr, meta.size, buffer.size());
                stop.store(true);
                chunk_ok = false;
                break;
              }
              if (buffer.size() > reuse_buffer.capacity()) {
                reuse_buffer.reserve(buffer.size());
              }
              const size_t bytes = buffer.size();
              const size_t limit = bytes >= pointer_size ? (bytes - pointer_size + 1) : 0;
              for (size_t offset = 0; offset < limit; offset += step) {
                const uint64_t addr = meta.addr + offset;
                if (addr >= meta.scan_limit) {
                  break;
                }
                uint64_t value = 0;
                if (pointer_size == 4) {
                  uint32_t v32 = 0;
                  std::memcpy(&v32, buffer.data() + offset, sizeof(v32));
                  value = static_cast<uint64_t>(v32);
                } else {
                  uint64_t v64 = 0;
                  std::memcpy(&v64, buffer.data() + offset, sizeof(v64));
                  value = StripTag64(v64);
                }
                process_value(value, addr, thread_nodes[id]);
                if (stop.load()) {
                  chunk_ok = false;
                  break;
                }
              }
              if (!chunk_ok) {
                break;
              }
            }

            if (!chunk_ok) {
              break;
            }

            cursor = batch_meta.back().next_cursor;
            success_streak++;
            if (success_streak >= 4 && dynamic_chunk < 4 * 1024 * 1024) {
              dynamic_chunk = std::min<uint32_t>(4 * 1024 * 1024, dynamic_chunk * 2);
              success_streak = 0;
            }
          }
        }
      };
      worker_pool.Run(worker);
    }

    if (!read_error.empty()) {
      pointer_scan_status_ = read_error;
      return false;
    }

    if (total_nodes.load() >= kPointerNodeLimit) {
      pointer_scan_status_ = u8"结果过多，已停止";
      return false;
    }

    std::vector<PointerNode> current;
    current.reserve(total_nodes.load());
    for (auto& list : thread_nodes) {
      current.insert(current.end(), list.begin(), list.end());
    }
    std::sort(current.begin(), current.end(), [](const PointerNode& a, const PointerNode& b) {
      if (a.address != b.address) {
        return a.address < b.address;
      }
      if (a.parent != b.parent) {
        return a.parent < b.parent;
      }
      return a.offset < b.offset;
    });
    current.erase(std::unique(current.begin(),
                              current.end(),
                              [](const PointerNode& a, const PointerNode& b) {
                                return a.address == b.address &&
                                       a.parent == b.parent &&
                                       a.offset == b.offset;
                              }),
                  current.end());

    if (current.empty()) {
      pointer_scan_status_ = std::string(u8"未找到第") + std::to_string(level) + u8"层指针";
      return false;
    }
    levels.push_back(std::move(current));
  }

  std::filesystem::create_directories("seach_point");
  const std::string filename = std::string("seach_point/scan_") + NowTimeString() +
                               "_d" + std::to_string(depth) + ".r3p";
  std::ofstream ofs(filename, std::ios::binary);
  if (!ofs.is_open()) {
    pointer_scan_status_ = u8"无法写入输出文件";
    return false;
  }

  PointerFileHeader header{};
  header.magic = kPointerMagic;
  header.version = kPointerVersion;
  header.pointer_size = pointer_size;
  header.depth = static_cast<uint32_t>(depth);
  const bool multi_target = target_values.size() > 1;
  header.reserved = multi_target ? static_cast<uint32_t>(target_values.size()) : 0;
  header.target = target_values.empty() ? 0 : target_values.front();
  header.count = 0;
  header.max_offset = max_offset;
  header.flags = kPointerFlagDeltaVarint | (multi_target ? kPointerFlagMultiTarget : 0);
  ofs.write(reinterpret_cast<const char*>(&header), sizeof(header));
  if (multi_target) {
    ofs.write(reinterpret_cast<const char*>(target_values.data()),
              static_cast<std::streamsize>(target_values.size() * sizeof(uint64_t)));
  }

  const auto& final_nodes = levels.back();
  uint64_t prev_base = 0;
  std::vector<uint8_t> buffer;
  buffer.reserve(64 * 1024);
  uint64_t written = 0;

  for (size_t i = 0; i < final_nodes.size(); ++i) {
    std::vector<int64_t> offsets(depth);
    int idx = static_cast<int>(i);
    for (int level = depth - 1; level >= 0; --level) {
      if (idx < 0 || idx >= static_cast<int>(levels[level].size())) {
        offsets.clear();
        break;
      }
      offsets[static_cast<size_t>(level)] = levels[level][idx].offset;
      idx = levels[level][idx].parent;
    }
    if (offsets.empty()) {
      continue;
    }
    const uint64_t base = final_nodes[i].address;
    WriteVarUint(&buffer, base - prev_base);
    prev_base = base;
    for (int level = 0; level < depth; ++level) {
      WriteVarInt(&buffer, offsets[static_cast<size_t>(level)]);
    }
    written++;
    if (buffer.size() > 64 * 1024) {
      ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
      buffer.clear();
    }
  }

  if (!buffer.empty()) {
    ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  }

  ofs.seekp(offsetof(PointerFileHeader, count), std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(&written), sizeof(written));
  ofs.close();

  pointer_scan_count_ = written;
  pointer_scan_output_path_ = filename;
  PointerOperationMeta scan_meta{};
  scan_meta.valid = true;
  scan_meta.op = "scan";
  scan_meta.snapshot_id = snapshot_id;
  scan_meta.maps_hash = snapshot_maps_hash;
  scan_meta.region_count = snapshot_region_count;
  scan_meta.region_bytes = snapshot_region_bytes;
  scan_meta.read_fail_pages = 0;
  scan_meta.pointer_candidates = static_cast<uint64_t>(final_nodes.size());
  scan_meta.final_count = written;
  WritePointerOperationMeta(filename, scan_meta);
  if (!freeze_warning.empty()) {
    pointer_scan_status_ = freeze_warning + " snapshot=" + std::to_string(snapshot_id);
  } else {
    pointer_scan_status_ = std::string(u8"指针扫描完成 snapshot=") + std::to_string(snapshot_id);
  }
  return true;
}

bool ClientUI::BuildPointerIndexFromAgent(uint32_t pointer_size, std::string* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (!state_.connected) {
    if (out_error) {
      *out_error = u8"未连接";
    }
    return false;
  }
  if (state_.pid == 0) {
    if (!Attach()) {
      if (out_error) {
        *out_error = u8"请先打开进程";
      }
      return false;
    }
  }

  protocol::PointerIndexBuildRequest req{};
  req.pid = static_cast<uint32_t>(state_.pid);
  req.pointer_size = static_cast<uint16_t>(pointer_size);
  req.flags = pointer_scan_use_pvm_ ? protocol::PTR_INDEX_FLAG_USE_PVM : 0;
  if (pointer_scan_allow_nonresident_) {
    req.flags |= protocol::PTR_INDEX_FLAG_ALLOW_NONRESIDENT;
  }
  if (pointer_scan_byte_step_) {
    req.flags |= protocol::PTR_INDEX_FLAG_BYTE_STEP;
  }
  if (pointer_scan_freeze_) {
    req.flags |= protocol::PTR_INDEX_FLAG_STRICT;
  }
  req.max_entries = static_cast<uint32_t>(std::min<size_t>(kPointerIndexLimit, std::numeric_limits<uint32_t>::max()));
  req.reserved = 0;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_INDEX_BUILD,
                           &req,
                           sizeof(req),
                           &header,
                           &payload)) {
    if (out_error) {
      *out_error = u8"索引构建失败";
    }
    return false;
  }
  if (payload.size() < sizeof(protocol::PointerIndexBuildResponse)) {
    if (out_error) {
      *out_error = u8"索引响应无效";
    }
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::PointerIndexBuildResponse*>(payload.data());
  if (resp->code != 0) {
    if (out_error) {
      *out_error = u8"索引构建失败";
    }
    return false;
  }
  if (resp->truncated != 0) {
    if (out_error) {
      *out_error = u8"索引条目超限，构建被截断";
    }
    return false;
  }
  const uint64_t total = resp->count;
  if (total == 0) {
    if (out_error) {
      *out_error = u8"索引为空";
    }
    return false;
  }
  const uint32_t effective_pointer_size = resp->pointer_size == 0 ? pointer_size : resp->pointer_size;

  pointer_index_entries_.clear();
  pointer_index_entries_.reserve(static_cast<size_t>(std::min<uint64_t>(total, kPointerIndexLimit)));

  const uint32_t max_query = 4096;
  uint64_t start_index = 0;
  while (start_index < total) {
    protocol::PointerIndexQueryRequest qreq{};
    qreq.start_index = start_index;
    qreq.max_count = max_query;
    qreq.reserved = 0;

    protocol::PacketHeader qhdr{};
    std::vector<uint8_t> qpayload;
    if (!net_.SendAndReceive(protocol::CommandType::CMD_PTR_INDEX_QUERY,
                             &qreq,
                             sizeof(qreq),
                             &qhdr,
                             &qpayload)) {
      if (out_error) {
        *out_error = u8"索引下载失败";
      }
      return false;
    }
    if (qpayload.size() < offsetof(protocol::PointerIndexQueryResponse, entries)) {
      if (out_error) {
        *out_error = u8"索引响应无效";
      }
      return false;
    }
    const auto* qresp = reinterpret_cast<const protocol::PointerIndexQueryResponse*>(qpayload.data());
    const uint32_t returned = qresp->returned;
    const size_t expected = offsetof(protocol::PointerIndexQueryResponse, entries) +
                            static_cast<size_t>(returned) * sizeof(protocol::PointerIndexEntry);
    if (qpayload.size() < expected) {
      if (out_error) {
        *out_error = u8"索引响应无效";
      }
      return false;
    }
    for (uint32_t i = 0; i < returned; ++i) {
      const auto& entry = qresp->entries[i];
      pointer_index_entries_.push_back({entry.value, entry.address});
    }
    if (returned == 0) {
      break;
    }
    start_index += returned;
  }

  pointer_index_pointer_size_ = effective_pointer_size;
  pointer_index_pid_ = static_cast<uint32_t>(state_.pid);
  pointer_index_flags_ = kPointerIndexFlagDeltaVarint |
                         (pointer_scan_byte_step_ ? kPointerIndexFlagByteStep : 0) |
                         (pointer_scan_freeze_ ? kPointerIndexFlagStrict : 0);

  if (pointer_scan_index_path_[0] != '\0') {
    std::string err;
    const uint64_t idx_flags = (pointer_scan_byte_step_ ? kPointerIndexFlagByteStep : 0) |
                               (pointer_scan_freeze_ ? kPointerIndexFlagStrict : 0);
    if (!SavePointerIndexFile(pointer_scan_index_path_,
                              pointer_index_pointer_size_,
                              pointer_index_pid_,
                              idx_flags,
                              pointer_index_entries_,
                              &err)) {
      if (out_error) {
        *out_error = err.empty() ? u8"索引保存失败" : err;
      }
    }
  }
  return true;
}

bool ClientUI::RunPointerCompare() {
  pointer_compare_status_.clear();
  pointer_compare_output_path_.clear();
  pointer_compare_count_ = 0;

  if (!state_.connected) {
    pointer_compare_status_ = u8"未连接";
    return false;
  }
  std::vector<std::string> files;
  if (pointer_compare_multi_mode_) {
    files = pointer_compare_files_;
  } else {
    if (pointer_compare_file_a_.empty() || pointer_compare_file_b_.empty()) {
      pointer_compare_status_ = u8"请选择两份指针文件";
      return false;
    }
    files.push_back(pointer_compare_file_a_);
    files.push_back(pointer_compare_file_b_);
  }
  if (files.size() < 2) {
    pointer_compare_status_ = u8"至少需要两份指针文件";
    return false;
  }

  uint64_t compare_snapshot_id = 0;
  uint64_t compare_region_count = 0;
  uint64_t compare_region_bytes = 0;
  uint64_t compare_maps_hash = 0;
  if (!pointer_compare_bench_mode_) {
    if (state_.modules.empty()) {
      FetchModules();
    }
    compare_snapshot_id = NextSnapshotId();
    compare_maps_hash =
        ComputeModuleSnapshotHash(state_.modules,
                                  nullptr,
                                  false,
                                  &compare_region_count,
                                  &compare_region_bytes);

    uint64_t input_maps_hash = 0;
    bool has_input_maps_hash = false;
    for (const auto& path : files) {
      PointerOperationMeta meta{};
      if (!ReadPointerOperationMeta(path, &meta) || !meta.valid || meta.maps_hash == 0) {
        continue;
      }
      if (!has_input_maps_hash) {
        input_maps_hash = meta.maps_hash;
        has_input_maps_hash = true;
        continue;
      }
      if (meta.maps_hash != input_maps_hash) {
        pointer_compare_status_ = u8"输入指针文件快照不一致";
        return false;
      }
    }
  }

  std::vector<PointerFileHeader> headers(files.size());
  std::vector<std::vector<uint64_t>> target_lists(files.size());
  std::string header_cache_key;
  if (pointer_compare_bench_mode_) {
    header_cache_key.reserve(256);
    header_cache_key.append(pointer_compare_multi_mode_ ? "multi|" : "pair|");
    header_cache_key.append(pointer_compare_fast_mode_ ? "fast|" : "normal|");
    for (const auto& path : files) {
      std::error_code ec;
      const uint64_t size = std::filesystem::exists(path, ec) ? std::filesystem::file_size(path, ec) : 0;
      const auto ts = std::filesystem::exists(path, ec)
                        ? std::filesystem::last_write_time(path, ec).time_since_epoch().count()
                        : 0;
      header_cache_key.append(path)
                      .append("@")
                      .append(std::to_string(size))
                      .append("@")
                      .append(std::to_string(static_cast<long long>(ts)))
                      .append("|");
    }
  }
  auto read_header_targets = [&](const std::string& path,
                                 PointerFileHeader* out_hdr,
                                 std::vector<uint64_t>* out_targets) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
      return false;
    }
    ifs.read(reinterpret_cast<char*>(out_hdr), sizeof(*out_hdr));
    if (ifs.gcount() != static_cast<std::streamsize>(sizeof(*out_hdr))) {
      return false;
    }
    if (out_hdr->magic != kPointerMagic || out_hdr->version != kPointerVersion) {
      return false;
    }
    return ReadPointerTargets(ifs, *out_hdr, out_targets);
  };

  bool used_cached_headers = false;
  if (pointer_compare_bench_mode_ && !header_cache_key.empty()) {
    struct BenchHeaderCache {
      std::string key;
      std::vector<PointerFileHeader> headers;
      std::vector<std::vector<uint64_t>> targets;
    };
    static BenchHeaderCache s_header_cache;
    if (s_header_cache.key == header_cache_key &&
        s_header_cache.headers.size() == files.size() &&
        s_header_cache.targets.size() == files.size()) {
      headers = s_header_cache.headers;
      target_lists = s_header_cache.targets;
      used_cached_headers = true;
    } else {
      for (size_t i = 0; i < files.size(); ++i) {
        if (!read_header_targets(files[i], &headers[i], &target_lists[i])) {
          pointer_compare_status_ = u8"指针文件读取失败";
          return false;
        }
      }
      s_header_cache.key = header_cache_key;
      s_header_cache.headers = headers;
      s_header_cache.targets = target_lists;
    }
  }
  if (!used_cached_headers) {
    for (size_t i = 0; i < files.size(); ++i) {
      if (!read_header_targets(files[i], &headers[i], &target_lists[i])) {
        pointer_compare_status_ = u8"指针文件读取失败";
        return false;
      }
    }
  }

  const uint32_t depth = headers[0].depth;
  const uint32_t pointer_size = headers[0].pointer_size;
  for (size_t i = 1; i < headers.size(); ++i) {
    if (headers[i].depth != depth || headers[i].pointer_size != pointer_size) {
      pointer_compare_status_ = u8"指针文件层数/指针大小不一致";
      return false;
    }
  }

  std::unordered_set<uint64_t> target_set;
  for (const auto& list : target_lists) {
    for (uint64_t t : list) {
      if (pointer_size == 8) {
        t = StripTag64(t);
      }
      if (t != 0) {
        target_set.insert(t);
      }
    }
  }
  if (target_set.empty()) {
    target_set.insert(headers[0].target);
  }
  std::vector<uint64_t> target_union(target_set.begin(), target_set.end());
  std::sort(target_union.begin(), target_union.end());
  auto is_target_match = [&](uint64_t addr) {
    return std::binary_search(target_union.begin(), target_union.end(), addr);
  };

  if (state_.pid == 0) {
    if (!Attach()) {
      pointer_compare_status_ = u8"请先打开进程";
      return false;
    }
  }

  auto stream_file = [](const std::string& path,
                        const PointerFileHeader& hdr,
                        const std::function<bool(const PointerChain&)>& cb) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
      return false;
    }
    const std::streamoff data_offset = PointerFileDataOffset(hdr);
    ifs.seekg(data_offset, std::ios::beg);
    uint64_t prev_base = 0;
    for (uint64_t i = 0; (hdr.count == 0) || (i < hdr.count); ++i) {
      uint64_t delta = 0;
      if (!ReadVarUint(ifs, &delta)) {
        return hdr.count == 0;
      }
      uint64_t base = prev_base + delta;
      prev_base = base;
      PointerChain chain;
      chain.base = base;
      chain.offsets.resize(hdr.depth);
      for (uint32_t d = 0; d < hdr.depth; ++d) {
        int64_t off = 0;
        if (!ReadVarInt(ifs, &off)) {
          return false;
        }
        chain.offsets[d] = off;
      }
      if (!cb(chain)) {
        break;
      }
    }
    return true;
  };

  std::string bench_cache_key;
  if (pointer_compare_bench_mode_) {
    bench_cache_key.reserve(256);
    bench_cache_key.append(pointer_compare_multi_mode_ ? "multi|" : "pair|");
    bench_cache_key.append(pointer_compare_fast_mode_ ? "fast|" : "normal|");
    bench_cache_key.append("d").append(std::to_string(depth)).append("|ps").append(std::to_string(pointer_size)).append("|");
    for (const auto& path : files) {
      std::error_code ec;
      const uint64_t size = std::filesystem::exists(path, ec) ? std::filesystem::file_size(path, ec) : 0;
      const auto ts = std::filesystem::exists(path, ec)
                        ? std::filesystem::last_write_time(path, ec).time_since_epoch().count()
                        : 0;
      bench_cache_key.append(path)
                     .append("@")
                     .append(std::to_string(size))
                     .append("@")
                     .append(std::to_string(static_cast<long long>(ts)))
                     .append("|");
    }
  }
  static std::string s_bench_cache_key;
  static std::vector<PointerChain> s_bench_cached_candidates;
  std::vector<PointerChain> candidates;
  bool used_cached_candidates = false;
  if (pointer_compare_bench_mode_ &&
      !bench_cache_key.empty() &&
      bench_cache_key == s_bench_cache_key &&
      !s_bench_cached_candidates.empty()) {
    candidates = s_bench_cached_candidates;
    used_cached_candidates = true;
  }
  if (!used_cached_candidates) {
  if (!pointer_compare_multi_mode_ && files.size() == 2) {
    const uint64_t size_a = std::filesystem::exists(files[0]) ? std::filesystem::file_size(files[0]) : 0;
    const uint64_t size_b = std::filesystem::exists(files[1]) ? std::filesystem::file_size(files[1]) : 0;
    const bool a_smaller = size_a <= size_b;
    const std::string& small_path = a_smaller ? files[0] : files[1];
    const std::string& large_path = a_smaller ? files[1] : files[0];
    const PointerFileHeader& small_hdr = a_smaller ? headers[0] : headers[1];
    const PointerFileHeader& large_hdr = a_smaller ? headers[1] : headers[0];
    auto chain_less = [](const PointerChain& a, const PointerChain& b) {
      if (a.base != b.base) {
        return a.base < b.base;
      }
      return a.offsets < b.offsets;
    };
    constexpr size_t kCandidateLimit = 5'000'000;
    constexpr uint64_t kBucketThreshold = 128ull * 1024 * 1024;
    const bool use_bucket = pointer_compare_fast_mode_ && (size_a + size_b) >= kBucketThreshold;
    if (use_bucket) {
      const uint64_t target_bucket = 32ull * 1024 * 1024;
      size_t bucket_count = 1;
      const uint64_t total = std::max(size_a, size_b);
      while (bucket_count < 256 && (total / bucket_count) > target_bucket) {
        bucket_count <<= 1;
      }
      const std::filesystem::path tmp_dir = std::filesystem::path("seach_point/compare_tmp") / NowTimeString();
      std::filesystem::create_directories(tmp_dir);

      auto bucket_path = [&](const std::string& tag, size_t idx) {
        return (tmp_dir / (tag + "_" + std::to_string(idx) + ".bin")).string();
      };

      std::vector<std::ofstream> buckets_a(bucket_count);
      std::vector<std::ofstream> buckets_b(bucket_count);
      for (size_t i = 0; i < bucket_count; ++i) {
        buckets_a[i].open(bucket_path("a", i), std::ios::binary);
        buckets_b[i].open(bucket_path("b", i), std::ios::binary);
        if (!buckets_a[i].is_open() || !buckets_b[i].is_open()) {
          pointer_compare_status_ = u8"临时分桶文件创建失败";
          return false;
        }
      }

      auto write_bucket = [&](std::vector<std::ofstream>& buckets,
                              const PointerChain& chain,
                              size_t depth) {
        const uint64_t key = HashChain(chain.base, chain.offsets);
        const size_t idx = static_cast<size_t>(key) & (bucket_count - 1);
        auto& ofs = buckets[idx];
        ofs.write(reinterpret_cast<const char*>(&chain.base), sizeof(chain.base));
        ofs.write(reinterpret_cast<const char*>(chain.offsets.data()),
                  static_cast<std::streamsize>(depth * sizeof(int64_t)));
      };

      if (!stream_file(small_path, small_hdr, [&](const PointerChain& chain) {
            write_bucket(buckets_a, chain, depth);
            return true;
          })) {
        pointer_compare_status_ = u8"读取指针文件失败";
        return false;
      }
      if (!stream_file(large_path, large_hdr, [&](const PointerChain& chain) {
            write_bucket(buckets_b, chain, depth);
            return true;
          })) {
        pointer_compare_status_ = u8"读取指针文件失败";
        return false;
      }
      for (size_t i = 0; i < bucket_count; ++i) {
        buckets_a[i].close();
        buckets_b[i].close();
      }

      auto load_bucket = [&](const std::string& path, std::vector<PointerChain>* out) -> bool {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
          return false;
        }
        out->clear();
        const size_t record_size = sizeof(uint64_t) + depth * sizeof(int64_t);
        std::vector<uint8_t> buffer(record_size);
        while (ifs.read(reinterpret_cast<char*>(buffer.data()), record_size)) {
          PointerChain chain;
          std::memcpy(&chain.base, buffer.data(), sizeof(uint64_t));
          chain.offsets.resize(depth);
          std::memcpy(chain.offsets.data(),
                      buffer.data() + sizeof(uint64_t),
                      depth * sizeof(int64_t));
          out->push_back(std::move(chain));
        }
        return true;
      };

      for (size_t i = 0; i < bucket_count; ++i) {
        const std::string path_a = bucket_path("a", i);
        const std::string path_b = bucket_path("b", i);
        std::vector<PointerChain> list_a;
        std::vector<PointerChain> list_b;
        if (!load_bucket(path_a, &list_a) || !load_bucket(path_b, &list_b)) {
          pointer_compare_status_ = u8"读取分桶文件失败";
          std::error_code ec;
          std::filesystem::remove_all(tmp_dir, ec);
          return false;
        }
        if (list_a.empty() || list_b.empty()) {
          continue;
        }
        std::sort(list_a.begin(), list_a.end(), chain_less);
        std::sort(list_b.begin(), list_b.end(), chain_less);
        size_t ia = 0;
        size_t ib = 0;
        while (ia < list_a.size() && ib < list_b.size()) {
          if (chain_less(list_a[ia], list_b[ib])) {
            ia++;
            continue;
          }
          if (chain_less(list_b[ib], list_a[ia])) {
            ib++;
            continue;
          }
          candidates.push_back(list_a[ia]);
          if (candidates.size() >= kCandidateLimit) {
            pointer_compare_status_ = u8"候选链过多，已停止";
            std::error_code ec;
            std::filesystem::remove_all(tmp_dir, ec);
            return false;
          }
          const PointerChain matched = list_a[ia];
          while (ia < list_a.size() && ChainEqual(list_a[ia], matched)) {
            ia++;
          }
          while (ib < list_b.size() && ChainEqual(list_b[ib], matched)) {
            ib++;
          }
        }
      }
      std::error_code ec;
      std::filesystem::remove_all(tmp_dir, ec);
    } else {
      auto load_all = [&](const std::string& path,
                          const PointerFileHeader& hdr,
                          std::vector<PointerChain>* out_list) -> bool {
        if (!out_list) {
          return false;
        }
        out_list->clear();
        if (hdr.count > 0) {
          const size_t reserve_count = static_cast<size_t>(std::min<uint64_t>(hdr.count, kCandidateLimit));
          out_list->reserve(reserve_count);
        }
        bool overflow = false;
        const bool ok = stream_file(path, hdr, [&](const PointerChain& chain) {
          out_list->push_back(chain);
          if (out_list->size() > kCandidateLimit) {
            overflow = true;
            return false;
          }
          return true;
        });
        return ok && !overflow;
      };

      std::vector<PointerChain> list_small;
      std::vector<PointerChain> list_large;
      if (!load_all(small_path, small_hdr, &list_small) ||
          !load_all(large_path, large_hdr, &list_large)) {
        pointer_compare_status_ = u8"读取指针文件失败";
        return false;
      }
      if (!list_small.empty() && !list_large.empty()) {
        std::sort(list_small.begin(), list_small.end(), chain_less);
        std::sort(list_large.begin(), list_large.end(), chain_less);
        candidates.reserve(std::min(list_small.size(), list_large.size()));
        size_t ia = 0;
        size_t ib = 0;
        while (ia < list_small.size() && ib < list_large.size()) {
          if (chain_less(list_small[ia], list_large[ib])) {
            ia++;
            continue;
          }
          if (chain_less(list_large[ib], list_small[ia])) {
            ib++;
            continue;
          }
          candidates.push_back(list_small[ia]);
          if (candidates.size() >= kCandidateLimit) {
            pointer_compare_status_ = u8"候选链过多，已停止";
            return false;
          }
          const PointerChain matched = list_small[ia];
          while (ia < list_small.size() && ChainEqual(list_small[ia], matched)) {
            ia++;
          }
          while (ib < list_large.size() && ChainEqual(list_large[ib], matched)) {
            ib++;
          }
        }
      }
    }
  } else {
    struct ChainValue {
      PointerChain chain;
      uint32_t seen = 0;
    };
    std::unordered_map<std::string, ChainValue> map;
    if (!stream_file(files[0], headers[0], [&](const PointerChain& chain) {
          map.emplace(MakeChainKey(chain.base, chain.offsets), ChainValue{chain, 1});
          return true;
        })) {
      pointer_compare_status_ = u8"读取指针文件失败";
      return false;
    }
    for (size_t file_index = 1; file_index < files.size(); ++file_index) {
      std::unordered_set<std::string> matched;
      const uint32_t expect = static_cast<uint32_t>(file_index);
      if (!stream_file(files[file_index], headers[file_index], [&](const PointerChain& chain) {
            const std::string key = MakeChainKey(chain.base, chain.offsets);
            auto it = map.find(key);
            if (it != map.end() && it->second.seen == expect) {
              if (matched.insert(key).second) {
                it->second.seen = expect + 1;
              }
            }
            return true;
          })) {
        pointer_compare_status_ = u8"读取指针文件失败";
        return false;
      }
      for (auto it = map.begin(); it != map.end(); ) {
        if (it->second.seen != expect + 1) {
          it = map.erase(it);
        } else {
          ++it;
        }
      }
      if (map.empty()) {
        break;
      }
    }
    candidates.reserve(map.size());
    for (const auto& kv : map) {
      candidates.push_back(kv.second.chain);
    }
  }
  if (pointer_compare_bench_mode_ && !bench_cache_key.empty() && !candidates.empty()) {
    s_bench_cache_key = bench_cache_key;
    s_bench_cached_candidates = candidates;
  }
  }

  if (candidates.empty()) {
    pointer_compare_status_ = u8"无可对比的指针";
    return false;
  }

  uint32_t flags = pointer_compare_use_pvm_ ? protocol::READ_FLAG_USE_PVM : 0;
  if (pointer_compare_allow_nonresident_) {
    flags |= protocol::READ_FLAG_ALLOW_NONRESIDENT;
  }
  const uint16_t depth16 = depth > std::numeric_limits<uint16_t>::max()
                             ? 0
                             : static_cast<uint16_t>(depth);
  const size_t batch_header = offsetof(protocol::PointerVerifyBatchRequest, bases);
  const size_t per_chain = sizeof(uint64_t) + static_cast<size_t>(depth) * sizeof(int64_t);
  const size_t max_payload = 16u * 1024u * 1024u;
  size_t max_batch = 0;
  if (depth16 > 0 && per_chain > 0 && max_payload > batch_header) {
    max_batch = (max_payload - batch_header) / per_chain;
  }
  if (max_batch == 0) {
    max_batch = 1;
  }
  max_batch = std::min<size_t>(max_batch, 4096);
  const size_t min_batch = std::max<size_t>(1, std::min<size_t>(64, max_batch));
  std::atomic<size_t> dynamic_batch{std::max<size_t>(min_batch, std::min<size_t>(max_batch, 512))};
  std::atomic<bool> batch_supported{true};
  static std::atomic<bool> s_verify_batch_v2_supported{true};
  std::atomic<bool> batch_filter_supported{
      !target_union.empty() && s_verify_batch_v2_supported.load(std::memory_order_relaxed)};
  const unsigned hw = std::thread::hardware_concurrency();
  unsigned thread_count = std::max(1u, std::min(4u, hw == 0 ? 2u : hw / 2));
  if (candidates.size() < 256) {
    thread_count = 1;
  } else if (candidates.size() < 2048) {
    thread_count = std::min(thread_count, 2u);
  }
  std::atomic<size_t> index{0};
  std::vector<std::vector<PointerChain>> valid(thread_count);

  auto verify_chain = [&](NetClient& client, const PointerChain& chain, uint64_t* out_addr) -> bool {
    struct PrefixCacheEntry {
      bool ok = false;
      uint64_t addr = 0;
      uint16_t next = 0;
    };
    thread_local std::unordered_map<std::string, PrefixCacheEntry> prefix_cache;
    if (prefix_cache.size() > 200000) {
      prefix_cache.clear();
    }

    auto apply_offset = [](uint64_t ptr, int64_t off, uint64_t* out) -> bool {
      if (!out) {
        return false;
      }
      if (off >= 0) {
        const uint64_t uoff = static_cast<uint64_t>(off);
        if (ptr > UINT64_MAX - uoff) {
          return false;
        }
        *out = ptr + uoff;
        return true;
      }
      const uint64_t uoff = static_cast<uint64_t>(-off);
      if (ptr < uoff) {
        return false;
      }
      *out = ptr - uoff;
      return true;
    };

    uint64_t addr = chain.base;
    size_t start_idx = 0;
    const size_t prefix_depth = std::min<size_t>(chain.offsets.size(), 3);
    if (prefix_depth > 0) {
      std::string key;
      key.resize(sizeof(uint64_t) + prefix_depth * sizeof(int64_t));
      std::memcpy(&key[0], &chain.base, sizeof(uint64_t));
      std::memcpy(&key[sizeof(uint64_t)],
                  chain.offsets.data(),
                  prefix_depth * sizeof(int64_t));

      auto it = prefix_cache.find(key);
      if (it != prefix_cache.end()) {
        if (!it->second.ok) {
          return false;
        }
        addr = it->second.addr;
        start_idx = it->second.next;
      } else {
        bool ok_prefix = true;
        for (size_t i = 0; i < prefix_depth; ++i) {
          uint64_t ptr = 0;
          if (!ReadPointerValue(client, addr, pointer_size, flags, &ptr) || ptr == 0) {
            ok_prefix = false;
            break;
          }
          if (!apply_offset(ptr, chain.offsets[i], &addr)) {
            ok_prefix = false;
            break;
          }
        }
        PrefixCacheEntry entry{};
        entry.ok = ok_prefix;
        entry.addr = addr;
        entry.next = static_cast<uint16_t>(prefix_depth);
        prefix_cache.emplace(std::move(key), entry);
        if (!ok_prefix) {
          return false;
        }
        start_idx = prefix_depth;
      }
    }

    for (size_t i = start_idx; i < chain.offsets.size(); ++i) {
      const int64_t off = chain.offsets[i];
      uint64_t ptr = 0;
      if (!ReadPointerValue(client, addr, pointer_size, flags, &ptr)) {
        return false;
      }
      if (ptr == 0) {
        return false;
      }
      if (!apply_offset(ptr, off, &addr)) {
        return false;
      }
    }
    if (out_addr) {
      *out_addr = addr;
    }
    return true;
  };

  const bool use_attached_session =
      thread_count == 1 &&
      candidates.size() <= 4096 &&
      state_.pid != 0;
  if (use_attached_session) {
    size_t cursor = 0;
    size_t batch_success_streak = 0;
    while (cursor < candidates.size()) {
      const size_t batch_span =
          std::max<size_t>(1, std::min<size_t>(max_batch, dynamic_batch.load(std::memory_order_relaxed)));
      const size_t count = std::min(batch_span, candidates.size() - cursor);
      bool use_batch = batch_supported.load() && depth16 > 0 && count > 0;
      if (use_batch) {
        bool batch_ok = false;
        if (batch_filter_supported.load(std::memory_order_relaxed) && count >= 4) {
          std::vector<uint32_t> matched_indices;
          if (SendPointerVerifyBatchFilter(net_,
                                           candidates,
                                           cursor,
                                           count,
                                           pointer_size,
                                           depth16,
                                           flags,
                                           target_union,
                                           &matched_indices)) {
            batch_ok = true;
            batch_success_streak++;
            if (count == batch_span && batch_success_streak >= 2 && batch_span < max_batch) {
              const size_t grown = std::min(max_batch, batch_span * 2);
              size_t expected = batch_span;
              dynamic_batch.compare_exchange_weak(expected, grown, std::memory_order_relaxed);
              batch_success_streak = 0;
            }
            for (uint32_t midx : matched_indices) {
              valid[0].push_back(candidates[cursor + midx]);
            }
            cursor += count;
            continue;
          }
          batch_filter_supported.store(false, std::memory_order_relaxed);
          s_verify_batch_v2_supported.store(false, std::memory_order_relaxed);
        }
        std::vector<protocol::PointerVerifyBatchResult> results;
        if (count == 1) {
          protocol::PointerVerifyBatchResult one{};
          if (SendPointerVerifySingle(net_,
                                      candidates[cursor],
                                      pointer_size,
                                      depth16,
                                      flags,
                                      &one)) {
            results.resize(1);
            results[0] = one;
            batch_ok = true;
          }
        } else if (SendPointerVerifyBatch(net_,
                                          candidates,
                                          cursor,
                                          count,
                                          pointer_size,
                                          depth16,
                                          flags,
                                          &results)) {
          batch_ok = true;
        }
        if (batch_ok) {
          batch_success_streak++;
          if (count == batch_span && batch_success_streak >= 2 && batch_span < max_batch) {
            const size_t grown = std::min(max_batch, batch_span * 2);
            size_t expected = batch_span;
            dynamic_batch.compare_exchange_weak(expected, grown, std::memory_order_relaxed);
            batch_success_streak = 0;
          }
          for (size_t i = 0; i < count; ++i) {
            if (results[i].code != 0) {
              continue;
            }
            const uint64_t addr = results[i].address;
            if (is_target_match(addr)) {
              valid[0].push_back(candidates[cursor + i]);
            }
          }
          cursor += count;
          continue;
        }
        batch_success_streak = 0;
        if (batch_span > min_batch) {
          const size_t shrink = std::max(min_batch, batch_span / 2);
          size_t expected = batch_span;
          dynamic_batch.compare_exchange_weak(expected, shrink, std::memory_order_relaxed);
        } else {
          batch_supported.store(false);
        }
      }
      batch_success_streak = 0;
      for (size_t i = 0; i < count; ++i) {
        const auto& chain = candidates[cursor + i];
        uint64_t addr = 0;
        if (verify_chain(net_, chain, &addr) &&
            is_target_match(addr)) {
          valid[0].push_back(chain);
        }
      }
      cursor += count;
    }
  } else {
    auto worker = [&](unsigned id) {
      NetClient client;
      if (!client.Connect(host_, static_cast<uint16_t>(port_))) {
        return;
      }
      BenchTrackConnect();
      protocol::AttachRequest areq{};
      areq.pid = state_.pid;
      areq.reserved = 0;
      protocol::PacketHeader header{};
      std::vector<uint8_t> payload;
      if (!client.SendAndReceive(protocol::CommandType::CMD_ATTACH, &areq, sizeof(areq), &header, &payload)) {
        client.Disconnect();
        return;
      }
      BenchTrackPacket(sizeof(areq), payload.size());
      BenchTrackAttach();
      size_t batch_success_streak = 0;
      while (true) {
        const size_t batch_span =
            std::max<size_t>(1, std::min<size_t>(max_batch, dynamic_batch.load(std::memory_order_relaxed)));
        const size_t start = index.fetch_add(batch_span);
        if (start >= candidates.size()) {
          break;
        }
        const size_t count = std::min(batch_span, candidates.size() - start);
        bool use_batch = batch_supported.load() && depth16 > 0 && count > 0;
        if (use_batch) {
          if (batch_filter_supported.load(std::memory_order_relaxed) && count >= 4) {
            std::vector<uint32_t> matched_indices;
            if (SendPointerVerifyBatchFilter(client,
                                             candidates,
                                             start,
                                             count,
                                             pointer_size,
                                             depth16,
                                             flags,
                                             target_union,
                                             &matched_indices)) {
              batch_success_streak++;
              if (count == batch_span && batch_success_streak >= 2 && batch_span < max_batch) {
                const size_t grown = std::min(max_batch, batch_span * 2);
                size_t expected = batch_span;
                dynamic_batch.compare_exchange_weak(expected, grown, std::memory_order_relaxed);
                batch_success_streak = 0;
              }
              for (uint32_t midx : matched_indices) {
                valid[id].push_back(candidates[start + midx]);
              }
              continue;
            }
            batch_filter_supported.store(false, std::memory_order_relaxed);
            s_verify_batch_v2_supported.store(false, std::memory_order_relaxed);
          }
          std::vector<protocol::PointerVerifyBatchResult> results;
          if (SendPointerVerifyBatch(client,
                                     candidates,
                                     start,
                                     count,
                                     pointer_size,
                                     depth16,
                                     flags,
                                     &results)) {
            batch_success_streak++;
            if (count == batch_span && batch_success_streak >= 2 && batch_span < max_batch) {
              const size_t grown = std::min(max_batch, batch_span * 2);
              size_t expected = batch_span;
              dynamic_batch.compare_exchange_weak(expected, grown, std::memory_order_relaxed);
              batch_success_streak = 0;
            }
            for (size_t i = 0; i < count; ++i) {
              if (results[i].code != 0) {
                continue;
              }
              const uint64_t addr = results[i].address;
              if (is_target_match(addr)) {
                valid[id].push_back(candidates[start + i]);
              }
            }
            continue;
          }
          batch_success_streak = 0;
          if (batch_span > min_batch) {
            const size_t shrink = std::max(min_batch, batch_span / 2);
            size_t expected = batch_span;
            dynamic_batch.compare_exchange_weak(expected, shrink, std::memory_order_relaxed);
          } else {
            batch_supported.store(false);
          }
        }
        batch_success_streak = 0;
        for (size_t i = 0; i < count; ++i) {
          const auto& chain = candidates[start + i];
          uint64_t addr = 0;
          if (verify_chain(client, chain, &addr) &&
              is_target_match(addr)) {
            valid[id].push_back(chain);
          }
        }
      }
      client.Disconnect();
    };

    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (unsigned i = 0; i < thread_count; ++i) {
      threads.emplace_back(worker, i);
    }
    for (auto& t : threads) {
      t.join();
    }
  }

  uint64_t total_valid = 0;
  for (const auto& list : valid) {
    total_valid += list.size();
  }
  if (total_valid == 0) {
    pointer_compare_status_ = u8"对比后无有效指针";
    return false;
  }

  if (pointer_compare_bench_mode_) {
    pointer_compare_count_ = total_valid;
    pointer_compare_output_path_.clear();
    pointer_compare_status_ = u8"对比完成";
    return true;
  }

  std::filesystem::create_directories("seach_point/compare");
  const std::string out_path = std::string("seach_point/compare/compare_") + NowTimeString() + ".r3p";
  std::ofstream ofs(out_path, std::ios::binary);
  if (!ofs.is_open()) {
    pointer_compare_status_ = u8"无法写入对比结果";
    return false;
  }

  PointerFileHeader out_hdr = headers[0];
  out_hdr.count = 0;
  const bool multi_target = target_union.size() > 1;
  out_hdr.flags = kPointerFlagDeltaVarint | (multi_target ? kPointerFlagMultiTarget : 0);
  out_hdr.reserved = multi_target ? static_cast<uint32_t>(target_union.size()) : 0;
  out_hdr.target = target_union.empty() ? 0 : target_union.front();
  ofs.write(reinterpret_cast<const char*>(&out_hdr), sizeof(out_hdr));
  if (multi_target) {
    ofs.write(reinterpret_cast<const char*>(target_union.data()),
              static_cast<std::streamsize>(target_union.size() * sizeof(uint64_t)));
  }

  uint64_t prev_base = 0;
  std::vector<uint8_t> buffer;
  buffer.reserve(64 * 1024);
  uint64_t written = 0;

  for (const auto& list : valid) {
    for (const auto& chain : list) {
      WriteVarUint(&buffer, chain.base - prev_base);
      prev_base = chain.base;
      for (int64_t off : chain.offsets) {
        WriteVarInt(&buffer, off);
      }
      written++;
      if (buffer.size() > 64 * 1024) {
        ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        buffer.clear();
      }
    }
  }

  if (!buffer.empty()) {
    ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  }

  ofs.seekp(offsetof(PointerFileHeader, count), std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(&written), sizeof(written));
  ofs.close();

  pointer_compare_count_ = written;
  pointer_compare_output_path_ = out_path;
  PointerOperationMeta compare_meta{};
  compare_meta.valid = true;
  compare_meta.op = "compare";
  compare_meta.snapshot_id = compare_snapshot_id;
  compare_meta.maps_hash = compare_maps_hash;
  compare_meta.region_count = compare_region_count;
  compare_meta.region_bytes = compare_region_bytes;
  compare_meta.read_fail_pages = 0;
  compare_meta.pointer_candidates = static_cast<uint64_t>(candidates.size());
  compare_meta.final_count = written;
  WritePointerOperationMeta(out_path, compare_meta);
  pointer_compare_status_ = std::string(u8"对比完成 snapshot=") + std::to_string(compare_snapshot_id);
  return true;
}

bool ClientUI::RunDataTraverse() {
  data_traverse_entries_.clear();
  data_traverse_node_overrides_.clear();
  data_traverse_child_cache_.clear();
  data_traverse_cache_lru_.clear();
  data_traverse_status_.clear();

  if (!state_.connected) {
    data_traverse_status_ = u8"未连接";
    return false;
  }
  if (state_.pid == 0) {
    if (!Attach()) {
      data_traverse_status_ = u8"请先打开进程";
      return false;
    }
  }

  uint64_t addr = ParseAddress(data_traverse_addr_);
  if (addr == 0) {
    data_traverse_status_ = u8"地址无效";
    return false;
  }

  std::string status;
  const bool ok = BuildTraverseEntries(addr,
                                       data_traverse_count_,
                                       data_traverse_stride_,
                                       data_traverse_type_,
                                       data_traverse_use_pvm_,
                                       &data_traverse_entries_,
                                       &status);
  if (!status.empty()) {
    data_traverse_status_ = status;
  } else if (ok) {
    data_traverse_status_ = u8"遍历完成";
  }
  return ok;
}

bool ClientUI::RunPointerVerify() {
  pointer_verify_lines_.clear();
  pointer_verify_status_.clear();
  pointer_verify_expr_.clear();

  if (!state_.connected) {
    pointer_verify_status_ = u8"未连接";
    return false;
  }
  if (state_.pid == 0) {
    if (!Attach()) {
      pointer_verify_status_ = u8"请先打开进程";
      return false;
    }
  }

  const uint64_t base = ParseAddress(pointer_verify_addr_);
  if (base == 0) {
    pointer_verify_status_ = u8"地址无效";
    return false;
  }

  if (state_.modules.empty()) {
    FetchModules();
  }
  const uint32_t pointer_size = GetPointerSizeFromModules();
  const uint64_t verify_snapshot_id = pointer_verify_bench_mode_ ? 0 : NextSnapshotId();
  uint64_t verify_region_count = 0;
  uint64_t verify_region_bytes = 0;
  uint64_t verify_maps_hash = 0;
  if (!pointer_verify_bench_mode_) {
    verify_maps_hash =
        ComputeModuleSnapshotHash(state_.modules,
                                  nullptr,
                                  false,
                                  &verify_region_count,
                                  &verify_region_bytes);
  }

  uint32_t flags = 0;
  if (pointer_verify_use_pvm_) {
    flags |= protocol::READ_FLAG_USE_PVM;
  }
  if (pointer_verify_allow_nonresident_) {
    flags |= protocol::READ_FLAG_ALLOW_NONRESIDENT;
  }

  uint64_t addr = base;
  pointer_verify_expr_ = pointer_verify_is_pointer_
                           ? BuildPointerExpr(base, pointer_verify_offsets_, true)
                           : Hex64(base);

  bool resolved_by_batch = false;
  if (pointer_verify_is_pointer_ &&
      !pointer_verify_offsets_.empty() &&
      pointer_verify_offsets_.size() <= std::numeric_limits<uint16_t>::max()) {
    auto apply_offset = [](uint64_t value, int64_t off, uint64_t* out) -> bool {
      if (!out) {
        return false;
      }
      if (off >= 0) {
        const uint64_t uoff = static_cast<uint64_t>(off);
        if (value > UINT64_MAX - uoff) {
          return false;
        }
        *out = value + uoff;
        return true;
      }
      const uint64_t uoff = static_cast<uint64_t>(-off);
      if (value < uoff) {
        return false;
      }
      *out = value - uoff;
      return true;
    };

    PointerChain batch_chain;
    uint64_t shifted_base = base;
    if (apply_offset(base, pointer_verify_offsets_.front(), &shifted_base)) {
      batch_chain.base = shifted_base;
      batch_chain.offsets.reserve(pointer_verify_offsets_.size());
      for (size_t i = 1; i < pointer_verify_offsets_.size(); ++i) {
        batch_chain.offsets.push_back(pointer_verify_offsets_[i]);
      }
      // UI 输入语义为 [addr+off] 先偏移后解引用，转换为 after-deref 协议后追加 0 偏移。
      batch_chain.offsets.push_back(0);
      protocol::PointerVerifyBatchResult result{};
      if (SendPointerVerifySingle(net_,
                                  batch_chain,
                                  pointer_size,
                                  static_cast<uint16_t>(batch_chain.offsets.size()),
                                  flags,
                                  &result) &&
          result.code == 0 &&
          result.address != 0) {
        addr = result.address;
        resolved_by_batch = true;
      }
    }
  }

  if (!resolved_by_batch && pointer_verify_is_pointer_ && !pointer_verify_offsets_.empty()) {
    for (size_t i = 0; i < pointer_verify_offsets_.size(); ++i) {
      const int64_t off = pointer_verify_offsets_[i];
      uint64_t read_addr = addr;
      if (off >= 0) {
        const uint64_t uoff = static_cast<uint64_t>(off);
        if (read_addr > UINT64_MAX - uoff) {
          pointer_verify_status_ = u8"偏移导致地址溢出";
          return false;
        }
        read_addr += uoff;
      } else {
        const uint64_t uoff = static_cast<uint64_t>(-off);
        if (read_addr < uoff) {
          pointer_verify_status_ = u8"偏移导致地址溢出";
          return false;
        }
        read_addr -= uoff;
      }

      uint64_t ptr = 0;
      if (!ReadPointerValue(net_, read_addr, pointer_size, flags, &ptr)) {
        pointer_verify_status_ = u8"读取指针失败";
        return false;
      }
      if (!pointer_verify_bench_mode_) {
        char line[256] = {0};
        std::snprintf(line, sizeof(line), "L%zu: %s => %s",
                      i + 1,
                      Hex64(read_addr).c_str(),
                      Hex64(ptr).c_str());
        pointer_verify_lines_.emplace_back(line);
      }
      addr = ptr;
      if (addr == 0) {
        pointer_verify_status_ = u8"指针为空";
        return false;
      }
    }
  } else if (resolved_by_batch && !pointer_verify_bench_mode_) {
    pointer_verify_lines_.emplace_back(std::string("Batch: ") + pointer_verify_expr_ +
                                       " => " + Hex64(addr));
  }

  size_t type_size = 4;
  switch (pointer_verify_type_) {
    case 0: type_size = 1; break;
    case 1: type_size = 2; break;
    case 2: type_size = 4; break;
    case 3: type_size = 8; break;
    case 4: type_size = 4; break;
    case 5: type_size = 8; break;
    default: type_size = 4; break;
  }

  std::vector<uint8_t> data;
  if (!ReadMemoryRangeEx(addr,
                         static_cast<uint32_t>(type_size),
                         &data,
                         pointer_verify_allow_nonresident_,
                         false,
                         pointer_verify_use_pvm_)) {
    pointer_verify_status_ = u8"读取最终值失败";
    return false;
  }
  if (data.size() < type_size) {
    pointer_verify_status_ = u8"读取数据不足";
    return false;
  }

  if (pointer_verify_bench_mode_) {
    pointer_verify_status_ = u8"读取完成";
    return true;
  }

  char value_line[256] = {0};
  switch (pointer_verify_type_) {
    case 0: {
      uint8_t v = 0;
      std::memcpy(&v, data.data(), sizeof(v));
      if (pointer_verify_signed_) {
        const int8_t sv = static_cast<int8_t>(v);
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: %d (0x%02X)", sv, v);
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %d", sv);
        }
      } else {
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: 0x%02X", v);
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %u", v);
        }
      }
      break;
    }
    case 1: {
      uint16_t v = 0;
      std::memcpy(&v, data.data(), sizeof(v));
      if (pointer_verify_signed_) {
        const int16_t sv = static_cast<int16_t>(v);
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: %d (0x%04X)", sv, v);
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %d", sv);
        }
      } else {
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: 0x%04X", v);
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %u", v);
        }
      }
      break;
    }
    case 2: {
      uint32_t v = 0;
      std::memcpy(&v, data.data(), sizeof(v));
      if (pointer_verify_signed_) {
        const int32_t sv = static_cast<int32_t>(v);
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: %d (0x%08X)", sv, v);
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %d", sv);
        }
      } else {
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: 0x%08X", v);
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %u", v);
        }
      }
      break;
    }
    case 3: {
      uint64_t v = 0;
      std::memcpy(&v, data.data(), sizeof(v));
      if (pointer_verify_signed_) {
        const int64_t sv = static_cast<int64_t>(v);
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: %lld (0x%016llX)",
                        static_cast<long long>(sv),
                        static_cast<unsigned long long>(v));
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %lld", static_cast<long long>(sv));
        }
      } else {
        if (pointer_verify_hex_) {
          std::snprintf(value_line, sizeof(value_line), "值: 0x%016llX",
                        static_cast<unsigned long long>(v));
        } else {
          std::snprintf(value_line, sizeof(value_line), "值: %llu",
                        static_cast<unsigned long long>(v));
        }
      }
      break;
    }
    case 4: {
      float v = 0.0f;
      std::memcpy(&v, data.data(), sizeof(v));
      std::snprintf(value_line, sizeof(value_line), "值: %.6f", v);
      break;
    }
    case 5: {
      double v = 0.0;
      std::memcpy(&v, data.data(), sizeof(v));
      std::snprintf(value_line, sizeof(value_line), "值: %.6f", v);
      break;
    }
    default:
      std::snprintf(value_line, sizeof(value_line), "值: (unsupported)");
      break;
  }
  pointer_verify_lines_.emplace_back(std::string("最终地址: ") + Hex64(addr));
  pointer_verify_lines_.emplace_back(value_line);

  (void)verify_maps_hash;
  (void)verify_region_count;
  (void)verify_region_bytes;
  pointer_verify_status_ = std::string(u8"读取完成 snapshot=") + std::to_string(verify_snapshot_id);
  return true;
}

bool ClientUI::ApplyBreakpoints(bool clear_all_first, bool allow_fallback) {
  if (!state_.connected) {
    breakpoint_status_ = u8"未连接";
    return false;
  }
  if (state_.pid == 0) {
    if (!Attach()) {
      breakpoint_status_ = u8"请先打开进程";
      return false;
    }
  }

  auto send_clear_all = [&](uint8_t backend) -> bool {
    protocol::DebugBreakpointRequest req{};
    req.pid = static_cast<uint32_t>(state_.pid);
    req.backend = backend;
    req.type = 0;
    req.size = 0;
    req.flags = protocol::DEBUG_BP_FLAG_CLEAR_ALL;
    req.address = 0;
    protocol::PacketHeader header{};
    std::vector<uint8_t> payload;
    if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_CLR_BP, &req, sizeof(req), &header, &payload)) {
      return false;
    }
    if (payload.size() < sizeof(protocol::StatusResponse)) {
      return false;
    }
    const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
    return resp->code == 0;
  };

  auto send_set = [&](uint8_t backend, const BreakpointEntry& bp) -> bool {
    protocol::DebugBreakpointRequest req{};
    req.pid = static_cast<uint32_t>(state_.pid);
    req.backend = backend;
    req.type = static_cast<uint8_t>(bp.type);
    req.size = static_cast<uint8_t>(bp.size);
    req.flags = breakpoint_stop_on_hit_ ? protocol::DEBUG_BP_FLAG_STOP_ON_HIT : 0;
    req.address = bp.addr;
    protocol::PacketHeader header{};
    std::vector<uint8_t> payload;
    if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_SET_BP, &req, sizeof(req), &header, &payload)) {
      breakpoint_status_ = u8"断点设置失败(通信)";
      return false;
    }
    if (payload.size() < sizeof(protocol::StatusResponse)) {
      breakpoint_status_ = u8"断点设置失败(响应无效)";
      return false;
    }
    const auto* resp = reinterpret_cast<const protocol::StatusResponse*>(payload.data());
    if (resp->code != 0) {
      breakpoint_status_ = u8"断点设置失败(设备拒绝)";
    }
    return resp->code == 0;
  };

  auto apply_backend = [&](uint8_t backend) -> bool {
    if (clear_all_first) {
      send_clear_all(backend);
    }
    breakpoint_no_hit_polls_ = 0;
    for (const auto& bp : breakpoints_) {
      if (!bp.enabled) {
        continue;
      }
      if (backend == protocol::DEBUG_BACKEND_PTRACE &&
          bp.type != static_cast<int>(protocol::DEBUG_BP_EXEC)) {
        breakpoint_status_ = u8"ptrace 断点仅支持执行类型";
        return false;
      }
      if (!send_set(backend, bp)) {
        if (breakpoint_status_.empty()) {
          breakpoint_status_ = u8"断点设置失败";
        }
        return false;
      }
    }
    return true;
  };

  uint8_t backend = breakpoint_backend_ == 0
                      ? protocol::DEBUG_BACKEND_PTRACE
                      : protocol::DEBUG_BACKEND_PERF;
  if (apply_backend(backend)) {
    breakpoint_status_ = u8"断点已应用";
    breakpoint_fallback_used_ = false;
    return true;
  }

  if (allow_fallback && backend == protocol::DEBUG_BACKEND_PERF) {
    breakpoint_status_ = u8"perf 不可用，尝试 ptrace...";
    if (apply_backend(protocol::DEBUG_BACKEND_PTRACE)) {
      breakpoint_backend_ = 0;
      breakpoint_status_ = u8"已切换 ptrace 断点";
      breakpoint_fallback_used_ = true;
      return true;
    }
  }

  return false;
}

bool ClientUI::PollBreakpoints() {
  if (!state_.connected || state_.pid == 0) {
    return false;
  }
  uint64_t prev_hits = 0;
  for (const auto& bp : breakpoints_) {
    prev_hits += bp.hit_count;
  }
  protocol::DebugBreakpointPollRequest req{};
  req.pid = static_cast<uint32_t>(state_.pid);
  req.backend = breakpoint_backend_ == 0
                  ? protocol::DEBUG_BACKEND_PTRACE
                  : protocol::DEBUG_BACKEND_PERF;
  req.flags = 0;
  req.reserved = 0;
  req.max_events = 256;

  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!net_.SendAndReceive(protocol::CommandType::CMD_DEBUG_POLL_BP, &req, sizeof(req), &header, &payload)) {
    return false;
  }
  if (payload.size() < sizeof(protocol::DebugBreakpointPollResponse)) {
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::DebugBreakpointPollResponse*>(payload.data());
  const uint32_t count = resp->count;
  const size_t expected = offsetof(protocol::DebugBreakpointPollResponse, events) +
                          static_cast<size_t>(count) * sizeof(protocol::DebugBreakpointEvent);
  if (payload.size() < expected) {
    return false;
  }
  for (uint32_t i = 0; i < count; ++i) {
    const auto& ev = resp->events[i];
    for (auto& bp : breakpoints_) {
      if (bp.addr == ev.address &&
          bp.type == static_cast<int>(ev.type) &&
          bp.size == static_cast<int>(ev.size)) {
        bp.hit_count += ev.count;
        break;
      }
    }
  }
  uint64_t after_hits = 0;
  for (const auto& bp : breakpoints_) {
    after_hits += bp.hit_count;
  }
  const bool got_hits = after_hits > prev_hits;
  if (breakpoint_backend_ == 1 && breakpoint_auto_fallback_ptrace_) {
    if (got_hits) {
      breakpoint_no_hit_polls_ = 0;
    } else {
      breakpoint_no_hit_polls_++;
    }
    if (breakpoint_no_hit_polls_ >= 5 && !breakpoints_.empty() && !breakpoint_fallback_used_) {
      const int prev_backend = breakpoint_backend_;
      breakpoint_backend_ = 0;
      if (ApplyBreakpoints(true, false)) {
        breakpoint_status_ = u8"perf 无命中，已回退 ptrace";
        breakpoint_fallback_used_ = true;
      } else {
        breakpoint_backend_ = prev_backend;
        breakpoint_status_ = u8"perf 无命中回退 ptrace 失败";
      }
      breakpoint_no_hit_polls_ = 0;
    }
  } else if (breakpoint_backend_ == 0 && breakpoint_auto_fallback_ptrace_) {
    if (got_hits) {
      breakpoint_no_hit_polls_ = 0;
    } else {
      breakpoint_no_hit_polls_++;
    }
    if (breakpoint_no_hit_polls_ >= 5 && !breakpoints_.empty() && !breakpoint_fallback_used_) {
      bool all_exec = true;
      for (const auto& bp : breakpoints_) {
        if (bp.type != static_cast<int>(protocol::DEBUG_BP_EXEC)) {
          all_exec = false;
          break;
        }
      }
      if (all_exec) {
        const int prev_backend = breakpoint_backend_;
        breakpoint_backend_ = 1;
        if (ApplyBreakpoints(true, false)) {
          breakpoint_status_ = u8"ptrace 无命中，已回退 perf";
          breakpoint_fallback_used_ = true;
        } else {
          breakpoint_backend_ = prev_backend;
          breakpoint_status_ = u8"ptrace 无命中回退 perf 失败";
        }
        breakpoint_no_hit_polls_ = 0;
      } else {
        breakpoint_no_hit_polls_ = 0;
      }
    }
  } else {
    breakpoint_no_hit_polls_ = 0;
  }
  return true;
}

bool ClientUI::DisassembleBuffer(uint64_t addr, const std::vector<uint8_t>& code) {
  disasm_lines_.clear();
  disasm_status_.clear();
  disasm_last_decoded_count_ = 0;
  disasm_last_fallback_count_ = 0;
  if (code.empty()) {
    disasm_status_ = u8"无可用数据";
    return false;
  }

  auto append_hex_line = [&](uint64_t line_addr, const uint8_t* bytes, size_t len, bool fallback_tag) {
    char bytes_buf[96] = {0};
    char* cursor = bytes_buf;
    const char* end = bytes_buf + sizeof(bytes_buf);
    for (size_t i = 0; i < len && cursor + 3 < end; ++i) {
      cursor += std::snprintf(cursor,
                              static_cast<size_t>(end - cursor),
                              "%02X ",
                              bytes[i]);
    }
    char line[256] = {0};
    if (fallback_tag) {
      std::snprintf(line, sizeof(line), "0x%llX  %-24s  <HEX>",
                    static_cast<unsigned long long>(line_addr),
                    bytes_buf);
    } else {
      std::snprintf(line, sizeof(line), "0x%llX  %s",
                    static_cast<unsigned long long>(line_addr),
                    bytes_buf);
    }
    disasm_lines_.emplace_back(line);
  };

  if (disasm_view_mode_ == 1) {
    for (size_t i = 0; i < code.size(); i += 16) {
      const size_t line_len = std::min<size_t>(16, code.size() - i);
      append_hex_line(addr + i, code.data() + i, line_len, false);
      disasm_last_fallback_count_++;
    }
    disasm_status_ = std::string(u8"HEX模式，字节=") + std::to_string(code.size()) +
                     u8"，行=" + std::to_string(disasm_last_fallback_count_);
    return true;
  }

  csh handle = 0;
  const bool is_arm64 = (disasm_arch_ == 0);
  cs_arch arch = is_arm64 ? CS_ARCH_AARCH64 : CS_ARCH_ARM;
  cs_mode mode = is_arm64 ? CS_MODE_ARM : (disasm_thumb_ ? CS_MODE_THUMB : CS_MODE_ARM);
  if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
    for (size_t i = 0; i < code.size(); i += 16) {
      const size_t line_len = std::min<size_t>(16, code.size() - i);
      append_hex_line(addr + i, code.data() + i, line_len, true);
      disasm_last_fallback_count_++;
    }
    disasm_status_ = u8"反汇编初始化失败，已自动降级为HEX显示";
    return true;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

  cs_insn* insn = cs_malloc(handle);
  if (!insn) {
    cs_close(&handle);
    for (size_t i = 0; i < code.size(); i += 16) {
      const size_t line_len = std::min<size_t>(16, code.size() - i);
      append_hex_line(addr + i, code.data() + i, line_len, true);
      disasm_last_fallback_count_++;
    }
    disasm_status_ = u8"反汇编资源分配失败，已自动降级为HEX显示";
    return true;
  }

  const uint8_t* cursor = code.data();
  size_t remaining = code.size();
  uint64_t pc = addr;
  disasm_lines_.reserve(code.size() / 2 + 8);
  while (remaining > 0) {
    const uint8_t* before = cursor;
    const size_t before_remaining = remaining;
    const uint64_t before_pc = pc;
    if (cs_disasm_iter(handle, &cursor, &remaining, &pc, insn)) {
      char bytes[64] = {0};
      char* out = bytes;
      const char* end = bytes + sizeof(bytes);
      for (size_t i = 0; i < insn->size && out + 3 < end; ++i) {
        out += std::snprintf(out,
                             static_cast<size_t>(end - out),
                             "%02X ",
                             insn->bytes[i]);
      }
      char line[256] = {0};
      if (insn->op_str[0]) {
        std::snprintf(line, sizeof(line), "0x%llX  %-24s  %s %s",
                      static_cast<unsigned long long>(insn->address),
                      bytes,
                      insn->mnemonic,
                      insn->op_str);
      } else {
        std::snprintf(line, sizeof(line), "0x%llX  %-24s  %s",
                      static_cast<unsigned long long>(insn->address),
                      bytes,
                      insn->mnemonic);
      }
      disasm_lines_.emplace_back(line);
      disasm_last_decoded_count_++;
      continue;
    }

    // 失败时强制回退到 HEX，保证浏览不中断。
    append_hex_line(before_pc, before, 1, true);
    disasm_last_fallback_count_++;
    cursor = before + 1;
    remaining = before_remaining - 1;
    pc = before_pc + 1;
  }

  cs_free(insn, 1);
  cs_close(&handle);
  if (disasm_last_decoded_count_ == 0 && disasm_last_fallback_count_ > 0) {
    disasm_status_ = std::string(u8"未识别汇编，已自动降级HEX显示，字节=") +
                     std::to_string(code.size());
  } else {
    disasm_status_ = std::string(u8"反汇编完成，指令=") +
                     std::to_string(disasm_last_decoded_count_) +
                     u8"，HEX回退=" + std::to_string(disasm_last_fallback_count_);
  }
  return true;
}
