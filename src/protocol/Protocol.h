#pragma once

#include <cstddef>
#include <cstdint>

namespace protocol {

static constexpr uint32_t kMagic = 0x52444441u; // 'RDDA'

enum class CommandType : uint16_t {
  CMD_PING = 0x0001,
  CMD_ATTACH = 0x0002,
  CMD_SCAN_FIRST = 0x0003,
  CMD_SCAN_NEXT = 0x0004,
  CMD_READ_MEM = 0x0005,
  CMD_WRITE_MEM = 0x0006,
  CMD_GET_POINTER_CHAIN = 0x0007,
  CMD_SCAN_PAGE = 0x0008,
  CMD_LIST_PROCESSES = 0x0009,
  CMD_GET_REGS = 0x000A,
  CMD_DEBUG_ATTACH = 0x000B,
  CMD_DEBUG_DETACH = 0x000C,
  CMD_LIST_MODULES = 0x000D,
  CMD_GET_PROC_INFO = 0x000E,
  CMD_PTR_INDEX_BUILD = 0x000F,
  CMD_PTR_INDEX_QUERY = 0x0010,
  CMD_PTR_INDEX_CLEAR = 0x0011,
  CMD_PTR_VERIFY_BATCH = 0x0012,
  CMD_DEBUG_SET_BP = 0x0013,
  CMD_DEBUG_CLR_BP = 0x0014,
  CMD_DEBUG_POLL_BP = 0x0015,
  CMD_READ_MEM_BATCH = 0x0016,
  CMD_PTR_VERIFY_BATCH_V2 = 0x0017,
  CMD_GET_PROCESS_ICON = 0x0018,
  CMD_DEBUG_CONTROL = 0x0019,
  CMD_GET_CAPS = 0x001A,
  CMD_CUSTOM_MEM_OP = 0x001B,
};

enum class ValueType : uint8_t {
  U8 = 0,
  U16 = 1,
  U32 = 2,
  U64 = 3,
  FLOAT = 4,
  DOUBLE = 5,
  S32 = 6,
  S64 = 7,
  STRING = 8,
  AOB = 9,
  BINARY = 10,
  ALL = 11,
};

enum class ComparisonType : uint8_t {
  EQ = 0,
  NE = 1,
  GT = 2,
  LT = 3,
  GE = 4,
  LE = 5,
  CHANGED = 6,
  UNCHANGED = 7,
};

enum class RegsArch : uint8_t {
  UNKNOWN = 0,
  ARM64 = 1,
  ARM32 = 2,
};

enum ScanFlags : uint16_t {
  SCAN_FLAG_USE_PVM = 1u << 0,
  SCAN_FLAG_ALLOW_NONRESIDENT = 1u << 1,
  SCAN_FLAG_BYTE_STEP = 1u << 2,
  SCAN_FLAG_STRICT = 1u << 3,
  SCAN_FLAG_REQUIRE_WRITABLE = 1u << 4,
  SCAN_FLAG_REQUIRE_EXEC = 1u << 5,
  SCAN_FLAG_REQUIRE_PRIVATE = 1u << 6,
  SCAN_FLAG_REQUIRE_IMAGE = 1u << 7,
  SCAN_FLAG_REQUIRE_MAPPED = 1u << 8,
  SCAN_FLAG_GG_SHIFT = 9,
  SCAN_FLAG_GG_MASK = static_cast<uint16_t>(0x1Fu << SCAN_FLAG_GG_SHIFT),
};

enum GgRegionCode : uint8_t {
  GG_REGION_NONE = 0,
  GG_REGION_XA = 1,
  GG_REGION_A = 2,
  GG_REGION_O = 3,
  GG_REGION_BSS = 4,
  GG_REGION_JH = 5,
  GG_REGION_CH = 6,
  GG_REGION_CA = 7,
  GG_REGION_PS = 8,
  GG_REGION_J = 9,
  GG_REGION_S = 10,
  GG_REGION_AS = 11,
  GG_REGION_V = 12,
  GG_REGION_XS = 13,
};

enum ReadMemFlags : uint32_t {
  READ_FLAG_ALLOW_NONRESIDENT = 1u << 0,
  READ_FLAG_IGNORE_PERMS = 1u << 1,
  READ_FLAG_USE_PVM = 1u << 2,
  READ_FLAG_NO_COMPRESS = 1u << 3,
};

enum PtrVerifyBatchFlags : uint32_t {
  PTR_VERIFY_BATCH_FLAG_TARGET_FILTER = 1u << 16,
};

enum PtrIndexFlags : uint16_t {
  PTR_INDEX_FLAG_USE_PVM = 1u << 0,
  PTR_INDEX_FLAG_ALLOW_NONRESIDENT = 1u << 1,
  PTR_INDEX_FLAG_BYTE_STEP = 1u << 2,
  PTR_INDEX_FLAG_STRICT = 1u << 3,
};

enum PacketFlags : uint16_t {
  PACKET_FLAG_COMPRESSED = 1u << 0,
};

enum CompressionType : uint16_t {
  COMPRESS_NONE = 0,
  COMPRESS_RLE0 = 1,
  COMPRESS_LZ4 = 2,
};

enum DebugBackend : uint8_t {
  DEBUG_BACKEND_PTRACE = 0,
  DEBUG_BACKEND_PERF = 1,
};

constexpr uint32_t DEBUG_ATTACH_FLAG_ALLOW_SIGSTOP = 1u << 0;

enum DebugBpType : uint8_t {
  DEBUG_BP_EXEC = 0,
  DEBUG_BP_WRITE = 1,
  DEBUG_BP_READ = 2,
  DEBUG_BP_READWRITE = 3,
};

enum DebugBpFlags : uint8_t {
  DEBUG_BP_FLAG_CLEAR_ALL = 1u << 0,
  DEBUG_BP_FLAG_STOP_ON_HIT = 1u << 1,
};

enum DebugControlAction : uint8_t {
  DEBUG_CTRL_CONTINUE = 0,
  DEBUG_CTRL_STEP_IN = 1,
  DEBUG_CTRL_STEP_OVER = 2,
};

enum ModulePerms : uint32_t {
  MODULE_PERM_READ = 1u << 0,
  MODULE_PERM_WRITE = 1u << 1,
  MODULE_PERM_EXEC = 1u << 2,
  MODULE_PERM_PRIVATE = 1u << 3,
  MODULE_PERM_SHARED = 1u << 4,
};

enum AgentCapabilityFlags : uint64_t {
  AGENT_CAP_DEBUG_BP = 1ull << 0,
  AGENT_CAP_DEBUG_CONTROL_STEP = 1ull << 1,
  AGENT_CAP_READ_MEM_BATCH = 1ull << 2,
  AGENT_CAP_POINTER_INDEX = 1ull << 3,
  AGENT_CAP_CUSTOM_MEM_OP = 1ull << 4,
  AGENT_CAP_PLUGIN_MEM_PROVIDER = 1ull << 5,
};

enum CustomMemOpType : uint32_t {
  CUSTOM_MEM_OP_READ = 1u,
  CUSTOM_MEM_OP_WRITE = 2u,
};

enum CustomMemOpFlags : uint32_t {
  CUSTOM_MEM_FLAG_ALLOW_FALLBACK = 1u << 0,
  CUSTOM_MEM_FLAG_USE_PVM = 1u << 1,
};

#pragma pack(push, 1)
struct PacketHeader {
  uint32_t magic;
  uint16_t command;
  uint16_t reserved;
  uint32_t data_size;
};

struct CompressedPayloadHeader {
  uint32_t raw_size;
  uint16_t algorithm;
  uint16_t reserved;
  uint8_t data[1];
};

struct ScanRequest {
  uint8_t value_type;
  uint8_t comparison_type;
  uint16_t reserved;
  uint64_t start_addr;
  uint64_t end_addr;
  uint32_t value_len;
  uint8_t data[1];
};

struct ScanResult {
  uint64_t count;
  uint64_t addresses[1];
};

struct ScanPageRequest {
  uint64_t start_index;
  uint32_t max_count;
  uint32_t reserved;
};

struct ProcessListRequest {
  uint32_t max_count;
  uint32_t reserved;
};

struct ProcessListHeader {
  uint32_t count;
  uint32_t reserved;
};

struct ProcessEntry {
  uint32_t pid;
  uint16_t name_len;
  uint16_t reserved;  // ProcessEntryFlags
  uint8_t name[1];
};

struct ProcessIconRequest {
  uint32_t pid;
  uint32_t desired_size;
};

enum ProcessIconFormat : uint16_t {
  PROCESS_ICON_FMT_NONE = 0,
  PROCESS_ICON_FMT_PNG = 1,
};

enum ProcessEntryFlags : uint16_t {
  PROCESS_ENTRY_FLAG_SYSTEM = 1u << 0,
  PROCESS_ENTRY_FLAG_CLASSIFIED = 1u << 1,
};

struct ProcessIconResponse {
  int32_t code;
  uint32_t bytes;
  uint16_t format;
  uint16_t reserved;
  uint8_t data[1];
};

struct ModuleListRequest {
  uint32_t pid;
  uint32_t reserved;
};

struct ModuleListHeader {
  uint32_t count;
  uint32_t reserved;
};

struct ModuleEntry {
  uint64_t start;
  uint64_t end;
  uint32_t perms;
  uint32_t path_len;
  uint8_t path[1];
};

struct AttachRequest {
  uint32_t pid;
  uint32_t reserved;
};

struct StatusResponse {
  int32_t code;
  uint32_t reserved;
};

struct ReadMemRequest {
  uint64_t address;
  uint32_t size;
  uint32_t reserved;
};

struct ReadMemResponse {
  int32_t code;
  uint32_t bytes_read;
  uint8_t data[1];
};

struct ReadMemBatchRange {
  uint64_t address;
  uint32_t size;
  uint32_t reserved;
};

struct ReadMemBatchRequest {
  uint32_t count;
  uint32_t flags;
  ReadMemBatchRange ranges[1];
};

struct ReadMemBatchResult {
  int32_t code;
  uint32_t bytes_read;
};

struct ReadMemBatchResponse {
  uint32_t count;
  uint32_t reserved;
  ReadMemBatchResult results[1];
};

struct WriteMemRequest {
  uint64_t address;
  uint32_t size;
  uint32_t reserved;
  uint8_t data[1];
};

struct WriteMemResponse {
  int32_t code;
  uint32_t bytes_written;
};

struct GetRegsRequest {
  uint32_t pid;
  uint32_t reserved;
};

struct Arm64Regs {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
};

struct Arm32Regs {
  uint32_t regs[16];
  uint32_t cpsr;
  uint32_t orig_r0;
};

struct GetRegsResponse {
  int32_t code;
  uint8_t arch;
  uint8_t reserved[3];
  union {
    Arm64Regs arm64;
    Arm32Regs arm32;
  } regs;
};

struct DebugAttachRequest {
  uint32_t pid;
  uint32_t reserved;
};

struct AgentCapabilitiesRequest {
  uint32_t abi_version;
  uint32_t reserved;
};

struct AgentCapabilitiesResponse {
  int32_t code;
  uint32_t protocol_version;
  uint64_t capability_flags;
  uint32_t max_read_batch;
  uint32_t max_custom_mem;
  uint32_t reserved0;
  uint32_t reserved1;
};

struct DebugControlRequest {
  uint32_t pid;
  uint8_t action;
  uint8_t reserved0;
  uint16_t reserved1;
};

struct CustomMemOpRequest {
  uint32_t pid;
  uint32_t abi_version;
  uint32_t op;
  uint32_t flags;
  uint64_t address;
  uint32_t size;
  uint32_t timeout_ms;
  uint64_t trace_id;
  int32_t syscall_read;
  int32_t syscall_write;
  uint32_t user_ctx_len;
  uint32_t write_data_len;
  uint8_t payload[1]; // user_ctx + write_data
};

struct CustomMemOpResponse {
  int32_t code;
  int32_t provider_errno;
  int32_t sys_errno;
  uint32_t bytes_done;
  uint64_t elapsed_us;
  uint64_t trace_id;
  uint32_t read_data_len;
  uint32_t reserved;
  uint8_t data[1];
};

struct DebugBreakpointRequest {
  uint32_t pid;
  uint8_t backend;
  uint8_t type;
  uint8_t size;
  uint8_t flags;
  uint64_t address;
};

struct DebugBreakpointPollRequest {
  uint32_t pid;
  uint8_t backend;
  uint8_t flags;
  uint16_t reserved;
  uint32_t max_events;
};

struct DebugBreakpointEvent {
  uint64_t address;
  uint32_t type;
  uint32_t size;
  uint64_t count;
};

struct DebugBreakpointPollResponse {
  uint32_t count;
  uint32_t reserved;
  DebugBreakpointEvent events[1];
};

struct ProcInfoRequest {
  uint32_t pid;
  uint32_t reserved;
};

struct ProcInfoResponse {
  int32_t code;
  uint8_t arch;
  uint8_t pointer_size;
  uint8_t reserved[2];
};

struct PointerChainRequest {
  uint64_t base;
  uint32_t count;
  uint32_t pointer_size;
  uint64_t offsets[1];
};

struct PointerChainResponse {
  int32_t code;
  uint32_t reserved;
  uint64_t address;
};

struct PointerIndexBuildRequest {
  uint32_t pid;
  uint16_t pointer_size;
  uint16_t flags;
  uint32_t max_entries;
  uint32_t reserved;
};

struct PointerIndexBuildResponse {
  int32_t code;
  uint16_t pointer_size;
  uint16_t reserved;
  uint64_t count;
  uint32_t truncated;
  uint32_t reserved2;
};

struct PointerIndexQueryRequest {
  uint64_t start_index;
  uint32_t max_count;
  uint32_t reserved;
};

struct PointerIndexEntry {
  uint64_t value;
  uint64_t address;
};

struct PointerIndexQueryResponse {
  uint64_t total;
  uint32_t returned;
  uint32_t reserved;
  PointerIndexEntry entries[1];
};

struct PointerVerifyBatchRequest {
  uint32_t count;
  uint16_t pointer_size;
  uint16_t depth;
  uint32_t flags;
  uint32_t reserved;
  uint64_t bases[1];
};

struct PointerVerifyBatchResult {
  int32_t code;
  uint32_t reserved;
  uint64_t address;
};

struct PointerVerifyBatchResponse {
  uint32_t count;
  uint32_t reserved;
  PointerVerifyBatchResult results[1];
};

struct PointerVerifyBatchV2Request {
  uint32_t count;
  uint16_t pointer_size;
  uint16_t depth;
  uint32_t flags;
  uint32_t target_count;
  uint32_t reserved;
  uint64_t bases[1];
};

struct PointerVerifyBatchV2Response {
  uint32_t count;
  uint32_t matched_count;
  uint32_t reserved;
  uint32_t reserved2;
  uint32_t matched_indices[1];
};
#pragma pack(pop)

} // namespace protocol
