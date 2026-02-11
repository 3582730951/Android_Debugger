#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "NetClient.h"

namespace r3::windows_client_ng::services {

struct ProcessInfo {
  uint32_t pid = 0;
  std::string name;
  bool system_hint_valid = false;
  bool is_system = false;
};

class ClientService {
 public:
  enum class OverrideAction {
    kPass = 0,
    kHandled = 1,
    kError = -1,
  };

  using ReadOverrideHook = std::function<OverrideAction(uint32_t pid,
                                                        uint64_t address,
                                                        uint32_t size,
                                                        bool use_pvm,
                                                        std::vector<uint8_t>* out_data,
                                                        std::string* out_error)>;
  using WriteOverrideHook = std::function<OverrideAction(uint32_t pid,
                                                         uint64_t address,
                                                         const std::vector<uint8_t>& bytes,
                                                         std::string* out_error)>;

  struct AgentCapabilities {
    uint32_t protocol_version = 0;
    uint64_t flags = 0;
    uint32_t max_read_batch = 0;
    uint32_t max_custom_mem = 0;
  };

  struct CustomMemoryProviderConfig {
    bool enabled = false;
    bool allow_fallback = true;
    uint32_t abi_version = 1;
    uint32_t flags = 0;
    uint32_t timeout_ms = 1000;
    int32_t syscall_read = -1;
    int32_t syscall_write = -1;
    std::vector<uint8_t> user_ctx;
    std::string provider_id;
  };

  struct TelemetrySnapshot {
    uint64_t read_calls = 0;
    uint64_t read_ok = 0;
    uint64_t read_custom_hits = 0;
    uint64_t write_calls = 0;
    uint64_t write_ok = 0;
    uint64_t write_custom_hits = 0;
    uint64_t read_time_us = 0;
    uint64_t write_time_us = 0;
  };

  struct ProviderRuntimeSnapshot {
    bool configured_enabled = false;
    bool fused = false;
    uint32_t fail_streak = 0;
    uint32_t fail_threshold = 3;
    uint64_t fallback_count = 0;
    bool last_used_custom = false;
    bool last_fallback = false;
    int32_t last_code = 0;
    int32_t last_sys_errno = 0;
    uint64_t last_elapsed_us = 0;
    uint64_t avg_elapsed_us = 0;
    std::string provider_id;
    std::string last_error;
  };

  struct ReadCompressionRuntime {
    double compressed_bytes_per_ms_ewma = 0.0;
    double raw_bytes_per_ms_ewma = 0.0;
    uint32_t compressed_samples = 0;
    uint32_t raw_samples = 0;
  };

  ClientService() = default;

  bool Connect(const std::string& host, uint16_t port, std::string* out_error);
  void Disconnect();
  bool IsConnected() const;
  bool FetchCapabilities(AgentCapabilities* out_caps, std::string* out_error);
  AgentCapabilities CachedCapabilities() const { return capabilities_cache_; }
  bool HasCapabilities() const { return capabilities_valid_; }

  void SetCustomMemoryProviderConfig(const CustomMemoryProviderConfig& config);
  void SetMemoryOverrideHooks(ReadOverrideHook read_hook, WriteOverrideHook write_hook);
  void ClearMemoryOverrideHooks();
  CustomMemoryProviderConfig GetCustomMemoryProviderConfig() const { return custom_provider_; }
  ProviderRuntimeSnapshot GetProviderRuntimeSnapshot() const { return provider_runtime_; }
  bool ProviderFused() const { return provider_runtime_.fused; }
  void ForceProviderFallback(const std::string& reason);
  void ClearProviderFuse();

  TelemetrySnapshot GetTelemetrySnapshot() const { return telemetry_; }
  void ResetTelemetry();

  bool FetchProcesses(std::vector<ProcessInfo>* out_processes, std::string* out_error);
  bool FetchProcessIcon(uint32_t pid,
                        uint32_t desired_size,
                        std::vector<uint8_t>* out_png,
                        std::string* out_error);
  bool Attach(uint32_t pid, std::string* out_error);
  bool FetchProcInfo(uint8_t* out_arch, uint8_t* out_pointer_size, std::string* out_error);

  bool ScanFirst(protocol::ValueType value_type,
                 protocol::ComparisonType comparison,
                 const std::string& value_text,
                 bool value_hex,
                 uint16_t flags,
                 uint64_t start_addr,
                 uint64_t end_addr,
                 uint64_t* out_total,
                 std::vector<uint64_t>* out_page_addresses,
                 std::string* out_error);
  bool ScanNext(protocol::ValueType value_type,
                protocol::ComparisonType comparison,
                const std::string& value_text,
                bool value_hex,
                uint16_t flags,
                uint64_t start_addr,
                uint64_t end_addr,
                uint64_t* out_total,
                std::vector<uint64_t>* out_page_addresses,
                std::string* out_error);
  bool ScanPage(uint64_t page_index,
                uint32_t page_size,
                uint64_t* out_total,
                std::vector<uint64_t>* out_page_addresses,
                std::string* out_error);

  bool ReadMemory(uint64_t address,
                  uint32_t size,
                  bool use_pvm,
                  std::vector<uint8_t>* out_data,
                  std::string* out_error);
  struct ReadRange {
    uint64_t address = 0;
    uint32_t size = 0;
  };
  bool ReadMemoryBatch(const std::vector<ReadRange>& ranges,
                       uint32_t flags,
                       std::vector<std::vector<uint8_t>>* out_buffers,
                       std::string* out_error);
  bool WriteMemory(uint64_t address,
                   const std::vector<uint8_t>& bytes,
                   std::string* out_error);

  struct RegsSnapshot {
    protocol::RegsArch arch = protocol::RegsArch::UNKNOWN;
    protocol::Arm64Regs arm64{};
    protocol::Arm32Regs arm32{};
  };
  bool FetchRegs(uint32_t pid, RegsSnapshot* out_regs, std::string* out_error);

  bool DebugAttach(uint32_t pid, bool allow_sigstop, std::string* out_error);
  bool DebugDetach(std::string* out_error);
  bool DebugControl(uint32_t pid,
                    protocol::DebugControlAction action,
                    std::string* out_error);
  bool DebugStepIn(uint32_t pid, std::string* out_error);
  bool DebugStepOver(uint32_t pid, std::string* out_error);

  struct BreakpointEvent {
    uint64_t address = 0;
    uint32_t type = 0;
    uint32_t size = 0;
    uint64_t count = 0;
  };
  bool PollBreakpoints(uint32_t pid,
                       protocol::DebugBackend backend,
                       uint8_t flags,
                       uint32_t max_events,
                       std::vector<BreakpointEvent>* out_events,
                       std::string* out_error);

  bool SetBreakpoint(uint32_t pid,
                     protocol::DebugBackend backend,
                     protocol::DebugBpType type,
                     uint8_t size,
                     uint8_t flags,
                     uint64_t address,
                     std::string* out_error);
  bool ClearBreakpoint(uint32_t pid,
                       protocol::DebugBackend backend,
                       protocol::DebugBpType type,
                       uint8_t size,
                       uint8_t flags,
                       uint64_t address,
                       std::string* out_error);

  struct ModuleInfo {
    uint64_t start = 0;
    uint64_t end = 0;
    uint32_t perms = 0;
    std::string path;
  };
  bool FetchModules(uint32_t pid, std::vector<ModuleInfo>* out_modules, std::string* out_error);

  struct PointerIndexBuildResult {
    uint16_t pointer_size = 0;
    uint64_t count = 0;
    bool truncated = false;
  };
  struct PointerIndexEntry {
    uint64_t value = 0;
    uint64_t address = 0;
  };
  struct PointerChain {
    uint64_t base = 0;
    std::vector<int64_t> offsets;
  };

  bool BuildPointerIndex(uint32_t pid,
                         uint16_t pointer_size,
                         uint16_t flags,
                         uint32_t max_entries,
                         PointerIndexBuildResult* out_result,
                         std::string* out_error);
  bool QueryPointerIndex(uint64_t start_index,
                         uint32_t max_count,
                         uint64_t* out_total,
                         std::vector<PointerIndexEntry>* out_entries,
                         std::string* out_error);
  bool ClearPointerIndex(std::string* out_error);
  bool VerifyPointerChains(uint16_t pointer_size,
                           uint16_t depth,
                           uint32_t flags,
                           const std::vector<PointerChain>& chains,
                           size_t start,
                           size_t count,
                           std::vector<protocol::PointerVerifyBatchResult>* out_results,
                           std::string* out_error);
  bool VerifyPointerChainsFilter(uint16_t pointer_size,
                                 uint16_t depth,
                                 uint32_t flags,
                                 const std::vector<PointerChain>& chains,
                                 size_t start,
                                 size_t count,
                                 const std::vector<uint64_t>& targets,
                                 std::vector<uint32_t>* out_matched_indices,
                                 std::string* out_error);
  bool ResolvePointerChain(uint64_t base,
                           const std::vector<uint64_t>& offsets,
                           uint32_t pointer_size,
                           uint64_t* out_address,
                           std::string* out_error);

 private:
  bool BuildValueBytes(protocol::ValueType value_type,
                       const std::string& text,
                       bool value_hex,
                       std::vector<uint8_t>* out_bytes,
                       std::string* out_error) const;
  bool ScanImpl(protocol::CommandType cmd,
                protocol::ValueType value_type,
                protocol::ComparisonType comparison,
                const std::string& value_text,
                bool value_hex,
                uint16_t flags,
                uint64_t start_addr,
                uint64_t end_addr,
                uint64_t* out_total,
                std::vector<uint64_t>* out_page_addresses,
                std::string* out_error);
  bool ReadMemoryViaCustomProvider(uint64_t address,
                                   uint32_t size,
                                   bool use_pvm,
                                   std::vector<uint8_t>* out_data,
                                   std::string* out_error);
  bool WriteMemoryViaCustomProvider(uint64_t address,
                                    const std::vector<uint8_t>& bytes,
                                    std::string* out_error);
  bool ShouldDisableReadResponseCompression(uint32_t expected_bytes, uint32_t request_flags) const;
  void UpdateReadCompressionRuntime(const NetClient::ExchangeStats& exchange);
  static std::string CustomMemCodeText(int32_t code);
  void RecordProviderSuccess(bool used_custom, uint64_t elapsed_us);
  void RecordProviderFailure(const std::string& error, int32_t code, int32_t sys_errno);

  NetClient net_;
  ReadOverrideHook read_override_hook_{};
  WriteOverrideHook write_override_hook_{};
  AgentCapabilities capabilities_cache_{};
  bool capabilities_valid_ = false;
  CustomMemoryProviderConfig custom_provider_{};
  ProviderRuntimeSnapshot provider_runtime_{};
  ReadCompressionRuntime read_compression_runtime_{};
  TelemetrySnapshot telemetry_{};
  uint64_t trace_seq_ = 1;
  uint32_t attached_pid_ = 0;
};

}  // namespace r3::windows_client_ng::services
