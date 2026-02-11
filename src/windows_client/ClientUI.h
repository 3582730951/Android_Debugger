#pragma once

#include "ClientState.h"
#include "NetClient.h"

#include <chrono>
#include <unordered_map>

class ClientUI {
 public:
  struct PointerBenchResult {
    int depth = 0;
    double seconds = 0.0;
    uint64_t iterations = 0;
    uint64_t chains = 0;
    double ops_per_sec = 0.0;
    double connect_ms = 0.0;
    double attach_ms = 0.0;
    double scan_ms = 0.0;
    double verify_ms = 0.0;
    uint64_t net_packets = 0;
    uint64_t net_req_bytes = 0;
    uint64_t net_rsp_bytes = 0;
    uint64_t read_calls = 0;
    uint64_t read_bytes = 0;
    double avg_chunk_bytes = 0.0;
    bool use_index = false;
    bool strict_mode = true;
    std::string file;
    std::string status;
  };

  explicit ClientUI(bool auto_mode = false);
  void SetServer(const char* host, int port);
  void SetSvgAtlasTexture(void* texture_id);
  void SetSvgAtlasIconUv(const char* id, float u0, float v0, float u1, float v1);
  void Render();
  bool RequestQuit() const { return request_quit_; }
  bool RunPointerScanBench(int seconds,
                           int depth,
                           const std::string& out_file,
                           PointerBenchResult* out,
                           bool use_index = false,
                           bool strict_mode = true);
  bool RunPointerCompareBench(int seconds,
                              int depth,
                              const std::string& file_a,
                              const std::string& file_b,
                              PointerBenchResult* out);
  bool RunPointerVerifyBench(int seconds,
                             const std::string& file,
                             PointerBenchResult* out);

 private:
  struct DataTraverseEntry;

  bool ConnectToServer();
  void DisconnectFromServer();
  bool Attach();
  bool ScanFirst();
  bool ScanNext();
  bool ScanPage();
  void RefreshScanPreviewValues();
  bool ReadMemory();
  bool ReadMemoryRange(uint64_t addr, uint32_t size, std::vector<uint8_t>* out, bool allow_nonresident);
  bool WriteMemory();
  bool FetchProcesses();
  bool FetchProcInfo();
  bool FetchModules();
  bool FetchRegs();
  bool DebugAttach(bool allow_sigstop = false);
  bool DebugDetach();
  void RenderDisasmWindow();
  void RenderMemoryViewWindow();
  void RenderDisasmPanel();
  void RenderPointerScanWindow();
  void RenderPointerCompareWindow();
  void RenderDataTraverseWindow();
  void RenderDataTraversePanel();
  void RenderPointerVerifyWindow();
  void RenderPointerVerifyPanel();
  void RenderDebuggerWindow();
  void RenderTestWindow();
  void RenderMemoryViewPanel();
  void OpenMemoryWorkspaceAt(uint64_t addr, bool read_memory, bool open_disasm);
  uint64_t GetProgramCounterAddress() const;
  bool RunPointerScan();
  bool RunPointerCompare();
  bool RunDataTraverse();
  bool RunPointerVerify();
  bool RunDisasm(uint64_t addr);
  bool BuildPointerIndexFromAgent(uint32_t pointer_size, std::string* out_error);
  bool DisassembleBuffer(uint64_t addr, const std::vector<uint8_t>& code);
  bool DrawSvgButton(const char* icon_id, const char* label);
  bool ApplyBreakpoints(bool clear_all_first, bool allow_fallback = true);
  bool PollBreakpoints();
  static std::string PermsToString(uint32_t perms);
  static bool IsModuleVisible(int category, const ClientState::ModuleInfo& mod);
  static std::string ModuleTypeTag(const ClientState::ModuleInfo& mod);
  uint64_t ResolveExecStart(const ClientState::ModuleInfo& mod) const;
  const ClientState::ModuleInfo* FindModuleForAddress(uint64_t addr) const;
  bool IsReadableAddress(uint64_t addr,
                         uint64_t size,
                         const ClientState::ModuleInfo** out_mod) const;
  uint64_t ComputeAppBaseHigh() const;
  void UpdateAppBaseHigh();
  void SyncPointerModuleSelection();
  void SyncPointerPreviewSelection();
  void RenderPointerTreeNode(uint64_t addr,
                             uint32_t pointer_size,
                             uint32_t flags,
                             int depth,
                             int max_depth);
  bool BuildTraverseEntries(uint64_t base,
                            int count,
                            int stride,
                            int type,
                            bool use_pvm,
                            std::vector<DataTraverseEntry>* out,
                            std::string* out_status);
  void RenderTraverseEntries(const std::vector<DataTraverseEntry>& entries,
                             int depth);
  void TouchTraverseCache(uint64_t base);
  void PruneTraverseCache();

  void StartAutoTest();
  void RunAutoTest();
  void AutoLog(const std::string& line);
  void AddAddressEntry(uint64_t addr, protocol::ValueType type, const char* desc);
  void RefreshAddressListValues(bool force);
  bool WriteMemoryBytes(uint64_t addr, const std::vector<uint8_t>& bytes);
  bool LoadAutoTargets();

  bool BuildValueBytes(std::vector<uint8_t>* out) const;
  uint64_t ParseAddress(const std::string& text) const;
  bool ParseHexBytes(const char* text, std::vector<uint8_t>* out) const;
  uint64_t ParseAddressWithBase(const std::string& text, bool force_hex) const;
  bool ReadMemoryRangeEx(uint64_t addr,
                         uint32_t size,
                         std::vector<uint8_t>* out,
                         bool allow_nonresident,
                         bool ignore_perms,
                         bool use_pvm);

  uint32_t GetPointerSizeFromModules() const;
  bool LoadPointerPreview(const std::string& path,
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
                          std::string* out_error);

  NetClient net_;
  ClientState state_;

  char host_[64];
  int port_;
  char pid_input_[16];
  char value_input_[64];
  char scan_start_[32];
  char scan_end_[32];
  bool scan_use_pvm_ = false;
  bool scan_allow_nonresident_ = false;
  bool scan_strict_ = true;
  bool scan_freeze_ = true;
  char mem_addr_[32];
  int mem_size_;
  char write_addr_[32];
  char write_data_[256];
  int read_format_ = 0;
  int write_format_ = 0;
  bool read_use_length_override_ = false;
  bool read_use_pvm_ = false;
  std::string read_value_text_;
  std::string read_value_text_utf16_;
  struct SvgIconUv {
    float u0 = 0.0f;
    float v0 = 0.0f;
    float u1 = 1.0f;
    float v1 = 1.0f;
  };
  void* svg_atlas_texture_ = nullptr;
  std::unordered_map<std::string, SvgIconUv> svg_icon_uvs_;

  char process_filter_[64];
  char module_filter_[128];
  int module_category_ = 0;
  int selected_module_index_ = -1;

  bool show_debug_window_ = false;
  bool show_memory_window_ = false;
  bool show_pointer_scan_window_ = false;
  bool show_pointer_compare_window_ = false;
  bool show_pointer_verify_window_ = false;
  bool show_debugger_window_ = false;
  bool show_test_window_ = false;
  bool show_command_palette_ = false;
  int right_tab_request_ = -1;
  char command_filter_[64];
  char disasm_addr_[32];
  char disasm_jump_addr_[32];
  int disasm_size_ = 64;
  int disasm_arch_ = 0;
  bool disasm_thumb_ = false;
  bool disasm_allow_nonresident_ = false;
  bool disasm_ignore_perms_ = false;
  bool disasm_use_pvm_ = false;
  bool disasm_auto_arch_ = true;
  bool disasm_continuous_mode_ = true;
  bool disasm_follow_pc_ = false;
  bool disasm_sync_memory_ = true;
  int disasm_view_mode_ = 0;
  int disasm_scroll_step_ = 32;
  int disasm_page_step_ = 256;
  uint64_t disasm_follow_last_ms_ = 0;
  uint32_t disasm_last_decoded_count_ = 0;
  uint32_t disasm_last_fallback_count_ = 0;
  std::string disasm_status_;
  std::vector<std::string> disasm_lines_;
  std::vector<uint64_t> disasm_bookmarks_;
  int disasm_bookmark_selected_ = -1;

  char pointer_scan_target_[256];
  int pointer_scan_depth_ = 3;
  int pointer_scan_max_offset_ = 4096;
  bool pointer_scan_use_modules_ = false;
  bool pointer_scan_use_pvm_ = true;
  bool pointer_scan_allow_nonresident_ = false;
  bool pointer_scan_freeze_ = false;
  bool pointer_scan_byte_step_ = false;
  bool pointer_scan_use_index_ = false;
  int pointer_scan_thread_count_ = 0;
  char pointer_scan_index_path_[260];
  std::vector<std::pair<uint64_t, uint64_t>> pointer_index_entries_;
  uint32_t pointer_index_pointer_size_ = 0;
  uint32_t pointer_index_pid_ = 0;
  uint64_t pointer_index_flags_ = 0;
  std::string pointer_index_status_;
  bool pointer_scan_select_popup_ = false;
  char pointer_scan_module_search_[64];
  std::vector<bool> pointer_scan_module_selected_;
  uint64_t pointer_scan_count_ = 0;
  std::string pointer_scan_status_;
  std::string pointer_scan_output_path_;

  uint64_t pointer_preview_page_index_ = 0;
  uint32_t pointer_preview_page_size_ = 64;
  int pointer_preview_min_offset_ = 0;
  int pointer_preview_max_offset_ = 4096;
  bool pointer_preview_use_modules_ = false;
  bool pointer_preview_select_popup_ = false;
  bool pointer_preview_use_category_ = false;
  int pointer_preview_category_ = 0;
  char pointer_preview_module_keyword_[64];
  char pointer_preview_module_search_[64];
  std::vector<bool> pointer_preview_module_selected_;
  std::vector<std::string> pointer_preview_items_;
  uint64_t pointer_preview_total_ = 0;
  std::string pointer_preview_status_;
  struct PointerPreviewCache {
    bool valid = false;
    std::string path;
    uint64_t start_index = 0;
    uint32_t page_size = 0;
    int64_t min_offset = 0;
    int64_t max_offset = 0;
    bool use_modules = false;
    uint64_t module_mask_hash = 0;
    bool use_category = false;
    int category = 0;
    std::string module_keyword;
    std::vector<std::string> items;
    uint64_t total = 0;
  };
  PointerPreviewCache pointer_preview_cache_;

  std::string pointer_compare_file_a_;
  std::string pointer_compare_file_b_;
  bool pointer_compare_multi_mode_ = false;
  bool pointer_compare_fast_mode_ = true;
  std::vector<std::string> pointer_compare_files_;
  bool pointer_compare_use_pvm_ = true;
  bool pointer_compare_allow_nonresident_ = false;
  bool pointer_compare_bench_mode_ = false;
  uint64_t pointer_compare_count_ = 0;
  std::string pointer_compare_status_;
  std::string pointer_compare_output_path_;
  std::string pointer_compare_export_path_;
  uint64_t pointer_compare_preview_page_index_ = 0;
  uint32_t pointer_compare_preview_page_size_ = 64;
  std::vector<std::string> pointer_compare_preview_items_;
  uint64_t pointer_compare_preview_total_ = 0;
  std::string pointer_compare_preview_status_;

  bool show_data_traverse_window_ = false;
  char data_traverse_addr_[32];
  int data_traverse_count_ = 64;
  int data_traverse_stride_ = 4;
  int data_traverse_type_ = 2;
  bool data_traverse_use_pvm_ = true;
  struct DataTraverseEntry {
    uint64_t addr = 0;
    uint64_t value_u = 0;
    uint64_t pointer_value = 0;
    uint64_t pointer_resolved = 0;
    bool pointer_valid = false;
    bool pointer_checked = false;
    int pointer_score = 0;
    bool pointer_candidate = false;
    int override_type = -1;
    uint64_t override_value = 0;
    uint8_t override_size = 0;
    bool override_valid = false;
    std::string text;
    uint64_t raw_value = 0;
    uint8_t raw_size = 0;
  };
  std::vector<DataTraverseEntry> data_traverse_entries_;
  std::unordered_map<uint64_t, DataTraverseEntry> data_traverse_node_overrides_;
  struct TraverseNodeCache {
    uint64_t base = 0;
    int count = 0;
    int stride = 0;
    int type = 0;
    bool use_pvm = false;
    std::vector<DataTraverseEntry> entries;
    std::string status;
  };
  std::unordered_map<uint64_t, TraverseNodeCache> data_traverse_child_cache_;
  std::vector<uint64_t> data_traverse_cache_lru_;
  size_t data_traverse_cache_limit_ = 32;
  int data_traverse_pointer_threshold_ = 4;
  bool data_traverse_auto_pointer_ = true;
  bool data_traverse_light_mode_ = false;
  std::string data_traverse_status_;

  bool address_default_hex_ = true;
  bool ui_layout_inited_ = false;
  uint64_t app_base_high_ = 0;

  char pointer_verify_addr_[32];
  char pointer_verify_desc_[64];
  int pointer_verify_type_ = 2;
  bool pointer_verify_hex_ = true;
  bool pointer_verify_signed_ = false;
  bool pointer_verify_is_pointer_ = true;
  bool pointer_verify_use_pvm_ = true;
  bool pointer_verify_allow_nonresident_ = false;
  bool pointer_verify_bench_mode_ = false;
  char pointer_verify_offset_input_[32];
  std::vector<int64_t> pointer_verify_offsets_;
  std::string pointer_verify_status_;
  std::string pointer_verify_expr_;
  std::vector<std::string> pointer_verify_lines_;

  struct BreakpointEntry {
    uint64_t addr = 0;
    int type = 0;
    int size = 4;
    bool enabled = true;
    uint64_t hit_count = 0;
  };
  char breakpoint_addr_[32];
  int breakpoint_type_ = 0;
  int breakpoint_size_ = 4;
  int breakpoint_selected_ = -1;
  std::vector<BreakpointEntry> breakpoints_;
  std::string breakpoint_status_;
  int breakpoint_backend_ = 1; // 0=ptrace,1=perf
  bool breakpoint_stop_on_hit_ = false;
  bool breakpoint_monitoring_ = false;
  uint64_t breakpoint_last_poll_ms_ = 0;
  bool breakpoint_auto_fallback_ptrace_ = false;
  bool breakpoint_fallback_used_ = false;
  int breakpoint_no_hit_polls_ = 0;
  bool debug_attach_allow_sigstop_ = false;

  struct AddressEntry {
    bool active = true;
    uint64_t addr = 0;
    protocol::ValueType type = protocol::ValueType::U32;
    char desc[64] = {};
    char value_input[64] = {};
    std::string value_display;
    bool value_dirty = false;
    bool freeze_has_value = false;
    std::vector<uint8_t> freeze_bytes;
    std::vector<uint8_t> last_read_bytes;
    bool freeze_failed = false;
    std::string freeze_error;
  };
  std::vector<AddressEntry> address_list_;
  int address_list_selected_ = -1;
  bool address_list_auto_refresh_ = true;
  bool address_list_use_pvm_ = true;
  std::string address_list_status_;
  char address_add_addr_[32];
  char address_add_desc_[64];
  int address_add_type_index_ = 2;
  bool show_process_popup_ = false;
  bool show_module_popup_ = false;
  bool show_add_address_popup_ = false;
  bool show_scan_advanced_popup_ = false;
  uint64_t address_list_last_refresh_ms_ = 0;
  uint64_t address_list_last_freeze_ms_ = 0;
  int address_list_refresh_interval_ms_ = 500;
  int address_list_freeze_interval_ms_ = 100;
  bool address_list_hex_ = false;

  bool auto_mode_ = false;
  bool auto_running_ = false;
  bool auto_done_ = false;
  bool request_quit_ = false;
  int auto_step_ = 0;
  int auto_retry_ = 0;
  uint64_t auto_target_addr_ = 0;
  uint32_t auto_original_value_ = 0;
  bool auto_have_original_ = false;
  uint64_t auto_rw_region_ = 0;
  uint64_t auto_perf_write_addr_ = 0;
  uint32_t auto_perf_original_value_ = 0;
  bool auto_perf_has_original_ = false;
  bool auto_perf_write_done_ = false;
  uint64_t auto_ptr3_value_addr_ = 0;
  uint64_t auto_ptr5_value_addr_ = 0;
  uint64_t auto_ptr7_value_addr_ = 0;
  uint64_t auto_ptr10_value_addr_ = 0;
  uint64_t auto_ptr_exec_addr_ = 0;
  bool auto_ptrace_fallback_used_ = false;
  std::string auto_ptr_file_a_;
  std::string auto_ptr_file_b_;
  std::vector<std::string> auto_logs_;
  std::string auto_log_path_;

  std::vector<std::string> scan_preview_values_;
};
