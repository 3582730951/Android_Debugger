#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include "app/UiState.h"
#include "services/ClientService.h"

namespace r3::windows_client_ng::ui {

class PointerToolsWindow {
 public:
  PointerToolsWindow();
  ~PointerToolsWindow();

  bool Create(HINSTANCE instance, HWND owner, services::ClientService* service, app::UiState* state);
  void ShowPointerSearch();
  void ShowPointerCompare();
  void ShowDataTraverse();

 private:
  enum class Mode {
    PointerSearch = 0,
    PointerCompare,
    DataTraverse,
  };

  struct TraverseRow {
    uint64_t id = 0;
    uint64_t parent_id = 0;
    int level = 0;
    int64_t offset = 0;
    uint64_t addr = 0;
    protocol::ValueType value_type = protocol::ValueType::U32;
    bool pointer_candidate = false;
    bool expanded = false;
    bool children_loaded = false;
    uint64_t pointer_value = 0;
    std::wstring type_label;
    std::wstring value_label;
    std::wstring note_label;
    std::vector<uint64_t> child_ids;
  };

  struct ToolWindow {
    PointerToolsWindow* owner = nullptr;
    Mode mode = Mode::PointerSearch;
    HWND hwnd = nullptr;
    HFONT font = nullptr;
    HBRUSH bg_brush = nullptr;
    UINT dpi = 96;
    float scale = 1.0f;

    HWND edit_a = nullptr;
    HWND edit_b = nullptr;
    HWND label_a = nullptr;
    HWND label_b = nullptr;
    HWND label_depth = nullptr;
    HWND label_max_offset = nullptr;
    HWND label_max_results = nullptr;
    HWND label_pointer_size = nullptr;
    HWND label_max_entries = nullptr;
    HWND label_type = nullptr;
    HWND label_count = nullptr;
    HWND label_stride = nullptr;
    HWND label_output = nullptr;
    HWND edit_depth = nullptr;
    HWND edit_max_offset = nullptr;
    HWND edit_max_results = nullptr;
    HWND edit_max_entries = nullptr;
    HWND edit_stride = nullptr;
    HWND edit_output = nullptr;
    HWND combo_pointer_size = nullptr;
    HWND combo_type = nullptr;
    HWND check_use_pvm = nullptr;
    HWND check_allow_nonresident = nullptr;
    HWND check_byte_step = nullptr;
    HWND check_strict = nullptr;
    HWND check_auto_pointer = nullptr;
    HWND btn_build = nullptr;
    HWND btn_run = nullptr;
    HWND btn_clear = nullptr;
    HWND btn_save = nullptr;
    HWND btn_browse_a = nullptr;
    HWND btn_browse_b = nullptr;
    HWND btn_browse_output = nullptr;
    HWND list = nullptr;
    HWND status = nullptr;
    HIMAGELIST traverse_icons = nullptr;
    HMENU menu_bar = nullptr;
    HMENU menu_structure = nullptr;
    HMENU menu_options = nullptr;
    HMENU menu_type = nullptr;
    HMENU menu_count = nullptr;
    HMENU menu_stride = nullptr;
    uint64_t context_row_id = 0;

    std::vector<services::ClientService::PointerIndexEntry> pointer_index;
    uint16_t pointer_size = 0;
    bool index_ready = false;

    std::vector<services::ClientService::PointerChain> search_results;
    uint64_t search_target = 0;
    uint16_t search_depth = 0;
    int64_t search_max_offset = 0;

    std::unordered_map<uint64_t, TraverseRow> traverse_rows;
    std::vector<uint64_t> traverse_roots;
    std::vector<uint64_t> traverse_visible;
    uint64_t traverse_next_id = 1;
    int traverse_count = 128;
    int traverse_stride = 4;
    int traverse_type_idx = 2;
    bool traverse_use_pvm = true;
    bool traverse_auto_pointer = true;
    uint32_t traverse_pointer_size = 8;
    std::vector<services::ClientService::ModuleInfo> traverse_modules;
  };

  bool EnsureClassRegistered();
  bool EnsureWindowCreated(ToolWindow* tool);
  void ShowWindowFor(ToolWindow* tool);
  void ResetIndexCache(ToolWindow* tool);

  void LayoutControls(ToolWindow* tool, int width, int height);
  void ConfigureListColumns(ToolWindow* tool);
  void ApplyFontToChildren(ToolWindow* tool);

  bool EnsureConnected(ToolWindow* tool, std::wstring* out_error) const;
  bool EnsureConnectedForScan(ToolWindow* tool, std::wstring* out_error) const;
  bool BuildPointerIndex(ToolWindow* tool, bool force_rebuild, std::wstring* out_status);
  bool SearchChains(ToolWindow* tool,
                    uint64_t target,
                    uint16_t depth,
                    int64_t max_offset,
                    size_t max_results,
                    std::vector<services::ClientService::PointerChain>* out_chains,
                    std::wstring* out_error);
  bool VerifyChains(ToolWindow* tool,
                    uint16_t depth,
                    const std::vector<services::ClientService::PointerChain>& chains,
                    const std::vector<uint64_t>& targets,
                    std::vector<services::ClientService::PointerChain>* out_verified,
                    std::wstring* out_error);

  void RunPointerSearch(ToolWindow* tool);
  void RunPointerCompare(ToolWindow* tool);
  void RunDataTraverse(ToolWindow* tool);
  void SavePointerSearchResult(ToolWindow* tool);

  void ResetTraverseModel(ToolWindow* tool);
  void BuildTraverseVisible(ToolWindow* tool);
  void RefreshTraverseList(ToolWindow* tool);
  bool PopulateTraverseRow(ToolWindow* tool, TraverseRow* row);
  void BuildTraverseChildren(ToolWindow* tool, TraverseRow* parent);
  void ToggleTraverseExpand(ToolWindow* tool, int list_index);
  void UpdateTraverseMenuState(ToolWindow* tool);
  TraverseRow* TraverseRowById(ToolWindow* tool, uint64_t id);
  TraverseRow* TraverseRowByListIndex(ToolWindow* tool, int list_index);
  void ShowTraverseContextMenu(ToolWindow* tool, int list_index, const POINT& screen_pt);

  void SetStatus(ToolWindow* tool, const std::wstring& text) const;
  static std::wstring Utf8ToWide(const std::string& text);
  static std::wstring FormatAddress(uint64_t addr);
  static std::wstring FormatOffsets(const std::vector<int64_t>& offsets);
  static bool ParseAddressText(const std::wstring& text, uint64_t* out_addr);
  static bool ParseIntText(const std::wstring& text, int64_t* out_value);
  static std::wstring ModuleNameFromPath(const std::string& path);

  static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
  LRESULT WndProc(ToolWindow* tool, HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

  HINSTANCE instance_ = nullptr;
  HWND owner_ = nullptr;
  services::ClientService* service_ = nullptr;
  app::UiState* state_ = nullptr;
  bool class_registered_ = false;

  ToolWindow search_{};
  ToolWindow compare_{};
  ToolWindow traverse_{};
};

}  // namespace r3::windows_client_ng::ui
