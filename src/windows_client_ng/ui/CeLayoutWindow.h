#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <d2d1.h>
#include <dwrite.h>
#include <windows.h>
#include <windowsx.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "app/UiState.h"
#include "memory_view/MemoryViewWindow.h"
#include "ui/PointerToolsWindow.h"
#include "ui/SettingsWindow.h"
#include "services/ClientService.h"

namespace r3::windows_client_ng::ui {

class CeLayoutWindow {
 public:
  CeLayoutWindow();
  ~CeLayoutWindow();

  bool Create(HINSTANCE instance, int nCmdShow);
  int Run();

 private:
  enum class ButtonId : uint32_t {
    None = 0,
    SelectProcess,
    OpenFile,
    SaveFile,
    ToggleConnect,
    FirstScan,
    NextScan,
    UndoScan,
    PrevPage,
    NextPage,
    OpenMemoryView,
    OpenSettings,
    OpenSettingsSide,
    ScanTab1,
    ScanTab2,
    RefreshValue,
    RefreshAddressList,
    OpenModuleRange,
    AttachFirstProcess,
    AddSelectedAddress,
    ClearAddressList,
    AddManualAddress,
  };

  struct Button {
    ButtonId id = ButtonId::None;
    D2D1_RECT_F rect{};
    std::wstring text;
  };

  struct ScanSnapshot {
    uint64_t match_total = 0;
    uint64_t page_index = 0;
    std::vector<uint64_t> page_addresses;
    int selected_row = -1;
  };

  static constexpr UINT kMenuFileExit = 40001;
  static constexpr UINT kMenuFileOpen = 40002;
  static constexpr UINT kMenuFileSave = 40003;
  static constexpr UINT kMenuViewMemory = 40004;
  static constexpr UINT kMenuViewSettings = 40005;
  static constexpr UINT kMenuDebugPointerScan = 40006;
  static constexpr UINT kMenuDebugPointerCompare = 40007;
  static constexpr UINT kMenuDebugDataTraverse = 40008;
  static constexpr UINT kProcessMenuBase = 50000;
  static constexpr UINT kProcessMenuMax = 40;
  static constexpr UINT kModuleMenuBase = 54000;
  static constexpr UINT kModuleMenuMax = 120;
  static constexpr UINT kTimerAddressList = 1;

  bool CreateDeviceIndependentResources();
  bool CreateDeviceResources();
  void DiscardDeviceResources();
  void BuildMenuBar();

  void Draw();
  void DrawToolbar(const D2D1_RECT_F& rect);
  void DrawProcessStrip(const D2D1_RECT_F& rect);
  void DrawScanArea(const D2D1_RECT_F& rect);
  void DrawAddressListArea(const D2D1_RECT_F& rect);
  void DrawStatusBar(const D2D1_RECT_F& rect);
  void DrawHoverHintOverlay(const D2D1_RECT_F& rect);
  int GetGuideStep() const;
  int GetGuideStepForButton(ButtonId id) const;
  ButtonId GetGuidedAction() const;
  bool IsButtonEnabled(ButtonId id) const;
  const wchar_t* GetButtonHint(ButtonId id) const;
  std::wstring BuildGuideHint() const;
  void DrawTableHeader(const D2D1_RECT_F& rect,
                       const wchar_t* c1,
                       const wchar_t* c2,
                       const wchar_t* c3);
  void DrawButton(ButtonId id,
                  const std::wstring& text,
                  float x,
                  float y,
                  float w,
                  float h,
                  bool primary = false);
  void DrawIconButton(ButtonId id, const char* icon_id, float x, float y, float w, float h);
  void DrawTab(ButtonId id, const wchar_t* text, bool selected, float x, float y, float w, float h);
  bool HitTestButton(const POINT& pt, ButtonId* out_button) const;
  bool HitTestScanRow(const POINT& pt, size_t* out_row) const;
  bool HitTestAddressRow(const POINT& pt, size_t* out_row) const;
  void HandleButton(ButtonId id);
  void EditAddressValue(size_t row);
  bool AddScanAddressToList(size_t scan_row, bool open_editor);
  bool CopyTextToClipboard(const std::wstring& text) const;
  bool LoadSettingsFromFile();
  void SaveSettingsToFile() const;

  bool EnsureConnected();
  bool RefreshProcesses();
  void ShowProcessPopup();
  void AttachProcessByIndex(size_t index);
  void CreateNativeControls();
  void ApplyControlFont();
  void LayoutNativeControls();
  void SyncStateFromControls();
  void SyncControlsFromState();
  void ApplyScanResult(uint64_t total, const std::vector<uint64_t>& addresses, const std::wstring& ok_status);
  void ApplySettingsSnapshot(const SettingsSnapshot& snapshot);
  void TryAutoBootstrapOnStartup();
  bool ResolveAdbExecutablePath(std::wstring* out_path) const;
  std::filesystem::path FindRuntimeScript(const wchar_t* script_name) const;
  std::filesystem::path ResolveAndroidAgentOutRoot() const;
  bool RunProcessForBootstrap(const std::wstring& exe_path,
                              const std::vector<std::wstring>& args,
                              DWORD timeout_ms,
                              DWORD* out_exit_code) const;
  bool ReadScanControls(uint64_t* start, uint64_t* end);
  void UpdateStatus(const std::wstring& text);
  void Invalidate();
  bool LoadSvgAtlas();
  void DrawSvgIcon(const char* icon_id, const D2D1_RECT_F& dest);
  void ApplyMenuIcons(HMENU menu_bar);
  void UpdateScrollBars();
  uint16_t BuildScanFlags() const;
  bool BuildScanRequest(protocol::ComparisonType* out_comparison,
                        std::string* out_value_text,
                        std::wstring* out_error) const;
  bool ReloadModulesCache(bool force, std::string* out_error = nullptr);
  void ReloadScanRegionOptions(bool force_modules);
  void ApplySelectedScanRegion(bool update_status);
  void OpenModuleRangePopup();
  void SaveCurrentTabState();
  void LoadTabState(int tab_index);
  void SortScanAddressesIfNeeded(std::vector<uint64_t>* addresses) const;
  uint64_t ParseAddressText(const std::wstring& text, bool* ok = nullptr) const;
  void TickAddressList();
  void RefreshAddressListValues(bool force);
  bool ResolveEntryAddress(const app::AddressEntry& entry, uint64_t* out_addr, std::string* out_error);
  std::wstring FormatValueText(protocol::ValueType type,
                               const uint8_t* data,
                               size_t size,
                               bool value_hex,
                               bool value_signed) const;
  size_t ValueTypeSize(protocol::ValueType type) const;
  uint64_t NowMs() const;

  std::wstring Utf8ToWide(const std::string& text) const;
  std::string WideToUtf8(const std::wstring& text) const;
  std::wstring BuildProcessCaption(uint32_t pid, const std::wstring& name) const;

  static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
  LRESULT WndProc(UINT msg, WPARAM wparam, LPARAM lparam);

  HINSTANCE instance_ = nullptr;
  HWND hwnd_ = nullptr;

  ID2D1Factory* d2d_factory_ = nullptr;
  ID2D1HwndRenderTarget* render_target_ = nullptr;
  IDWriteFactory* dwrite_factory_ = nullptr;
  IDWriteTextFormat* font_ui_ = nullptr;
  IDWriteTextFormat* font_ui_center_ = nullptr;
  IDWriteTextFormat* font_mono_ = nullptr;

  ID2D1SolidColorBrush* brush_bg_ = nullptr;
  ID2D1SolidColorBrush* brush_panel_ = nullptr;
  ID2D1SolidColorBrush* brush_row_alt_ = nullptr;
  ID2D1SolidColorBrush* brush_row_select_ = nullptr;
  ID2D1SolidColorBrush* brush_border_ = nullptr;
  ID2D1SolidColorBrush* brush_text_ = nullptr;
  ID2D1SolidColorBrush* brush_muted_ = nullptr;
  ID2D1SolidColorBrush* brush_accent_ = nullptr;
  ID2D1SolidColorBrush* brush_accent_text_ = nullptr;

  struct SvgIconAtlas {
    ID2D1Bitmap* bitmap = nullptr;
    UINT32 width = 0;
    UINT32 height = 0;
    std::unordered_map<std::string, D2D1_RECT_F> icon_uv;
  } svg_atlas_{};
  std::vector<HBITMAP> menu_bitmaps_;

  app::UiState state_;
  services::ClientService service_;
  memory_view::MemoryViewWindow memory_view_window_;
  SettingsWindow settings_window_;
  PointerToolsWindow pointer_tools_window_;
  std::vector<Button> buttons_;
  ButtonId hovered_button_ = ButtonId::None;
  D2D1_RECT_F scan_rows_rect_{};
  float scan_row_height_ = 22.0f;
  size_t scan_rows_count_ = 0;
  size_t scan_rows_visible_ = 0;
  size_t scan_rows_total_ = 0;
  int selected_scan_row_ = -1;
  int scan_scroll_offset_ = 0;
  D2D1_RECT_F address_rows_rect_{};
  float address_row_height_ = 22.0f;
  size_t address_rows_count_ = 0;
  size_t address_rows_visible_ = 0;
  size_t address_rows_total_ = 0;
  int selected_address_row_ = -1;
  int context_scan_row_ = -1;
  int context_address_row_ = -1;
  int address_scroll_offset_ = 0;
  float address_hit_active_left_ = 0.0f;
  float address_hit_active_right_ = 0.0f;
  float address_hit_freeze_left_ = 0.0f;
  float address_hit_freeze_right_ = 0.0f;
  float address_hit_value_left_ = 0.0f;
  ScanSnapshot prev_scan_{};
  bool has_prev_scan_ = false;
  int scan_tab_ = 0;
  int backend_scan_tab_ = -1;
  struct ScanTabState {
    uint64_t match_total = 0;
    uint64_t page_index = 0;
    std::vector<uint64_t> page_addresses;
    int selected_row = -1;
    ScanSnapshot prev{};
    bool has_prev = false;
  };
  std::array<ScanTabState, 2> scan_tabs_{};

  HFONT ctrl_font_ = nullptr;
  HBRUSH ctrl_bg_brush_ = nullptr;
  UINT dpi_ = 96;
  float dpi_scale_ = 1.0f;

  HWND edit_scan_value_ = nullptr;
  HWND edit_scan_start_ = nullptr;
  HWND edit_scan_end_ = nullptr;
  HWND combo_scan_type_ = nullptr;
  HWND combo_scan_cond_ = nullptr;
  HWND combo_scan_region_ = nullptr;
  HWND check_scan_hex_ = nullptr;
  HWND check_scan_fast_ = nullptr;
  HWND edit_scan_fast_value_ = nullptr;
  HWND radio_scan_align_ = nullptr;
  HWND radio_scan_last_ = nullptr;
  HWND check_scan_writable_ = nullptr;
  HWND check_scan_executable_ = nullptr;
  HWND check_scan_copy_ = nullptr;
  HWND check_scan_active_ = nullptr;
  HWND scroll_scan_ = nullptr;
  HWND scroll_addr_ = nullptr;

  bool address_auto_refresh_ = true;
  bool address_freeze_enabled_ = false;
  bool address_auto_add_ = false;
  bool address_use_pvm_ = true;
  bool ui_scan_active_only_ = false;
  int ui_scan_fast_value_ = 4;
  int ui_scan_fast_mode_ = 0;
  bool startup_bootstrap_done_ = false;
  bool auto_bootstrap_android_ = true;
  int address_refresh_interval_ms_ = 500;
  int address_freeze_interval_ms_ = 100;
  uint64_t address_last_refresh_ms_ = 0;
  uint64_t address_last_freeze_ms_ = 0;
  uint64_t process_list_last_refresh_ms_ = 0;
  std::string adb_path_;

  struct ScanRegionOption {
    std::wstring label;
    uint64_t start = 0;
    uint64_t end = 0;
    bool from_module = false;
    bool from_gg = false;
    uint8_t gg_code = protocol::GG_REGION_NONE;
  };
  uint32_t modules_pid_ = 0;
  std::vector<services::ClientService::ModuleInfo> modules_cache_;
  std::vector<ScanRegionOption> scan_region_all_options_;
  std::vector<ScanRegionOption> scan_region_options_;
  bool scan_region_reloading_ = false;
  uint8_t scan_region_gg_code_ = protocol::GG_REGION_NONE;
};

}  // namespace r3::windows_client_ng::ui
