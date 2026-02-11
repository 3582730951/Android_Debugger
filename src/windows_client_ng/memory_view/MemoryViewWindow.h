#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <d2d1.h>
#include <dwrite.h>
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include "app/UiState.h"
#include "services/ClientService.h"

namespace r3::windows_client_ng::memory_view {

class MemoryViewWindow {
 public:
  MemoryViewWindow();
  ~MemoryViewWindow();

  bool Create(HINSTANCE instance, HWND owner, services::ClientService* service, app::UiState* state);
  void Show(uint64_t preferred_addr);
  bool IsOpen() const;

  struct DisasmLine {
    uint64_t addr = 0;
    std::wstring bytes;
    std::wstring op;
    std::wstring comment;
  };

 private:
  enum class DisasmMode {
    AsmHex = 0,
    AsmOnly,
    HexOnly,
  };

  bool CreateDeviceIndependentResources();
  bool CreateDeviceResources();
  void DiscardDeviceResources();
  void BuildMenuBar();

  void RefreshData();
  void BuildDisasmLines();
  void Draw();
  void ScrollLines(int delta_lines);
  void JumpTo(uint64_t addr);
  void JumpToInternal(uint64_t addr, bool remember_history);
  void RememberNavigation(uint64_t addr);
  bool FetchProgramCounter(uint64_t* out_pc, std::wstring* out_error);
  void UpdateViewMenuChecks();
  void UpdateMenuEnabledState();
  void ApplyMenuIcons();
  void LayoutTopControls();
  bool HitTestContext(const POINT& pt, uint64_t* out_addr, std::wstring* out_bytes);
  bool HitTestDisasmRow(const POINT& pt, uint64_t* out_addr);
  bool CopyTextToClipboard(const std::wstring& text);
  std::wstring BuildPermText(uint32_t perms) const;
  bool EnsureModulesLoaded();
  std::wstring BuildAddressAlias(uint64_t addr) const;
  void UpdateSelectedAddressStatus();
  bool ResolveJumpExpression(const std::wstring& input, uint64_t* out_addr, std::wstring* out_error);
  void UpdateRegionInfo();
  void ShowModuleViewer();

  std::wstring Utf8ToWide(const std::string& text) const;
  std::string WideToUtf8(const std::wstring& text) const;
  std::wstring HexBytes(const uint8_t* data, size_t n) const;
  std::wstring AsciiBytes(const uint8_t* data, size_t n) const;

  static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
  LRESULT WndProc(UINT msg, WPARAM wparam, LPARAM lparam);

  static constexpr UINT kMenuFindHex = 41001;
  static constexpr UINT kMenuFindAsm = 41002;
  static constexpr UINT kMenuReload = 41003;
  static constexpr UINT kMenuJump = 41004;
  static constexpr UINT kMenuViewAsmHex = 41005;
  static constexpr UINT kMenuViewAsmOnly = 41006;
  static constexpr UINT kMenuViewHexOnly = 41007;
  static constexpr UINT kMenuViewFollowPc = 41008;
  static constexpr UINT kMenuViewBack = 41009;
  static constexpr UINT kMenuViewForward = 41010;
  static constexpr UINT kMenuViewBookmark = 41011;
  static constexpr UINT kMenuViewModuleStart = 41012;
  static constexpr UINT kMenuViewPrevSegment = 41013;
  static constexpr UINT kMenuViewNextSegment = 41014;
  static constexpr UINT kMenuHexEdit = 41015;
  static constexpr UINT kMenuViewModules = 41016;
  static constexpr UINT kMenuToolPointerScan = 41301;
  static constexpr UINT kMenuToolPointerCompare = 41302;
  static constexpr UINT kMenuToolDataTraverse = 41303;
  static constexpr UINT kMenuDebugRun = 41220;
  static constexpr UINT kMenuDebugStepIn = 41221;
  static constexpr UINT kMenuDebugStepOver = 41222;
  static constexpr UINT kMenuDebugRunTo = 41223;
  static constexpr UINT kMenuDebugSetAddr = 41224;
  static constexpr UINT kMenuDebugToggleBp = 41225;
  static constexpr UINT kMenuDebugBreak = 41226;
  static constexpr UINT kMenuCtxCopyAddr = 41101;
  static constexpr UINT kMenuCtxCopyBytes = 41102;
  static constexpr UINT kMenuCtxDisasmHere = 41103;
  static constexpr UINT kMenuCtxAddToList = 41104;
  static constexpr UINT kMenuCtxNop = 41105;
  static constexpr UINT kMenuCtxRestore = 41106;
  static constexpr UINT kMenuCtxJumpAddr = 41107;

  HINSTANCE instance_ = nullptr;
  HWND owner_ = nullptr;
  HWND hwnd_ = nullptr;
  HWND addr_edit_ = nullptr;
  HWND goto_btn_ = nullptr;
  HMENU menu_bar_ = nullptr;
  HMENU menu_search_ = nullptr;
  HMENU menu_view_ = nullptr;
  HMENU menu_debug_ = nullptr;
  HMENU menu_tool_ = nullptr;
  std::vector<HBITMAP> menu_bitmaps_;

  ID2D1Factory* d2d_factory_ = nullptr;
  ID2D1HwndRenderTarget* render_target_ = nullptr;
  IDWriteFactory* dwrite_factory_ = nullptr;
  IDWriteTextFormat* font_ui_ = nullptr;
  IDWriteTextFormat* font_mono_ = nullptr;

  ID2D1SolidColorBrush* brush_bg_ = nullptr;
  ID2D1SolidColorBrush* brush_panel_ = nullptr;
  ID2D1SolidColorBrush* brush_border_ = nullptr;
  ID2D1SolidColorBrush* brush_text_ = nullptr;
  ID2D1SolidColorBrush* brush_muted_ = nullptr;
  ID2D1SolidColorBrush* brush_highlight_ = nullptr;
  ID2D1SolidColorBrush* brush_select_fill_ = nullptr;
  ID2D1SolidColorBrush* brush_select_border_ = nullptr;

  services::ClientService* service_ = nullptr;
  app::UiState* state_ = nullptr;

  HFONT ctrl_font_ = nullptr;
  HBRUSH ctrl_bg_brush_ = nullptr;
  UINT dpi_ = 96;
  float dpi_scale_ = 1.0f;
  DisasmMode disasm_mode_ = DisasmMode::AsmHex;
  uint32_t modules_pid_ = 0;
  std::vector<services::ClientService::ModuleInfo> modules_;
  uint64_t context_addr_ = 0;
  std::wstring context_bytes_;
  std::unordered_map<uint64_t, std::vector<uint8_t>> patch_backup_;
  std::unordered_map<uint64_t, protocol::DebugBackend> breakpoints_;
  uint64_t selected_disasm_addr_ = 0;
  std::vector<uint64_t> nav_history_;
  size_t nav_history_pos_ = 0;
  uint64_t bookmark_addr_ = 0;
  bool follow_pc_ = false;
  bool debug_attached_ = false;

  uint64_t base_addr_ = 0x400000;
  uint32_t window_size_ = 0x400;
  std::vector<uint8_t> mem_;
  std::vector<DisasmLine> disasm_;
  std::wstring status_ = L"请先打开一个进程";
  std::wstring region_info_;
};

}  // namespace r3::windows_client_ng::memory_view
