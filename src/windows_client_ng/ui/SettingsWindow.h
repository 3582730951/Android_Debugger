#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "protocol/Protocol.h"

namespace r3::windows_client_ng::ui {

constexpr UINT kSettingsCmdConnect = 62001;
constexpr UINT kSettingsCmdDisconnect = 62002;
constexpr UINT kSettingsCmdSelectProcess = 62003;
constexpr UINT kSettingsCmdAttachProcess = 62004;
constexpr UINT kSettingsCmdChanged = 62005;

struct SettingsSnapshot {
  std::wstring host = L"127.0.0.1";
  uint16_t port = 12345;
  uint32_t pid = 0;
  protocol::ValueType scan_type = protocol::ValueType::U32;
  bool scan_hex = false;
  bool scan_strict = false;
  bool scan_use_pvm = true;
  bool scan_writable = true;
  bool scan_exec = false;
  bool scan_private = true;
  bool scan_image = false;
  bool scan_mapped = false;
  int address_refresh_ms = 500;
  int address_freeze_ms = 100;
  bool address_auto_refresh = true;
  bool address_freeze_enable = false;
  bool address_auto_add = false;
};

class SettingsWindow {
 public:
  SettingsWindow();
  ~SettingsWindow();

  bool Create(HINSTANCE instance, HWND owner);
  void Show();
  bool IsOpen() const;
  void ApplySnapshot(const SettingsSnapshot& snapshot);
  bool ReadSnapshot(SettingsSnapshot* out) const;

 private:
  void BuildTree();
  void UpdatePage(int page_index);
  void LayoutControls(int width, int height);
  void AddPageControl(int page_index, HWND ctrl);
  void ShowPageControls(int page_index);

  static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
  LRESULT WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

  HINSTANCE instance_ = nullptr;
  HWND owner_ = nullptr;
  HWND hwnd_ = nullptr;
  HWND tree_ = nullptr;
  HWND title_ = nullptr;
  HWND body_ = nullptr;
  HFONT font_ = nullptr;
  HBRUSH bg_brush_ = nullptr;
  UINT dpi_ = 96;
  int current_page_ = 0;

  std::vector<std::vector<HWND>> page_controls_;

  HWND general_group_conn_ = nullptr;
  HWND general_group_proc_ = nullptr;
  HWND general_label_host_ = nullptr;
  HWND general_label_port_ = nullptr;
  HWND general_label_pid_ = nullptr;
  HWND general_edit_host_ = nullptr;
  HWND general_edit_port_ = nullptr;
  HWND general_edit_pid_ = nullptr;
  HWND general_btn_connect_ = nullptr;
  HWND general_btn_disconnect_ = nullptr;
  HWND general_btn_select_proc_ = nullptr;
  HWND general_btn_attach_ = nullptr;
  HWND general_check_auto_connect_ = nullptr;

  HWND scan_group_strategy_ = nullptr;
  HWND scan_group_region_ = nullptr;
  HWND scan_check_strict_ = nullptr;
  HWND scan_check_pvm_ = nullptr;
  HWND scan_label_type_ = nullptr;
  HWND scan_combo_type_ = nullptr;
  HWND scan_check_hex_ = nullptr;
  HWND scan_check_writable_ = nullptr;
  HWND scan_check_exec_ = nullptr;
  HWND scan_check_private_ = nullptr;
  HWND scan_check_image_ = nullptr;
  HWND scan_check_mapped_ = nullptr;

  HWND font_label_ui_ = nullptr;
  HWND font_label_mono_ = nullptr;
  HWND font_combo_ui_ = nullptr;
  HWND font_combo_mono_ = nullptr;
  HWND font_preview_ = nullptr;

  HWND lang_label_ = nullptr;
  HWND lang_combo_ = nullptr;
  HWND lang_check_auto_ = nullptr;

  HWND addr_group_ = nullptr;
  HWND addr_label_refresh_ = nullptr;
  HWND addr_label_freeze_ = nullptr;
  HWND addr_edit_refresh_ = nullptr;
  HWND addr_edit_freeze_ = nullptr;
  HWND addr_check_freeze_ = nullptr;
  HWND addr_check_auto_add_ = nullptr;

  HWND script_label_dir_ = nullptr;
  HWND script_edit_dir_ = nullptr;
  HWND script_btn_browse_ = nullptr;
  HWND script_check_auto_ = nullptr;
  HWND script_list_ = nullptr;
};

}  // namespace r3::windows_client_ng::ui
