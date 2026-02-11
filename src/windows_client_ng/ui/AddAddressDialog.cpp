#include "ui/AddAddressDialog.h"

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cwchar>
#include <iterator>
#include <dwmapi.h>

namespace r3::windows_client_ng::ui {

namespace {

constexpr UINT kCtrlEditAddress = 51001;
constexpr UINT kCtrlEditDesc = 51002;
constexpr UINT kCtrlComboType = 51003;
constexpr UINT kCtrlCheckHex = 51004;
constexpr UINT kCtrlCheckSigned = 51005;
constexpr UINT kCtrlCheckPointer = 51006;
constexpr UINT kCtrlListOffsets = 51007;
constexpr UINT kCtrlEditOffset = 51008;
constexpr UINT kCtrlBtnAddOffset = 51009;
constexpr UINT kCtrlBtnDelOffset = 51010;
constexpr UINT kCtrlPreviewText = 51011;

constexpr protocol::ValueType kTypeMap[] = {
    protocol::ValueType::U8,
    protocol::ValueType::U16,
    protocol::ValueType::U32,
    protocol::ValueType::U64,
    protocol::ValueType::S32,
    protocol::ValueType::S64,
    protocol::ValueType::FLOAT,
    protocol::ValueType::DOUBLE,
};

int TypeToIndex(protocol::ValueType type) {
  for (size_t i = 0; i < std::size(kTypeMap); ++i) {
    if (kTypeMap[i] == type) {
      return static_cast<int>(i);
    }
  }
  return 2;
}

protocol::ValueType IndexToType(int idx) {
  if (idx < 0 || idx >= static_cast<int>(std::size(kTypeMap))) {
    return protocol::ValueType::U32;
  }
  return kTypeMap[idx];
}

bool ParseUint64(const wchar_t* text, uint64_t* out) {
  if (!text || !*text) {
    return false;
  }
  wchar_t* endptr = nullptr;
  unsigned long long value = std::wcstoull(text, &endptr, 0);
  if (endptr == text) {
    return false;
  }
  if (out) {
    *out = static_cast<uint64_t>(value);
  }
  return true;
}

bool ParseInt64(const wchar_t* text, int64_t* out) {
  if (!text || !*text) {
    return false;
  }
  wchar_t* endptr = nullptr;
  long long value = std::wcstoll(text, &endptr, 0);
  if (endptr == text) {
    return false;
  }
  if (out) {
    *out = static_cast<int64_t>(value);
  }
  return true;
}

UINT GetDpiForWindowCompat(HWND hwnd) {
  HMODULE user32 = GetModuleHandleW(L"user32.dll");
  using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
  auto fn = reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(user32, "GetDpiForWindow"));
  if (fn) {
    return fn(hwnd);
  }
  HDC hdc = GetDC(hwnd);
  UINT dpi = 96;
  if (hdc) {
    dpi = static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSX));
    ReleaseDC(hwnd, hdc);
  }
  return dpi;
}

std::wstring FormatOffset(int64_t offset) {
  wchar_t buf[64] = {0};
  if (offset >= 0) {
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"+0x%llX", static_cast<long long>(offset));
  } else {
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"-0x%llX", static_cast<long long>(-offset));
  }
  return buf;
}

struct AddAddressDialogState {
  AddAddressDialogPreset preset;
  AddAddressDialogResult result;
  bool done = false;
  bool ok = false;
  HWND hwnd = nullptr;
  HWND edit_addr = nullptr;
  HWND edit_desc = nullptr;
  HWND combo_type = nullptr;
  HWND check_hex = nullptr;
  HWND check_signed = nullptr;
  HWND check_pointer = nullptr;
  HWND label_offsets = nullptr;
  HWND list_offsets = nullptr;
  HWND edit_offset = nullptr;
  HWND btn_add = nullptr;
  HWND btn_del = nullptr;
  HWND label_preview = nullptr;
  HWND text_preview = nullptr;
  HWND ok_btn = nullptr;
  HWND cancel_btn = nullptr;
  HFONT font = nullptr;
  HBRUSH bg_brush = nullptr;
  UINT dpi = 96;
  float scale = 1.0f;
  int width_dip = 0;
  int collapsed_h_dip = 0;
  int expanded_h_dip = 0;
  int width_px = 0;
  int collapsed_h_px = 0;
  int expanded_h_px = 0;
  std::vector<int64_t> offsets;
};

void UpdateDialogLayout(AddAddressDialogState* state, bool expanded);
void UpdatePointerPreview(AddAddressDialogState* state);

void SetEnabledPointerControls(AddAddressDialogState* state, bool enabled) {
  if (!state) return;
  const int cmd = enabled ? TRUE : FALSE;
  EnableWindow(state->list_offsets, cmd);
  EnableWindow(state->edit_offset, cmd);
  EnableWindow(state->btn_add, cmd);
  EnableWindow(state->btn_del, cmd);
  UpdateDialogLayout(state, enabled);
  UpdatePointerPreview(state);
}

void RefreshOffsetsList(AddAddressDialogState* state) {
  if (!state || !state->list_offsets) return;
  SendMessageW(state->list_offsets, LB_RESETCONTENT, 0, 0);
  for (const auto& off : state->offsets) {
    std::wstring text = FormatOffset(off);
    SendMessageW(state->list_offsets, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
  }
  UpdatePointerPreview(state);
}

void UpdateDialogLayout(AddAddressDialogState* state, bool expanded) {
  if (!state || !state->hwnd) return;
  auto px = [state](float dip) { return static_cast<int>(std::lround(dip * state->scale)); };
  const int width = state->width_px;
  const int height = expanded ? state->expanded_h_px : state->collapsed_h_px;
  SetWindowPos(state->hwnd, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

  const int margin = px(16.0f);
  const int label_w = px(60.0f);
  const int row_h = px(24.0f);
  const int gap_y = px(10.0f);
  const int x_ctrl = margin + label_w + px(2.0f);
  const int content_w = width - margin * 2;

  const int y_addr = px(14.0f);
  const int y_desc = y_addr + row_h + gap_y;
  const int y_type = y_desc + row_h + gap_y;
  const int y_ptr = y_type + row_h + gap_y;
  const int y_offsets = y_ptr + row_h + px(4.0f);

  if (state->edit_addr) {
    MoveWindow(state->edit_addr, x_ctrl, y_addr, px(250.0f), row_h, TRUE);
  }
  if (state->edit_desc) {
    MoveWindow(state->edit_desc, x_ctrl, y_desc, content_w - label_w - px(4.0f), row_h, TRUE);
  }
  if (state->combo_type) {
    MoveWindow(state->combo_type, x_ctrl, y_type, px(124.0f), px(220.0f), TRUE);
  }
  if (state->check_hex) {
    MoveWindow(state->check_hex, x_ctrl + px(140.0f), y_type + px(2.0f), px(96.0f), px(22.0f), TRUE);
  }
  if (state->check_signed) {
    MoveWindow(state->check_signed, x_ctrl + px(240.0f), y_type + px(2.0f), px(92.0f), px(22.0f), TRUE);
  }
  if (state->check_pointer) {
    MoveWindow(state->check_pointer, margin, y_ptr, px(80.0f), px(22.0f), TRUE);
  }
  if (state->label_offsets) {
    MoveWindow(state->label_offsets, margin, y_offsets + px(2.0f), label_w, px(18.0f), TRUE);
  }
  if (state->list_offsets) {
    MoveWindow(state->list_offsets, x_ctrl, y_offsets, px(220.0f), px(110.0f), TRUE);
  }
  if (state->edit_offset) {
    MoveWindow(state->edit_offset, x_ctrl + px(230.0f), y_offsets, px(116.0f), row_h, TRUE);
  }
  if (state->btn_add) {
    MoveWindow(state->btn_add, x_ctrl + px(354.0f), y_offsets, px(64.0f), row_h, TRUE);
  }
  if (state->btn_del) {
    MoveWindow(state->btn_del, x_ctrl + px(354.0f), y_offsets + row_h + px(6.0f), px(64.0f), row_h, TRUE);
  }
  if (state->label_preview) {
    MoveWindow(state->label_preview, x_ctrl + px(230.0f), y_offsets + px(56.0f), px(190.0f), px(18.0f), TRUE);
  }
  if (state->text_preview) {
    MoveWindow(state->text_preview, x_ctrl + px(230.0f), y_offsets + px(76.0f), px(190.0f), px(70.0f), TRUE);
  }

  int btn_y = height - px(52.0f);
  if (expanded) {
    // Keep action buttons below the pointer preview block for high-DPI layouts.
    const int content_bottom = y_offsets + px(162.0f);
    btn_y = std::max(btn_y, content_bottom + px(10.0f));
  }
  if (state->ok_btn) {
    MoveWindow(state->ok_btn, width - px(188.0f), btn_y, px(80.0f), px(26.0f), TRUE);
  }
  if (state->cancel_btn) {
    MoveWindow(state->cancel_btn, width - px(98.0f), btn_y, px(80.0f), px(26.0f), TRUE);
  }
  const int show = expanded ? SW_SHOW : SW_HIDE;
  if (state->label_offsets) ShowWindow(state->label_offsets, show);
  if (state->list_offsets) ShowWindow(state->list_offsets, show);
  if (state->edit_offset) ShowWindow(state->edit_offset, show);
  if (state->btn_add) ShowWindow(state->btn_add, show);
  if (state->btn_del) ShowWindow(state->btn_del, show);
  if (state->label_preview) ShowWindow(state->label_preview, show);
  if (state->text_preview) ShowWindow(state->text_preview, show);
}

void UpdatePointerPreview(AddAddressDialogState* state) {
  if (!state || !state->text_preview) {
    return;
  }
  wchar_t addr_buf[128] = {0};
  std::wstring base = L"???";
  if (state->edit_addr) {
    GetWindowTextW(state->edit_addr, addr_buf, static_cast<int>(std::size(addr_buf)));
    if (addr_buf[0] != 0) {
      base = addr_buf;
    }
  }
  std::wstring preview = base;
  if (state->offsets.empty()) {
    preview.append(L" + 0 = ???");
  } else {
    for (size_t i = 0; i < state->offsets.size(); ++i) {
      preview.append(L"\r\n");
      preview.append(i == 0 ? L"??" : L"ptr");
      preview.append(L" ");
      preview.append(FormatOffset(state->offsets[i]));
      preview.append(L" = ??");
    }
  }
  SetWindowTextW(state->text_preview, preview.c_str());
}

LRESULT CALLBACK AddAddressDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  AddAddressDialogState* state = reinterpret_cast<AddAddressDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    state = reinterpret_cast<AddAddressDialogState*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
  }
  if (!state) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  switch (msg) {
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      const UINT notify = HIWORD(wparam);
      if (cmd == IDOK) {
        wchar_t addr_buf[128] = {0};
        GetWindowTextW(state->edit_addr, addr_buf, static_cast<int>(std::size(addr_buf)));
        uint64_t addr = 0;
        if (!ParseUint64(addr_buf, &addr) || addr == 0) {
          MessageBoxW(hwnd, L"请输入有效地址", L"提示", MB_OK | MB_ICONWARNING);
          return 0;
        }
        wchar_t desc_buf[256] = {0};
        GetWindowTextW(state->edit_desc, desc_buf, static_cast<int>(std::size(desc_buf)));
        const int type_idx = static_cast<int>(SendMessageW(state->combo_type, CB_GETCURSEL, 0, 0));
        const bool hex = (SendMessageW(state->check_hex, BM_GETCHECK, 0, 0) == BST_CHECKED);
        const bool sign = (SendMessageW(state->check_signed, BM_GETCHECK, 0, 0) == BST_CHECKED);
        const bool ptr = (SendMessageW(state->check_pointer, BM_GETCHECK, 0, 0) == BST_CHECKED);

        state->result.address = addr;
        state->result.description = desc_buf;
        state->result.type = IndexToType(type_idx);
        state->result.value_hex = hex;
        state->result.value_signed = sign;
        state->result.is_pointer = ptr;
        state->result.offsets = ptr ? state->offsets : std::vector<int64_t>();
        state->ok = true;
        state->done = true;
        DestroyWindow(hwnd);
        return 0;
      }
      if (cmd == IDCANCEL) {
        state->ok = false;
        state->done = true;
        DestroyWindow(hwnd);
        return 0;
      }
      if (cmd == kCtrlCheckPointer) {
        const bool ptr = (SendMessageW(state->check_pointer, BM_GETCHECK, 0, 0) == BST_CHECKED);
        SetEnabledPointerControls(state, ptr);
        return 0;
      }
      if ((cmd == kCtrlEditAddress || cmd == kCtrlEditOffset) && notify == EN_CHANGE) {
        UpdatePointerPreview(state);
        return 0;
      }
      if (cmd == kCtrlBtnAddOffset) {
        wchar_t buf[128] = {0};
        GetWindowTextW(state->edit_offset, buf, static_cast<int>(std::size(buf)));
        int64_t offset = 0;
        if (!ParseInt64(buf, &offset)) {
          MessageBoxW(hwnd, L"偏移格式错误", L"提示", MB_OK | MB_ICONWARNING);
          return 0;
        }
        state->offsets.push_back(offset);
        RefreshOffsetsList(state);
        SetWindowTextW(state->edit_offset, L"");
        return 0;
      }
      if (cmd == kCtrlBtnDelOffset) {
        const int sel = static_cast<int>(SendMessageW(state->list_offsets, LB_GETCURSEL, 0, 0));
        if (sel >= 0 && sel < static_cast<int>(state->offsets.size())) {
          state->offsets.erase(state->offsets.begin() + sel);
          RefreshOffsetsList(state);
        }
        return 0;
      }
      break;
    }
    case WM_DPICHANGED: {
      const UINT new_dpi = LOWORD(wparam);
      state->dpi = new_dpi == 0 ? 96 : new_dpi;
      state->scale = static_cast<float>(state->dpi) / 96.0f;
      state->width_px = static_cast<int>(std::lround(static_cast<float>(state->width_dip) * state->scale));
      state->collapsed_h_px = static_cast<int>(std::lround(static_cast<float>(state->collapsed_h_dip) * state->scale));
      state->expanded_h_px = static_cast<int>(std::lround(static_cast<float>(state->expanded_h_dip) * state->scale));
      if (state->font) {
        DeleteObject(state->font);
        state->font = nullptr;
      }
      LOGFONTW lf{};
      lf.lfHeight = -MulDiv(12, static_cast<int>(state->dpi), 96);
      lf.lfWeight = FW_NORMAL;
      wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
      state->font = CreateFontIndirectW(&lf);
      HFONT font = state->font ? state->font : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
      const HWND controls[] = {
          state->edit_addr,      state->edit_desc,     state->combo_type,  state->check_hex,
          state->check_signed,   state->check_pointer, state->label_offsets, state->list_offsets,
          state->edit_offset,    state->btn_add,       state->btn_del,     state->label_preview,
          state->text_preview,   state->ok_btn,        state->cancel_btn,
      };
      for (HWND ctrl : controls) {
        if (ctrl) {
          SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        }
      }
      const bool expanded = SendMessageW(state->check_pointer, BM_GETCHECK, 0, 0) == BST_CHECKED;
      if (lparam) {
        const RECT* suggested = reinterpret_cast<const RECT*>(lparam);
        SetWindowPos(hwnd,
                     nullptr,
                     suggested->left,
                     suggested->top,
                     suggested->right - suggested->left,
                     suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
      }
      UpdateDialogLayout(state, expanded);
      UpdatePointerPreview(state);
      return 0;
    }
    case WM_CLOSE:
      state->ok = false;
      state->done = true;
      DestroyWindow(hwnd);
      return 0;
    case WM_CTLCOLORDLG:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      SetTextColor(hdc, RGB(230, 230, 230));
      SetBkColor(hdc, RGB(43, 43, 43));
      return reinterpret_cast<LRESULT>(state->bg_brush);
    }
    case WM_ERASEBKGND: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      RECT rc{};
      GetClientRect(hwnd, &rc);
      FillRect(hdc, &rc, state->bg_brush ? state->bg_brush : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
      return 1;
    }
    case WM_NCDESTROY:
      if (state->font) {
        DeleteObject(state->font);
        state->font = nullptr;
      }
      if (state->bg_brush) {
        DeleteObject(state->bg_brush);
        state->bg_brush = nullptr;
      }
      break;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

}  // namespace

bool ShowAddAddressDialog(HWND owner,
                          const AddAddressDialogPreset& preset,
                          AddAddressDialogResult* out_result) {
  if (!out_result) {
    return false;
  }
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = AddAddressDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"R3NgAddAddressDialog";
    RegisterClassExW(&wc);
    registered = true;
  }

  AddAddressDialogState state{};
  state.preset = preset;
  state.result = {};
  state.dpi = owner ? GetDpiForWindowCompat(owner) : 96;
  state.scale = static_cast<float>(state.dpi) / 96.0f;
  state.width_dip = 520;
  state.collapsed_h_dip = 236;
  state.expanded_h_dip = 392;
  state.width_px = static_cast<int>(std::lround(static_cast<float>(state.width_dip) * state.scale));
  state.collapsed_h_px = static_cast<int>(std::lround(static_cast<float>(state.collapsed_h_dip) * state.scale));
  state.expanded_h_px = static_cast<int>(std::lround(static_cast<float>(state.expanded_h_dip) * state.scale));

  RECT owner_rc{};
  int x = CW_USEDEFAULT;
  int y = CW_USEDEFAULT;
  if (owner && GetWindowRect(owner, &owner_rc)) {
    x = owner_rc.left + (owner_rc.right - owner_rc.left - state.width_px) / 2;
    y = owner_rc.top + (owner_rc.bottom - owner_rc.top - state.collapsed_h_px) / 2;
  }

  state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                               L"R3NgAddAddressDialog",
                               L"添加地址",
                               WS_POPUP | WS_CAPTION | WS_SYSMENU,
                               x,
                               y,
                               state.width_px,
                               state.collapsed_h_px,
                               owner,
                               nullptr,
                               GetModuleHandleW(nullptr),
                               &state);
  if (!state.hwnd) {
    return false;
  }

  state.bg_brush = CreateSolidBrush(RGB(43, 43, 43));
  const BOOL use_dark = TRUE;
  DwmSetWindowAttribute(state.hwnd, 20, &use_dark, sizeof(use_dark));
  DwmSetWindowAttribute(state.hwnd, 19, &use_dark, sizeof(use_dark));

  LOGFONTW lf{};
  lf.lfHeight = -MulDiv(12, static_cast<int>(state.dpi), 96);
  lf.lfWeight = FW_NORMAL;
  wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
  state.font = CreateFontIndirectW(&lf);
  if (!state.font) {
    state.font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  }
  auto px = [&state](float dip) { return static_cast<int>(std::lround(dip * state.scale)); };

  CreateWindowExW(0, L"STATIC", L"地址", WS_CHILD | WS_VISIBLE, px(16.0f), px(18.0f), px(60.0f), px(18.0f), state.hwnd,
                  nullptr, GetModuleHandleW(nullptr), nullptr);
  state.edit_addr = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    px(78.0f), px(14.0f), px(250.0f), px(24.0f), state.hwnd,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditAddress)),
                                    GetModuleHandleW(nullptr), nullptr);
  CreateWindowExW(0, L"STATIC", L"= ???", WS_CHILD | WS_VISIBLE,
                  px(336.0f), px(18.0f), px(120.0f), px(18.0f), state.hwnd,
                  nullptr, GetModuleHandleW(nullptr), nullptr);
  CreateWindowExW(0, L"STATIC", L"描述", WS_CHILD | WS_VISIBLE, px(16.0f), px(52.0f), px(60.0f), px(18.0f), state.hwnd,
                  nullptr, GetModuleHandleW(nullptr), nullptr);
  state.edit_desc = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    px(78.0f), px(48.0f), px(400.0f), px(24.0f), state.hwnd,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditDesc)),
                                    GetModuleHandleW(nullptr), nullptr);
  CreateWindowExW(0, L"STATIC", L"类型", WS_CHILD | WS_VISIBLE, px(16.0f), px(86.0f), px(60.0f), px(18.0f), state.hwnd,
                  nullptr, GetModuleHandleW(nullptr), nullptr);
  state.combo_type = CreateWindowExW(0, L"COMBOBOX", nullptr,
                                     WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                     px(78.0f), px(82.0f), px(124.0f), px(220.0f), state.hwnd,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlComboType)),
                                     GetModuleHandleW(nullptr), nullptr);
  state.check_hex = CreateWindowExW(0, L"BUTTON", L"十六进制", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                    px(220.0f), px(84.0f), px(96.0f), px(22.0f), state.hwnd,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckHex)),
                                    GetModuleHandleW(nullptr), nullptr);
  state.check_signed = CreateWindowExW(0, L"BUTTON", L"有符号", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                       px(320.0f), px(84.0f), px(96.0f), px(22.0f), state.hwnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckSigned)),
                                       GetModuleHandleW(nullptr), nullptr);

  state.check_pointer = CreateWindowExW(0, L"BUTTON", L"指针", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                        px(16.0f), px(122.0f), px(80.0f), px(22.0f), state.hwnd,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckPointer)),
                                        GetModuleHandleW(nullptr), nullptr);
  state.label_offsets = CreateWindowExW(0, L"STATIC", L"偏移链", WS_CHILD | WS_VISIBLE,
                                        px(16.0f), px(148.0f), px(60.0f), px(18.0f), state.hwnd,
                                        nullptr, GetModuleHandleW(nullptr), nullptr);
  state.list_offsets = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", nullptr,
                                       WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
                                       px(78.0f), px(146.0f), px(220.0f), px(110.0f), state.hwnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlListOffsets)),
                                       GetModuleHandleW(nullptr), nullptr);
  state.edit_offset = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                      px(310.0f), px(146.0f), px(116.0f), px(24.0f), state.hwnd,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditOffset)),
                                      GetModuleHandleW(nullptr), nullptr);
  state.btn_add = CreateWindowExW(0, L"BUTTON", L"添加", WS_CHILD | WS_VISIBLE,
                                  px(438.0f), px(146.0f), px(64.0f), px(24.0f), state.hwnd,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlBtnAddOffset)),
                                  GetModuleHandleW(nullptr), nullptr);
  state.btn_del = CreateWindowExW(0, L"BUTTON", L"删除", WS_CHILD | WS_VISIBLE,
                                  px(438.0f), px(176.0f), px(64.0f), px(24.0f), state.hwnd,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlBtnDelOffset)),
                                  GetModuleHandleW(nullptr), nullptr);
  state.label_preview = CreateWindowExW(0, L"STATIC", L"链路预览",
                                        WS_CHILD | WS_VISIBLE,
                                        px(310.0f), px(202.0f), px(190.0f), px(18.0f), state.hwnd,
                                        nullptr, GetModuleHandleW(nullptr), nullptr);
  state.text_preview = CreateWindowExW(WS_EX_CLIENTEDGE,
                                       L"EDIT",
                                       L"?? + 0 = ??",
                                       WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                       px(310.0f), px(222.0f), px(190.0f), px(70.0f), state.hwnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlPreviewText)),
                                       GetModuleHandleW(nullptr), nullptr);

  state.ok_btn = CreateWindowExW(0, L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                 state.width_px - px(188.0f), state.collapsed_h_px - px(44.0f), px(80.0f), px(26.0f), state.hwnd,
                                 reinterpret_cast<HMENU>(IDOK), GetModuleHandleW(nullptr), nullptr);
  state.cancel_btn = CreateWindowExW(0, L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE,
                                     state.width_px - px(98.0f), state.collapsed_h_px - px(44.0f), px(80.0f), px(26.0f), state.hwnd,
                                     reinterpret_cast<HMENU>(IDCANCEL), GetModuleHandleW(nullptr), nullptr);

  const wchar_t* type_names[] = {
      L"Byte",
      L"2 Bytes",
      L"4 Bytes",
      L"8 Bytes",
      L"4 Bytes (Signed)",
      L"8 Bytes (Signed)",
      L"Float",
      L"Double",
  };
  for (const wchar_t* name : type_names) {
    SendMessageW(state.combo_type, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
  }
  SendMessageW(state.combo_type, CB_SETCURSEL, static_cast<WPARAM>(TypeToIndex(preset.type)), 0);

  if (preset.address != 0) {
    wchar_t addr_buf[64] = {0};
    std::swprintf(addr_buf, sizeof(addr_buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(preset.address));
    SetWindowTextW(state.edit_addr, addr_buf);
  }
  if (!preset.description.empty()) {
    SetWindowTextW(state.edit_desc, preset.description.c_str());
  } else {
    SetWindowTextW(state.edit_desc, L"无描述");
  }

  HWND controls[] = {
      state.edit_addr, state.edit_desc, state.combo_type, state.check_hex, state.check_signed,
      state.check_pointer, state.label_offsets, state.list_offsets, state.edit_offset, state.btn_add,
      state.btn_del, state.label_preview, state.text_preview, state.ok_btn, state.cancel_btn,
  };
  for (HWND ctrl : controls) {
    if (ctrl) {
      SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(state.font), TRUE);
    }
  }

  SendMessageW(state.check_pointer, BM_SETCHECK, BST_UNCHECKED, 0);
  SetEnabledPointerControls(&state, false);
  UpdateDialogLayout(&state, false);
  UpdatePointerPreview(&state);

  if (owner) {
    EnableWindow(owner, FALSE);
  }
  ShowWindow(state.hwnd, SW_SHOW);
  SetForegroundWindow(state.hwnd);
  SetFocus(state.edit_addr);

  MSG msg{};
  while (!state.done && GetMessageW(&msg, nullptr, 0, 0)) {
    if (!IsDialogMessageW(state.hwnd, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }

  if (owner) {
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
  }

  if (state.ok) {
    *out_result = state.result;
    return true;
  }
  return false;
}

}  // namespace r3::windows_client_ng::ui
