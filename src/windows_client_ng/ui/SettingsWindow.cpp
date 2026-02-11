#include "ui/SettingsWindow.h"

#include <commctrl.h>
#include <dwmapi.h>

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cwchar>
#include <iterator>
#include <string>

namespace r3::windows_client_ng::ui {

namespace {

struct PageInfo {
  const wchar_t* name;
  const wchar_t* body;
};

constexpr int kPageGeneral = 0;
constexpr int kPageScan = 1;
constexpr int kPageHotkeys = 2;
constexpr int kPageOther = 3;

constexpr protocol::ValueType kTypeMap[] = {
    protocol::ValueType::U8,
    protocol::ValueType::U16,
    protocol::ValueType::U32,
    protocol::ValueType::U64,
    protocol::ValueType::S32,
    protocol::ValueType::S64,
    protocol::ValueType::FLOAT,
    protocol::ValueType::DOUBLE,
    protocol::ValueType::STRING,
    protocol::ValueType::AOB,
    protocol::ValueType::BINARY,
    protocol::ValueType::ALL,
};

constexpr PageInfo kPages[] = {
    {L"常规设置", L"连接目标与进程附加。"},
    {L"扫描设置", L"默认扫描类型、十六进制模式与内存区域过滤。"},
    {L"快捷键", L"当前支持:\r\n- G / Ctrl+G 跳转地址或模块(模块名[:cd|bss|a|code])\r\n- Ctrl+F 查找HEX\r\n- Ctrl+Shift+F 查找汇编\r\n- Ctrl+H 十六进制编辑\r\n- Insert 扫描结果快速添加到地址列表\r\n- Ctrl+Enter 添加并编辑扫描结果\r\n- F2 切换断点\r\n- F5 刷新\r\n- 上/下 选择地址\r\n- Enter 跳转选中地址\r\n- Shift+F10 或 Menu键 打开右键菜单\r\n- Ctrl+C 复制选中地址"},
    {L"其它", L"界面字体与地址列表刷新/冻结行为。"},
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

bool ParseUint32(const wchar_t* text, uint32_t* out) {
  if (!text || !*text) {
    return false;
  }
  wchar_t* endptr = nullptr;
  unsigned long value = std::wcstoul(text, &endptr, 0);
  if (endptr == text) {
    return false;
  }
  if (out) {
    *out = static_cast<uint32_t>(value);
  }
  return true;
}

bool ParseInt32(const wchar_t* text, int* out) {
  if (!text || !*text) {
    return false;
  }
  wchar_t* endptr = nullptr;
  long value = std::wcstol(text, &endptr, 0);
  if (endptr == text) {
    return false;
  }
  if (out) {
    *out = static_cast<int>(value);
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

}  // namespace

SettingsWindow::SettingsWindow() = default;

SettingsWindow::~SettingsWindow() {
  if (font_) {
    DeleteObject(font_);
    font_ = nullptr;
  }
  if (bg_brush_) {
    DeleteObject(bg_brush_);
    bg_brush_ = nullptr;
  }
}

bool SettingsWindow::Create(HINSTANCE instance, HWND owner) {
  if (hwnd_) {
    return true;
  }
  instance_ = instance;
  owner_ = owner;

  INITCOMMONCONTROLSEX icc{};
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_TREEVIEW_CLASSES;
  InitCommonControlsEx(&icc);

  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = SettingsWindow::StaticWndProc;
    wc.hInstance = instance_;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"R3NgSettingsWindow";
    RegisterClassExW(&wc);
    registered = true;
  }

  hwnd_ = CreateWindowExW(0,
                         L"R3NgSettingsWindow",
                         L"设置",
                         WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX,
                         CW_USEDEFAULT,
                         CW_USEDEFAULT,
                         1520,
                         1020,
                         owner_,
                         nullptr,
                         instance_,
                         this);
  if (!hwnd_) {
    return false;
  }
  dpi_ = GetDpiForWindowCompat(hwnd_);
  if (!bg_brush_) {
    bg_brush_ = CreateSolidBrush(RGB(43, 43, 43));
  }
  const BOOL use_dark = TRUE;
  DwmSetWindowAttribute(hwnd_, 20, &use_dark, sizeof(use_dark));
  DwmSetWindowAttribute(hwnd_, 19, &use_dark, sizeof(use_dark));
  ShowWindow(hwnd_, SW_SHOW);
  UpdateWindow(hwnd_);
  return true;
}

void SettingsWindow::Show() {
  if (hwnd_) {
    ShowWindow(hwnd_, SW_SHOW);
    SetForegroundWindow(hwnd_);
  }
}

bool SettingsWindow::IsOpen() const {
  return hwnd_ != nullptr;
}

void SettingsWindow::ApplySnapshot(const SettingsSnapshot& snapshot) {
  if (!hwnd_) {
    return;
  }
  if (general_edit_host_) {
    SetWindowTextW(general_edit_host_, snapshot.host.c_str());
  }
  if (general_edit_port_) {
    wchar_t buf[32] = {0};
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%u", snapshot.port);
    SetWindowTextW(general_edit_port_, buf);
  }
  if (general_edit_pid_) {
    wchar_t buf[32] = {0};
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%u", snapshot.pid);
    SetWindowTextW(general_edit_pid_, buf);
  }
  if (scan_combo_type_) {
    SendMessageW(scan_combo_type_, CB_SETCURSEL, static_cast<WPARAM>(TypeToIndex(snapshot.scan_type)), 0);
  }
  if (scan_check_hex_) {
    SendMessageW(scan_check_hex_, BM_SETCHECK, snapshot.scan_hex ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_strict_) {
    SendMessageW(scan_check_strict_, BM_SETCHECK, snapshot.scan_strict ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_strict_) {
    SendMessageW(scan_check_strict_, BM_SETCHECK, snapshot.scan_strict ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_pvm_) {
    SendMessageW(scan_check_pvm_, BM_SETCHECK, snapshot.scan_use_pvm ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_writable_) {
    SendMessageW(scan_check_writable_, BM_SETCHECK, snapshot.scan_writable ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_exec_) {
    SendMessageW(scan_check_exec_, BM_SETCHECK, snapshot.scan_exec ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_private_) {
    SendMessageW(scan_check_private_, BM_SETCHECK, snapshot.scan_private ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_image_) {
    SendMessageW(scan_check_image_, BM_SETCHECK, snapshot.scan_image ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (scan_check_mapped_) {
    SendMessageW(scan_check_mapped_, BM_SETCHECK, snapshot.scan_mapped ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (addr_edit_refresh_) {
    const int refresh_value = snapshot.address_auto_refresh ? snapshot.address_refresh_ms : 0;
    wchar_t buf[32] = {0};
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%d", refresh_value);
    SetWindowTextW(addr_edit_refresh_, buf);
  }
  if (addr_edit_freeze_) {
    wchar_t buf[32] = {0};
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%d", snapshot.address_freeze_ms);
    SetWindowTextW(addr_edit_freeze_, buf);
  }
  if (addr_check_freeze_) {
    SendMessageW(addr_check_freeze_, BM_SETCHECK, snapshot.address_freeze_enable ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (addr_check_auto_add_) {
    SendMessageW(addr_check_auto_add_, BM_SETCHECK, snapshot.address_auto_add ? BST_CHECKED : BST_UNCHECKED, 0);
  }
}

bool SettingsWindow::ReadSnapshot(SettingsSnapshot* out) const {
  if (!out) {
    return false;
  }
  SettingsSnapshot snapshot{};
  if (general_edit_host_) {
    wchar_t buf[256] = {0};
    GetWindowTextW(general_edit_host_, buf, static_cast<int>(std::size(buf)));
    snapshot.host = buf;
    if (snapshot.host.empty()) {
      snapshot.host = L"127.0.0.1";
    }
  }
  if (general_edit_port_) {
    wchar_t buf[64] = {0};
    GetWindowTextW(general_edit_port_, buf, static_cast<int>(std::size(buf)));
    uint32_t port = 0;
    if (ParseUint32(buf, &port) && port > 0 && port <= 65535) {
      snapshot.port = static_cast<uint16_t>(port);
    } else {
      snapshot.port = 12345;
    }
  }
  if (general_edit_pid_) {
    wchar_t buf[64] = {0};
    GetWindowTextW(general_edit_pid_, buf, static_cast<int>(std::size(buf)));
    uint32_t pid = 0;
    if (ParseUint32(buf, &pid)) {
      snapshot.pid = pid;
    }
  }
  if (scan_combo_type_) {
    const int idx = static_cast<int>(SendMessageW(scan_combo_type_, CB_GETCURSEL, 0, 0));
    snapshot.scan_type = IndexToType(idx);
  }
  if (scan_check_hex_) {
    snapshot.scan_hex = SendMessageW(scan_check_hex_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_strict_) {
    snapshot.scan_strict = SendMessageW(scan_check_strict_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_pvm_) {
    snapshot.scan_use_pvm = SendMessageW(scan_check_pvm_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_writable_) {
    snapshot.scan_writable = SendMessageW(scan_check_writable_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_exec_) {
    snapshot.scan_exec = SendMessageW(scan_check_exec_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_private_) {
    snapshot.scan_private = SendMessageW(scan_check_private_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_image_) {
    snapshot.scan_image = SendMessageW(scan_check_image_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (scan_check_mapped_) {
    snapshot.scan_mapped = SendMessageW(scan_check_mapped_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (addr_edit_refresh_) {
    wchar_t buf[64] = {0};
    GetWindowTextW(addr_edit_refresh_, buf, static_cast<int>(std::size(buf)));
    int value = 0;
    if (ParseInt32(buf, &value)) {
      snapshot.address_refresh_ms = value;
    }
  }
  if (addr_edit_freeze_) {
    wchar_t buf[64] = {0};
    GetWindowTextW(addr_edit_freeze_, buf, static_cast<int>(std::size(buf)));
    int value = 0;
    if (ParseInt32(buf, &value)) {
      snapshot.address_freeze_ms = value;
    }
  }
  if (addr_check_freeze_) {
    snapshot.address_freeze_enable = SendMessageW(addr_check_freeze_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (addr_check_auto_add_) {
    snapshot.address_auto_add = SendMessageW(addr_check_auto_add_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  snapshot.address_auto_refresh = snapshot.address_refresh_ms > 0;
  *out = snapshot;
  return true;
}

void SettingsWindow::BuildTree() {
  if (!tree_) return;
  SendMessageW(tree_, TVM_DELETEITEM, 0, reinterpret_cast<LPARAM>(TVI_ROOT));

  TVINSERTSTRUCTW ins{};
  ins.hParent = TVI_ROOT;
  ins.hInsertAfter = TVI_LAST;
  for (int i = 0; i < static_cast<int>(std::size(kPages)); ++i) {
    ins.item.mask = TVIF_TEXT | TVIF_PARAM;
    ins.item.pszText = const_cast<wchar_t*>(kPages[i].name);
    ins.item.lParam = i;
    HTREEITEM item = reinterpret_cast<HTREEITEM>(SendMessageW(tree_, TVM_INSERTITEM, 0, reinterpret_cast<LPARAM>(&ins)));
    if (i == 0 && item) {
      SendMessageW(tree_, TVM_SELECTITEM, TVGN_CARET, reinterpret_cast<LPARAM>(item));
    }
  }
}

void SettingsWindow::UpdatePage(int page_index) {
  if (page_index < 0 || page_index >= static_cast<int>(std::size(kPages))) {
    return;
  }
  current_page_ = page_index;
  if (title_) {
    SetWindowTextW(title_, kPages[page_index].name);
  }
  if (body_) {
    SetWindowTextW(body_, kPages[page_index].body);
  }
  ShowPageControls(page_index);
}

void SettingsWindow::AddPageControl(int page_index, HWND ctrl) {
  if (!ctrl) {
    return;
  }
  if (page_index < 0) {
    return;
  }
  if (page_controls_.size() <= static_cast<size_t>(page_index)) {
    return;
  }
  page_controls_[page_index].push_back(ctrl);
}

void SettingsWindow::ShowPageControls(int page_index) {
  bool has_controls = false;
  for (size_t i = 0; i < page_controls_.size(); ++i) {
    const int show = (static_cast<int>(i) == page_index) ? SW_SHOW : SW_HIDE;
    for (HWND ctrl : page_controls_[i]) {
      if (ctrl) {
        ShowWindow(ctrl, show);
      }
    }
    if (static_cast<int>(i) == page_index && !page_controls_[i].empty()) {
      has_controls = true;
    }
  }
  if (body_) {
    ShowWindow(body_, has_controls ? SW_HIDE : SW_SHOW);
  }
}

void SettingsWindow::LayoutControls(int width, int height) {
  const float s = static_cast<float>(dpi_) / 96.0f;
  auto px = [s](float dip) { return static_cast<int>(std::lround(dip * s)); };

  const int margin = px(30.0f);
  const int min_right_w = px(560.0f);
  int tree_w = px(380.0f);
  const int max_tree = std::max(px(250.0f), width - margin * 3 - min_right_w);
  tree_w = std::clamp(tree_w, px(250.0f), max_tree);
  const int top_h = px(54.0f);
  if (tree_) {
    MoveWindow(tree_, margin, margin, tree_w, height - margin * 2, TRUE);
  }
  const int right_x = margin + tree_w + margin;
  int right_w = width - right_x - margin;
  if (right_w < px(300.0f)) {
    right_w = px(300.0f);
  }
  if (title_) {
    MoveWindow(title_, right_x, margin, right_w, top_h, TRUE);
  }
  if (body_) {
    MoveWindow(body_, right_x, margin + top_h + px(14.0f), right_w, height - margin * 2 - top_h - px(14.0f), TRUE);
  }

  const int content_right = right_x + right_w;
  const int inner_margin = px(30.0f);
  auto right_limit_for = [&](int group_x, int group_w) { return group_x + group_w - inner_margin; };
  auto clamp_w = [&](int x, int w, int right_limit) {
    return std::max(px(40.0f), std::min(w, right_limit - x));
  };

  const int y_start = margin + top_h + px(14.0f);
  const int group_w = right_w;

  const int g1_h = px(190.0f);
  const int g2_h = px(198.0f);
  const int gap = px(18.0f);

  if (general_group_conn_) {
    const int gx = right_x;
    const int gy = y_start;
    MoveWindow(general_group_conn_, gx, gy, group_w, g1_h, TRUE);
    const int rl = right_limit_for(gx, group_w);
    const int label_w = px(64.0f);
    const int field_h = px(38.0f);
    const int line1_y = gy + px(40.0f);
    const int line2_y = gy + px(96.0f);
    const int x0 = gx + inner_margin;
    const int host_edit_x = x0 + label_w + px(6.0f);
    const int port_edit_w = std::max(px(90.0f), (group_w - px(320.0f)) / 3);
    const int host_edit_w = std::max(px(200.0f), rl - host_edit_x - px(58.0f) - px(8.0f) - port_edit_w - px(4.0f));
    const int port_label_x = host_edit_x + host_edit_w + px(12.0f);
    const int port_edit_x = port_label_x + px(48.0f) + px(6.0f);

    MoveWindow(general_label_host_, x0, line1_y + px(9.0f), label_w, px(24.0f), TRUE);
    MoveWindow(general_edit_host_, host_edit_x, line1_y, clamp_w(host_edit_x, host_edit_w, rl), field_h, TRUE);
    MoveWindow(general_label_port_, port_label_x, line1_y + px(9.0f), px(48.0f), px(24.0f), TRUE);
    MoveWindow(general_edit_port_, port_edit_x, line1_y, clamp_w(port_edit_x, port_edit_w, rl), field_h, TRUE);

    const int btn_w = std::max(px(92.0f), std::min(px(128.0f), (group_w - px(240.0f)) / 4));
    const int connect_x = host_edit_x;
    const int disconnect_x = connect_x + btn_w + px(10.0f);
    const int auto_x = disconnect_x + btn_w + px(12.0f);
    MoveWindow(general_btn_connect_, connect_x, line2_y, clamp_w(connect_x, btn_w, rl), px(38.0f), TRUE);
    MoveWindow(general_btn_disconnect_, disconnect_x, line2_y, clamp_w(disconnect_x, btn_w, rl), px(38.0f), TRUE);
    MoveWindow(general_check_auto_connect_, auto_x, line2_y + px(8.0f), clamp_w(auto_x, px(280.0f), rl), px(24.0f), TRUE);
  }
  if (general_group_proc_) {
    const int y2 = y_start + g1_h + gap;
    const int gx = right_x;
    const int rl = right_limit_for(gx, group_w);
    const int x0 = gx + inner_margin;
    const int label_w = px(64.0f);
    const int field_h = px(38.0f);
    const int row_y = y2 + px(40.0f);
    const int pid_edit_x = x0 + label_w + px(6.0f);
    const int pid_w = std::max(px(150.0f), (group_w - px(280.0f)) / 3);
    const int select_x = pid_edit_x + pid_w + px(12.0f);
    const int button_gap = px(10.0f);
    const int min_button_w = px(100.0f);
    const int max_button_w = px(150.0f);
    const int available_for_buttons = rl - select_x;
    bool wrap_buttons = available_for_buttons < (min_button_w * 2 + button_gap);
    int btn_w = min_button_w;
    if (!wrap_buttons) {
      btn_w = std::clamp((available_for_buttons - button_gap) / 2, min_button_w, max_button_w);
    } else {
      btn_w = std::clamp(available_for_buttons, min_button_w, max_button_w);
    }
    const int attach_x = wrap_buttons ? select_x : (select_x + btn_w + button_gap);
    const int attach_y = wrap_buttons ? (row_y + px(44.0f)) : row_y;
    const int group_h = g2_h + (wrap_buttons ? px(48.0f) : 0);
    MoveWindow(general_group_proc_, gx, y2, group_w, group_h, TRUE);

    MoveWindow(general_label_pid_, x0, row_y + px(9.0f), label_w, px(24.0f), TRUE);
    MoveWindow(general_edit_pid_, pid_edit_x, row_y, clamp_w(pid_edit_x, pid_w, rl), field_h, TRUE);
    MoveWindow(general_btn_select_proc_, select_x, row_y, clamp_w(select_x, btn_w, rl), px(38.0f), TRUE);
    MoveWindow(general_btn_attach_, attach_x, attach_y, clamp_w(attach_x, btn_w, rl), px(38.0f), TRUE);
  }

  if (scan_group_strategy_) {
    const int gx = right_x;
    const int gy = y_start;
    MoveWindow(scan_group_strategy_, gx, gy, group_w, px(194.0f), TRUE);
    const int rl = right_limit_for(gx, group_w);
    const int x0 = gx + inner_margin;
    MoveWindow(scan_check_strict_, x0, gy + px(36.0f), clamp_w(x0, px(280.0f), rl), px(24.0f), TRUE);
    MoveWindow(scan_check_pvm_, x0, gy + px(72.0f), clamp_w(x0, px(340.0f), rl), px(24.0f), TRUE);
    MoveWindow(scan_label_type_, x0, gy + px(114.0f), px(90.0f), px(24.0f), TRUE);
    const int combo_x = x0 + px(82.0f);
    const int combo_w = std::max(px(160.0f), std::min(px(230.0f), rl - combo_x - px(150.0f)));
    MoveWindow(scan_combo_type_, combo_x, gy + px(108.0f), clamp_w(combo_x, combo_w, rl), px(240.0f), TRUE);
    const int hex_x = combo_x + combo_w + px(10.0f);
    MoveWindow(scan_check_hex_, hex_x, gy + px(114.0f), clamp_w(hex_x, px(150.0f), rl), px(24.0f), TRUE);
  }
  if (scan_group_region_) {
    const int y2 = y_start + px(180.0f) + gap;
    MoveWindow(scan_group_region_, right_x, y2, group_w, px(184.0f), TRUE);
    const int rl = right_limit_for(right_x, group_w);
    int cx = right_x + inner_margin;
    int cy = y2 + px(30.0f);
    const int item_h = px(26.0f);
    const int row_gap = px(12.0f);
    const int item_w = px(104.0f);
    HWND items[] = {scan_check_writable_, scan_check_exec_, scan_check_private_, scan_check_image_, scan_check_mapped_};
    for (HWND item : items) {
      if (!item) {
        continue;
      }
      if (cx + item_w > rl) {
        cx = right_x + inner_margin;
        cy += item_h + row_gap;
      }
      MoveWindow(item, cx, cy, clamp_w(cx, item_w, rl), item_h, TRUE);
      cx += item_w + px(10.0f);
    }
  }

  if (font_label_ui_) {
    const int x0 = right_x + inner_margin;
    const int rl = content_right - inner_margin;
    const int combo_x = x0 + px(94.0f);
    const int combo_w = std::max(px(170.0f), rl - combo_x);
    MoveWindow(font_label_ui_, x0, y_start + px(10.0f), px(88.0f), px(24.0f), TRUE);
    MoveWindow(font_combo_ui_, combo_x, y_start + px(2.0f), combo_w, px(220.0f), TRUE);
    MoveWindow(font_label_mono_, x0, y_start + px(62.0f), px(88.0f), px(24.0f), TRUE);
    MoveWindow(font_combo_mono_, combo_x, y_start + px(50.0f), combo_w, px(220.0f), TRUE);
    MoveWindow(font_preview_, x0, y_start + px(116.0f), rl - x0, px(90.0f), TRUE);
  }

  if (lang_label_) {
    const int x0 = right_x + inner_margin;
    const int rl = content_right - inner_margin;
    const int combo_x = x0 + px(56.0f);
    MoveWindow(lang_label_, x0, y_start + px(6.0f), px(50.0f), px(18.0f), TRUE);
    MoveWindow(lang_combo_, combo_x, y_start + px(2.0f), std::max(px(160.0f), rl - combo_x), px(220.0f), TRUE);
    MoveWindow(lang_check_auto_, x0, y_start + px(36.0f), rl - x0, px(20.0f), TRUE);
  }

  if (addr_group_) {
    const int gy = y_start + px(250.0f);
    MoveWindow(addr_group_, right_x, gy, group_w, px(194.0f), TRUE);
    const int rl = right_limit_for(right_x, group_w);
    const int x0 = right_x + inner_margin;
    const int field_w = px(108.0f);
    MoveWindow(addr_label_refresh_, x0, gy + px(40.0f), px(112.0f), px(24.0f), TRUE);
    MoveWindow(addr_edit_refresh_, x0 + px(118.0f), gy + px(36.0f), field_w, px(30.0f), TRUE);
    int freeze_label_x = x0 + px(238.0f);
    if (freeze_label_x + px(200.0f) > rl) {
      freeze_label_x = x0;
    }
    MoveWindow(addr_label_freeze_, freeze_label_x, gy + px(40.0f), px(112.0f), px(24.0f), TRUE);
    MoveWindow(addr_edit_freeze_, freeze_label_x + px(118.0f), gy + px(36.0f), clamp_w(freeze_label_x + px(118.0f), field_w, rl), px(30.0f), TRUE);
    MoveWindow(addr_check_freeze_, x0, gy + px(86.0f), clamp_w(x0, px(220.0f), rl), px(24.0f), TRUE);
    MoveWindow(addr_check_auto_add_, x0 + px(228.0f), gy + px(86.0f), clamp_w(x0 + px(228.0f), px(340.0f), rl), px(24.0f), TRUE);
  }

  if (script_label_dir_) {
    const int x0 = right_x + inner_margin;
    const int rl = content_right - inner_margin;
    MoveWindow(script_label_dir_, x0, y_start + px(6.0f), px(70.0f), px(18.0f), TRUE);
    const int browse_w = px(72.0f);
    MoveWindow(script_btn_browse_, rl - browse_w, y_start + px(2.0f), browse_w, px(24.0f), TRUE);
    MoveWindow(script_edit_dir_, x0 + px(76.0f), y_start + px(2.0f), std::max(px(140.0f), rl - browse_w - px(8.0f) - (x0 + px(76.0f))), px(24.0f), TRUE);
    MoveWindow(script_check_auto_, x0, y_start + px(36.0f), rl - x0, px(20.0f), TRUE);
    MoveWindow(script_list_, x0, y_start + px(64.0f), rl - x0, px(172.0f), TRUE);
  }
}

LRESULT CALLBACK SettingsWindow::StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  SettingsWindow* self = reinterpret_cast<SettingsWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    self = reinterpret_cast<SettingsWindow*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
  }
  if (!self) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }
  return self->WndProc(hwnd, msg, wparam, lparam);
}

LRESULT SettingsWindow::WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  switch (msg) {
    case WM_GETMINMAXINFO: {
      MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lparam);
      if (mmi) {
        mmi->ptMinTrackSize.x = static_cast<LONG>(1220);
        mmi->ptMinTrackSize.y = static_cast<LONG>(790);
      }
      return 0;
    }
    case WM_CREATE: {
      if (!font_) {
        LOGFONTW lf{};
        lf.lfHeight = -MulDiv(21, static_cast<int>(dpi_), 96);
        lf.lfWeight = FW_NORMAL;
        wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
        font_ = CreateFontIndirectW(&lf);
        if (!font_) {
          font_ = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        }
      }
      tree_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
                              0, 0, 0, 0, hwnd, nullptr, instance_, nullptr);
      title_ = CreateWindowExW(0, L"STATIC", L"",
                               WS_CHILD | WS_VISIBLE,
                               0, 0, 0, 0, hwnd, nullptr, instance_, nullptr);
      body_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"",
                              WS_CHILD | WS_VISIBLE | SS_LEFT | SS_EDITCONTROL,
                              0, 0, 0, 0, hwnd, nullptr, instance_, nullptr);
      SendMessageW(tree_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
      SendMessageW(title_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
      SendMessageW(body_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
      SendMessageW(tree_, TVM_SETBKCOLOR, 0, RGB(43, 43, 43));
      SendMessageW(tree_, TVM_SETTEXTCOLOR, 0, RGB(230, 230, 230));
      SendMessageW(tree_, TVM_SETITEMHEIGHT, static_cast<WPARAM>(MulDiv(50, static_cast<int>(dpi_), 96)), 0);

      page_controls_.assign(static_cast<size_t>(std::size(kPages)), {});

      auto make_ctrl = [&](int page,
                           DWORD ex_style,
                           const wchar_t* cls,
                           const wchar_t* text,
                           DWORD style) -> HWND {
        HWND ctrl = CreateWindowExW(ex_style,
                                    cls,
                                    text,
                                    style | WS_CHILD,
                                    0, 0, 0, 0,
                                    hwnd,
                                    nullptr,
                                    instance_,
                                    nullptr);
        if (ctrl) {
          SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
          AddPageControl(page, ctrl);
        }
        return ctrl;
      };

      // 常规
      general_group_conn_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"连接", WS_VISIBLE | BS_GROUPBOX);
      general_group_proc_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"进程", WS_VISIBLE | BS_GROUPBOX);
      general_label_host_ = make_ctrl(kPageGeneral, 0, L"STATIC", L"主机", WS_VISIBLE);
      general_label_port_ = make_ctrl(kPageGeneral, 0, L"STATIC", L"端口", WS_VISIBLE);
      general_label_pid_ = make_ctrl(kPageGeneral, 0, L"STATIC", L"PID", WS_VISIBLE);
      general_edit_host_ = make_ctrl(kPageGeneral, WS_EX_CLIENTEDGE, L"EDIT", L"127.0.0.1",
                                      WS_VISIBLE | ES_AUTOHSCROLL);
      general_edit_port_ = make_ctrl(kPageGeneral, WS_EX_CLIENTEDGE, L"EDIT", L"12345",
                                      WS_VISIBLE | ES_AUTOHSCROLL);
      general_edit_pid_ = make_ctrl(kPageGeneral, WS_EX_CLIENTEDGE, L"EDIT", L"-",
                                     WS_VISIBLE | ES_AUTOHSCROLL);
      general_btn_connect_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"连接", WS_VISIBLE);
      general_btn_disconnect_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"断开", WS_VISIBLE);
      general_btn_select_proc_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"选择进程", WS_VISIBLE);
      general_btn_attach_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"打开进程", WS_VISIBLE);
      general_check_auto_connect_ = make_ctrl(kPageGeneral, 0, L"BUTTON", L"启动后自动连接", WS_VISIBLE | BS_AUTOCHECKBOX);

      // 扫描设置
      scan_group_strategy_ = make_ctrl(kPageScan, 0, L"BUTTON", L"扫描策略", WS_VISIBLE | BS_GROUPBOX);
      scan_group_region_ = make_ctrl(kPageScan, 0, L"BUTTON", L"内存区域", WS_VISIBLE | BS_GROUPBOX);
      scan_check_strict_ = make_ctrl(kPageScan, 0, L"BUTTON", L"严格不漏(冻结进程)", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_check_pvm_ = make_ctrl(kPageScan, 0, L"BUTTON", L"系统读取(process_vm_readv)", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_label_type_ = make_ctrl(kPageScan, 0, L"STATIC", L"默认类型", WS_VISIBLE);
      scan_combo_type_ = make_ctrl(kPageScan, 0, L"COMBOBOX", L"",
                                    WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL);
      scan_check_hex_ = make_ctrl(kPageScan, 0, L"BUTTON", L"默认十六进制", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_check_writable_ = make_ctrl(kPageScan, 0, L"BUTTON", L"可写", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_check_exec_ = make_ctrl(kPageScan, 0, L"BUTTON", L"可执行", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_check_private_ = make_ctrl(kPageScan, 0, L"BUTTON", L"私有", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_check_image_ = make_ctrl(kPageScan, 0, L"BUTTON", L"映像", WS_VISIBLE | BS_AUTOCHECKBOX);
      scan_check_mapped_ = make_ctrl(kPageScan, 0, L"BUTTON", L"映射", WS_VISIBLE | BS_AUTOCHECKBOX);
      if (scan_combo_type_) {
        const wchar_t* types[] = {
            L"1 Byte",
            L"2 Bytes",
            L"4 Bytes",
            L"8 Bytes",
            L"4 Bytes (Signed)",
            L"8 Bytes (Signed)",
            L"Float",
            L"Double",
            L"String",
            L"Array of Byte",
            L"Binary",
            L"All",
        };
        for (const wchar_t* name : types) {
          SendMessageW(scan_combo_type_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
        }
        SendMessageW(scan_combo_type_, CB_SETCURSEL, 2, 0);
      }

      // 其它(字体)
      font_label_ui_ = make_ctrl(kPageOther, 0, L"STATIC", L"界面字体", WS_VISIBLE);
      font_label_mono_ = make_ctrl(kPageOther, 0, L"STATIC", L"等宽字体", WS_VISIBLE);
      font_combo_ui_ = make_ctrl(kPageOther, 0, L"COMBOBOX", L"",
                                  WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL);
      font_combo_mono_ = make_ctrl(kPageOther, 0, L"COMBOBOX", L"",
                                    WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL);
      font_preview_ = make_ctrl(kPageOther, WS_EX_CLIENTEDGE, L"STATIC", L"示例: 0123456789 ABCDEF",
                                 WS_VISIBLE | SS_LEFT);
      if (font_combo_ui_) {
        const wchar_t* ui_fonts[] = {L"Noto Sans CJK SC", L"Microsoft YaHei UI", L"Segoe UI"};
        for (const wchar_t* name : ui_fonts) {
          SendMessageW(font_combo_ui_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
        }
        SendMessageW(font_combo_ui_, CB_SETCURSEL, 0, 0);
      }
      if (font_combo_mono_) {
        const wchar_t* mono_fonts[] = {L"JetBrains Mono", L"Consolas"};
        for (const wchar_t* name : mono_fonts) {
          SendMessageW(font_combo_mono_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
        }
        SendMessageW(font_combo_mono_, CB_SETCURSEL, 0, 0);
      }

      // 其它(地址列表)
      addr_group_ = make_ctrl(kPageOther, 0, L"BUTTON", L"刷新与冻结", WS_VISIBLE | BS_GROUPBOX);
      addr_label_refresh_ = make_ctrl(kPageOther, 0, L"STATIC", L"刷新间隔(ms)", WS_VISIBLE);
      addr_label_freeze_ = make_ctrl(kPageOther, 0, L"STATIC", L"冻结间隔(ms)", WS_VISIBLE);
      addr_edit_refresh_ = make_ctrl(kPageOther, WS_EX_CLIENTEDGE, L"EDIT", L"500",
                                      WS_VISIBLE | ES_AUTOHSCROLL);
      addr_edit_freeze_ = make_ctrl(kPageOther, WS_EX_CLIENTEDGE, L"EDIT", L"100",
                                     WS_VISIBLE | ES_AUTOHSCROLL);
      addr_check_freeze_ = make_ctrl(kPageOther, 0, L"BUTTON", L"启用冻结循环", WS_VISIBLE | BS_AUTOCHECKBOX);
      addr_check_auto_add_ = make_ctrl(kPageOther, 0, L"BUTTON", L"扫描后自动添加到列表", WS_VISIBLE | BS_AUTOCHECKBOX);

      BuildTree();
      UpdatePage(0);
      RECT rc{};
      GetClientRect(hwnd, &rc);
      LayoutControls(rc.right - rc.left, rc.bottom - rc.top);
      return 0;
    }
    case WM_SIZE: {
      const int width = LOWORD(lparam);
      const int height = HIWORD(lparam);
      LayoutControls(width, height);
      return 0;
    }
    case WM_NOTIFY: {
      const NMHDR* hdr = reinterpret_cast<const NMHDR*>(lparam);
      if (hdr && hdr->hwndFrom == tree_ && hdr->code == TVN_SELCHANGEDW) {
        const auto* change = reinterpret_cast<const NMTREEVIEWW*>(lparam);
        const int index = static_cast<int>(change->itemNew.lParam);
        UpdatePage(index);
      }
      return 0;
    }
    case WM_COMMAND: {
      const UINT code = HIWORD(wparam);
      HWND ctrl = reinterpret_cast<HWND>(lparam);
      if (ctrl == general_btn_connect_) {
        if (owner_) {
          SendMessageW(owner_, WM_COMMAND, kSettingsCmdConnect, 0);
        }
        return 0;
      }
      if (ctrl == general_btn_disconnect_) {
        if (owner_) {
          SendMessageW(owner_, WM_COMMAND, kSettingsCmdDisconnect, 0);
        }
        return 0;
      }
      if (ctrl == general_btn_select_proc_) {
        if (owner_) {
          SendMessageW(owner_, WM_COMMAND, kSettingsCmdSelectProcess, 0);
        }
        return 0;
      }
      if (ctrl == general_btn_attach_) {
        if (owner_) {
          SendMessageW(owner_, WM_COMMAND, kSettingsCmdAttachProcess, 0);
        }
        return 0;
      }
      if (code == BN_CLICKED || code == CBN_SELCHANGE || code == EN_CHANGE) {
        if (owner_) {
          SendMessageW(owner_, WM_COMMAND, kSettingsCmdChanged, 0);
        }
        return 0;
      }
      return 0;
    }
    case WM_DPICHANGED: {
      const UINT new_dpi = LOWORD(wparam);
      dpi_ = new_dpi == 0 ? 96 : new_dpi;
      if (font_) {
        DeleteObject(font_);
        font_ = nullptr;
      }
      LOGFONTW lf{};
      lf.lfHeight = -MulDiv(21, static_cast<int>(dpi_), 96);
      lf.lfWeight = FW_NORMAL;
      wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
      font_ = CreateFontIndirectW(&lf);
      if (!font_) {
        font_ = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
      }
      if (tree_) SendMessageW(tree_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
      if (tree_) SendMessageW(tree_, TVM_SETITEMHEIGHT, static_cast<WPARAM>(MulDiv(50, static_cast<int>(dpi_), 96)), 0);
      if (title_) SendMessageW(title_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
      if (body_) SendMessageW(body_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
      for (const auto& page : page_controls_) {
        for (HWND ctrl : page) {
          if (ctrl) {
            SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
          }
        }
      }
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
      RECT rc{};
      GetClientRect(hwnd, &rc);
      LayoutControls(rc.right - rc.left, rc.bottom - rc.top);
      return 0;
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      SetTextColor(hdc, RGB(230, 230, 230));
      SetBkColor(hdc, RGB(43, 43, 43));
      return reinterpret_cast<LRESULT>(bg_brush_);
    }
    case WM_ERASEBKGND: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      RECT rc{};
      GetClientRect(hwnd, &rc);
      FillRect(hdc, &rc, bg_brush_ ? bg_brush_ : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
      return 1;
    }
    case WM_CLOSE:
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      hwnd_ = nullptr;
      tree_ = nullptr;
      title_ = nullptr;
      body_ = nullptr;
      page_controls_.clear();
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

}  // namespace r3::windows_client_ng::ui
