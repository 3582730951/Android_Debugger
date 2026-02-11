#include "ui/PointerToolsWindow.h"

#include <commdlg.h>
#include <commctrl.h>
#include <dwmapi.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace r3::windows_client_ng::ui {

namespace {

constexpr UINT kCtrlEditA = 71001;
constexpr UINT kCtrlEditB = 71002;
constexpr UINT kCtrlEditDepth = 71003;
constexpr UINT kCtrlEditMaxOffset = 71004;
constexpr UINT kCtrlEditMaxResults = 71005;
constexpr UINT kCtrlEditMaxEntries = 71006;
constexpr UINT kCtrlEditStride = 71007;
constexpr UINT kCtrlComboPointerSize = 71008;
constexpr UINT kCtrlComboType = 71009;
constexpr UINT kCtrlCheckUsePvm = 71010;
constexpr UINT kCtrlCheckAllowNonresident = 71011;
constexpr UINT kCtrlCheckByteStep = 71012;
constexpr UINT kCtrlCheckStrict = 71013;
constexpr UINT kCtrlCheckAutoPointer = 71014;
constexpr UINT kCtrlBtnBuild = 71020;
constexpr UINT kCtrlBtnRun = 71021;
constexpr UINT kCtrlBtnClear = 71022;
constexpr UINT kCtrlListResult = 71023;
constexpr UINT kCtrlStatus = 71024;
constexpr UINT kCtrlBtnSave = 71025;
constexpr UINT kCtrlBtnBrowseA = 71026;
constexpr UINT kCtrlBtnBrowseB = 71027;
constexpr UINT kCtrlBtnBrowseOutput = 71028;
constexpr UINT kCtrlEditOutput = 71029;

constexpr UINT kMenuTraverseRun = 71201;
constexpr UINT kMenuTraverseRefresh = 71202;
constexpr UINT kMenuTraverseClose = 71203;
constexpr UINT kMenuTraverseFocusAddr = 71204;
constexpr UINT kMenuTraverseTypeByte = 71210;
constexpr UINT kMenuTraverseType2Bytes = 71211;
constexpr UINT kMenuTraverseType4Bytes = 71212;
constexpr UINT kMenuTraverseType8Bytes = 71213;
constexpr UINT kMenuTraverseTypeFloat = 71214;
constexpr UINT kMenuTraverseTypeDouble = 71215;
constexpr UINT kMenuTraverseTypePointer = 71216;
constexpr UINT kMenuTraverseCount32 = 71220;
constexpr UINT kMenuTraverseCount64 = 71221;
constexpr UINT kMenuTraverseCount128 = 71222;
constexpr UINT kMenuTraverseCount256 = 71223;
constexpr UINT kMenuTraverseStride1 = 71230;
constexpr UINT kMenuTraverseStride2 = 71231;
constexpr UINT kMenuTraverseStride4 = 71232;
constexpr UINT kMenuTraverseStride8 = 71233;
constexpr UINT kMenuTraverseStride16 = 71234;
constexpr UINT kMenuTraverseToggleAutoPointer = 71240;
constexpr UINT kMenuTraverseToggleUsePvm = 71241;
constexpr UINT kMenuTraverseCtxToggleExpand = 71250;
constexpr UINT kMenuTraverseCtxCopyAddr = 71251;
constexpr UINT kMenuTraverseCtxCopyValue = 71252;
constexpr UINT kMenuTraverseCtxAddToList = 71253;

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

std::wstring TrimText(const std::wstring& text) {
  const wchar_t* ws = L" \t\r\n";
  const size_t begin = text.find_first_not_of(ws);
  if (begin == std::wstring::npos) {
    return L"";
  }
  const size_t end = text.find_last_not_of(ws);
  return text.substr(begin, end - begin + 1);
}

std::wstring ReadWindowText(HWND hwnd) {
  if (!hwnd) {
    return L"";
  }
  const int len = GetWindowTextLengthW(hwnd);
  if (len <= 0) {
    return L"";
  }
  std::wstring out(static_cast<size_t>(len), L'\0');
  GetWindowTextW(hwnd, out.data(), len + 1);
  return out;
}

bool IsChecked(HWND hwnd) {
  return hwnd && SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

int ComboSel(HWND hwnd) {
  if (!hwnd) {
    return -1;
  }
  return static_cast<int>(SendMessageW(hwnd, CB_GETCURSEL, 0, 0));
}

bool CopyTextToClipboard(HWND owner, const std::wstring& text) {
  if (text.empty()) {
    return false;
  }
  if (!OpenClipboard(owner)) {
    return false;
  }
  EmptyClipboard();
  const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
  HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (!mem) {
    CloseClipboard();
    return false;
  }
  void* dst = GlobalLock(mem);
  if (!dst) {
    GlobalFree(mem);
    CloseClipboard();
    return false;
  }
  std::memcpy(dst, text.c_str(), bytes);
  GlobalUnlock(mem);
  SetClipboardData(CF_UNICODETEXT, mem);
  CloseClipboard();
  return true;
}

protocol::ValueType TraverseTypeToValueType(int type_idx, uint32_t pointer_size) {
  switch (type_idx) {
    case 0:
      return protocol::ValueType::U8;
    case 1:
      return protocol::ValueType::U16;
    case 2:
      return protocol::ValueType::U32;
    case 3:
      return protocol::ValueType::U64;
    case 4:
      return protocol::ValueType::FLOAT;
    case 5:
      return protocol::ValueType::DOUBLE;
    case 6:
      return pointer_size == 4 ? protocol::ValueType::U32 : protocol::ValueType::U64;
    default:
      return protocol::ValueType::U32;
  }
}

int MenuTypeCmdToIndex(UINT cmd) {
  switch (cmd) {
    case kMenuTraverseTypeByte:
      return 0;
    case kMenuTraverseType2Bytes:
      return 1;
    case kMenuTraverseType4Bytes:
      return 2;
    case kMenuTraverseType8Bytes:
      return 3;
    case kMenuTraverseTypeFloat:
      return 4;
    case kMenuTraverseTypeDouble:
      return 5;
    case kMenuTraverseTypePointer:
      return 6;
    default:
      return -1;
  }
}

int NormalizeTraverseCount(int value) {
  if (value <= 32) {
    return 32;
  }
  if (value <= 64) {
    return 64;
  }
  if (value <= 128) {
    return 128;
  }
  return 256;
}

int NormalizeTraverseStride(int value) {
  if (value <= 1) {
    return 1;
  }
  if (value <= 2) {
    return 2;
  }
  if (value <= 4) {
    return 4;
  }
  if (value <= 8) {
    return 8;
  }
  return 16;
}

std::wstring ChainKey(uint64_t base, const std::vector<int64_t>& offsets) {
  std::wstring key;
  wchar_t addr_buf[32] = {0};
  std::swprintf(addr_buf, std::size(addr_buf), L"%016llX", static_cast<unsigned long long>(base));
  key.append(addr_buf);
  for (int64_t off : offsets) {
    wchar_t off_buf[32] = {0};
    std::swprintf(off_buf, std::size(off_buf), L"|%lld", static_cast<long long>(off));
    key.append(off_buf);
  }
  return key;
}

bool SafeSubSigned(uint64_t value, int64_t offset, uint64_t* out) {
  if (!out) {
    return false;
  }
  if (offset >= 0) {
    const uint64_t u = static_cast<uint64_t>(offset);
    if (value < u) {
      return false;
    }
    *out = value - u;
    return true;
  }
  const uint64_t add = static_cast<uint64_t>(-offset);
  if (value > std::numeric_limits<uint64_t>::max() - add) {
    return false;
  }
  *out = value + add;
  return true;
}

constexpr uint32_t kPointerMagic = 0x53503352u;  // 'R3PS'
constexpr uint16_t kPointerVersion = 1;
constexpr uint64_t kPointerFlagDeltaVarint = 1u;
constexpr uint64_t kPointerFlagMultiTarget = 1u << 1;
constexpr size_t kPointerCompareLimit = 5'000'000;

struct PointerFileHeader {
  uint32_t magic = 0;
  uint16_t version = 0;
  uint16_t pointer_size = 0;
  uint32_t depth = 0;
  uint32_t reserved = 0;
  uint64_t target = 0;
  uint64_t count = 0;
  int64_t max_offset = 0;
  uint64_t flags = 0;
};

uint64_t StripTag64(uint64_t value) {
  return value & 0x00FFFFFFFFFFFFFFull;
}

void WriteVarUint(std::vector<uint8_t>* out, uint64_t value) {
  if (!out) {
    return;
  }
  while (value >= 0x80) {
    out->push_back(static_cast<uint8_t>(value) | 0x80);
    value >>= 7;
  }
  out->push_back(static_cast<uint8_t>(value));
}

void WriteVarInt(std::vector<uint8_t>* out, int64_t value) {
  const uint64_t zigzag = (static_cast<uint64_t>(value) << 1) ^ static_cast<uint64_t>(value >> 63);
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

std::streamoff PointerFileDataOffset(const PointerFileHeader& hdr) {
  if ((hdr.flags & kPointerFlagMultiTarget) != 0 && hdr.reserved > 0) {
    return static_cast<std::streamoff>(sizeof(PointerFileHeader)) +
           static_cast<std::streamoff>(hdr.reserved) * static_cast<std::streamoff>(sizeof(uint64_t));
  }
  return static_cast<std::streamoff>(sizeof(PointerFileHeader));
}

std::string ChainKeyBinary(uint64_t base, const std::vector<int64_t>& offsets) {
  std::string key;
  key.resize(sizeof(uint64_t) + offsets.size() * sizeof(int64_t));
  std::memcpy(key.data(), &base, sizeof(uint64_t));
  if (!offsets.empty()) {
    std::memcpy(reinterpret_cast<uint8_t*>(key.data()) + sizeof(uint64_t),
                offsets.data(),
                offsets.size() * sizeof(int64_t));
  }
  return key;
}

std::wstring TimestampForFileName() {
  SYSTEMTIME st{};
  GetLocalTime(&st);
  wchar_t buf[64] = {0};
  std::swprintf(buf,
                std::size(buf),
                L"%04u%02u%02u_%02u%02u%02u",
                st.wYear,
                st.wMonth,
                st.wDay,
                st.wHour,
                st.wMinute,
                st.wSecond);
  return buf;
}

std::wstring MakeDefaultPointerPath(const wchar_t* prefix) {
  std::filesystem::path dir = std::filesystem::path(L"seach_point");
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  std::wstring name = prefix ? prefix : L"pointer";
  name += L"_";
  name += TimestampForFileName();
  name += L".r3ptr";
  return (dir / name).wstring();
}

bool BrowsePathDialog(HWND owner,
                      bool save_mode,
                      const wchar_t* title,
                      const wchar_t* default_path,
                      std::wstring* out_path) {
  if (!out_path) {
    return false;
  }
  wchar_t file_buf[MAX_PATH] = {0};
  if (default_path && *default_path) {
    wcsncpy_s(file_buf, default_path, _TRUNCATE);
  }
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = owner;
  ofn.lpstrFilter = L"R3 指针文件 (*.r3ptr)\0*.r3ptr\0所有文件 (*.*)\0*.*\0\0";
  ofn.lpstrFile = file_buf;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrTitle = title;
  ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST;
  if (save_mode) {
    ofn.Flags |= OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"r3ptr";
    if (!GetSaveFileNameW(&ofn)) {
      return false;
    }
  } else {
    ofn.Flags |= OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
      return false;
    }
  }
  *out_path = file_buf;
  return !out_path->empty();
}

HBITMAP CreateTraverseArrowBitmap(int size, bool expanded) {
  const int icon = std::max(8, size);
  HDC screen_dc = GetDC(nullptr);
  if (!screen_dc) {
    return nullptr;
  }
  HDC mem_dc = CreateCompatibleDC(screen_dc);
  if (!mem_dc) {
    ReleaseDC(nullptr, screen_dc);
    return nullptr;
  }
  HBITMAP bmp = CreateCompatibleBitmap(screen_dc, icon, icon);
  if (!bmp) {
    DeleteDC(mem_dc);
    ReleaseDC(nullptr, screen_dc);
    return nullptr;
  }
  HGDIOBJ old_bmp = SelectObject(mem_dc, bmp);
  RECT rc{0, 0, icon, icon};
  HBRUSH key_bg = CreateSolidBrush(RGB(255, 0, 255));
  FillRect(mem_dc, &rc, key_bg);
  DeleteObject(key_bg);
  SetBkMode(mem_dc, TRANSPARENT);
  POINT pts[3]{};
  if (expanded) {
    pts[0] = POINT{icon / 2, icon - 3};
    pts[1] = POINT{3, 3};
    pts[2] = POINT{icon - 3, 3};
  } else {
    pts[0] = POINT{3, 3};
    pts[1] = POINT{icon - 3, icon / 2};
    pts[2] = POINT{3, icon - 3};
  }
  HBRUSH tri = CreateSolidBrush(RGB(180, 198, 220));
  HPEN pen = CreatePen(PS_SOLID, 1, RGB(180, 198, 220));
  HGDIOBJ old_pen = SelectObject(mem_dc, pen);
  HGDIOBJ old_brush = SelectObject(mem_dc, tri);
  Polygon(mem_dc, pts, 3);
  SelectObject(mem_dc, old_brush);
  SelectObject(mem_dc, old_pen);
  DeleteObject(tri);
  DeleteObject(pen);
  SelectObject(mem_dc, old_bmp);
  DeleteDC(mem_dc);
  ReleaseDC(nullptr, screen_dc);
  return bmp;
}

HIMAGELIST CreateTraverseIconList(UINT dpi) {
  const UINT used_dpi = dpi == 0 ? 96 : dpi;
  const int icon = std::max(10, MulDiv(13, static_cast<int>(used_dpi), 96));
  HIMAGELIST list = ImageList_Create(icon, icon, ILC_COLOR32 | ILC_MASK, 2, 1);
  if (!list) {
    return nullptr;
  }
  HBITMAP collapsed = CreateTraverseArrowBitmap(icon, false);
  HBITMAP expanded = CreateTraverseArrowBitmap(icon, true);
  if (collapsed) {
    ImageList_AddMasked(list, collapsed, RGB(255, 0, 255));
    DeleteObject(collapsed);
  }
  if (expanded) {
    ImageList_AddMasked(list, expanded, RGB(255, 0, 255));
    DeleteObject(expanded);
  }
  if (ImageList_GetImageCount(list) < 2) {
    ImageList_Destroy(list);
    return nullptr;
  }
  return list;
}

}  // namespace

PointerToolsWindow::PointerToolsWindow() {
  search_.owner = this;
  search_.mode = Mode::PointerSearch;
  compare_.owner = this;
  compare_.mode = Mode::PointerCompare;
  traverse_.owner = this;
  traverse_.mode = Mode::DataTraverse;
}

PointerToolsWindow::~PointerToolsWindow() {
  if (search_.hwnd) {
    DestroyWindow(search_.hwnd);
    search_.hwnd = nullptr;
  }
  if (compare_.hwnd) {
    DestroyWindow(compare_.hwnd);
    compare_.hwnd = nullptr;
  }
  if (traverse_.hwnd) {
    DestroyWindow(traverse_.hwnd);
    traverse_.hwnd = nullptr;
  }
}

bool PointerToolsWindow::Create(HINSTANCE instance,
                                HWND owner,
                                services::ClientService* service,
                                app::UiState* state) {
  instance_ = instance;
  owner_ = owner;
  service_ = service;
  state_ = state;
  return EnsureClassRegistered();
}

void PointerToolsWindow::ShowPointerSearch() { ShowWindowFor(&search_); }

void PointerToolsWindow::ShowPointerCompare() { ShowWindowFor(&compare_); }

void PointerToolsWindow::ShowDataTraverse() { ShowWindowFor(&traverse_); }

bool PointerToolsWindow::EnsureClassRegistered() {
  if (class_registered_) {
    return true;
  }
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = PointerToolsWindow::StaticWndProc;
  wc.hInstance = instance_;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.lpszClassName = L"R3NgPointerToolsWindow";
  if (!RegisterClassExW(&wc)) {
    return false;
  }
  class_registered_ = true;
  return true;
}

bool PointerToolsWindow::EnsureWindowCreated(ToolWindow* tool) {
  if (!tool) {
    return false;
  }
  if (tool->hwnd && IsWindow(tool->hwnd)) {
    return true;
  }
  if (!EnsureClassRegistered()) {
    return false;
  }

  const wchar_t* title = L"指针工具";
  int width = 1220;
  int height = 780;
  if (tool->mode == Mode::PointerSearch) {
    title = L"指针搜索";
    width = 1320;
    height = 820;
  } else if (tool->mode == Mode::PointerCompare) {
    title = L"指针对比";
    width = 1360;
    height = 840;
  } else {
    title = L"结构分析";
    width = 1280;
    height = 820;
  }

  tool->hwnd = CreateWindowExW(0,
                               L"R3NgPointerToolsWindow",
                               title,
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_SIZEBOX | WS_MAXIMIZEBOX,
                               CW_USEDEFAULT,
                               CW_USEDEFAULT,
                               width,
                               height,
                               owner_,
                               nullptr,
                               instance_,
                               tool);
  return tool->hwnd != nullptr;
}

void PointerToolsWindow::ShowWindowFor(ToolWindow* tool) {
  if (!tool) {
    return;
  }
  if (!EnsureWindowCreated(tool)) {
    MessageBoxW(owner_, L"工具窗口创建失败", L"错误", MB_OK | MB_ICONERROR);
    return;
  }
  if (tool->mode == Mode::DataTraverse) {
    UpdateTraverseMenuState(tool);
  }
  ShowWindow(tool->hwnd, SW_SHOW);
  SetForegroundWindow(tool->hwnd);
  // Keep Structure Analysis immediately actionable on open:
  // - attached process: populate rows at once
  // - detached state: show explicit status instead of blank "就绪"
  if (tool->mode == Mode::DataTraverse && tool->list) {
    RunDataTraverse(tool);
  }
}

void PointerToolsWindow::ResetIndexCache(ToolWindow* tool) {
  if (!tool) {
    return;
  }
  tool->pointer_index.clear();
  tool->pointer_size = 0;
  tool->index_ready = false;
}

void PointerToolsWindow::LayoutControls(ToolWindow* tool, int width, int height) {
  if (!tool) {
    return;
  }
  const auto px = [tool](float dip) { return static_cast<int>(std::lround(dip * tool->scale)); };
  const int margin = px(14.0f);
  const int line_h = px(32.0f);
  const int label_w = px(108.0f);
  const int status_h = px(30.0f);
  const int action_h = px(34.0f);
  const int gap = px(10.0f);
  const int left = margin;
  const int right = std::max(left + px(420.0f), width - margin);
  const int x_field = left + label_w;
  auto fit_w = [&](int x, int desired, int min_w) {
    const int avail = std::max(min_w, right - x);
    return std::max(min_w, std::min(desired, avail));
  };

  int y = margin + px(4.0f);
  if (tool->mode == Mode::DataTraverse) {
    const int panel_w = std::clamp(width / 3, px(220.0f), px(340.0f));
    if (tool->label_a) {
      MoveWindow(tool->label_a, left, y + px(2.0f), panel_w, px(22.0f), TRUE);
    }
    if (tool->edit_a) {
      MoveWindow(tool->edit_a, left, y + px(28.0f), panel_w, line_h, TRUE);
    }
    const int btn_w = px(160.0f);
    if (tool->btn_run) {
      MoveWindow(tool->btn_run, right - btn_w, y + px(22.0f), btn_w, action_h, TRUE);
    }
    y += px(72.0f) + gap;
  } else if (tool->mode == Mode::PointerCompare) {
    const int browse_w = px(96.0f);
    const int field_w = std::max(px(260.0f), right - x_field - browse_w - gap);
    if (tool->label_a) MoveWindow(tool->label_a, left, y + px(4.0f), label_w, px(24.0f), TRUE);
    if (tool->edit_a) MoveWindow(tool->edit_a, x_field, y, field_w, line_h, TRUE);
    if (tool->btn_browse_a) MoveWindow(tool->btn_browse_a, x_field + field_w + gap, y, browse_w, action_h, TRUE);
    y += line_h + gap;

    if (tool->label_b) MoveWindow(tool->label_b, left, y + px(4.0f), label_w, px(24.0f), TRUE);
    if (tool->edit_b) MoveWindow(tool->edit_b, x_field, y, field_w, line_h, TRUE);
    if (tool->btn_browse_b) MoveWindow(tool->btn_browse_b, x_field + field_w + gap, y, browse_w, action_h, TRUE);
    y += line_h + gap;

    if (tool->label_output) MoveWindow(tool->label_output, left, y + px(4.0f), label_w, px(24.0f), TRUE);
    if (tool->edit_output) MoveWindow(tool->edit_output, x_field, y, field_w, line_h, TRUE);
    if (tool->btn_browse_output) MoveWindow(tool->btn_browse_output, x_field + field_w + gap, y, browse_w, action_h, TRUE);
    y += line_h + gap;

    const int btn_w = px(130.0f);
    if (tool->btn_run) MoveWindow(tool->btn_run, x_field, y, btn_w, action_h, TRUE);
    if (tool->btn_clear) MoveWindow(tool->btn_clear, x_field + btn_w + gap, y, btn_w, action_h, TRUE);
    y += action_h + gap;
  } else {
    int w_a = fit_w(x_field, px(280.0f), px(170.0f));
    const int x_depth = x_field + w_a + gap + px(44.0f);
    const int w_depth = fit_w(x_depth, px(80.0f), px(60.0f));
    const int x_off = x_depth + w_depth + gap + px(70.0f);
    const int w_off = fit_w(x_off, px(130.0f), px(90.0f));
    const int x_result = x_off + w_off + gap + px(70.0f);
    const int w_result = fit_w(x_result, px(130.0f), px(90.0f));

    if (tool->label_a) MoveWindow(tool->label_a, left, y + px(4.0f), label_w, px(24.0f), TRUE);
    if (tool->edit_a) MoveWindow(tool->edit_a, x_field, y, w_a, line_h, TRUE);
    if (tool->label_depth) MoveWindow(tool->label_depth, x_depth - px(44.0f), y + px(4.0f), px(40.0f), px(24.0f), TRUE);
    if (tool->edit_depth) MoveWindow(tool->edit_depth, x_depth, y, w_depth, line_h, TRUE);
    if (tool->label_max_offset) MoveWindow(tool->label_max_offset, x_off - px(70.0f), y + px(4.0f), px(66.0f), px(24.0f), TRUE);
    if (tool->edit_max_offset) MoveWindow(tool->edit_max_offset, x_off, y, w_off, line_h, TRUE);
    if (tool->label_max_results) MoveWindow(tool->label_max_results, x_result - px(70.0f), y + px(4.0f), px(66.0f), px(24.0f), TRUE);
    if (tool->edit_max_results) MoveWindow(tool->edit_max_results, x_result, y, w_result, line_h, TRUE);
    y += line_h + gap;

    if (tool->label_pointer_size) MoveWindow(tool->label_pointer_size, left, y + px(4.0f), label_w, px(24.0f), TRUE);
    if (tool->combo_pointer_size) MoveWindow(tool->combo_pointer_size, x_field, y, fit_w(x_field, px(180.0f), px(122.0f)), px(260.0f), TRUE);
    const int x_max_entries = x_field + fit_w(x_field, px(180.0f), px(122.0f)) + gap + px(68.0f);
    if (tool->label_max_entries) MoveWindow(tool->label_max_entries, x_max_entries - px(68.0f), y + px(4.0f), px(64.0f), px(24.0f), TRUE);
    if (tool->edit_max_entries) MoveWindow(tool->edit_max_entries, x_max_entries, y, fit_w(x_max_entries, px(170.0f), px(120.0f)), line_h, TRUE);
    const int x_pvm = x_max_entries + fit_w(x_max_entries, px(170.0f), px(120.0f)) + gap;
    if (tool->check_use_pvm) MoveWindow(tool->check_use_pvm, x_pvm, y + px(4.0f), fit_w(x_pvm, px(120.0f), px(100.0f)), px(24.0f), TRUE);
    const int x_nonresident = x_pvm + fit_w(x_pvm, px(120.0f), px(100.0f)) + gap;
    if (tool->check_allow_nonresident) {
      MoveWindow(tool->check_allow_nonresident, x_nonresident, y + px(4.0f), fit_w(x_nonresident, px(150.0f), px(120.0f)), px(24.0f), TRUE);
    }
    y += line_h + gap;

    if (tool->check_byte_step) MoveWindow(tool->check_byte_step, x_field, y + px(4.0f), fit_w(x_field, px(120.0f), px(96.0f)), px(24.0f), TRUE);
    if (tool->check_strict) MoveWindow(tool->check_strict, x_field + px(130.0f), y + px(4.0f), fit_w(x_field + px(130.0f), px(120.0f), px(96.0f)), px(24.0f), TRUE);
    const int btn_w = px(124.0f);
    const int x_save = right - btn_w;
    const int x_clear = x_save - gap - btn_w;
    const int x_run = x_clear - gap - btn_w;
    const int x_build = x_run - gap - btn_w;
    if (tool->btn_build) MoveWindow(tool->btn_build, x_build, y, btn_w, action_h, TRUE);
    if (tool->btn_run) MoveWindow(tool->btn_run, x_run, y, btn_w, action_h, TRUE);
    if (tool->btn_clear) MoveWindow(tool->btn_clear, x_clear, y, btn_w, action_h, TRUE);
    if (tool->btn_save) MoveWindow(tool->btn_save, x_save, y, btn_w, action_h, TRUE);
    y += action_h + gap;
  }

  const int list_h = std::max(px(170.0f), height - y - status_h - margin * 2);
  if (tool->list) {
    const int list_w = std::max(px(360.0f), width - margin * 2);
    MoveWindow(tool->list, margin, y, list_w, list_h, TRUE);
    if (tool->mode == Mode::DataTraverse) {
      const int col0 = std::clamp((list_w * 27) / 100, px(220.0f), px(360.0f));
      ListView_SetColumnWidth(tool->list, 0, col0);
      ListView_SetColumnWidth(tool->list, 1, std::max(px(280.0f), list_w - col0 - px(10.0f)));
    }
  }
  y += list_h + px(8.0f);
  if (tool->status) {
    MoveWindow(tool->status, margin, y, std::max(px(360.0f), width - margin * 2), status_h, TRUE);
  }
}

void PointerToolsWindow::ConfigureListColumns(ToolWindow* tool) {
  if (!tool || !tool->list) {
    return;
  }
  ListView_DeleteAllItems(tool->list);
  while (ListView_DeleteColumn(tool->list, 0)) {
  }
  if (tool->mode == Mode::PointerSearch) {
    LVCOLUMNW c0{};
    c0.mask = LVCF_TEXT | LVCF_WIDTH;
    c0.pszText = const_cast<wchar_t*>(L"基址");
    c0.cx = 190;
    ListView_InsertColumn(tool->list, 0, &c0);
    LVCOLUMNW c1{};
    c1.mask = LVCF_TEXT | LVCF_WIDTH;
    c1.pszText = const_cast<wchar_t*>(L"偏移链");
    c1.cx = 450;
    ListView_InsertColumn(tool->list, 1, &c1);
    LVCOLUMNW c2{};
    c2.mask = LVCF_TEXT | LVCF_WIDTH;
    c2.pszText = const_cast<wchar_t*>(L"结果地址");
    c2.cx = 190;
    ListView_InsertColumn(tool->list, 2, &c2);
  } else if (tool->mode == Mode::PointerCompare) {
    LVCOLUMNW c0{};
    c0.mask = LVCF_TEXT | LVCF_WIDTH;
    c0.pszText = const_cast<wchar_t*>(L"基址");
    c0.cx = 190;
    ListView_InsertColumn(tool->list, 0, &c0);
    LVCOLUMNW c1{};
    c1.mask = LVCF_TEXT | LVCF_WIDTH;
    c1.pszText = const_cast<wchar_t*>(L"偏移链");
    c1.cx = 780;
    ListView_InsertColumn(tool->list, 1, &c1);
  } else {
    LVCOLUMNW c0{};
    c0.mask = LVCF_TEXT | LVCF_WIDTH;
    c0.pszText = const_cast<wchar_t*>(L"偏移-描述");
    c0.cx = 300;
    ListView_InsertColumn(tool->list, 0, &c0);
    LVCOLUMNW c1{};
    c1.mask = LVCF_TEXT | LVCF_WIDTH;
    c1.pszText = const_cast<wchar_t*>(L"地址:数值");
    c1.cx = 900;
    ListView_InsertColumn(tool->list, 1, &c1);
  }
}

void PointerToolsWindow::ApplyFontToChildren(ToolWindow* tool) {
  if (!tool || !tool->font || !tool->hwnd) {
    return;
  }
  HWND child = GetWindow(tool->hwnd, GW_CHILD);
  while (child) {
    SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(tool->font), TRUE);
    child = GetWindow(child, GW_HWNDNEXT);
  }
}

bool PointerToolsWindow::EnsureConnected(ToolWindow* tool, std::wstring* out_error) const {
  (void)tool;
  if (!service_ || !state_) {
    if (out_error) {
      *out_error = L"服务未初始化";
    }
    return false;
  }
  if (!service_->IsConnected()) {
    if (out_error) {
      *out_error = L"请先连接服务";
    }
    return false;
  }
  if (state_->pid == 0) {
    if (out_error) {
      *out_error = L"请先附加进程";
    }
    return false;
  }
  return true;
}

bool PointerToolsWindow::EnsureConnectedForScan(ToolWindow* tool, std::wstring* out_error) const {
  return EnsureConnected(tool, out_error);
}

bool PointerToolsWindow::BuildPointerIndex(ToolWindow* tool, bool force_rebuild, std::wstring* out_status) {
  if (!tool) {
    return false;
  }
  if (!force_rebuild && tool->index_ready && !tool->pointer_index.empty()) {
    if (out_status) {
      *out_status = L"沿用已构建索引";
    }
    return true;
  }

  std::wstring connect_error;
  if (!EnsureConnected(tool, &connect_error)) {
    if (out_status) {
      *out_status = connect_error;
    }
    return false;
  }

  const int ptr_sel = ComboSel(tool->combo_pointer_size);
  uint16_t pointer_size = 0;
  if (ptr_sel == 1) {
    pointer_size = 4;
  } else if (ptr_sel == 2) {
    pointer_size = 8;
  }

  int64_t max_entries = 500000;
  if (tool->edit_max_entries) {
    const std::wstring text = TrimText(ReadWindowText(tool->edit_max_entries));
    if (!text.empty()) {
      ParseIntText(text, &max_entries);
    }
  }
  if (max_entries <= 0) {
    max_entries = 500000;
  }
  if (max_entries > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
    max_entries = std::numeric_limits<uint32_t>::max();
  }

  uint16_t flags = 0;
  if (IsChecked(tool->check_use_pvm)) {
    flags |= protocol::PTR_INDEX_FLAG_USE_PVM;
  }
  if (IsChecked(tool->check_allow_nonresident)) {
    flags |= protocol::PTR_INDEX_FLAG_ALLOW_NONRESIDENT;
  }
  if (IsChecked(tool->check_byte_step)) {
    flags |= protocol::PTR_INDEX_FLAG_BYTE_STEP;
  }
  if (IsChecked(tool->check_strict)) {
    flags |= protocol::PTR_INDEX_FLAG_STRICT;
  }

  services::ClientService::PointerIndexBuildResult build{};
  std::string error;
  if (!service_->BuildPointerIndex(state_->pid,
                                   pointer_size,
                                   flags,
                                   static_cast<uint32_t>(max_entries),
                                   &build,
                                   &error)) {
    if (out_status) {
      *out_status = Utf8ToWide(error.empty() ? "构建索引失败" : error);
    }
    return false;
  }

  std::vector<services::ClientService::PointerIndexEntry> entries;
  entries.reserve(static_cast<size_t>(std::min<uint64_t>(build.count, 2000000ULL)));
  uint64_t total = 0;
  uint64_t start = 0;
  while (start < build.count) {
    std::vector<services::ClientService::PointerIndexEntry> page;
    if (!service_->QueryPointerIndex(start, 4096, &total, &page, &error)) {
      if (out_status) {
        *out_status = Utf8ToWide(error.empty() ? "下载索引失败" : error);
      }
      return false;
    }
    if (page.empty()) {
      break;
    }
    entries.insert(entries.end(), page.begin(), page.end());
    start += page.size();
  }

  tool->pointer_index = std::move(entries);
  tool->pointer_size = build.pointer_size == 4 || build.pointer_size == 8 ? build.pointer_size : pointer_size;
  if (tool->pointer_size == 0) {
    tool->pointer_size = state_ && state_->pointer_size ? state_->pointer_size : 8;
  }
  tool->index_ready = !tool->pointer_index.empty();

  if (out_status) {
    wchar_t buf[256] = {0};
    std::swprintf(buf,
                  std::size(buf),
                  L"索引构建完成: %llu 条，指针宽度=%u%s",
                  static_cast<unsigned long long>(tool->pointer_index.size()),
                  static_cast<unsigned>(tool->pointer_size),
                  build.truncated ? L"（已截断）" : L"");
    *out_status = buf;
  }
  return tool->index_ready;
}

bool PointerToolsWindow::SearchChains(ToolWindow* tool,
                                      uint64_t target,
                                      uint16_t depth,
                                      int64_t max_offset,
                                      size_t max_results,
                                      std::vector<services::ClientService::PointerChain>* out_chains,
                                      std::wstring* out_error) {
  if (!tool || !out_chains) {
    return false;
  }
  out_chains->clear();
  if (tool->pointer_index.empty()) {
    if (out_error) {
      *out_error = L"索引为空";
    }
    return false;
  }
  if (depth == 0) {
    if (out_error) {
      *out_error = L"层数必须大于0";
    }
    return false;
  }

  const int64_t abs_offset = std::max<int64_t>(0, std::min<int64_t>(std::llabs(max_offset), 0x2000));
  int64_t step = IsChecked(tool->check_byte_step) ? 1 : static_cast<int64_t>(tool->pointer_size == 8 ? 8 : 4);
  if (step <= 0) {
    step = 1;
  }
  std::vector<int64_t> offset_candidates;
  offset_candidates.reserve(static_cast<size_t>((abs_offset * 2) / step + 1));
  for (int64_t off = -abs_offset; off <= abs_offset; off += step) {
    offset_candidates.push_back(off);
  }
  if (std::find(offset_candidates.begin(), offset_candidates.end(), 0) == offset_candidates.end()) {
    offset_candidates.push_back(0);
  }

  std::unordered_map<uint64_t, std::vector<uint64_t>> by_value;
  by_value.reserve(tool->pointer_index.size());
  for (const auto& e : tool->pointer_index) {
    by_value[e.value].push_back(e.address);
  }

  struct SearchItem {
    uint64_t base = 0;
    std::vector<int64_t> offsets;
  };
  std::vector<SearchItem> found;
  found.reserve(max_results);
  std::vector<int64_t> reverse_offsets;
  reverse_offsets.reserve(depth);

  std::function<void(uint16_t, uint64_t)> dfs = [&](uint16_t level, uint64_t desired_addr) {
    if (found.size() >= max_results) {
      return;
    }
    for (int64_t off : offset_candidates) {
      uint64_t prev_value = 0;
      if (!SafeSubSigned(desired_addr, off, &prev_value)) {
        continue;
      }
      auto it = by_value.find(prev_value);
      if (it == by_value.end()) {
        continue;
      }
      for (uint64_t source_addr : it->second) {
        reverse_offsets.push_back(off);
        if (level == 1) {
          SearchItem item{};
          item.base = source_addr;
          item.offsets.assign(reverse_offsets.rbegin(), reverse_offsets.rend());
          found.push_back(std::move(item));
          if (found.size() >= max_results) {
            reverse_offsets.pop_back();
            return;
          }
        } else {
          dfs(static_cast<uint16_t>(level - 1), source_addr);
          if (found.size() >= max_results) {
            reverse_offsets.pop_back();
            return;
          }
        }
        reverse_offsets.pop_back();
      }
      if (found.size() >= max_results) {
        return;
      }
    }
  };
  dfs(depth, target);

  std::sort(found.begin(), found.end(), [](const SearchItem& a, const SearchItem& b) {
    if (a.base != b.base) {
      return a.base < b.base;
    }
    return a.offsets < b.offsets;
  });
  found.erase(std::unique(found.begin(), found.end(), [](const SearchItem& a, const SearchItem& b) {
                return a.base == b.base && a.offsets == b.offsets;
              }),
              found.end());

  out_chains->reserve(found.size());
  for (const auto& item : found) {
    services::ClientService::PointerChain c{};
    c.base = item.base;
    c.offsets = item.offsets;
    out_chains->push_back(std::move(c));
  }
  if (out_chains->empty()) {
    if (out_error) {
      *out_error = L"未找到符合条件的链路";
    }
    return false;
  }
  return true;
}

bool PointerToolsWindow::VerifyChains(ToolWindow* tool,
                                      uint16_t depth,
                                      const std::vector<services::ClientService::PointerChain>& chains,
                                      const std::vector<uint64_t>& targets,
                                      std::vector<services::ClientService::PointerChain>* out_verified,
                                      std::wstring* out_error) {
  if (!tool || !out_verified) {
    return false;
  }
  out_verified->clear();
  if (chains.empty()) {
    return true;
  }
  uint32_t flags = 0;
  if (IsChecked(tool->check_use_pvm)) {
    flags |= protocol::READ_FLAG_USE_PVM;
  }
  if (IsChecked(tool->check_allow_nonresident)) {
    flags |= protocol::READ_FLAG_ALLOW_NONRESIDENT;
  }

  const size_t batch_size = 256;
  std::vector<services::ClientService::PointerChain> verified;
  std::string error;
  for (size_t start = 0; start < chains.size(); start += batch_size) {
    const size_t count = std::min(batch_size, chains.size() - start);
    std::vector<uint32_t> matched;
    if (!service_->VerifyPointerChainsFilter(tool->pointer_size,
                                             depth,
                                             flags,
                                             chains,
                                             start,
                                             count,
                                             targets,
                                             &matched,
                                             &error)) {
      if (out_error) {
        *out_error = Utf8ToWide(error.empty() ? "链路验证失败" : error);
      }
      return false;
    }
    for (uint32_t idx : matched) {
      verified.push_back(chains[start + idx]);
    }
  }
  *out_verified = std::move(verified);
  return true;
}

void PointerToolsWindow::RunPointerSearch(ToolWindow* tool) {
  if (!tool || !tool->list) {
    return;
  }
  ListView_DeleteAllItems(tool->list);
  tool->search_results.clear();
  tool->search_target = 0;
  tool->search_depth = 0;
  tool->search_max_offset = 0;

  std::wstring build_status;
  if (!BuildPointerIndex(tool, false, &build_status)) {
    SetStatus(tool, build_status);
    return;
  }

  uint64_t target = 0;
  if (!ParseAddressText(ReadWindowText(tool->edit_a), &target)) {
    SetStatus(tool, L"目标地址格式无效");
    return;
  }

  int64_t depth_i = 3;
  ParseIntText(ReadWindowText(tool->edit_depth), &depth_i);
  const uint16_t depth = static_cast<uint16_t>(std::clamp<int64_t>(depth_i, 1, 6));

  int64_t max_offset = 0x400;
  ParseIntText(ReadWindowText(tool->edit_max_offset), &max_offset);

  int64_t max_results_i = 300;
  ParseIntText(ReadWindowText(tool->edit_max_results), &max_results_i);
  const size_t max_results = static_cast<size_t>(std::clamp<int64_t>(max_results_i, 1, 5000));

  std::vector<services::ClientService::PointerChain> raw_chains;
  std::wstring search_error;
  if (!SearchChains(tool, target, depth, max_offset, max_results, &raw_chains, &search_error)) {
    SetStatus(tool, search_error);
    return;
  }

  std::vector<services::ClientService::PointerChain> verified;
  if (!VerifyChains(tool, depth, raw_chains, {target}, &verified, &search_error)) {
    SetStatus(tool, search_error);
    return;
  }
  tool->search_results = verified;
  tool->search_target = target;
  tool->search_depth = depth;
  tool->search_max_offset = max_offset;

  int row = 0;
  for (const auto& chain : verified) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = row;
    std::wstring base = FormatAddress(chain.base);
    item.pszText = base.data();
    ListView_InsertItem(tool->list, &item);

    std::wstring offsets = FormatOffsets(chain.offsets);
    ListView_SetItemText(tool->list, row, 1, offsets.data());

    std::wstring target_text = FormatAddress(target);
    ListView_SetItemText(tool->list, row, 2, target_text.data());
    ++row;
  }

  wchar_t status[256] = {0};
  std::swprintf(status,
                std::size(status),
                L"%s | 原始链路=%llu，验证通过=%llu",
                build_status.c_str(),
                static_cast<unsigned long long>(raw_chains.size()),
                static_cast<unsigned long long>(verified.size()));
  SetStatus(tool, status);
}

void PointerToolsWindow::SavePointerSearchResult(ToolWindow* tool) {
  if (!tool) {
    return;
  }
  if (tool->search_results.empty()) {
    SetStatus(tool, L"当前没有可保存的指针搜索结果");
    return;
  }

  std::wstring path;
  if (!BrowsePathDialog(tool->hwnd,
                        true,
                        L"保存指针搜索结果",
                        MakeDefaultPointerPath(L"pointer_scan").c_str(),
                        &path)) {
    return;
  }

  std::vector<services::ClientService::PointerChain> chains = tool->search_results;
  std::sort(chains.begin(), chains.end(), [](const auto& a, const auto& b) {
    if (a.base != b.base) {
      return a.base < b.base;
    }
    return a.offsets < b.offsets;
  });
  chains.erase(std::unique(chains.begin(), chains.end(), [](const auto& a, const auto& b) {
                return a.base == b.base && a.offsets == b.offsets;
              }),
              chains.end());
  if (chains.empty()) {
    SetStatus(tool, L"结果为空，未写入文件");
    return;
  }

  const uint16_t pointer_size = (tool->pointer_size == 4 || tool->pointer_size == 8)
                                  ? tool->pointer_size
                                  : static_cast<uint16_t>((state_ && state_->pointer_size == 4) ? 4 : 8);

  std::error_code ec;
  const std::filesystem::path out_path(path);
  if (!out_path.parent_path().empty()) {
    std::filesystem::create_directories(out_path.parent_path(), ec);
  }

  std::ofstream ofs(out_path, std::ios::binary);
  if (!ofs.is_open()) {
    SetStatus(tool, L"无法写入指针文件");
    return;
  }

  const uint32_t depth = chains.empty() ? 0 : static_cast<uint32_t>(chains.front().offsets.size());
  PointerFileHeader hdr{};
  hdr.magic = kPointerMagic;
  hdr.version = kPointerVersion;
  hdr.pointer_size = pointer_size;
  hdr.depth = depth;
  hdr.reserved = 0;
  hdr.target = tool->search_target;
  hdr.count = 0;
  hdr.max_offset = tool->search_max_offset;
  hdr.flags = kPointerFlagDeltaVarint;
  ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

  uint64_t prev_base = 0;
  uint64_t written = 0;
  std::vector<uint8_t> buffer;
  buffer.reserve(64 * 1024);
  for (const auto& chain : chains) {
    if (chain.offsets.size() != depth) {
      continue;
    }
    WriteVarUint(&buffer, chain.base - prev_base);
    prev_base = chain.base;
    for (int64_t off : chain.offsets) {
      WriteVarInt(&buffer, off);
    }
    ++written;
    if (buffer.size() > 64 * 1024) {
      ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
      buffer.clear();
    }
  }
  if (!buffer.empty()) {
    ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
  }
  ofs.seekp(offsetof(PointerFileHeader, count), std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(&written), sizeof(written));
  ofs.flush();

  wchar_t status[512] = {0};
  std::swprintf(status,
                std::size(status),
                L"已保存指针文件: %s | 条数=%llu",
                path.c_str(),
                static_cast<unsigned long long>(written));
  SetStatus(tool, status);
}

void PointerToolsWindow::RunPointerCompare(ToolWindow* tool) {
  if (!tool || !tool->list) {
    return;
  }
  ListView_DeleteAllItems(tool->list);
  const std::wstring file_a = TrimText(ReadWindowText(tool->edit_a));
  const std::wstring file_b = TrimText(ReadWindowText(tool->edit_b));
  std::wstring out_file = TrimText(ReadWindowText(tool->edit_output));
  if (file_a.empty() || file_b.empty()) {
    SetStatus(tool, L"请选择两个指针搜索文件");
    return;
  }
  if (out_file.empty()) {
    out_file = MakeDefaultPointerPath(L"pointer_compare_result");
    if (tool->edit_output) {
      SetWindowTextW(tool->edit_output, out_file.c_str());
    }
  }

  auto load_file = [](const std::wstring& path,
                      PointerFileHeader* out_hdr,
                      std::vector<services::ClientService::PointerChain>* out_chains,
                      std::wstring* out_error) -> bool {
    if (out_error) {
      out_error->clear();
    }
    if (!out_hdr || !out_chains) {
      if (out_error) {
        *out_error = L"参数无效";
      }
      return false;
    }
    out_chains->clear();
    std::ifstream ifs(std::filesystem::path(path), std::ios::binary);
    if (!ifs.is_open()) {
      if (out_error) {
        *out_error = L"无法打开文件";
      }
      return false;
    }
    PointerFileHeader hdr{};
    ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (ifs.gcount() != static_cast<std::streamsize>(sizeof(hdr)) ||
        hdr.magic != kPointerMagic ||
        hdr.version != kPointerVersion ||
        hdr.depth == 0 ||
        hdr.depth > 16) {
      if (out_error) {
        *out_error = L"文件格式无效";
      }
      return false;
    }
    const std::streamoff data_offset = PointerFileDataOffset(hdr);
    ifs.seekg(data_offset, std::ios::beg);
    if (!ifs.good()) {
      if (out_error) {
        *out_error = L"文件数据偏移无效";
      }
      return false;
    }
    uint64_t prev_base = 0;
    for (uint64_t i = 0; (hdr.count == 0) || (i < hdr.count); ++i) {
      uint64_t delta = 0;
      if (!ReadVarUint(ifs, &delta)) {
        if (hdr.count == 0) {
          break;
        }
        if (out_error) {
          *out_error = L"读取链路失败";
        }
        return false;
      }
      services::ClientService::PointerChain chain{};
      chain.base = prev_base + delta;
      prev_base = chain.base;
      chain.offsets.resize(hdr.depth);
      for (uint32_t d = 0; d < hdr.depth; ++d) {
        int64_t off = 0;
        if (!ReadVarInt(ifs, &off)) {
          if (out_error) {
            *out_error = L"读取偏移失败";
          }
          return false;
        }
        chain.offsets[d] = off;
      }
      out_chains->push_back(std::move(chain));
      if (out_chains->size() > kPointerCompareLimit) {
        if (out_error) {
          *out_error = L"文件链路过多，已超过上限";
        }
        return false;
      }
    }
    *out_hdr = hdr;
    return true;
  };

  PointerFileHeader hdr_a{};
  PointerFileHeader hdr_b{};
  std::vector<services::ClientService::PointerChain> chains_a;
  std::vector<services::ClientService::PointerChain> chains_b;
  std::wstring load_error;
  if (!load_file(file_a, &hdr_a, &chains_a, &load_error)) {
    SetStatus(tool, std::wstring(L"文件A读取失败: ") + load_error);
    return;
  }
  if (!load_file(file_b, &hdr_b, &chains_b, &load_error)) {
    SetStatus(tool, std::wstring(L"文件B读取失败: ") + load_error);
    return;
  }
  if (hdr_a.depth != hdr_b.depth) {
    SetStatus(tool, L"两个文件层数不一致，无法直接对比");
    return;
  }

  const bool a_smaller = chains_a.size() <= chains_b.size();
  const auto& small = a_smaller ? chains_a : chains_b;
  const auto& large = a_smaller ? chains_b : chains_a;
  std::unordered_set<std::string> keys;
  keys.reserve(small.size() * 2 + 1);
  for (const auto& chain : small) {
    keys.insert(ChainKeyBinary(chain.base, chain.offsets));
  }

  std::vector<services::ClientService::PointerChain> common;
  common.reserve(std::min(chains_a.size(), chains_b.size()));
  std::unordered_set<std::string> emitted;
  emitted.reserve(common.capacity() * 2 + 1);
  for (const auto& chain : large) {
    const std::string key = ChainKeyBinary(chain.base, chain.offsets);
    if (keys.find(key) == keys.end()) {
      continue;
    }
    if (emitted.insert(key).second) {
      common.push_back(chain);
    }
  }
  std::sort(common.begin(), common.end(), [](const auto& a, const auto& b) {
    if (a.base != b.base) {
      return a.base < b.base;
    }
    return a.offsets < b.offsets;
  });

  int row = 0;
  for (const auto& chain : common) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = row;
    std::wstring base = FormatAddress(chain.base);
    item.pszText = base.data();
    ListView_InsertItem(tool->list, &item);
    std::wstring offsets = FormatOffsets(chain.offsets);
    ListView_SetItemText(tool->list, row, 1, offsets.data());
    ++row;
  }

  std::error_code ec;
  const std::filesystem::path output_path(out_file);
  if (!output_path.parent_path().empty()) {
    std::filesystem::create_directories(output_path.parent_path(), ec);
  }
  std::ofstream ofs(output_path, std::ios::binary);
  if (!ofs.is_open()) {
    SetStatus(tool, L"对比完成，但无法写入结果文件");
    return;
  }
  PointerFileHeader out_hdr{};
  out_hdr.magic = kPointerMagic;
  out_hdr.version = kPointerVersion;
  out_hdr.pointer_size = hdr_a.pointer_size != 0 ? hdr_a.pointer_size : hdr_b.pointer_size;
  out_hdr.depth = hdr_a.depth;
  out_hdr.reserved = 0;
  out_hdr.target = 0;
  out_hdr.count = 0;
  out_hdr.max_offset = std::max(hdr_a.max_offset, hdr_b.max_offset);
  out_hdr.flags = kPointerFlagDeltaVarint;
  ofs.write(reinterpret_cast<const char*>(&out_hdr), sizeof(out_hdr));
  uint64_t prev_base = 0;
  uint64_t written = 0;
  std::vector<uint8_t> buffer;
  buffer.reserve(64 * 1024);
  for (const auto& chain : common) {
    WriteVarUint(&buffer, chain.base - prev_base);
    prev_base = chain.base;
    for (int64_t off : chain.offsets) {
      WriteVarInt(&buffer, off);
    }
    ++written;
    if (buffer.size() > 64 * 1024) {
      ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
      buffer.clear();
    }
  }
  if (!buffer.empty()) {
    ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
  }
  ofs.seekp(offsetof(PointerFileHeader, count), std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(&written), sizeof(written));
  ofs.flush();

  wchar_t status[512] = {0};
  std::swprintf(status,
                std::size(status),
                L"对比完成: A=%llu, B=%llu, 共同=%llu, 输出=%s",
                static_cast<unsigned long long>(chains_a.size()),
                static_cast<unsigned long long>(chains_b.size()),
                static_cast<unsigned long long>(common.size()),
                out_file.c_str());
  SetStatus(tool, status);
}

void PointerToolsWindow::RunDataTraverse(ToolWindow* tool) {
  if (!tool || !tool->list) {
    return;
  }
  ResetTraverseModel(tool);
  ListView_DeleteAllItems(tool->list);

  std::wstring connect_error;
  if (!EnsureConnectedForScan(tool, &connect_error)) {
    SetStatus(tool, connect_error);
    return;
  }

  uint64_t start_addr = 0;
  if (!ParseAddressText(ReadWindowText(tool->edit_a), &start_addr)) {
    SetStatus(tool, L"起始地址格式无效");
    return;
  }
  int64_t count_i = tool->traverse_count > 0 ? tool->traverse_count : 128;
  if (tool->edit_b) {
    ParseIntText(ReadWindowText(tool->edit_b), &count_i);
  }
  int64_t stride_i = tool->traverse_stride > 0 ? tool->traverse_stride : 4;
  if (tool->edit_stride) {
    ParseIntText(ReadWindowText(tool->edit_stride), &stride_i);
  }
  tool->traverse_count = static_cast<int>(std::clamp<int64_t>(count_i, 1, 256));
  tool->traverse_stride = static_cast<int>(std::clamp<int64_t>(stride_i, 1, 0x1000));
  if (tool->combo_type) {
    tool->traverse_type_idx = std::max(0, ComboSel(tool->combo_type));
  } else {
    tool->traverse_type_idx = std::clamp(tool->traverse_type_idx, 0, 6);
  }
  if (tool->check_use_pvm) {
    tool->traverse_use_pvm = IsChecked(tool->check_use_pvm);
  }
  if (tool->check_auto_pointer) {
    tool->traverse_auto_pointer = IsChecked(tool->check_auto_pointer);
  }
  tool->traverse_pointer_size = (state_ && state_->pointer_size == 4) ? 4 : 8;
  if (tool->traverse_pointer_size != 4 && tool->traverse_pointer_size != 8) {
    tool->traverse_pointer_size = 8;
  }

  std::string module_error;
  if (!service_->FetchModules(state_->pid, &tool->traverse_modules, &module_error)) {
    tool->traverse_modules.clear();
  }
  std::sort(tool->traverse_modules.begin(), tool->traverse_modules.end(), [](const auto& a, const auto& b) {
    return a.start < b.start;
  });

  int ok_rows = 0;
  for (int i = 0; i < tool->traverse_count; ++i) {
    const uint64_t off = static_cast<uint64_t>(i) * static_cast<uint64_t>(tool->traverse_stride);
    if (start_addr > std::numeric_limits<uint64_t>::max() - off) {
      break;
    }
    TraverseRow row{};
    row.id = tool->traverse_next_id++;
    row.parent_id = 0;
    row.level = 0;
    row.offset = static_cast<int64_t>(off);
    row.addr = start_addr + off;
    if (PopulateTraverseRow(tool, &row)) {
      ++ok_rows;
    }
    tool->traverse_roots.push_back(row.id);
    tool->traverse_rows.emplace(row.id, std::move(row));
  }

  BuildTraverseVisible(tool);
  RefreshTraverseList(tool);

  wchar_t status[256] = {0};
  std::swprintf(status,
                std::size(status),
                L"结构分析就绪: 行=%llu，读取成功=%d，双击或右键可展开指针",
                static_cast<unsigned long long>(tool->traverse_roots.size()),
                ok_rows);
  SetStatus(tool, status);
}

void PointerToolsWindow::ResetTraverseModel(ToolWindow* tool) {
  if (!tool) {
    return;
  }
  tool->traverse_rows.clear();
  tool->traverse_roots.clear();
  tool->traverse_visible.clear();
  tool->traverse_next_id = 1;
  tool->context_row_id = 0;
}

void PointerToolsWindow::BuildTraverseVisible(ToolWindow* tool) {
  if (!tool) {
    return;
  }
  tool->traverse_visible.clear();
  std::function<void(uint64_t)> visit = [&](uint64_t id) {
    auto it = tool->traverse_rows.find(id);
    if (it == tool->traverse_rows.end()) {
      return;
    }
    tool->traverse_visible.push_back(id);
    if (!it->second.expanded) {
      return;
    }
    for (uint64_t child_id : it->second.child_ids) {
      visit(child_id);
    }
  };
  for (uint64_t id : tool->traverse_roots) {
    visit(id);
  }
}

bool PointerToolsWindow::PopulateTraverseRow(ToolWindow* tool, TraverseRow* row) {
  if (!tool || !row) {
    return false;
  }
  static const wchar_t* kTypeNames[] = {L"Byte", L"2 Bytes", L"4 Bytes", L"8 Bytes", L"Float", L"Double", L"Pointer"};
  const int type_idx = std::clamp(tool->traverse_type_idx, 0, 6);
  row->type_label = kTypeNames[type_idx];
  row->value_type = TraverseTypeToValueType(type_idx, tool->traverse_pointer_size);
  row->pointer_candidate = false;
  row->expanded = false;
  row->children_loaded = false;
  row->pointer_value = 0;
  row->note_label.clear();
  row->value_label = L"读取失败";

  uint32_t read_size = 4;
  switch (type_idx) {
    case 0: read_size = 1; break;
    case 1: read_size = 2; break;
    case 2: read_size = 4; break;
    case 3: read_size = 8; break;
    case 4: read_size = 4; break;
    case 5: read_size = 8; break;
    case 6: read_size = tool->traverse_pointer_size; break;
    default: read_size = 4; break;
  }
  if (read_size == 0) {
    read_size = 4;
  }

  std::vector<uint8_t> bytes;
  std::string error;
  const bool read_ok = service_->ReadMemory(row->addr, read_size, tool->traverse_use_pvm, &bytes, &error) && bytes.size() >= read_size;
  if (read_ok) {
    wchar_t buf[160] = {0};
    if (type_idx == 0) {
      const uint8_t v = bytes[0];
      std::swprintf(buf, std::size(buf), L"%u (0x%02X)", static_cast<unsigned>(v), static_cast<unsigned>(v));
    } else if (type_idx == 1) {
      uint16_t v = 0;
      std::memcpy(&v, bytes.data(), sizeof(v));
      std::swprintf(buf, std::size(buf), L"%u (0x%04X)", static_cast<unsigned>(v), static_cast<unsigned>(v));
    } else if (type_idx == 2) {
      uint32_t v = 0;
      std::memcpy(&v, bytes.data(), sizeof(v));
      std::swprintf(buf, std::size(buf), L"%u (0x%08X)", static_cast<unsigned>(v), static_cast<unsigned>(v));
    } else if (type_idx == 3) {
      uint64_t v = 0;
      std::memcpy(&v, bytes.data(), sizeof(v));
      std::swprintf(buf, std::size(buf), L"%llu (0x%016llX)", static_cast<unsigned long long>(v), static_cast<unsigned long long>(v));
    } else if (type_idx == 4) {
      float v = 0.0f;
      std::memcpy(&v, bytes.data(), sizeof(v));
      std::swprintf(buf, std::size(buf), L"%.6g", static_cast<double>(v));
    } else if (type_idx == 5) {
      double v = 0.0;
      std::memcpy(&v, bytes.data(), sizeof(v));
      std::swprintf(buf, std::size(buf), L"%.8g", v);
    } else {
      uint64_t v = 0;
      if (read_size == 4) {
        uint32_t v32 = 0;
        std::memcpy(&v32, bytes.data(), sizeof(v32));
        v = v32;
      } else {
        std::memcpy(&v, bytes.data(), sizeof(v));
        v = StripTag64(v);
      }
      std::swprintf(buf, std::size(buf), L"0x%llX", static_cast<unsigned long long>(v));
    }
    row->value_label = buf;
  } else if (!error.empty()) {
    row->note_label = Utf8ToWide(error);
  }

  const bool try_pointer = (type_idx == 6) || tool->traverse_auto_pointer;
  if (try_pointer) {
    uint64_t pointer_value = 0;
    bool have_pointer = false;
    const uint32_t pointer_size = tool->traverse_pointer_size == 4 ? 4 : 8;
    if (read_ok && read_size >= pointer_size) {
      if (pointer_size == 4) {
        uint32_t v32 = 0;
        std::memcpy(&v32, bytes.data(), sizeof(v32));
        pointer_value = v32;
      } else {
        std::memcpy(&pointer_value, bytes.data(), sizeof(pointer_value));
        pointer_value = StripTag64(pointer_value);
      }
      have_pointer = true;
    } else {
      std::vector<uint8_t> ptr_bytes;
      std::string ptr_error;
      if (service_->ReadMemory(row->addr, pointer_size, tool->traverse_use_pvm, &ptr_bytes, &ptr_error) &&
          ptr_bytes.size() >= pointer_size) {
        if (pointer_size == 4) {
          uint32_t v32 = 0;
          std::memcpy(&v32, ptr_bytes.data(), sizeof(v32));
          pointer_value = v32;
        } else {
          std::memcpy(&pointer_value, ptr_bytes.data(), sizeof(pointer_value));
          pointer_value = StripTag64(pointer_value);
        }
        have_pointer = true;
      }
    }
    if (have_pointer && pointer_value != 0) {
      std::vector<uint8_t> probe;
      std::string probe_error;
      if (service_->ReadMemory(pointer_value, 1, tool->traverse_use_pvm, &probe, &probe_error) && !probe.empty()) {
        row->pointer_candidate = true;
        row->pointer_value = pointer_value;
        for (const auto& mod : tool->traverse_modules) {
          if (pointer_value >= mod.start && pointer_value < mod.end) {
            wchar_t note[320] = {0};
            std::swprintf(note,
                          std::size(note),
                          L"P->%s+0x%llX",
                          ModuleNameFromPath(mod.path).c_str(),
                          static_cast<unsigned long long>(pointer_value - mod.start));
            row->note_label = note;
            break;
          }
        }
        if (row->note_label.empty()) {
          wchar_t note[128] = {0};
          std::swprintf(note, std::size(note), L"P->0x%llX", static_cast<unsigned long long>(pointer_value));
          row->note_label = note;
        }
      }
    }
  }
  return read_ok;
}

void PointerToolsWindow::BuildTraverseChildren(ToolWindow* tool, TraverseRow* parent) {
  if (!tool || !parent || parent->children_loaded || !parent->pointer_candidate || parent->pointer_value == 0) {
    return;
  }
  std::vector<uint64_t> child_ids;
  child_ids.reserve(static_cast<size_t>(tool->traverse_count));
  const uint64_t parent_id = parent->id;
  const uint64_t child_base = parent->pointer_value;
  const int child_level = parent->level + 1;
  for (int i = 0; i < tool->traverse_count; ++i) {
    const uint64_t off = static_cast<uint64_t>(i) * static_cast<uint64_t>(tool->traverse_stride);
    if (child_base > std::numeric_limits<uint64_t>::max() - off) {
      break;
    }
    TraverseRow child{};
    child.id = tool->traverse_next_id++;
    child.parent_id = parent_id;
    child.level = child_level;
    child.offset = static_cast<int64_t>(off);
    child.addr = child_base + off;
    PopulateTraverseRow(tool, &child);
    child_ids.push_back(child.id);
    tool->traverse_rows.emplace(child.id, std::move(child));
  }
  auto parent_it = tool->traverse_rows.find(parent_id);
  if (parent_it != tool->traverse_rows.end()) {
    parent_it->second.child_ids = std::move(child_ids);
    parent_it->second.children_loaded = true;
  }
}

void PointerToolsWindow::RefreshTraverseList(ToolWindow* tool) {
  if (!tool || !tool->list) {
    return;
  }
  ListView_DeleteAllItems(tool->list);
  int row_index = 0;
  for (uint64_t id : tool->traverse_visible) {
    const auto it = tool->traverse_rows.find(id);
    if (it == tool->traverse_rows.end()) {
      continue;
    }
    const TraverseRow& row = it->second;
    wchar_t off_buf[64] = {0};
    std::swprintf(off_buf,
                  std::size(off_buf),
                  row.offset >= 0 ? L"+%04llX" : L"-%04llX",
                  static_cast<unsigned long long>(row.offset >= 0 ? row.offset : -row.offset));
    std::wstring col0;
    if (row.pointer_candidate) {
      col0 = row.expanded ? L"▼ " : L"▶ ";
    }
    col0 += std::wstring(off_buf) + L" - " + row.type_label;
    std::wstring col1 = FormatAddress(row.addr) + L" : " + row.value_label;
    if (!row.note_label.empty()) {
      col1 += L"    ";
      col1 += row.note_label;
    }

    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_INDENT | LVIF_IMAGE;
    item.iItem = row_index;
    item.pszText = col0.data();
    item.lParam = static_cast<LPARAM>(row.id);
    item.iIndent = std::clamp(row.level, 0, 32);
    item.iImage = row.pointer_candidate ? (row.expanded ? 1 : 0) : I_IMAGENONE;
    ListView_InsertItem(tool->list, &item);
    ListView_SetItemText(tool->list, row_index, 1, col1.data());
    ++row_index;
  }
}

void PointerToolsWindow::ToggleTraverseExpand(ToolWindow* tool, int list_index) {
  if (!tool || list_index < 0 || static_cast<size_t>(list_index) >= tool->traverse_visible.size()) {
    return;
  }
  const uint64_t id = tool->traverse_visible[static_cast<size_t>(list_index)];
  auto it = tool->traverse_rows.find(id);
  if (it == tool->traverse_rows.end() || !it->second.pointer_candidate) {
    return;
  }
  if (!it->second.expanded) {
    BuildTraverseChildren(tool, &it->second);
    auto it_after = tool->traverse_rows.find(id);
    if (it_after != tool->traverse_rows.end()) {
      it_after->second.expanded = true;
    }
  } else {
    it->second.expanded = false;
  }
  BuildTraverseVisible(tool);
  RefreshTraverseList(tool);
  if (tool->list && list_index < ListView_GetItemCount(tool->list)) {
    ListView_SetItemState(tool->list,
                          list_index,
                          LVIS_SELECTED | LVIS_FOCUSED,
                          LVIS_SELECTED | LVIS_FOCUSED);
  }
}

void PointerToolsWindow::UpdateTraverseMenuState(ToolWindow* tool) {
  if (!tool || tool->mode != Mode::DataTraverse || !tool->hwnd) {
    return;
  }
  if (tool->menu_type) {
    UINT type_cmd = kMenuTraverseType4Bytes;
    switch (std::clamp(tool->traverse_type_idx, 0, 6)) {
      case 0:
        type_cmd = kMenuTraverseTypeByte;
        break;
      case 1:
        type_cmd = kMenuTraverseType2Bytes;
        break;
      case 2:
        type_cmd = kMenuTraverseType4Bytes;
        break;
      case 3:
        type_cmd = kMenuTraverseType8Bytes;
        break;
      case 4:
        type_cmd = kMenuTraverseTypeFloat;
        break;
      case 5:
        type_cmd = kMenuTraverseTypeDouble;
        break;
      case 6:
        type_cmd = kMenuTraverseTypePointer;
        break;
      default:
        break;
    }
    CheckMenuRadioItem(tool->menu_type,
                       kMenuTraverseTypeByte,
                       kMenuTraverseTypePointer,
                       type_cmd,
                       MF_BYCOMMAND);
  }
  if (tool->menu_count) {
    const int count = NormalizeTraverseCount(tool->traverse_count);
    UINT count_cmd = kMenuTraverseCount128;
    if (count == 32) {
      count_cmd = kMenuTraverseCount32;
    } else if (count == 64) {
      count_cmd = kMenuTraverseCount64;
    } else if (count == 256) {
      count_cmd = kMenuTraverseCount256;
    }
    CheckMenuRadioItem(tool->menu_count,
                       kMenuTraverseCount32,
                       kMenuTraverseCount256,
                       count_cmd,
                       MF_BYCOMMAND);
  }
  if (tool->menu_stride) {
    const int stride = NormalizeTraverseStride(tool->traverse_stride);
    UINT stride_cmd = kMenuTraverseStride4;
    if (stride == 1) {
      stride_cmd = kMenuTraverseStride1;
    } else if (stride == 2) {
      stride_cmd = kMenuTraverseStride2;
    } else if (stride == 8) {
      stride_cmd = kMenuTraverseStride8;
    } else if (stride == 16) {
      stride_cmd = kMenuTraverseStride16;
    }
    CheckMenuRadioItem(tool->menu_stride,
                       kMenuTraverseStride1,
                       kMenuTraverseStride16,
                       stride_cmd,
                       MF_BYCOMMAND);
  }
  if (tool->menu_options) {
    CheckMenuItem(tool->menu_options,
                  kMenuTraverseToggleAutoPointer,
                  MF_BYCOMMAND | (tool->traverse_auto_pointer ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(tool->menu_options,
                  kMenuTraverseToggleUsePvm,
                  MF_BYCOMMAND | (tool->traverse_use_pvm ? MF_CHECKED : MF_UNCHECKED));
  }
  DrawMenuBar(tool->hwnd);
}

PointerToolsWindow::TraverseRow* PointerToolsWindow::TraverseRowById(ToolWindow* tool, uint64_t id) {
  if (!tool || id == 0) {
    return nullptr;
  }
  auto it = tool->traverse_rows.find(id);
  if (it == tool->traverse_rows.end()) {
    return nullptr;
  }
  return &it->second;
}

PointerToolsWindow::TraverseRow* PointerToolsWindow::TraverseRowByListIndex(ToolWindow* tool, int list_index) {
  if (!tool || list_index < 0 || static_cast<size_t>(list_index) >= tool->traverse_visible.size()) {
    return nullptr;
  }
  return TraverseRowById(tool, tool->traverse_visible[static_cast<size_t>(list_index)]);
}

void PointerToolsWindow::ShowTraverseContextMenu(ToolWindow* tool, int list_index, const POINT& screen_pt) {
  if (!tool || tool->mode != Mode::DataTraverse || !tool->list) {
    return;
  }
  TraverseRow* row = TraverseRowByListIndex(tool, list_index);
  if (!row) {
    return;
  }
  tool->context_row_id = row->id;

  HMENU menu = CreatePopupMenu();
  if (!menu) {
    return;
  }
  if (row->pointer_candidate) {
    AppendMenuW(menu, MF_STRING, kMenuTraverseCtxToggleExpand, row->expanded ? L"折叠指针" : L"展开指针");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  }
  AppendMenuW(menu, MF_STRING, kMenuTraverseCtxCopyAddr, L"复制地址");
  AppendMenuW(menu, MF_STRING, kMenuTraverseCtxCopyValue, L"复制数值");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, kMenuTraverseCtxAddToList, L"添加到地址表");
  const UINT cmd = TrackPopupMenu(menu,
                                  TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN | TPM_TOPALIGN,
                                  screen_pt.x,
                                  screen_pt.y,
                                  0,
                                  tool->hwnd,
                                  nullptr);
  DestroyMenu(menu);
  if (cmd != 0) {
    SendMessageW(tool->hwnd, WM_COMMAND, cmd, 0);
  }
}

void PointerToolsWindow::SetStatus(ToolWindow* tool, const std::wstring& text) const {
  if (tool && tool->status) {
    SetWindowTextW(tool->status, text.c_str());
  }
}

std::wstring PointerToolsWindow::Utf8ToWide(const std::string& text) {
  if (text.empty()) {
    return L"";
  }
  const int chars = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  if (chars <= 0) {
    return L"";
  }
  std::wstring out(static_cast<size_t>(chars), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), chars);
  return out;
}

std::wstring PointerToolsWindow::FormatAddress(uint64_t addr) {
  wchar_t buf[64] = {0};
  std::swprintf(buf, std::size(buf), L"0x%llX", static_cast<unsigned long long>(addr));
  return buf;
}

std::wstring PointerToolsWindow::FormatOffsets(const std::vector<int64_t>& offsets) {
  std::wstring out;
  for (size_t i = 0; i < offsets.size(); ++i) {
    wchar_t buf[48] = {0};
    const long long v = static_cast<long long>(offsets[i]);
    if (v >= 0) {
      std::swprintf(buf, std::size(buf), L"[+0x%llX]", static_cast<unsigned long long>(v));
    } else {
      std::swprintf(buf, std::size(buf), L"[-0x%llX]", static_cast<unsigned long long>(-v));
    }
    if (!out.empty()) {
      out.push_back(L' ');
    }
    out.append(buf);
  }
  if (out.empty()) {
    out = L"[+0x0]";
  }
  return out;
}

bool PointerToolsWindow::ParseAddressText(const std::wstring& text, uint64_t* out_addr) {
  if (!out_addr) {
    return false;
  }
  const std::wstring t = TrimText(text);
  if (t.empty()) {
    return false;
  }
  wchar_t* end = nullptr;
  const unsigned long long v = std::wcstoull(t.c_str(), &end, 0);
  if (end == t.c_str()) {
    return false;
  }
  *out_addr = static_cast<uint64_t>(v);
  return true;
}

bool PointerToolsWindow::ParseIntText(const std::wstring& text, int64_t* out_value) {
  if (!out_value) {
    return false;
  }
  const std::wstring t = TrimText(text);
  if (t.empty()) {
    return false;
  }
  wchar_t* end = nullptr;
  const long long v = std::wcstoll(t.c_str(), &end, 0);
  if (end == t.c_str()) {
    return false;
  }
  *out_value = static_cast<int64_t>(v);
  return true;
}

std::wstring PointerToolsWindow::ModuleNameFromPath(const std::string& path) {
  if (path.empty()) {
    return L"(unknown)";
  }
  const std::wstring wide = Utf8ToWide(path);
  const size_t pos = wide.find_last_of(L"/\\");
  if (pos == std::wstring::npos || pos + 1 >= wide.size()) {
    return wide;
  }
  return wide.substr(pos + 1);
}

LRESULT CALLBACK PointerToolsWindow::StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  ToolWindow* tool = reinterpret_cast<ToolWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    tool = reinterpret_cast<ToolWindow*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(tool));
  }
  if (!tool || !tool->owner) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }
  return tool->owner->WndProc(tool, hwnd, msg, wparam, lparam);
}

LRESULT PointerToolsWindow::WndProc(ToolWindow* tool,
                                    HWND hwnd,
                                    UINT msg,
                                    WPARAM wparam,
                                    LPARAM lparam) {
  switch (msg) {
    case WM_GETMINMAXINFO: {
      MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lparam);
      if (mmi) {
        mmi->ptMinTrackSize.x = static_cast<LONG>(std::lround(980.0f));
        mmi->ptMinTrackSize.y = static_cast<LONG>(std::lround(660.0f));
      }
      return 0;
    }
    case WM_CREATE: {
      tool->dpi = GetDpiForWindowCompat(hwnd);
      tool->scale = static_cast<float>(tool->dpi) / 96.0f;
      if (!tool->bg_brush) {
        tool->bg_brush = CreateSolidBrush(RGB(43, 43, 43));
      }
      if (!tool->font) {
        LOGFONTW lf{};
        lf.lfHeight = -MulDiv(16, static_cast<int>(tool->dpi), 96);
        lf.lfWeight = FW_NORMAL;
        wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
        tool->font = CreateFontIndirectW(&lf);
      }
      const BOOL use_dark = TRUE;
      DwmSetWindowAttribute(hwnd, 20, &use_dark, sizeof(use_dark));
      DwmSetWindowAttribute(hwnd, 19, &use_dark, sizeof(use_dark));

      const auto px = [tool](float dip) { return static_cast<int>(std::lround(dip * tool->scale)); };
      auto mk = [&](DWORD ex_style,
                    const wchar_t* cls,
                    const wchar_t* text,
                    DWORD style,
                    int x,
                    int y,
                    int w,
                    int h,
                    int id) -> HWND {
        HWND ctrl = CreateWindowExW(ex_style,
                                    cls,
                                    text,
                                    style | WS_CHILD | WS_VISIBLE,
                                    x,
                                    y,
                                    w,
                                    h,
                                    hwnd,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                    instance_,
                                    nullptr);
        if (ctrl && tool->font) {
          SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(tool->font), TRUE);
        }
        return ctrl;
      };

      if (tool->mode == Mode::DataTraverse) {
        tool->menu_bar = CreateMenu();
        HMENU menu_file = CreatePopupMenu();
        HMENU menu_view = CreatePopupMenu();
        tool->menu_structure = CreatePopupMenu();
        tool->menu_options = CreatePopupMenu();
        tool->menu_type = CreatePopupMenu();
        tool->menu_count = CreatePopupMenu();
        tool->menu_stride = CreatePopupMenu();

        if (menu_file && menu_view && tool->menu_structure && tool->menu_options && tool->menu_type && tool->menu_count && tool->menu_stride &&
            tool->menu_bar) {
          AppendMenuW(menu_file, MF_STRING, kMenuTraverseRefresh, L"刷新\tF5");
          AppendMenuW(menu_file, MF_SEPARATOR, 0, nullptr);
          AppendMenuW(menu_file, MF_STRING, kMenuTraverseClose, L"关闭");

          AppendMenuW(menu_view, MF_STRING, kMenuTraverseFocusAddr, L"定位地址栏\tCtrl+G");

          AppendMenuW(tool->menu_structure, MF_STRING, kMenuTraverseRun, L"开始遍历\tF9");
          AppendMenuW(tool->menu_structure, MF_SEPARATOR, 0, nullptr);

          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseTypeByte, L"Byte");
          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseType2Bytes, L"2 Bytes");
          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseType4Bytes, L"4 Bytes");
          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseType8Bytes, L"8 Bytes");
          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseTypeFloat, L"Float");
          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseTypeDouble, L"Double");
          AppendMenuW(tool->menu_type, MF_STRING, kMenuTraverseTypePointer, L"Pointer");
          AppendMenuW(tool->menu_structure, MF_POPUP, reinterpret_cast<UINT_PTR>(tool->menu_type), L"读取类型");

          AppendMenuW(tool->menu_count, MF_STRING, kMenuTraverseCount32, L"32");
          AppendMenuW(tool->menu_count, MF_STRING, kMenuTraverseCount64, L"64");
          AppendMenuW(tool->menu_count, MF_STRING, kMenuTraverseCount128, L"128");
          AppendMenuW(tool->menu_count, MF_STRING, kMenuTraverseCount256, L"256");
          AppendMenuW(tool->menu_structure, MF_POPUP, reinterpret_cast<UINT_PTR>(tool->menu_count), L"数量");

          AppendMenuW(tool->menu_stride, MF_STRING, kMenuTraverseStride1, L"1");
          AppendMenuW(tool->menu_stride, MF_STRING, kMenuTraverseStride2, L"2");
          AppendMenuW(tool->menu_stride, MF_STRING, kMenuTraverseStride4, L"4");
          AppendMenuW(tool->menu_stride, MF_STRING, kMenuTraverseStride8, L"8");
          AppendMenuW(tool->menu_stride, MF_STRING, kMenuTraverseStride16, L"16");
          AppendMenuW(tool->menu_structure, MF_POPUP, reinterpret_cast<UINT_PTR>(tool->menu_stride), L"步长");

          AppendMenuW(tool->menu_options, MF_STRING, kMenuTraverseToggleAutoPointer, L"自动识别指针");
          AppendMenuW(tool->menu_options, MF_STRING, kMenuTraverseToggleUsePvm, L"使用系统读取(process_vm_readv)");

          AppendMenuW(tool->menu_bar, MF_POPUP, reinterpret_cast<UINT_PTR>(menu_file), L"文件");
          AppendMenuW(tool->menu_bar, MF_POPUP, reinterpret_cast<UINT_PTR>(menu_view), L"视图");
          AppendMenuW(tool->menu_bar, MF_POPUP, reinterpret_cast<UINT_PTR>(tool->menu_structure), L"结构");
          AppendMenuW(tool->menu_bar, MF_POPUP, reinterpret_cast<UINT_PTR>(tool->menu_options), L"结构选项");
          SetMenu(hwnd, tool->menu_bar);
        } else {
          if (tool->menu_bar) {
            DestroyMenu(tool->menu_bar);
            tool->menu_bar = nullptr;
          }
        }

        tool->traverse_count = NormalizeTraverseCount(tool->traverse_count);
        tool->traverse_stride = NormalizeTraverseStride(tool->traverse_stride);
        tool->traverse_type_idx = std::clamp(tool->traverse_type_idx, 0, 6);
        tool->label_a = mk(0, L"STATIC", L"#组 1", 0, px(14), px(18), px(200), px(24), 0);
        tool->edit_a = mk(WS_EX_CLIENTEDGE, L"EDIT", L"0x400000", ES_AUTOHSCROLL, px(14), px(46), px(260), px(30), kCtrlEditA);
        tool->btn_run = mk(0, L"BUTTON", L"刷新结构(F5)", BS_PUSHBUTTON, px(850), px(42), px(150), px(34), kCtrlBtnRun);
      } else if (tool->mode == Mode::PointerCompare) {
        tool->label_a = mk(0, L"STATIC", L"文件A", 0, px(14), px(20), px(90), px(22), 0);
        tool->edit_a = mk(WS_EX_CLIENTEDGE, L"EDIT", L"", ES_AUTOHSCROLL, px(120), px(16), px(720), px(28), kCtrlEditA);
        tool->btn_browse_a = mk(0, L"BUTTON", L"浏览...", BS_PUSHBUTTON, px(850), px(16), px(90), px(30), kCtrlBtnBrowseA);

        tool->label_b = mk(0, L"STATIC", L"文件B", 0, px(14), px(58), px(90), px(22), 0);
        tool->edit_b = mk(WS_EX_CLIENTEDGE, L"EDIT", L"", ES_AUTOHSCROLL, px(120), px(54), px(720), px(28), kCtrlEditB);
        tool->btn_browse_b = mk(0, L"BUTTON", L"浏览...", BS_PUSHBUTTON, px(850), px(54), px(90), px(30), kCtrlBtnBrowseB);

        tool->label_output = mk(0, L"STATIC", L"结果文件", 0, px(14), px(96), px(90), px(22), 0);
        tool->edit_output = mk(WS_EX_CLIENTEDGE, L"EDIT", L"", ES_AUTOHSCROLL, px(120), px(92), px(720), px(28), kCtrlEditOutput);
        tool->btn_browse_output = mk(0, L"BUTTON", L"保存到...", BS_PUSHBUTTON, px(850), px(92), px(90), px(30), kCtrlBtnBrowseOutput);
        if (tool->edit_output) {
          const std::wstring def_out = MakeDefaultPointerPath(L"pointer_compare_result");
          SetWindowTextW(tool->edit_output, def_out.c_str());
        }

        tool->btn_run = mk(0, L"BUTTON", L"开始对比", BS_PUSHBUTTON, px(120), px(130), px(120), px(34), kCtrlBtnRun);
        tool->btn_clear = mk(0, L"BUTTON", L"清空结果", BS_PUSHBUTTON, px(250), px(130), px(120), px(34), kCtrlBtnClear);
      } else {
        tool->label_a = mk(0, L"STATIC", L"目标地址A", 0, px(14), px(20), px(90), px(22), 0);
        tool->edit_a = mk(WS_EX_CLIENTEDGE, L"EDIT", L"0x0", ES_AUTOHSCROLL, px(120), px(16), px(260), px(28), kCtrlEditA);
        tool->label_depth = mk(0, L"STATIC", L"层数", 0, px(394), px(20), px(46), px(22), 0);
        tool->edit_depth = mk(WS_EX_CLIENTEDGE, L"EDIT", L"3", ES_AUTOHSCROLL, px(442), px(16), px(70), px(28), kCtrlEditDepth);
        tool->label_max_offset = mk(0, L"STATIC", L"最大偏移", 0, px(526), px(20), px(74), px(22), 0);
        tool->edit_max_offset = mk(WS_EX_CLIENTEDGE, L"EDIT", L"0x400", ES_AUTOHSCROLL, px(604), px(16), px(110), px(28), kCtrlEditMaxOffset);
        tool->label_max_results = mk(0, L"STATIC", L"最大结果", 0, px(728), px(20), px(74), px(22), 0);
        tool->edit_max_results = mk(WS_EX_CLIENTEDGE, L"EDIT", L"300", ES_AUTOHSCROLL, px(806), px(16), px(110), px(28), kCtrlEditMaxResults);

        tool->label_pointer_size = mk(0, L"STATIC", L"指针宽度", 0, px(14), px(58), px(90), px(22), 0);
        tool->combo_pointer_size = mk(0, L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | WS_VSCROLL, px(120), px(54), px(170), px(240), kCtrlComboPointerSize);
        if (tool->combo_pointer_size) {
          SendMessageW(tool->combo_pointer_size, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"自动"));
          SendMessageW(tool->combo_pointer_size, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"4字节"));
          SendMessageW(tool->combo_pointer_size, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"8字节"));
          SendMessageW(tool->combo_pointer_size, CB_SETCURSEL, 0, 0);
        }
        tool->label_max_entries = mk(0, L"STATIC", L"索引上限", 0, px(304), px(58), px(68), px(22), 0);
        tool->edit_max_entries = mk(WS_EX_CLIENTEDGE, L"EDIT", L"500000", ES_AUTOHSCROLL, px(376), px(54), px(150), px(28), kCtrlEditMaxEntries);
        tool->check_use_pvm = mk(0, L"BUTTON", L"系统读取", BS_AUTOCHECKBOX, px(540), px(58), px(90), px(22), kCtrlCheckUsePvm);
        SendMessageW(tool->check_use_pvm, BM_SETCHECK, BST_CHECKED, 0);
        tool->check_allow_nonresident = mk(0, L"BUTTON", L"允许非驻留", BS_AUTOCHECKBOX, px(640), px(58), px(120), px(22), kCtrlCheckAllowNonresident);

        tool->check_byte_step = mk(0, L"BUTTON", L"字节步进", BS_AUTOCHECKBOX, px(120), px(96), px(120), px(22), kCtrlCheckByteStep);
        tool->check_strict = mk(0, L"BUTTON", L"严格构建", BS_AUTOCHECKBOX, px(250), px(96), px(120), px(22), kCtrlCheckStrict);
        tool->btn_build = mk(0, L"BUTTON", L"构建索引", BS_PUSHBUTTON, px(470), px(92), px(120), px(34), kCtrlBtnBuild);
        tool->btn_run = mk(0, L"BUTTON", L"开始搜索", BS_PUSHBUTTON, px(600), px(92), px(120), px(34), kCtrlBtnRun);
        tool->btn_clear = mk(0, L"BUTTON", L"清空索引", BS_PUSHBUTTON, px(730), px(92), px(120), px(34), kCtrlBtnClear);
        tool->btn_save = mk(0, L"BUTTON", L"保存结果", BS_PUSHBUTTON, px(860), px(92), px(120), px(34), kCtrlBtnSave);
      }

      tool->list = mk(WS_EX_CLIENTEDGE,
                      WC_LISTVIEWW,
                      nullptr,
                      LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                      px(14),
                      px(150),
                      px(1020),
                      px(540),
                      kCtrlListResult);
      if (tool->list) {
        ListView_SetExtendedListViewStyle(tool->list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        ListView_SetBkColor(tool->list, RGB(43, 43, 43));
        ListView_SetTextBkColor(tool->list, RGB(43, 43, 43));
        ListView_SetTextColor(tool->list, RGB(230, 230, 230));
        if (tool->mode == Mode::DataTraverse) {
          if (tool->traverse_icons) {
            ImageList_Destroy(tool->traverse_icons);
            tool->traverse_icons = nullptr;
          }
          tool->traverse_icons = CreateTraverseIconList(tool->dpi);
          if (tool->traverse_icons) {
            ListView_SetImageList(tool->list, tool->traverse_icons, LVSIL_SMALL);
          }
        }
      }
      tool->status = mk(WS_EX_CLIENTEDGE, L"STATIC", L"就绪", SS_LEFT, px(14), px(700), px(1020), px(26), kCtrlStatus);
      ConfigureListColumns(tool);
      ApplyFontToChildren(tool);
      if (tool->mode == Mode::DataTraverse) {
        UpdateTraverseMenuState(tool);
      }

      RECT rc{};
      GetClientRect(hwnd, &rc);
      LayoutControls(tool, rc.right - rc.left, rc.bottom - rc.top);
      return 0;
    }
    case WM_SIZE: {
      const int width = LOWORD(lparam);
      const int height = HIWORD(lparam);
      LayoutControls(tool, width, height);
      return 0;
    }
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      if (cmd == kCtrlBtnBrowseA || cmd == kCtrlBtnBrowseB || cmd == kCtrlBtnBrowseOutput) {
        const bool save_mode = (cmd == kCtrlBtnBrowseOutput);
        HWND target_edit = nullptr;
        const wchar_t* title = L"选择指针文件";
        if (cmd == kCtrlBtnBrowseA) {
          target_edit = tool->edit_a;
          title = L"选择指针文件A";
        } else if (cmd == kCtrlBtnBrowseB) {
          target_edit = tool->edit_b;
          title = L"选择指针文件B";
        } else {
          target_edit = tool->edit_output;
          title = L"保存对比结果";
        }
        std::wstring default_path = TrimText(ReadWindowText(target_edit));
        if (default_path.empty() && save_mode) {
          default_path = MakeDefaultPointerPath(L"pointer_compare_result");
        }
        std::wstring selected_path;
        if (BrowsePathDialog(tool->hwnd, save_mode, title, default_path.c_str(), &selected_path)) {
          if (target_edit) {
            SetWindowTextW(target_edit, selected_path.c_str());
          }
        }
        return 0;
      }
      if (tool->mode == Mode::DataTraverse) {
        const int new_type_idx = MenuTypeCmdToIndex(cmd);
        if (new_type_idx >= 0) {
          tool->traverse_type_idx = new_type_idx;
          UpdateTraverseMenuState(tool);
          SetStatus(tool, L"读取类型已更新");
          return 0;
        }
        if (cmd == kMenuTraverseCount32 || cmd == kMenuTraverseCount64 || cmd == kMenuTraverseCount128 || cmd == kMenuTraverseCount256) {
          if (cmd == kMenuTraverseCount32) {
            tool->traverse_count = 32;
          } else if (cmd == kMenuTraverseCount64) {
            tool->traverse_count = 64;
          } else if (cmd == kMenuTraverseCount128) {
            tool->traverse_count = 128;
          } else {
            tool->traverse_count = 256;
          }
          UpdateTraverseMenuState(tool);
          SetStatus(tool, L"遍历数量已更新");
          return 0;
        }
        if (cmd == kMenuTraverseStride1 || cmd == kMenuTraverseStride2 || cmd == kMenuTraverseStride4 || cmd == kMenuTraverseStride8 ||
            cmd == kMenuTraverseStride16) {
          if (cmd == kMenuTraverseStride1) {
            tool->traverse_stride = 1;
          } else if (cmd == kMenuTraverseStride2) {
            tool->traverse_stride = 2;
          } else if (cmd == kMenuTraverseStride4) {
            tool->traverse_stride = 4;
          } else if (cmd == kMenuTraverseStride8) {
            tool->traverse_stride = 8;
          } else {
            tool->traverse_stride = 16;
          }
          UpdateTraverseMenuState(tool);
          SetStatus(tool, L"遍历步长已更新");
          return 0;
        }
        if (cmd == kMenuTraverseToggleAutoPointer) {
          tool->traverse_auto_pointer = !tool->traverse_auto_pointer;
          UpdateTraverseMenuState(tool);
          SetStatus(tool, tool->traverse_auto_pointer ? L"已启用自动识别指针" : L"已关闭自动识别指针");
          return 0;
        }
        if (cmd == kMenuTraverseToggleUsePvm) {
          tool->traverse_use_pvm = !tool->traverse_use_pvm;
          UpdateTraverseMenuState(tool);
          SetStatus(tool, tool->traverse_use_pvm ? L"已启用系统读取" : L"已关闭系统读取");
          return 0;
        }
        if (cmd == kMenuTraverseRun || cmd == kMenuTraverseRefresh) {
          RunDataTraverse(tool);
          return 0;
        }
        if (cmd == kMenuTraverseClose) {
          ShowWindow(hwnd, SW_HIDE);
          return 0;
        }
        if (cmd == kMenuTraverseFocusAddr) {
          if (tool->edit_a) {
            SetFocus(tool->edit_a);
            SendMessageW(tool->edit_a, EM_SETSEL, 0, -1);
          }
          return 0;
        }
        if (cmd == kMenuTraverseCtxToggleExpand) {
          int target_index = -1;
          for (size_t i = 0; i < tool->traverse_visible.size(); ++i) {
            if (tool->traverse_visible[i] == tool->context_row_id) {
              target_index = static_cast<int>(i);
              break;
            }
          }
          if (target_index >= 0) {
            ToggleTraverseExpand(tool, target_index);
          }
          return 0;
        }
        if (cmd == kMenuTraverseCtxCopyAddr || cmd == kMenuTraverseCtxCopyValue || cmd == kMenuTraverseCtxAddToList) {
          TraverseRow* row = TraverseRowById(tool, tool->context_row_id);
          if (!row && tool->list) {
            const int selected = ListView_GetNextItem(tool->list, -1, LVNI_SELECTED);
            row = TraverseRowByListIndex(tool, selected);
          }
          if (!row) {
            SetStatus(tool, L"未选中可操作行");
            return 0;
          }
          if (cmd == kMenuTraverseCtxCopyAddr) {
            if (CopyTextToClipboard(tool->hwnd, FormatAddress(row->addr))) {
              SetStatus(tool, L"地址已复制");
            } else {
              SetStatus(tool, L"复制地址失败");
            }
            return 0;
          }
          if (cmd == kMenuTraverseCtxCopyValue) {
            if (CopyTextToClipboard(tool->hwnd, row->value_label)) {
              SetStatus(tool, L"数值已复制");
            } else {
              SetStatus(tool, L"复制数值失败");
            }
            return 0;
          }
          if (state_) {
            bool exists = false;
            for (const auto& entry : state_->address_entries) {
              if (entry.addr == row->addr) {
                exists = true;
                break;
              }
            }
            if (!exists) {
              app::AddressEntry entry{};
              entry.active = false;
              entry.desc = L"结构分析";
              entry.addr = row->addr;
              entry.type = row->value_type;
              entry.value = row->value_label;
              state_->address_entries.push_back(std::move(entry));
              SetStatus(tool, L"已添加到地址表");
            } else {
              SetStatus(tool, L"地址已存在于地址表");
            }
          }
          return 0;
        }
      }
      if (cmd == kCtrlBtnBuild) {
        std::wstring status;
        if (BuildPointerIndex(tool, true, &status)) {
          SetStatus(tool, status);
        } else {
          SetStatus(tool, status.empty() ? L"索引构建失败" : status);
        }
        return 0;
      }
      if (cmd == kCtrlBtnRun) {
        if (tool->mode == Mode::PointerSearch) {
          RunPointerSearch(tool);
        } else if (tool->mode == Mode::PointerCompare) {
          RunPointerCompare(tool);
        } else {
          RunDataTraverse(tool);
        }
        return 0;
      }
      if (cmd == kCtrlBtnClear) {
        if (tool->mode == Mode::PointerSearch) {
          std::string error;
          if (service_ && service_->IsConnected()) {
            service_->ClearPointerIndex(&error);
          }
          ResetIndexCache(tool);
          tool->search_results.clear();
          tool->search_target = 0;
          tool->search_depth = 0;
          tool->search_max_offset = 0;
          ListView_DeleteAllItems(tool->list);
          SetStatus(tool, error.empty() ? L"已清空指针索引与搜索结果" : Utf8ToWide(error));
        } else if (tool->mode == Mode::PointerCompare) {
          ListView_DeleteAllItems(tool->list);
          SetStatus(tool, L"已清空对比结果");
        } else {
          ResetTraverseModel(tool);
          ListView_DeleteAllItems(tool->list);
          SetStatus(tool, L"已清空数据遍历结果");
        }
        return 0;
      }
      if (cmd == kCtrlBtnSave) {
        if (tool->mode == Mode::PointerSearch) {
          SavePointerSearchResult(tool);
        }
        return 0;
      }
      return 0;
    }
    case WM_NOTIFY: {
      const NMHDR* hdr = reinterpret_cast<const NMHDR*>(lparam);
      if (hdr && hdr->hwndFrom == tool->list && tool->mode == Mode::DataTraverse) {
        if (hdr->code == NM_CLICK) {
          const auto* act = reinterpret_cast<const NMITEMACTIVATE*>(lparam);
          if (act && act->iItem >= 0) {
            LVHITTESTINFO hit{};
            hit.pt = act->ptAction;
            const int row_index = ListView_SubItemHitTest(tool->list, &hit);
            if (row_index >= 0 && hit.iSubItem == 0) {
              TraverseRow* row = TraverseRowByListIndex(tool, row_index);
              if (row && row->pointer_candidate) {
                bool toggle = (hit.flags & LVHT_ONITEMICON) != 0;
                if (!toggle) {
                  RECT label_rc{};
                  if (ListView_GetItemRect(tool->list, row_index, &label_rc, LVIR_LABEL)) {
                    const int hotspot_right = label_rc.left + 26;
                    if (hit.pt.x <= hotspot_right) {
                      toggle = true;
                    }
                  }
                }
                if (toggle) {
                  ToggleTraverseExpand(tool, row_index);
                  return 0;
                }
              }
            }
          }
        }
        if (hdr->code == NM_DBLCLK) {
          const auto* act = reinterpret_cast<const NMITEMACTIVATE*>(lparam);
          if (act && act->iItem >= 0) {
            ToggleTraverseExpand(tool, act->iItem);
          }
          return 0;
        }
        if (hdr->code == NM_RCLICK) {
          POINT screen_pt{};
          GetCursorPos(&screen_pt);
          POINT list_pt = screen_pt;
          ScreenToClient(tool->list, &list_pt);
          LVHITTESTINFO hit{};
          hit.pt = list_pt;
          int row_index = ListView_SubItemHitTest(tool->list, &hit);
          if (row_index >= 0) {
            ListView_SetItemState(tool->list,
                                  row_index,
                                  LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
          } else {
            row_index = ListView_GetNextItem(tool->list, -1, LVNI_SELECTED);
          }
          if (row_index >= 0) {
            ShowTraverseContextMenu(tool, row_index, screen_pt);
          }
          return 0;
        }
        if (hdr->code == LVN_KEYDOWN) {
          const auto* key = reinterpret_cast<const NMLVKEYDOWN*>(lparam);
          if (key && (key->wVKey == VK_RETURN || key->wVKey == VK_SPACE)) {
            const int selected = ListView_GetNextItem(tool->list, -1, LVNI_SELECTED);
            if (selected >= 0) {
              ToggleTraverseExpand(tool, selected);
              return 0;
            }
          }
        }
      }
      return 0;
    }
    case WM_KEYDOWN: {
      if (tool->mode == Mode::DataTraverse) {
        const bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        if (wparam == VK_F5 || wparam == VK_F9) {
          RunDataTraverse(tool);
          return 0;
        }
        if (ctrl && wparam == 'G') {
          if (tool->edit_a) {
            SetFocus(tool->edit_a);
            SendMessageW(tool->edit_a, EM_SETSEL, 0, -1);
          }
          return 0;
        }
        if (wparam == VK_APPS || (wparam == VK_F10 && (GetKeyState(VK_SHIFT) & 0x8000) != 0)) {
          const int selected = tool->list ? ListView_GetNextItem(tool->list, -1, LVNI_SELECTED) : -1;
          if (selected >= 0 && tool->list) {
            RECT row_rc{};
            if (ListView_GetItemRect(tool->list, selected, &row_rc, LVIR_BOUNDS)) {
              POINT pt{row_rc.left + 8, row_rc.top + (row_rc.bottom - row_rc.top) / 2};
              ClientToScreen(tool->list, &pt);
              ShowTraverseContextMenu(tool, selected, pt);
            }
          }
          return 0;
        }
      }
      break;
    }
    case WM_DPICHANGED: {
      tool->dpi = LOWORD(wparam);
      if (tool->dpi == 0) {
        tool->dpi = 96;
      }
      tool->scale = static_cast<float>(tool->dpi) / 96.0f;
      if (tool->font) {
        DeleteObject(tool->font);
        tool->font = nullptr;
      }
      LOGFONTW lf{};
      lf.lfHeight = -MulDiv(16, static_cast<int>(tool->dpi), 96);
      lf.lfWeight = FW_NORMAL;
      wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
      tool->font = CreateFontIndirectW(&lf);
      ApplyFontToChildren(tool);
      if (tool->mode == Mode::DataTraverse) {
        if (tool->traverse_icons) {
          ImageList_Destroy(tool->traverse_icons);
          tool->traverse_icons = nullptr;
        }
        tool->traverse_icons = CreateTraverseIconList(tool->dpi);
        if (tool->list && tool->traverse_icons) {
          ListView_SetImageList(tool->list, tool->traverse_icons, LVSIL_SMALL);
        }
        UpdateTraverseMenuState(tool);
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
      LayoutControls(tool, rc.right - rc.left, rc.bottom - rc.top);
      return 0;
    }
    case WM_CLOSE:
      ShowWindow(hwnd, SW_HIDE);
      return 0;
    case WM_INITMENUPOPUP: {
      if (tool->mode == Mode::DataTraverse) {
        UpdateTraverseMenuState(tool);
      }
      return 0;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      SetTextColor(hdc, RGB(230, 230, 230));
      SetBkColor(hdc, RGB(43, 43, 43));
      return reinterpret_cast<LRESULT>(tool->bg_brush ? tool->bg_brush : GetStockObject(BLACK_BRUSH));
    }
    case WM_ERASEBKGND: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      RECT rc{};
      GetClientRect(hwnd, &rc);
      FillRect(hdc, &rc, tool->bg_brush ? tool->bg_brush : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
      return 1;
    }
    case WM_DESTROY:
      if (tool->menu_bar) {
        SetMenu(hwnd, nullptr);
        DestroyMenu(tool->menu_bar);
        tool->menu_bar = nullptr;
        tool->menu_structure = nullptr;
        tool->menu_options = nullptr;
        tool->menu_type = nullptr;
        tool->menu_count = nullptr;
        tool->menu_stride = nullptr;
      }
      if (tool->font) {
        DeleteObject(tool->font);
        tool->font = nullptr;
      }
      if (tool->bg_brush) {
        DeleteObject(tool->bg_brush);
        tool->bg_brush = nullptr;
      }
      if (tool->traverse_icons) {
        ImageList_Destroy(tool->traverse_icons);
        tool->traverse_icons = nullptr;
      }
      tool->hwnd = nullptr;
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

}  // namespace r3::windows_client_ng::ui
