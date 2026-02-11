#include "ui/CeLayoutWindow.h"

#include "ui/AddAddressDialog.h"

#include <commctrl.h>
#include <wincodec.h>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <thread>

#include <dwmapi.h>

namespace r3::windows_client_ng::ui {

namespace {

constexpr UINT kCtrlEditScanValue = 42010;
constexpr UINT kCtrlEditScanStart = 42011;
constexpr UINT kCtrlEditScanEnd = 42012;
constexpr UINT kCtrlComboType = 42013;
constexpr UINT kCtrlComboCond = 42014;
constexpr UINT kCtrlComboRegion = 42015;
constexpr UINT kCtrlCheckHex = 42016;
constexpr UINT kCtrlCheckFast = 42019;
constexpr UINT kCtrlEditFastValue = 42020;
constexpr UINT kCtrlRadioAlign = 42021;
constexpr UINT kCtrlRadioLast = 42022;
constexpr UINT kCtrlCheckWritable = 42023;
constexpr UINT kCtrlCheckExecutable = 42024;
constexpr UINT kCtrlCheckCopy = 42025;
constexpr UINT kCtrlCheckActive = 42026;
constexpr UINT kCtrlScrollScan = 42030;
constexpr UINT kCtrlScrollAddr = 42031;
constexpr UINT kCtrlProcListUser = 42040;
constexpr UINT kCtrlProcListSystem = 42041;
constexpr UINT kCtrlProcInfo = 42042;
constexpr UINT kTimerProcPickerIcons = 42043;
constexpr UINT kCtrlProcTab = 42044;
constexpr UINT kCtrlProcFilter = 42045;
constexpr UINT kCtrlProcFilterLabel = 42046;
constexpr UINT kTimerProcPickerFilter = 42047;
constexpr UINT kMsgAutoBootstrapDone = WM_APP + 201;
constexpr UINT kCtrlModFilter = 42050;
constexpr UINT kCtrlModList = 42051;
constexpr UINT kCtrlModInfo = 42052;
constexpr UINT kMenuCtxScanAdd = 42160;
constexpr UINT kMenuCtxScanAddEdit = 42161;
constexpr UINT kMenuCtxScanOpenMemory = 42162;
constexpr UINT kMenuCtxScanCopyAddr = 42163;
constexpr UINT kMenuCtxScanCopyAddrValue = 42164;
constexpr UINT kMenuCtxScanBatchAdd = 42165;
constexpr UINT kMenuCtxAddrEditDesc = 42180;
constexpr UINT kMenuCtxAddrEditValue = 42181;
constexpr UINT kMenuCtxAddrToggleFreeze = 42182;
constexpr UINT kMenuCtxAddrOpenMemory = 42183;
constexpr UINT kMenuCtxAddrCopyEntry = 42184;
constexpr UINT kMenuCtxAddrDelete = 42185;
constexpr UINT kMenuCtxAddrBatchActivate = 42186;
constexpr UINT kMenuCtxAddrBatchFreeze = 42187;
constexpr UINT kMenuCtxAddrBatchDelete = 42188;
constexpr float kScanRightPanelWidth = 352.0f;

struct AutoBootstrapResult {
  bool device_online = false;
  bool push_attempted = false;
  bool push_ok = false;
  bool forward_attempted = false;
  bool forward_ok = false;
  std::wstring status;
};

constexpr const wchar_t* kScanValueTypeNames[] = {
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

constexpr const wchar_t* kScanConditionNames[] = {
    L"精确数值 (=)",
    L"不等于 (!=)",
    L"大于 (>)",
    L"小于 (<)",
    L"大于等于 (>=)",
    L"小于等于 (<=)",
    L"已改变 (Changed)",
    L"未改变 (Unchanged)",
};

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

constexpr protocol::ComparisonType kCondMap[] = {
    protocol::ComparisonType::EQ,
    protocol::ComparisonType::NE,
    protocol::ComparisonType::GT,
    protocol::ComparisonType::LT,
    protocol::ComparisonType::GE,
    protocol::ComparisonType::LE,
    protocol::ComparisonType::CHANGED,
    protocol::ComparisonType::UNCHANGED,
};

struct GGRegionOptionDef {
  uint8_t code = protocol::GG_REGION_NONE;
  const wchar_t* code_text = L"";
  const wchar_t* label = L"";
};

constexpr GGRegionOptionDef kGGRegionOptionDefs[] = {
    {protocol::GG_REGION_XA, L"XA", L"Code App"},
    {protocol::GG_REGION_A, L"A", L"Anonymous"},
    {protocol::GG_REGION_O, L"O", L"Other"},
    {protocol::GG_REGION_BSS, L".bss", L"C++ .bss"},
    {protocol::GG_REGION_JH, L"jh", L"Java Heap"},
    {protocol::GG_REGION_CH, L"ch", L"C++ Heap"},
    {protocol::GG_REGION_CA, L"ca", L"C++ Alloc"},
    {protocol::GG_REGION_PS, L"ps", L"PPSSPP"},
    {protocol::GG_REGION_J, L"J", L"Java"},
    {protocol::GG_REGION_S, L"S", L"Stack"},
    {protocol::GG_REGION_AS, L"As", L"Ashmem"},
    {protocol::GG_REGION_V, L"V", L"Video"},
    {protocol::GG_REGION_XS, L"XS", L"Code System"},
};

template <typename T>
void SafeRelease(T** ptr) {
  if (ptr && *ptr) {
    (*ptr)->Release();
    *ptr = nullptr;
  }
}

D2D1_COLOR_F Rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a = 255) {
  return D2D1::ColorF(
      static_cast<float>(r) / 255.0f,
      static_cast<float>(g) / 255.0f,
      static_cast<float>(b) / 255.0f,
      static_cast<float>(a) / 255.0f);
}

std::filesystem::path GetExeDir() {
  wchar_t path[MAX_PATH] = {0};
  const DWORD len = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
  if (len == 0 || len >= std::size(path)) {
    return {};
  }
  std::filesystem::path exe_path(path);
  return exe_path.parent_path();
}

HBRUSH GetDialogDarkBrush() {
  static HBRUSH brush = CreateSolidBrush(RGB(43, 43, 43));
  return brush ? brush : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
}

void ApplyExplorerTheme(HWND hwnd, bool dark) {
  if (!hwnd) {
    return;
  }
  using SetWindowThemeFn = HRESULT(WINAPI*)(HWND, LPCWSTR, LPCWSTR);
  static SetWindowThemeFn fn = []() -> SetWindowThemeFn {
    HMODULE lib = LoadLibraryW(L"uxtheme.dll");
    if (!lib) {
      return nullptr;
    }
    return reinterpret_cast<SetWindowThemeFn>(GetProcAddress(lib, "SetWindowTheme"));
  }();
  if (!fn) {
    return;
  }
  if (dark) {
    fn(hwnd, L"DarkMode_Explorer", nullptr);
  } else {
    fn(hwnd, L"Explorer", nullptr);
  }
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

bool RectContains(const D2D1_RECT_F& rect, const POINT& pt) {
  const float x = static_cast<float>(pt.x);
  const float y = static_cast<float>(pt.y);
  return x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
}

std::wstring ToLowerWide(std::wstring text) {
  std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
    return static_cast<wchar_t>(std::towlower(ch));
  });
  return text;
}

bool ContainsWideInsensitive(const std::wstring& text, const std::wstring& needle) {
  if (needle.empty()) {
    return true;
  }
  const std::wstring text_l = ToLowerWide(text);
  const std::wstring needle_l = ToLowerWide(needle);
  return text_l.find(needle_l) != std::wstring::npos;
}

int TypeToIndex(protocol::ValueType type) {
  for (size_t i = 0; i < std::size(kTypeMap); ++i) {
    if (kTypeMap[i] == type) {
      return static_cast<int>(i);
    }
  }
  return 2;
}

int CondToIndex(protocol::ComparisonType cond) {
  for (size_t i = 0; i < std::size(kCondMap); ++i) {
    if (kCondMap[i] == cond) {
      return static_cast<int>(i);
    }
  }
  return 0;
}

const GGRegionOptionDef* FindGGOptionByCode(uint8_t code) {
  for (const auto& opt : kGGRegionOptionDefs) {
    if (opt.code == code) {
      return &opt;
    }
  }
  return nullptr;
}

std::wstring BuildGGRegionOptionText(const GGRegionOptionDef& opt) {
  std::wstring text = L"GG: ";
  text += opt.code_text ? opt.code_text : L"?";
  if (opt.label && *opt.label) {
    text += L" (";
    text += opt.label;
    text += L")";
  }
  return text;
}

const wchar_t* ValueTypeName(protocol::ValueType type) {
  switch (type) {
    case protocol::ValueType::U8: return L"1 Byte";
    case protocol::ValueType::U16: return L"2 Bytes";
    case protocol::ValueType::U32: return L"4 Bytes";
    case protocol::ValueType::U64: return L"8 Bytes";
    case protocol::ValueType::S32: return L"4 Bytes (Signed)";
    case protocol::ValueType::S64: return L"8 Bytes (Signed)";
    case protocol::ValueType::FLOAT: return L"Float";
    case protocol::ValueType::DOUBLE: return L"Double";
    case protocol::ValueType::STRING: return L"String";
    case protocol::ValueType::AOB: return L"Array of Byte";
    case protocol::ValueType::BINARY: return L"Binary";
    case protocol::ValueType::ALL: return L"All";
    default: return L"4 Bytes";
  }
}

protocol::ValueType NormalizeEntryValueType(protocol::ValueType type) {
  switch (type) {
    case protocol::ValueType::STRING:
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
      return protocol::ValueType::U8;
    case protocol::ValueType::ALL:
      return protocol::ValueType::U32;
    default:
      return type;
  }
}

bool ComparisonNeedsInput(protocol::ComparisonType cond) {
  return cond != protocol::ComparisonType::CHANGED &&
         cond != protocol::ComparisonType::UNCHANGED;
}

void UpdateScanValueInputState(HWND value_edit,
                               HWND hex_check,
                               protocol::ComparisonType cond) {
  const BOOL enable = ComparisonNeedsInput(cond) ? TRUE : FALSE;
  if (value_edit) {
    EnableWindow(value_edit, enable);
  }
  if (hex_check) {
    EnableWindow(hex_check, enable);
  }
}

std::string TrimAscii(const std::string& text) {
  const char* ws = " \t\r\n";
  const size_t start = text.find_first_not_of(ws);
  if (start == std::string::npos) {
    return "";
  }
  const size_t end = text.find_last_not_of(ws);
  return text.substr(start, end - start + 1);
}

std::string ToLowerAscii(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return text;
}

std::wstring ReadEnvWide(const wchar_t* key) {
  if (!key || !*key) {
    return L"";
  }
  wchar_t buf[2048] = {0};
  const DWORD n = GetEnvironmentVariableW(key, buf, static_cast<DWORD>(std::size(buf)));
  if (n == 0 || n >= std::size(buf)) {
    return L"";
  }
  return std::wstring(buf, buf + n);
}

std::wstring QuoteCommandArg(const std::wstring& value) {
  if (value.empty()) {
    return L"\"\"";
  }
  bool need_quote = false;
  for (wchar_t ch : value) {
    if (ch == L' ' || ch == L'\t' || ch == L'"') {
      need_quote = true;
      break;
    }
  }
  if (!need_quote) {
    return value;
  }
  std::wstring out;
  out.reserve(value.size() + 2);
  out.push_back(L'"');
  size_t slash_count = 0;
  for (wchar_t ch : value) {
    if (ch == L'\\') {
      ++slash_count;
      continue;
    }
    if (ch == L'"') {
      out.append(slash_count * 2 + 1, L'\\');
      out.push_back(L'"');
      slash_count = 0;
      continue;
    }
    if (slash_count > 0) {
      out.append(slash_count, L'\\');
      slash_count = 0;
    }
    out.push_back(ch);
  }
  if (slash_count > 0) {
    out.append(slash_count * 2, L'\\');
  }
  out.push_back(L'"');
  return out;
}

std::wstring BuildCommandLine(const std::wstring& exe_path, const std::vector<std::wstring>& args) {
  std::wstring cmd = QuoteCommandArg(exe_path);
  for (const auto& arg : args) {
    cmd.push_back(L' ');
    cmd += QuoteCommandArg(arg);
  }
  return cmd;
}

bool RunProcessAndWait(const std::wstring& exe_path,
                       const std::vector<std::wstring>& args,
                       DWORD timeout_ms,
                       DWORD* out_exit_code) {
  if (out_exit_code) {
    *out_exit_code = static_cast<DWORD>(-1);
  }
  if (exe_path.empty()) {
    return false;
  }

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi{};

  std::wstring cmd = BuildCommandLine(exe_path, args);
  std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
  cmd_buf.push_back(L'\0');
  BOOL created = CreateProcessW(nullptr,
                                cmd_buf.data(),
                                nullptr,
                                nullptr,
                                FALSE,
                                CREATE_NO_WINDOW,
                                nullptr,
                                nullptr,
                                &si,
                                &pi);
  if (!created) {
    return false;
  }

  const DWORD wait_code = WaitForSingleObject(pi.hProcess, timeout_ms == 0 ? INFINITE : timeout_ms);
  DWORD exit_code = static_cast<DWORD>(-1);
  if (wait_code == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 1000);
    GetExitCodeProcess(pi.hProcess, &exit_code);
  } else {
    GetExitCodeProcess(pi.hProcess, &exit_code);
  }
  if (out_exit_code) {
    *out_exit_code = exit_code;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return wait_code == WAIT_OBJECT_0;
}

std::filesystem::path SearchPathExecutable(const wchar_t* exe_name) {
  if (!exe_name || !*exe_name) {
    return {};
  }
  wchar_t buf[4096] = {0};
  const DWORD n = SearchPathW(nullptr, exe_name, nullptr, static_cast<DWORD>(std::size(buf)), buf, nullptr);
  if (n == 0 || n >= std::size(buf)) {
    return {};
  }
  return std::filesystem::path(buf);
}

bool ParseBool(const std::string& text, bool* out) {
  const std::string value = ToLowerAscii(TrimAscii(text));
  if (value == "1" || value == "true" || value == "yes" || value == "on") {
    if (out) *out = true;
    return true;
  }
  if (value == "0" || value == "false" || value == "no" || value == "off") {
    if (out) *out = false;
    return true;
  }
  return false;
}

bool ParseInt64(const std::string& text, int64_t* out) {
  try {
    size_t idx = 0;
    const int64_t value = std::stoll(text, &idx, 0);
    if (idx == 0) {
      return false;
    }
    if (out) {
      *out = value;
    }
    return true;
  } catch (...) {
    return false;
  }
}

struct IconAtlasRaw {
  struct Rect {
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
  };
  uint32_t width = 0;
  uint32_t height = 0;
  std::unordered_map<std::string, Rect> icon_rects;
  std::vector<uint8_t> pixels_bgra;
  bool loaded = false;
};

bool LoadIconAtlasRaw(IconAtlasRaw* out) {
  if (!out || out->loaded) {
    return out && out->loaded;
  }

  const std::filesystem::path atlas_path = GetExeDir() / "generated" / "icons" / "IconAtlas.bin";
  std::ifstream file(atlas_path, std::ios::binary);
  if (!file) {
    return false;
  }

  struct Header {
    char magic[4];
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t count;
    uint32_t table_size;
  };

  Header header{};
  file.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (!file || std::memcmp(header.magic, "R3IA", 4) != 0 || header.version != 1) {
    return false;
  }

  std::vector<uint8_t> table(header.table_size);
  file.read(reinterpret_cast<char*>(table.data()), static_cast<std::streamsize>(table.size()));
  if (!file) {
    return false;
  }

  out->icon_rects.clear();
  size_t offset = 0;
  while (offset + 12 <= table.size()) {
    uint16_t name_len = 0;
    uint16_t reserved = 0;
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t w = 0;
    uint16_t h = 0;
    std::memcpy(&name_len, table.data() + offset, 2);
    std::memcpy(&reserved, table.data() + offset + 2, 2);
    std::memcpy(&x, table.data() + offset + 4, 2);
    std::memcpy(&y, table.data() + offset + 6, 2);
    std::memcpy(&w, table.data() + offset + 8, 2);
    std::memcpy(&h, table.data() + offset + 10, 2);
    (void)reserved;
    offset += 12;
    if (offset + name_len > table.size()) {
      break;
    }
    std::string id(reinterpret_cast<const char*>(table.data() + offset), name_len);
    offset += name_len;
    IconAtlasRaw::Rect rect{};
    rect.x = x;
    rect.y = y;
    rect.w = w;
    rect.h = h;
    out->icon_rects.emplace(std::move(id), rect);
  }

  const size_t pixel_count = static_cast<size_t>(header.width) * static_cast<size_t>(header.height);
  std::vector<uint8_t> rgba(pixel_count * 4);
  file.read(reinterpret_cast<char*>(rgba.data()), static_cast<std::streamsize>(rgba.size()));
  if (!file) {
    return false;
  }
  for (size_t i = 0; i + 3 < rgba.size(); i += 4) {
    std::swap(rgba[i], rgba[i + 2]);
  }

  out->width = header.width;
  out->height = header.height;
  out->pixels_bgra = std::move(rgba);
  out->loaded = true;
  return true;
}

uint32_t SampleBGRA(const IconAtlasRaw& atlas, int x, int y) {
  x = std::clamp(x, 0, static_cast<int>(atlas.width) - 1);
  y = std::clamp(y, 0, static_cast<int>(atlas.height) - 1);
  const size_t off = (static_cast<size_t>(y) * atlas.width + static_cast<size_t>(x)) * 4;
  uint32_t pixel = 0;
  std::memcpy(&pixel, atlas.pixels_bgra.data() + off, sizeof(pixel));
  return pixel;
}

uint32_t LerpColor(uint32_t a, uint32_t b, float t) {
  const uint8_t ab = static_cast<uint8_t>(a & 0xFF);
  const uint8_t ag = static_cast<uint8_t>((a >> 8) & 0xFF);
  const uint8_t ar = static_cast<uint8_t>((a >> 16) & 0xFF);
  const uint8_t aa = static_cast<uint8_t>((a >> 24) & 0xFF);
  const uint8_t bb = static_cast<uint8_t>(b & 0xFF);
  const uint8_t bg = static_cast<uint8_t>((b >> 8) & 0xFF);
  const uint8_t br = static_cast<uint8_t>((b >> 16) & 0xFF);
  const uint8_t ba = static_cast<uint8_t>((b >> 24) & 0xFF);

  const auto lerp = [t](uint8_t v0, uint8_t v1) -> uint8_t {
    return static_cast<uint8_t>(std::lround(static_cast<float>(v0) + (static_cast<float>(v1) - static_cast<float>(v0)) * t));
  };
  const uint8_t rb = lerp(ab, bb);
  const uint8_t rg = lerp(ag, bg);
  const uint8_t rr = lerp(ar, br);
  const uint8_t ra = lerp(aa, ba);
  return (static_cast<uint32_t>(ra) << 24) | (static_cast<uint32_t>(rr) << 16) |
         (static_cast<uint32_t>(rg) << 8) | static_cast<uint32_t>(rb);
}

uint32_t SampleBilinear(const IconAtlasRaw& atlas, float x, float y) {
  const int x0 = static_cast<int>(std::floor(x));
  const int y0 = static_cast<int>(std::floor(y));
  const int x1 = x0 + 1;
  const int y1 = y0 + 1;
  const float tx = x - static_cast<float>(x0);
  const float ty = y - static_cast<float>(y0);
  const uint32_t p00 = SampleBGRA(atlas, x0, y0);
  const uint32_t p10 = SampleBGRA(atlas, x1, y0);
  const uint32_t p01 = SampleBGRA(atlas, x0, y1);
  const uint32_t p11 = SampleBGRA(atlas, x1, y1);
  const uint32_t p0 = LerpColor(p00, p10, tx);
  const uint32_t p1 = LerpColor(p01, p11, tx);
  return LerpColor(p0, p1, ty);
}

HBITMAP CreateMenuIconBitmap(const IconAtlasRaw& atlas, const char* id, int size_px) {
  if (!id || size_px <= 0) {
    return nullptr;
  }
  const auto it = atlas.icon_rects.find(id);
  if (it == atlas.icon_rects.end()) {
    return nullptr;
  }
  const IconAtlasRaw::Rect& r = it->second;
  if (r.w <= 0 || r.h <= 0) {
    return nullptr;
  }

  BITMAPINFO bi{};
  bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bi.bmiHeader.biWidth = size_px;
  bi.bmiHeader.biHeight = -size_px;
  bi.bmiHeader.biPlanes = 1;
  bi.bmiHeader.biBitCount = 32;
  bi.bmiHeader.biCompression = BI_RGB;

  void* bits = nullptr;
  HBITMAP bmp = CreateDIBSection(nullptr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
  if (!bmp || !bits) {
    if (bmp) {
      DeleteObject(bmp);
    }
    return nullptr;
  }

  uint32_t* dst = reinterpret_cast<uint32_t*>(bits);
  for (int y = 0; y < size_px; ++y) {
    for (int x = 0; x < size_px; ++x) {
      const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(size_px);
      const float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(size_px);
      const float sx = static_cast<float>(r.x) + u * static_cast<float>(r.w) - 0.5f;
      const float sy = static_cast<float>(r.y) + v * static_cast<float>(r.h) - 0.5f;
      dst[static_cast<size_t>(y) * static_cast<size_t>(size_px) + static_cast<size_t>(x)] = SampleBilinear(atlas, sx, sy);
    }
  }
  return bmp;
}

void SetMenuBitmap(HMENU menu, UINT cmd, HBITMAP bitmap) {
  if (!menu || !bitmap) {
    return;
  }
  MENUITEMINFOW mii{};
  mii.cbSize = sizeof(mii);
  mii.fMask = MIIM_BITMAP;
  mii.hbmpItem = bitmap;
  SetMenuItemInfoW(menu, cmd, FALSE, &mii);
}

protocol::ComparisonType InvertComparison(protocol::ComparisonType cmp) {
  switch (cmp) {
    case protocol::ComparisonType::EQ:
      return protocol::ComparisonType::NE;
    case protocol::ComparisonType::NE:
      return protocol::ComparisonType::EQ;
    case protocol::ComparisonType::GT:
      return protocol::ComparisonType::LE;
    case protocol::ComparisonType::LT:
      return protocol::ComparisonType::GE;
    case protocol::ComparisonType::GE:
      return protocol::ComparisonType::LT;
    case protocol::ComparisonType::LE:
      return protocol::ComparisonType::GT;
    case protocol::ComparisonType::CHANGED:
      return protocol::ComparisonType::UNCHANGED;
    case protocol::ComparisonType::UNCHANGED:
      return protocol::ComparisonType::CHANGED;
    default:
      return cmp;
  }
}

class ExprParser {
 public:
  explicit ExprParser(const std::wstring& text) : text_(text) {}

  bool Parse(double* out) {
    if (!out) {
      return false;
    }
    SkipWs();
    double v = 0.0;
    if (!ParseExpr(&v)) {
      return false;
    }
    SkipWs();
    if (pos_ != text_.size()) {
      return false;
    }
    *out = v;
    return true;
  }

 private:
  void SkipWs() {
    while (pos_ < text_.size() && (text_[pos_] == L' ' || text_[pos_] == L'\t' || text_[pos_] == L'\r' || text_[pos_] == L'\n')) {
      ++pos_;
    }
  }

  bool ParseExpr(double* out) {
    double lhs = 0.0;
    if (!ParseTerm(&lhs)) {
      return false;
    }
    while (true) {
      SkipWs();
      if (pos_ >= text_.size()) {
        break;
      }
      const wchar_t op = text_[pos_];
      if (op != L'+' && op != L'-') {
        break;
      }
      ++pos_;
      double rhs = 0.0;
      if (!ParseTerm(&rhs)) {
        return false;
      }
      lhs = (op == L'+') ? (lhs + rhs) : (lhs - rhs);
    }
    *out = lhs;
    return true;
  }

  bool ParseTerm(double* out) {
    double lhs = 0.0;
    if (!ParseFactor(&lhs)) {
      return false;
    }
    while (true) {
      SkipWs();
      if (pos_ >= text_.size()) {
        break;
      }
      const wchar_t op = text_[pos_];
      if (op != L'*' && op != L'/') {
        break;
      }
      ++pos_;
      double rhs = 0.0;
      if (!ParseFactor(&rhs)) {
        return false;
      }
      if (op == L'*') {
        lhs *= rhs;
      } else {
        if (rhs == 0.0) {
          return false;
        }
        lhs /= rhs;
      }
    }
    *out = lhs;
    return true;
  }

  bool ParseFactor(double* out) {
    SkipWs();
    if (pos_ >= text_.size()) {
      return false;
    }
    if (text_[pos_] == L'+') {
      ++pos_;
      return ParseFactor(out);
    }
    if (text_[pos_] == L'-') {
      ++pos_;
      double v = 0.0;
      if (!ParseFactor(&v)) {
        return false;
      }
      *out = -v;
      return true;
    }
    if (text_[pos_] == L'(') {
      ++pos_;
      if (!ParseExpr(out)) {
        return false;
      }
      SkipWs();
      if (pos_ >= text_.size() || text_[pos_] != L')') {
        return false;
      }
      ++pos_;
      return true;
    }
    return ParseNumber(out);
  }

  bool ParseNumber(double* out) {
    SkipWs();
    if (pos_ >= text_.size()) {
      return false;
    }
    const size_t start = pos_;
    if (text_[pos_] == L'0' && pos_ + 1 < text_.size() && (text_[pos_ + 1] == L'x' || text_[pos_ + 1] == L'X')) {
      pos_ += 2;
      size_t hex_start = pos_;
      while (pos_ < text_.size() && std::iswxdigit(text_[pos_])) {
        ++pos_;
      }
      if (pos_ == hex_start) {
        return false;
      }
      const std::wstring token = text_.substr(start, pos_ - start);
      wchar_t* endptr = nullptr;
      const unsigned long long v = std::wcstoull(token.c_str(), &endptr, 0);
      if (endptr == token.c_str()) {
        return false;
      }
      *out = static_cast<double>(v);
      return true;
    }
    bool has_digit = false;
    while (pos_ < text_.size() && std::iswdigit(text_[pos_])) {
      has_digit = true;
      ++pos_;
    }
    if (pos_ < text_.size() && text_[pos_] == L'.') {
      ++pos_;
      while (pos_ < text_.size() && std::iswdigit(text_[pos_])) {
        has_digit = true;
        ++pos_;
      }
    }
    if (!has_digit) {
      return false;
    }
    const std::wstring token = text_.substr(start, pos_ - start);
    wchar_t* endptr = nullptr;
    const double v = std::wcstod(token.c_str(), &endptr);
    if (endptr == token.c_str()) {
      return false;
    }
    *out = v;
    return true;
  }

  const std::wstring& text_;
  size_t pos_ = 0;
};

std::string ValueTypeToString(protocol::ValueType type) {
  switch (type) {
    case protocol::ValueType::U8: return "U8";
    case protocol::ValueType::U16: return "U16";
    case protocol::ValueType::U32: return "U32";
    case protocol::ValueType::U64: return "U64";
    case protocol::ValueType::S32: return "S32";
    case protocol::ValueType::S64: return "S64";
    case protocol::ValueType::FLOAT: return "FLOAT";
    case protocol::ValueType::DOUBLE: return "DOUBLE";
    case protocol::ValueType::STRING: return "STRING";
    case protocol::ValueType::AOB: return "AOB";
    case protocol::ValueType::BINARY: return "BINARY";
    case protocol::ValueType::ALL: return "ALL";
    default: return "U32";
  }
}

protocol::ValueType ParseValueType(const std::string& text) {
  const std::string value = ToLowerAscii(TrimAscii(text));
  if (value == "u8") return protocol::ValueType::U8;
  if (value == "u16") return protocol::ValueType::U16;
  if (value == "u32") return protocol::ValueType::U32;
  if (value == "u64") return protocol::ValueType::U64;
  if (value == "s32") return protocol::ValueType::S32;
  if (value == "s64") return protocol::ValueType::S64;
  if (value == "float") return protocol::ValueType::FLOAT;
  if (value == "double") return protocol::ValueType::DOUBLE;
  if (value == "string" || value == "str") return protocol::ValueType::STRING;
  if (value == "aob" || value == "arrayofbyte" || value == "array_of_byte") return protocol::ValueType::AOB;
  if (value == "binary" || value == "bin") return protocol::ValueType::BINARY;
  if (value == "all") return protocol::ValueType::ALL;
  return protocol::ValueType::U32;
}

std::wstring TrimWide(const std::wstring& text) {
  const wchar_t* ws = L" \t\r\n";
  const size_t start = text.find_first_not_of(ws);
  if (start == std::wstring::npos) {
    return L"";
  }
  const size_t end = text.find_last_not_of(ws);
  return text.substr(start, end - start + 1);
}

bool ParseUint64Wide(const std::wstring& text, bool hex, uint64_t* out) {
  const std::wstring value = TrimWide(text);
  if (value.empty()) {
    return false;
  }
  wchar_t* endptr = nullptr;
  const int base = hex ? 16 : 0;
  unsigned long long v = std::wcstoull(value.c_str(), &endptr, base);
  if (endptr == value.c_str()) {
    return false;
  }
  if (out) {
    *out = static_cast<uint64_t>(v);
  }
  return true;
}

bool ParseInt64Wide(const std::wstring& text, bool hex, int64_t* out) {
  const std::wstring value = TrimWide(text);
  if (value.empty()) {
    return false;
  }
  wchar_t* endptr = nullptr;
  const int base = hex ? 16 : 0;
  long long v = std::wcstoll(value.c_str(), &endptr, base);
  if (endptr == value.c_str()) {
    return false;
  }
  if (out) {
    *out = static_cast<int64_t>(v);
  }
  return true;
}

bool BuildValueBytesFromText(protocol::ValueType type,
                             const std::wstring& text,
                             bool hex,
                             std::vector<uint8_t>* out) {
  if (!out) return false;
  out->clear();
  switch (type) {
    case protocol::ValueType::U8: {
      uint64_t v = 0;
      if (!ParseUint64Wide(text, hex, &v)) return false;
      const uint8_t value = static_cast<uint8_t>(v);
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::U16: {
      uint64_t v = 0;
      if (!ParseUint64Wide(text, hex, &v)) return false;
      const uint16_t value = static_cast<uint16_t>(v);
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::U32: {
      uint64_t v = 0;
      if (!ParseUint64Wide(text, hex, &v)) return false;
      const uint32_t value = static_cast<uint32_t>(v);
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::U64: {
      uint64_t v = 0;
      if (!ParseUint64Wide(text, hex, &v)) return false;
      const uint64_t value = v;
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::S32: {
      int64_t v = 0;
      if (!ParseInt64Wide(text, hex, &v)) return false;
      const int32_t value = static_cast<int32_t>(v);
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::S64: {
      int64_t v = 0;
      if (!ParseInt64Wide(text, hex, &v)) return false;
      const int64_t value = v;
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::FLOAT: {
      float value = 0.0f;
      if (hex) {
        uint64_t bits = 0;
        if (!ParseUint64Wide(text, true, &bits)) return false;
        uint32_t v32 = static_cast<uint32_t>(bits);
        std::memcpy(&value, &v32, sizeof(value));
      } else {
        const std::wstring trimmed = TrimWide(text);
        if (trimmed.empty()) return false;
        wchar_t* endptr = nullptr;
        value = std::wcstof(trimmed.c_str(), &endptr);
        if (endptr == trimmed.c_str()) return false;
      }
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    case protocol::ValueType::DOUBLE: {
      double value = 0.0;
      if (hex) {
        uint64_t bits = 0;
        if (!ParseUint64Wide(text, true, &bits)) return false;
        std::memcpy(&value, &bits, sizeof(value));
      } else {
        const std::wstring trimmed = TrimWide(text);
        if (trimmed.empty()) return false;
        wchar_t* endptr = nullptr;
        value = std::wcstod(trimmed.c_str(), &endptr);
        if (endptr == trimmed.c_str()) return false;
      }
      out->assign(reinterpret_cast<const uint8_t*>(&value),
                  reinterpret_cast<const uint8_t*>(&value) + sizeof(value));
      return true;
    }
    default:
      break;
  }
  return false;
}

struct ValueDialogState {
  std::wstring title;
  std::wstring label;
  std::wstring text;
  bool done = false;
  bool ok = false;
  HWND hwnd = nullptr;
  HWND edit = nullptr;
};

LRESULT CALLBACK ValueDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  ValueDialogState* state = reinterpret_cast<ValueDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    state = reinterpret_cast<ValueDialogState*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
  }
  if (!state) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  switch (msg) {
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      if (cmd == IDOK) {
        wchar_t buf[512] = {0};
        if (state->edit) {
          GetWindowTextW(state->edit, buf, static_cast<int>(std::size(buf)));
        }
        state->text = buf;
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
      break;
    }
    case WM_CLOSE:
      state->ok = false;
      state->done = true;
      DestroyWindow(hwnd);
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

bool PromptValueDialog(HWND owner,
                       const wchar_t* title,
                       const wchar_t* label,
                       const wchar_t* preset,
                       std::wstring* out_text) {
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ValueDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"R3NgValueDialog";
    RegisterClassExW(&wc);
    registered = true;
  }

  ValueDialogState state{};
  state.title = title ? title : L"输入";
  state.label = label ? label : L"内容";
  state.text = preset ? preset : L"";

  const int width = 420;
  const int height = 160;
  RECT owner_rc{};
  int x = CW_USEDEFAULT;
  int y = CW_USEDEFAULT;
  if (owner && GetWindowRect(owner, &owner_rc)) {
    x = owner_rc.left + (owner_rc.right - owner_rc.left - width) / 2;
    y = owner_rc.top + (owner_rc.bottom - owner_rc.top - height) / 2;
  }
  state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                               L"R3NgValueDialog",
                               state.title.c_str(),
                               WS_POPUP | WS_CAPTION | WS_SYSMENU,
                               x,
                               y,
                               width,
                               height,
                               owner,
                               nullptr,
                               GetModuleHandleW(nullptr),
                               &state);
  if (!state.hwnd) {
    return false;
  }

  HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  CreateWindowExW(0,
                  L"STATIC",
                  state.label.c_str(),
                  WS_CHILD | WS_VISIBLE,
                  12,
                  14,
                  width - 24,
                  18,
                  state.hwnd,
                  nullptr,
                  GetModuleHandleW(nullptr),
                  nullptr);
  state.edit = CreateWindowExW(WS_EX_CLIENTEDGE,
                               L"EDIT",
                               state.text.c_str(),
                               WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                               12,
                               36,
                               width - 24,
                               24,
                               state.hwnd,
                               nullptr,
                               GetModuleHandleW(nullptr),
                               nullptr);
  HWND ok_btn = CreateWindowExW(0,
                                L"BUTTON",
                                L"确定",
                                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                width - 190,
                                72,
                                80,
                                26,
                                state.hwnd,
                                reinterpret_cast<HMENU>(IDOK),
                                GetModuleHandleW(nullptr),
                                nullptr);
  HWND cancel_btn = CreateWindowExW(0,
                                    L"BUTTON",
                                    L"取消",
                                    WS_CHILD | WS_VISIBLE,
                                    width - 100,
                                    72,
                                    80,
                                    26,
                                    state.hwnd,
                                    reinterpret_cast<HMENU>(IDCANCEL),
                                    GetModuleHandleW(nullptr),
                                    nullptr);
  SendMessageW(state.edit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
  SendMessageW(ok_btn, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
  SendMessageW(cancel_btn, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

  if (owner) {
    EnableWindow(owner, FALSE);
  }
  ShowWindow(state.hwnd, SW_SHOW);
  SetForegroundWindow(state.hwnd);
  SetFocus(state.edit);

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
    if (out_text) {
      *out_text = state.text;
    }
    return true;
  }
  return false;
}

bool IsSystemProcessName(const std::wstring& name) {
  const std::wstring n = ToLowerWide(TrimWide(name));
  if (n.empty()) {
    return true;
  }
  if (n[0] == L'[' || n.find(L'/') != std::wstring::npos) {
    return true;
  }
  if (n.rfind(L"com.android.", 0) == 0 ||
      n.rfind(L"com.google.android.", 0) == 0 ||
      n.rfind(L"android.", 0) == 0 ||
      n.rfind(L"androidx.", 0) == 0 ||
      n.rfind(L"vendor.", 0) == 0) {
    return true;
  }
  if (n.rfind(L"com.", 0) == 0 ||
      n.rfind(L"cn.", 0) == 0 ||
      n.rfind(L"org.", 0) == 0 ||
      n.rfind(L"net.", 0) == 0 ||
      n.rfind(L"io.", 0) == 0 ||
      n.rfind(L"app.", 0) == 0) {
    return false;
  }
  if (n.find(L'.') != std::wstring::npos) {
    return false;
  }
  static const wchar_t* kSystemNames[] = {
      L"init",         L"ueventd",      L"logd",          L"lmkd",      L"servicemanager",
      L"hwservicemanager",              L"vndservicemanager",           L"adbd",      L"zygote",
      L"zygote64",     L"system_server", L"surfaceflinger", L"audioserver",           L"mediaserver",
      L"cameraserver", L"vold",          L"netd",           L"wificond",               L"statsd",
      L"keystore",     L"installd",      L"thermal-engine", L"android.hardware",      L"vendor.",
  };
  for (const wchar_t* key : kSystemNames) {
    if (!key || !*key) {
      continue;
    }
    std::wstring prefix = key;
    if (n == prefix || n.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return true;
}

std::wstring BuildProcessDisplayLabel(const app::ProcessItem& proc) {
  wchar_t buf[512] = {0};
  std::swprintf(buf,
                std::size(buf),
                L"%6u  %ls",
                proc.pid,
                proc.name.empty() ? L"(unknown)" : proc.name.c_str());
  return buf;
}

void EnsureListViewControls() {
  static bool initialized = false;
  if (initialized) {
    return;
  }
  INITCOMMONCONTROLSEX icc{};
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES;
  InitCommonControlsEx(&icc);
  initialized = true;
}

int ProcessPickerIconIndex(const app::ProcessItem& proc, bool system_list) {
  if (proc.name.empty()) {
    return 2;
  }
  return system_list ? 1 : 0;
}

void ClearProcessPickerSelection(HWND list) {
  if (!list) {
    return;
  }
  int item = ListView_GetNextItem(list, -1, LVNI_SELECTED);
  while (item >= 0) {
    ListView_SetItemState(list, item, 0, LVIS_SELECTED | LVIS_FOCUSED);
    item = ListView_GetNextItem(list, item, LVNI_SELECTED);
  }
}

size_t GetSelectedProcessIndex(HWND list) {
  if (!list) {
    return std::numeric_limits<size_t>::max();
  }
  const int item = ListView_GetNextItem(list, -1, LVNI_SELECTED);
  if (item < 0) {
    return std::numeric_limits<size_t>::max();
  }
  LVITEMW info{};
  info.mask = LVIF_PARAM;
  info.iItem = item;
  if (!ListView_GetItem(list, &info)) {
    return std::numeric_limits<size_t>::max();
  }
  return static_cast<size_t>(info.lParam);
}

void ResizeProcessListColumns(HWND list, int list_w) {
  if (!list) {
    return;
  }
  const int pid_w = std::clamp(list_w / 4, 78, 120);
  ListView_SetColumnWidth(list, 0, pid_w);
  ListView_SetColumnWidth(list, 1, std::max(140, list_w - pid_w - 6));
}

void SetupProcessListView(HWND list) {
  if (!list) {
    return;
  }
  ListView_SetExtendedListViewStyle(
      list,
      LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
  ApplyExplorerTheme(list, true);
  ListView_SetBkColor(list, RGB(43, 43, 43));
  ListView_SetTextBkColor(list, RGB(43, 43, 43));
  ListView_SetTextColor(list, RGB(230, 230, 230));
  if (HWND header = ListView_GetHeader(list)) {
    ApplyExplorerTheme(header, true);
  }
  LVCOLUMNW col{};
  col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  col.iSubItem = 0;
  col.cx = 92;
  col.pszText = const_cast<LPWSTR>(L"PID");
  ListView_InsertColumn(list, 0, &col);
  col.iSubItem = 1;
  col.cx = 320;
  col.pszText = const_cast<LPWSTR>(L"进程名");
  ListView_InsertColumn(list, 1, &col);
}

std::unordered_map<uint32_t, std::vector<uint8_t>>& ProcessIconPngCache() {
  static std::unordered_map<uint32_t, std::vector<uint8_t>> cache;
  return cache;
}

std::unordered_map<std::wstring, std::vector<uint8_t>>& ProcessIconPngNameCache() {
  static std::unordered_map<std::wstring, std::vector<uint8_t>> cache;
  return cache;
}

std::filesystem::path GetProcessIconCacheDir() {
  std::error_code ec;
  const std::filesystem::path dir = GetExeDir() / "cache" / "process_icons";
  std::filesystem::create_directories(dir, ec);
  return dir;
}

std::filesystem::path GetProcessIconNameCacheDir() {
  std::error_code ec;
  const std::filesystem::path dir = GetExeDir() / "cache" / "process_icons_by_name";
  std::filesystem::create_directories(dir, ec);
  return dir;
}

std::wstring BuildProcessIconNameKey(const std::wstring& name) {
  std::wstring key = ToLowerWide(TrimWide(name));
  if (key.empty()) {
    return {};
  }
  for (wchar_t& ch : key) {
    const bool keep = (ch >= L'0' && ch <= L'9') ||
                      (ch >= L'a' && ch <= L'z') ||
                      ch == L'.' || ch == L'_' || ch == L'-';
    if (!keep) {
      ch = L'_';
    }
  }
  if (key.size() > 120) {
    key.resize(120);
  }
  return key;
}

bool LoadProcessIconPngFromMemoryCache(uint32_t pid, std::vector<uint8_t>* out_png) {
  if (!out_png || pid == 0) {
    return false;
  }
  auto& mem_cache = ProcessIconPngCache();
  const auto it = mem_cache.find(pid);
  if (it != mem_cache.end() && !it->second.empty()) {
    *out_png = it->second;
    return true;
  }
  return false;
}

bool LoadProcessIconPngFromCache(uint32_t pid, std::vector<uint8_t>* out_png) {
  if (!out_png || pid == 0) {
    return false;
  }
  if (LoadProcessIconPngFromMemoryCache(pid, out_png)) {
    return true;
  }
  auto& mem_cache = ProcessIconPngCache();
  const std::filesystem::path path = GetProcessIconCacheDir() / (std::to_wstring(pid) + L".png");
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  if (bytes.empty()) {
    return false;
  }
  mem_cache[pid] = bytes;
  *out_png = std::move(bytes);
  return true;
}

bool LoadProcessIconPngFromNameCache(const std::wstring& process_name, std::vector<uint8_t>* out_png) {
  if (!out_png) {
    return false;
  }
  const std::wstring key = BuildProcessIconNameKey(process_name);
  if (key.empty()) {
    return false;
  }
  auto& mem_cache = ProcessIconPngNameCache();
  const auto it = mem_cache.find(key);
  if (it != mem_cache.end() && !it->second.empty()) {
    *out_png = it->second;
    return true;
  }
  const std::filesystem::path path = GetProcessIconNameCacheDir() / (key + L".png");
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  if (bytes.empty()) {
    return false;
  }
  mem_cache[key] = bytes;
  *out_png = std::move(bytes);
  return true;
}

void SaveProcessIconPngToCache(uint32_t pid, const std::vector<uint8_t>& png) {
  if (pid == 0 || png.empty()) {
    return;
  }
  auto& mem_cache = ProcessIconPngCache();
  mem_cache[pid] = png;
  const std::filesystem::path path = GetProcessIconCacheDir() / (std::to_wstring(pid) + L".png");
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return;
  }
  file.write(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
}

void SaveProcessIconPngToNameCache(const std::wstring& process_name, const std::vector<uint8_t>& png) {
  if (png.empty()) {
    return;
  }
  const std::wstring key = BuildProcessIconNameKey(process_name);
  if (key.empty()) {
    return;
  }
  auto& mem_cache = ProcessIconPngNameCache();
  mem_cache[key] = png;
  const std::filesystem::path path = GetProcessIconNameCacheDir() / (key + L".png");
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return;
  }
  file.write(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
}

HIMAGELIST CreateProcessIconList() {
  HIMAGELIST icons = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 3, 1);
  if (!icons) {
    return nullptr;
  }
  const HICON icon_app = LoadIconW(nullptr, IDI_APPLICATION);
  const HICON icon_sys = LoadIconW(nullptr, IDI_INFORMATION);
  const HICON icon_unknown = LoadIconW(nullptr, IDI_WARNING);
  if (icon_app) {
    ImageList_AddIcon(icons, icon_app);
  }
  if (icon_sys) {
    ImageList_AddIcon(icons, icon_sys);
  }
  if (icon_unknown) {
    ImageList_AddIcon(icons, icon_unknown);
  }
  return icons;
}

HBITMAP DecodePngIconBitmap(const std::vector<uint8_t>& png, int icon_px) {
  if (png.empty() || icon_px <= 0) {
    return nullptr;
  }

  IWICImagingFactory* factory = nullptr;
  IWICStream* stream = nullptr;
  IWICBitmapDecoder* decoder = nullptr;
  IWICBitmapFrameDecode* frame = nullptr;
  IWICBitmapSource* source = nullptr;
  IWICBitmapScaler* scaler = nullptr;
  IWICFormatConverter* converter = nullptr;
  HBITMAP out_bitmap = nullptr;
  std::vector<uint8_t> pixels;
  auto cleanup = [&]() {
    SafeRelease(&converter);
    SafeRelease(&scaler);
    SafeRelease(&source);
    SafeRelease(&frame);
    SafeRelease(&decoder);
    SafeRelease(&stream);
    SafeRelease(&factory);
  };

  do {
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory,
                                  nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&factory));
    if (FAILED(hr) || !factory) {
      break;
    }
    hr = factory->CreateStream(&stream);
    if (FAILED(hr) || !stream) {
      break;
    }
    hr = stream->InitializeFromMemory(const_cast<BYTE*>(png.data()), static_cast<DWORD>(png.size()));
    if (FAILED(hr)) {
      break;
    }
    hr = factory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnLoad, &decoder);
    if (FAILED(hr) || !decoder) {
      break;
    }
    hr = decoder->GetFrame(0, &frame);
    if (FAILED(hr) || !frame) {
      break;
    }

    source = frame;
    frame->AddRef();
    UINT src_w = 0;
    UINT src_h = 0;
    frame->GetSize(&src_w, &src_h);
    if (src_w == 0 || src_h == 0) {
      break;
    }

    if (static_cast<int>(src_w) != icon_px || static_cast<int>(src_h) != icon_px) {
      hr = factory->CreateBitmapScaler(&scaler);
      if (FAILED(hr) || !scaler) {
        break;
      }
      hr = scaler->Initialize(frame,
                              static_cast<UINT>(icon_px),
                              static_cast<UINT>(icon_px),
                              WICBitmapInterpolationModeFant);
      if (FAILED(hr)) {
        break;
      }
      SafeRelease(&source);
      source = scaler;
      scaler->AddRef();
    }

    hr = factory->CreateFormatConverter(&converter);
    if (FAILED(hr) || !converter) {
      break;
    }
    hr = converter->Initialize(source,
                               GUID_WICPixelFormat32bppBGRA,
                               WICBitmapDitherTypeNone,
                               nullptr,
                               0.0,
                               WICBitmapPaletteTypeCustom);
    if (FAILED(hr)) {
      break;
    }
    UINT out_w = 0;
    UINT out_h = 0;
    converter->GetSize(&out_w, &out_h);
    if (out_w == 0 || out_h == 0 || out_w > 4096 || out_h > 4096) {
      break;
    }

    const UINT stride = out_w * 4;
    pixels.resize(static_cast<size_t>(stride) * static_cast<size_t>(out_h));
    hr = converter->CopyPixels(nullptr, stride, static_cast<UINT>(pixels.size()), pixels.data());
    if (FAILED(hr)) {
      break;
    }

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = static_cast<LONG>(out_w);
    bi.bmiHeader.biHeight = -static_cast<LONG>(out_h);
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    out_bitmap = CreateDIBSection(nullptr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!out_bitmap || !bits) {
      if (out_bitmap) {
        DeleteObject(out_bitmap);
        out_bitmap = nullptr;
      }
      break;
    }
    std::memcpy(bits, pixels.data(), pixels.size());
  } while (false);

  cleanup();
  return out_bitmap;
}

int AddPngIconToImageList(HIMAGELIST icons, const std::vector<uint8_t>& png) {
  if (!icons || png.empty()) {
    return -1;
  }
  HBITMAP bmp = DecodePngIconBitmap(png, 16);
  if (!bmp) {
    return -1;
  }
  const int idx = ImageList_Add(icons, bmp, nullptr);
  DeleteObject(bmp);
  return idx;
}

void PopulateProcessListView(HWND list,
                             HIMAGELIST* out_icons,
                             const std::vector<size_t>& indices,
                             const std::vector<app::ProcessItem>& processes,
                             bool system_list) {
  if (!list) {
    return;
  }
  SendMessageW(list, WM_SETREDRAW, FALSE, 0);
  ListView_DeleteAllItems(list);
  if (out_icons && *out_icons) {
    ListView_SetImageList(list, nullptr, LVSIL_SMALL);
    ImageList_Destroy(*out_icons);
    *out_icons = nullptr;
  }
  HIMAGELIST icons = CreateProcessIconList();
  if (icons) {
    ListView_SetImageList(list, icons, LVSIL_SMALL);
    if (out_icons) {
      *out_icons = icons;
    }
  }
  for (size_t row = 0; row < indices.size(); ++row) {
    const size_t proc_idx = indices[row];
    if (proc_idx >= processes.size()) {
      continue;
    }
    const auto& proc = processes[proc_idx];
    wchar_t pid_buf[32] = {0};
    std::swprintf(pid_buf, std::size(pid_buf), L"%u", proc.pid);
    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    if (icons) {
      item.mask |= LVIF_IMAGE;
      item.iImage = ProcessPickerIconIndex(proc, system_list);
    }
    item.iItem = static_cast<int>(row);
    item.iSubItem = 0;
    item.pszText = pid_buf;
    item.lParam = static_cast<LPARAM>(proc_idx);
    const int inserted = ListView_InsertItem(list, &item);
    if (inserted >= 0) {
      std::wstring name = proc.name.empty() ? L"(unknown)" : proc.name;
      ListView_SetItemText(list, inserted, 1, const_cast<LPWSTR>(name.c_str()));
    }
  }
  SendMessageW(list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(list, nullptr, FALSE);
}

struct ProcessPickerDialogState {
  services::ClientService* service = nullptr;
  const std::vector<app::ProcessItem>* processes = nullptr;
  std::vector<size_t> all_user_indices;
  std::vector<size_t> all_system_indices;
  std::vector<size_t> user_indices;
  std::vector<size_t> system_indices;
  size_t icon_user_cursor = 0;
  size_t icon_system_cursor = 0;
  size_t selected_process_index = std::numeric_limits<size_t>::max();
  int active_tab = 0;
  std::wstring filter_text;
  bool done = false;
  bool ok = false;
  HWND hwnd = nullptr;
  HWND tab = nullptr;
  HWND filter_label = nullptr;
  HWND filter_edit = nullptr;
  HWND list_user = nullptr;
  HWND list_system = nullptr;
  HWND info = nullptr;
  HWND ok_btn = nullptr;
  HWND cancel_btn = nullptr;
  HIMAGELIST icons_user = nullptr;
  HIMAGELIST icons_system = nullptr;
};

void LayoutProcessPickerDialog(ProcessPickerDialogState* state, int width, int height) {
  if (!state || !state->hwnd) {
    return;
  }
  const int margin = 12;
  const int top = 10;
  const int tab_h = 26;
  const int filter_h = 24;
  const int gap = 8;
  const int btn_w_ok = 120;
  const int btn_w_cancel = 80;
  const int btn_h = 28;
  const int info_h = 28;
  const int client_w = std::max(360, width);
  const int client_h = std::max(280, height);
  const int filter_y = top + tab_h + 6;
  const int list_top = filter_y + filter_h + 6;
  const int btn_y = client_h - margin - btn_h;
  const int info_y = btn_y - info_h - gap;
  const int list_h = std::max(100, info_y - list_top - gap);
  const int list_w = std::max(200, client_w - margin * 2);

  if (state->tab) {
    MoveWindow(state->tab, margin, top, list_w, tab_h, TRUE);
  }
  if (state->filter_label) {
    MoveWindow(state->filter_label, margin, filter_y + 2, 56, filter_h, TRUE);
  }
  if (state->filter_edit) {
    MoveWindow(state->filter_edit, margin + 58, filter_y, list_w - 58, filter_h, TRUE);
  }
  if (state->list_user) {
    MoveWindow(state->list_user, margin, list_top, list_w, list_h, TRUE);
    ResizeProcessListColumns(state->list_user, list_w - 2);
  }
  if (state->list_system) {
    MoveWindow(state->list_system, margin, list_top, list_w, list_h, TRUE);
    ResizeProcessListColumns(state->list_system, list_w - 2);
  }
  if (state->list_user && state->list_system) {
    ShowWindow(state->list_user, state->active_tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(state->list_system, state->active_tab == 1 ? SW_SHOW : SW_HIDE);
  }
  if (state->info) {
    MoveWindow(state->info, margin, info_y, client_w - margin * 2, info_h, TRUE);
  }
  if (state->ok_btn) {
    MoveWindow(state->ok_btn,
               client_w - margin - btn_w_cancel - gap - btn_w_ok,
               btn_y,
               btn_w_ok,
               btn_h,
               TRUE);
  }
  if (state->cancel_btn) {
    MoveWindow(state->cancel_btn, client_w - margin - btn_w_cancel, btn_y, btn_w_cancel, btn_h, TRUE);
  }
}

HWND ActiveProcessPickerList(ProcessPickerDialogState* state) {
  if (!state) {
    return nullptr;
  }
  return state->active_tab == 1 ? state->list_system : state->list_user;
}

void ApplyProcessPickerFilter(ProcessPickerDialogState* state) {
  if (!state || !state->processes) {
    return;
  }
  const auto selected_pid_from = [&](HWND list) -> uint32_t {
    const size_t idx = GetSelectedProcessIndex(list);
    if (idx == std::numeric_limits<size_t>::max() || idx >= state->processes->size()) {
      return 0;
    }
    return (*state->processes)[idx].pid;
  };
  const uint32_t prev_selected_pid =
      selected_pid_from(ActiveProcessPickerList(state)) != 0
          ? selected_pid_from(ActiveProcessPickerList(state))
          : (selected_pid_from(state->list_user) != 0 ? selected_pid_from(state->list_user)
                                                       : selected_pid_from(state->list_system));
  const int prev_top_user = state->list_user ? ListView_GetTopIndex(state->list_user) : 0;
  const int prev_top_system = state->list_system ? ListView_GetTopIndex(state->list_system) : 0;

  const std::wstring filter = ToLowerWide(TrimWide(state->filter_text));
  const auto matches = [&](size_t idx) -> bool {
    if (idx >= state->processes->size()) {
      return false;
    }
    if (filter.empty()) {
      return true;
    }
    const auto& proc = (*state->processes)[idx];
    wchar_t pid_buf[32] = {0};
    std::swprintf(pid_buf, std::size(pid_buf), L"%u", proc.pid);
    return ContainsWideInsensitive(proc.name, filter) ||
           ContainsWideInsensitive(std::wstring(pid_buf), filter);
  };

  state->user_indices.clear();
  state->system_indices.clear();
  for (size_t idx : state->all_user_indices) {
    if (matches(idx)) {
      state->user_indices.push_back(idx);
    }
  }
  for (size_t idx : state->all_system_indices) {
    if (matches(idx)) {
      state->system_indices.push_back(idx);
    }
  }

  state->icon_user_cursor = 0;
  state->icon_system_cursor = 0;
  if (state->list_user) {
    PopulateProcessListView(state->list_user,
                            &state->icons_user,
                            state->user_indices,
                            *state->processes,
                            false);
  }
  if (state->list_system) {
    PopulateProcessListView(state->list_system,
                            &state->icons_system,
                            state->system_indices,
                            *state->processes,
                            true);
  }

  if (state->active_tab == 0 && state->user_indices.empty() && !state->system_indices.empty()) {
    state->active_tab = 1;
  } else if (state->active_tab == 1 && state->system_indices.empty() && !state->user_indices.empty()) {
    state->active_tab = 0;
  }
  if (state->tab) {
    TabCtrl_SetCurSel(state->tab, state->active_tab);
  }
  RECT rc{};
  if (state->hwnd && GetClientRect(state->hwnd, &rc)) {
    LayoutProcessPickerDialog(state, rc.right - rc.left, rc.bottom - rc.top);
  }

  auto restore_top = [](HWND list, int top) {
    if (!list) {
      return;
    }
    const int count = ListView_GetItemCount(list);
    if (count <= 0) {
      return;
    }
    const int clamped = std::clamp(top, 0, count - 1);
    ListView_EnsureVisible(list, clamped, FALSE);
  };
  restore_top(state->list_user, prev_top_user);
  restore_top(state->list_system, prev_top_system);

  auto select_by_pid = [&](HWND list, uint32_t pid) -> bool {
    if (!list || pid == 0) {
      return false;
    }
    const int count = ListView_GetItemCount(list);
    for (int row = 0; row < count; ++row) {
      LVITEMW item{};
      item.mask = LVIF_PARAM;
      item.iItem = row;
      if (!ListView_GetItem(list, &item)) {
        continue;
      }
      const size_t idx = static_cast<size_t>(item.lParam);
      if (idx >= state->processes->size()) {
        continue;
      }
      if ((*state->processes)[idx].pid == pid) {
        ListView_SetItemState(list, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, row, FALSE);
        return true;
      }
    }
    return false;
  };

  bool restored = false;
  restored = select_by_pid(state->list_user, prev_selected_pid) || restored;
  restored = select_by_pid(state->list_system, prev_selected_pid) || restored;

  if (!restored) {
    HWND active = ActiveProcessPickerList(state);
    if (active && ListView_GetItemCount(active) > 0) {
      ListView_SetItemState(active, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      ListView_EnsureVisible(active, 0, FALSE);
    }
  }
}

void UpdateProcessPickerInfo(ProcessPickerDialogState* state) {
  if (!state || !state->info || !state->processes) {
    return;
  }
  std::wstring text;
  size_t selected = GetSelectedProcessIndex(ActiveProcessPickerList(state));
  if (selected == std::numeric_limits<size_t>::max()) {
    selected = GetSelectedProcessIndex(state->list_user);
  }
  if (selected == std::numeric_limits<size_t>::max()) {
    selected = GetSelectedProcessIndex(state->list_system);
  }
  if (selected != std::numeric_limits<size_t>::max() && selected < state->processes->size()) {
    const auto& proc = (*state->processes)[selected];
    wchar_t buf[512] = {0};
    std::swprintf(buf,
                  std::size(buf),
                  L"已选择: PID %u  %ls%s",
                  proc.pid,
                  proc.name.empty() ? L"(unknown)" : proc.name.c_str(),
                  state->filter_text.empty() ? L"" : L"  (过滤中)");
    text = buf;
  } else {
    wchar_t buf[512] = {0};
    std::swprintf(buf,
                  std::size(buf),
                  L"应用程序: %zu  |  系统进程: %zu  |  过滤: %ls  (Ctrl+F)",
                  state->user_indices.size(),
                  state->system_indices.size(),
                  state->filter_text.empty() ? L"(无)" : state->filter_text.c_str());
    text = buf;
  }
  SetWindowTextW(state->info, text.c_str());
}

bool ApplyNextRealProcessIcon(ProcessPickerDialogState* state, bool system_list) {
  if (!state || !state->processes) {
    return false;
  }
  const bool can_fetch_remote = state->service && state->service->IsConnected();
  HWND list = system_list ? state->list_system : state->list_user;
  HIMAGELIST icons = system_list ? state->icons_system : state->icons_user;
  if (!list || !icons) {
    return false;
  }

  const std::vector<size_t>& indices = system_list ? state->system_indices : state->user_indices;
  size_t* cursor = system_list ? &state->icon_system_cursor : &state->icon_user_cursor;
  if (!cursor) {
    return false;
  }

  const size_t row_count = indices.size();
  const int top = std::max(0, ListView_GetTopIndex(list));
  const int per_page = std::max(1, ListView_GetCountPerPage(list));
  const int visible_begin = std::max(0, top - 2);
  const int visible_end = top + per_page + 2;
  size_t inspected = 0;
  while (*cursor < row_count && inspected < 24) {
    inspected++;
    const size_t row = *cursor;
    (*cursor)++;
    if (row >= indices.size()) {
      continue;
    }
    const size_t proc_idx = indices[row];
    if (proc_idx >= state->processes->size()) {
      continue;
    }
    const auto& proc = (*state->processes)[proc_idx];
    if (proc.pid == 0) {
      continue;
    }
    if (static_cast<int>(row) < visible_begin || static_cast<int>(row) > visible_end) {
      continue;
    }
    std::vector<uint8_t> png;
    if (!(LoadProcessIconPngFromNameCache(proc.name, &png) || LoadProcessIconPngFromCache(proc.pid, &png)) ||
        png.empty()) {
      if (!can_fetch_remote) {
        continue;
      }
      std::string error;
      if (!state->service->FetchProcessIcon(proc.pid, 48, &png, &error) || png.empty()) {
        continue;
      }
      SaveProcessIconPngToCache(proc.pid, png);
      SaveProcessIconPngToNameCache(proc.name, png);
    }
    const int icon_idx = AddPngIconToImageList(icons, png);
    if (icon_idx < 0) {
      continue;
    }
    LVITEMW item{};
    item.mask = LVIF_IMAGE;
    item.iItem = static_cast<int>(row);
    item.iSubItem = 0;
    item.iImage = icon_idx;
    ListView_SetItem(list, &item);
    return true;
  }
  return *cursor < row_count;
}

LRESULT CALLBACK ProcessPickerDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  ProcessPickerDialogState* state =
      reinterpret_cast<ProcessPickerDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    state = reinterpret_cast<ProcessPickerDialogState*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
  }
  if (!state) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  switch (msg) {
    case WM_SIZE: {
      LayoutProcessPickerDialog(state, LOWORD(lparam), HIWORD(lparam));
      return 0;
    }
    case WM_TIMER:
      if (wparam == kTimerProcPickerIcons) {
        const bool u = ApplyNextRealProcessIcon(state, false);
        const bool s = ApplyNextRealProcessIcon(state, true);
        if (!u && !s) {
          KillTimer(hwnd, kTimerProcPickerIcons);
        }
        return 0;
      }
      if (wparam == kTimerProcPickerFilter) {
        KillTimer(hwnd, kTimerProcPickerFilter);
        wchar_t buf[256] = {0};
        if (state->filter_edit) {
          GetWindowTextW(state->filter_edit, buf, static_cast<int>(std::size(buf)));
        }
        state->filter_text = TrimWide(buf);
        ApplyProcessPickerFilter(state);
        UpdateProcessPickerInfo(state);
        KillTimer(hwnd, kTimerProcPickerIcons);
        SetTimer(hwnd, kTimerProcPickerIcons, 40, nullptr);
        return 0;
      }
      break;
    case WM_NOTIFY: {
      const NMHDR* hdr = reinterpret_cast<const NMHDR*>(lparam);
      if (!hdr) {
        return 0;
      }
      if (hdr->idFrom == kCtrlProcTab && hdr->code == TCN_SELCHANGE) {
        const int sel = state->tab ? TabCtrl_GetCurSel(state->tab) : 0;
        state->active_tab = sel == 1 ? 1 : 0;
        RECT rc{};
        if (GetClientRect(hwnd, &rc)) {
          LayoutProcessPickerDialog(state, rc.right - rc.left, rc.bottom - rc.top);
        }
        UpdateProcessPickerInfo(state);
        HWND active = ActiveProcessPickerList(state);
        if (active && ListView_GetItemCount(active) > 0) {
          SetFocus(active);
        }
        return 0;
      }
      const bool from_user = hdr->idFrom == kCtrlProcListUser;
      const bool from_system = hdr->idFrom == kCtrlProcListSystem;
      if (!from_user && !from_system) {
        return 0;
      }
      state->active_tab = from_system ? 1 : 0;
      HWND active = from_user ? state->list_user : state->list_system;
      HWND other = from_user ? state->list_system : state->list_user;
      if (hdr->code == LVN_ITEMCHANGED) {
        const auto* lv = reinterpret_cast<const NMLISTVIEW*>(lparam);
        if (lv && (lv->uChanged & LVIF_STATE) != 0) {
          const bool selected_now = (lv->uNewState & LVIS_SELECTED) != 0;
          if (selected_now) {
            ClearProcessPickerSelection(other);
            UpdateProcessPickerInfo(state);
          }
        }
      } else if (hdr->code == NM_CLICK) {
        size_t selected = GetSelectedProcessIndex(active);
        if (selected != std::numeric_limits<size_t>::max()) {
          ClearProcessPickerSelection(other);
        }
        UpdateProcessPickerInfo(state);
      } else if (hdr->code == NM_DBLCLK) {
        SendMessageW(hwnd, WM_COMMAND, IDOK, 0);
      }
      return 0;
    }
    case WM_KEYDOWN:
      if ((GetKeyState(VK_CONTROL) & 0x8000) != 0 && (wparam == 'F' || wparam == 'f')) {
        if (state->filter_edit) {
          SetFocus(state->filter_edit);
          SendMessageW(state->filter_edit, EM_SETSEL, 0, -1);
        }
        return 0;
      }
      if (wparam == VK_RETURN) {
        SendMessageW(hwnd, WM_COMMAND, IDOK, 0);
        return 0;
      }
      break;
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      const UINT notify = HIWORD(wparam);
      if (cmd == kCtrlProcFilter && notify == EN_CHANGE) {
        KillTimer(hwnd, kTimerProcPickerFilter);
        SetTimer(hwnd, kTimerProcPickerFilter, 90, nullptr);
        return 0;
      }
      if (cmd == IDCANCEL) {
        state->ok = false;
        state->done = true;
        DestroyWindow(hwnd);
        return 0;
      }
      if (cmd == IDOK) {
        size_t selected = GetSelectedProcessIndex(ActiveProcessPickerList(state));
        if (selected == std::numeric_limits<size_t>::max()) {
          selected = GetSelectedProcessIndex(state->list_user);
        }
        if (selected == std::numeric_limits<size_t>::max()) {
          selected = GetSelectedProcessIndex(state->list_system);
        }
        if (!state->processes || selected == std::numeric_limits<size_t>::max() || selected >= state->processes->size()) {
          MessageBoxW(hwnd, L"请先选择一个进程", L"提示", MB_OK | MB_ICONINFORMATION);
          return 0;
        }
        state->selected_process_index = selected;
        state->ok = true;
        state->done = true;
        DestroyWindow(hwnd);
        return 0;
      }
      break;
    }
    case WM_DESTROY:
      KillTimer(hwnd, kTimerProcPickerIcons);
      KillTimer(hwnd, kTimerProcPickerFilter);
      if (state->icons_user) {
        ImageList_Destroy(state->icons_user);
        state->icons_user = nullptr;
      }
      if (state->icons_system) {
        ImageList_Destroy(state->icons_system);
        state->icons_system = nullptr;
      }
      return 0;
    case WM_CTLCOLORDLG:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      SetTextColor(hdc, RGB(230, 230, 230));
      SetBkColor(hdc, RGB(43, 43, 43));
      return reinterpret_cast<LRESULT>(GetDialogDarkBrush());
    }
    case WM_CLOSE:
      state->ok = false;
      state->done = true;
      DestroyWindow(hwnd);
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

bool PromptProcessPickerDialog(HWND owner,
                               const std::vector<app::ProcessItem>& processes,
                               services::ClientService* service,
                               size_t* out_selected_index) {
  EnsureListViewControls();
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ProcessPickerDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = GetDialogDarkBrush();
    wc.lpszClassName = L"R3NgProcessPickerDialog";
    RegisterClassExW(&wc);
    registered = true;
  }

  ProcessPickerDialogState state{};
  state.service = service;
  state.processes = &processes;
  for (size_t i = 0; i < processes.size(); ++i) {
    if (IsSystemProcessName(processes[i].name)) {
      state.all_system_indices.push_back(i);
    } else {
      state.all_user_indices.push_back(i);
    }
  }
  const auto by_pid = [&](size_t lhs, size_t rhs) {
    return processes[lhs].pid < processes[rhs].pid;
  };
  std::sort(state.all_user_indices.begin(), state.all_user_indices.end(), by_pid);
  std::sort(state.all_system_indices.begin(), state.all_system_indices.end(), by_pid);

  const int width = 900;
  const int height = 620;
  RECT owner_rc{};
  int x = CW_USEDEFAULT;
  int y = CW_USEDEFAULT;
  if (owner && GetWindowRect(owner, &owner_rc)) {
    x = owner_rc.left + (owner_rc.right - owner_rc.left - width) / 2;
    y = owner_rc.top + (owner_rc.bottom - owner_rc.top - height) / 2;
  }
  state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                               L"R3NgProcessPickerDialog",
                               L"进程列表",
                               WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX,
                               x,
                               y,
                               width,
                               height,
                               owner,
                               nullptr,
                               GetModuleHandleW(nullptr),
                               &state);
  if (!state.hwnd) {
    return false;
  }
  const BOOL use_dark = TRUE;
  DwmSetWindowAttribute(state.hwnd, 20, &use_dark, sizeof(use_dark));
  DwmSetWindowAttribute(state.hwnd, 19, &use_dark, sizeof(use_dark));

  HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  state.tab = CreateWindowExW(0,
                              WC_TABCONTROLW,
                              nullptr,
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                              0,
                              0,
                              0,
                              0,
                              state.hwnd,
                              reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlProcTab)),
                              GetModuleHandleW(nullptr),
                              nullptr);
  state.filter_label = CreateWindowExW(0,
                                       L"STATIC",
                                       L"过滤:",
                                       WS_CHILD | WS_VISIBLE | SS_LEFT,
                                       0,
                                       0,
                                       0,
                                       0,
                                       state.hwnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlProcFilterLabel)),
                                       GetModuleHandleW(nullptr),
                                       nullptr);
  state.filter_edit = CreateWindowExW(WS_EX_CLIENTEDGE,
                                      L"EDIT",
                                      L"",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                      0,
                                      0,
                                      0,
                                      0,
                                      state.hwnd,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlProcFilter)),
                                      GetModuleHandleW(nullptr),
                                      nullptr);
  state.list_user = CreateWindowExW(WS_EX_CLIENTEDGE,
                                    WC_LISTVIEWW,
                                    nullptr,
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                    0,
                                    0,
                                    0,
                                    0,
                                    state.hwnd,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlProcListUser)),
                                    GetModuleHandleW(nullptr),
                                    nullptr);
  state.list_system = CreateWindowExW(WS_EX_CLIENTEDGE,
                                      WC_LISTVIEWW,
                                      nullptr,
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                      0,
                                      0,
                                      0,
                                      0,
                                      state.hwnd,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlProcListSystem)),
                                      GetModuleHandleW(nullptr),
                                      nullptr);
  SetupProcessListView(state.list_user);
  SetupProcessListView(state.list_system);
  state.info = CreateWindowExW(WS_EX_CLIENTEDGE,
                               L"STATIC",
                               L"",
                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                               0,
                               0,
                               0,
                               0,
                               state.hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlProcInfo)),
                               GetModuleHandleW(nullptr),
                               nullptr);
  state.ok_btn = CreateWindowExW(0,
                                 L"BUTTON",
                                 L"打开",
                                 WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                 0,
                                 0,
                                 0,
                                 0,
                                 state.hwnd,
                                 reinterpret_cast<HMENU>(IDOK),
                                 GetModuleHandleW(nullptr),
                                 nullptr);
  state.cancel_btn = CreateWindowExW(0,
                                     L"BUTTON",
                                     L"取消",
                                     WS_CHILD | WS_VISIBLE,
                                     0,
                                     0,
                                     0,
                                     0,
                                     state.hwnd,
                                    reinterpret_cast<HMENU>(IDCANCEL),
                                    GetModuleHandleW(nullptr),
                                    nullptr);

  if (state.tab) {
    TCITEMW item{};
    item.mask = TCIF_TEXT;
    item.pszText = const_cast<LPWSTR>(L"应用程序");
    TabCtrl_InsertItem(state.tab, 0, &item);
    item.pszText = const_cast<LPWSTR>(L"系统进程");
    TabCtrl_InsertItem(state.tab, 1, &item);
    TabCtrl_SetCurSel(state.tab, 0);
  }

  auto set_font = [&](HWND h) {
    if (h) {
      SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
  };
  set_font(state.tab);
  set_font(state.filter_label);
  set_font(state.filter_edit);
  set_font(state.list_user);
  set_font(state.list_system);
  set_font(state.info);
  set_font(state.ok_btn);
  set_font(state.cancel_btn);
  ApplyExplorerTheme(state.tab, true);
  ApplyExplorerTheme(state.filter_edit, true);
  ApplyExplorerTheme(state.list_user, true);
  ApplyExplorerTheme(state.list_system, true);
  ApplyExplorerTheme(state.ok_btn, true);
  ApplyExplorerTheme(state.cancel_btn, true);

  ApplyProcessPickerFilter(&state);
  LayoutProcessPickerDialog(&state, width, height);

  if (!state.user_indices.empty()) {
    ListView_SetItemState(state.list_user, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(state.list_user, 0, FALSE);
  } else if (!state.system_indices.empty()) {
    ListView_SetItemState(state.list_system, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(state.list_system, 0, FALSE);
  }
  UpdateProcessPickerInfo(&state);

  if (owner) {
    EnableWindow(owner, FALSE);
  }
  ShowWindow(state.hwnd, SW_SHOW);
  SetForegroundWindow(state.hwnd);
  if (HWND active = ActiveProcessPickerList(&state)) {
    SetFocus(active);
  }
  SetTimer(state.hwnd, kTimerProcPickerIcons, 60, nullptr);

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

  if (state.ok && out_selected_index) {
    *out_selected_index = state.selected_process_index;
  }
  return state.ok;
}

std::wstring BuildModuleDisplayLabel(const services::ClientService::ModuleInfo& module) {
  std::wstring path = L"(anonymous)";
  if (!module.path.empty()) {
    const int chars = MultiByteToWideChar(CP_UTF8,
                                          0,
                                          module.path.c_str(),
                                          static_cast<int>(module.path.size()),
                                          nullptr,
                                          0);
    if (chars > 0) {
      path.assign(static_cast<size_t>(chars), L'\0');
      MultiByteToWideChar(CP_UTF8,
                          0,
                          module.path.c_str(),
                          static_cast<int>(module.path.size()),
                          path.data(),
                          chars);
    }
  }
  size_t pos = path.find_last_of(L"/\\");
  std::wstring name = pos == std::wstring::npos ? path : path.substr(pos + 1);
  if (name.empty()) {
    name = L"(anonymous)";
  }
  if (name.size() > 42) {
    name = name.substr(0, 39) + L"...";
  }
  wchar_t perms[8] = {0};
  perms[0] = (module.perms & protocol::MODULE_PERM_READ) ? L'r' : L'-';
  perms[1] = (module.perms & protocol::MODULE_PERM_WRITE) ? L'w' : L'-';
  perms[2] = (module.perms & protocol::MODULE_PERM_EXEC) ? L'x' : L'-';
  perms[3] = (module.perms & protocol::MODULE_PERM_PRIVATE) ? L'p'
             : (module.perms & protocol::MODULE_PERM_SHARED) ? L's'
                                                              : L'-';
  perms[4] = 0;
  wchar_t line[960] = {0};
  std::swprintf(line,
                std::size(line),
                L"%-42ls\t[%-4ls]\t0x%llX - 0x%llX",
                name.c_str(),
                perms,
                static_cast<unsigned long long>(module.start),
                static_cast<unsigned long long>(module.end));
  return line;
}

struct ModuleRangeDialogState {
  const std::vector<services::ClientService::ModuleInfo>* modules = nullptr;
  std::vector<size_t> visible_indices;
  size_t selected_module_index = std::numeric_limits<size_t>::max();
  bool done = false;
  bool ok = false;
  HWND hwnd = nullptr;
  HWND filter_edit = nullptr;
  HWND list = nullptr;
  HWND info = nullptr;
  HFONT list_font = nullptr;
};

void RefreshModuleRangeList(ModuleRangeDialogState* state) {
  if (!state || !state->modules || !state->list) {
    return;
  }
  wchar_t filter_buf[256] = {0};
  if (state->filter_edit) {
    GetWindowTextW(state->filter_edit, filter_buf, static_cast<int>(std::size(filter_buf)));
  }
  const std::wstring filter = ToLowerWide(TrimWide(filter_buf));

  state->visible_indices.clear();
  ListView_DeleteAllItems(state->list);
  for (size_t i = 0; i < state->modules->size(); ++i) {
    const auto& m = (*state->modules)[i];
    if (m.end <= m.start) {
      continue;
    }
    std::wstring path;
    if (!m.path.empty()) {
      const int chars = MultiByteToWideChar(CP_UTF8,
                                            0,
                                            m.path.c_str(),
                                            static_cast<int>(m.path.size()),
                                            nullptr,
                                            0);
      if (chars > 0) {
        path.assign(static_cast<size_t>(chars), L'\0');
        MultiByteToWideChar(CP_UTF8,
                            0,
                            m.path.c_str(),
                            static_cast<int>(m.path.size()),
                            path.data(),
                            chars);
      }
    }
    size_t pos = path.find_last_of(L"/\\");
    std::wstring name = pos == std::wstring::npos ? path : path.substr(pos + 1);
    if (name.empty()) {
      name = L"(anonymous)";
    }
    wchar_t perms[8] = {0};
    perms[0] = (m.perms & protocol::MODULE_PERM_READ) ? L'r' : L'-';
    perms[1] = (m.perms & protocol::MODULE_PERM_WRITE) ? L'w' : L'-';
    perms[2] = (m.perms & protocol::MODULE_PERM_EXEC) ? L'x' : L'-';
    perms[3] = (m.perms & protocol::MODULE_PERM_PRIVATE) ? L'p'
               : (m.perms & protocol::MODULE_PERM_SHARED) ? L's'
                                                           : L'-';
    perms[4] = 0;
    wchar_t start_buf[64] = {0};
    wchar_t end_buf[64] = {0};
    std::swprintf(start_buf, std::size(start_buf), L"0x%llX", static_cast<unsigned long long>(m.start));
    std::swprintf(end_buf, std::size(end_buf), L"0x%llX", static_cast<unsigned long long>(m.end));

    std::wstring filter_key = name + L" " + path + L" " + start_buf + L" " + end_buf;
    if (!filter.empty() && ToLowerWide(filter_key).find(filter) == std::wstring::npos) {
      continue;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = static_cast<int>(state->visible_indices.size());
    item.iSubItem = 0;
    item.pszText = const_cast<LPWSTR>(name.c_str());
    item.lParam = static_cast<LPARAM>(i);
    const int row = ListView_InsertItem(state->list, &item);
    if (row < 0) {
      continue;
    }
    ListView_SetItemText(state->list, row, 1, perms);
    ListView_SetItemText(state->list, row, 2, start_buf);
    ListView_SetItemText(state->list, row, 3, end_buf);
    ListView_SetItemText(state->list, row, 4, const_cast<LPWSTR>(path.c_str()));
    state->visible_indices.push_back(i);
  }
  if (!state->visible_indices.empty()) {
    ListView_SetItemState(state->list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(state->list, 0, FALSE);
  }
  if (state->info) {
    wchar_t info_buf[256] = {0};
    std::swprintf(info_buf,
                  std::size(info_buf),
                  L"可选模块: %zu / %zu",
                  state->visible_indices.size(),
                  state->modules->size());
    SetWindowTextW(state->info, info_buf);
  }
}

LRESULT CALLBACK ModuleRangeDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  ModuleRangeDialogState* state =
      reinterpret_cast<ModuleRangeDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    state = reinterpret_cast<ModuleRangeDialogState*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
  }
  if (!state) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }
  switch (msg) {
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      const UINT notify = HIWORD(wparam);
      if (cmd == IDCANCEL) {
        state->ok = false;
        state->done = true;
        DestroyWindow(hwnd);
        return 0;
      }
      if (cmd == IDOK) {
        if (!state->list) {
          return 0;
        }
        const int sel = ListView_GetNextItem(state->list, -1, LVNI_SELECTED);
        if (sel < 0) {
          MessageBoxW(hwnd, L"请先选择一个模块范围", L"提示", MB_OK | MB_ICONINFORMATION);
          return 0;
        }
        LVITEMW item{};
        item.mask = LVIF_PARAM;
        item.iItem = sel;
        if (!ListView_GetItem(state->list, &item)) {
          MessageBoxW(hwnd, L"模块项无效", L"提示", MB_OK | MB_ICONWARNING);
          return 0;
        }
        state->selected_module_index = static_cast<size_t>(item.lParam);
        state->ok = true;
        state->done = true;
        DestroyWindow(hwnd);
        return 0;
      }
      if (cmd == kCtrlModFilter && notify == EN_CHANGE) {
        RefreshModuleRangeList(state);
        return 0;
      }
      break;
    }
    case WM_NOTIFY: {
      const NMHDR* hdr = reinterpret_cast<const NMHDR*>(lparam);
      if (hdr && hdr->idFrom == kCtrlModList && hdr->code == NM_DBLCLK) {
        SendMessageW(hwnd, WM_COMMAND, IDOK, 0);
        return 0;
      }
      break;
    }
    case WM_DESTROY:
      if (state->list_font) {
        DeleteObject(state->list_font);
        state->list_font = nullptr;
      }
      return 0;
    case WM_CTLCOLORDLG:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      SetTextColor(hdc, RGB(230, 230, 230));
      SetBkColor(hdc, RGB(43, 43, 43));
      return reinterpret_cast<LRESULT>(GetDialogDarkBrush());
    }
    case WM_CLOSE:
      state->ok = false;
      state->done = true;
      DestroyWindow(hwnd);
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

bool PromptModuleRangeDialog(HWND owner,
                             const std::vector<services::ClientService::ModuleInfo>& modules,
                             size_t* out_selected_index) {
  EnsureListViewControls();
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ModuleRangeDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = GetDialogDarkBrush();
    wc.lpszClassName = L"R3NgModuleRangeDialog";
    RegisterClassExW(&wc);
    registered = true;
  }

  ModuleRangeDialogState state{};
  state.modules = &modules;

  const int width = 760;
  const int height = 560;
  RECT owner_rc{};
  int x = CW_USEDEFAULT;
  int y = CW_USEDEFAULT;
  if (owner && GetWindowRect(owner, &owner_rc)) {
    x = owner_rc.left + (owner_rc.right - owner_rc.left - width) / 2;
    y = owner_rc.top + (owner_rc.bottom - owner_rc.top - height) / 2;
  }
  state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                               L"R3NgModuleRangeDialog",
                               L"选择模块范围",
                               WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX,
                               x,
                               y,
                               width,
                               height,
                               owner,
                               nullptr,
                               GetModuleHandleW(nullptr),
                               &state);
  if (!state.hwnd) {
    return false;
  }
  const BOOL use_dark = TRUE;
  DwmSetWindowAttribute(state.hwnd, 20, &use_dark, sizeof(use_dark));
  DwmSetWindowAttribute(state.hwnd, 19, &use_dark, sizeof(use_dark));

  HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  const int margin = 12;
  const int list_top = 58;
  const int list_h = height - 160;

  CreateWindowExW(0,
                  L"STATIC",
                  L"筛选(模块名或地址):",
                  WS_CHILD | WS_VISIBLE,
                  margin,
                  14,
                  150,
                  20,
                  state.hwnd,
                  nullptr,
                  GetModuleHandleW(nullptr),
                  nullptr);
  state.filter_edit = CreateWindowExW(WS_EX_CLIENTEDGE,
                                      L"EDIT",
                                      L"",
                                      WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                      margin + 150,
                                      10,
                                      width - margin * 2 - 160,
                                      24,
                                      state.hwnd,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlModFilter)),
                                      GetModuleHandleW(nullptr),
                                      nullptr);
  state.list = CreateWindowExW(WS_EX_CLIENTEDGE,
                               WC_LISTVIEWW,
                               nullptr,
                               WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                                   WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                               margin,
                               list_top,
                               width - margin * 2 - 4,
                               list_h,
                               state.hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlModList)),
                               GetModuleHandleW(nullptr),
                               nullptr);
  state.info = CreateWindowExW(WS_EX_CLIENTEDGE,
                               L"STATIC",
                               L"",
                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                               margin,
                               list_top + list_h + 8,
                               width - margin * 2 - 4,
                               28,
                               state.hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlModInfo)),
                               GetModuleHandleW(nullptr),
                               nullptr);
  HWND ok_btn = CreateWindowExW(0,
                                L"BUTTON",
                                L"应用范围",
                                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                width - 220,
                                list_top + list_h + 44,
                                90,
                                28,
                                state.hwnd,
                                reinterpret_cast<HMENU>(IDOK),
                                GetModuleHandleW(nullptr),
                                nullptr);
  HWND cancel_btn = CreateWindowExW(0,
                                    L"BUTTON",
                                    L"取消",
                                    WS_CHILD | WS_VISIBLE,
                                    width - 120,
                                    list_top + list_h + 44,
                                    80,
                                    28,
                                    state.hwnd,
                                    reinterpret_cast<HMENU>(IDCANCEL),
                                    GetModuleHandleW(nullptr),
                                    nullptr);

  auto set_font = [&](HWND h) {
    if (h) {
      SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
  };
  set_font(state.filter_edit);
  if (state.list) {
    LOGFONTW lf{};
    lf.lfHeight = -13;
    lf.lfWeight = FW_NORMAL;
    wcscpy_s(lf.lfFaceName, L"Consolas");
    state.list_font = CreateFontIndirectW(&lf);
    if (state.list_font) {
      SendMessageW(state.list, WM_SETFONT, reinterpret_cast<WPARAM>(state.list_font), TRUE);
    } else {
      set_font(state.list);
    }
    ListView_SetExtendedListViewStyle(
        state.list,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    ListView_SetBkColor(state.list, RGB(43, 43, 43));
    ListView_SetTextBkColor(state.list, RGB(43, 43, 43));
    ListView_SetTextColor(state.list, RGB(230, 230, 230));
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.iSubItem = 0;
    col.cx = 220;
    col.pszText = const_cast<LPWSTR>(L"模块名");
    ListView_InsertColumn(state.list, 0, &col);
    col.iSubItem = 1;
    col.cx = 74;
    col.pszText = const_cast<LPWSTR>(L"权限");
    ListView_InsertColumn(state.list, 1, &col);
    col.iSubItem = 2;
    col.cx = 156;
    col.pszText = const_cast<LPWSTR>(L"起始");
    ListView_InsertColumn(state.list, 2, &col);
    col.iSubItem = 3;
    col.cx = 156;
    col.pszText = const_cast<LPWSTR>(L"结束");
    ListView_InsertColumn(state.list, 3, &col);
    col.iSubItem = 4;
    col.cx = 420;
    col.pszText = const_cast<LPWSTR>(L"路径");
    ListView_InsertColumn(state.list, 4, &col);
    ApplyExplorerTheme(state.list, true);
    if (HWND header = ListView_GetHeader(state.list)) {
      ApplyExplorerTheme(header, true);
    }
  }
  set_font(state.info);
  set_font(ok_btn);
  set_font(cancel_btn);
  ApplyExplorerTheme(ok_btn, true);
  ApplyExplorerTheme(cancel_btn, true);

  RefreshModuleRangeList(&state);

  if (owner) {
    EnableWindow(owner, FALSE);
  }
  ShowWindow(state.hwnd, SW_SHOW);
  SetForegroundWindow(state.hwnd);
  SetFocus(state.filter_edit ? state.filter_edit : state.list);

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

  if (state.ok && out_selected_index) {
    *out_selected_index = state.selected_module_index;
  }
  return state.ok;
}

std::wstring FormatOffsetList(const std::vector<int64_t>& offsets) {
  if (offsets.empty()) {
    return L"";
  }
  std::wstring out;
  for (size_t i = 0; i < offsets.size(); ++i) {
    wchar_t buf[64] = {0};
    const int64_t offset = offsets[i];
    if (offset >= 0) {
      std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"+0x%llX", static_cast<long long>(offset));
    } else {
      std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"-0x%llX", static_cast<long long>(-offset));
    }
    if (!out.empty()) {
      out.append(L" ");
    }
    out.append(buf);
  }
  return out;
}

std::wstring BuildEntryText(const app::AddressEntry& entry) {
  wchar_t base[64] = {0};
  std::swprintf(base,
                sizeof(base) / sizeof(wchar_t),
                L"0x%llX",
                static_cast<unsigned long long>(entry.addr));
  std::wstring text = base;
  if (entry.is_pointer) {
    std::wstring offsets = FormatOffsetList(entry.offsets);
    text.append(L" -> ");
    text.append(offsets.empty() ? L"(无偏移)" : offsets);
  }
  text.append(L" / ");
  text.append(ValueTypeName(entry.type));
  text.append(L" / ");
  if (!entry.value.empty()) {
    text.append(entry.value);
  } else {
    text.append(L"-");
  }
  return text;
}

bool SameEntry(const app::AddressEntry& a, const app::AddressEntry& b) {
  if (a.addr != b.addr) {
    return false;
  }
  if (a.type != b.type) {
    return false;
  }
  if (a.is_pointer != b.is_pointer) {
    return false;
  }
  if (a.is_pointer && a.offsets != b.offsets) {
    return false;
  }
  return true;
}

}  // namespace

CeLayoutWindow::CeLayoutWindow() = default;

CeLayoutWindow::~CeLayoutWindow() {
  DiscardDeviceResources();
  for (HBITMAP bmp : menu_bitmaps_) {
    if (bmp) {
      DeleteObject(bmp);
    }
  }
  menu_bitmaps_.clear();
  SafeRelease(&font_mono_);
  SafeRelease(&font_ui_center_);
  SafeRelease(&font_ui_);
  SafeRelease(&dwrite_factory_);
  SafeRelease(&d2d_factory_);
  if (ctrl_font_) {
    DeleteObject(ctrl_font_);
    ctrl_font_ = nullptr;
  }
  if (ctrl_bg_brush_) {
    DeleteObject(ctrl_bg_brush_);
    ctrl_bg_brush_ = nullptr;
  }
}

bool CeLayoutWindow::CreateDeviceIndependentResources() {
  HRESULT hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &d2d_factory_);
  if (FAILED(hr)) {
    return false;
  }

  hr = DWriteCreateFactory(
      DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown**>(&dwrite_factory_));
  if (FAILED(hr)) {
    return false;
  }

  auto create_font = [&](const wchar_t* primary,
                         const wchar_t* fallback,
                         float size,
                         const wchar_t* locale,
                         IDWriteTextFormat** out) -> HRESULT {
    HRESULT font_hr = dwrite_factory_->CreateTextFormat(primary,
                                                        nullptr,
                                                        DWRITE_FONT_WEIGHT_NORMAL,
                                                        DWRITE_FONT_STYLE_NORMAL,
                                                        DWRITE_FONT_STRETCH_NORMAL,
                                                        size,
                                                        locale,
                                                        out);
    if (FAILED(font_hr) && fallback) {
      font_hr = dwrite_factory_->CreateTextFormat(fallback,
                                                  nullptr,
                                                  DWRITE_FONT_WEIGHT_NORMAL,
                                                  DWRITE_FONT_STYLE_NORMAL,
                                                  DWRITE_FONT_STRETCH_NORMAL,
                                                  size,
                                                  locale,
                                                  out);
    }
    if (FAILED(font_hr)) {
      font_hr = dwrite_factory_->CreateTextFormat(L"Segoe UI",
                                                  nullptr,
                                                  DWRITE_FONT_WEIGHT_NORMAL,
                                                  DWRITE_FONT_STYLE_NORMAL,
                                                  DWRITE_FONT_STRETCH_NORMAL,
                                                  size,
                                                  L"en-US",
                                                  out);
    }
    return font_hr;
  };

  hr = create_font(L"Noto Sans CJK SC", L"Microsoft YaHei UI", 12.0f, L"zh-CN", &font_ui_);
  if (FAILED(hr)) {
    return false;
  }
  font_ui_->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);

  hr = create_font(L"Noto Sans CJK SC", L"Microsoft YaHei UI", 12.0f, L"zh-CN", &font_ui_center_);
  if (FAILED(hr)) {
    return false;
  }
  font_ui_center_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
  font_ui_center_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
  font_ui_center_->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);

  hr = create_font(L"JetBrains Mono", L"Consolas", 12.0f, L"en-US", &font_mono_);
  if (FAILED(hr)) {
    return false;
  }
  font_mono_->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
  return true;
}

bool CeLayoutWindow::CreateDeviceResources() {
  if (render_target_ != nullptr) {
    return true;
  }
  RECT rc{};
  GetClientRect(hwnd_, &rc);
  const D2D1_SIZE_U size = D2D1::SizeU(
      static_cast<UINT32>(std::max<LONG>(1, rc.right - rc.left)),
      static_cast<UINT32>(std::max<LONG>(1, rc.bottom - rc.top)));

  HRESULT hr = d2d_factory_->CreateHwndRenderTarget(
      D2D1::RenderTargetProperties(),
      D2D1::HwndRenderTargetProperties(hwnd_, size),
      &render_target_);
  if (FAILED(hr)) {
    return false;
  }
  render_target_->SetDpi(static_cast<float>(dpi_), static_cast<float>(dpi_));

  hr = render_target_->CreateSolidColorBrush(Rgba(43, 43, 43), &brush_bg_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(48, 48, 48), &brush_panel_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(47, 47, 47), &brush_row_alt_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(62, 90, 128), &brush_row_select_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(74, 74, 74), &brush_border_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(230, 230, 230), &brush_text_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(190, 190, 190), &brush_muted_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(64, 64, 64), &brush_accent_);
  if (FAILED(hr)) return false;
  hr = render_target_->CreateSolidColorBrush(Rgba(235, 235, 235), &brush_accent_text_);
  if (FAILED(hr)) return false;

  LoadSvgAtlas();
  return true;
}

void CeLayoutWindow::DiscardDeviceResources() {
  SafeRelease(&brush_accent_text_);
  SafeRelease(&brush_accent_);
  SafeRelease(&brush_muted_);
  SafeRelease(&brush_text_);
  SafeRelease(&brush_border_);
  SafeRelease(&brush_row_select_);
  SafeRelease(&brush_row_alt_);
  SafeRelease(&brush_panel_);
  SafeRelease(&brush_bg_);
  SafeRelease(&svg_atlas_.bitmap);
  svg_atlas_.icon_uv.clear();
  svg_atlas_.width = 0;
  svg_atlas_.height = 0;
  SafeRelease(&render_target_);
}

void CeLayoutWindow::BuildMenuBar() {
  HMENU bar = CreateMenu();
  HMENU file = CreatePopupMenu();
  HMENU view = CreatePopupMenu();
  HMENU debug = CreatePopupMenu();

  AppendMenuW(file, MF_STRING, kMenuFileOpen, L"选择进程...\tCtrl+P");
  AppendMenuW(file, MF_STRING, kMenuFileSave, L"连接/断开");
  AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(file, MF_STRING, kMenuFileExit, L"退出");

  AppendMenuW(view, MF_STRING, kMenuViewMemory, L"查看内存");
  AppendMenuW(view, MF_STRING, kMenuViewSettings, L"设置");

  AppendMenuW(debug, MF_STRING, kMenuViewMemory, L"调试窗口(内存/反汇编)");
  AppendMenuW(debug, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(debug, MF_STRING, kMenuDebugPointerScan, L"指针搜索");
  AppendMenuW(debug, MF_STRING, kMenuDebugPointerCompare, L"指针对比");
  AppendMenuW(debug, MF_STRING, kMenuDebugDataTraverse, L"结构分析(智能识别指针)");

  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"文件(F)");
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(view), L"视图(V)");
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(debug), L"调试");
  SetMenu(hwnd_, bar);
  ApplyMenuIcons(bar);
}

bool CeLayoutWindow::ReloadModulesCache(bool force, std::string* out_error) {
  if (!service_.IsConnected() || state_.pid == 0) {
    modules_cache_.clear();
    modules_pid_ = 0;
    return false;
  }
  if (!force && modules_pid_ == state_.pid && !modules_cache_.empty()) {
    return true;
  }
  std::vector<services::ClientService::ModuleInfo> modules;
  std::string error;
  if (!service_.FetchModules(state_.pid, &modules, &error)) {
    if (out_error) {
      *out_error = error;
    }
    return false;
  }
  std::sort(modules.begin(), modules.end(), [](const auto& a, const auto& b) {
    return a.start < b.start;
  });
  modules_cache_ = std::move(modules);
  modules_pid_ = state_.pid;
  return true;
}

void CeLayoutWindow::ReloadScanRegionOptions(bool force_modules) {
  if (!combo_scan_region_) {
    return;
  }
  const LONG_PTR combo_style = GetWindowLongPtrW(combo_scan_region_, GWL_STYLE);
  const bool combo_has_edit = (combo_style & CBS_DROPDOWN) == CBS_DROPDOWN;
  wchar_t edit_buf[512] = {0};
  if (combo_has_edit) {
    GetWindowTextW(combo_scan_region_, edit_buf, static_cast<int>(std::size(edit_buf)));
  }
  const std::wstring combo_text = edit_buf;
  std::wstring selected_label;
  const int prev_sel = static_cast<int>(SendMessageW(combo_scan_region_, CB_GETCURSEL, 0, 0));
  if (prev_sel >= 0) {
    wchar_t sel_buf[512] = {0};
    SendMessageW(combo_scan_region_, CB_GETLBTEXT, static_cast<WPARAM>(prev_sel), reinterpret_cast<LPARAM>(sel_buf));
    selected_label = sel_buf;
  }

  std::wstring filter_text;
  if (combo_has_edit && !(prev_sel >= 0 && !selected_label.empty() && combo_text == selected_label)) {
    filter_text = combo_text;
  }

  scan_region_all_options_.clear();
  scan_region_all_options_.push_back({L"All", 0, 0, false, false, protocol::GG_REGION_NONE});
  for (const auto& gg : kGGRegionOptionDefs) {
    scan_region_all_options_.push_back({BuildGGRegionOptionText(gg), 0, 0, false, true, gg.code});
  }

  std::string err;
  if (ReloadModulesCache(force_modules, &err)) {
    for (const auto& module : modules_cache_) {
      if (module.end <= module.start) {
        continue;
      }
      std::wstring path = Utf8ToWide(module.path);
      size_t pos = path.find_last_of(L"/\\");
      std::wstring name = pos == std::wstring::npos ? path : path.substr(pos + 1);
      if (name.empty()) {
        name = L"(anonymous)";
      }
      wchar_t range[96] = {0};
      std::swprintf(range,
                    sizeof(range) / sizeof(wchar_t),
                    L" [0x%llX-0x%llX]",
                    static_cast<unsigned long long>(module.start),
                    static_cast<unsigned long long>(module.end));
      scan_region_all_options_.push_back(
          {name + range, module.start, module.end, true, false, protocol::GG_REGION_NONE});
    }
  } else if (force_modules && !err.empty()) {
    UpdateStatus(Utf8ToWide(err));
  }

  scan_region_options_.clear();
  if (filter_text.empty()) {
    scan_region_options_ = scan_region_all_options_;
  } else {
    scan_region_options_.push_back(scan_region_all_options_.front());
    for (size_t i = 1; i < scan_region_all_options_.size(); ++i) {
      if (ContainsWideInsensitive(scan_region_all_options_[i].label, filter_text)) {
        scan_region_options_.push_back(scan_region_all_options_[i]);
      }
    }
  }
  if (scan_region_options_.empty()) {
    scan_region_options_.push_back({L"All", 0, 0, false, false, protocol::GG_REGION_NONE});
  }

  scan_region_reloading_ = true;
  SendMessageW(combo_scan_region_, CB_RESETCONTENT, 0, 0);
  int select_idx = -1;
  for (size_t i = 0; i < scan_region_options_.size(); ++i) {
    SendMessageW(combo_scan_region_,
                 CB_ADDSTRING,
                 0,
                 reinterpret_cast<LPARAM>(scan_region_options_[i].label.c_str()));
    if (!selected_label.empty() && scan_region_options_[i].label == selected_label) {
      select_idx = static_cast<int>(i);
    }
    if (select_idx < 0 &&
        scan_region_gg_code_ != protocol::GG_REGION_NONE &&
        scan_region_options_[i].from_gg &&
        scan_region_options_[i].gg_code == scan_region_gg_code_) {
      select_idx = static_cast<int>(i);
    }
  }
  if (select_idx < 0) {
    select_idx = 0;
  }
  SendMessageW(combo_scan_region_, CB_SETCURSEL, static_cast<WPARAM>(select_idx), 0);
  if (combo_has_edit && !filter_text.empty()) {
    SetWindowTextW(combo_scan_region_, filter_text.c_str());
    SendMessageW(combo_scan_region_, CB_SETEDITSEL, 0, MAKELPARAM(static_cast<INT>(filter_text.size()), -1));
  }
  scan_region_reloading_ = false;
}

void CeLayoutWindow::ApplySelectedScanRegion(bool update_status) {
  if (!combo_scan_region_) {
    return;
  }
  const int idx = static_cast<int>(SendMessageW(combo_scan_region_, CB_GETCURSEL, 0, 0));
  if (idx < 0 || idx >= static_cast<int>(scan_region_options_.size())) {
    return;
  }
  const ScanRegionOption& opt = scan_region_options_[static_cast<size_t>(idx)];
  if (opt.from_module) {
    scan_region_gg_code_ = protocol::GG_REGION_NONE;
    wchar_t start_buf[64] = {0};
    wchar_t end_buf[64] = {0};
    std::swprintf(start_buf, sizeof(start_buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(opt.start));
    std::swprintf(end_buf, sizeof(end_buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(opt.end));
    if (edit_scan_start_) {
      SetWindowTextW(edit_scan_start_, start_buf);
    }
    if (edit_scan_end_) {
      SetWindowTextW(edit_scan_end_, end_buf);
    }
    if (update_status) {
      std::wstring status = L"已选择模块范围: ";
      status += opt.label;
      UpdateStatus(status);
    }
  } else if (opt.from_gg) {
    scan_region_gg_code_ = opt.gg_code;
    if (edit_scan_start_) {
      SetWindowTextW(edit_scan_start_, L"");
    }
    if (edit_scan_end_) {
      SetWindowTextW(edit_scan_end_, L"");
    }
    if (update_status) {
      std::wstring status = L"已切换为GG段: ";
      if (const GGRegionOptionDef* def = FindGGOptionByCode(opt.gg_code)) {
        status += def->code_text;
      } else {
        status += L"未知";
      }
      UpdateStatus(status);
    }
  } else {
    scan_region_gg_code_ = protocol::GG_REGION_NONE;
    if (edit_scan_start_) {
      SetWindowTextW(edit_scan_start_, L"");
    }
    if (edit_scan_end_) {
      SetWindowTextW(edit_scan_end_, L"");
    }
    if (update_status) {
      UpdateStatus(L"已切换为全内存范围");
    }
  }
  SyncStateFromControls();
}

void CeLayoutWindow::OpenModuleRangePopup() {
  if (!EnsureConnected()) {
    return;
  }
  if (state_.pid == 0) {
    UpdateStatus(L"请先附加进程后再选择模块范围");
    return;
  }
  std::string error;
  if (!ReloadModulesCache(true, &error)) {
    if (!error.empty()) {
      UpdateStatus(Utf8ToWide(error));
    } else {
      UpdateStatus(L"模块列表刷新失败");
    }
    return;
  }
  std::vector<services::ClientService::ModuleInfo> modules;
  modules.reserve(modules_cache_.size());
  for (const auto& mod : modules_cache_) {
    if (mod.end > mod.start) {
      modules.push_back(mod);
    }
  }
  if (modules.empty()) {
    UpdateStatus(L"当前进程没有可选模块");
    return;
  }
  size_t selected = std::numeric_limits<size_t>::max();
  if (!PromptModuleRangeDialog(hwnd_, modules, &selected)) {
    UpdateStatus(L"已取消模块范围选择");
    return;
  }
  if (selected >= modules.size()) {
    UpdateStatus(L"模块范围选择无效");
    return;
  }
  const auto& module = modules[selected];
  wchar_t start_buf[64] = {0};
  wchar_t end_buf[64] = {0};
  std::swprintf(start_buf, std::size(start_buf), L"0x%llX", static_cast<unsigned long long>(module.start));
  std::swprintf(end_buf, std::size(end_buf), L"0x%llX", static_cast<unsigned long long>(module.end));
  if (edit_scan_start_) {
    SetWindowTextW(edit_scan_start_, start_buf);
  }
  if (edit_scan_end_) {
    SetWindowTextW(edit_scan_end_, end_buf);
  }
  ReloadScanRegionOptions(false);
  if (combo_scan_region_) {
    int match_idx = -1;
    for (size_t i = 0; i < scan_region_options_.size(); ++i) {
      const auto& opt = scan_region_options_[i];
      if (opt.from_module && opt.start == module.start && opt.end == module.end) {
        match_idx = static_cast<int>(i);
        break;
      }
    }
    if (match_idx >= 0) {
      SendMessageW(combo_scan_region_, CB_SETCURSEL, static_cast<WPARAM>(match_idx), 0);
      ApplySelectedScanRegion(false);
    }
  }
  SyncStateFromControls();
  std::wstring label = BuildModuleDisplayLabel(module);
  UpdateStatus(std::wstring(L"已应用模块范围: ") + label);
}

void CeLayoutWindow::CreateNativeControls() {
  if (!ctrl_font_) {
    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(12, static_cast<int>(dpi_), 96);
    lf.lfWeight = FW_NORMAL;
    wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
    ctrl_font_ = CreateFontIndirectW(&lf);
  }
  edit_scan_value_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"0", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                     0, 0, 100, 24, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditScanValue)), instance_, nullptr);
  edit_scan_start_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                     0, 0, 100, 24, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditScanStart)), instance_, nullptr);
  edit_scan_end_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                   0, 0, 100, 24, hwnd_,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditScanEnd)), instance_, nullptr);
  combo_scan_type_ = CreateWindowExW(0, L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                     0, 0, 100, 300, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlComboType)), instance_, nullptr);
  combo_scan_cond_ = CreateWindowExW(0, L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                     0, 0, 100, 300, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlComboCond)), instance_, nullptr);
  combo_scan_region_ = CreateWindowExW(0, L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                       0, 0, 100, 200, hwnd_,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlComboRegion)), instance_, nullptr);
  check_scan_hex_ = CreateWindowExW(0, L"BUTTON", L"十六进制", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                    0, 0, 100, 24, hwnd_,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckHex)), instance_, nullptr);
  check_scan_fast_ = CreateWindowExW(0, L"BUTTON", L"快速扫描", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                     0, 0, 100, 24, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckFast)), instance_, nullptr);
  edit_scan_fast_value_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"4", WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL,
                                          0, 0, 40, 24, hwnd_,
                                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlEditFastValue)), instance_, nullptr);
  radio_scan_align_ = CreateWindowExW(0, L"BUTTON", L"对齐", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                                      0, 0, 60, 24, hwnd_,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlRadioAlign)), instance_, nullptr);
  radio_scan_last_ = CreateWindowExW(0, L"BUTTON", L"最后位数", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                                     0, 0, 80, 24, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlRadioLast)), instance_, nullptr);
  check_scan_writable_ = CreateWindowExW(0, L"BUTTON", L"只可写", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                         0, 0, 80, 24, hwnd_,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckWritable)), instance_, nullptr);
  check_scan_executable_ = CreateWindowExW(0, L"BUTTON", L"可执行", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                           0, 0, 80, 24, hwnd_,
                                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckExecutable)), instance_, nullptr);
  check_scan_copy_ = CreateWindowExW(0, L"BUTTON", L"写时拷贝", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                     0, 0, 90, 24, hwnd_,
                                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckCopy)), instance_, nullptr);
  check_scan_active_ = CreateWindowExW(0, L"BUTTON", L"私有内存", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                       0, 0, 150, 24, hwnd_,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlCheckActive)), instance_, nullptr);
  scroll_scan_ = CreateWindowExW(0,
                                 L"SCROLLBAR",
                                 nullptr,
                                 WS_CHILD | WS_VISIBLE | SBS_VERT,
                                 0,
                                 0,
                                 12,
                                 100,
                                 hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlScrollScan)),
                                 instance_,
                                 nullptr);
  scroll_addr_ = CreateWindowExW(0,
                                 L"SCROLLBAR",
                                 nullptr,
                                 WS_CHILD | WS_VISIBLE | SBS_VERT,
                                 0,
                                 0,
                                 12,
                                 100,
                                 hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlScrollAddr)),
                                 instance_,
                                 nullptr);
  ApplyExplorerTheme(combo_scan_type_, true);
  ApplyExplorerTheme(combo_scan_cond_, true);
  ApplyExplorerTheme(combo_scan_region_, true);
  ApplyExplorerTheme(scroll_scan_, true);
  ApplyExplorerTheme(scroll_addr_, true);

  for (const wchar_t* name : kScanValueTypeNames) {
    SendMessageW(combo_scan_type_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
  }
  SendMessageW(combo_scan_type_, CB_SETCURSEL, static_cast<WPARAM>(TypeToIndex(state_.scan_value_type)), 0);

  for (const wchar_t* name : kScanConditionNames) {
    SendMessageW(combo_scan_cond_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
  }
  SendMessageW(combo_scan_cond_, CB_SETCURSEL, static_cast<WPARAM>(CondToIndex(state_.scan_condition)), 0);

  ReloadScanRegionOptions(false);

  SendMessageW(check_scan_hex_, BM_SETCHECK, state_.scan_value_hex ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(check_scan_fast_, BM_SETCHECK, state_.scan_fast ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(check_scan_writable_, BM_SETCHECK, state_.scan_writable ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(check_scan_executable_, BM_SETCHECK, state_.scan_executable ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(check_scan_copy_, BM_SETCHECK, state_.scan_copy_on_write ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(check_scan_active_, BM_SETCHECK, state_.scan_private ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(radio_scan_align_, BM_SETCHECK, ui_scan_fast_mode_ == 0 ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(radio_scan_last_, BM_SETCHECK, ui_scan_fast_mode_ == 1 ? BST_CHECKED : BST_UNCHECKED, 0);

  ApplyControlFont();
  UpdateScrollBars();
}

void CeLayoutWindow::ApplyControlFont() {
  HFONT font = ctrl_font_ ? ctrl_font_ : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  HWND controls[] = {
      edit_scan_value_,
      edit_scan_start_,
      edit_scan_end_,
      combo_scan_type_,
      combo_scan_cond_,
      combo_scan_region_,
      check_scan_hex_,
      check_scan_fast_,
      edit_scan_fast_value_,
      radio_scan_align_,
      radio_scan_last_,
      check_scan_writable_,
      check_scan_executable_,
      check_scan_copy_,
      check_scan_active_,
  };
  for (HWND ctrl : controls) {
    if (ctrl) {
      SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
  }
}

void CeLayoutWindow::LayoutNativeControls() {
  if (!hwnd_ || !edit_scan_value_) return;
  RECT rc{};
  GetClientRect(hwnd_, &rc);
  const float s = dpi_scale_;
  const float width = static_cast<float>(rc.right - rc.left) / s;
  const float height = static_cast<float>(rc.bottom - rc.top) / s;

  const float toolbar_h = 36.0f;
  const float process_h = 22.0f;
  const float status_h = 22.0f;
  const float fixed_h = toolbar_h + process_h + status_h;
  float address_h = std::max(90.0f, height * 0.28f);
  float scan_h = height - fixed_h - address_h;
  if (scan_h < 334.0f) {
    address_h = std::max(72.0f, height - fixed_h - 334.0f);
    scan_h = height - fixed_h - address_h;
  }
  if (scan_h < 304.0f) {
    address_h = std::max(60.0f, height - fixed_h - 304.0f);
    scan_h = height - fixed_h - address_h;
  }
  if (scan_h < 230.0f) {
    scan_h = 230.0f;
    address_h = std::max(60.0f, height - fixed_h - scan_h);
  }

  const float scan_top = toolbar_h + process_h;
  const float right_w = kScanRightPanelWidth;
  const float right_left = std::max(0.0f, width - right_w);
  const bool compact = scan_h < 340.0f;
  const float row_h = compact ? 20.0f : 22.0f;
  const float row_gap = compact ? 4.0f : 6.0f;
  const float row_extra = compact ? 2.0f : 5.0f;
  const float pad = 10.0f;
  const float right_col_w = 112.0f;
  const float label_w = 64.0f;
  const float left_col_w = right_w - pad * 2.0f - right_col_w;
  const float x_label = right_left + pad;
  const float x_ctrl = x_label + label_w;
  const float ctrl_w = left_col_w - label_w;
  const float x_right_col = right_left + right_w - pad - right_col_w;

  auto px = [s](float v) { return static_cast<int>(std::lround(v * s)); };

  const float left_scan_left = 0.0f;
  const float left_scan_right = right_left - 4.0f;
  const float tab_h = 22.0f;
  const float header_top = scan_top + 4.0f + tab_h + 26.0f;
  const float rows_top = header_top + 24.0f + 4.0f;
  const float rows_bottom = scan_top + scan_h - 4.0f;
  const float scroll_w = 12.0f;
  if (scroll_scan_) {
    MoveWindow(scroll_scan_,
               px(left_scan_right - scroll_w - 2.0f),
               px(rows_top),
               px(scroll_w),
               px(std::max(24.0f, rows_bottom - rows_top)),
               TRUE);
  }

  const float addr_top = scan_top + scan_h;
  const float addr_top_h = 28.0f;
  const float addr_header_top = addr_top + addr_top_h + 2.0f;
  const float addr_rows_top = addr_header_top + 24.0f + 4.0f;
  const float addr_rows_bottom = addr_top + address_h - 6.0f;
  if (scroll_addr_) {
    MoveWindow(scroll_addr_,
               px(width - scroll_w - 2.0f),
               px(addr_rows_top),
               px(scroll_w),
               px(std::max(24.0f, addr_rows_bottom - addr_rows_top)),
               TRUE);
  }

  float y = scan_top + 54.0f;
  const float hex_w = 84.0f;
  const float value_w = std::max(80.0f, ctrl_w - hex_w - 6.0f);
  MoveWindow(edit_scan_value_, px(x_ctrl), px(y), px(value_w), px(row_h), TRUE);
  MoveWindow(check_scan_hex_, px(x_ctrl + value_w + 6.0f), px(y), px(hex_w), px(row_h), TRUE);

  y += row_h + row_gap;
  MoveWindow(combo_scan_cond_, px(x_ctrl), px(y), px(ctrl_w), px(row_h + 4.0f), TRUE);
  y += row_h + row_gap;
  MoveWindow(combo_scan_type_, px(x_ctrl), px(y), px(ctrl_w), px(row_h + 4.0f), TRUE);
  y += row_h + row_gap + row_extra;

  const float group_top = y + 8.0f;
  float g_y = group_top + 28.0f;
  MoveWindow(combo_scan_region_, px(x_ctrl), px(g_y), px(ctrl_w), px(row_h + 4.0f), TRUE);
  g_y += row_h + row_gap;
  MoveWindow(edit_scan_start_, px(x_ctrl), px(g_y), px(ctrl_w), px(row_h), TRUE);
  g_y += row_h + row_gap;
  MoveWindow(edit_scan_end_, px(x_ctrl), px(g_y), px(ctrl_w), px(row_h), TRUE);
  g_y += row_h + 4.0f;

  MoveWindow(check_scan_writable_, px(x_label + 6.0f), px(g_y), px(70.0f), px(row_h), TRUE);
  MoveWindow(check_scan_executable_, px(x_label + 84.0f), px(g_y), px(72.0f), px(row_h), TRUE);
  MoveWindow(check_scan_copy_, px(x_label + 162.0f), px(g_y), px(88.0f), px(row_h), TRUE);
  g_y += row_h;
  MoveWindow(check_scan_active_, px(x_label + 6.0f), px(g_y), px(150.0f), px(row_h), TRUE);
  g_y += row_h;

  MoveWindow(check_scan_fast_, px(x_label + 6.0f), px(g_y), px(84.0f), px(row_h), TRUE);
  MoveWindow(edit_scan_fast_value_, px(x_label + 92.0f), px(g_y + 2.0f), px(36.0f), px(row_h - 2.0f), TRUE);
  MoveWindow(radio_scan_align_, px(x_label + 134.0f), px(g_y), px(58.0f), px(row_h), TRUE);
  MoveWindow(radio_scan_last_, px(x_label + 194.0f), px(g_y), px(80.0f), px(row_h), TRUE);
}

bool CeLayoutWindow::Create(HINSTANCE instance, int nCmdShow) {
  instance_ = instance;
  if (!CreateDeviceIndependentResources()) {
    return false;
  }

  LoadSettingsFromFile();

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
  wc.lpfnWndProc = StaticWndProc;
  wc.hInstance = instance_;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = GetDialogDarkBrush();
  wc.lpszClassName = L"R3WindowsClientNgWndClass";
  if (!RegisterClassExW(&wc)) {
    return false;
  }

  hwnd_ = CreateWindowExW(0,
                          wc.lpszClassName,
                          L"R3 Android Debug Client",
                          WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                          CW_USEDEFAULT,
                          CW_USEDEFAULT,
                          1280,
                          820,
                          nullptr,
                          nullptr,
                          instance_,
                          this);
  if (!hwnd_) {
    return false;
  }

  dpi_ = GetDpiForWindowCompat(hwnd_);
  dpi_scale_ = static_cast<float>(dpi_) / 96.0f;
  if (!ctrl_bg_brush_) {
    ctrl_bg_brush_ = CreateSolidBrush(RGB(43, 43, 43));
  }
  const BOOL use_dark = TRUE;
  DwmSetWindowAttribute(hwnd_, 20, &use_dark, sizeof(use_dark));
  DwmSetWindowAttribute(hwnd_, 19, &use_dark, sizeof(use_dark));

  BuildMenuBar();
  CreateNativeControls();
  LayoutNativeControls();
  pointer_tools_window_.Create(instance_, hwnd_, &service_, &state_);
  SyncControlsFromState();
  SaveCurrentTabState();

  SetTimer(hwnd_, kTimerAddressList, 100, nullptr);

  ShowWindow(hwnd_, nCmdShow);
  UpdateWindow(hwnd_);
  TryAutoBootstrapOnStartup();
  return true;
}

int CeLayoutWindow::Run() {
  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return static_cast<int>(msg.wParam);
}

bool CeLayoutWindow::RunProcessForBootstrap(const std::wstring& exe_path,
                                            const std::vector<std::wstring>& args,
                                            DWORD timeout_ms,
                                            DWORD* out_exit_code) const {
  return RunProcessAndWait(exe_path, args, timeout_ms, out_exit_code);
}

std::filesystem::path CeLayoutWindow::FindRuntimeScript(const wchar_t* script_name) const {
  if (!script_name || !*script_name) {
    return {};
  }
  std::vector<std::filesystem::path> roots;
  std::error_code ec;
  const std::filesystem::path cwd = std::filesystem::current_path(ec);
  if (!ec && !cwd.empty()) {
    roots.push_back(cwd);
  }
  const std::filesystem::path exe_dir = GetExeDir();
  if (!exe_dir.empty()) {
    roots.push_back(exe_dir);
    std::filesystem::path parent = exe_dir;
    for (int i = 0; i < 4; ++i) {
      parent = parent.parent_path();
      if (parent.empty()) {
        break;
      }
      roots.push_back(parent);
    }
  }
  for (const auto& root : roots) {
    const std::filesystem::path p1 = root / "tools" / script_name;
    if (std::filesystem::exists(p1)) {
      return p1;
    }
    const std::filesystem::path p2 = root / script_name;
    if (std::filesystem::exists(p2)) {
      return p2;
    }
  }
  return {};
}

std::filesystem::path CeLayoutWindow::ResolveAndroidAgentOutRoot() const {
  auto has_agent_binary = [](const std::filesystem::path& root) -> bool {
    if (root.empty()) {
      return false;
    }
    const std::filesystem::path arm64_a = root / "arm64-v8a" / "src" / "android_agent" / "r3_android_agent";
    const std::filesystem::path arm32_a = root / "armeabi-v7a" / "src" / "android_agent" / "r3_android_agent";
    const std::filesystem::path arm64_b = root / "arm64-v8a" / "r3_android_agent";
    const std::filesystem::path arm32_b = root / "armeabi-v7a" / "r3_android_agent";
    return std::filesystem::exists(arm64_a) || std::filesystem::exists(arm32_a) ||
           std::filesystem::exists(arm64_b) || std::filesystem::exists(arm32_b);
  };

  std::vector<std::filesystem::path> candidates;
  const std::filesystem::path exe_dir = GetExeDir();
  if (!exe_dir.empty()) {
    candidates.push_back(exe_dir / "android_agent");
    candidates.push_back(exe_dir.parent_path() / "android_agent");
    candidates.push_back(exe_dir / "runtime" / "android_agent");
  }

  const std::filesystem::path push_script = FindRuntimeScript(L"push_run_agent.ps1");
  if (!push_script.empty()) {
    const std::filesystem::path repo_root = push_script.parent_path().parent_path();
    candidates.push_back(repo_root / "build" / "android_agent");
  }

  std::error_code ec;
  const std::filesystem::path cwd = std::filesystem::current_path(ec);
  if (!ec && !cwd.empty()) {
    candidates.push_back(cwd / "build" / "android_agent");
    candidates.push_back(cwd / "core" / "build" / "android_agent");
  }

  for (const auto& path : candidates) {
    if (has_agent_binary(path)) {
      return path;
    }
  }
  return {};
}

bool CeLayoutWindow::ResolveAdbExecutablePath(std::wstring* out_path) const {
  if (out_path) {
    out_path->clear();
  }
  auto accept = [&](const std::filesystem::path& path) -> bool {
    if (path.empty()) {
      return false;
    }
    std::filesystem::path candidate = path;
    std::error_code ec;
    if (std::filesystem::is_directory(candidate, ec) && !ec) {
      candidate /= "adb.exe";
    }
    ec.clear();
    const bool ok = std::filesystem::exists(candidate, ec) && !ec;
    if (!ok) {
      return false;
    }
    if (out_path) {
      *out_path = candidate.wstring();
    }
    return true;
  };

  if (!adb_path_.empty() && accept(std::filesystem::path(Utf8ToWide(adb_path_)))) {
    return true;
  }

  const std::wstring env_r3_adb = ReadEnvWide(L"R3_ADB");
  if (!env_r3_adb.empty() && accept(std::filesystem::path(env_r3_adb))) {
    return true;
  }
  const std::wstring env_adb = ReadEnvWide(L"ADB");
  if (!env_adb.empty() && accept(std::filesystem::path(env_adb))) {
    return true;
  }

  const std::filesystem::path exe_dir = GetExeDir();
  if (!exe_dir.empty()) {
    const std::filesystem::path bundled0 = exe_dir / "adb_bundle" / "adb.exe";
    const std::filesystem::path bundled1 = exe_dir / "adb_bundle" / "platform-tools" / "adb.exe";
    const std::filesystem::path bundled2 = exe_dir / "adb" / "adb.exe";
    if (accept(bundled0) || accept(bundled1) || accept(bundled2)) {
      return true;
    }
  }

  const std::filesystem::path user_hint = L"E:\\gjzs\\adb.exe";
  if (accept(user_hint)) {
    return true;
  }

  const std::filesystem::path search = SearchPathExecutable(L"adb.exe");
  if (accept(search)) {
    return true;
  }
  return false;
}

void CeLayoutWindow::TryAutoBootstrapOnStartup() {
  if (startup_bootstrap_done_ || !auto_bootstrap_android_) {
    return;
  }
  startup_bootstrap_done_ = true;

  std::wstring adb_path;
  if (!ResolveAdbExecutablePath(&adb_path)) {
    UpdateStatus(L"启动检查: 未找到 ADB，跳过自动推送与连接");
    return;
  }
  const std::filesystem::path push_script = FindRuntimeScript(L"push_run_agent.ps1");
  const std::filesystem::path forward_script = FindRuntimeScript(L"adb_forward.ps1");
  const std::filesystem::path agent_root = ResolveAndroidAgentOutRoot();
  const std::wstring port_text = std::to_wstring(state_.port == 0 ? 12345 : state_.port);
  const HWND target_hwnd = hwnd_;
  UpdateStatus(L"启动检查: 正在检测设备并初始化 Android 侧...");
  std::thread([target_hwnd, adb_path, push_script, forward_script, agent_root, port_text]() {
    std::unique_ptr<AutoBootstrapResult> result = std::make_unique<AutoBootstrapResult>();
    if (!result) {
      return;
    }

    DWORD exit_code = 1;
    RunProcessAndWait(adb_path, {L"start-server"}, 10000, &exit_code);
    if (!RunProcessAndWait(adb_path, {L"get-state"}, 10000, &exit_code) || exit_code != 0) {
      result->status = L"启动检查: ADB 已就绪，但未检测到可用设备";
    } else {
      result->device_online = true;
      if (!push_script.empty() && !agent_root.empty()) {
        result->push_attempted = true;
        std::vector<std::wstring> args{
            L"-NoProfile",
            L"-ExecutionPolicy",
            L"Bypass",
            L"-File",
            push_script.wstring(),
            L"-Adb",
            adb_path,
            L"-Port",
            port_text,
            L"-OutRoot",
            agent_root.wstring(),
            L"-Run",
        };
        result->push_ok = RunProcessAndWait(L"powershell.exe", args, 120000, &exit_code) && exit_code == 0;
      }
      if (!forward_script.empty()) {
        result->forward_attempted = true;
        std::vector<std::wstring> args{
            L"-NoProfile",
            L"-ExecutionPolicy",
            L"Bypass",
            L"-File",
            forward_script.wstring(),
            L"-Adb",
            adb_path,
            L"-Port",
            port_text,
        };
        result->forward_ok = RunProcessAndWait(L"powershell.exe", args, 30000, &exit_code) && exit_code == 0;
      }
      if (!result->push_attempted && !result->forward_attempted) {
        result->status = L"启动检查: 设备在线，正在建立连接...";
      } else {
        result->status = L"启动检查: Android 侧初始化完成，正在建立连接...";
      }
    }

    AutoBootstrapResult* raw = result.release();
    if (!raw) {
      return;
    }
    if (target_hwnd && IsWindow(target_hwnd)) {
      PostMessageW(target_hwnd, kMsgAutoBootstrapDone, 0, reinterpret_cast<LPARAM>(raw));
    } else {
      delete raw;
    }
  }).detach();
}

void CeLayoutWindow::DrawTableHeader(const D2D1_RECT_F& rect,
                                     const wchar_t* c1,
                                     const wchar_t* c2,
                                     const wchar_t* c3) {
  render_target_->FillRectangle(rect, brush_panel_);
  render_target_->DrawRectangle(rect, brush_border_, 1.0f);

  const float w = rect.right - rect.left;
  const float c1w = w * 0.22f;
  const float c2w = w * 0.40f;

  const D2D1_RECT_F r1 = D2D1::RectF(rect.left + 8.0f, rect.top + 2.0f, rect.left + c1w, rect.bottom);
  const D2D1_RECT_F r2 = D2D1::RectF(rect.left + c1w + 8.0f, rect.top + 2.0f, rect.left + c1w + c2w, rect.bottom);
  const D2D1_RECT_F r3 = D2D1::RectF(rect.left + c1w + c2w + 8.0f, rect.top + 2.0f, rect.right - 8.0f, rect.bottom);
  render_target_->DrawTextW(c1, static_cast<UINT32>(wcslen(c1)), font_ui_, r1, brush_text_);
  render_target_->DrawTextW(c2, static_cast<UINT32>(wcslen(c2)), font_ui_, r2, brush_text_);
  render_target_->DrawTextW(c3, static_cast<UINT32>(wcslen(c3)), font_ui_, r3, brush_text_);
}

void CeLayoutWindow::DrawButton(ButtonId id,
                                const std::wstring& text,
                                float x,
                                float y,
                                float w,
                                float h,
                                bool primary) {
  Button button{};
  button.id = id;
  button.text = text;
  button.rect = D2D1::RectF(x, y, x + w, y + h);
  buttons_.push_back(button);

  const bool hovered = hovered_button_ == id;
  const bool guided = GetGuidedAction() == id;
  const bool enabled = IsButtonEnabled(id);
  ID2D1SolidColorBrush* fill = primary ? brush_accent_ : brush_panel_;
  ID2D1SolidColorBrush* text_brush = primary ? brush_accent_text_ : (enabled ? brush_text_ : brush_muted_);
  if (!enabled && !primary) {
    fill = brush_bg_;
  } else if (guided && !primary) {
    fill = brush_accent_;
    text_brush = brush_accent_text_;
  } else if (hovered && !primary) {
    fill = brush_row_alt_;
  }
  if (guided && enabled) {
    const D2D1_RECT_F halo = D2D1::RectF(button.rect.left - 2.0f, button.rect.top - 2.0f, button.rect.right + 2.0f, button.rect.bottom + 2.0f);
    render_target_->DrawRectangle(halo, brush_accent_, 1.8f);
  }
  render_target_->FillRectangle(button.rect, fill);
  render_target_->DrawRectangle(button.rect, guided && enabled ? brush_accent_text_ : brush_border_, guided && enabled ? 2.0f : 1.0f);
  render_target_->DrawTextW(button.text.c_str(),
                            static_cast<UINT32>(button.text.size()),
                            font_ui_center_,
                            button.rect,
                            text_brush);
}

void CeLayoutWindow::DrawIconButton(ButtonId id, const char* icon_id, float x, float y, float w, float h) {
  Button button{};
  button.id = id;
  button.rect = D2D1::RectF(x, y, x + w, y + h);
  buttons_.push_back(button);

  const bool hovered = hovered_button_ == id;
  const bool guided = GetGuidedAction() == id;
  const bool enabled = IsButtonEnabled(id);
  ID2D1SolidColorBrush* fill = brush_panel_;
  if (!enabled) {
    fill = brush_bg_;
  } else if (guided) {
    fill = brush_accent_;
  } else if (hovered) {
    fill = brush_row_alt_;
  }
  if (guided && enabled) {
    const D2D1_RECT_F halo = D2D1::RectF(button.rect.left - 2.0f, button.rect.top - 2.0f, button.rect.right + 2.0f, button.rect.bottom + 2.0f);
    render_target_->DrawRectangle(halo, brush_accent_, 1.8f);
  }
  render_target_->FillRectangle(button.rect, fill);
  render_target_->DrawRectangle(button.rect, guided && enabled ? brush_accent_text_ : brush_border_, guided && enabled ? 2.0f : 1.0f);

  if (icon_id && icon_id[0] != '\0') {
    const float pad = 4.0f;
    D2D1_RECT_F icon_rect = D2D1::RectF(button.rect.left + pad,
                                        button.rect.top + pad,
                                        button.rect.right - pad,
                                        button.rect.bottom - pad);
    DrawSvgIcon(icon_id, icon_rect);
  }
  if (!enabled) {
    render_target_->DrawLine(D2D1::Point2F(button.rect.left + 4.0f, button.rect.bottom - 4.0f),
                             D2D1::Point2F(button.rect.right - 4.0f, button.rect.top + 4.0f),
                             brush_muted_,
                             1.0f);
  }
}

void CeLayoutWindow::DrawTab(ButtonId id, const wchar_t* text, bool selected, float x, float y, float w, float h) {
  Button button{};
  button.id = id;
  button.rect = D2D1::RectF(x, y, x + w, y + h);
  buttons_.push_back(button);

  ID2D1SolidColorBrush* fill = selected ? brush_panel_ : brush_bg_;
  render_target_->FillRectangle(button.rect, fill);
  render_target_->DrawRectangle(button.rect, brush_border_, 1.0f);
  render_target_->DrawTextW(text,
                            static_cast<UINT32>(wcslen(text)),
                            font_ui_center_,
                            button.rect,
                            brush_text_);
}

void CeLayoutWindow::DrawSvgIcon(const char* icon_id, const D2D1_RECT_F& dest) {
  if (!svg_atlas_.bitmap || !icon_id) {
    return;
  }
  const auto it = svg_atlas_.icon_uv.find(icon_id);
  if (it == svg_atlas_.icon_uv.end()) {
    return;
  }
  render_target_->DrawBitmap(svg_atlas_.bitmap,
                             dest,
                             1.0f,
                             D2D1_BITMAP_INTERPOLATION_MODE_LINEAR,
                             &it->second);
}

void CeLayoutWindow::ApplyMenuIcons(HMENU menu_bar) {
  for (HBITMAP bmp : menu_bitmaps_) {
    if (bmp) {
      DeleteObject(bmp);
    }
  }
  menu_bitmaps_.clear();
  if (!menu_bar) {
    return;
  }

  static IconAtlasRaw atlas{};
  if (!LoadIconAtlasRaw(&atlas)) {
    return;
  }

  const int icon_px = std::max(14, static_cast<int>(std::lround(16.0f * dpi_scale_)));
  HMENU file = GetSubMenu(menu_bar, 0);
  HMENU view = GetSubMenu(menu_bar, 1);
  if (file) {
    HBITMAP open_bmp = CreateMenuIconBitmap(atlas, "open", icon_px);
    HBITMAP conn_bmp = CreateMenuIconBitmap(atlas, "connect", icon_px);
    HBITMAP stop_bmp = CreateMenuIconBitmap(atlas, "stop", icon_px);
    if (open_bmp) {
      menu_bitmaps_.push_back(open_bmp);
      SetMenuBitmap(file, kMenuFileOpen, open_bmp);
    }
    if (conn_bmp) {
      menu_bitmaps_.push_back(conn_bmp);
      SetMenuBitmap(file, kMenuFileSave, conn_bmp);
    }
    if (stop_bmp) {
      menu_bitmaps_.push_back(stop_bmp);
      SetMenuBitmap(file, kMenuFileExit, stop_bmp);
    }
  }
  if (view) {
    HBITMAP mem_bmp = CreateMenuIconBitmap(atlas, "memory", icon_px);
    if (mem_bmp) {
      menu_bitmaps_.push_back(mem_bmp);
      SetMenuBitmap(view, kMenuViewMemory, mem_bmp);
    }
  }
  DrawMenuBar(hwnd_);
}

bool CeLayoutWindow::LoadSvgAtlas() {
  if (!render_target_ || svg_atlas_.bitmap) {
    return svg_atlas_.bitmap != nullptr;
  }
  const std::filesystem::path atlas_path = GetExeDir() / "generated" / "icons" / "IconAtlas.bin";
  std::ifstream file(atlas_path, std::ios::binary);
  if (!file) {
    return false;
  }

  struct Header {
    char magic[4];
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t count;
    uint32_t table_size;
  };

  Header header{};
  file.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (!file || std::memcmp(header.magic, "R3IA", 4) != 0 || header.version != 1) {
    return false;
  }

  std::vector<uint8_t> table(header.table_size);
  file.read(reinterpret_cast<char*>(table.data()), static_cast<std::streamsize>(table.size()));
  if (!file) {
    return false;
  }

  svg_atlas_.icon_uv.clear();
  size_t offset = 0;
  while (offset + 12 <= table.size()) {
    uint16_t name_len = 0;
    uint16_t reserved = 0;
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t w = 0;
    uint16_t h = 0;
    std::memcpy(&name_len, table.data() + offset, 2);
    std::memcpy(&reserved, table.data() + offset + 2, 2);
    std::memcpy(&x, table.data() + offset + 4, 2);
    std::memcpy(&y, table.data() + offset + 6, 2);
    std::memcpy(&w, table.data() + offset + 8, 2);
    std::memcpy(&h, table.data() + offset + 10, 2);
    (void)reserved;
    offset += 12;
    if (offset + name_len > table.size()) {
      break;
    }
    std::string id(reinterpret_cast<const char*>(table.data() + offset), name_len);
    offset += name_len;
    svg_atlas_.icon_uv.emplace(std::move(id), D2D1::RectF(static_cast<float>(x),
                                                          static_cast<float>(y),
                                                          static_cast<float>(x + w),
                                                          static_cast<float>(y + h)));
  }

  const size_t pixel_count = static_cast<size_t>(header.width) * static_cast<size_t>(header.height);
  std::vector<uint8_t> rgba(pixel_count * 4);
  file.read(reinterpret_cast<char*>(rgba.data()), static_cast<std::streamsize>(rgba.size()));
  if (!file) {
    return false;
  }
  for (size_t i = 0; i + 3 < rgba.size(); i += 4) {
    std::swap(rgba[i], rgba[i + 2]);
  }

  svg_atlas_.width = header.width;
  svg_atlas_.height = header.height;
  const D2D1_BITMAP_PROPERTIES props =
      D2D1::BitmapProperties(D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));
  HRESULT hr = render_target_->CreateBitmap(D2D1::SizeU(header.width, header.height),
                                            rgba.data(),
                                            header.width * 4,
                                            props,
                                            &svg_atlas_.bitmap);
  return SUCCEEDED(hr);
}

bool CeLayoutWindow::HitTestButton(const POINT& pt, ButtonId* out_button) const {
  const POINT dip{static_cast<LONG>(std::lround(pt.x / dpi_scale_)),
                  static_cast<LONG>(std::lround(pt.y / dpi_scale_))};
  for (auto it = buttons_.rbegin(); it != buttons_.rend(); ++it) {
    if (RectContains(it->rect, dip)) {
      if (out_button) {
        *out_button = it->id;
      }
      return true;
    }
  }
  return false;
}

bool CeLayoutWindow::HitTestScanRow(const POINT& pt, size_t* out_row) const {
  const POINT dip{static_cast<LONG>(std::lround(pt.x / dpi_scale_)),
                  static_cast<LONG>(std::lround(pt.y / dpi_scale_))};
  if (!RectContains(scan_rows_rect_, dip)) {
    return false;
  }
  const float y = static_cast<float>(dip.y);
  if (scan_row_height_ <= 0.0f) {
    return false;
  }
  const float rel_y = y - scan_rows_rect_.top;
  const size_t row = static_cast<size_t>(rel_y / scan_row_height_);
  if (row >= scan_rows_count_) {
    return false;
  }
  const size_t actual_row = static_cast<size_t>(scan_scroll_offset_) + row;
  if (actual_row >= scan_rows_total_) {
    return false;
  }
  if (out_row) {
    *out_row = actual_row;
  }
  return true;
}

bool CeLayoutWindow::HitTestAddressRow(const POINT& pt, size_t* out_row) const {
  const POINT dip{static_cast<LONG>(std::lround(pt.x / dpi_scale_)),
                  static_cast<LONG>(std::lround(pt.y / dpi_scale_))};
  if (!RectContains(address_rows_rect_, dip)) {
    return false;
  }
  const float y = static_cast<float>(dip.y);
  if (address_row_height_ <= 0.0f) {
    return false;
  }
  const float rel_y = y - address_rows_rect_.top;
  const size_t row = static_cast<size_t>(rel_y / address_row_height_);
  if (row >= address_rows_count_) {
    return false;
  }
  const size_t actual_row = static_cast<size_t>(address_scroll_offset_) + row;
  if (actual_row >= address_rows_total_) {
    return false;
  }
  if (out_row) {
    *out_row = actual_row;
  }
  return true;
}

void CeLayoutWindow::DrawToolbar(const D2D1_RECT_F& rect) {
  render_target_->FillRectangle(rect, brush_panel_);
  render_target_->DrawRectangle(rect, brush_border_, 1.0f);

  float x = rect.left + 8.0f;
  const float y = rect.top + 6.0f;
  const float size = 24.0f;
  const float gap = 6.0f;

  DrawIconButton(ButtonId::SelectProcess, "process", x, y, size, size);
  x += size + gap;
  DrawIconButton(ButtonId::FirstScan, "scan", x, y, size, size);
  x += size + gap;
  DrawIconButton(ButtonId::OpenMemoryView, "memory", x, y, size, size);
  x += size + gap;
  DrawIconButton(ButtonId::OpenSettings, "settings", x, y, size, size);
}

void CeLayoutWindow::DrawProcessStrip(const D2D1_RECT_F& rect) {
  render_target_->FillRectangle(rect, brush_panel_);
  render_target_->DrawRectangle(rect, brush_border_, 1.0f);
  const int total_steps = 3;
  const float guide_w = 150.0f;
  const D2D1_RECT_F caption_rect = D2D1::RectF(rect.left + 8.0f, rect.top, rect.right - guide_w - 8.0f, rect.bottom);
  render_target_->DrawTextW(state_.process_caption.c_str(),
                            static_cast<UINT32>(state_.process_caption.size()),
                            font_ui_center_,
                            caption_rect,
                            brush_text_);

  const float cy = (rect.top + rect.bottom) * 0.5f;
  const float start_x = rect.right - guide_w + 10.0f;
  const float step_gap = 44.0f;
  const int current_step = GetGuideStep();
  for (int i = 1; i <= total_steps; ++i) {
    const float cx = start_x + static_cast<float>(i - 1) * step_gap;
    if (i < total_steps) {
      const D2D1_POINT_2F p0 = D2D1::Point2F(cx + 8.0f, cy);
      const D2D1_POINT_2F p1 = D2D1::Point2F(cx + step_gap - 8.0f, cy);
      render_target_->DrawLine(p0, p1, i < current_step ? brush_accent_ : brush_border_, 1.0f);
    }
    ID2D1SolidColorBrush* fill = brush_panel_;
    if (i < current_step) {
      fill = brush_row_alt_;
    } else if (i == current_step) {
      fill = brush_accent_;
    }
    render_target_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), 8.0f, 8.0f), fill);
    render_target_->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), 8.0f, 8.0f), brush_border_, 1.0f);
    wchar_t step_text[4] = {0};
    std::swprintf(step_text, static_cast<size_t>(std::size(step_text)), L"%d", i);
    render_target_->DrawTextW(step_text,
                              static_cast<UINT32>(wcslen(step_text)),
                              font_ui_center_,
                              D2D1::RectF(cx - 8.0f, cy - 8.0f, cx + 8.0f, cy + 8.0f),
                              brush_accent_text_);
  }
}

int CeLayoutWindow::GetGuideStep() const {
  if (!service_.IsConnected() || state_.pid == 0) {
    return 1;
  }
  if (state_.match_total == 0 || state_.page_addresses.empty()) {
    return 2;
  }
  return 3;
}

int CeLayoutWindow::GetGuideStepForButton(ButtonId id) const {
  switch (id) {
    case ButtonId::SelectProcess:
      return 1;
    case ButtonId::FirstScan:
      return 2;
    case ButtonId::OpenMemoryView:
      return 3;
    default:
      return 0;
  }
}

CeLayoutWindow::ButtonId CeLayoutWindow::GetGuidedAction() const {
  switch (GetGuideStep()) {
    case 1:
      return ButtonId::SelectProcess;
    case 2:
      return ButtonId::FirstScan;
    case 3:
      return ButtonId::OpenMemoryView;
    default:
      return ButtonId::None;
  }
}

bool CeLayoutWindow::IsButtonEnabled(ButtonId id) const {
  const bool has_pid = service_.IsConnected() && state_.pid != 0;
  switch (id) {
    case ButtonId::FirstScan:
      return has_pid;
    case ButtonId::NextScan:
    case ButtonId::UndoScan:
      return has_pid && (state_.match_total > 0 || !state_.page_addresses.empty());
    case ButtonId::OpenMemoryView:
      return has_pid;
    case ButtonId::OpenModuleRange:
      return has_pid;
    default:
      return true;
  }
}

const wchar_t* CeLayoutWindow::GetButtonHint(ButtonId id) const {
  switch (id) {
    case ButtonId::SelectProcess:
      return L"步骤1: 选择并附加进程";
    case ButtonId::ToggleConnect:
      return service_.IsConnected() ? L"断开与 Agent 的连接" : L"连接到 Agent";
    case ButtonId::OpenFile:
      return L"步骤1: 选择并附加进程";
    case ButtonId::SaveFile:
      return service_.IsConnected() ? L"断开与 Agent 的连接" : L"连接到 Agent";
    case ButtonId::OpenSettings:
    case ButtonId::OpenSettingsSide:
      return L"打开设置";
    case ButtonId::FirstScan:
      return L"步骤2: 首次扫描";
    case ButtonId::NextScan:
      return L"在首次扫描后执行再次扫描";
    case ButtonId::UndoScan:
      return L"撤销到上一轮扫描结果";
    case ButtonId::OpenMemoryView:
      return L"步骤3: 打开内存窗口";
    case ButtonId::AddManualAddress:
      return L"手动添加地址到地址列表";
    case ButtonId::OpenModuleRange:
      return L"刷新模块并选择扫描范围";
    case ButtonId::ScanTab1:
    case ButtonId::ScanTab2:
      return L"切换扫描标签";
    default:
      return nullptr;
  }
}

std::wstring CeLayoutWindow::BuildGuideHint() const {
  switch (GetGuideStep()) {
    case 1:
      return L"引导: 点击工具栏左侧进程图标，选择并附加进程";
    case 2:
      return L"引导: 输入数值后点击“首次扫描”";
    case 3:
      return L"引导: 点击“查看内存”进入 Memory View";
    default:
      return L"";
  }
}

void CeLayoutWindow::DrawScanArea(const D2D1_RECT_F& rect) {
  const float right_w = kScanRightPanelWidth;
  D2D1_RECT_F left = D2D1::RectF(rect.left, rect.top, rect.right - right_w - 4.0f, rect.bottom);
  D2D1_RECT_F right = D2D1::RectF(left.right + 4.0f, rect.top, rect.right, rect.bottom);
  const float panel_h = rect.bottom - rect.top;
  const bool compact = panel_h < 340.0f;
  const float row_h = compact ? 20.0f : 22.0f;
  const float row_gap = compact ? 4.0f : 6.0f;
  const float row_extra = compact ? 2.0f : 5.0f;

  render_target_->FillRectangle(left, brush_bg_);
  render_target_->DrawRectangle(left, brush_border_, 1.0f);
  render_target_->FillRectangle(right, brush_bg_);
  render_target_->DrawRectangle(right, brush_border_, 1.0f);

  const float tab_h = 22.0f;
  const float tab_w = 56.0f;
  const float tab_y = left.top + 4.0f;
  const float tab_x = left.left + 6.0f;
  DrawTab(ButtonId::ScanTab1, L"扫描1", scan_tab_ == 0, tab_x, tab_y, tab_w, tab_h);
  DrawTab(ButtonId::ScanTab2, L"扫描2", scan_tab_ == 1, tab_x + tab_w + 4.0f, tab_y, tab_w, tab_h);

  wchar_t result_label[128] = {0};
  std::swprintf(result_label,
                sizeof(result_label) / sizeof(wchar_t),
                L"结果: %llu",
                static_cast<unsigned long long>(state_.match_total));
  const D2D1_RECT_F result_rect = D2D1::RectF(left.left + 8.0f, tab_y + tab_h + 6.0f, left.left + 240.0f, tab_y + tab_h + 24.0f);
  render_target_->DrawTextW(result_label, static_cast<UINT32>(wcslen(result_label)), font_ui_, result_rect, brush_text_);

  const D2D1_RECT_F header = D2D1::RectF(left.left + 1.0f, tab_y + tab_h + 26.0f, left.right - 1.0f, tab_y + tab_h + 50.0f);
  DrawTableHeader(header, L"地址", L"当前值", L"先前值");

  float row_y = header.bottom + 4.0f;
  scan_row_height_ = 20.0f;
  const float scroll_w = 12.0f;
  const float rows_right = left.right - scroll_w - 4.0f;
  const size_t max_rows = static_cast<size_t>((left.bottom - row_y - 4.0f) / scan_row_height_);
  scan_rows_total_ = state_.page_addresses.size();
  scan_rows_visible_ = max_rows;
  if (scan_scroll_offset_ < 0) {
    scan_scroll_offset_ = 0;
  }
  const int max_scroll = std::max<int>(0, static_cast<int>(scan_rows_total_) - static_cast<int>(max_rows));
  if (scan_scroll_offset_ > max_scroll) {
    scan_scroll_offset_ = max_scroll;
  }
  const size_t start = static_cast<size_t>(scan_scroll_offset_);
  const size_t rows = std::min(max_rows, scan_rows_total_ > start ? scan_rows_total_ - start : 0);
  scan_rows_count_ = rows;
  scan_rows_rect_ = D2D1::RectF(left.left + 2.0f,
                                row_y,
                                rows_right,
                                row_y + static_cast<float>(rows) * scan_row_height_);
  const float content_w = std::max(120.0f, rows_right - (left.left + 2.0f));
  const float c1w = content_w * 0.38f;
  const float c2w = content_w * 0.30f;
  for (size_t i = 0; i < rows; ++i) {
    const size_t idx = start + i;
    wchar_t row_addr[64] = {0};
    std::swprintf(row_addr,
                  sizeof(row_addr) / sizeof(wchar_t),
                  L"0x%llX",
                  static_cast<unsigned long long>(state_.page_addresses[idx]));
    const bool is_selected = selected_scan_row_ == static_cast<int>(idx);
    const D2D1_RECT_F row_rect =
        D2D1::RectF(left.left + 2.0f, row_y, rows_right, row_y + scan_row_height_ - 1.0f);
    if (is_selected) {
      render_target_->FillRectangle(row_rect, brush_row_select_);
    } else if (i % 2 == 1) {
      render_target_->FillRectangle(row_rect, brush_row_alt_);
    }
    const float x0 = left.left + 10.0f;
    const float x1 = x0 + c1w;
    const float x2 = x1 + c2w;
    const D2D1_RECT_F r1 = D2D1::RectF(x0, row_y, x1, row_y + 20.0f);
    const D2D1_RECT_F r2 = D2D1::RectF(x1 + 8.0f, row_y, x2, row_y + 20.0f);
    const D2D1_RECT_F r3 = D2D1::RectF(x2 + 8.0f, row_y, rows_right - 8.0f, row_y + 20.0f);
    render_target_->DrawTextW(row_addr, static_cast<UINT32>(wcslen(row_addr)), font_mono_, r1, brush_text_);
    render_target_->DrawTextW(L"-", 1, font_ui_, r2, brush_muted_);
    render_target_->DrawTextW(L"-", 1, font_ui_, r3, brush_muted_);
    row_y += scan_row_height_;
  }

  float x = right.left + 10.0f;
  float y = right.top + 8.0f;
  DrawButton(ButtonId::FirstScan, L"首次扫描", x, y, 88.0f, 24.0f);
  DrawButton(ButtonId::NextScan, L"再次扫描", x + 96.0f, y, 88.0f, 24.0f);
  DrawButton(ButtonId::UndoScan, L"撤销扫描", x + 192.0f, y, 96.0f, 24.0f);

  const float gear_w = 30.0f;
  const float gear_h = 60.0f;
  const D2D1_RECT_F gear_rect =
      D2D1::RectF(right.right - gear_w - 6.0f, right.top + 6.0f, right.right - 6.0f, right.top + 6.0f + gear_h);
  Button gear_btn{};
  gear_btn.id = ButtonId::OpenSettingsSide;
  gear_btn.rect = gear_rect;
  buttons_.push_back(gear_btn);
  render_target_->FillRectangle(gear_rect, brush_panel_);
  render_target_->DrawRectangle(gear_rect, brush_border_, 1.0f);
  DrawSvgIcon("settings", D2D1::RectF(gear_rect.left + 4.0f, gear_rect.top + 4.0f, gear_rect.right - 4.0f, gear_rect.top + 24.0f));
  render_target_->DrawTextW(L"设置", 2, font_ui_center_,
                            D2D1::RectF(gear_rect.left + 2.0f, gear_rect.top + 26.0f, gear_rect.right - 2.0f, gear_rect.bottom - 2.0f),
                            brush_text_);

  const float pad = 10.0f;
  const float right_col_w = 112.0f;
  const float label_w = 64.0f;
  const float label_x = right.left + pad;
  const float ctrl_x = label_x + label_w;
  const float right_col_x = right.right - pad - right_col_w;
  y = right.top + 54.0f;
  render_target_->DrawTextW(L"数值", 2, font_ui_, D2D1::RectF(label_x, y + 2.0f, label_x + label_w, y + row_h), brush_text_);
  y += row_h + row_gap;
  render_target_->DrawTextW(L"扫描类型", 4, font_ui_, D2D1::RectF(label_x, y + 2.0f, label_x + label_w, y + row_h), brush_text_);
  y += row_h + row_gap;
  render_target_->DrawTextW(L"数值类型", 4, font_ui_, D2D1::RectF(label_x, y + 2.0f, label_x + label_w, y + row_h), brush_text_);
  y += row_h + row_gap + row_extra;

  const float group_top = y + 8.0f;
  const float group_h = 28.0f + (row_h + row_gap) + (row_h + row_gap) + (row_h + 4.0f) +
                        row_h + row_h + row_h + row_h + 4.0f;
  const float group_bottom = std::min(right.bottom - 6.0f, group_top + group_h);
  const D2D1_RECT_F group_rect = D2D1::RectF(right.left + pad, group_top, right.right - pad, group_bottom);
  render_target_->DrawRectangle(group_rect, brush_border_, 1.0f);
  const D2D1_RECT_F group_title_bg =
      D2D1::RectF(group_rect.left + 8.0f, group_rect.top + 1.0f, group_rect.left + 130.0f, group_rect.top + 19.0f);
  render_target_->FillRectangle(group_title_bg, brush_bg_);
  render_target_->DrawTextW(L"内存扫描选项",
                            6,
                            font_ui_,
                            D2D1::RectF(group_rect.left + 10.0f, group_rect.top + 2.0f, group_rect.right - 8.0f, group_rect.top + 18.0f),
                            brush_muted_);

  float gy = group_top + 28.0f;
  render_target_->DrawTextW(L"内存区域", 4, font_ui_, D2D1::RectF(label_x, gy + 2.0f, label_x + label_w, gy + row_h), brush_text_);
  DrawButton(ButtonId::OpenModuleRange, L"模块范围...", right_col_x, gy, right_col_w, row_h);
  gy += row_h + row_gap;
  render_target_->DrawTextW(L"起始", 2, font_ui_, D2D1::RectF(label_x, gy + 2.0f, label_x + label_w, gy + row_h), brush_text_);
  gy += row_h + row_gap;
  render_target_->DrawTextW(L"停止", 2, font_ui_, D2D1::RectF(label_x, gy + 2.0f, label_x + label_w, gy + row_h), brush_text_);
}

void CeLayoutWindow::DrawAddressListArea(const D2D1_RECT_F& rect) {
  render_target_->FillRectangle(rect, brush_bg_);
  render_target_->DrawRectangle(rect, brush_border_, 1.0f);

  const float top_h = 28.0f;
  const D2D1_RECT_F top = D2D1::RectF(rect.left, rect.top, rect.right, rect.top + top_h);
  render_target_->FillRectangle(top, brush_panel_);
  render_target_->DrawRectangle(top, brush_border_, 1.0f);
  DrawButton(ButtonId::OpenMemoryView, L"查看内存", top.left + 6.0f, top.top + 3.0f, 86.0f, 22.0f);
  DrawButton(ButtonId::AddManualAddress, L"手动添加地址", top.right - 110.0f, top.top + 3.0f, 104.0f, 22.0f);
  DrawIconButton(ButtonId::ClearAddressList, "stop", (top.left + top.right) * 0.5f - 11.0f, top.top + 3.0f, 22.0f, 22.0f);

  const D2D1_RECT_F header = D2D1::RectF(rect.left + 1.0f, top.bottom + 2.0f, rect.right - 1.0f, top.bottom + 26.0f);
  render_target_->FillRectangle(header, brush_panel_);
  render_target_->DrawRectangle(header, brush_border_, 1.0f);

  const float scroll_w = 12.0f;
  const float rows_right = rect.right - scroll_w - 4.0f;
  const float col_active_left = rect.left + 8.0f;
  const float col_active_right = col_active_left + 24.0f;
  const float col_freeze_left = col_active_right + 2.0f;
  const float col_freeze_right = col_freeze_left + 22.0f;
  const float col_desc_left = col_freeze_right + 4.0f;
  const float col_desc_right = col_desc_left + 208.0f;
  const float col_addr_left = col_desc_right + 8.0f;
  const float col_addr_right = col_addr_left + 170.0f;
  const float col_type_left = col_addr_right + 8.0f;
  const float col_type_right = col_type_left + 84.0f;
  const float col_value_left = col_type_right + 8.0f;
  address_hit_active_left_ = col_active_left;
  address_hit_active_right_ = col_active_right;
  address_hit_freeze_left_ = col_freeze_left;
  address_hit_freeze_right_ = col_freeze_right;
  address_hit_value_left_ = col_value_left;

  render_target_->DrawTextW(L"激活", 2, font_ui_,
                            D2D1::RectF(col_active_left, header.top + 4.0f, col_active_right, header.bottom),
                            brush_muted_);
  render_target_->DrawTextW(L"冻", 1, font_ui_,
                            D2D1::RectF(col_freeze_left, header.top + 4.0f, col_freeze_right, header.bottom),
                            brush_muted_);
  render_target_->DrawTextW(L"描述", 2, font_ui_,
                            D2D1::RectF(col_desc_left, header.top + 4.0f, col_desc_right, header.bottom),
                            brush_muted_);
  render_target_->DrawTextW(L"地址", 2, font_ui_,
                            D2D1::RectF(col_addr_left, header.top + 4.0f, col_addr_right, header.bottom),
                            brush_muted_);
  render_target_->DrawTextW(L"类型", 2, font_ui_,
                            D2D1::RectF(col_type_left, header.top + 4.0f, col_type_right, header.bottom),
                            brush_muted_);
  render_target_->DrawTextW(L"数值", 2, font_ui_,
                            D2D1::RectF(col_value_left, header.top + 4.0f, rect.right - 12.0f, header.bottom),
                            brush_muted_);

  float row_y = header.bottom + 4.0f;
  const float row_h = 20.0f;
  const size_t max_rows = static_cast<size_t>((rect.bottom - row_y - 6.0f) / row_h);
  address_rows_total_ = state_.address_entries.size();
  address_rows_visible_ = max_rows;
  if (address_scroll_offset_ < 0) {
    address_scroll_offset_ = 0;
  }
  const int addr_max_scroll = std::max<int>(0, static_cast<int>(address_rows_total_) - static_cast<int>(max_rows));
  if (address_scroll_offset_ > addr_max_scroll) {
    address_scroll_offset_ = addr_max_scroll;
  }
  const size_t start = static_cast<size_t>(address_scroll_offset_);
  const size_t rows = std::min(max_rows, address_rows_total_ > start ? address_rows_total_ - start : 0);
  address_row_height_ = row_h;
  address_rows_count_ = rows;
  address_rows_rect_ = D2D1::RectF(rect.left + 2.0f,
                                   row_y,
                                   rows_right,
                                   row_y + static_cast<float>(rows) * row_h);
  for (size_t i = 0; i < rows; ++i) {
    const size_t idx = start + i;
    const D2D1_RECT_F row_rect = D2D1::RectF(rect.left + 2.0f, row_y, rows_right, row_y + row_h - 1.0f);
    if (i % 2 == 1) {
      render_target_->FillRectangle(row_rect, brush_row_alt_);
    }
    const D2D1_RECT_F r_desc = D2D1::RectF(col_desc_left, row_y, col_desc_right, row_y + 18.0f);
    const D2D1_RECT_F r_addr = D2D1::RectF(col_addr_left, row_y, col_addr_right, row_y + 18.0f);
    const D2D1_RECT_F r_type = D2D1::RectF(col_type_left, row_y, col_type_right, row_y + 18.0f);
    const D2D1_RECT_F r_value = D2D1::RectF(col_value_left, row_y, rows_right - 8.0f, row_y + 18.0f);

    const auto& entry = state_.address_entries[idx];
    const D2D1_RECT_F checkbox_rect = D2D1::RectF(col_active_left + 3.0f, row_y + 3.0f, col_active_left + 15.0f, row_y + 15.0f);
    render_target_->DrawRectangle(checkbox_rect, brush_border_, 1.0f);
    if (entry.active) {
      const D2D1_POINT_2F p1 = D2D1::Point2F(checkbox_rect.left + 2.0f, checkbox_rect.top + 6.0f);
      const D2D1_POINT_2F p2 = D2D1::Point2F(checkbox_rect.left + 5.0f, checkbox_rect.bottom - 2.0f);
      const D2D1_POINT_2F p3 = D2D1::Point2F(checkbox_rect.right - 2.0f, checkbox_rect.top + 2.0f);
      render_target_->DrawLine(p1, p2, brush_text_, 1.5f);
      render_target_->DrawLine(p2, p3, brush_text_, 1.5f);
    }

    const D2D1_RECT_F freeze_rect = D2D1::RectF(col_freeze_left + 4.0f, row_y + 3.0f, col_freeze_left + 16.0f, row_y + 15.0f);
    const D2D1_COLOR_F freeze_color = entry.frozen ? Rgba(224, 90, 90) : Rgba(120, 120, 120);
    ID2D1SolidColorBrush* freeze_brush = brush_muted_;
    if (brush_muted_) {
      brush_muted_->SetColor(freeze_color);
      freeze_brush = brush_muted_;
    }
    render_target_->DrawEllipse(D2D1::Ellipse(D2D1::Point2F((freeze_rect.left + freeze_rect.right) * 0.5f,
                                                             (freeze_rect.top + freeze_rect.bottom) * 0.5f),
                                              5.0f,
                                              5.0f),
                                freeze_brush,
                                1.3f);
    render_target_->DrawLine(D2D1::Point2F(freeze_rect.left + 2.0f, freeze_rect.bottom - 2.0f),
                             D2D1::Point2F(freeze_rect.right - 2.0f, freeze_rect.top + 2.0f),
                             freeze_brush,
                             1.3f);
    if (brush_muted_) {
      brush_muted_->SetColor(Rgba(190, 190, 190));
    }

    const wchar_t* desc = entry.desc.empty() ? L"扫描结果" : entry.desc.c_str();
    render_target_->DrawTextW(desc, static_cast<UINT32>(wcslen(desc)), font_ui_, r_desc, brush_text_);

    wchar_t addr_buf[64] = {0};
    std::swprintf(addr_buf,
                  sizeof(addr_buf) / sizeof(wchar_t),
                  L"0x%llX",
                  static_cast<unsigned long long>(entry.addr));
    render_target_->DrawTextW(addr_buf, static_cast<UINT32>(wcslen(addr_buf)), font_mono_, r_addr, brush_text_);
    const wchar_t* type_name = ValueTypeName(entry.type);
    render_target_->DrawTextW(type_name, static_cast<UINT32>(wcslen(type_name)), font_ui_, r_type, brush_text_);
    render_target_->DrawTextW(entry.value.empty() ? L"-" : entry.value.c_str(),
                              entry.value.empty() ? 1 : static_cast<UINT32>(entry.value.size()),
                              font_mono_,
                              r_value,
                              brush_text_);
    row_y += row_h;
  }
}

void CeLayoutWindow::DrawStatusBar(const D2D1_RECT_F& rect) {
  render_target_->FillRectangle(rect, brush_panel_);
  render_target_->DrawRectangle(rect, brush_border_, 1.0f);

  wchar_t left[256] = {0};
  std::swprintf(left,
                sizeof(left) / sizeof(wchar_t),
                L"%ls | PID:%u | 匹配:%llu | 页:%llu",
                service_.IsConnected() ? L"已连接" : L"未连接",
                state_.pid,
                static_cast<unsigned long long>(state_.match_total),
                static_cast<unsigned long long>(state_.page_index + 1));
  render_target_->DrawTextW(left,
                            static_cast<UINT32>(wcslen(left)),
                            font_ui_,
                            D2D1::RectF(rect.left + 8.0f, rect.top + 3.0f, rect.left + 380.0f, rect.bottom),
                            brush_text_);
  const wchar_t* hover_hint = GetButtonHint(hovered_button_);
  std::wstring status;
  if (hover_hint) {
    status = hover_hint;
  } else if (GetGuideStep() <= 3) {
    status = BuildGuideHint();
    if (!state_.status.empty()) {
      status += L" | ";
      status += state_.status;
    }
  } else {
    status = state_.status.empty() ? L"就绪" : state_.status;
  }
  render_target_->DrawTextW(status.c_str(),
                            static_cast<UINT32>(status.size()),
                            font_ui_,
                            D2D1::RectF(rect.left + 392.0f, rect.top + 3.0f, rect.right - 8.0f, rect.bottom),
                            brush_muted_);
}

void CeLayoutWindow::DrawHoverHintOverlay(const D2D1_RECT_F& rect) {
  if (hovered_button_ == ButtonId::None) {
    return;
  }
  const wchar_t* hint = GetButtonHint(hovered_button_);
  if (!hint || hint[0] == L'\0') {
    return;
  }
  const Button* target = nullptr;
  for (auto it = buttons_.rbegin(); it != buttons_.rend(); ++it) {
    if (it->id == hovered_button_) {
      target = &(*it);
      break;
    }
  }
  if (!target) {
    return;
  }

  const size_t text_len = wcslen(hint);
  const float bubble_h = 24.0f;
  const float bubble_w = std::clamp(20.0f + static_cast<float>(text_len) * 7.2f, 110.0f, std::max(110.0f, rect.right - 16.0f));
  float x = target->rect.left;
  float y = target->rect.bottom + 6.0f;
  if (x + bubble_w > rect.right - 8.0f) {
    x = rect.right - 8.0f - bubble_w;
  }
  if (x < 8.0f) {
    x = 8.0f;
  }
  if (y + bubble_h > rect.bottom - 26.0f) {
    y = target->rect.top - bubble_h - 6.0f;
  }
  if (y < 8.0f) {
    y = 8.0f;
  }

  const D2D1_RECT_F bubble = D2D1::RectF(x, y, x + bubble_w, y + bubble_h);
  render_target_->FillRectangle(bubble, brush_panel_);
  render_target_->DrawRectangle(bubble, brush_accent_, 1.3f);
  render_target_->DrawTextW(hint, static_cast<UINT32>(text_len), font_ui_center_, bubble, brush_text_);
}

void CeLayoutWindow::Draw() {
  if (!render_target_) return;
  buttons_.clear();

  render_target_->BeginDraw();
  render_target_->Clear(Rgba(43, 43, 43));

  const D2D1_SIZE_F size = render_target_->GetSize();
  const float toolbar_h = 36.0f;
  const float process_h = 22.0f;
  const float status_h = 22.0f;
  const float fixed_h = toolbar_h + process_h + status_h;
  float address_h = std::max(90.0f, size.height * 0.28f);
  float scan_h = size.height - fixed_h - address_h;
  if (scan_h < 334.0f) {
    address_h = std::max(72.0f, size.height - fixed_h - 334.0f);
    scan_h = size.height - fixed_h - address_h;
  }
  if (scan_h < 304.0f) {
    address_h = std::max(60.0f, size.height - fixed_h - 304.0f);
    scan_h = size.height - fixed_h - address_h;
  }
  if (scan_h < 230.0f) {
    scan_h = 230.0f;
    address_h = std::max(60.0f, size.height - fixed_h - scan_h);
  }

  float y = 0.0f;
  const D2D1_RECT_F toolbar = D2D1::RectF(0.0f, y, size.width, y + toolbar_h); y += toolbar_h;
  const D2D1_RECT_F process = D2D1::RectF(0.0f, y, size.width, y + process_h); y += process_h;
  const D2D1_RECT_F scan = D2D1::RectF(0.0f, y, size.width, y + scan_h); y += scan_h;
  const D2D1_RECT_F addr = D2D1::RectF(0.0f, y, size.width, y + address_h); y += address_h;
  const D2D1_RECT_F status = D2D1::RectF(0.0f, y, size.width, size.height);

  DrawToolbar(toolbar);
  DrawProcessStrip(process);
  DrawScanArea(scan);
  DrawAddressListArea(addr);
  DrawStatusBar(status);
  UpdateScrollBars();

  const HRESULT hr = render_target_->EndDraw();
  if (hr == D2DERR_RECREATE_TARGET) {
    DiscardDeviceResources();
  }
}
bool CeLayoutWindow::EnsureConnected() {
  if (service_.IsConnected()) {
    state_.connected = true;
    return true;
  }
  std::string error;
  if (!service_.Connect(state_.host, state_.port, &error)) {
    state_.connected = false;
    UpdateStatus(Utf8ToWide(error));
    return false;
  }
  state_.connected = true;
  UpdateStatus(L"连接成功");
  return true;
}

bool CeLayoutWindow::RefreshProcesses() {
  if (!EnsureConnected()) {
    return false;
  }
  std::vector<services::ProcessInfo> list;
  std::string error;
  if (!service_.FetchProcesses(&list, &error)) {
    UpdateStatus(Utf8ToWide(error));
    return false;
  }

  state_.processes.clear();
  state_.processes.reserve(list.size());
  for (const auto& item : list) {
    app::ProcessItem proc{};
    proc.pid = item.pid;
    proc.name = Utf8ToWide(item.name);
    state_.processes.push_back(std::move(proc));
  }

  wchar_t msg[128] = {0};
  std::swprintf(msg, sizeof(msg) / sizeof(wchar_t), L"进程列表已更新: %zu", state_.processes.size());
  UpdateStatus(msg);
  process_list_last_refresh_ms_ = NowMs();
  return true;
}

void CeLayoutWindow::ShowProcessPopup() {
  const uint64_t now = NowMs();
  const bool has_cache = !state_.processes.empty();
  const bool cache_fresh = has_cache && process_list_last_refresh_ms_ != 0 &&
                           (now - process_list_last_refresh_ms_ <= 2500);
  if (!cache_fresh) {
    if (!RefreshProcesses() && state_.processes.empty()) {
      UpdateStatus(L"连接失败，显示空进程列表（可重试）");
    }
  } else {
    UpdateStatus(L"使用缓存进程列表（Ctrl+F 过滤）");
  }
  size_t selected = std::numeric_limits<size_t>::max();
  if (!PromptProcessPickerDialog(hwnd_, state_.processes, &service_, &selected)) {
    UpdateStatus(L"已取消进程选择");
    return;
  }
  if (selected >= state_.processes.size()) {
    UpdateStatus(L"进程选择无效");
    return;
  }
  AttachProcessByIndex(selected);
}

void CeLayoutWindow::AttachProcessByIndex(size_t index) {
  if (index >= state_.processes.size()) return;
  const auto& proc = state_.processes[index];
  std::string error;
  if (!service_.Attach(proc.pid, &error)) {
    UpdateStatus(Utf8ToWide(error));
    return;
  }
  state_.pid = proc.pid;
  state_.process_caption = BuildProcessCaption(proc.pid, proc.name);
  state_.match_total = 0;
  state_.page_index = 0;
  state_.page_addresses.clear();
  selected_scan_row_ = -1;
  scan_scroll_offset_ = 0;
  prev_scan_ = {};
  has_prev_scan_ = false;
  backend_scan_tab_ = -1;
  for (auto& tab : scan_tabs_) {
    tab = {};
  }
  uint8_t arch = static_cast<uint8_t>(protocol::RegsArch::UNKNOWN);
  uint8_t ptr_size = 0;
  if (service_.FetchProcInfo(&arch, &ptr_size, nullptr)) {
    state_.arch = arch;
    state_.pointer_size = ptr_size;
  }
  UpdateStatus(L"附加进程成功");
  ReloadScanRegionOptions(true);
  ApplySelectedScanRegion(false);
  if (settings_window_.IsOpen()) {
    SettingsSnapshot snapshot{};
    snapshot.host = Utf8ToWide(state_.host);
    snapshot.port = state_.port;
    snapshot.pid = state_.pid;
    snapshot.scan_type = state_.scan_value_type;
    snapshot.scan_hex = state_.scan_value_hex;
    snapshot.scan_strict = state_.scan_fast && state_.scan_copy_on_write;
    snapshot.scan_use_pvm = state_.scan_use_pvm;
    snapshot.scan_writable = state_.scan_writable;
    snapshot.scan_exec = state_.scan_executable;
    snapshot.scan_private = state_.scan_private;
    snapshot.scan_image = state_.scan_image;
    snapshot.scan_mapped = state_.scan_mapped;
    snapshot.address_refresh_ms = address_refresh_interval_ms_;
    snapshot.address_freeze_ms = address_freeze_interval_ms_;
    snapshot.address_auto_refresh = address_auto_refresh_;
    snapshot.address_freeze_enable = address_freeze_enabled_;
    snapshot.address_auto_add = address_auto_add_;
    settings_window_.ApplySnapshot(snapshot);
  }
}

void CeLayoutWindow::SyncStateFromControls() {
  wchar_t buf[256] = {0};

  if (edit_scan_value_) {
    GetWindowTextW(edit_scan_value_, buf, static_cast<int>(std::size(buf)));
    state_.scan_value_text = WideToUtf8(std::wstring(buf));
  }
  if (edit_scan_start_) {
    GetWindowTextW(edit_scan_start_, buf, static_cast<int>(std::size(buf)));
    state_.scan_start_text = WideToUtf8(std::wstring(buf));
  }
  if (edit_scan_end_) {
    GetWindowTextW(edit_scan_end_, buf, static_cast<int>(std::size(buf)));
    state_.scan_end_text = WideToUtf8(std::wstring(buf));
  }

  if (combo_scan_type_) {
    LRESULT idx = SendMessageW(combo_scan_type_, CB_GETCURSEL, 0, 0);
    if (idx >= 0 && idx < static_cast<LRESULT>(std::size(kTypeMap))) {
      state_.scan_value_type = kTypeMap[idx];
    }
  }
  if (combo_scan_cond_) {
    LRESULT idx = SendMessageW(combo_scan_cond_, CB_GETCURSEL, 0, 0);
    if (idx >= 0 && idx < static_cast<LRESULT>(std::size(kCondMap))) {
      state_.scan_condition = kCondMap[idx];
    }
  }
  UpdateScanValueInputState(edit_scan_value_, check_scan_hex_, state_.scan_condition);
  if (check_scan_hex_) {
    state_.scan_value_hex = SendMessageW(check_scan_hex_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (check_scan_fast_) {
    state_.scan_fast = SendMessageW(check_scan_fast_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (edit_scan_fast_value_) {
    wchar_t num_buf[32] = {0};
    GetWindowTextW(edit_scan_fast_value_, num_buf, static_cast<int>(std::size(num_buf)));
    int value = static_cast<int>(std::wcstol(num_buf, nullptr, 10));
    if (value > 0 && value <= 1024) {
      ui_scan_fast_value_ = value;
    }
  }
  if (radio_scan_align_ && radio_scan_last_) {
    const bool align = SendMessageW(radio_scan_align_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    ui_scan_fast_mode_ = align ? 0 : 1;
  }
  if (check_scan_writable_) {
    state_.scan_writable = SendMessageW(check_scan_writable_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (check_scan_executable_) {
    state_.scan_executable = SendMessageW(check_scan_executable_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (check_scan_copy_) {
    state_.scan_copy_on_write = SendMessageW(check_scan_copy_, BM_GETCHECK, 0, 0) == BST_CHECKED;
  }
  if (check_scan_active_) {
    const bool private_only = SendMessageW(check_scan_active_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    state_.scan_private = private_only;
  }
}

void CeLayoutWindow::SyncControlsFromState() {
  if (combo_scan_type_) {
    EnableWindow(combo_scan_type_, TRUE);
    SendMessageW(combo_scan_type_, CB_SETCURSEL, static_cast<WPARAM>(TypeToIndex(state_.scan_value_type)), 0);
  }
  if (combo_scan_cond_) {
    EnableWindow(combo_scan_cond_, TRUE);
    SendMessageW(combo_scan_cond_, CB_SETCURSEL, static_cast<WPARAM>(CondToIndex(state_.scan_condition)), 0);
  }
  UpdateScanValueInputState(edit_scan_value_, check_scan_hex_, state_.scan_condition);
  if (check_scan_hex_) {
    SendMessageW(check_scan_hex_, BM_SETCHECK, state_.scan_value_hex ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (check_scan_fast_) {
    SendMessageW(check_scan_fast_, BM_SETCHECK, state_.scan_fast ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (check_scan_writable_) {
    SendMessageW(check_scan_writable_, BM_SETCHECK, state_.scan_writable ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (check_scan_executable_) {
    SendMessageW(check_scan_executable_, BM_SETCHECK, state_.scan_executable ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (check_scan_copy_) {
    SendMessageW(check_scan_copy_, BM_SETCHECK, state_.scan_copy_on_write ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (check_scan_active_) {
    SendMessageW(check_scan_active_, BM_SETCHECK, state_.scan_private ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (radio_scan_align_) {
    SendMessageW(radio_scan_align_, BM_SETCHECK, ui_scan_fast_mode_ == 0 ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (radio_scan_last_) {
    SendMessageW(radio_scan_last_, BM_SETCHECK, ui_scan_fast_mode_ == 1 ? BST_CHECKED : BST_UNCHECKED, 0);
  }
  if (edit_scan_fast_value_) {
    wchar_t buf[32] = {0};
    std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%d", ui_scan_fast_value_);
    SetWindowTextW(edit_scan_fast_value_, buf);
  }
  if (edit_scan_value_) {
    SetWindowTextW(edit_scan_value_, Utf8ToWide(state_.scan_value_text).c_str());
  }
  if (edit_scan_start_) {
    SetWindowTextW(edit_scan_start_, Utf8ToWide(state_.scan_start_text).c_str());
  }
  if (edit_scan_end_) {
    SetWindowTextW(edit_scan_end_, Utf8ToWide(state_.scan_end_text).c_str());
  }
}

void CeLayoutWindow::UpdateScrollBars() {
  auto apply_scroll = [](HWND scroll,
                         size_t total,
                         size_t visible,
                         int pos) {
    if (!scroll) {
      return;
    }
    SCROLLINFO si{};
    si.cbSize = sizeof(si);
    si.fMask = SIF_PAGE | SIF_POS | SIF_RANGE;
    si.nMin = 0;
    si.nMax = std::max<int>(0, static_cast<int>(total) - 1);
    si.nPage = static_cast<UINT>(std::max<size_t>(1, visible));
    si.nPos = std::max(0, pos);
    SetScrollInfo(scroll, SB_CTL, &si, TRUE);
    ShowWindow(scroll, total > visible ? SW_SHOW : SW_HIDE);
  };
  apply_scroll(scroll_scan_, scan_rows_total_, scan_rows_visible_, scan_scroll_offset_);
  apply_scroll(scroll_addr_, address_rows_total_, address_rows_visible_, address_scroll_offset_);
}

uint16_t CeLayoutWindow::BuildScanFlags() const {
  uint16_t flags = 0;
  if (state_.scan_use_pvm) {
    flags |= protocol::SCAN_FLAG_USE_PVM;
  }
  if (state_.scan_fast) {
    flags |= protocol::SCAN_FLAG_BYTE_STEP;
  }
  if (state_.scan_copy_on_write) {
    flags |= protocol::SCAN_FLAG_ALLOW_NONRESIDENT;
  }
  if (state_.scan_fast && state_.scan_copy_on_write) {
    flags |= protocol::SCAN_FLAG_STRICT;
  }
  if (state_.scan_writable) {
    flags |= protocol::SCAN_FLAG_REQUIRE_WRITABLE;
  }
  if (state_.scan_executable) {
    flags |= protocol::SCAN_FLAG_REQUIRE_EXEC;
  }
  if (state_.scan_private) {
    flags |= protocol::SCAN_FLAG_REQUIRE_PRIVATE;
  }
  if (state_.scan_image) {
    flags |= protocol::SCAN_FLAG_REQUIRE_IMAGE;
  }
  if (state_.scan_mapped) {
    flags |= protocol::SCAN_FLAG_REQUIRE_MAPPED;
  }
  if (scan_region_gg_code_ != protocol::GG_REGION_NONE) {
    flags |= static_cast<uint16_t>(
        (static_cast<uint16_t>(scan_region_gg_code_) << protocol::SCAN_FLAG_GG_SHIFT) &
        protocol::SCAN_FLAG_GG_MASK);
  }
  return flags;
}

bool CeLayoutWindow::BuildScanRequest(protocol::ComparisonType* out_comparison,
                                      std::string* out_value_text,
                                      std::wstring* out_error) const {
  if (!out_comparison || !out_value_text) {
    if (out_error) {
      *out_error = L"扫描参数无效";
    }
    return false;
  }
  const bool variable_pattern_type =
      state_.scan_value_type == protocol::ValueType::STRING ||
      state_.scan_value_type == protocol::ValueType::AOB ||
      state_.scan_value_type == protocol::ValueType::BINARY;
  const bool all_type = state_.scan_value_type == protocol::ValueType::ALL;
  if ((variable_pattern_type || all_type) &&
      (state_.scan_condition == protocol::ComparisonType::CHANGED ||
       state_.scan_condition == protocol::ComparisonType::UNCHANGED)) {
    if (out_error) {
      *out_error = L"当前数值类型不支持“已改变/未改变”";
    }
    return false;
  }
  if (variable_pattern_type &&
      state_.scan_condition != protocol::ComparisonType::EQ &&
      state_.scan_condition != protocol::ComparisonType::NE) {
    if (out_error) {
      *out_error = L"String/AOB/Binary 仅支持 = 和 !=";
    }
    return false;
  }
  if (all_type &&
      state_.scan_condition != protocol::ComparisonType::EQ &&
      state_.scan_condition != protocol::ComparisonType::NE &&
      state_.scan_condition != protocol::ComparisonType::GT &&
      state_.scan_condition != protocol::ComparisonType::LT &&
      state_.scan_condition != protocol::ComparisonType::GE &&
      state_.scan_condition != protocol::ComparisonType::LE) {
    if (out_error) {
      *out_error = L"扫描条件不支持当前数值类型";
    }
    return false;
  }
  *out_comparison = state_.scan_condition;
  if (!ComparisonNeedsInput(state_.scan_condition)) {
    *out_value_text = "0";
    return true;
  }
  const std::string value = TrimAscii(state_.scan_value_text);
  if (value.empty()) {
    if (out_error) {
      *out_error = L"请输入扫描数值";
    }
    return false;
  }
  *out_value_text = value;
  return true;
}

void CeLayoutWindow::SaveCurrentTabState() {
  if (scan_tab_ < 0 || scan_tab_ >= static_cast<int>(scan_tabs_.size())) {
    return;
  }
  ScanTabState& tab = scan_tabs_[static_cast<size_t>(scan_tab_)];
  tab.match_total = state_.match_total;
  tab.page_index = state_.page_index;
  tab.page_addresses = state_.page_addresses;
  tab.selected_row = selected_scan_row_;
  tab.prev = prev_scan_;
  tab.has_prev = has_prev_scan_;
}

void CeLayoutWindow::LoadTabState(int tab_index) {
  if (tab_index < 0 || tab_index >= static_cast<int>(scan_tabs_.size())) {
    return;
  }
  scan_tab_ = tab_index;
  const ScanTabState& tab = scan_tabs_[static_cast<size_t>(tab_index)];
  state_.match_total = tab.match_total;
  state_.page_index = tab.page_index;
  state_.page_addresses = tab.page_addresses;
  selected_scan_row_ = tab.selected_row;
  prev_scan_ = tab.prev;
  has_prev_scan_ = tab.has_prev;
  scan_scroll_offset_ = 0;
}

void CeLayoutWindow::SortScanAddressesIfNeeded(std::vector<uint64_t>* addresses) const {
  (void)addresses;
}

uint64_t CeLayoutWindow::ParseAddressText(const std::wstring& text, bool* ok) const {
  if (ok) *ok = false;
  if (text.empty()) {
    if (ok) *ok = true;
    return 0;
  }
  wchar_t* endptr = nullptr;
  uint64_t value = std::wcstoull(text.c_str(), &endptr, 0);
  if (endptr == text.c_str()) {
    return 0;
  }
  if (ok) *ok = true;
  return value;
}

bool CeLayoutWindow::LoadSettingsFromFile() {
  CreateDirectoryW(L"settings", nullptr);
  std::ifstream file("settings\\windows_client_ng.ini", std::ios::in);
  if (!file.is_open()) {
    return false;
  }
  bool has_auto_refresh = false;
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[0] == '\xEF') {
      if (line.size() >= 3 &&
          static_cast<unsigned char>(line[0]) == 0xEF &&
          static_cast<unsigned char>(line[1]) == 0xBB &&
          static_cast<unsigned char>(line[2]) == 0xBF) {
        line.erase(0, 3);
      }
    }
    std::string trimmed = TrimAscii(line);
    if (trimmed.empty()) {
      continue;
    }
    if (trimmed[0] == '#' || trimmed[0] == ';') {
      continue;
    }
    const size_t pos = trimmed.find('=');
    if (pos == std::string::npos) {
      continue;
    }
    std::string key = ToLowerAscii(TrimAscii(trimmed.substr(0, pos)));
    std::string value = TrimAscii(trimmed.substr(pos + 1));
    if (key == "host") {
      if (!value.empty()) {
        state_.host = value;
      }
    } else if (key == "port") {
      int64_t v = 0;
      if (ParseInt64(value, &v) && v > 0 && v <= 65535) {
        state_.port = static_cast<uint16_t>(v);
      }
    } else if (key == "scan_type") {
      state_.scan_value_type = ParseValueType(value);
    } else if (key == "scan_hex") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_value_hex = v;
      }
    } else if (key == "scan_use_pvm") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_use_pvm = v;
      }
    } else if (key == "scan_fast") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_fast = v;
      }
    } else if (key == "scan_copy_on_write") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_copy_on_write = v;
      }
    } else if (key == "scan_writable") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_writable = v;
      }
    } else if (key == "scan_executable") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_executable = v;
      }
    } else if (key == "scan_private") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_private = v;
      }
    } else if (key == "scan_image") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_image = v;
      }
    } else if (key == "scan_mapped") {
      bool v = false;
      if (ParseBool(value, &v)) {
        state_.scan_mapped = v;
      }
    } else if (key == "scan_region_gg") {
      int64_t v = 0;
      if (ParseInt64(value, &v) && v >= 0 && v <= 31) {
        scan_region_gg_code_ = static_cast<uint8_t>(v);
      }
    } else if (key == "ui_scan_active_only") {
      bool v = false;
      if (ParseBool(value, &v)) {
        ui_scan_active_only_ = v;
      }
    } else if (key == "ui_scan_fast_value") {
      int64_t v = 0;
      if (ParseInt64(value, &v) && v > 0 && v <= 1024) {
        ui_scan_fast_value_ = static_cast<int>(v);
      }
    } else if (key == "ui_scan_fast_mode") {
      int64_t v = 0;
      if (ParseInt64(value, &v)) {
        ui_scan_fast_mode_ = v == 0 ? 0 : 1;
      }
    } else if (key == "address_auto_refresh") {
      bool v = false;
      if (ParseBool(value, &v)) {
        address_auto_refresh_ = v;
        has_auto_refresh = true;
      }
    } else if (key == "address_refresh_ms") {
      int64_t v = 0;
      if (ParseInt64(value, &v)) {
        address_refresh_interval_ms_ = static_cast<int>(v);
      }
    } else if (key == "address_freeze_enable") {
      bool v = false;
      if (ParseBool(value, &v)) {
        address_freeze_enabled_ = v;
      }
    } else if (key == "address_freeze_ms") {
      int64_t v = 0;
      if (ParseInt64(value, &v)) {
        address_freeze_interval_ms_ = static_cast<int>(v);
      }
    } else if (key == "address_auto_add") {
      bool v = false;
      if (ParseBool(value, &v)) {
        address_auto_add_ = v;
      }
    } else if (key == "adb_path") {
      adb_path_ = value;
    } else if (key == "auto_bootstrap_android" || key == "auto_connect") {
      bool v = false;
      if (ParseBool(value, &v)) {
        auto_bootstrap_android_ = v;
      }
    }
  }

  if (!has_auto_refresh) {
    address_auto_refresh_ = address_refresh_interval_ms_ > 0;
  }

  if (!address_auto_refresh_) {
    address_refresh_interval_ms_ = 0;
  } else {
    if (address_refresh_interval_ms_ < 50) {
      address_refresh_interval_ms_ = 50;
    }
    if (address_refresh_interval_ms_ > 10000) {
      address_refresh_interval_ms_ = 10000;
    }
  }
  if (address_freeze_interval_ms_ < 20) {
    address_freeze_interval_ms_ = 20;
  }
  if (address_freeze_interval_ms_ > 5000) {
    address_freeze_interval_ms_ = 5000;
  }
  address_use_pvm_ = state_.scan_use_pvm;
  return true;
}

void CeLayoutWindow::SaveSettingsToFile() const {
  CreateDirectoryW(L"settings", nullptr);
  std::ofstream file("settings\\windows_client_ng.ini", std::ios::out | std::ios::trunc);
  if (!file.is_open()) {
    return;
  }
  file << "host=" << state_.host << "\n";
  file << "port=" << state_.port << "\n";
  file << "scan_type=" << ValueTypeToString(state_.scan_value_type) << "\n";
  file << "scan_hex=" << (state_.scan_value_hex ? 1 : 0) << "\n";
  file << "scan_use_pvm=" << (state_.scan_use_pvm ? 1 : 0) << "\n";
  file << "scan_fast=" << (state_.scan_fast ? 1 : 0) << "\n";
  file << "scan_copy_on_write=" << (state_.scan_copy_on_write ? 1 : 0) << "\n";
  file << "scan_writable=" << (state_.scan_writable ? 1 : 0) << "\n";
  file << "scan_executable=" << (state_.scan_executable ? 1 : 0) << "\n";
  file << "scan_private=" << (state_.scan_private ? 1 : 0) << "\n";
  file << "scan_image=" << (state_.scan_image ? 1 : 0) << "\n";
  file << "scan_mapped=" << (state_.scan_mapped ? 1 : 0) << "\n";
  file << "scan_region_gg=" << static_cast<unsigned>(scan_region_gg_code_) << "\n";
  file << "ui_scan_active_only=" << (ui_scan_active_only_ ? 1 : 0) << "\n";
  file << "ui_scan_fast_value=" << ui_scan_fast_value_ << "\n";
  file << "ui_scan_fast_mode=" << ui_scan_fast_mode_ << "\n";
  file << "address_auto_refresh=" << (address_auto_refresh_ ? 1 : 0) << "\n";
  file << "address_refresh_ms=" << address_refresh_interval_ms_ << "\n";
  file << "address_freeze_enable=" << (address_freeze_enabled_ ? 1 : 0) << "\n";
  file << "address_freeze_ms=" << address_freeze_interval_ms_ << "\n";
  file << "address_auto_add=" << (address_auto_add_ ? 1 : 0) << "\n";
  file << "auto_bootstrap_android=" << (auto_bootstrap_android_ ? 1 : 0) << "\n";
  file << "adb_path=" << adb_path_ << "\n";
}

void CeLayoutWindow::ApplySettingsSnapshot(const SettingsSnapshot& snapshot) {
  state_.host = WideToUtf8(snapshot.host);
  state_.port = snapshot.port;
  state_.scan_value_type = snapshot.scan_type;
  state_.scan_value_hex = snapshot.scan_hex;
  state_.scan_use_pvm = snapshot.scan_use_pvm;
  state_.scan_writable = snapshot.scan_writable;
  state_.scan_executable = snapshot.scan_exec;
  state_.scan_private = snapshot.scan_private;
  state_.scan_image = snapshot.scan_image;
  state_.scan_mapped = snapshot.scan_mapped;

  if (snapshot.scan_strict) {
    state_.scan_fast = true;
    state_.scan_copy_on_write = true;
  } else {
    state_.scan_copy_on_write = false;
  }

  address_auto_refresh_ = snapshot.address_auto_refresh;
  address_freeze_enabled_ = snapshot.address_freeze_enable;
  address_auto_add_ = snapshot.address_auto_add;
  address_use_pvm_ = snapshot.scan_use_pvm;
  address_refresh_interval_ms_ = snapshot.address_refresh_ms;
  address_freeze_interval_ms_ = snapshot.address_freeze_ms;

  if (!address_auto_refresh_) {
    address_refresh_interval_ms_ = 0;
  } else {
    if (address_refresh_interval_ms_ < 50) {
      address_refresh_interval_ms_ = 50;
    }
    if (address_refresh_interval_ms_ > 10000) {
      address_refresh_interval_ms_ = 10000;
    }
  }
  if (address_freeze_interval_ms_ < 20) {
    address_freeze_interval_ms_ = 20;
  }
  if (address_freeze_interval_ms_ > 5000) {
    address_freeze_interval_ms_ = 5000;
  }

  SyncControlsFromState();
  SaveSettingsToFile();
  Invalidate();
}

size_t CeLayoutWindow::ValueTypeSize(protocol::ValueType type) const {
  switch (type) {
    case protocol::ValueType::U8:
    case protocol::ValueType::STRING:
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
      return 1;
    case protocol::ValueType::U16:
      return 2;
    case protocol::ValueType::U32:
    case protocol::ValueType::S32:
    case protocol::ValueType::FLOAT:
      return 4;
    case protocol::ValueType::U64:
    case protocol::ValueType::S64:
    case protocol::ValueType::DOUBLE:
    case protocol::ValueType::ALL:
      return 8;
    default:
      return 4;
  }
}

std::wstring CeLayoutWindow::FormatValueText(protocol::ValueType type,
                                              const uint8_t* data,
                                              size_t size,
                                              bool value_hex,
                                              bool value_signed) const {
  wchar_t buf[128] = {0};
  uint64_t raw = 0;
  const size_t n = std::min<size_t>(size, 8);
  for (size_t i = 0; i < n; ++i) {
    raw |= static_cast<uint64_t>(data[i]) << (i * 8);
  }

  switch (type) {
    case protocol::ValueType::U8:
    case protocol::ValueType::U16:
    case protocol::ValueType::U32:
    case protocol::ValueType::U64: {
      if (value_hex) {
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(raw));
        return buf;
      }
      if (value_signed) {
        int64_t signed_value = 0;
        if (type == protocol::ValueType::U8) {
          int8_t v = 0;
          std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
          signed_value = v;
        } else if (type == protocol::ValueType::U16) {
          int16_t v = 0;
          std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
          signed_value = v;
        } else if (type == protocol::ValueType::U32) {
          int32_t v = 0;
          std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
          signed_value = v;
        } else {
          int64_t v = 0;
          std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
          signed_value = v;
        }
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%lld", static_cast<long long>(signed_value));
        return buf;
      }
      std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%llu", static_cast<unsigned long long>(raw));
      return buf;
    }
    case protocol::ValueType::S32: {
      int32_t v = 0;
      std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
      if (value_hex) {
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"0x%X", static_cast<uint32_t>(v));
      } else {
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%d", v);
      }
      return buf;
    }
    case protocol::ValueType::S64: {
      int64_t v = 0;
      std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
      if (value_hex) {
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(v));
      } else {
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%lld", static_cast<long long>(v));
      }
      return buf;
    }
    case protocol::ValueType::FLOAT: {
      float v = 0.0f;
      std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
      std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%.6f", v);
      return buf;
    }
    case protocol::ValueType::DOUBLE: {
      double v = 0.0;
      std::memcpy(&v, data, std::min<size_t>(size, sizeof(v)));
      std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%.6f", v);
      return buf;
    }
    case protocol::ValueType::STRING: {
      std::wstring out;
      out.reserve(size);
      for (size_t i = 0; i < size; ++i) {
        const wchar_t ch = static_cast<wchar_t>(data[i]);
        out.push_back((ch >= 32 && ch < 127) ? ch : L'.');
      }
      return out.empty() ? L"-" : out;
    }
    case protocol::ValueType::AOB:
    case protocol::ValueType::BINARY:
    case protocol::ValueType::ALL: {
      std::wstring out;
      for (size_t i = 0; i < size; ++i) {
        wchar_t byte_buf[8] = {0};
        std::swprintf(byte_buf, std::size(byte_buf), L"%02X", static_cast<unsigned>(data[i]));
        if (!out.empty()) {
          out.push_back(L' ');
        }
        out.append(byte_buf);
      }
      return out.empty() ? L"-" : out;
    }
    default:
      break;
  }
  return L"-";
}

bool CeLayoutWindow::ResolveEntryAddress(const app::AddressEntry& entry,
                                         uint64_t* out_addr,
                                         std::string* out_error) {
  if (!service_.IsConnected() || state_.pid == 0) {
    if (out_error) {
      *out_error = "未连接";
    }
    return false;
  }
  uint64_t addr = entry.addr;
  if (entry.is_pointer) {
    const size_t steps = entry.offsets.empty() ? 1 : entry.offsets.size();
    for (size_t i = 0; i < steps; ++i) {
      const size_t ptr_size = state_.pointer_size == 0 ? sizeof(uint64_t) : state_.pointer_size;
      std::vector<uint8_t> data;
      std::string error;
      if (!service_.ReadMemory(addr, static_cast<uint32_t>(ptr_size), address_use_pvm_, &data, &error)) {
        if (out_error) {
          *out_error = error;
        }
        return false;
      }
      uint64_t ptr_value = 0;
      for (size_t b = 0; b < std::min<size_t>(ptr_size, data.size()); ++b) {
        ptr_value |= static_cast<uint64_t>(data[b]) << (b * 8);
      }
      const int64_t offset = entry.offsets.empty() ? 0 : entry.offsets[i];
      addr = static_cast<uint64_t>(static_cast<int64_t>(ptr_value) + offset);
    }
  }
  if (out_addr) {
    *out_addr = addr;
  }
  return true;
}

void CeLayoutWindow::RefreshAddressListValues(bool force) {
  if (!force && !address_auto_refresh_) {
    return;
  }
  if (!service_.IsConnected() || state_.pid == 0) {
    UpdateStatus(L"未连接");
    return;
  }
  if (state_.address_entries.empty()) {
    return;
  }
  std::string error;
  bool updated = false;
  for (auto& entry : state_.address_entries) {
    if (!force && !entry.active) {
      continue;
    }
    uint64_t addr = 0;
    if (!ResolveEntryAddress(entry, &addr, &error)) {
      continue;
    }
    const size_t size = ValueTypeSize(entry.type);
    std::vector<uint8_t> data;
    if (!service_.ReadMemory(addr, static_cast<uint32_t>(size), address_use_pvm_, &data, &error)) {
      continue;
    }
    entry.last_read_bytes = data;
    entry.value = FormatValueText(entry.type, data.data(), data.size(), entry.value_hex, entry.value_signed);
    updated = true;
    if (entry.frozen && entry.freeze_bytes.empty()) {
      entry.freeze_bytes = data;
    }
  }
  if (updated) {
    UpdateStatus(L"地址列表已刷新");
    Invalidate();
  }
}

void CeLayoutWindow::TickAddressList() {
  const uint64_t now_ms = NowMs();
  const int refresh_interval = address_refresh_interval_ms_;
  const int freeze_interval = address_freeze_interval_ms_;
  if (address_auto_refresh_ && !state_.address_entries.empty()) {
    if (now_ms - address_last_refresh_ms_ >= static_cast<uint64_t>(std::max(1, refresh_interval))) {
      RefreshAddressListValues(false);
      address_last_refresh_ms_ = now_ms;
    }
  }
  if (address_freeze_enabled_ && !state_.address_entries.empty() && service_.IsConnected() && state_.pid != 0) {
    if (now_ms - address_last_freeze_ms_ >= static_cast<uint64_t>(std::max(1, freeze_interval))) {
      bool has_freeze = false;
      for (auto& entry : state_.address_entries) {
        if (!entry.frozen || !entry.active) {
          continue;
        }
        if (entry.freeze_bytes.empty()) {
          if (!entry.last_read_bytes.empty()) {
            entry.freeze_bytes = entry.last_read_bytes;
          } else {
            continue;
          }
        }
        uint64_t addr = 0;
        std::string error;
        if (!ResolveEntryAddress(entry, &addr, &error)) {
          continue;
        }
        has_freeze = true;
        service_.WriteMemory(addr, entry.freeze_bytes, &error);
      }
      if (has_freeze) {
        address_last_freeze_ms_ = now_ms;
      }
    }
  }
}

uint64_t CeLayoutWindow::NowMs() const {
  return static_cast<uint64_t>(GetTickCount64());
}

bool CeLayoutWindow::ReadScanControls(uint64_t* start, uint64_t* end) {
  SyncStateFromControls();

  bool start_ok = false;
  bool end_ok = false;
  uint64_t s = ParseAddressText(Utf8ToWide(state_.scan_start_text), &start_ok);
  uint64_t e = ParseAddressText(Utf8ToWide(state_.scan_end_text), &end_ok);
  if (!start_ok || !end_ok) {
    UpdateStatus(L"地址范围格式错误");
    return false;
  }
  if (start) *start = s;
  if (end) *end = e;
  return true;
}

void CeLayoutWindow::ApplyScanResult(uint64_t total,
                                     const std::vector<uint64_t>& addresses,
                                     const std::wstring& ok_status) {
  std::vector<uint64_t> sorted = addresses;
  SortScanAddressesIfNeeded(&sorted);
  prev_scan_.match_total = state_.match_total;
  prev_scan_.page_index = state_.page_index;
  prev_scan_.page_addresses = state_.page_addresses;
  prev_scan_.selected_row = selected_scan_row_;
  has_prev_scan_ = !prev_scan_.page_addresses.empty() || prev_scan_.match_total != 0;

  state_.match_total = total;
  state_.page_addresses = sorted;
  selected_scan_row_ = state_.page_addresses.empty() ? -1 : 0;
  scan_scroll_offset_ = 0;
  UpdateStatus(ok_status);
  SaveCurrentTabState();

  if (address_auto_add_ && selected_scan_row_ >= 0 &&
      selected_scan_row_ < static_cast<int>(state_.page_addresses.size())) {
    const uint64_t addr = state_.page_addresses[static_cast<size_t>(selected_scan_row_)];
    app::AddressEntry entry{};
    entry.active = true;
    entry.desc = L"扫描结果";
    entry.addr = addr;
    entry.type = NormalizeEntryValueType(state_.scan_value_type);
    entry.value = L"-";
    entry.value_hex = state_.scan_value_hex;
    entry.value_signed = false;
    entry.is_pointer = false;
    entry.frozen = false;
    bool exists = false;
    for (const auto& existing : state_.address_entries) {
      if (SameEntry(existing, entry)) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      state_.address_entries.push_back(std::move(entry));
      RefreshAddressListValues(true);
      address_last_refresh_ms_ = NowMs();
    }
  }
}

void CeLayoutWindow::HandleButton(ButtonId id) {
  switch (id) {
    case ButtonId::SelectProcess:
      ShowProcessPopup();
      break;
    case ButtonId::OpenFile:
      ShowProcessPopup();
      break;
    case ButtonId::SaveFile:
      HandleButton(ButtonId::ToggleConnect);
      break;
    case ButtonId::ToggleConnect:
      if (service_.IsConnected()) {
        service_.Disconnect();
        state_.connected = false;
        state_.pid = 0;
        state_.match_total = 0;
        state_.page_addresses.clear();
        state_.process_caption = L"未选择进程";
        backend_scan_tab_ = -1;
        for (auto& tab : scan_tabs_) {
          tab = {};
        }
        has_prev_scan_ = false;
        prev_scan_ = {};
        selected_scan_row_ = -1;
        scan_scroll_offset_ = 0;
        UpdateStatus(L"连接已断开");
      } else {
        EnsureConnected();
      }
      break;
    case ButtonId::FirstScan: {
      if (!EnsureConnected()) break;
      if (state_.pid == 0) {
        UpdateStatus(L"请先选择并附加进程");
        break;
      }
      if (state_.scan_condition == protocol::ComparisonType::CHANGED ||
          state_.scan_condition == protocol::ComparisonType::UNCHANGED) {
        UpdateStatus(L"首次扫描不支持“已改变/未改变”，请先做一次基线扫描");
        break;
      }
      uint64_t start = 0;
      uint64_t end = 0;
      if (!ReadScanControls(&start, &end)) break;
      protocol::ComparisonType comparison = state_.scan_condition;
      std::string scan_value = state_.scan_value_text;
      std::wstring req_error;
      if (!BuildScanRequest(&comparison, &scan_value, &req_error)) {
        UpdateStatus(req_error);
        break;
      }
      uint16_t flags = BuildScanFlags();
      if (state_.page_size == 0) {
        state_.page_size = 128u;
      }
      std::string error;
      uint64_t total = 0;
      std::vector<uint64_t> addresses;
      if (!service_.ScanFirst(state_.scan_value_type,
                              comparison,
                              scan_value,
                              state_.scan_value_hex,
                              flags,
                              start,
                              end,
                              &total,
                              &addresses,
                              &error)) {
        UpdateStatus(Utf8ToWide(error));
        break;
      }
      backend_scan_tab_ = scan_tab_;
      state_.page_index = 0;
      ApplyScanResult(total, addresses, L"首次扫描完成");
      break;
    }
    case ButtonId::NextScan: {
      if (!EnsureConnected()) break;
      if (state_.pid == 0) {
        UpdateStatus(L"请先选择并附加进程");
        break;
      }
      if (backend_scan_tab_ != scan_tab_) {
        UpdateStatus(L"该扫描标签尚未建立独立扫描上下文，请先执行“首次扫描”");
        break;
      }
      uint64_t start = 0;
      uint64_t end = 0;
      if (!ReadScanControls(&start, &end)) break;
      protocol::ComparisonType comparison = state_.scan_condition;
      std::string scan_value = state_.scan_value_text;
      std::wstring req_error;
      if (!BuildScanRequest(&comparison, &scan_value, &req_error)) {
        UpdateStatus(req_error);
        break;
      }
      uint16_t flags = BuildScanFlags();
      std::string error;
      uint64_t total = 0;
      std::vector<uint64_t> addresses;
      if (!service_.ScanNext(state_.scan_value_type,
                             comparison,
                             scan_value,
                             state_.scan_value_hex,
                             flags,
                             start,
                             end,
                             &total,
                             &addresses,
                             &error)) {
        UpdateStatus(Utf8ToWide(error));
        break;
      }
      state_.page_index = 0;
      ApplyScanResult(total, addresses, L"再次扫描完成");
      break;
    }
    case ButtonId::UndoScan:
      if (!has_prev_scan_) {
        UpdateStatus(L"没有可撤销的扫描");
        break;
      }
      {
        ScanSnapshot current{};
        current.match_total = state_.match_total;
        current.page_index = state_.page_index;
        current.page_addresses = state_.page_addresses;
        current.selected_row = selected_scan_row_;

        state_.match_total = prev_scan_.match_total;
        state_.page_index = prev_scan_.page_index;
        state_.page_addresses = prev_scan_.page_addresses;
        selected_scan_row_ = prev_scan_.selected_row;

        prev_scan_ = std::move(current);
        has_prev_scan_ = true;
        scan_scroll_offset_ = 0;
        SaveCurrentTabState();
        UpdateStatus(L"已撤销到上一结果");
      }
      break;
    case ButtonId::PrevPage: {
      if (!EnsureConnected()) break;
      if (backend_scan_tab_ != scan_tab_) {
        UpdateStatus(L"该扫描标签尚未建立独立扫描上下文，请先执行“首次扫描”");
        break;
      }
      if (state_.page_index == 0) {
        UpdateStatus(L"已经是第一页");
        break;
      }
      state_.page_index--;
      std::string error;
      uint64_t total = 0;
      std::vector<uint64_t> addresses;
      if (!service_.ScanPage(state_.page_index, state_.page_size, &total, &addresses, &error)) {
        UpdateStatus(Utf8ToWide(error));
        break;
      }
      ApplyScanResult(total, addresses, L"已切换到上一页");
      break;
    }
    case ButtonId::NextPage: {
      if (!EnsureConnected()) break;
      if (backend_scan_tab_ != scan_tab_) {
        UpdateStatus(L"该扫描标签尚未建立独立扫描上下文，请先执行“首次扫描”");
        break;
      }
      if (state_.match_total == 0) {
        UpdateStatus(L"没有可翻页的结果");
        break;
      }
      const uint64_t page_total = state_.page_size == 0 ? 0 : (state_.match_total + state_.page_size - 1) / state_.page_size;
      if (page_total > 0 && state_.page_index + 1 >= page_total) {
        UpdateStatus(L"已经是最后一页");
        break;
      }
      state_.page_index++;
      std::string error;
      uint64_t total = 0;
      std::vector<uint64_t> addresses;
      if (!service_.ScanPage(state_.page_index, state_.page_size, &total, &addresses, &error)) {
        UpdateStatus(Utf8ToWide(error));
        break;
      }
      ApplyScanResult(total, addresses, L"已切换到下一页");
      break;
    }
    case ButtonId::OpenMemoryView: {
      if (!memory_view_window_.Create(instance_, hwnd_, &service_, &state_)) {
        UpdateStatus(L"Memory View 创建失败");
        break;
      }
      uint64_t preferred = 0;
      if (selected_scan_row_ >= 0 && selected_scan_row_ < static_cast<int>(state_.page_addresses.size())) {
        preferred = state_.page_addresses[static_cast<size_t>(selected_scan_row_)];
      } else if (!state_.page_addresses.empty()) {
        preferred = state_.page_addresses.front();
      }
      memory_view_window_.Show(preferred);
      UpdateStatus(L"Memory View 已打开");
      break;
    }
    case ButtonId::OpenSettings:
    case ButtonId::OpenSettingsSide:
      if (!settings_window_.IsOpen()) {
        settings_window_.Create(instance_, hwnd_);
      } else {
        settings_window_.Show();
      }
      if (settings_window_.IsOpen()) {
        SettingsSnapshot snapshot{};
        snapshot.host = Utf8ToWide(state_.host);
        snapshot.port = state_.port;
        snapshot.pid = state_.pid;
        snapshot.scan_type = state_.scan_value_type;
        snapshot.scan_hex = state_.scan_value_hex;
        snapshot.scan_strict = state_.scan_fast && state_.scan_copy_on_write;
        snapshot.scan_use_pvm = state_.scan_use_pvm;
        snapshot.scan_writable = state_.scan_writable;
        snapshot.scan_exec = state_.scan_executable;
        snapshot.scan_private = state_.scan_private;
        snapshot.scan_image = state_.scan_image;
        snapshot.scan_mapped = state_.scan_mapped;
        snapshot.address_refresh_ms = address_refresh_interval_ms_;
        snapshot.address_freeze_ms = address_freeze_interval_ms_;
        snapshot.address_auto_refresh = address_auto_refresh_;
        snapshot.address_freeze_enable = address_freeze_enabled_;
        snapshot.address_auto_add = address_auto_add_;
        settings_window_.ApplySnapshot(snapshot);
      }
      break;
    case ButtonId::ScanTab1:
      if (scan_tab_ != 0) {
        SaveCurrentTabState();
        LoadTabState(0);
      }
      break;
    case ButtonId::ScanTab2:
      if (scan_tab_ != 1) {
        SaveCurrentTabState();
        LoadTabState(1);
      }
      break;
    case ButtonId::ClearAddressList:
      state_.address_entries.clear();
      address_scroll_offset_ = 0;
      UpdateStatus(L"已清空地址列表");
      break;
    case ButtonId::RefreshAddressList:
      RefreshAddressListValues(true);
      address_last_refresh_ms_ = NowMs();
      break;
    case ButtonId::RefreshValue: {
      if (!EnsureConnected()) break;
      if (backend_scan_tab_ != scan_tab_) {
        UpdateStatus(L"该扫描标签尚未建立独立扫描上下文，请先执行“首次扫描”");
        break;
      }
      std::string error;
      uint64_t total = 0;
      std::vector<uint64_t> addresses;
      if (!service_.ScanPage(state_.page_index, state_.page_size, &total, &addresses, &error)) {
        UpdateStatus(Utf8ToWide(error));
        break;
      }
      ApplyScanResult(total, addresses, L"结果页已更新");
      break;
    }
    case ButtonId::OpenModuleRange:
      OpenModuleRangePopup();
      break;
    case ButtonId::AttachFirstProcess:
      if (RefreshProcesses() && !state_.processes.empty()) {
        AttachProcessByIndex(0);
      }
      break;
    case ButtonId::AddSelectedAddress: {
      const size_t row = selected_scan_row_ < 0 ? std::numeric_limits<size_t>::max()
                                                 : static_cast<size_t>(selected_scan_row_);
      AddScanAddressToList(row, false);
      break;
    }
    case ButtonId::AddManualAddress: {
      AddAddressDialogPreset preset{};
      preset.type = NormalizeEntryValueType(state_.scan_value_type);
      AddAddressDialogResult result{};
      if (!ShowAddAddressDialog(hwnd_, preset, &result)) {
        break;
      }
      app::AddressEntry entry{};
      entry.active = true;
      entry.desc = result.description.empty() ? L"手动添加" : result.description;
      entry.addr = result.address;
      entry.type = result.type;
      entry.value = L"-";
      entry.value_hex = result.value_hex;
      entry.value_signed = result.value_signed;
      entry.is_pointer = result.is_pointer;
      entry.frozen = false;
      entry.offsets = std::move(result.offsets);
      bool exists = false;
      for (const auto& existing : state_.address_entries) {
        if (SameEntry(existing, entry)) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        state_.address_entries.push_back(std::move(entry));
        RefreshAddressListValues(true);
        address_last_refresh_ms_ = NowMs();
      }
      UpdateStatus(exists ? L"地址已存在于地址列表" : L"已手动添加地址");
      break;
    }
    case ButtonId::None:
    default:
      break;
  }
  Invalidate();
}

void CeLayoutWindow::EditAddressValue(size_t row) {
  if (row >= state_.address_entries.size()) {
    return;
  }
  if (!service_.IsConnected() || state_.pid == 0) {
    UpdateStatus(L"未连接");
    return;
  }
  auto& entry = state_.address_entries[row];
  uint64_t addr = 0;
  std::string error;
  if (!ResolveEntryAddress(entry, &addr, &error)) {
    UpdateStatus(Utf8ToWide(error));
    return;
  }

  const wchar_t* title = L"修改数值";
  const wchar_t* label = entry.value_hex ? L"输入数值(HEX)" : L"输入数值";
  std::wstring preset = entry.value == L"-" ? L"" : entry.value;
  std::wstring input;
  if (!PromptValueDialog(hwnd_, title, label, preset.c_str(), &input)) {
    return;
  }
  std::vector<uint8_t> bytes;
  if (!BuildValueBytesFromText(entry.type, input, entry.value_hex, &bytes)) {
    UpdateStatus(L"数值格式错误");
    return;
  }
  if (!service_.WriteMemory(addr, bytes, &error)) {
    UpdateStatus(Utf8ToWide(error));
    return;
  }
  entry.last_read_bytes = bytes;
  entry.value = FormatValueText(entry.type, bytes.data(), bytes.size(), entry.value_hex, entry.value_signed);
  if (entry.frozen) {
    entry.freeze_bytes = bytes;
  }
  UpdateStatus(L"写入成功");
  Invalidate();
}

bool CeLayoutWindow::AddScanAddressToList(size_t scan_row, bool open_editor) {
  if (scan_row >= state_.page_addresses.size()) {
    UpdateStatus(L"请先在结果列表选择地址");
    return false;
  }
  const uint64_t addr = state_.page_addresses[scan_row];
  app::AddressEntry entry{};
  entry.active = true;
  entry.desc = L"扫描结果";
  entry.addr = addr;
  entry.type = NormalizeEntryValueType(state_.scan_value_type);
  entry.value = L"-";
  entry.value_hex = state_.scan_value_hex;
  entry.value_signed = false;
  entry.is_pointer = false;
  entry.frozen = false;

  bool exists = false;
  size_t target_index = std::numeric_limits<size_t>::max();
  for (size_t i = 0; i < state_.address_entries.size(); ++i) {
    if (SameEntry(state_.address_entries[i], entry)) {
      exists = true;
      target_index = i;
      break;
    }
  }
  if (!exists) {
    state_.address_entries.push_back(entry);
    target_index = state_.address_entries.size() - 1;
    RefreshAddressListValues(true);
    address_last_refresh_ms_ = NowMs();
  }
  if (target_index != std::numeric_limits<size_t>::max()) {
    selected_address_row_ = static_cast<int>(target_index);
  }
  UpdateStatus(exists ? L"地址已存在于地址列表" : L"已添加到地址列表");
  if (open_editor && target_index != std::numeric_limits<size_t>::max()) {
    EditAddressValue(target_index);
  }
  Invalidate();
  return true;
}

bool CeLayoutWindow::CopyTextToClipboard(const std::wstring& text) const {
  if (!hwnd_) {
    return false;
  }
  if (!OpenClipboard(hwnd_)) {
    return false;
  }
  bool ok = false;
  do {
    if (!EmptyClipboard()) {
      break;
    }
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!mem) {
      break;
    }
    void* ptr = GlobalLock(mem);
    if (!ptr) {
      GlobalFree(mem);
      break;
    }
    std::memcpy(ptr, text.c_str(), bytes);
    GlobalUnlock(mem);
    if (!SetClipboardData(CF_UNICODETEXT, mem)) {
      GlobalFree(mem);
      break;
    }
    ok = true;
  } while (false);
  CloseClipboard();
  return ok;
}

void CeLayoutWindow::UpdateStatus(const std::wstring& text) {
  state_.status = text;
  state_.connected = service_.IsConnected();
}

void CeLayoutWindow::Invalidate() {
  if (hwnd_) {
    InvalidateRect(hwnd_, nullptr, FALSE);
  }
}

std::wstring CeLayoutWindow::Utf8ToWide(const std::string& text) const {
  if (text.empty()) {
    return L"";
  }
  int chars = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  if (chars <= 0) {
    return L"";
  }
  std::wstring out(static_cast<size_t>(chars), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), chars);
  return out;
}

std::string CeLayoutWindow::WideToUtf8(const std::wstring& text) const {
  if (text.empty()) {
    return "";
  }
  int chars = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
  if (chars <= 0) {
    return "";
  }
  std::string out(static_cast<size_t>(chars), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), chars, nullptr, nullptr);
  return out;
}

std::wstring CeLayoutWindow::BuildProcessCaption(uint32_t pid, const std::wstring& name) const {
  wchar_t line[384] = {0};
  std::swprintf(line, sizeof(line) / sizeof(wchar_t), L"PID %u - %ls", pid, name.c_str());
  return std::wstring(line);
}

LRESULT CALLBACK CeLayoutWindow::StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  CeLayoutWindow* self = reinterpret_cast<CeLayoutWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    self = reinterpret_cast<CeLayoutWindow*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    if (self) {
      self->hwnd_ = hwnd;
    }
  }
  if (self) {
    return self->WndProc(msg, wparam, lparam);
  }
  return DefWindowProcW(hwnd, msg, wparam, lparam);
}

LRESULT CeLayoutWindow::WndProc(UINT msg, WPARAM wparam, LPARAM lparam) {
  switch (msg) {
    case WM_SIZE: {
      if (render_target_) {
        const UINT width = LOWORD(lparam);
        const UINT height = HIWORD(lparam);
        render_target_->Resize(D2D1::SizeU(width, height));
      }
      LayoutNativeControls();
      Invalidate();
      return 0;
    }
    case WM_DPICHANGED: {
      const UINT new_dpi = LOWORD(wparam);
      dpi_ = new_dpi == 0 ? 96 : new_dpi;
      dpi_scale_ = static_cast<float>(dpi_) / 96.0f;
      if (render_target_) {
        render_target_->SetDpi(static_cast<float>(dpi_), static_cast<float>(dpi_));
      }
      if (ctrl_font_) {
        DeleteObject(ctrl_font_);
        ctrl_font_ = nullptr;
      }
      LOGFONTW lf{};
      lf.lfHeight = -MulDiv(12, static_cast<int>(dpi_), 96);
      lf.lfWeight = FW_NORMAL;
      wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
      ctrl_font_ = CreateFontIndirectW(&lf);
      ApplyControlFont();
      ApplyMenuIcons(GetMenu(hwnd_));
      LayoutNativeControls();
      if (lparam) {
        const RECT* suggested = reinterpret_cast<const RECT*>(lparam);
        SetWindowPos(hwnd_,
                     nullptr,
                     suggested->left,
                     suggested->top,
                     suggested->right - suggested->left,
                     suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
      }
      Invalidate();
      return 0;
    }
    case WM_TIMER: {
      if (wparam == kTimerAddressList) {
        TickAddressList();
        return 0;
      }
      break;
    }
    case kMsgAutoBootstrapDone: {
      std::unique_ptr<AutoBootstrapResult> result(reinterpret_cast<AutoBootstrapResult*>(lparam));
      if (!result) {
        return 0;
      }
      if (!result->status.empty()) {
        UpdateStatus(result->status);
      }
      if (!result->device_online) {
        return 0;
      }
      if (EnsureConnected()) {
        if (result->push_ok && result->forward_ok) {
          UpdateStatus(L"启动检查: 设备在线，Android 端已自动推送并连接");
        } else if (result->forward_ok) {
          UpdateStatus(L"启动检查: 已自动连接（推送步骤被跳过或失败）");
        } else if (!result->push_attempted && !result->forward_attempted) {
          UpdateStatus(L"启动检查: 设备在线，未找到运行脚本，已直接连接");
        } else {
          UpdateStatus(L"启动检查: 已连接，ADB 转发步骤可能失败");
        }
      } else if (result->push_ok || result->forward_ok) {
        UpdateStatus(L"启动检查: 推送/转发已执行，但连接失败");
      } else if (!result->push_attempted && !result->forward_attempted) {
        UpdateStatus(L"启动检查: 设备在线，但运行脚本不可用");
      } else {
        UpdateStatus(L"启动检查: 设备在线，但自动推送未执行");
      }
      return 0;
    }
    case WM_MOUSEWHEEL: {
      const int z = GET_WHEEL_DELTA_WPARAM(wparam);
      const int delta_rows = z > 0 ? -3 : 3;
      POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      ScreenToClient(hwnd_, &pt);
      const POINT dip{static_cast<LONG>(std::lround(pt.x / dpi_scale_)),
                      static_cast<LONG>(std::lround(pt.y / dpi_scale_))};
      if (RectContains(scan_rows_rect_, dip) && scan_rows_total_ > scan_rows_visible_) {
        scan_scroll_offset_ = std::clamp(scan_scroll_offset_ + delta_rows,
                                         0,
                                         std::max<int>(0, static_cast<int>(scan_rows_total_) - static_cast<int>(scan_rows_visible_)));
        Invalidate();
        return 0;
      }
      if (RectContains(address_rows_rect_, dip) && address_rows_total_ > address_rows_visible_) {
        address_scroll_offset_ = std::clamp(address_scroll_offset_ + delta_rows,
                                            0,
                                            std::max<int>(0, static_cast<int>(address_rows_total_) - static_cast<int>(address_rows_visible_)));
        Invalidate();
        return 0;
      }
      break;
    }
    case WM_VSCROLL: {
      HWND src = reinterpret_cast<HWND>(lparam);
      if (src != scroll_scan_ && src != scroll_addr_) {
        break;
      }
      SCROLLINFO si{};
      si.cbSize = sizeof(si);
      si.fMask = SIF_ALL;
      GetScrollInfo(src, SB_CTL, &si);
      int pos = si.nPos;
      switch (LOWORD(wparam)) {
        case SB_LINEUP:
          pos -= 1;
          break;
        case SB_LINEDOWN:
          pos += 1;
          break;
        case SB_PAGEUP:
          pos -= static_cast<int>(si.nPage);
          break;
        case SB_PAGEDOWN:
          pos += static_cast<int>(si.nPage);
          break;
        case SB_TOP:
          pos = si.nMin;
          break;
        case SB_BOTTOM:
          pos = si.nMax;
          break;
        case SB_THUMBPOSITION:
        case SB_THUMBTRACK:
          pos = HIWORD(wparam);
          break;
        default:
          break;
      }
      const int max_pos = std::max<int>(si.nMin, si.nMax - static_cast<int>(si.nPage) + 1);
      pos = std::clamp(pos, si.nMin, max_pos);
      si.fMask = SIF_POS;
      si.nPos = pos;
      SetScrollInfo(src, SB_CTL, &si, TRUE);
      if (src == scroll_scan_) {
        scan_scroll_offset_ = pos;
      } else {
        address_scroll_offset_ = pos;
      }
      Invalidate();
      return 0;
    }
    case WM_KEYDOWN: {
      const bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
      if (ctrl && (wparam == 'P' || wparam == 'p')) {
        ShowProcessPopup();
        return 0;
      }
      if (wparam == VK_INSERT) {
        HandleButton(ButtonId::AddSelectedAddress);
        return 0;
      }
      if ((GetKeyState(VK_CONTROL) & 0x8000) != 0 && wparam == VK_RETURN) {
        const size_t before_count = state_.address_entries.size();
        const uint64_t selected_addr =
            (selected_scan_row_ >= 0 && selected_scan_row_ < static_cast<int>(state_.page_addresses.size()))
                ? state_.page_addresses[static_cast<size_t>(selected_scan_row_)]
                : 0;
        HandleButton(ButtonId::AddSelectedAddress);
        if (selected_addr != 0) {
          size_t edit_row = std::numeric_limits<size_t>::max();
          for (size_t i = 0; i < state_.address_entries.size(); ++i) {
            if (state_.address_entries[i].addr == selected_addr) {
              edit_row = i;
              break;
            }
          }
          if (edit_row == std::numeric_limits<size_t>::max() && state_.address_entries.size() > before_count) {
            edit_row = state_.address_entries.size() - 1;
          }
          if (edit_row != std::numeric_limits<size_t>::max()) {
            EditAddressValue(edit_row);
          }
        }
        return 0;
      }
      if (wparam == VK_DELETE && selected_address_row_ >= 0 &&
          selected_address_row_ < static_cast<int>(state_.address_entries.size())) {
        state_.address_entries.erase(state_.address_entries.begin() + selected_address_row_);
        selected_address_row_ = std::min(selected_address_row_, static_cast<int>(state_.address_entries.size()) - 1);
        UpdateStatus(L"已删除地址项");
        Invalidate();
        return 0;
      }
      break;
    }
    case WM_DISPLAYCHANGE:
      Invalidate();
      return 0;
    case WM_MOUSEMOVE: {
      const POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      ButtonId hit = ButtonId::None;
      if (HitTestButton(pt, &hit)) {
        if (hit != hovered_button_) {
          hovered_button_ = hit;
          Invalidate();
        }
      } else if (hovered_button_ != ButtonId::None) {
        hovered_button_ = ButtonId::None;
        Invalidate();
      }
      TRACKMOUSEEVENT tme{};
      tme.cbSize = sizeof(tme);
      tme.dwFlags = TME_LEAVE;
      tme.hwndTrack = hwnd_;
      TrackMouseEvent(&tme);
      return 0;
    }
    case WM_MOUSELEAVE:
      hovered_button_ = ButtonId::None;
      Invalidate();
      return 0;
    case WM_LBUTTONDOWN: {
      const POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      const float dip_x = static_cast<float>(pt.x) / dpi_scale_;
      size_t row = 0;
      if (HitTestScanRow(pt, &row)) {
        selected_scan_row_ = static_cast<int>(row);
        Invalidate();
        return 0;
      }
      if (HitTestAddressRow(pt, &row)) {
        if (row < state_.address_entries.size()) {
          selected_address_row_ = static_cast<int>(row);
          auto& entry = state_.address_entries[row];
          if (dip_x >= address_hit_active_left_ && dip_x <= address_hit_active_right_) {
            entry.active = !entry.active;
            if (!entry.active && entry.frozen) {
              entry.frozen = false;
              entry.freeze_bytes.clear();
            }
            UpdateStatus(entry.active ? L"已激活该地址" : L"已取消激活");
          } else if (dip_x >= address_hit_freeze_left_ && dip_x <= address_hit_freeze_right_) {
            entry.frozen = !entry.frozen;
            if (!entry.frozen) {
              entry.freeze_bytes.clear();
            } else if (!entry.last_read_bytes.empty()) {
              entry.freeze_bytes = entry.last_read_bytes;
            }
            UpdateStatus(entry.frozen ? L"已启用冻结" : L"已取消冻结");
          }
        }
        Invalidate();
        return 0;
      }
      return 0;
    }
    case WM_LBUTTONDBLCLK: {
      const POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      const float dip_x = static_cast<float>(pt.x) / dpi_scale_;
      size_t row = 0;
      if (HitTestScanRow(pt, &row)) {
        selected_scan_row_ = static_cast<int>(row);
        if ((GetKeyState(VK_MENU) & 0x8000) != 0) {
          HandleButton(ButtonId::OpenMemoryView);
        } else {
          HandleButton(ButtonId::AddSelectedAddress);
        }
        return 0;
      }
      if (HitTestAddressRow(pt, &row)) {
        if (row < state_.address_entries.size()) {
          selected_address_row_ = static_cast<int>(row);
          if (dip_x >= address_hit_value_left_) {
            EditAddressValue(row);
          } else {
            memory_view_window_.Show(state_.address_entries[row].addr);
            UpdateStatus(L"Memory View 已打开");
          }
        }
        return 0;
      }
      return 0;
    }
    case WM_LBUTTONUP: {
      const POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      ButtonId hit = ButtonId::None;
      if (HitTestButton(pt, &hit)) {
        if (IsButtonEnabled(hit)) {
          HandleButton(hit);
        }
      }
      return 0;
    }
    case WM_CONTEXTMENU: {
      POINT screen_pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      if (screen_pt.x == -1 && screen_pt.y == -1) {
        GetCursorPos(&screen_pt);
      }
      POINT client_pt = screen_pt;
      ScreenToClient(hwnd_, &client_pt);

      size_t row = 0;
      if (HitTestScanRow(client_pt, &row)) {
        selected_scan_row_ = static_cast<int>(row);
        context_scan_row_ = static_cast<int>(row);
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, kMenuCtxScanAdd, L"添加到地址列表\tInsert");
        AppendMenuW(menu, MF_STRING, kMenuCtxScanBatchAdd, L"批量添加选中项");
        AppendMenuW(menu, MF_STRING, kMenuCtxScanAddEdit, L"添加并编辑值\tCtrl+Enter");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, kMenuCtxScanOpenMemory, L"在 Memory View 打开");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, kMenuCtxScanCopyAddr, L"复制地址");
        AppendMenuW(menu, MF_STRING, kMenuCtxScanCopyAddrValue, L"复制地址+当前值");
        const UINT cmd = TrackPopupMenu(menu,
                                        TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN | TPM_TOPALIGN,
                                        screen_pt.x,
                                        screen_pt.y,
                                        0,
                                        hwnd_,
                                        nullptr);
        DestroyMenu(menu);
        if (cmd != 0) {
          SendMessageW(hwnd_, WM_COMMAND, cmd, 0);
        }
        return 0;
      }
      if (HitTestAddressRow(client_pt, &row)) {
        selected_address_row_ = static_cast<int>(row);
        context_address_row_ = static_cast<int>(row);
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrEditDesc, L"编辑描述");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrEditValue, L"修改数值");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrToggleFreeze, L"冻结/解冻");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrOpenMemory, L"跳转到 Memory View");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrCopyEntry, L"复制完整条目");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrDelete, L"删除选中");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrBatchActivate, L"批量激活");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrBatchFreeze, L"批量冻结");
        AppendMenuW(menu, MF_STRING, kMenuCtxAddrBatchDelete, L"批量删除");
        const UINT cmd = TrackPopupMenu(menu,
                                        TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN | TPM_TOPALIGN,
                                        screen_pt.x,
                                        screen_pt.y,
                                        0,
                                        hwnd_,
                                        nullptr);
        DestroyMenu(menu);
        if (cmd != 0) {
          SendMessageW(hwnd_, WM_COMMAND, cmd, 0);
        }
        return 0;
      }
      break;
    }
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      const UINT notify = HIWORD(wparam);
      if (cmd == kMenuCtxScanAdd || cmd == kMenuCtxScanBatchAdd || cmd == kMenuCtxScanAddEdit ||
          cmd == kMenuCtxScanOpenMemory || cmd == kMenuCtxScanCopyAddr || cmd == kMenuCtxScanCopyAddrValue ||
          cmd == kMenuCtxAddrEditDesc || cmd == kMenuCtxAddrEditValue || cmd == kMenuCtxAddrToggleFreeze ||
          cmd == kMenuCtxAddrOpenMemory || cmd == kMenuCtxAddrCopyEntry || cmd == kMenuCtxAddrDelete ||
          cmd == kMenuCtxAddrBatchActivate || cmd == kMenuCtxAddrBatchFreeze || cmd == kMenuCtxAddrBatchDelete) {
        if (cmd == kMenuCtxScanAdd || cmd == kMenuCtxScanBatchAdd || cmd == kMenuCtxScanAddEdit) {
          const size_t row = context_scan_row_ >= 0 ? static_cast<size_t>(context_scan_row_)
                                                     : (selected_scan_row_ >= 0 ? static_cast<size_t>(selected_scan_row_)
                                                                                : std::numeric_limits<size_t>::max());
          AddScanAddressToList(row, cmd == kMenuCtxScanAddEdit);
          return 0;
        }
        if (cmd == kMenuCtxScanOpenMemory) {
          if (context_scan_row_ >= 0) {
            selected_scan_row_ = context_scan_row_;
          }
          HandleButton(ButtonId::OpenMemoryView);
          return 0;
        }
        if (cmd == kMenuCtxScanCopyAddr || cmd == kMenuCtxScanCopyAddrValue) {
          const size_t row = context_scan_row_ >= 0 ? static_cast<size_t>(context_scan_row_)
                                                     : (selected_scan_row_ >= 0 ? static_cast<size_t>(selected_scan_row_)
                                                                                : std::numeric_limits<size_t>::max());
          if (row < state_.page_addresses.size()) {
            wchar_t addr_buf[64] = {0};
            std::swprintf(addr_buf, std::size(addr_buf), L"0x%llX",
                          static_cast<unsigned long long>(state_.page_addresses[row]));
            std::wstring text = addr_buf;
            if (cmd == kMenuCtxScanCopyAddrValue) {
              text.append(L" = -");
            }
            UpdateStatus(CopyTextToClipboard(text) ? L"已复制到剪贴板" : L"复制失败");
          } else {
            UpdateStatus(L"无有效扫描地址");
          }
          Invalidate();
          return 0;
        }
        const size_t addr_row = context_address_row_ >= 0 ? static_cast<size_t>(context_address_row_)
                                                           : (selected_address_row_ >= 0 ? static_cast<size_t>(selected_address_row_)
                                                                                         : std::numeric_limits<size_t>::max());
        if (cmd == kMenuCtxAddrEditDesc) {
          if (addr_row >= state_.address_entries.size()) {
            UpdateStatus(L"未选择地址项");
            return 0;
          }
          std::wstring input;
          const auto& entry = state_.address_entries[addr_row];
          if (PromptValueDialog(hwnd_, L"编辑描述", L"描述", entry.desc.c_str(), &input)) {
            state_.address_entries[addr_row].desc = TrimWide(input);
            UpdateStatus(L"描述已更新");
            Invalidate();
          }
          return 0;
        }
        if (cmd == kMenuCtxAddrEditValue) {
          if (addr_row < state_.address_entries.size()) {
            EditAddressValue(addr_row);
          } else {
            UpdateStatus(L"未选择地址项");
          }
          return 0;
        }
        if (cmd == kMenuCtxAddrToggleFreeze) {
          if (addr_row < state_.address_entries.size()) {
            auto& entry = state_.address_entries[addr_row];
            entry.frozen = !entry.frozen;
            if (!entry.frozen) {
              entry.freeze_bytes.clear();
            } else if (!entry.last_read_bytes.empty()) {
              entry.freeze_bytes = entry.last_read_bytes;
            }
            UpdateStatus(entry.frozen ? L"已启用冻结" : L"已取消冻结");
            Invalidate();
          } else {
            UpdateStatus(L"未选择地址项");
          }
          return 0;
        }
        if (cmd == kMenuCtxAddrOpenMemory) {
          if (addr_row < state_.address_entries.size()) {
            memory_view_window_.Show(state_.address_entries[addr_row].addr);
            UpdateStatus(L"Memory View 已打开");
          } else {
            UpdateStatus(L"未选择地址项");
          }
          return 0;
        }
        if (cmd == kMenuCtxAddrCopyEntry) {
          if (addr_row < state_.address_entries.size()) {
            const std::wstring text = BuildEntryText(state_.address_entries[addr_row]);
            UpdateStatus(CopyTextToClipboard(text) ? L"已复制完整条目" : L"复制失败");
            Invalidate();
          } else {
            UpdateStatus(L"未选择地址项");
          }
          return 0;
        }
        if (cmd == kMenuCtxAddrDelete) {
          if (addr_row < state_.address_entries.size()) {
            state_.address_entries.erase(state_.address_entries.begin() + static_cast<int>(addr_row));
            selected_address_row_ = std::min(selected_address_row_, static_cast<int>(state_.address_entries.size()) - 1);
            UpdateStatus(L"已删除选中地址");
            Invalidate();
          } else {
            UpdateStatus(L"未选择地址项");
          }
          return 0;
        }
        if (cmd == kMenuCtxAddrBatchActivate) {
          for (auto& entry : state_.address_entries) {
            entry.active = true;
          }
          UpdateStatus(L"批量激活完成");
          Invalidate();
          return 0;
        }
        if (cmd == kMenuCtxAddrBatchFreeze) {
          for (auto& entry : state_.address_entries) {
            entry.frozen = true;
            if (!entry.last_read_bytes.empty()) {
              entry.freeze_bytes = entry.last_read_bytes;
            }
          }
          UpdateStatus(L"批量冻结完成");
          Invalidate();
          return 0;
        }
        if (cmd == kMenuCtxAddrBatchDelete) {
          state_.address_entries.clear();
          selected_address_row_ = -1;
          UpdateStatus(L"批量删除完成");
          Invalidate();
          return 0;
        }
      }
      if (cmd == kSettingsCmdConnect) {
        SettingsSnapshot snapshot{};
        if (settings_window_.ReadSnapshot(&snapshot)) {
          ApplySettingsSnapshot(snapshot);
        }
        EnsureConnected();
        return 0;
      }
      if (cmd == kSettingsCmdDisconnect) {
        if (service_.IsConnected()) {
          service_.Disconnect();
          state_.connected = false;
          state_.pid = 0;
          state_.process_caption = L"未选择进程";
          backend_scan_tab_ = -1;
          for (auto& tab : scan_tabs_) {
            tab = {};
          }
          has_prev_scan_ = false;
          prev_scan_ = {};
          selected_scan_row_ = -1;
          scan_scroll_offset_ = 0;
          modules_cache_.clear();
          modules_pid_ = 0;
          ReloadScanRegionOptions(false);
          UpdateStatus(L"连接已断开");
        }
        return 0;
      }
      if (cmd == kSettingsCmdSelectProcess) {
        ShowProcessPopup();
        return 0;
      }
      if (cmd == kSettingsCmdAttachProcess) {
        SettingsSnapshot snapshot{};
        if (settings_window_.ReadSnapshot(&snapshot)) {
          if (snapshot.pid != 0) {
            std::string error;
            if (service_.Attach(snapshot.pid, &error)) {
              state_.pid = snapshot.pid;
              state_.process_caption = BuildProcessCaption(snapshot.pid, L"");
              state_.match_total = 0;
              state_.page_index = 0;
              state_.page_addresses.clear();
              selected_scan_row_ = -1;
              scan_scroll_offset_ = 0;
              prev_scan_ = {};
              has_prev_scan_ = false;
              backend_scan_tab_ = -1;
              for (auto& tab : scan_tabs_) {
                tab = {};
              }
              uint8_t arch = static_cast<uint8_t>(protocol::RegsArch::UNKNOWN);
              uint8_t ptr_size = 0;
              if (service_.FetchProcInfo(&arch, &ptr_size, nullptr)) {
                state_.arch = arch;
                state_.pointer_size = ptr_size;
              }
              ReloadScanRegionOptions(true);
              ApplySelectedScanRegion(false);
              UpdateStatus(L"附加进程成功");
              if (settings_window_.IsOpen()) {
                SettingsSnapshot sync = snapshot;
                settings_window_.ApplySnapshot(sync);
              }
            } else {
              UpdateStatus(Utf8ToWide(error));
            }
          } else {
            UpdateStatus(L"PID 无效");
          }
        }
        return 0;
      }
      if (cmd == kSettingsCmdChanged) {
        SettingsSnapshot snapshot{};
        if (settings_window_.ReadSnapshot(&snapshot)) {
          ApplySettingsSnapshot(snapshot);
        }
        return 0;
      }
      if (cmd == kMenuFileExit) {
        DestroyWindow(hwnd_);
        return 0;
      }
      if (cmd == kMenuFileOpen) {
        HandleButton(ButtonId::OpenFile);
        return 0;
      }
      if (cmd == kMenuFileSave) {
        HandleButton(ButtonId::SaveFile);
        return 0;
      }
      if (cmd == kMenuViewMemory) {
        HandleButton(ButtonId::OpenMemoryView);
        return 0;
      }
      if (cmd == kMenuViewSettings) {
        HandleButton(ButtonId::OpenSettings);
        return 0;
      }
      if (cmd == kMenuDebugPointerScan) {
        pointer_tools_window_.ShowPointerSearch();
        UpdateStatus(L"已打开指针搜索");
        return 0;
      }
      if (cmd == kMenuDebugPointerCompare) {
        pointer_tools_window_.ShowPointerCompare();
        UpdateStatus(L"已打开指针对比");
        return 0;
      }
      if (cmd == kMenuDebugDataTraverse) {
        pointer_tools_window_.ShowDataTraverse();
        UpdateStatus(L"已打开结构分析");
        return 0;
      }
      if (cmd == kCtrlComboRegion) {
        if (scan_region_reloading_) {
          return 0;
        }
        if (notify == CBN_DROPDOWN) {
          ReloadScanRegionOptions(true);
        } else if (notify == CBN_EDITCHANGE) {
          ReloadScanRegionOptions(false);
          SendMessageW(combo_scan_region_, CB_SHOWDROPDOWN, TRUE, 0);
        } else if (notify == CBN_SELCHANGE || notify == CBN_SELENDOK || notify == CBN_CLOSEUP) {
          ApplySelectedScanRegion(true);
        }
        return 0;
      }
      if (cmd == kCtrlComboType || cmd == kCtrlComboCond || cmd == kCtrlCheckHex ||
          cmd == kCtrlCheckFast || cmd == kCtrlEditFastValue || cmd == kCtrlRadioAlign || cmd == kCtrlRadioLast ||
          cmd == kCtrlCheckWritable || cmd == kCtrlCheckExecutable || cmd == kCtrlCheckCopy || cmd == kCtrlCheckActive ||
          cmd == kCtrlEditScanValue || cmd == kCtrlEditScanStart || cmd == kCtrlEditScanEnd) {
        if (notify == CBN_SELCHANGE || notify == CBN_SELENDOK || notify == BN_CLICKED || notify == EN_CHANGE) {
          SyncStateFromControls();
        }
        return 0;
      }
      return 0;
    }
    case WM_PAINT: {
      PAINTSTRUCT ps{};
      BeginPaint(hwnd_, &ps);
      if (CreateDeviceResources()) {
        Draw();
      } else {
        RECT rc{};
        GetClientRect(hwnd_, &rc);
        FillRect(ps.hdc,
                 &rc,
                 ctrl_bg_brush_ ? ctrl_bg_brush_ : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        SetBkMode(ps.hdc, TRANSPARENT);
        SetTextColor(ps.hdc, RGB(210, 210, 210));
        const wchar_t* text = L"UI 渲染初始化中...";
        TextOutW(ps.hdc, 16, 16, text, static_cast<int>(wcslen(text)));
      }
      EndPaint(hwnd_, &ps);
      return 0;
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORSCROLLBAR: {
      HDC hdc = reinterpret_cast<HDC>(wparam);
      SetTextColor(hdc, RGB(230, 230, 230));
      SetBkColor(hdc, RGB(43, 43, 43));
      return reinterpret_cast<LRESULT>(ctrl_bg_brush_);
    }
    case WM_ERASEBKGND:
      return 1;
    case WM_DESTROY:
      SaveSettingsToFile();
      KillTimer(hwnd_, kTimerAddressList);
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(hwnd_, msg, wparam, lparam);
  }
  return DefWindowProcW(hwnd_, msg, wparam, lparam);
}

}  // namespace r3::windows_client_ng::ui
