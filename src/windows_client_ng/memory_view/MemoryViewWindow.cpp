#include "memory_view/MemoryViewWindow.h"

#include <commctrl.h>
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <unordered_set>
#include <windowsx.h>

#include <capstone/capstone.h>
#include <dwmapi.h>

namespace r3::windows_client_ng::memory_view {

namespace {

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

constexpr float kMvTopBarHeight = 0.0f;
constexpr float kMvDisasmHintHeight = 0.0f;
constexpr float kMvSectionHeaderHeight = 24.0f;
constexpr float kMvHexInfoHeight = 18.0f;
constexpr float kMvRowHeight = 20.0f;
constexpr UINT kMainMenuDebugPointerScan = 40006;
constexpr UINT kMainMenuDebugPointerCompare = 40007;
constexpr UINT kMainMenuDebugDataTraverse = 40008;

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

std::filesystem::path GetExeDir() {
  wchar_t path[MAX_PATH] = {0};
  const DWORD len = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
  if (len == 0 || len >= std::size(path)) {
    return {};
  }
  std::filesystem::path exe_path(path);
  return exe_path.parent_path();
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
  size_t off = 0;
  while (off + 12 <= table.size()) {
    uint16_t name_len = 0;
    uint16_t reserved = 0;
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t w = 0;
    uint16_t h = 0;
    std::memcpy(&name_len, table.data() + off, 2);
    std::memcpy(&reserved, table.data() + off + 2, 2);
    std::memcpy(&x, table.data() + off + 4, 2);
    std::memcpy(&y, table.data() + off + 6, 2);
    std::memcpy(&w, table.data() + off + 8, 2);
    std::memcpy(&h, table.data() + off + 10, 2);
    (void)reserved;
    off += 12;
    if (off + name_len > table.size()) {
      break;
    }
    std::string id(reinterpret_cast<const char*>(table.data() + off), name_len);
    off += name_len;
    out->icon_rects[id] = IconAtlasRaw::Rect{static_cast<int>(x), static_cast<int>(y), static_cast<int>(w), static_cast<int>(h)};
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
  return (static_cast<uint32_t>(lerp(aa, ba)) << 24) | (static_cast<uint32_t>(lerp(ar, br)) << 16) |
         (static_cast<uint32_t>(lerp(ag, bg)) << 8) | static_cast<uint32_t>(lerp(ab, bb));
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
  return LerpColor(LerpColor(p00, p10, tx), LerpColor(p01, p11, tx), ty);
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

uint64_t ParseAddressText(const wchar_t* text) {
  if (!text || !*text) {
    return 0;
  }
  wchar_t* endptr = nullptr;
  uint64_t value = std::wcstoull(text, &endptr, 0);
  if (endptr == text) {
    return 0;
  }
  return value;
}

struct InputDialogState {
  std::wstring title;
  std::wstring label;
  std::wstring text;
  bool done = false;
  bool ok = false;
  HWND hwnd = nullptr;
  HWND edit = nullptr;
};

LRESULT CALLBACK InputDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  InputDialogState* state = reinterpret_cast<InputDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    state = reinterpret_cast<InputDialogState*>(cs->lpCreateParams);
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
          GetWindowTextW(state->edit, buf, static_cast<int>(sizeof(buf) / sizeof(buf[0])));
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

bool PromptInputDialog(HWND owner,
                       const wchar_t* title,
                       const wchar_t* label,
                       const wchar_t* preset,
                       std::wstring* out_text) {
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = InputDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"R3NgInputDialog";
    RegisterClassExW(&wc);
    registered = true;
  }

  InputDialogState state{};
  state.title = title ? title : L"输入";
  state.label = label ? label : L"内容";
  state.text = preset ? preset : L"";

  const int width = 420;
  const int height = 160;
  RECT owner_rc{};
  if (owner && GetWindowRect(owner, &owner_rc)) {
    const int x = owner_rc.left + (owner_rc.right - owner_rc.left - width) / 2;
    const int y = owner_rc.top + (owner_rc.bottom - owner_rc.top - height) / 2;
    state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                                 L"R3NgInputDialog",
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
  } else {
    state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                                 L"R3NgInputDialog",
                                 state.title.c_str(),
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                 CW_USEDEFAULT,
                                 CW_USEDEFAULT,
                                 width,
                                 height,
                                 owner,
                                 nullptr,
                                 GetModuleHandleW(nullptr),
                                 &state);
  }
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

  if (state.ok && out_text) {
    *out_text = state.text;
  }
  return state.ok;
}

int HexValue(wchar_t c) {
  if (c >= L'0' && c <= L'9') return c - L'0';
  if (c >= L'a' && c <= L'f') return 10 + (c - L'a');
  if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
  return -1;
}

bool ParseHexBytes(const std::wstring& text, std::vector<uint8_t>* out) {
  if (!out) return false;
  out->clear();
  std::wstring hex;
  hex.reserve(text.size());
  for (wchar_t c : text) {
    if (HexValue(c) >= 0) {
      hex.push_back(c);
    }
  }
  if (hex.empty() || (hex.size() % 2) != 0) {
    return false;
  }
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = HexValue(hex[i]);
    const int lo = HexValue(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out->push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return !out->empty();
}

bool FindBytes(const std::vector<uint8_t>& haystack,
               const std::vector<uint8_t>& needle,
               size_t* out_offset) {
  if (needle.empty() || haystack.size() < needle.size()) {
    return false;
  }
  for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
    if (std::memcmp(haystack.data() + i, needle.data(), needle.size()) == 0) {
      if (out_offset) {
        *out_offset = i;
      }
      return true;
    }
  }
  return false;
}

bool FindDisasmText(const std::vector<MemoryViewWindow::DisasmLine>& lines,
                    const std::wstring& query,
                    uint64_t* out_addr) {
  if (query.empty()) {
    return false;
  }
  for (const auto& line : lines) {
    if (line.op.find(query) != std::wstring::npos || line.comment.find(query) != std::wstring::npos) {
      if (out_addr) {
        *out_addr = line.addr;
      }
      return true;
    }
  }
  return false;
}

std::string TrimAscii(const std::string& text) {
  const char* ws = " \t\r\n";
  const size_t begin = text.find_first_not_of(ws);
  if (begin == std::string::npos) {
    return "";
  }
  const size_t end = text.find_last_not_of(ws);
  return text.substr(begin, end - begin + 1);
}

std::string ToLowerAscii(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
}

bool StartsWith(const std::string& text, const char* prefix) {
  if (!prefix) {
    return false;
  }
  return text.rfind(prefix, 0) == 0;
}

bool EndsWith(const std::string& text, const char* suffix) {
  if (!suffix) {
    return false;
  }
  const size_t len = std::strlen(suffix);
  if (text.size() < len) {
    return false;
  }
  return text.compare(text.size() - len, len, suffix) == 0;
}

bool ContainsCI(const std::string& text, const char* needle) {
  if (!needle || !*needle) {
    return false;
  }
  return ToLowerAscii(text).find(ToLowerAscii(std::string(needle))) != std::string::npos;
}

std::string BaseNameFromPath(const std::string& path) {
  if (path.empty()) {
    return "";
  }
  const size_t pos = path.find_last_of("/\\");
  if (pos == std::string::npos) {
    return path;
  }
  if (pos + 1 >= path.size()) {
    return "";
  }
  return path.substr(pos + 1);
}

struct ModuleProps {
  bool exec = false;
  bool rw = false;
  bool anon = false;
  bool heap = false;
  bool stack = false;
  bool java = false;
  bool java_heap = false;
  bool jit = false;
  bool ashmem = false;
  bool system = false;
  bool so = false;
  bool app = false;
  bool shared = false;
  bool cdata = false;
  bool dex = false;
  bool oat = false;
  bool vdex = false;
  bool art = false;
  bool apk = false;
  bool dev = false;
  bool guard = false;
  bool file = false;
};

ModuleProps GetModuleProps(const services::ClientService::ModuleInfo& mod) {
  ModuleProps props{};
  const std::string& path = mod.path;
  const bool has_path = !path.empty();
  const bool bracket = has_path && path[0] == '[';

  props.exec = (mod.perms & protocol::MODULE_PERM_EXEC) != 0;
  props.rw = (mod.perms & protocol::MODULE_PERM_READ) && (mod.perms & protocol::MODULE_PERM_WRITE);
  props.shared = (mod.perms & protocol::MODULE_PERM_SHARED) != 0;
  props.dev = StartsWith(path, "/dev");
  props.system = StartsWith(path, "/system") || StartsWith(path, "/apex") ||
                 StartsWith(path, "/vendor") || StartsWith(path, "/product") ||
                 StartsWith(path, "/odm") || StartsWith(path, "/system_ext");
  props.app = StartsWith(path, "/data/app") || StartsWith(path, "/data/user") ||
              StartsWith(path, "/data/data") || StartsWith(path, "/mnt/asec");
  props.so = EndsWith(path, ".so");
  props.apk = EndsWith(path, ".apk") || ContainsCI(path, ".apk");
  props.dex = EndsWith(path, ".dex") || ContainsCI(path, ".dex");
  props.oat = EndsWith(path, ".oat") || ContainsCI(path, ".oat");
  props.vdex = EndsWith(path, ".vdex") || ContainsCI(path, ".vdex");
  props.art = EndsWith(path, ".art") || ContainsCI(path, "boot.art");

  props.anon = !has_path || bracket || ContainsCI(path, "anon");
  props.heap = ContainsCI(path, "[heap]") || ContainsCI(path, "libc_malloc") ||
               ContainsCI(path, "scudo") || ContainsCI(path, "malloc");
  props.stack = ContainsCI(path, "[stack") || ContainsCI(path, "stack:");
  props.guard = ContainsCI(path, "guard");

  props.java_heap = ContainsCI(path, "dalvik-heap") || ContainsCI(path, "dalvik main") ||
                    ContainsCI(path, "zygote space") || ContainsCI(path, "alloc space") ||
                    ContainsCI(path, "large object") || ContainsCI(path, "main space");
  props.jit = ContainsCI(path, "jit-cache") || ContainsCI(path, "jit") || ContainsCI(path, "jit-zygote");
  props.java = ContainsCI(path, "dalvik") || ContainsCI(path, "art") || ContainsCI(path, "oat") ||
               ContainsCI(path, "vdex") || ContainsCI(path, "dex");
  props.ashmem = ContainsCI(path, "ashmem") || ContainsCI(path, "memfd");

  props.cdata = props.rw && !props.exec && !props.anon &&
                (props.so || props.apk || props.dex || props.oat || props.vdex || props.art);

  props.file = has_path && !bracket && !props.dev;
  return props;
}

struct GGSegment {
  const char* code = "";
  const char* name = "";
};

GGSegment ModuleGGSegment(const services::ClientService::ModuleInfo& mod) {
  const ModuleProps props = GetModuleProps(mod);
  const bool readable = (mod.perms & protocol::MODULE_PERM_READ) != 0;
  const std::string& path = mod.path;
  if (!readable) return {"O", "Other"};
  if (ContainsCI(path, "ppsspp")) return {"ps", "PPSSPP"};
  if (props.java_heap) return {"jh", "Java heap"};
  if (props.heap) return {"ch", "C++ heap"};
  if (ContainsCI(path, "alloc")) return {"ca", "C++ alloc"};
  if (props.anon && props.rw && !props.exec && !props.file) return {".bss", "C++ .bss"};
  if (props.java) return {"J", "Java"};
  if (props.stack) return {"S", "Stack"};
  if (props.ashmem) return {"As", "Ashmem"};
  if (props.exec && props.app) return {"XA", "Code app"};
  if (props.exec && props.system) return {"XS", "Code system"};
  if (props.dev &&
      (ContainsCI(path, "video") || ContainsCI(path, "kgsl") ||
       ContainsCI(path, "gpu") || ContainsCI(path, "graphics"))) {
    return {"V", "Video"};
  }
  if (props.anon) return {"A", "Anonymous"};
  return {"O", "Other"};
}

struct ModuleIndexCache {
  std::unordered_map<std::string, uint64_t> owner_base_by_key;
  std::unordered_map<std::string, std::string> owner_path_by_key;
  std::vector<std::string> assoc_owner_key_by_index;
};

ModuleIndexCache BuildModuleIndexCache(const std::vector<services::ClientService::ModuleInfo>& modules) {
  ModuleIndexCache cache{};
  cache.assoc_owner_key_by_index.resize(modules.size());
  if (modules.empty()) {
    return cache;
  }

  for (const auto& mod : modules) {
    const ModuleProps props = GetModuleProps(mod);
    if (!props.file || mod.path.empty()) {
      continue;
    }
    const std::string key = ToLowerAscii(mod.path);
    auto it = cache.owner_base_by_key.find(key);
    if (it == cache.owner_base_by_key.end()) {
      cache.owner_base_by_key[key] = mod.start;
      cache.owner_path_by_key[key] = mod.path;
    } else if (mod.start < it->second) {
      it->second = mod.start;
    }
  }

  std::vector<size_t> order(modules.size());
  for (size_t i = 0; i < modules.size(); ++i) {
    order[i] = i;
  }
  std::sort(order.begin(), order.end(), [&](size_t lhs, size_t rhs) {
    const auto& a = modules[lhs];
    const auto& b = modules[rhs];
    if (a.start != b.start) {
      return a.start < b.start;
    }
    return a.end < b.end;
  });

  static constexpr uint64_t kOwnerAssocGap = 0x200000ull;  // 2MB
  std::string active_owner_key;
  uint64_t active_owner_end = 0;
  for (size_t idx : order) {
    const auto& mod = modules[idx];
    const ModuleProps props = GetModuleProps(mod);
    if (props.file && !mod.path.empty()) {
      active_owner_key = ToLowerAscii(mod.path);
      active_owner_end = mod.end;
      continue;
    }
    if (active_owner_key.empty() || mod.start > active_owner_end + kOwnerAssocGap) {
      active_owner_key.clear();
      active_owner_end = 0;
      continue;
    }
    // Only associate likely data-ish anonymous pages; avoid stack/heap/java regions.
    if (props.anon && props.rw && !props.exec && !props.stack && !props.heap && !props.java_heap) {
      cache.assoc_owner_key_by_index[idx] = active_owner_key;
      if (mod.end > active_owner_end) {
        active_owner_end = mod.end;
      }
    }
  }
  return cache;
}

struct AddressSymbol {
  bool valid = false;
  size_t hit_index = std::numeric_limits<size_t>::max();
  uint64_t owner_base = 0;
  uint64_t region_start = 0;
  uint64_t region_end = 0;
  uint32_t perms = 0;
  std::string owner_path;
  std::string owner_name;
  GGSegment gg{};
};

bool ResolveAddressSymbol(const std::vector<services::ClientService::ModuleInfo>& modules,
                          const ModuleIndexCache& cache,
                          uint64_t addr,
                          AddressSymbol* out) {
  if (!out) {
    return false;
  }
  *out = {};
  if (modules.empty()) {
    return false;
  }

  size_t hit_index = std::numeric_limits<size_t>::max();
  for (size_t i = 0; i < modules.size(); ++i) {
    const auto& m = modules[i];
    if (addr >= m.start && addr < m.end) {
      hit_index = i;
      break;
    }
  }
  if (hit_index == std::numeric_limits<size_t>::max()) {
    return false;
  }

  const auto& hit = modules[hit_index];
  const ModuleProps props = GetModuleProps(hit);
  const std::string own_key = props.file && !hit.path.empty()
                                  ? ToLowerAscii(hit.path)
                                  : (hit_index < cache.assoc_owner_key_by_index.size()
                                         ? cache.assoc_owner_key_by_index[hit_index]
                                         : "");

  std::string owner_path = hit.path;
  uint64_t owner_base = hit.start;
  if (!own_key.empty()) {
    const auto pit = cache.owner_path_by_key.find(own_key);
    if (pit != cache.owner_path_by_key.end()) {
      owner_path = pit->second;
    }
    const auto bit = cache.owner_base_by_key.find(own_key);
    if (bit != cache.owner_base_by_key.end()) {
      owner_base = bit->second;
    }
  }

  out->valid = true;
  out->hit_index = hit_index;
  out->owner_base = owner_base;
  out->region_start = hit.start;
  out->region_end = hit.end;
  out->perms = hit.perms;
  out->owner_path = owner_path;
  out->owner_name = BaseNameFromPath(owner_path);
  out->gg = ModuleGGSegment(hit);
  return true;
}

enum class JumpTargetKind {
  DefaultCd = 0,
  Bss,
  Anonymous,
  Code,
  Any,
};

bool ParseJumpTargetKind(const std::string& text, JumpTargetKind* out_kind) {
  if (!out_kind) {
    return false;
  }
  const std::string kind = ToLowerAscii(TrimAscii(text));
  if (kind.empty() || kind == "cd" || kind == "cdata" || kind == "data" || kind == "d") {
    *out_kind = JumpTargetKind::DefaultCd;
    return true;
  }
  if (kind == "bss" || kind == "cb") {
    *out_kind = JumpTargetKind::Bss;
    return true;
  }
  if (kind == "a" || kind == "anon" || kind == "anonymous") {
    *out_kind = JumpTargetKind::Anonymous;
    return true;
  }
  if (kind == "x" || kind == "code" || kind == "exec" || kind == "xa" || kind == "xs") {
    *out_kind = JumpTargetKind::Code;
    return true;
  }
  if (kind == "all" || kind == "any") {
    *out_kind = JumpTargetKind::Any;
    return true;
  }
  return false;
}

std::string WideToUtf8Local(const std::wstring& text) {
  if (text.empty()) {
    return "";
  }
  const int bytes = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
  if (bytes <= 0) {
    return "";
  }
  std::string out(static_cast<size_t>(bytes), '\0');
  WideCharToMultiByte(CP_UTF8,
                      0,
                      text.c_str(),
                      static_cast<int>(text.size()),
                      out.data(),
                      bytes,
                      nullptr,
                      nullptr);
  return out;
}

std::wstring Utf8ToWideLocal(const std::string& text) {
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

struct AddressAliasCacheState {
  uint32_t pid = 0;
  size_t module_count = 0;
  uint64_t first_start = 0;
  uint64_t last_end = 0;
  ModuleIndexCache module_index;
  std::unordered_map<uint64_t, std::wstring> alias_by_addr;
};

AddressAliasCacheState& GetAddressAliasCacheState() {
  static AddressAliasCacheState state;
  return state;
}

void ResetAddressAliasCache() {
  GetAddressAliasCacheState() = {};
}

const ModuleIndexCache& PrepareModuleIndexCache(uint32_t pid,
                                                const std::vector<services::ClientService::ModuleInfo>& modules) {
  AddressAliasCacheState& cache_state = GetAddressAliasCacheState();
  const uint64_t first_start = modules.empty() ? 0 : modules.front().start;
  const uint64_t last_end = modules.empty() ? 0 : modules.back().end;
  const bool same_modules = cache_state.pid == pid &&
                            cache_state.module_count == modules.size() &&
                            cache_state.first_start == first_start &&
                            cache_state.last_end == last_end;
  if (!same_modules) {
    cache_state.pid = pid;
    cache_state.module_count = modules.size();
    cache_state.first_start = first_start;
    cache_state.last_end = last_end;
    cache_state.module_index = BuildModuleIndexCache(modules);
    cache_state.alias_by_addr.clear();
  }
  return cache_state.module_index;
}

std::wstring BuildAddressAliasWithCache(const std::vector<services::ClientService::ModuleInfo>& modules,
                                        const ModuleIndexCache& cache,
                                        uint64_t addr) {
  AddressSymbol symbol{};
  if (!ResolveAddressSymbol(modules, cache, addr, &symbol) || !symbol.valid) {
    return L"";
  }
  const std::wstring owner =
      symbol.owner_name.empty() ? L"(anonymous)" : Utf8ToWideLocal(symbol.owner_name);
  const uint64_t offset = addr >= symbol.owner_base ? (addr - symbol.owner_base) : 0;
  wchar_t off_buf[40] = {0};
  std::swprintf(off_buf, std::size(off_buf), L"+0x%llX", static_cast<unsigned long long>(offset));
  std::wstring alias = owner;
  alias += off_buf;
  if (symbol.gg.code && symbol.gg.code[0] != '\0') {
    alias += L" [";
    alias += Utf8ToWideLocal(symbol.gg.code);
    alias += L"]";
  }
  return alias;
}

std::wstring LookupAddressAliasCached(uint32_t pid,
                                      const std::vector<services::ClientService::ModuleInfo>& modules,
                                      uint64_t addr) {
  if (modules.empty()) {
    return L"";
  }
  AddressAliasCacheState& cache_state = GetAddressAliasCacheState();
  const ModuleIndexCache& index_cache = PrepareModuleIndexCache(pid, modules);
  const auto hit = cache_state.alias_by_addr.find(addr);
  if (hit != cache_state.alias_by_addr.end()) {
    return hit->second;
  }
  std::wstring alias = BuildAddressAliasWithCache(modules, index_cache, addr);
  if (!alias.empty()) {
    if (cache_state.alias_by_addr.size() > 4096) {
      cache_state.alias_by_addr.clear();
    }
    cache_state.alias_by_addr.emplace(addr, alias);
  }
  return alias;
}

void EnsureListViewClasses() {
  static bool initialized = false;
  if (initialized) {
    return;
  }
  INITCOMMONCONTROLSEX icc{};
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_LISTVIEW_CLASSES;
  InitCommonControlsEx(&icc);
  initialized = true;
}

std::wstring BuildPermTextLocal(uint32_t perms) {
  const wchar_t r = (perms & protocol::MODULE_PERM_READ) ? L'R' : L'-';
  const wchar_t w = (perms & protocol::MODULE_PERM_WRITE) ? L'W' : L'-';
  const wchar_t x = (perms & protocol::MODULE_PERM_EXEC) ? L'X' : L'-';
  const wchar_t p = (perms & protocol::MODULE_PERM_PRIVATE)
                        ? L'P'
                        : ((perms & protocol::MODULE_PERM_SHARED) ? L'S' : L'-');
  wchar_t buf[8] = {0};
  std::swprintf(buf, std::size(buf), L"%lc%lc%lc%lc", r, w, x, p);
  return std::wstring(buf);
}

std::wstring BuildModuleViewerInfo(const std::vector<services::ClientService::ModuleInfo>& modules) {
  size_t cd = 0;
  size_t xa = 0;
  size_t bss = 0;
  size_t anon = 0;
  size_t other = 0;
  for (const auto& mod : modules) {
    const GGSegment gg = ModuleGGSegment(mod);
    const std::string code = ToLowerAscii(gg.code ? std::string(gg.code) : std::string());
    if (code == "cd") {
      ++cd;
    } else if (code == "cb") {
      ++bss;
    } else if (code == "a") {
      ++anon;
    } else if (code == "xa" || code == "xs") {
      ++xa;
    } else if (code == "o") {
      ++other;
    }
  }
  wchar_t buf[256] = {0};
  std::swprintf(buf,
                std::size(buf),
                L"模块段总数: %zu | Cd:%zu  Xa:%zu  Bss(Cb):%zu  A:%zu  O:%zu",
                modules.size(),
                cd,
                xa,
                bss,
                anon,
                other);
  return std::wstring(buf);
}

struct ModuleViewerDialogState {
  const std::vector<services::ClientService::ModuleInfo>* modules = nullptr;
  bool done = false;
  bool ok = false;
  HWND hwnd = nullptr;
  HWND list = nullptr;
  HWND info = nullptr;
  HWND close_btn = nullptr;
  HFONT font = nullptr;
};

constexpr UINT kCtrlModuleViewerList = 41960;
constexpr UINT kCtrlModuleViewerInfo = 41961;

void ResizeModuleViewerColumns(HWND list, int list_w) {
  if (!list) {
    return;
  }
  const int w_start = 130;
  const int w_end = 130;
  const int w_size = 92;
  const int w_perms = 70;
  const int w_gg = 96;
  const int w_name = 150;
  const int used = w_start + w_end + w_size + w_perms + w_gg + w_name;
  const int w_path = std::max(220, list_w - used - 10);
  ListView_SetColumnWidth(list, 0, w_start);
  ListView_SetColumnWidth(list, 1, w_end);
  ListView_SetColumnWidth(list, 2, w_size);
  ListView_SetColumnWidth(list, 3, w_perms);
  ListView_SetColumnWidth(list, 4, w_gg);
  ListView_SetColumnWidth(list, 5, w_name);
  ListView_SetColumnWidth(list, 6, w_path);
}

void LayoutModuleViewerDialog(ModuleViewerDialogState* state, int width, int height) {
  if (!state || !state->hwnd) {
    return;
  }
  const int margin = 10;
  const int btn_h = 28;
  const int btn_w = 84;
  const int info_h = 24;
  const int gap = 8;
  const int client_w = std::max(520, width);
  const int client_h = std::max(320, height);
  const int btn_y = client_h - margin - btn_h;
  const int info_y = btn_y - gap - info_h;
  const int list_h = std::max(120, info_y - margin - gap);
  if (state->list) {
    MoveWindow(state->list, margin, margin, client_w - margin * 2, list_h, TRUE);
    ResizeModuleViewerColumns(state->list, client_w - margin * 2 - 4);
  }
  if (state->info) {
    MoveWindow(state->info, margin, info_y, client_w - margin * 2 - btn_w - gap, info_h, TRUE);
  }
  if (state->close_btn) {
    MoveWindow(state->close_btn, client_w - margin - btn_w, info_y - 2, btn_w, btn_h, TRUE);
  }
}

void PopulateModuleViewerList(ModuleViewerDialogState* state) {
  if (!state || !state->list || !state->modules) {
    return;
  }
  ListView_DeleteAllItems(state->list);
  for (size_t i = 0; i < state->modules->size(); ++i) {
    const auto& mod = (*state->modules)[i];
    wchar_t start_buf[32] = {0};
    wchar_t end_buf[32] = {0};
    wchar_t size_buf[32] = {0};
    std::swprintf(start_buf, std::size(start_buf), L"0x%llX", static_cast<unsigned long long>(mod.start));
    std::swprintf(end_buf, std::size(end_buf), L"0x%llX", static_cast<unsigned long long>(mod.end));
    const uint64_t size = mod.end > mod.start ? (mod.end - mod.start) : 0;
    std::swprintf(size_buf, std::size(size_buf), L"0x%llX", static_cast<unsigned long long>(size));

    const std::wstring perms = BuildPermTextLocal(mod.perms);
    const GGSegment gg = ModuleGGSegment(mod);
    std::wstring gg_text = gg.code ? Utf8ToWideLocal(gg.code) : L"";
    if (gg.name && gg.name[0] != '\0') {
      gg_text.append(L" / ");
      gg_text.append(Utf8ToWideLocal(gg.name));
    }
    if (gg_text.empty()) {
      gg_text = L"-";
    }
    const std::string base_name = BaseNameFromPath(mod.path);
    const std::wstring module_name = base_name.empty() ? L"(anonymous)" : Utf8ToWideLocal(base_name);
    const std::wstring path = mod.path.empty() ? L"(anonymous)" : Utf8ToWideLocal(mod.path);

    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = static_cast<int>(i);
    item.iSubItem = 0;
    item.pszText = start_buf;
    item.lParam = static_cast<LPARAM>(i);
    const int row = ListView_InsertItem(state->list, &item);
    if (row < 0) {
      continue;
    }
    ListView_SetItemText(state->list, row, 1, end_buf);
    ListView_SetItemText(state->list, row, 2, size_buf);
    ListView_SetItemText(state->list, row, 3, const_cast<LPWSTR>(perms.c_str()));
    ListView_SetItemText(state->list, row, 4, const_cast<LPWSTR>(gg_text.c_str()));
    ListView_SetItemText(state->list, row, 5, const_cast<LPWSTR>(module_name.c_str()));
    ListView_SetItemText(state->list, row, 6, const_cast<LPWSTR>(path.c_str()));
  }
}

LRESULT CALLBACK ModuleViewerDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  ModuleViewerDialogState* state =
      reinterpret_cast<ModuleViewerDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    state = reinterpret_cast<ModuleViewerDialogState*>(cs->lpCreateParams);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
  }
  if (!state) {
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }
  switch (msg) {
    case WM_SIZE:
      LayoutModuleViewerDialog(state, LOWORD(lparam), HIWORD(lparam));
      return 0;
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      if (cmd == IDOK || cmd == IDCANCEL) {
        state->ok = (cmd == IDOK);
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

bool PromptModuleViewerDialog(HWND owner, const std::vector<services::ClientService::ModuleInfo>& modules) {
  EnsureListViewClasses();
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ModuleViewerDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"R3NgModuleViewerDialog";
    RegisterClassExW(&wc);
    registered = true;
  }

  ModuleViewerDialogState state{};
  state.modules = &modules;
  state.font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

  const int width = 1120;
  const int height = 700;
  RECT owner_rc{};
  int x = CW_USEDEFAULT;
  int y = CW_USEDEFAULT;
  if (owner && GetWindowRect(owner, &owner_rc)) {
    x = owner_rc.left + (owner_rc.right - owner_rc.left - width) / 2;
    y = owner_rc.top + (owner_rc.bottom - owner_rc.top - height) / 2;
  }
  state.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME,
                               L"R3NgModuleViewerDialog",
                               L"查看模块",
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

  state.list = CreateWindowExW(WS_EX_CLIENTEDGE,
                               WC_LISTVIEWW,
                               nullptr,
                               WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                               0,
                               0,
                               0,
                               0,
                               state.hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlModuleViewerList)),
                               GetModuleHandleW(nullptr),
                               nullptr);
  state.info = CreateWindowExW(WS_EX_CLIENTEDGE,
                               L"STATIC",
                               L"",
                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                               0,
                               0,
                               0,
                               0,
                               state.hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCtrlModuleViewerInfo)),
                               GetModuleHandleW(nullptr),
                               nullptr);
  state.close_btn = CreateWindowExW(0,
                                    L"BUTTON",
                                    L"关闭",
                                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                    0,
                                    0,
                                    0,
                                    0,
                                    state.hwnd,
                                    reinterpret_cast<HMENU>(IDCANCEL),
                                    GetModuleHandleW(nullptr),
                                    nullptr);

  if (state.list) {
    ListView_SetExtendedListViewStyle(
        state.list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.iSubItem = 0;
    col.cx = 130;
    col.pszText = const_cast<LPWSTR>(L"起始");
    ListView_InsertColumn(state.list, 0, &col);
    col.iSubItem = 1;
    col.cx = 130;
    col.pszText = const_cast<LPWSTR>(L"结束");
    ListView_InsertColumn(state.list, 1, &col);
    col.iSubItem = 2;
    col.cx = 92;
    col.pszText = const_cast<LPWSTR>(L"大小");
    ListView_InsertColumn(state.list, 2, &col);
    col.iSubItem = 3;
    col.cx = 70;
    col.pszText = const_cast<LPWSTR>(L"保护");
    ListView_InsertColumn(state.list, 3, &col);
    col.iSubItem = 4;
    col.cx = 96;
    col.pszText = const_cast<LPWSTR>(L"GG段");
    ListView_InsertColumn(state.list, 4, &col);
    col.iSubItem = 5;
    col.cx = 150;
    col.pszText = const_cast<LPWSTR>(L"模块名");
    ListView_InsertColumn(state.list, 5, &col);
    col.iSubItem = 6;
    col.cx = 360;
    col.pszText = const_cast<LPWSTR>(L"路径");
    ListView_InsertColumn(state.list, 6, &col);
  }

  HWND controls[] = {state.list, state.info, state.close_btn};
  for (HWND ctrl : controls) {
    if (ctrl && state.font) {
      SendMessageW(ctrl, WM_SETFONT, reinterpret_cast<WPARAM>(state.font), TRUE);
    }
  }

  PopulateModuleViewerList(&state);
  const std::wstring info = BuildModuleViewerInfo(modules);
  if (state.info) {
    SetWindowTextW(state.info, info.c_str());
  }
  LayoutModuleViewerDialog(&state, width, height);

  if (owner) {
    EnableWindow(owner, FALSE);
  }
  ShowWindow(state.hwnd, SW_SHOW);
  SetForegroundWindow(state.hwnd);
  if (state.list) {
    SetFocus(state.list);
  }

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
  return true;
}

}  // namespace

MemoryViewWindow::MemoryViewWindow() = default;

MemoryViewWindow::~MemoryViewWindow() {
  if (hwnd_) {
    DestroyWindow(hwnd_);
    hwnd_ = nullptr;
  }
  DiscardDeviceResources();
  SafeRelease(&font_mono_);
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
  for (HBITMAP bmp : menu_bitmaps_) {
    if (bmp) {
      DeleteObject(bmp);
    }
  }
  menu_bitmaps_.clear();
}

bool MemoryViewWindow::CreateDeviceIndependentResources() {
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

  hr = create_font(L"JetBrains Mono", L"Consolas", 12.0f, L"en-US", &font_mono_);
  if (FAILED(hr)) {
    return false;
  }
  font_mono_->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
  return true;
}

bool MemoryViewWindow::CreateDeviceResources() {
  if (render_target_) {
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
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(48, 48, 48), &brush_panel_);
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(74, 74, 74), &brush_border_);
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(230, 230, 230), &brush_text_);
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(190, 190, 190), &brush_muted_);
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(224, 195, 90), &brush_highlight_);
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(52, 106, 176, 210), &brush_select_fill_);
  if (FAILED(hr)) {
    return false;
  }
  hr = render_target_->CreateSolidColorBrush(Rgba(132, 196, 255), &brush_select_border_);
  if (FAILED(hr)) {
    return false;
  }
  return true;
}

void MemoryViewWindow::DiscardDeviceResources() {
  SafeRelease(&brush_select_border_);
  SafeRelease(&brush_select_fill_);
  SafeRelease(&brush_highlight_);
  SafeRelease(&brush_muted_);
  SafeRelease(&brush_text_);
  SafeRelease(&brush_border_);
  SafeRelease(&brush_panel_);
  SafeRelease(&brush_bg_);
  SafeRelease(&render_target_);
}

bool MemoryViewWindow::Create(HINSTANCE instance,
                              HWND owner,
                              services::ClientService* service,
                              app::UiState* state) {
  if (hwnd_) {
    return true;
  }
  instance_ = instance;
  owner_ = owner;
  service_ = service;
  state_ = state;

  if (!CreateDeviceIndependentResources()) {
    return false;
  }

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = StaticWndProc;
  wc.hInstance = instance_;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.lpszClassName = L"R3NgMemoryViewWindowClass";
  RegisterClassExW(&wc);

  hwnd_ = CreateWindowExW(WS_EX_APPWINDOW,
                          wc.lpszClassName,
                          L"Memory View",
                          WS_OVERLAPPEDWINDOW,
                          CW_USEDEFAULT,
                          CW_USEDEFAULT,
                          1200,
                          780,
                          owner_,
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

  if (!ctrl_font_) {
    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(12, static_cast<int>(dpi_), 96);
    lf.lfWeight = FW_NORMAL;
    wcscpy_s(lf.lfFaceName, L"Microsoft YaHei UI");
    ctrl_font_ = CreateFontIndirectW(&lf);
  }
  HFONT font = ctrl_font_ ? ctrl_font_ : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
  (void)font;

  nav_history_.clear();
  nav_history_.push_back(base_addr_);
  nav_history_pos_ = 0;
  bookmark_addr_ = 0;
  follow_pc_ = false;
  debug_attached_ = false;

  BuildMenuBar();
  LayoutTopControls();
  RefreshData();
  return true;
}

void MemoryViewWindow::Show(uint64_t preferred_addr) {
  if (!hwnd_) {
    return;
  }
  if (preferred_addr != 0) {
    JumpToInternal(preferred_addr, true);
  } else if (mem_.empty()) {
    RefreshData();
  }
  ShowWindow(hwnd_, SW_SHOW);
  SetForegroundWindow(hwnd_);
}

bool MemoryViewWindow::IsOpen() const { return hwnd_ != nullptr && IsWindow(hwnd_) != FALSE; }

void MemoryViewWindow::LayoutTopControls() {
  if (!hwnd_ || !addr_edit_ || !goto_btn_) {
    return;
  }
  RECT rc{};
  GetClientRect(hwnd_, &rc);
  const float s = dpi_scale_;
  auto px = [s](float dip) { return static_cast<int>(std::lround(dip * s)); };
  const int margin = px(8.0f);
  const int top = px(4.0f);
  const int btn_w = px(112.0f);
  const int ctrl_h = px(22.0f);
  const int gap = px(8.0f);
  const int preferred_edit_w = px(240.0f);
  const int client_w = std::max(0, static_cast<int>(rc.right) - static_cast<int>(rc.left));
  const int max_row_w = std::max(0, client_w - margin * 2);
  int edit_w = preferred_edit_w;
  if (max_row_w > btn_w + gap + px(120.0f)) {
    edit_w = std::min(preferred_edit_w, max_row_w - btn_w - gap);
  } else {
    edit_w = std::max(px(120.0f), max_row_w - btn_w - gap);
  }
  const int btn_x = margin + edit_w + gap;
  MoveWindow(addr_edit_, margin, top, std::max(px(120.0f), edit_w), ctrl_h, TRUE);
  MoveWindow(goto_btn_, btn_x, top, btn_w, ctrl_h, TRUE);
}

void MemoryViewWindow::BuildMenuBar() {
  HMENU bar = CreateMenu();
  HMENU file = CreatePopupMenu();
  HMENU search = CreatePopupMenu();
  HMENU view = CreatePopupMenu();
  HMENU debug = CreatePopupMenu();
  HMENU tool = CreatePopupMenu();

  AppendMenuW(file, MF_STRING, kMenuReload, L"刷新\tF5");

  AppendMenuW(search, MF_STRING, kMenuFindHex, L"查找内存");
  AppendMenuW(search, MF_STRING, kMenuFindAsm, L"查找汇编码");

  AppendMenuW(view, MF_STRING, kMenuJump, L"跳转地址/模块...\tG");
  AppendMenuW(view, MF_STRING, kMenuViewBack, L"后退");
  AppendMenuW(view, MF_STRING, kMenuViewForward, L"前进");
  AppendMenuW(view, MF_STRING, kMenuViewBookmark, L"收藏当前地址");
  AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(view, MF_STRING, kMenuViewModuleStart, L"跳到当前段起始");
  AppendMenuW(view, MF_STRING, kMenuViewPrevSegment, L"上一个内存段");
  AppendMenuW(view, MF_STRING, kMenuViewNextSegment, L"下一个内存段");
  AppendMenuW(view, MF_STRING, kMenuViewModules, L"查看模块...");
  AppendMenuW(view, MF_STRING, kMenuViewFollowPc, L"跟随PC");
  AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(view, MF_STRING, kMenuViewAsmHex, L"汇编+HEX");
  AppendMenuW(view, MF_STRING, kMenuViewAsmOnly, L"仅汇编");
  AppendMenuW(view, MF_STRING, kMenuViewHexOnly, L"仅HEX");
  AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(view, MF_STRING, kMenuHexEdit, L"十六进制编辑\tCtrl+H");

  AppendMenuW(debug, MF_STRING, kMenuDebugRun, L"继续运行\tF9");
  AppendMenuW(debug, MF_STRING, kMenuDebugBreak, L"暂停进程");
  AppendMenuW(debug, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(debug, MF_STRING, kMenuDebugToggleBp, L"切换断点\tF2");
  AppendMenuW(debug, MF_STRING, kMenuDebugRunTo, L"运行到选中地址");
  AppendMenuW(debug, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(debug, MF_STRING, kMenuDebugStepIn, L"单步步入\tF7");
  AppendMenuW(debug, MF_STRING, kMenuDebugStepOver, L"单步步过\tF8");
  AppendMenuW(debug, MF_STRING, kMenuDebugSetAddr, L"设置PC到选中地址");

  AppendMenuW(tool, MF_STRING, kMenuToolPointerScan, L"指针搜索");
  AppendMenuW(tool, MF_STRING, kMenuToolPointerCompare, L"指针对比");
  AppendMenuW(tool, MF_STRING, kMenuToolDataTraverse, L"结构分析(智能识别指针)");

  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"文件");
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(search), L"搜索");
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(view), L"视图");
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(debug), L"调试");
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(tool), L"工具");

  menu_bar_ = bar;
  menu_search_ = search;
  menu_view_ = view;
  menu_debug_ = debug;
  menu_tool_ = tool;
  SetMenu(hwnd_, bar);
  ApplyMenuIcons();
  UpdateViewMenuChecks();
  UpdateMenuEnabledState();
}

void MemoryViewWindow::UpdateViewMenuChecks() {
  if (!menu_view_) {
    return;
  }
  CheckMenuItem(menu_view_,
                kMenuViewFollowPc,
                MF_BYCOMMAND | (follow_pc_ ? MF_CHECKED : MF_UNCHECKED));
  CheckMenuItem(menu_view_,
                kMenuViewAsmHex,
                MF_BYCOMMAND | (disasm_mode_ == DisasmMode::AsmHex ? MF_CHECKED : MF_UNCHECKED));
  CheckMenuItem(menu_view_,
                kMenuViewAsmOnly,
                MF_BYCOMMAND | (disasm_mode_ == DisasmMode::AsmOnly ? MF_CHECKED : MF_UNCHECKED));
  CheckMenuItem(menu_view_,
                kMenuViewHexOnly,
                MF_BYCOMMAND | (disasm_mode_ == DisasmMode::HexOnly ? MF_CHECKED : MF_UNCHECKED));
}

void MemoryViewWindow::ApplyMenuIcons() {
  for (HBITMAP bmp : menu_bitmaps_) {
    if (bmp) {
      DeleteObject(bmp);
    }
  }
  menu_bitmaps_.clear();
  if (!menu_bar_) {
    return;
  }

  static IconAtlasRaw atlas{};
  if (!LoadIconAtlasRaw(&atlas)) {
    return;
  }
  const int icon_px = std::max(14, static_cast<int>(std::lround(16.0f * dpi_scale_)));

  auto add = [&](HMENU menu, UINT cmd, const char* icon_id) {
    if (!menu) {
      return;
    }
    HBITMAP bmp = CreateMenuIconBitmap(atlas, icon_id, icon_px);
    if (!bmp) {
      return;
    }
    menu_bitmaps_.push_back(bmp);
    SetMenuBitmap(menu, cmd, bmp);
  };

  add(menu_search_, kMenuFindHex, "scan");
  add(menu_search_, kMenuFindAsm, "scan");
  add(menu_view_, kMenuJump, "memory");
  add(menu_view_, kMenuViewBack, "arrow-left");
  add(menu_view_, kMenuViewForward, "arrow-right");
  add(menu_view_, kMenuViewModuleStart, "segment");
  add(menu_view_, kMenuViewModules, "segment");
  add(menu_debug_, kMenuDebugToggleBp, "debugger");
  add(menu_debug_, kMenuDebugRun, "play");
  add(menu_debug_, kMenuDebugBreak, "pause");
  DrawMenuBar(hwnd_);
}

void MemoryViewWindow::UpdateMenuEnabledState() {
  if (!menu_bar_) {
    return;
  }
  const bool connected = service_ && state_ && service_->IsConnected() && state_->pid != 0;
  const bool has_mem = !mem_.empty();
  auto set_enabled = [&](HMENU menu, UINT cmd, bool enabled) {
    if (!menu) {
      return;
    }
    EnableMenuItem(menu, cmd, MF_BYCOMMAND | (enabled ? MF_ENABLED : MF_GRAYED));
  };
  set_enabled(menu_bar_, kMenuReload, connected);
  set_enabled(menu_bar_, kMenuFindHex, has_mem);
  set_enabled(menu_bar_, kMenuFindAsm, has_mem);
  set_enabled(menu_bar_, kMenuJump, true);
  set_enabled(menu_bar_, kMenuViewBack, nav_history_pos_ > 0);
  set_enabled(menu_bar_, kMenuViewForward, nav_history_pos_ + 1 < nav_history_.size());
  set_enabled(menu_bar_, kMenuViewBookmark, has_mem);
  set_enabled(menu_bar_, kMenuViewModuleStart, connected && !modules_.empty());
  set_enabled(menu_bar_, kMenuViewPrevSegment, connected && !modules_.empty());
  set_enabled(menu_bar_, kMenuViewNextSegment, connected && !modules_.empty());
  set_enabled(menu_bar_, kMenuViewModules, connected);
  set_enabled(menu_bar_, kMenuViewFollowPc, connected);
  set_enabled(menu_bar_, kMenuViewAsmHex, true);
  set_enabled(menu_bar_, kMenuViewAsmOnly, true);
  set_enabled(menu_bar_, kMenuViewHexOnly, true);
  set_enabled(menu_bar_, kMenuHexEdit, connected);
  set_enabled(menu_bar_, kMenuDebugRun, connected && debug_attached_);
  set_enabled(menu_bar_, kMenuDebugBreak, connected && !debug_attached_);
  set_enabled(menu_bar_, kMenuDebugToggleBp, connected);
  set_enabled(menu_bar_, kMenuDebugRunTo, false);
  set_enabled(menu_bar_, kMenuDebugStepIn, false);
  set_enabled(menu_bar_, kMenuDebugStepOver, false);
  set_enabled(menu_bar_, kMenuDebugSetAddr, false);
  set_enabled(menu_bar_, kMenuToolPointerScan, true);
  set_enabled(menu_bar_, kMenuToolPointerCompare, true);
  set_enabled(menu_bar_, kMenuToolDataTraverse, true);
  // Also set state directly on popup menu to avoid stale disabled rendering on some systems.
  set_enabled(menu_tool_, kMenuToolPointerScan, true);
  set_enabled(menu_tool_, kMenuToolPointerCompare, true);
  set_enabled(menu_tool_, kMenuToolDataTraverse, true);
  DrawMenuBar(hwnd_);
}

bool MemoryViewWindow::CopyTextToClipboard(const std::wstring& text) {
  if (!OpenClipboard(hwnd_)) {
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

std::wstring MemoryViewWindow::BuildPermText(uint32_t perms) const {
  wchar_t buf[64] = {0};
  const wchar_t r = (perms & protocol::MODULE_PERM_READ) ? L'R' : L'-';
  const wchar_t w = (perms & protocol::MODULE_PERM_WRITE) ? L'W' : L'-';
  const wchar_t x = (perms & protocol::MODULE_PERM_EXEC) ? L'X' : L'-';
  const wchar_t* extra = L"";
  if (perms & protocol::MODULE_PERM_PRIVATE) {
    extra = L" 私有";
  } else if (perms & protocol::MODULE_PERM_SHARED) {
    extra = L" 共享";
  }
  std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"%lc%lc%lc%ls", r, w, x, extra);
  return std::wstring(buf);
}

bool MemoryViewWindow::EnsureModulesLoaded() {
  if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
    modules_.clear();
    modules_pid_ = 0;
    ResetAddressAliasCache();
    return false;
  }
  if (modules_pid_ == state_->pid && !modules_.empty()) {
    return true;
  }
  std::string error;
  if (!service_->FetchModules(state_->pid, &modules_, &error)) {
    if (modules_pid_ != state_->pid) {
      ResetAddressAliasCache();
    }
    return false;
  }
  std::sort(modules_.begin(), modules_.end(), [](const auto& a, const auto& b) {
    if (a.start != b.start) {
      return a.start < b.start;
    }
    return a.end < b.end;
  });
  modules_pid_ = state_->pid;
  ResetAddressAliasCache();
  return !modules_.empty();
}

std::wstring MemoryViewWindow::BuildAddressAlias(uint64_t addr) const {
  const uint32_t pid = state_ ? state_->pid : modules_pid_;
  return LookupAddressAliasCached(pid, modules_, addr);
}

void MemoryViewWindow::UpdateSelectedAddressStatus() {
  const uint64_t selected = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
  const std::wstring alias = BuildAddressAlias(selected);
  if (alias.empty()) {
    return;
  }
  status_ = L"已定位: ";
  status_.append(alias);
}

bool MemoryViewWindow::ResolveJumpExpression(const std::wstring& input,
                                             uint64_t* out_addr,
                                             std::wstring* out_error) {
  if (out_error) {
    out_error->clear();
  }
  if (!out_addr) {
    if (out_error) {
      *out_error = L"跳转参数无效";
    }
    return false;
  }

  std::wstring text = input;
  const wchar_t* ws = L" \t\r\n";
  const size_t first = text.find_first_not_of(ws);
  if (first == std::wstring::npos) {
    if (out_error) {
      *out_error = L"请输入地址或模块名";
    }
    return false;
  }
  const size_t last = text.find_last_not_of(ws);
  text = text.substr(first, last - first + 1);

  wchar_t* endptr = nullptr;
  const uint64_t numeric = std::wcstoull(text.c_str(), &endptr, 0);
  if (endptr && endptr != text.c_str()) {
    const wchar_t* tail = endptr;
    while (*tail != 0 && std::iswspace(static_cast<wint_t>(*tail)) != 0) {
      ++tail;
    }
    if (*tail == 0) {
      *out_addr = numeric;
      return true;
    }
  }

  if (!EnsureModulesLoaded()) {
    if (out_error) {
      *out_error = L"模块列表不可用，请先附加进程";
    }
    return false;
  }

  std::string query = TrimAscii(WideToUtf8Local(text));
  if (query.empty()) {
    if (out_error) {
      *out_error = L"请输入地址或模块名";
    }
    return false;
  }

  std::string module_text = query;
  std::string selector_text;
  const size_t colon = query.find(':');
  if (colon != std::string::npos) {
    module_text = TrimAscii(query.substr(0, colon));
    selector_text = TrimAscii(query.substr(colon + 1));
  }
  module_text = ToLowerAscii(module_text);
  if (module_text.empty()) {
    if (out_error) {
      *out_error = L"模块名为空";
    }
    return false;
  }

  JumpTargetKind target_kind = JumpTargetKind::DefaultCd;
  if (!ParseJumpTargetKind(selector_text, &target_kind)) {
    if (out_error) {
      *out_error = L"段名无效，仅支持 :cd / :bss / :a / :code";
    }
    return false;
  }

  const ModuleIndexCache& cache = PrepareModuleIndexCache(state_ ? state_->pid : modules_pid_, modules_);
  if (cache.owner_path_by_key.empty()) {
    if (out_error) {
      *out_error = L"未识别到可跳转模块";
    }
    return false;
  }

  struct MatchCandidate {
    std::string owner_key;
    int score = -1;
    uint64_t base = std::numeric_limits<uint64_t>::max();
  };
  MatchCandidate best{};
  for (const auto& item : cache.owner_path_by_key) {
    const std::string full = ToLowerAscii(item.second);
    const std::string base_name = ToLowerAscii(BaseNameFromPath(item.second));
    int score = -1;
    if (base_name == module_text) {
      score = 500;
    } else if (full == module_text) {
      score = 480;
    } else if (base_name.rfind(module_text, 0) == 0) {
      score = 420;
    } else if (base_name.find(module_text) != std::string::npos) {
      score = 380;
    } else if (full.find(module_text) != std::string::npos) {
      score = 320;
    }
    if (score < 0) {
      continue;
    }
    const auto bit = cache.owner_base_by_key.find(item.first);
    const uint64_t base = (bit == cache.owner_base_by_key.end()) ? std::numeric_limits<uint64_t>::max() : bit->second;
    if (score > best.score || (score == best.score && base < best.base)) {
      best.owner_key = item.first;
      best.score = score;
      best.base = base;
    }
  }
  if (best.score < 0) {
    if (out_error) {
      *out_error = L"未找到匹配模块";
    }
    return false;
  }

  struct SegmentCandidate {
    size_t index = std::numeric_limits<size_t>::max();
    bool owner_file = false;
    bool owner_assoc = false;
    GGSegment gg{};
  };
  std::vector<SegmentCandidate> candidates;
  candidates.reserve(modules_.size());
  for (size_t i = 0; i < modules_.size(); ++i) {
    const auto& mod = modules_[i];
    const ModuleProps props = GetModuleProps(mod);
    const bool owner_file = props.file && !mod.path.empty() && ToLowerAscii(mod.path) == best.owner_key;
    const bool owner_assoc =
        i < cache.assoc_owner_key_by_index.size() && cache.assoc_owner_key_by_index[i] == best.owner_key;
    if (!owner_file && !owner_assoc) {
      continue;
    }
    candidates.push_back({i, owner_file, owner_assoc, ModuleGGSegment(mod)});
  }
  if (candidates.empty()) {
    if (out_error) {
      *out_error = L"模块没有可用段";
    }
    return false;
  }

  std::sort(candidates.begin(), candidates.end(), [&](const auto& lhs, const auto& rhs) {
    return modules_[lhs.index].start < modules_[rhs.index].start;
  });

  auto pick_first = [&](auto&& pred, uint64_t* out_target) -> bool {
    for (const auto& seg : candidates) {
      const auto& mod = modules_[seg.index];
      if (pred(seg, mod)) {
        if (out_target) {
          *out_target = mod.start;
        }
        return true;
      }
    }
    return false;
  };

  const auto is_exec = [](const services::ClientService::ModuleInfo& mod) {
    return (mod.perms & protocol::MODULE_PERM_EXEC) != 0;
  };

  uint64_t target = 0;
  bool found = false;
  switch (target_kind) {
    case JumpTargetKind::DefaultCd:
      found = pick_first([](const auto& seg, const auto&) { return std::strcmp(seg.gg.code, "Cd") == 0; }, &target) ||
              pick_first([&](const auto& seg, const auto& mod) {
                return seg.owner_file && (mod.perms & protocol::MODULE_PERM_READ) &&
                       (mod.perms & protocol::MODULE_PERM_WRITE) && !is_exec(mod);
              }, &target) ||
              pick_first([&](const auto& seg, const auto& mod) { return seg.owner_file && is_exec(mod); }, &target);
      break;
    case JumpTargetKind::Bss:
      found = pick_first([](const auto& seg, const auto&) { return seg.owner_assoc && std::strcmp(seg.gg.code, "Cb") == 0; }, &target) ||
              pick_first([&](const auto& seg, const auto& mod) {
                return seg.owner_assoc && (mod.perms & protocol::MODULE_PERM_READ) &&
                       (mod.perms & protocol::MODULE_PERM_WRITE) && !is_exec(mod);
              }, &target);
      break;
    case JumpTargetKind::Anonymous:
      found = pick_first([](const auto& seg, const auto&) { return seg.owner_assoc && std::strcmp(seg.gg.code, "A") == 0; }, &target) ||
              pick_first([](const auto& seg, const auto&) { return seg.owner_assoc && std::strcmp(seg.gg.code, "Cb") == 0; }, &target) ||
              pick_first([](const auto& seg, const auto&) { return seg.owner_assoc; }, &target);
      break;
    case JumpTargetKind::Code:
      found = pick_first([&](const auto& seg, const auto& mod) { return seg.owner_file && is_exec(mod); }, &target);
      break;
    case JumpTargetKind::Any:
      found = pick_first([](const auto&, const auto&) { return true; }, &target);
      break;
  }

  if (!found) {
    const auto it = cache.owner_base_by_key.find(best.owner_key);
    if (it != cache.owner_base_by_key.end()) {
      target = it->second;
      found = true;
    }
  }
  if (!found) {
    if (out_error) {
      *out_error = L"没有匹配到目标段";
    }
    return false;
  }

  *out_addr = target;
  return true;
}

void MemoryViewWindow::UpdateRegionInfo() {
  region_info_.clear();
  if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
    return;
  }
  EnsureModulesLoaded();

  std::wstring perm = L"N/A";
  std::wstring gg_text;
  if (!modules_.empty()) {
    const ModuleIndexCache& cache = PrepareModuleIndexCache(state_->pid, modules_);
    AddressSymbol symbol{};
    if (ResolveAddressSymbol(modules_, cache, base_addr_, &symbol) && symbol.valid) {
      perm = BuildPermText(symbol.perms);
      if (symbol.gg.code && symbol.gg.code[0] != '\0') {
        gg_text = Utf8ToWideLocal(symbol.gg.code);
        if (symbol.gg.name && symbol.gg.name[0] != '\0') {
          gg_text += L" / ";
          gg_text += Utf8ToWideLocal(symbol.gg.name);
        }
      }
    }
  }

  wchar_t head[192] = {0};
  std::swprintf(head,
                std::size(head),
                L"基址: 0x%llX  长度: %u  保护: %ls",
                static_cast<unsigned long long>(base_addr_),
                static_cast<unsigned>(mem_.size()),
                perm.c_str());
  region_info_ = head;
  if (!gg_text.empty()) {
    region_info_.append(L"  GG: ");
    region_info_.append(gg_text);
  }

  const std::wstring base_alias = BuildAddressAlias(base_addr_);
  if (!base_alias.empty()) {
    region_info_.append(L"  符号: ");
    region_info_.append(base_alias);
  }
  const uint64_t selected = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
  if (selected != base_addr_) {
    const std::wstring selected_alias = BuildAddressAlias(selected);
    if (!selected_alias.empty()) {
      region_info_.append(L"  选中: ");
      region_info_.append(selected_alias);
    }
  }
}

void MemoryViewWindow::ShowModuleViewer() {
  if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
    status_ = L"未连接";
    InvalidateRect(hwnd_, nullptr, FALSE);
    return;
  }
  if (!EnsureModulesLoaded()) {
    status_ = L"未获取到模块列表";
    InvalidateRect(hwnd_, nullptr, FALSE);
    return;
  }
  if (modules_.empty()) {
    status_ = L"当前进程没有可显示模块";
    InvalidateRect(hwnd_, nullptr, FALSE);
    return;
  }
  if (PromptModuleViewerDialog(hwnd_, modules_)) {
    wchar_t buf[96] = {0};
    std::swprintf(buf, std::size(buf), L"模块列表已刷新，共 %zu 段", modules_.size());
    status_ = buf;
    InvalidateRect(hwnd_, nullptr, FALSE);
  } else {
    status_ = L"打开模块查看失败";
    InvalidateRect(hwnd_, nullptr, FALSE);
  }
}

bool MemoryViewWindow::HitTestContext(const POINT& pt, uint64_t* out_addr, std::wstring* out_bytes) {
  if (!out_addr || !out_bytes || !hwnd_) {
    return false;
  }
  RECT rc{};
  GetClientRect(hwnd_, &rc);
  const float width = static_cast<float>(rc.right - rc.left) / dpi_scale_;
  const float height = static_cast<float>(rc.bottom - rc.top) / dpi_scale_;
  const float top_h = kMvTopBarHeight;
  const float split = std::max(220.0f, height * 0.45f);
  const D2D1_RECT_F disasm_rect = D2D1::RectF(0.0f, top_h, width, split);
  const D2D1_RECT_F hex_rect = D2D1::RectF(0.0f, split + 3.0f, width, height);
  const float row_h = kMvRowHeight;
  const POINT dip{static_cast<LONG>(std::lround(pt.x / dpi_scale_)),
                  static_cast<LONG>(std::lround(pt.y / dpi_scale_))};

  if (dip.y >= static_cast<LONG>(disasm_rect.top) && dip.y <= static_cast<LONG>(disasm_rect.bottom)) {
    const float rows_top = disasm_rect.top + 1.0f + kMvDisasmHintHeight + kMvSectionHeaderHeight + 2.0f;
    if (dip.y < rows_top) {
      return false;
    }
    const float rel_y = static_cast<float>(dip.y) - rows_top;
    if (rel_y < 0.0f) {
      return false;
    }
    const size_t row = static_cast<size_t>(rel_y / row_h);
    size_t max_rows = static_cast<size_t>((disasm_rect.bottom - rows_top - 4.0f) / row_h);
    if (max_rows == 0) {
      max_rows = 1;
    }
    if (row >= max_rows) {
      return false;
    }
    if (row < disasm_.size()) {
      *out_addr = disasm_[row].addr;
      *out_bytes = disasm_[row].bytes;
      return true;
    }
    *out_addr = base_addr_ + row;
    const uint64_t off64 = static_cast<uint64_t>(row);
    if (off64 < mem_.size()) {
      const size_t off = static_cast<size_t>(off64);
      const size_t n = std::min<size_t>(16, mem_.size() - off);
      *out_bytes = HexBytes(mem_.data() + off, n);
    } else {
      *out_bytes = L"?? ";
    }
    return true;
  }

  if (dip.y >= static_cast<LONG>(hex_rect.top) && dip.y <= static_cast<LONG>(hex_rect.bottom)) {
    const float rows_top = hex_rect.top + 1.0f + kMvSectionHeaderHeight + 1.0f + kMvHexInfoHeight + 2.0f;
    if (dip.y < rows_top) {
      return false;
    }
    const float rel_y = static_cast<float>(dip.y) - rows_top;
    if (rel_y < 0.0f) {
      return false;
    }
    const size_t row = static_cast<size_t>(rel_y / row_h);
    const size_t bytes_per_row = 16;
    const size_t offset = row * bytes_per_row;
    if (offset >= mem_.size()) {
      return false;
    }
    const size_t n = std::min(bytes_per_row, mem_.size() - offset);
    *out_addr = base_addr_ + offset;
    *out_bytes = HexBytes(mem_.data() + offset, n);
    return true;
  }
  return false;
}

bool MemoryViewWindow::HitTestDisasmRow(const POINT& pt, uint64_t* out_addr) {
  if (!out_addr || !hwnd_) {
    return false;
  }
  RECT rc{};
  GetClientRect(hwnd_, &rc);
  const float width = static_cast<float>(rc.right - rc.left) / dpi_scale_;
  const float height = static_cast<float>(rc.bottom - rc.top) / dpi_scale_;
  const float top_h = kMvTopBarHeight;
  const float split = std::max(220.0f, height * 0.45f);
  const D2D1_RECT_F disasm_rect = D2D1::RectF(0.0f, top_h, width, split);
  const POINT dip{static_cast<LONG>(std::lround(pt.x / dpi_scale_)),
                  static_cast<LONG>(std::lround(pt.y / dpi_scale_))};
  if (dip.y < static_cast<LONG>(disasm_rect.top) || dip.y > static_cast<LONG>(disasm_rect.bottom)) {
    return false;
  }
  const float rows_top = disasm_rect.top + 1.0f + kMvDisasmHintHeight + kMvSectionHeaderHeight + 2.0f;
  if (dip.y < rows_top) {
    return false;
  }
  const float row_h = kMvRowHeight;
  const float rel_y = static_cast<float>(dip.y) - rows_top;
  if (rel_y < 0.0f) {
    return false;
  }
  const size_t row = static_cast<size_t>(rel_y / row_h);
  size_t max_rows = static_cast<size_t>((disasm_rect.bottom - rows_top - 4.0f) / row_h);
  if (max_rows == 0) {
    max_rows = 1;
  }
  if (row >= max_rows) {
    return false;
  }
  if (row < disasm_.size()) {
    *out_addr = disasm_[row].addr;
  } else {
    *out_addr = base_addr_ + row;
  }
  return true;
}

std::wstring MemoryViewWindow::Utf8ToWide(const std::string& text) const {
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

std::string MemoryViewWindow::WideToUtf8(const std::wstring& text) const {
  if (text.empty()) {
    return "";
  }
  const int bytes =
      WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
  if (bytes <= 0) {
    return "";
  }
  std::string out(static_cast<size_t>(bytes), '\0');
  WideCharToMultiByte(CP_UTF8,
                      0,
                      text.c_str(),
                      static_cast<int>(text.size()),
                      out.data(),
                      bytes,
                      nullptr,
                      nullptr);
  return out;
}

std::wstring MemoryViewWindow::HexBytes(const uint8_t* data, size_t n) const {
  wchar_t buf[256] = {0};
  wchar_t* cursor = buf;
  const wchar_t* end = buf + (sizeof(buf) / sizeof(wchar_t));
  for (size_t i = 0; i < n && cursor + 4 < end; ++i) {
    int written = std::swprintf(cursor, static_cast<size_t>(end - cursor), L"%02X ", data[i]);
    if (written <= 0) {
      break;
    }
    cursor += written;
  }
  return std::wstring(buf);
}

std::wstring MemoryViewWindow::AsciiBytes(const uint8_t* data, size_t n) const {
  std::wstring out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    uint8_t c = data[i];
    if (c >= 0x20 && c <= 0x7E) {
      out.push_back(static_cast<wchar_t>(c));
    } else {
      out.push_back(L'.');
    }
  }
  return out;
}

void MemoryViewWindow::RefreshData() {
  if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
    mem_.clear();
    disasm_.clear();
    status_ = L"请先打开一个进程";
    region_info_.clear();
    modules_.clear();
    modules_pid_ = 0;
    ResetAddressAliasCache();
    breakpoints_.clear();
    patch_backup_.clear();
    follow_pc_ = false;
    debug_attached_ = false;
    UpdateMenuEnabledState();
    InvalidateRect(hwnd_, nullptr, FALSE);
    return;
  }

  if (modules_pid_ != 0 && modules_pid_ != state_->pid) {
    ResetAddressAliasCache();
    breakpoints_.clear();
    patch_backup_.clear();
    follow_pc_ = false;
    debug_attached_ = false;
  }

  if (follow_pc_) {
    uint64_t pc = 0;
    std::wstring pc_error;
    if (FetchProgramCounter(&pc, &pc_error) && pc != 0) {
      base_addr_ = pc;
      selected_disasm_addr_ = pc;
    } else {
      follow_pc_ = false;
    }
  }

  std::string error;
  if (!service_->ReadMemory(base_addr_, window_size_, true, &mem_, &error)) {
    status_ = Utf8ToWide(error);
    region_info_.clear();
    mem_.clear();
    disasm_.clear();
    UpdateMenuEnabledState();
    InvalidateRect(hwnd_, nullptr, FALSE);
    return;
  }

  BuildDisasmLines();
  const uint64_t visible_span = std::max<uint64_t>(1, static_cast<uint64_t>(mem_.size()));
  if (selected_disasm_addr_ < base_addr_ || selected_disasm_addr_ >= base_addr_ + visible_span) {
    selected_disasm_addr_ = base_addr_;
  }
  UpdateRegionInfo();
  status_ = L"读取完成";
  if (!breakpoints_.empty()) {
    bool has_perf = false;
    bool has_ptrace = false;
    for (const auto& item : breakpoints_) {
      if (item.second == protocol::DebugBackend::DEBUG_BACKEND_PERF) {
        has_perf = true;
      } else if (item.second == protocol::DebugBackend::DEBUG_BACKEND_PTRACE) {
        has_ptrace = true;
      }
    }
    uint64_t hit_total = 0;
    uint64_t hit_addr = 0;
    auto poll_backend = [&](protocol::DebugBackend backend) {
      std::vector<services::ClientService::BreakpointEvent> events;
      std::string poll_error;
      if (!service_->PollBreakpoints(state_->pid, backend, 0, 64, &events, &poll_error)) {
        return;
      }
      for (const auto& ev : events) {
        const auto it = breakpoints_.find(ev.address);
        if (it == breakpoints_.end() || it->second != backend) {
          continue;
        }
        hit_total += ev.count;
        hit_addr = ev.address;
      }
    };
    if (has_perf) {
      poll_backend(protocol::DebugBackend::DEBUG_BACKEND_PERF);
    }
    if (has_ptrace) {
      poll_backend(protocol::DebugBackend::DEBUG_BACKEND_PTRACE);
    }
    if (hit_total > 0) {
      wchar_t hit_buf[128] = {0};
      std::swprintf(hit_buf,
                    std::size(hit_buf),
                    L"断点命中 %llu 次 @ 0x%llX",
                    static_cast<unsigned long long>(hit_total),
                    static_cast<unsigned long long>(hit_addr));
      status_ = hit_buf;
      if (hit_addr != 0) {
        selected_disasm_addr_ = hit_addr;
      }
    }
  }
  UpdateMenuEnabledState();
  InvalidateRect(hwnd_, nullptr, FALSE);
}

void MemoryViewWindow::BuildDisasmLines() {
  disasm_.clear();
  if (mem_.empty()) {
    return;
  }

  cs_arch arch = CS_ARCH_AARCH64;
  cs_mode mode = CS_MODE_ARM;
  if (state_ && state_->arch == static_cast<uint8_t>(protocol::RegsArch::ARM32)) {
    arch = CS_ARCH_ARM;
    mode = CS_MODE_ARM;
  }

  csh handle = 0;
  if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
    for (size_t i = 0; i < mem_.size(); ++i) {
      DisasmLine line{};
      line.addr = base_addr_ + i;
      line.bytes = HexBytes(mem_.data() + i, 1);
      line.op = L"??";
      line.comment = L"HEX";
      disasm_.push_back(std::move(line));
    }
    return;
  }

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
  cs_insn* insn = cs_malloc(handle);
  if (!insn) {
    cs_close(&handle);
    return;
  }

  const uint8_t* cursor = mem_.data();
  size_t remaining = mem_.size();
  uint64_t pc = base_addr_;
  while (remaining > 0) {
    const uint8_t* before = cursor;
    const size_t before_remaining = remaining;
    const uint64_t before_pc = pc;
    if (cs_disasm_iter(handle, &cursor, &remaining, &pc, insn)) {
      DisasmLine line{};
      line.addr = insn->address;
      line.bytes = HexBytes(insn->bytes, insn->size);
      if (insn->op_str[0]) {
        std::string op = std::string(insn->mnemonic) + " " + insn->op_str;
        line.op = Utf8ToWide(op);
      } else {
        line.op = Utf8ToWide(std::string(insn->mnemonic));
      }
      disasm_.push_back(std::move(line));
      continue;
    }

    DisasmLine line{};
    line.addr = before_pc;
    line.bytes = HexBytes(before, 1);
    line.op = L"??";
    line.comment = L"HEX";
    disasm_.push_back(std::move(line));
    cursor = before + 1;
    remaining = before_remaining - 1;
    pc = before_pc + 1;
  }

  cs_free(insn, 1);
  cs_close(&handle);
}

void MemoryViewWindow::Draw() {
  if (!render_target_) {
    return;
  }
  render_target_->BeginDraw();
  render_target_->Clear(Rgba(43, 43, 43));

  const D2D1_SIZE_F size = render_target_->GetSize();
  const bool connected = service_ && state_ && service_->IsConnected() && state_->pid != 0;
  const float split = std::max(220.0f, size.height * 0.45f);
  const D2D1_RECT_F disasm_rect = D2D1::RectF(0.0f, 0.0f, size.width, split);
  const D2D1_RECT_F hex_rect = D2D1::RectF(0.0f, split + 3.0f, size.width, size.height);

  render_target_->FillRectangle(disasm_rect, brush_bg_);
  render_target_->DrawRectangle(disasm_rect, brush_border_, 1.0f);
  render_target_->FillRectangle(hex_rect, brush_bg_);
  render_target_->DrawRectangle(hex_rect, brush_border_, 1.0f);

  const D2D1_RECT_F dheader = D2D1::RectF(disasm_rect.left + 1.0f,
                                          disasm_rect.top + 1.0f,
                                          disasm_rect.right - 1.0f,
                                          disasm_rect.top + 1.0f + kMvSectionHeaderHeight);
  render_target_->FillRectangle(dheader, brush_panel_);
  render_target_->DrawRectangle(dheader, brush_border_, 1.0f);

  const float marker_w = 18.0f;
  const float content_left = disasm_rect.left + 8.0f + marker_w;
  const float content_right = disasm_rect.right - 8.0f;
  const float avail = content_right - content_left;
  float addr_w = 220.0f;
  float bytes_w = 0.0f;
  float op_w = 0.0f;
  float comment_w = 0.0f;
  if (disasm_mode_ == DisasmMode::AsmHex) {
    const float min_comment = 96.0f;
    addr_w = std::clamp(avail * 0.42f, 240.0f, 460.0f);
    bytes_w = std::clamp(avail * 0.18f, 96.0f, 220.0f);
    op_w = std::clamp(avail * 0.24f, 120.0f, 320.0f);
    const float budget = std::max(0.0f, avail - min_comment);
    const float used = addr_w + bytes_w + op_w;
    if (used > budget && used > 1.0f) {
      const float scale = budget / used;
      addr_w *= scale;
      bytes_w *= scale;
      op_w *= scale;
    }
    comment_w = std::max(0.0f, avail - (addr_w + bytes_w + op_w));
  } else if (disasm_mode_ == DisasmMode::AsmOnly) {
    addr_w = std::clamp(avail * 0.45f, 180.0f, 420.0f);
    if (addr_w + 120.0f > avail) {
      addr_w = std::max(100.0f, avail - 120.0f);
    }
    op_w = std::max(120.0f, avail - addr_w);
  } else {
    addr_w = std::clamp(avail * 0.40f, 160.0f, 420.0f);
    if (addr_w + 120.0f > avail) {
      addr_w = std::max(100.0f, avail - 120.0f);
    }
    bytes_w = std::max(120.0f, avail - addr_w);
  }

  float col_x = content_left;
  render_target_->DrawTextW(L"地址",
                            2,
                            font_ui_,
                            D2D1::RectF(col_x, dheader.top + 3, col_x + addr_w, dheader.bottom),
                            brush_text_,
                            D2D1_DRAW_TEXT_OPTIONS_CLIP);
  col_x += addr_w + 8.0f;
  if (bytes_w > 0.0f) {
    render_target_->DrawTextW(L"字节",
                              2,
                              font_ui_,
                              D2D1::RectF(col_x, dheader.top + 3, col_x + bytes_w, dheader.bottom),
                              brush_text_,
                              D2D1_DRAW_TEXT_OPTIONS_CLIP);
    col_x += bytes_w + 8.0f;
  }
  if (op_w > 0.0f) {
    render_target_->DrawTextW(L"操作码",
                              3,
                              font_ui_,
                              D2D1::RectF(col_x, dheader.top + 3, col_x + op_w, dheader.bottom),
                              brush_text_,
                              D2D1_DRAW_TEXT_OPTIONS_CLIP);
    col_x += op_w + 8.0f;
  }
  if (comment_w > 0.0f) {
    render_target_->DrawTextW(L"注释",
                              2,
                              font_ui_,
                              D2D1::RectF(col_x, dheader.top + 3, content_right, dheader.bottom),
                              brush_text_,
                              D2D1_DRAW_TEXT_OPTIONS_CLIP);
  }
  const float v1 = content_left + addr_w + 4.0f;
  render_target_->DrawLine(D2D1::Point2F(v1, dheader.top), D2D1::Point2F(v1, disasm_rect.bottom - 2.0f), brush_border_, 1.0f);
  if (bytes_w > 0.0f) {
    const float v2 = v1 + bytes_w + 8.0f;
    render_target_->DrawLine(D2D1::Point2F(v2, dheader.top), D2D1::Point2F(v2, disasm_rect.bottom - 2.0f), brush_border_, 1.0f);
    if (op_w > 0.0f) {
      const float v3 = v2 + op_w + 8.0f;
      render_target_->DrawLine(D2D1::Point2F(v3, dheader.top), D2D1::Point2F(v3, disasm_rect.bottom - 2.0f), brush_border_, 1.0f);
    }
  }

  float y = dheader.bottom + 2.0f;
  const float row_h = kMvRowHeight;
  size_t max_rows = static_cast<size_t>((disasm_rect.bottom - y - 4.0f) / row_h);
  if (max_rows == 0) {
    max_rows = 1;
  }
  const bool has_disasm = !disasm_.empty();
  if (has_disasm) {
    max_rows = std::min(max_rows, disasm_.size());
  }
  for (size_t i = 0; i < max_rows; ++i) {
    DisasmLine placeholder{};
    if (!has_disasm) {
      placeholder.addr = base_addr_ + i;
      placeholder.bytes = L"?? ";
      placeholder.op = L"??";
      placeholder.comment = L"";
    }
    const DisasmLine& row = has_disasm ? disasm_[i] : placeholder;
    std::wstring addr_text = BuildAddressAlias(row.addr);
    if (addr_text.empty()) {
      wchar_t addr_buf[32] = {0};
      std::swprintf(addr_buf, std::size(addr_buf), L"0x%llX", static_cast<unsigned long long>(row.addr));
      addr_text = addr_buf;
    } else if (addr_text.size() > 64) {
      addr_text = addr_text.substr(0, 61) + L"...";
    }
    const bool selected_row = (row.addr == selected_disasm_addr_);
    if (i % 2 == 1) {
      const D2D1_RECT_F row_rect_alt = D2D1::RectF(disasm_rect.left + 1.0f, y, disasm_rect.right - 1.0f, y + row_h - 1.0f);
      render_target_->FillRectangle(row_rect_alt, brush_panel_);
    }
    if (selected_row) {
      const D2D1_RECT_F row_rect = D2D1::RectF(disasm_rect.left + 1.0f, y, disasm_rect.right - 1.0f, y + row_h - 1.0f);
      render_target_->FillRectangle(row_rect, brush_select_fill_ ? brush_select_fill_ : brush_panel_);
      render_target_->DrawRectangle(row_rect, brush_select_border_ ? brush_select_border_ : brush_highlight_, 1.1f);
    }
    const float marker_left = disasm_rect.left + 4.0f;
    const float marker_right = marker_left + marker_w;
    if (breakpoints_.find(row.addr) != breakpoints_.end()) {
      render_target_->DrawTextW(L"B",
                                1,
                                font_ui_,
                                D2D1::RectF(marker_left, y, marker_right, y + row_h),
                                brush_highlight_);
    }
    if (selected_row) {
      render_target_->DrawTextW(L"▶",
                                1,
                                font_ui_,
                                D2D1::RectF(marker_left, y, marker_right, y + row_h),
                                brush_select_border_ ? brush_select_border_ : brush_highlight_);
    }
    float draw_x = content_left;
    render_target_->DrawTextW(addr_text.c_str(),
                              static_cast<UINT32>(addr_text.size()),
                              font_ui_,
                              D2D1::RectF(draw_x, y, draw_x + addr_w, y + row_h),
                              brush_text_,
                              D2D1_DRAW_TEXT_OPTIONS_CLIP);
    draw_x += addr_w + 8.0f;
    if (bytes_w > 0.0f) {
      render_target_->DrawTextW(row.bytes.c_str(),
                                static_cast<UINT32>(row.bytes.size()),
                                font_mono_,
                                D2D1::RectF(draw_x, y, draw_x + bytes_w, y + row_h),
                                (selected_row || !has_disasm) ? brush_highlight_ : brush_muted_,
                                D2D1_DRAW_TEXT_OPTIONS_CLIP);
      draw_x += bytes_w + 8.0f;
    }
    if (op_w > 0.0f) {
      render_target_->DrawTextW(row.op.c_str(),
                                static_cast<UINT32>(row.op.size()),
                                font_mono_,
                                D2D1::RectF(draw_x, y, draw_x + op_w, y + row_h),
                                selected_row ? brush_highlight_ : brush_text_,
                                D2D1_DRAW_TEXT_OPTIONS_CLIP);
      draw_x += op_w + 8.0f;
    }
    std::wstring comment = row.comment;
    if (comment.empty() && selected_row) {
      comment = BuildAddressAlias(row.addr);
    }
    if (comment_w > 0.0f && !comment.empty()) {
      render_target_->DrawTextW(comment.c_str(),
                                static_cast<UINT32>(comment.size()),
                                font_ui_,
                                D2D1::RectF(draw_x, y, content_right, y + row_h),
                                brush_highlight_,
                                D2D1_DRAW_TEXT_OPTIONS_CLIP);
    }
    y += row_h;
  }

  const D2D1_RECT_F hheader = D2D1::RectF(hex_rect.left + 1.0f,
                                          hex_rect.top + 1.0f,
                                          hex_rect.right - 1.0f,
                                          hex_rect.top + 1.0f + kMvSectionHeaderHeight);
  render_target_->FillRectangle(hheader, brush_panel_);
  render_target_->DrawRectangle(hheader, brush_border_, 1.0f);

  const float addr_w_hex = 96.0f;
  const float ascii_w = 160.0f;
  const float hex_left = hex_rect.left + 8.0f + addr_w_hex + 8.0f;
  const float ascii_left = std::max(hex_left + 240.0f, hex_rect.right - ascii_w - 10.0f);
  const float hex_w = std::max(120.0f, ascii_left - hex_left - 8.0f);

  render_target_->DrawTextW(L"地址", 2, font_ui_, D2D1::RectF(hex_rect.left + 8.0f, hheader.top + 3.0f, hex_left - 4.0f, hheader.bottom), brush_text_);
  const wchar_t* hex_header = L"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F";
  render_target_->DrawTextW(hex_header,
                            static_cast<UINT32>(wcslen(hex_header)),
                            font_mono_,
                            D2D1::RectF(hex_left, hheader.top + 3.0f, hex_left + hex_w, hheader.bottom),
                            brush_text_);
  render_target_->DrawTextW(L"ASCII", 5, font_ui_, D2D1::RectF(ascii_left, hheader.top + 3.0f, hheader.right - 8.0f, hheader.bottom), brush_text_);
  const D2D1_RECT_F hinfo =
      D2D1::RectF(hex_rect.left + 1.0f, hheader.bottom + 1.0f, hex_rect.right - 1.0f, hheader.bottom + 1.0f + kMvHexInfoHeight);
  render_target_->FillRectangle(hinfo, brush_panel_);
  render_target_->DrawRectangle(hinfo, brush_border_, 1.0f);
  std::wstring info_text = region_info_;
  if (info_text.empty()) {
    wchar_t info_buf[192] = {0};
    if (connected) {
      std::swprintf(info_buf,
                    sizeof(info_buf) / sizeof(wchar_t),
                    L"基址: 0x%llX  长度: %u  保护: N/A",
                    static_cast<unsigned long long>(base_addr_),
                    static_cast<unsigned>(mem_.size()));
    } else {
      std::swprintf(info_buf,
                    sizeof(info_buf) / sizeof(wchar_t),
                    L"请先打开一个进程（当前为占位数据显示）");
    }
    info_text = info_buf;
  }
  render_target_->DrawTextW(info_text.c_str(),
                            static_cast<UINT32>(info_text.size()),
                            font_ui_,
                            D2D1::RectF(hinfo.left + 6.0f, hinfo.top + 1.0f, hinfo.right - 6.0f, hinfo.bottom - 1.0f),
                            brush_muted_);

  y = hinfo.bottom + 2.0f;
  const size_t bytes_per_row = 16;
  size_t selected_offset = static_cast<size_t>(-1);
  if (selected_disasm_addr_ >= base_addr_) {
    const uint64_t off = selected_disasm_addr_ - base_addr_;
    if (off < mem_.size()) {
      selected_offset = static_cast<size_t>(off);
    }
  }
  const bool has_mem = !mem_.empty();
  const size_t max_hex_rows = static_cast<size_t>((hex_rect.bottom - y - 4.0f) / row_h);
  const float addr_split = hex_left - 4.0f;
  const float ascii_split = ascii_left - 4.0f;
  render_target_->DrawLine(D2D1::Point2F(addr_split, hheader.top), D2D1::Point2F(addr_split, hex_rect.bottom - 2.0f), brush_border_, 1.0f);
  render_target_->DrawLine(D2D1::Point2F(ascii_split, hheader.top), D2D1::Point2F(ascii_split, hex_rect.bottom - 2.0f), brush_border_, 1.0f);
  const float byte_w = hex_w / 16.0f;
  for (int i = 1; i < 16; ++i) {
    const float x0 = hex_left + static_cast<float>(i) * byte_w;
    const float thick = (i == 8) ? 1.2f : ((i % 4 == 0) ? 1.0f : 0.8f);
    render_target_->DrawLine(D2D1::Point2F(x0, hheader.top), D2D1::Point2F(x0, hex_rect.bottom - 2.0f), brush_border_, thick);
  }

  const std::wstring unknown_hex = L"?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ";
  const std::wstring unknown_ascii = L"????????????????";
  for (size_t row = 0; row < max_hex_rows; ++row) {
    const size_t offset = row * bytes_per_row;
    if (has_mem && offset >= mem_.size()) {
      break;
    }
    const size_t n = has_mem ? std::min(bytes_per_row, mem_.size() - offset) : bytes_per_row;
    const bool row_selected = has_mem && selected_offset != static_cast<size_t>(-1) &&
                              selected_offset >= offset &&
                              selected_offset < offset + n;
    if (row % 2 == 1) {
      const D2D1_RECT_F row_rect_alt = D2D1::RectF(hex_rect.left + 1.0f, y, hex_rect.right - 1.0f, y + row_h - 1.0f);
      render_target_->FillRectangle(row_rect_alt, brush_panel_);
    }
    if (row_selected) {
      const D2D1_RECT_F row_rect = D2D1::RectF(hex_rect.left + 1.0f, y, hex_rect.right - 1.0f, y + row_h - 1.0f);
      render_target_->FillRectangle(row_rect, brush_select_fill_ ? brush_select_fill_ : brush_panel_);
      render_target_->DrawRectangle(row_rect, brush_select_border_ ? brush_select_border_ : brush_highlight_, 1.0f);
    }
    wchar_t addr[32] = {0};
    std::swprintf(addr,
                  sizeof(addr) / sizeof(wchar_t),
                  L"%08llX",
                  static_cast<unsigned long long>(base_addr_ + offset));
    const std::wstring hex = has_mem ? HexBytes(mem_.data() + offset, n) : unknown_hex;
    const std::wstring asc = has_mem ? AsciiBytes(mem_.data() + offset, n) : unknown_ascii;
    render_target_->DrawTextW(addr,
                              static_cast<UINT32>(wcslen(addr)),
                              font_mono_,
                              D2D1::RectF(hex_rect.left + 8.0f, y, hex_rect.left + 8.0f + addr_w_hex, y + row_h),
                              brush_text_);
    render_target_->DrawTextW(hex.c_str(),
                              static_cast<UINT32>(hex.size()),
                              font_mono_,
                              D2D1::RectF(hex_left, y, hex_left + hex_w, y + row_h),
                              (row_selected || !has_mem) ? brush_highlight_ : brush_muted_);
    render_target_->DrawTextW(asc.c_str(),
                              static_cast<UINT32>(asc.size()),
                              font_mono_,
                              D2D1::RectF(ascii_left, y, hex_rect.right - 10.0f, y + row_h),
                              brush_text_);
    if (row_selected) {
      const size_t idx = selected_offset - offset;
      const float x0 = hex_left + static_cast<float>(idx) * byte_w;
      const D2D1_RECT_F byte_rect = D2D1::RectF(x0, y, x0 + byte_w - 1.0f, y + row_h - 1.0f);
      render_target_->DrawRectangle(byte_rect, brush_highlight_, 1.0f);
      const float ascii_w_cell = ascii_w / 16.0f;
      const float ax0 = ascii_left + static_cast<float>(idx) * ascii_w_cell;
      const D2D1_RECT_F asc_rect = D2D1::RectF(ax0, y, ax0 + ascii_w_cell - 1.0f, y + row_h - 1.0f);
      render_target_->DrawRectangle(asc_rect, brush_highlight_, 1.0f);
    }
    y += row_h;
  }

  const HRESULT hr = render_target_->EndDraw();
  if (hr == D2DERR_RECREATE_TARGET) {
    DiscardDeviceResources();
  }
}

void MemoryViewWindow::RememberNavigation(uint64_t addr) {
  if (nav_history_.empty()) {
    nav_history_.push_back(addr);
    nav_history_pos_ = 0;
    return;
  }
  if (nav_history_pos_ < nav_history_.size() && nav_history_[nav_history_pos_] == addr) {
    return;
  }
  if (nav_history_pos_ + 1 < nav_history_.size()) {
    nav_history_.erase(nav_history_.begin() + static_cast<ptrdiff_t>(nav_history_pos_ + 1), nav_history_.end());
  }
  nav_history_.push_back(addr);
  nav_history_pos_ = nav_history_.size() - 1;
  constexpr size_t kMaxNav = 128;
  if (nav_history_.size() > kMaxNav) {
    const size_t drop = nav_history_.size() - kMaxNav;
    nav_history_.erase(nav_history_.begin(), nav_history_.begin() + static_cast<ptrdiff_t>(drop));
    nav_history_pos_ = nav_history_.size() - 1;
  }
}

bool MemoryViewWindow::FetchProgramCounter(uint64_t* out_pc, std::wstring* out_error) {
  if (out_pc) {
    *out_pc = 0;
  }
  if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
    if (out_error) {
      *out_error = L"未连接";
    }
    return false;
  }
  services::ClientService::RegsSnapshot regs{};
  std::string error;
  if (!service_->FetchRegs(state_->pid, &regs, &error)) {
    if (out_error) {
      *out_error = Utf8ToWide(error);
    }
    return false;
  }
  uint64_t pc = 0;
  if (regs.arch == protocol::RegsArch::ARM64) {
    pc = regs.arm64.pc;
  } else if (regs.arch == protocol::RegsArch::ARM32) {
    pc = regs.arm32.regs[15];
  }
  if (pc == 0) {
    if (out_error) {
      *out_error = L"PC 无效";
    }
    return false;
  }
  if (out_pc) {
    *out_pc = pc;
  }
  return true;
}

void MemoryViewWindow::JumpToInternal(uint64_t addr, bool remember_history) {
  if (addr == base_addr_) {
    selected_disasm_addr_ = addr;
    if (remember_history) {
      RememberNavigation(addr);
    }
    UpdateRegionInfo();
    InvalidateRect(hwnd_, nullptr, FALSE);
    return;
  }
  base_addr_ = addr;
  selected_disasm_addr_ = addr;
  wchar_t buf[64] = {0};
  std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(base_addr_));
  if (addr_edit_) {
    SetWindowTextW(addr_edit_, buf);
  }
  if (remember_history) {
    RememberNavigation(addr);
  }
  RefreshData();
}

void MemoryViewWindow::ScrollLines(int delta_lines) {
  if (delta_lines == 0) {
    return;
  }
  uint64_t next = 0;
  const int64_t delta = static_cast<int64_t>(delta_lines) * 16;
  if (delta < 0 && base_addr_ < static_cast<uint64_t>(-delta)) {
    next = 0;
  } else {
    next = static_cast<uint64_t>(static_cast<int64_t>(base_addr_) + delta);
  }
  JumpToInternal(next, false);
}

void MemoryViewWindow::JumpTo(uint64_t addr) { JumpToInternal(addr, true); }

LRESULT CALLBACK MemoryViewWindow::StaticWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  MemoryViewWindow* self = reinterpret_cast<MemoryViewWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (msg == WM_NCCREATE) {
    const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    self = reinterpret_cast<MemoryViewWindow*>(cs->lpCreateParams);
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

LRESULT MemoryViewWindow::WndProc(UINT msg, WPARAM wparam, LPARAM lparam) {
  switch (msg) {
    case WM_SIZE: {
      if (render_target_) {
        render_target_->Resize(D2D1::SizeU(LOWORD(lparam), HIWORD(lparam)));
      }
      LayoutTopControls();
      InvalidateRect(hwnd_, nullptr, FALSE);
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
      HFONT font = ctrl_font_ ? ctrl_font_ : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
      if (addr_edit_) {
        SendMessageW(addr_edit_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
      }
      if (goto_btn_) {
        SendMessageW(goto_btn_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
      }
      ApplyMenuIcons();
      UpdateMenuEnabledState();
      LayoutTopControls();
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
      InvalidateRect(hwnd_, nullptr, FALSE);
      return 0;
    }
    case WM_MOUSEWHEEL: {
      const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
      ScrollLines(delta > 0 ? -4 : 4);
      return 0;
    }
    case WM_LBUTTONDOWN: {
      const POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      uint64_t addr = 0;
      if (HitTestDisasmRow(pt, &addr)) {
        selected_disasm_addr_ = addr;
        UpdateRegionInfo();
        UpdateSelectedAddressStatus();
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      break;
    }
    case WM_KEYDOWN:
      if ((GetKeyState(VK_CONTROL) & 0x8000) != 0) {
        if (wparam == 'G') {
          SendMessageW(hwnd_, WM_COMMAND, kMenuJump, 0);
          return 0;
        }
        if (wparam == 'C') {
          const uint64_t addr = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
          wchar_t addr_buf[64] = {0};
          std::swprintf(addr_buf, sizeof(addr_buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(addr));
          if (CopyTextToClipboard(addr_buf)) {
            status_ = L"地址已复制";
          } else {
            status_ = L"复制失败";
          }
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (wparam == 'F') {
          if ((GetKeyState(VK_SHIFT) & 0x8000) != 0) {
            SendMessageW(hwnd_, WM_COMMAND, kMenuFindAsm, 0);
          } else {
            SendMessageW(hwnd_, WM_COMMAND, kMenuFindHex, 0);
          }
          return 0;
        }
        if (wparam == 'H') {
          SendMessageW(hwnd_, WM_COMMAND, kMenuHexEdit, 0);
          return 0;
        }
      }
      if ((GetKeyState(VK_CONTROL) & 0x8000) == 0 &&
          (GetKeyState(VK_MENU) & 0x8000) == 0 &&
          wparam == 'G') {
        SendMessageW(hwnd_, WM_COMMAND, kMenuJump, 0);
        return 0;
      }
      if (wparam == VK_F2) {
        if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        const uint64_t addr = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
        if (addr == 0) {
          status_ = L"无效地址";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        auto it = breakpoints_.find(addr);
        std::string error;
        if (it != breakpoints_.end()) {
          if (service_->ClearBreakpoint(state_->pid,
                                        it->second,
                                        protocol::DebugBpType::DEBUG_BP_EXEC,
                                        4,
                                        0,
                                        addr,
                                        &error)) {
            breakpoints_.erase(it);
            status_ = L"断点已清除";
          } else {
            status_ = Utf8ToWide(error);
          }
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        bool ok = service_->SetBreakpoint(state_->pid,
                                          protocol::DebugBackend::DEBUG_BACKEND_PERF,
                                          protocol::DebugBpType::DEBUG_BP_EXEC,
                                          4,
                                          protocol::DEBUG_BP_FLAG_STOP_ON_HIT,
                                          addr,
                                          &error);
        protocol::DebugBackend backend_used = protocol::DebugBackend::DEBUG_BACKEND_PERF;
        if (!ok) {
          ok = service_->SetBreakpoint(state_->pid,
                                       protocol::DebugBackend::DEBUG_BACKEND_PTRACE,
                                       protocol::DebugBpType::DEBUG_BP_EXEC,
                                       4,
                                       protocol::DEBUG_BP_FLAG_STOP_ON_HIT,
                                       addr,
                                       &error);
          backend_used = protocol::DebugBackend::DEBUG_BACKEND_PTRACE;
        }
        if (ok) {
          breakpoints_[addr] = backend_used;
          status_ = L"断点已设置";
        } else {
          status_ = Utf8ToWide(error);
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (wparam == VK_F9) {
        SendMessageW(hwnd_, WM_COMMAND, kMenuDebugRun, 0);
        return 0;
      }
      if (wparam == VK_F7 || wparam == VK_F8) {
        status_ = L"单步调试暂未支持";
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (wparam == VK_NEXT) {
        ScrollLines(16);
        return 0;
      }
      if (wparam == VK_PRIOR) {
        ScrollLines(-16);
        return 0;
      }
      if (wparam == VK_UP || wparam == VK_DOWN) {
        if (disasm_.empty()) {
          uint64_t current = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
          if (wparam == VK_UP) {
            if (current > 0) {
              --current;
            }
          } else {
            ++current;
          }
          selected_disasm_addr_ = current;
          wchar_t buf[64] = {0};
          std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(selected_disasm_addr_));
          if (addr_edit_) {
            SetWindowTextW(addr_edit_, buf);
          }
          UpdateRegionInfo();
          UpdateSelectedAddressStatus();
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        size_t idx = 0;
        uint64_t current = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : disasm_.front().addr;
        while (idx + 1 < disasm_.size() && disasm_[idx].addr < current) {
          ++idx;
        }
        if (wparam == VK_UP) {
          if (idx > 0) {
            --idx;
          }
        } else if (idx + 1 < disasm_.size()) {
          ++idx;
        }
        selected_disasm_addr_ = disasm_[idx].addr;
        wchar_t buf[64] = {0};
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(selected_disasm_addr_));
        if (addr_edit_) {
          SetWindowTextW(addr_edit_, buf);
        }
        UpdateRegionInfo();
        UpdateSelectedAddressStatus();
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (wparam == VK_RETURN) {
        const uint64_t addr = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
        JumpTo(addr);
        return 0;
      }
      if (wparam == VK_APPS || (wparam == VK_F10 && (GetKeyState(VK_SHIFT) & 0x8000) != 0)) {
        uint64_t current = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : (disasm_.empty() ? base_addr_ : disasm_.front().addr);
        size_t idx = 0;
        if (!disasm_.empty()) {
          while (idx + 1 < disasm_.size() && disasm_[idx].addr < current) {
            ++idx;
          }
        }
        RECT rc{};
        GetClientRect(hwnd_, &rc);
        const float top_h = kMvTopBarHeight * dpi_scale_;
        const float disasm_hint_h = kMvDisasmHintHeight * dpi_scale_;
        const float section_header_h = kMvSectionHeaderHeight * dpi_scale_;
        const float row_h = kMvRowHeight * dpi_scale_;
        const int x_client = static_cast<int>(std::lround((static_cast<float>(rc.right) * 0.56f) * 0.25f));
        const int y_client = static_cast<int>(std::lround(top_h + disasm_hint_h + section_header_h + idx * row_h + row_h * 0.5f));
        POINT screen_pt{x_client, y_client};
        ClientToScreen(hwnd_, &screen_pt);
        SendMessageW(hwnd_,
                     WM_CONTEXTMENU,
                     reinterpret_cast<WPARAM>(hwnd_),
                     MAKELPARAM(static_cast<short>(screen_pt.x), static_cast<short>(screen_pt.y)));
        return 0;
      }
      if (wparam == VK_F5) {
        RefreshData();
        return 0;
      }
      break;
    case WM_CONTEXTMENU: {
      POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      if (pt.x == -1 && pt.y == -1) {
        GetCursorPos(&pt);
      }
      POINT client_pt = pt;
      ScreenToClient(hwnd_, &client_pt);
      uint64_t addr = 0;
      std::wstring bytes;
      if (!HitTestContext(client_pt, &addr, &bytes)) {
        addr = selected_disasm_addr_;
        if (addr < base_addr_ || addr >= base_addr_ + std::max<uint64_t>(1, static_cast<uint64_t>(mem_.size()))) {
          addr = base_addr_;
        }
        if (addr >= base_addr_ && addr < base_addr_ + mem_.size()) {
          const size_t off = static_cast<size_t>(addr - base_addr_);
          const size_t n = std::min<size_t>(16, mem_.size() - off);
          bytes = HexBytes(mem_.data() + off, n);
        }
      }
      selected_disasm_addr_ = addr;
      UpdateRegionInfo();
      context_addr_ = addr;
      context_bytes_ = bytes;
      HMENU menu = CreatePopupMenu();
      AppendMenuW(menu, MF_STRING, kMenuCtxCopyAddr, L"复制地址");
      AppendMenuW(menu, MF_STRING, kMenuCtxCopyBytes, L"复制字节");
      AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
      AppendMenuW(menu, MF_STRING, kMenuCtxJumpAddr, L"跳转地址...");
      AppendMenuW(menu, MF_STRING, kMenuCtxDisasmHere, L"反汇编到此");
      AppendMenuW(menu, MF_STRING, kMenuCtxAddToList, L"添加到地址表");
      AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
      AppendMenuW(menu, MF_STRING, kMenuCtxNop, L"写入NOP");
      AppendMenuW(menu, MF_STRING, kMenuCtxRestore, L"恢复原字节");
      const UINT cmd = TrackPopupMenu(menu,
                                      TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN | TPM_TOPALIGN,
                                      pt.x,
                                      pt.y,
                                      0,
                                      hwnd_,
                                      nullptr);
      DestroyMenu(menu);
      if (cmd != 0) {
        SendMessageW(hwnd_, WM_COMMAND, cmd, 0);
      }
      return 0;
    }
    case WM_INITMENUPOPUP: {
      HMENU popup = reinterpret_cast<HMENU>(wparam);
      if (popup == menu_view_ || popup == menu_debug_) {
        UpdateViewMenuChecks();
        UpdateMenuEnabledState();
      }
      if (popup && popup == menu_tool_) {
        EnableMenuItem(menu_tool_, kMenuToolPointerScan, MF_BYCOMMAND | MF_ENABLED);
        EnableMenuItem(menu_tool_, kMenuToolPointerCompare, MF_BYCOMMAND | MF_ENABLED);
        EnableMenuItem(menu_tool_, kMenuToolDataTraverse, MF_BYCOMMAND | MF_ENABLED);
      }
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
      return reinterpret_cast<LRESULT>(ctrl_bg_brush_);
    }
    case WM_COMMAND: {
      const UINT cmd = LOWORD(wparam);
      auto run_jump_dialog = [&](uint64_t preset_addr) -> bool {
        wchar_t preset[64] = {0};
        std::swprintf(preset, std::size(preset), L"0x%llX", static_cast<unsigned long long>(preset_addr));
        std::wstring input;
        if (!PromptInputDialog(hwnd_,
                               L"跳转地址/模块",
                               L"输入地址，或 模块名[:cd|bss|a|code] (默认cd)",
                               preset,
                               &input)) {
          return false;
        }
        uint64_t target = 0;
        std::wstring jump_error;
        if (!ResolveJumpExpression(input, &target, &jump_error)) {
          status_ = jump_error.empty() ? L"跳转失败" : jump_error;
          InvalidateRect(hwnd_, nullptr, FALSE);
          return false;
        }
        JumpTo(target);
        const std::wstring alias = BuildAddressAlias(target);
        if (!alias.empty()) {
          status_ = L"已跳转到 ";
          status_.append(alias);
        } else {
          status_ = L"已跳转";
        }
        return true;
      };
      if (cmd == kMenuReload) {
        RefreshData();
        return 0;
      }
      if (cmd == kMenuJump || cmd == kMenuCtxJumpAddr) {
        const uint64_t current = (cmd == kMenuCtxJumpAddr)
                                     ? context_addr_
                                     : (selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_);
        run_jump_dialog(current);
        return 0;
      }
      if (cmd == kMenuDebugToggleBp) {
        SendMessageW(hwnd_, WM_KEYDOWN, VK_F2, 0);
        return 0;
      }
      if (cmd == kMenuDebugRun) {
        if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (!debug_attached_) {
          status_ = L"当前未处于暂停调试状态";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        std::string error;
        if (service_->DebugDetach(&error)) {
          debug_attached_ = false;
          follow_pc_ = false;
          status_ = L"进程已继续运行";
        } else {
          status_ = Utf8ToWide(error);
        }
        UpdateViewMenuChecks();
        UpdateMenuEnabledState();
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuDebugBreak) {
        if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        std::string error;
        if (!service_->DebugAttach(state_->pid, true, &error)) {
          status_ = Utf8ToWide(error);
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        debug_attached_ = true;
        uint64_t pc = 0;
        std::wstring pc_error;
        if (FetchProgramCounter(&pc, &pc_error) && pc != 0) {
          JumpToInternal(pc, true);
          status_ = L"进程已暂停并定位到PC";
        } else {
          status_ = pc_error.empty() ? L"进程已暂停" : (std::wstring(L"进程已暂停，") + pc_error);
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        UpdateViewMenuChecks();
        UpdateMenuEnabledState();
        return 0;
      }
      if (cmd == kMenuDebugStepIn || cmd == kMenuDebugStepOver) {
        status_ = L"单步调试暂未支持";
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuDebugRunTo || cmd == kMenuDebugSetAddr) {
        status_ = L"当前协议未提供该调试动作";
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuViewAsmHex || cmd == kMenuViewAsmOnly || cmd == kMenuViewHexOnly) {
        if (cmd == kMenuViewAsmHex) {
          disasm_mode_ = DisasmMode::AsmHex;
        } else if (cmd == kMenuViewAsmOnly) {
          disasm_mode_ = DisasmMode::AsmOnly;
        } else {
          disasm_mode_ = DisasmMode::HexOnly;
        }
        UpdateViewMenuChecks();
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuViewBack) {
        if (nav_history_pos_ > 0 && nav_history_pos_ < nav_history_.size()) {
          nav_history_pos_--;
          JumpToInternal(nav_history_[nav_history_pos_], false);
          status_ = L"已后退";
        } else {
          status_ = L"没有更早的历史记录";
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        UpdateMenuEnabledState();
        return 0;
      }
      if (cmd == kMenuViewForward) {
        if (nav_history_pos_ + 1 < nav_history_.size()) {
          nav_history_pos_++;
          JumpToInternal(nav_history_[nav_history_pos_], false);
          status_ = L"已前进";
        } else {
          status_ = L"没有更新的历史记录";
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        UpdateMenuEnabledState();
        return 0;
      }
      if (cmd == kMenuViewBookmark) {
        const uint64_t current = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
        if (current == 0) {
          status_ = L"无有效地址可收藏";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (bookmark_addr_ == current) {
          bookmark_addr_ = 0;
          status_ = L"已取消收藏";
        } else {
          bookmark_addr_ = current;
          status_ = L"已收藏当前地址";
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuViewModules) {
        ShowModuleViewer();
        return 0;
      }
      if (cmd == kMenuViewFollowPc) {
        if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (!follow_pc_) {
          uint64_t pc = 0;
          std::wstring pc_error;
          if (!FetchProgramCounter(&pc, &pc_error) || pc == 0) {
            status_ = pc_error.empty() ? L"读取PC失败" : pc_error;
            InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
          }
          follow_pc_ = true;
          JumpToInternal(pc, true);
          status_ = L"已启用跟随PC";
        } else {
          follow_pc_ = false;
          status_ = L"已关闭跟随PC";
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        UpdateViewMenuChecks();
        UpdateMenuEnabledState();
        return 0;
      }
      if (cmd == kMenuViewModuleStart || cmd == kMenuViewPrevSegment || cmd == kMenuViewNextSegment) {
        if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (!EnsureModulesLoaded()) {
          status_ = L"未获取到内存段";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        bool jumped = false;
        uint64_t target = 0;
        if (cmd == kMenuViewModuleStart) {
          for (const auto& module : modules_) {
            if (base_addr_ >= module.start && base_addr_ < module.end) {
              target = module.start;
              jumped = true;
              break;
            }
          }
        } else if (cmd == kMenuViewPrevSegment) {
          for (const auto& module : modules_) {
            if (module.start >= base_addr_) {
              break;
            }
            target = module.start;
            jumped = true;
          }
        } else {
          for (const auto& module : modules_) {
            if (module.start > base_addr_) {
              target = module.start;
              jumped = true;
              break;
            }
          }
        }
        if (!jumped) {
          if (cmd == kMenuViewModuleStart) {
            status_ = L"当前位置不在已知内存段内";
          } else {
            status_ = (cmd == kMenuViewNextSegment) ? L"已是最后一个内存段" : L"已是第一个内存段";
          }
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        JumpTo(target);
        const std::wstring alias = BuildAddressAlias(target);
        status_ = alias.empty() ? L"已跳转到目标内存段" : (std::wstring(L"已跳转到 ") + alias);
        return 0;
      }
      if (cmd == kMenuToolPointerScan || cmd == kMenuToolPointerCompare || cmd == kMenuToolDataTraverse) {
        UINT owner_cmd = 0;
        const wchar_t* tool_name = L"工具";
        if (cmd == kMenuToolPointerScan) {
          owner_cmd = kMainMenuDebugPointerScan;
          tool_name = L"指针搜索";
        } else if (cmd == kMenuToolPointerCompare) {
          owner_cmd = kMainMenuDebugPointerCompare;
          tool_name = L"指针对比";
        } else {
          owner_cmd = kMainMenuDebugDataTraverse;
          tool_name = L"结构分析";
        }
        if (owner_ && IsWindow(owner_)) {
          PostMessageW(owner_, WM_COMMAND, owner_cmd, 0);
          const bool connected = service_ && state_ && service_->IsConnected() && state_->pid != 0;
          if (connected) {
            status_ = std::wstring(L"已打开") + tool_name;
          } else {
            status_ = std::wstring(L"已打开") + tool_name + L"（提示：附加进程后可执行）";
          }
        } else {
          status_ = std::wstring(tool_name) + L"入口不可用";
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuFindHex) {
        std::wstring input;
        if (!PromptInputDialog(hwnd_, L"查找内存", L"输入 HEX 字节 (例如: 90 90 90)", L"", &input)) {
          return 0;
        }
        std::vector<uint8_t> needle;
        if (!ParseHexBytes(input, &needle)) {
          status_ = L"输入格式错误";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        size_t offset = 0;
        if (FindBytes(mem_, needle, &offset)) {
          const uint64_t addr = base_addr_ + offset;
          JumpTo(addr);
          status_ = L"已定位匹配";
        } else {
          status_ = L"未找到匹配";
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        return 0;
      }
      if (cmd == kMenuFindAsm) {
        std::wstring input;
        if (!PromptInputDialog(hwnd_, L"查找汇编码", L"输入指令或关键字", L"", &input)) {
          return 0;
        }
        uint64_t addr = 0;
        if (FindDisasmText(disasm_, input, &addr)) {
          JumpTo(addr);
          status_ = L"已定位指令";
        } else {
          status_ = L"未找到指令";
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        return 0;
      }
      if (cmd == kMenuHexEdit) {
        if (!service_ || !state_ || !service_->IsConnected() || state_->pid == 0) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        uint64_t addr = selected_disasm_addr_ != 0 ? selected_disasm_addr_ : base_addr_;
        std::wstring preset;
        if (addr >= base_addr_) {
          const uint64_t offset = addr - base_addr_;
          if (offset < mem_.size()) {
            const size_t n = std::min<size_t>(8, mem_.size() - static_cast<size_t>(offset));
            preset = HexBytes(mem_.data() + offset, n);
          }
        }
        std::wstring input;
        if (!PromptInputDialog(hwnd_, L"十六进制编辑", L"输入 HEX 字节 (写入选中地址)", preset.c_str(), &input)) {
          return 0;
        }
        std::vector<uint8_t> bytes;
        if (!ParseHexBytes(input, &bytes)) {
          status_ = L"输入格式错误";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        std::string error;
        if (!service_->WriteMemory(addr, bytes, &error)) {
          status_ = Utf8ToWide(error);
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        status_ = L"写入完成";
        RefreshData();
        return 0;
      }
      if (cmd == kMenuCtxCopyAddr) {
        wchar_t addr_buf[64] = {0};
        std::swprintf(addr_buf, sizeof(addr_buf) / sizeof(wchar_t), L"0x%llX", static_cast<unsigned long long>(context_addr_));
        if (CopyTextToClipboard(addr_buf)) {
          status_ = L"地址已复制";
        } else {
          status_ = L"复制失败";
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuCtxCopyBytes) {
        if (context_bytes_.empty()) {
          status_ = L"没有可复制的字节";
        } else if (CopyTextToClipboard(context_bytes_)) {
          status_ = L"字节已复制";
        } else {
          status_ = L"复制失败";
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
      }
      if (cmd == kMenuCtxDisasmHere) {
        JumpTo(context_addr_);
        return 0;
      }
      if (cmd == kMenuCtxAddToList) {
        if (state_) {
          bool exists = false;
          for (const auto& entry : state_->address_entries) {
            if (entry.addr == context_addr_) {
              exists = true;
              break;
            }
          }
          if (!exists) {
            app::AddressEntry entry{};
            entry.active = false;
            entry.desc = L"Memory View";
            entry.addr = context_addr_;
            entry.type = protocol::ValueType::U32;
            entry.value = L"-";
            state_->address_entries.push_back(std::move(entry));
            status_ = L"已添加到地址表";
          } else {
            status_ = L"地址已存在";
          }
          InvalidateRect(hwnd_, nullptr, FALSE);
        }
        return 0;
      }
      if (cmd == kMenuCtxNop || cmd == kMenuCtxRestore) {
        if (!service_ || !state_ || !service_->IsConnected()) {
          status_ = L"未连接";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (context_addr_ == 0) {
          status_ = L"无效地址";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        if (cmd == kMenuCtxNop) {
          std::vector<uint8_t> nop;
          if (state_->arch == static_cast<uint8_t>(protocol::RegsArch::ARM32)) {
            nop = {0x00, 0xF0, 0x20, 0xE3};
          } else {
            nop = {0x1F, 0x20, 0x03, 0xD5};
          }
          std::vector<uint8_t> original;
          std::string error;
          if (!service_->ReadMemory(context_addr_, static_cast<uint32_t>(nop.size()), true, &original, &error)) {
            status_ = L"读取原字节失败";
            InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
          }
          patch_backup_[context_addr_] = original;
          if (!service_->WriteMemory(context_addr_, nop, &error)) {
            status_ = L"写入NOP失败";
            InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
          }
          status_ = L"已写入NOP";
          RefreshData();
          return 0;
        }
        auto it = patch_backup_.find(context_addr_);
        if (it == patch_backup_.end()) {
          status_ = L"无可恢复字节";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        std::string error;
        if (!service_->WriteMemory(context_addr_, it->second, &error)) {
          status_ = L"恢复失败";
          InvalidateRect(hwnd_, nullptr, FALSE);
          return 0;
        }
        status_ = L"已恢复字节";
        RefreshData();
        return 0;
      }
      break;
    }
    case WM_PAINT: {
      PAINTSTRUCT ps{};
      BeginPaint(hwnd_, &ps);
      if (CreateDeviceResources()) {
        Draw();
      }
      EndPaint(hwnd_, &ps);
      return 0;
    }
    case WM_ERASEBKGND:
      return 1;
    case WM_CLOSE:
      ShowWindow(hwnd_, SW_HIDE);
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd_, msg, wparam, lparam);
}

}  // namespace r3::windows_client_ng::memory_view
