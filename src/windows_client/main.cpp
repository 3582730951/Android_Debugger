#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <d3d11.h>
#include <tchar.h>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>
#include <chrono>
#include <vector>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "ClientUI.h"
#include "NetClient.h"
#include "../protocol/Protocol.h"

#pragma comment(lib, "d3d11.lib")

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static ULONGLONG g_last_input_ms = 0;
static ID3D11ShaderResourceView* g_svg_icon_srv = nullptr;

struct SvgAtlasUv {
  std::string id;
  float u0 = 0.0f;
  float v0 = 0.0f;
  float u1 = 1.0f;
  float v1 = 1.0f;
};

static std::filesystem::path GetExeDir() {
  std::wstring buf;
  buf.resize(32768);
  const DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
  if (len == 0 || len >= buf.size()) {
    return std::filesystem::current_path();
  }
  buf.resize(len);
  return std::filesystem::path(buf).parent_path();
}

static ImFont* AddFontCandidate(ImGuiIO& io,
                                const std::filesystem::path& path,
                                float size,
                                const ImWchar* ranges) {
  if (!std::filesystem::exists(path)) {
    return nullptr;
  }
  return io.Fonts->AddFontFromFileTTF(path.string().c_str(), size, nullptr, ranges);
}

static ImFont* LoadBestChineseFont(ImGuiIO& io, float size_px) {
  const ImWchar* ranges = io.Fonts->GetGlyphRangesChineseFull();
  const auto exe_dir = GetExeDir();
  const std::vector<std::filesystem::path> candidates = {
    exe_dir / "assets" / "fonts" / "NotoSansSC-Regular.otf",
    exe_dir / "assets" / "fonts" / "NotoSansCJKsc-Regular.otf",
    exe_dir / "assets" / "fonts" / "SourceHanSansCN-Regular.otf",
    "C:\\Windows\\Fonts\\msyh.ttc",
    "C:\\Windows\\Fonts\\msyh.ttf",
    "C:\\Windows\\Fonts\\msyhbd.ttc",
    "C:\\Windows\\Fonts\\msyhbd.ttf",
    "C:\\Windows\\Fonts\\Deng.ttf",
    "C:\\Windows\\Fonts\\Dengb.ttf",
    "C:\\Windows\\Fonts\\simhei.ttf",
    "C:\\Windows\\Fonts\\simsun.ttc",
    "C:\\Windows\\Fonts\\simsunb.ttf",
    "C:\\Windows\\Fonts\\simkai.ttf",
    "C:\\Windows\\Fonts\\Arialuni.ttf"
  };

  for (const auto& path : candidates) {
    ImFont* font = AddFontCandidate(io, path, size_px, ranges);
    if (font) {
      return font;
    }
  }
  return nullptr;
}

static void ApplyToolTheme() {
  ImGuiStyle& style = ImGui::GetStyle();
  style.WindowRounding = 5.0f;
  style.ChildRounding = 5.0f;
  style.FrameRounding = 5.0f;
  style.PopupRounding = 5.0f;
  style.GrabRounding = 4.0f;
  style.ScrollbarRounding = 6.0f;
  style.WindowBorderSize = 0.8f;
  style.ChildBorderSize = 0.0f;
  style.FrameBorderSize = 0.0f;
  style.ItemSpacing = ImVec2(9.0f, 7.0f);
  style.ItemInnerSpacing = ImVec2(7.0f, 4.0f);
  style.CellPadding = ImVec2(8.0f, 5.0f);

  ImVec4* colors = style.Colors;
  colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.12f, 0.14f, 1.00f);
  colors[ImGuiCol_ChildBg] = ImVec4(0.105f, 0.125f, 0.155f, 1.00f);
  colors[ImGuiCol_PopupBg] = ImVec4(0.12f, 0.14f, 0.17f, 0.96f);
  colors[ImGuiCol_Border] = ImVec4(0.26f, 0.31f, 0.36f, 0.55f);
  colors[ImGuiCol_FrameBg] = ImVec4(0.17f, 0.20f, 0.24f, 0.92f);
  colors[ImGuiCol_FrameBgHovered] = ImVec4(0.21f, 0.26f, 0.31f, 0.98f);
  colors[ImGuiCol_FrameBgActive] = ImVec4(0.24f, 0.30f, 0.36f, 1.00f);
  colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.12f, 0.15f, 0.96f);
  colors[ImGuiCol_TitleBgActive] = ImVec4(0.13f, 0.17f, 0.21f, 1.00f);
  colors[ImGuiCol_MenuBarBg] = ImVec4(0.11f, 0.14f, 0.17f, 0.95f);
  colors[ImGuiCol_Button] = ImVec4(0.20f, 0.37f, 0.56f, 0.88f);
  colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.47f, 0.68f, 1.00f);
  colors[ImGuiCol_ButtonActive] = ImVec4(0.19f, 0.34f, 0.51f, 1.00f);
  colors[ImGuiCol_Header] = ImVec4(0.20f, 0.37f, 0.56f, 0.70f);
  colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.47f, 0.68f, 0.85f);
  colors[ImGuiCol_HeaderActive] = ImVec4(0.20f, 0.37f, 0.56f, 1.00f);
  colors[ImGuiCol_Separator] = ImVec4(0.24f, 0.29f, 0.35f, 0.45f);
  colors[ImGuiCol_Tab] = ImVec4(0.14f, 0.19f, 0.25f, 1.00f);
  colors[ImGuiCol_TabHovered] = ImVec4(0.20f, 0.34f, 0.50f, 1.00f);
  colors[ImGuiCol_TabActive] = ImVec4(0.21f, 0.38f, 0.57f, 1.00f);
  colors[ImGuiCol_TableHeaderBg] = ImVec4(0.16f, 0.19f, 0.23f, 0.85f);
  colors[ImGuiCol_TableBorderStrong] = ImVec4(0.24f, 0.28f, 0.33f, 0.30f);
  colors[ImGuiCol_TableBorderLight] = ImVec4(0.24f, 0.28f, 0.33f, 0.18f);
  colors[ImGuiCol_TableRowBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.00f);
  colors[ImGuiCol_TableRowBgAlt] = ImVec4(1.0f, 1.0f, 1.0f, 0.02f);
}

static bool LoadSvgIconAtlas(ID3D11Device* device,
                             const std::filesystem::path& atlas_path,
                             ID3D11ShaderResourceView** out_srv,
                             std::vector<SvgAtlasUv>* out_uvs) {
  if (!device || !out_srv || !out_uvs) {
    return false;
  }
  *out_srv = nullptr;
  out_uvs->clear();

  std::ifstream ifs(atlas_path, std::ios::binary);
  if (!ifs.is_open()) {
    return false;
  }
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  if (data.size() < 24) {
    return false;
  }

  auto read_u32 = [&](size_t off) -> uint32_t {
    uint32_t v = 0;
    std::memcpy(&v, data.data() + off, sizeof(v));
    return v;
  };
  auto read_u16 = [&](size_t off) -> uint16_t {
    uint16_t v = 0;
    std::memcpy(&v, data.data() + off, sizeof(v));
    return v;
  };

  if (std::memcmp(data.data(), "R3IA", 4) != 0) {
    return false;
  }
  const uint32_t version = read_u32(4);
  const uint32_t atlas_w = read_u32(8);
  const uint32_t atlas_h = read_u32(12);
  const uint32_t icon_count = read_u32(16);
  const uint32_t table_bytes = read_u32(20);
  if (version != 1 || atlas_w == 0 || atlas_h == 0) {
    return false;
  }

  const size_t table_begin = 24;
  const size_t table_end = table_begin + table_bytes;
  if (table_end > data.size()) {
    return false;
  }

  size_t cursor = table_begin;
  out_uvs->reserve(icon_count);
  for (uint32_t i = 0; i < icon_count; ++i) {
    if (cursor + 12 > table_end) {
      return false;
    }
    const uint16_t name_len = read_u16(cursor + 0);
    const uint16_t x = read_u16(cursor + 4);
    const uint16_t y = read_u16(cursor + 6);
    const uint16_t w = read_u16(cursor + 8);
    const uint16_t h = read_u16(cursor + 10);
    cursor += 12;
    if (cursor + name_len > table_end) {
      return false;
    }
    std::string id(reinterpret_cast<const char*>(data.data() + cursor), name_len);
    cursor += name_len;
    if (w == 0 || h == 0 || x + w > atlas_w || y + h > atlas_h) {
      return false;
    }
    SvgAtlasUv uv;
    uv.id = id;
    uv.u0 = static_cast<float>(x) / static_cast<float>(atlas_w);
    uv.v0 = static_cast<float>(y) / static_cast<float>(atlas_h);
    uv.u1 = static_cast<float>(x + w) / static_cast<float>(atlas_w);
    uv.v1 = static_cast<float>(y + h) / static_cast<float>(atlas_h);
    out_uvs->push_back(std::move(uv));
  }
  if (cursor != table_end) {
    return false;
  }

  const size_t pixel_bytes = static_cast<size_t>(atlas_w) * static_cast<size_t>(atlas_h) * 4u;
  if (table_end + pixel_bytes > data.size()) {
    return false;
  }
  const uint8_t* pixels = data.data() + table_end;

  D3D11_TEXTURE2D_DESC desc{};
  desc.Width = atlas_w;
  desc.Height = atlas_h;
  desc.MipLevels = 1;
  desc.ArraySize = 1;
  desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  desc.SampleDesc.Count = 1;
  desc.Usage = D3D11_USAGE_DEFAULT;
  desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

  D3D11_SUBRESOURCE_DATA init{};
  init.pSysMem = pixels;
  init.SysMemPitch = atlas_w * 4;

  ID3D11Texture2D* texture = nullptr;
  if (device->CreateTexture2D(&desc, &init, &texture) != S_OK || !texture) {
    return false;
  }

  D3D11_SHADER_RESOURCE_VIEW_DESC srv_desc{};
  srv_desc.Format = desc.Format;
  srv_desc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
  srv_desc.Texture2D.MipLevels = 1;
  ID3D11ShaderResourceView* srv = nullptr;
  const HRESULT hr = device->CreateShaderResourceView(texture, &srv_desc, &srv);
  texture->Release();
  if (hr != S_OK || !srv) {
    return false;
  }
  *out_srv = srv;
  return true;
}

static void CreateRenderTarget() {
  ID3D11Texture2D* pBackBuffer = nullptr;
  g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
  if (pBackBuffer) {
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
  }
}

static void CleanupRenderTarget() {
  if (g_mainRenderTargetView) {
    g_mainRenderTargetView->Release();
    g_mainRenderTargetView = nullptr;
  }
}

static bool CreateDeviceD3D(HWND hWnd) {
  DXGI_SWAP_CHAIN_DESC sd{};
  sd.BufferCount = 2;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferDesc.RefreshRate.Numerator = 60;
  sd.BufferDesc.RefreshRate.Denominator = 1;
  sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = hWnd;
  sd.SampleDesc.Count = 1;
  sd.SampleDesc.Quality = 0;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  UINT createDeviceFlags = 0;
  D3D_FEATURE_LEVEL featureLevel;
  const D3D_FEATURE_LEVEL featureLevelArray[1] = { D3D_FEATURE_LEVEL_11_0 };
  if (D3D11CreateDeviceAndSwapChain(nullptr,
                                    D3D_DRIVER_TYPE_HARDWARE,
                                    nullptr,
                                    createDeviceFlags,
                                    featureLevelArray,
                                    1,
                                    D3D11_SDK_VERSION,
                                    &sd,
                                    &g_pSwapChain,
                                    &g_pd3dDevice,
                                    &featureLevel,
                                    &g_pd3dDeviceContext) != S_OK) {
    return false;
  }

  CreateRenderTarget();
  return true;
}

static void CleanupDeviceD3D() {
  CleanupRenderTarget();
  if (g_svg_icon_srv) {
    g_svg_icon_srv->Release();
    g_svg_icon_srv = nullptr;
  }
  if (g_pSwapChain) {
    g_pSwapChain->Release();
    g_pSwapChain = nullptr;
  }
  if (g_pd3dDeviceContext) {
    g_pd3dDeviceContext->Release();
    g_pd3dDeviceContext = nullptr;
  }
  if (g_pd3dDevice) {
    g_pd3dDevice->Release();
    g_pd3dDevice = nullptr;
  }
}

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
    return true;
  }
  switch (msg) {
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
    case WM_MOUSEMOVE:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
    case WM_MBUTTONDOWN:
    case WM_MBUTTONUP:
      g_last_input_ms = GetTickCount64();
      break;
    case WM_SIZE:
      if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
        CleanupRenderTarget();
        g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
        CreateRenderTarget();
      }
      return 0;
    case WM_SYSCOMMAND:
      if ((wParam & 0xfff0) == SC_KEYMENU) {
        return 0;
      }
      break;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProc(hWnd, msg, wParam, lParam);
}

static bool HasFlag(const char* cmd, const char* flag) {
  return cmd && flag && std::strstr(cmd, flag) != nullptr;
}

static bool ParseIntArg(const char* cmd, const char* key, int* out) {
  if (!cmd || !key || !out) {
    return false;
  }
  const char* pos = std::strstr(cmd, key);
  if (!pos) {
    return false;
  }
  pos += std::strlen(key);
  if (*pos != '=') {
    return false;
  }
  ++pos;
  char* endptr = nullptr;
  long v = std::strtol(pos, &endptr, 10);
  if (endptr == pos) {
    return false;
  }
  *out = static_cast<int>(v);
  return true;
}

static bool ParseStringArg(const char* cmd, const char* key, std::string* out) {
  if (!cmd || !key || !out) {
    return false;
  }
  const char* pos = std::strstr(cmd, key);
  if (!pos) {
    return false;
  }
  pos += std::strlen(key);
  if (*pos != '=') {
    return false;
  }
  ++pos;
  const char* end = pos;
  while (*end && !std::isspace(static_cast<unsigned char>(*end))) {
    ++end;
  }
  *out = std::string(pos, end);
  return !out->empty();
}

struct BenchModule {
  uint64_t start = 0;
  uint64_t end = 0;
  uint32_t perms = 0;
  std::string path;
};

static bool FetchProcessList(NetClient& client, std::vector<std::pair<uint32_t, std::string>>* out) {
  if (!out) {
    return false;
  }
  protocol::ProcessListRequest req{};
  req.max_count = 4096;
  req.reserved = 0;
  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!client.SendAndReceive(protocol::CommandType::CMD_LIST_PROCESSES,
                             &req,
                             sizeof(req),
                             &header,
                             &payload)) {
    return false;
  }
  if (payload.size() < sizeof(protocol::ProcessListHeader)) {
    return false;
  }
  out->clear();
  const auto* hdr = reinterpret_cast<const protocol::ProcessListHeader*>(payload.data());
  size_t offset = sizeof(protocol::ProcessListHeader);
  uint32_t parsed = 0;
  while (offset + offsetof(protocol::ProcessEntry, name) <= payload.size()) {
    if (hdr->count != 0 && parsed >= hdr->count) {
      break;
    }
    const auto* entry = reinterpret_cast<const protocol::ProcessEntry*>(payload.data() + offset);
    const size_t header_size = offsetof(protocol::ProcessEntry, name);
    const size_t total_size = header_size + entry->name_len;
    if (offset + total_size > payload.size()) {
      break;
    }
    std::string name(reinterpret_cast<const char*>(entry->name), entry->name_len);
    out->push_back({entry->pid, name});
    offset += total_size;
    parsed++;
  }
  return !out->empty();
}

static bool FetchModules(NetClient& client, uint32_t pid, std::vector<BenchModule>* out) {
  if (!out) {
    return false;
  }
  protocol::ModuleListRequest req{};
  req.pid = pid;
  req.reserved = 0;
  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!client.SendAndReceive(protocol::CommandType::CMD_LIST_MODULES,
                             &req,
                             sizeof(req),
                             &header,
                             &payload)) {
    return false;
  }
  if (payload.size() < sizeof(protocol::ModuleListHeader)) {
    return false;
  }
  out->clear();
  const auto* hdr = reinterpret_cast<const protocol::ModuleListHeader*>(payload.data());
  size_t offset = sizeof(protocol::ModuleListHeader);
  uint32_t parsed = 0;
  while (offset + offsetof(protocol::ModuleEntry, path) <= payload.size()) {
    if (hdr->count != 0 && parsed >= hdr->count) {
      break;
    }
    const auto* entry = reinterpret_cast<const protocol::ModuleEntry*>(payload.data() + offset);
    const size_t header_size = offsetof(protocol::ModuleEntry, path);
    const size_t total_size = header_size + entry->path_len;
    if (offset + total_size > payload.size()) {
      break;
    }
    BenchModule mod;
    mod.start = entry->start;
    mod.end = entry->end;
    mod.perms = entry->perms;
    if (entry->path_len > 0) {
      mod.path.assign(reinterpret_cast<const char*>(entry->path), entry->path_len);
    }
    out->push_back(std::move(mod));
    offset += total_size;
    parsed++;
  }
  return !out->empty();
}

static bool ReadMemoryOnce(NetClient& client, uint64_t addr, uint32_t size, uint32_t flags, uint32_t* out_read) {
  protocol::ReadMemRequest req{};
  req.address = addr;
  req.size = size;
  req.reserved = flags;
  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!client.SendAndReceive(protocol::CommandType::CMD_READ_MEM,
                             &req,
                             sizeof(req),
                             &header,
                             &payload)) {
    return false;
  }
  if (payload.size() < offsetof(protocol::ReadMemResponse, data)) {
    return false;
  }
  const auto* resp = reinterpret_cast<const protocol::ReadMemResponse*>(payload.data());
  if (resp->code != 0) {
    return false;
  }
  if (out_read) {
    *out_read = resp->bytes_read;
  }
  return true;
}

static int RunCompressionBench(const char* cmdline) {
  int seconds = 10;
  int size = 1024 * 1024;
  int iterations = 0;
  int port = 12345;
  ParseIntArg(cmdline, "--bench-seconds", &seconds);
  ParseIntArg(cmdline, "--bench-size", &size);
  ParseIntArg(cmdline, "--bench-iter", &iterations);
  ParseIntArg(cmdline, "--bench-port", &port);

  const bool mode_off = HasFlag(cmdline, "--bench-mode=off");
  const bool mode_on = HasFlag(cmdline, "--bench-mode=on");
  const bool run_both = !(mode_off || mode_on);

  NetClient client;
  if (!client.Connect("127.0.0.1", static_cast<uint16_t>(port))) {
    std::printf("BENCH error=connect_failed\n");
    return 1;
  }

  std::vector<std::pair<uint32_t, std::string>> procs;
  if (!FetchProcessList(client, &procs)) {
    std::printf("BENCH error=process_list_failed\n");
    return 1;
  }
  uint32_t pid = 0;
  for (const auto& p : procs) {
    if (p.second.find("com.r3.debugprobe") != std::string::npos) {
      pid = p.first;
      break;
    }
  }
  if (pid == 0) {
    std::printf("BENCH error=pid_not_found\n");
    return 1;
  }

  protocol::AttachRequest areq{};
  areq.pid = pid;
  areq.reserved = 0;
  protocol::PacketHeader header{};
  std::vector<uint8_t> payload;
  if (!client.SendAndReceive(protocol::CommandType::CMD_ATTACH,
                             &areq,
                             sizeof(areq),
                             &header,
                             &payload)) {
    std::printf("BENCH error=attach_failed\n");
    return 1;
  }

  std::vector<BenchModule> modules;
  if (!FetchModules(client, pid, &modules)) {
    std::printf("BENCH error=module_list_failed\n");
    return 1;
  }
  BenchModule best{};
  uint64_t best_size = 0;
  for (const auto& mod : modules) {
    if ((mod.perms & protocol::MODULE_PERM_READ) == 0) {
      continue;
    }
    const uint64_t mod_size = mod.end > mod.start ? (mod.end - mod.start) : 0;
    if (mod_size >= static_cast<uint64_t>(size) && mod_size > best_size) {
      best = mod;
      best_size = mod_size;
    }
  }
  if (best_size == 0) {
    std::printf("BENCH error=no_readable_range\n");
    return 1;
  }

  auto run_case = [&](const char* label, bool no_compress) {
    const uint32_t flags = protocol::READ_FLAG_USE_PVM |
                           (no_compress ? protocol::READ_FLAG_NO_COMPRESS : 0u);
    uint64_t addr = best.start;
    uint64_t bytes = 0;
    size_t iters = 0;
    int errors = 0;
    const auto t0 = std::chrono::steady_clock::now();
    while (true) {
      uint32_t read = 0;
      if (!ReadMemoryOnce(client, addr, static_cast<uint32_t>(size), flags, &read)) {
        if (++errors > 10) {
          break;
        }
      } else {
        bytes += read;
      }
      addr += static_cast<uint64_t>(size);
      if (addr + static_cast<uint64_t>(size) > best.end) {
        addr = best.start;
      }
      ++iters;
      if (iterations > 0 && static_cast<int>(iters) >= iterations) {
        break;
      }
      if (seconds > 0) {
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - t0).count();
        if (elapsed >= static_cast<double>(seconds)) {
          break;
        }
      }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double elapsed = std::chrono::duration<double>(t1 - t0).count();
    const double mbps = elapsed > 0.0 ? (static_cast<double>(bytes) / (1024.0 * 1024.0)) / elapsed : 0.0;
    std::printf("BENCH mode=%s size=%d bytes=%llu iters=%zu seconds=%.3f mbps=%.2f\n",
                label,
                size,
                static_cast<unsigned long long>(bytes),
                iters,
                elapsed,
                mbps);
  };

  if (run_both || mode_off) {
    run_case("off", true);
  }
  if (run_both || mode_on) {
    run_case("on", false);
  }
  return 0;
}

static int RunPointerBench(const char* cmdline) {
  int seconds = 600;
  int depth = 5;
  int port = 12345;
  int strict_mode = 1;
  ParseIntArg(cmdline, "--bench-seconds", &seconds);
  ParseIntArg(cmdline, "--bench-depth", &depth);
  ParseIntArg(cmdline, "--bench-port", &port);
  ParseIntArg(cmdline, "--bench-pointer-strict", &strict_mode);
  const bool strict = strict_mode != 0;

  std::string mode = "scan";
  ParseStringArg(cmdline, "--bench-pointer-mode", &mode);

  std::string file;
  ParseStringArg(cmdline, "--bench-pointer-file", &file);
  if (file.empty()) {
    file = std::string("seach_point/bench_ptr_d") + std::to_string(depth) + ".r3p";
  }

  ClientUI ui(false);
  ui.SetServer("127.0.0.1", port);

  ClientUI::PointerBenchResult result{};
  bool ok = false;
  if (mode == "scan" || mode == "scan_raw") {
    ok = ui.RunPointerScanBench(seconds, depth, file, &result, false, strict);
  } else if (mode == "scan_index") {
    ok = ui.RunPointerScanBench(seconds, depth, file, &result, true, strict);
  } else if (mode == "compare") {
    ok = ui.RunPointerCompareBench(seconds, depth, file, file, &result);
  } else if (mode == "verify") {
    ok = ui.RunPointerVerifyBench(seconds, file, &result);
  } else {
    std::printf("BENCHPTR error=unknown_mode\n");
    return 1;
  }

  if (!ok) {
    std::printf("BENCHPTR mode=%s error=%s\n", mode.c_str(), result.status.c_str());
    return 1;
  }
  std::printf("BENCHPTR mode=%s depth=%d seconds=%.3f iterations=%llu chains=%llu ops=%.2f file=%s use_index=%u strict=%u connect_ms=%.3f attach_ms=%.3f scan_ms=%.3f verify_ms=%.3f packets=%llu req_bytes=%llu rsp_bytes=%llu read_calls=%llu read_bytes=%llu avg_chunk=%.2f\n",
              mode.c_str(),
              result.depth,
              result.seconds,
              static_cast<unsigned long long>(result.iterations),
              static_cast<unsigned long long>(result.chains),
              result.ops_per_sec,
              result.file.c_str(),
              result.use_index ? 1u : 0u,
              result.strict_mode ? 1u : 0u,
              result.connect_ms,
              result.attach_ms,
              result.scan_ms,
              result.verify_ms,
              static_cast<unsigned long long>(result.net_packets),
              static_cast<unsigned long long>(result.net_req_bytes),
              static_cast<unsigned long long>(result.net_rsp_bytes),
              static_cast<unsigned long long>(result.read_calls),
              static_cast<unsigned long long>(result.read_bytes),
              result.avg_chunk_bytes);
  return 0;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int) {
  if (HasFlag(lpCmdLine, "--bench-compress")) {
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      return 1;
    }
    const int rc = RunCompressionBench(lpCmdLine);
    WSACleanup();
    return rc;
  }
  if (HasFlag(lpCmdLine, "--bench-pointer")) {
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      return 1;
    }
    const int rc = RunPointerBench(lpCmdLine);
    WSACleanup();
    return rc;
  }

  WSADATA wsaData{};
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    return 1;
  }

  WNDCLASSEXW wc = {
    sizeof(WNDCLASSEXW),
    CS_CLASSDC,
    WndProc,
    0L,
    0L,
    GetModuleHandle(nullptr),
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    L"R3DebugClient",
    nullptr
  };
  RegisterClassExW(&wc);
  HWND hwnd = CreateWindowW(wc.lpszClassName, L"R3 安卓调试客户端", WS_OVERLAPPEDWINDOW,
                           100, 100, 1280, 720, nullptr, nullptr, wc.hInstance, nullptr);

  if (!CreateDeviceD3D(hwnd)) {
    CleanupDeviceD3D();
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 1;
  }

  ShowWindow(hwnd, SW_SHOWDEFAULT);
  UpdateWindow(hwnd);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  ImFont* font = LoadBestChineseFont(io, 18.0f);
  if (font) {
    io.FontDefault = font;
  } else {
    io.Fonts->AddFontDefault();
  }
  ApplyToolTheme();

  ImGui_ImplWin32_Init(hwnd);
  ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

  const bool auto_mode = (lpCmdLine && std::strstr(lpCmdLine, "--auto") != nullptr);
  ClientUI ui(auto_mode);
  std::vector<SvgAtlasUv> icon_uvs;
  const std::filesystem::path atlas_path = GetExeDir() / "generated" / "icons" / "IconAtlas.bin";
  if (LoadSvgIconAtlas(g_pd3dDevice, atlas_path, &g_svg_icon_srv, &icon_uvs)) {
    ui.SetSvgAtlasTexture(g_svg_icon_srv);
    for (const auto& uv : icon_uvs) {
      ui.SetSvgAtlasIconUv(uv.id.c_str(), uv.u0, uv.v0, uv.u1, uv.v1);
    }
  }
  g_last_input_ms = GetTickCount64();

  bool done = false;
  while (!done) {
    const auto frame_begin = std::chrono::steady_clock::now();
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
      if (msg.message == WM_QUIT) {
        done = true;
      }
    }
    if (done) {
      break;
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ui.Render();
    if (ui.RequestQuit()) {
      done = true;
    }

    ImGui::Render();
    const float clear_color_with_alpha[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
    g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
    g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_pSwapChain->Present(1, 0);

    const bool focused = (GetForegroundWindow() == hwnd);
    const bool minimized = (IsIconic(hwnd) != FALSE);
    const ULONGLONG now_input_ms = GetTickCount64();
    const ULONGLONG idle_ms = now_input_ms - g_last_input_ms;
    int target_fps = 60;
    if (minimized) {
      target_fps = 10;
    } else if (!focused) {
      target_fps = 20;
    } else if (idle_ms > 3000) {
      target_fps = 15;
    }
    if (target_fps < 1) {
      target_fps = 1;
    }
    const int frame_budget_ms = 1000 / target_fps;
    const auto frame_end = std::chrono::steady_clock::now();
    const int elapsed_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(frame_end - frame_begin).count());
    if (elapsed_ms < frame_budget_ms) {
      Sleep(static_cast<DWORD>(frame_budget_ms - elapsed_ms));
    }
  }

  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();

  CleanupDeviceD3D();
  DestroyWindow(hwnd);
  UnregisterClassW(wc.lpszClassName, wc.hInstance);

  WSACleanup();
  return 0;
}
