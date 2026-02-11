#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include <objbase.h>

#include "ui/CeLayoutWindow.h"

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE,
                     LPSTR,
                     int nCmdShow) {
  if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
    using SetDpiContextFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
    auto set_ctx = reinterpret_cast<SetDpiContextFn>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
    if (set_ctx) {
      set_ctx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    } else {
      SetProcessDPIAware();
    }
  }
  WSADATA wsa_data{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    return 1;
  }

  HRESULT com_hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(com_hr)) {
    WSACleanup();
    return 2;
  }

  r3::windows_client_ng::ui::CeLayoutWindow app;
  if (!app.Create(hInstance, nCmdShow)) {
    CoUninitialize();
    WSACleanup();
    return 3;
  }

  int exit_code = app.Run();
  CoUninitialize();
  WSACleanup();
  return exit_code;
}
