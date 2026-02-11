#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "plugin_sdk/R3ModuleCompat.h"

namespace {

enum Mode {
  kPass = 0,
  kHandled = 1,
  kError = 2,
};

int g_read_mode = kHandled;
int g_write_mode = kHandled;
uint8_t g_read_fill = 0xAB;
R3HostAllocFn g_alloc = nullptr;
R3HostFreeFn g_free = nullptr;

int ParseMode(const char* text, int fallback) {
  if (!text || *text == '\0') {
    return fallback;
  }
  if (std::strcmp(text, "0") == 0) {
    return kPass;
  }
  if (std::strcmp(text, "1") == 0) {
    return kHandled;
  }
  if (std::strcmp(text, "2") == 0) {
    return kError;
  }
  if (_stricmp(text, "pass") == 0) {
    return kPass;
  }
  if (_stricmp(text, "handled") == 0) {
    return kHandled;
  }
  if (_stricmp(text, "error") == 0) {
    return kError;
  }
  return fallback;
}

uint8_t ParseReadFill(const char* text, uint8_t fallback) {
  if (!text || *text == '\0') {
    return fallback;
  }
  char* end = nullptr;
  const unsigned long raw = std::strtoul(text, &end, 0);
  if (end == text || raw > 0xFFu) {
    return fallback;
  }
  return static_cast<uint8_t>(raw);
}

uint8_t* AllocBytes(uint32_t len) {
  if (len == 0u) {
    return nullptr;
  }
  if (g_alloc) {
    return static_cast<uint8_t*>(g_alloc(len));
  }
  return static_cast<uint8_t*>(std::malloc(len));
}

void WriteOut(uint8_t** out_buf, uint32_t* out_len, uint8_t* buf, uint32_t len) {
  if (out_buf) {
    *out_buf = buf;
  }
  if (out_len) {
    *out_len = len;
  }
}

int32_t ReturnErrorText(const char* text, uint8_t** out_buf, uint32_t* out_len) {
  const char* msg = text ? text : "plugin forced error";
  const uint32_t len = static_cast<uint32_t>(std::strlen(msg));
  uint8_t* buf = AllocBytes(len);
  if (len > 0u && buf) {
    std::memcpy(buf, msg, len);
  }
  WriteOut(out_buf, out_len, buf, len);
  return static_cast<int32_t>(R3_MODULE_DISPATCH_ERROR);
}

int32_t OnReadEvent(const R3ModuleEventContext* ctx,
                    void* user_ctx,
                    uint8_t** out_buf,
                    uint32_t* out_len) {
  const int mode = user_ctx ? *reinterpret_cast<int*>(user_ctx) : g_read_mode;
  if (mode == kPass) {
    WriteOut(out_buf, out_len, nullptr, 0u);
    return static_cast<int32_t>(R3_MODULE_DISPATCH_PASS);
  }
  if (mode == kError) {
    return ReturnErrorText("read forced error", out_buf, out_len);
  }
  if (!ctx) {
    return ReturnErrorText("read context missing", out_buf, out_len);
  }
  const uint32_t len = ctx->size;
  uint8_t* buf = AllocBytes(len);
  if (len > 0u && !buf) {
    return ReturnErrorText("read alloc failed", out_buf, out_len);
  }
  if (len > 0u) {
    std::memset(buf, g_read_fill, len);
  }
  WriteOut(out_buf, out_len, buf, len);
  return static_cast<int32_t>(R3_MODULE_DISPATCH_HANDLED);
}

int32_t OnWriteEvent(const R3ModuleEventContext*,
                     void* user_ctx,
                     uint8_t** out_buf,
                     uint32_t* out_len) {
  const int mode = user_ctx ? *reinterpret_cast<int*>(user_ctx) : g_write_mode;
  if (mode == kPass) {
    WriteOut(out_buf, out_len, nullptr, 0u);
    return static_cast<int32_t>(R3_MODULE_DISPATCH_PASS);
  }
  if (mode == kError) {
    return ReturnErrorText("write forced error", out_buf, out_len);
  }
  WriteOut(out_buf, out_len, nullptr, 0u);
  return static_cast<int32_t>(R3_MODULE_DISPATCH_HANDLED);
}

int RegisterEvents(const R3ModuleHostApiV1* host) {
  if (!host || !host->register_callback) {
    return -1;
  }
  const int rc_read =
      host->register_callback(static_cast<uint32_t>(R3_MODULE_EVENT_READ_MEM), &OnReadEvent, &g_read_mode);
  if (rc_read != 0) {
    return rc_read;
  }
  const int rc_write =
      host->register_callback(static_cast<uint32_t>(R3_MODULE_EVENT_WRITE_MEM), &OnWriteEvent, &g_write_mode);
  if (rc_write != 0) {
    return rc_write;
  }
  return 0;
}

}  // namespace

extern "C" R3_PLUGIN_API int R3Plugin_Query(R3PluginInfo* out_info) {
  if (!out_info) {
    return -1;
  }
  out_info->abi_version = 1;
  out_info->struct_size = sizeof(R3PluginInfo);
  out_info->capability_flags = static_cast<uint32_t>(R3_CAP_MEMORY_PROVIDER);
  out_info->reserved = 0;
  out_info->plugin_id = "com.r3.e2e.override";
  out_info->plugin_name = "R3 Override E2E Plugin";
  out_info->plugin_version = "1.0.0";
  return 0;
}

extern "C" R3_PLUGIN_API int R3Plugin_Init(const R3HostApi* host) {
  g_alloc = host ? host->alloc : nullptr;
  g_free = host ? host->free_ptr : nullptr;
  return 0;
}

extern "C" R3_PLUGIN_API int R3Plugin_Start(void) {
  g_read_mode = ParseMode(std::getenv("R3_E2E_READ_MODE"), kHandled);
  g_write_mode = ParseMode(std::getenv("R3_E2E_WRITE_MODE"), kHandled);
  g_read_fill = ParseReadFill(std::getenv("R3_E2E_READ_FILL"), 0xAB);
  return 0;
}

extern "C" R3_PLUGIN_API int R3Plugin_Stop(void) {
  return 0;
}

extern "C" R3_PLUGIN_API void R3Plugin_Free(void* p) {
  if (!p) {
    return;
  }
  if (g_free) {
    g_free(p);
    return;
  }
  std::free(p);
}

module_name("com.r3.e2e.override");
module_version("1.0.0");
module_author("R3 QA");
register_module_events(RegisterEvents);
