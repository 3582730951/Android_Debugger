#pragma once

#include <stdint.h>

#include "R3PluginApi.h"

#ifdef __cplusplus
  #define R3_MODULE_EXTERN_C extern "C"
#else
  #define R3_MODULE_EXTERN_C
#endif

typedef enum R3ModuleEventId {
  R3_MODULE_EVENT_READ_MEM = 1u,
  R3_MODULE_EVENT_WRITE_MEM = 2u,
  R3_MODULE_EVENT_PTR_VERIFY = 3u,
  R3_MODULE_EVENT_ANALYZE = 4u,
} R3ModuleEventId;

typedef enum R3ModuleDispatchResult {
  R3_MODULE_DISPATCH_PASS = 0,     // Use host default flow.
  R3_MODULE_DISPATCH_HANDLED = 1,  // Plugin handled; host should skip default flow.
  R3_MODULE_DISPATCH_ERROR = -1,   // Plugin error; host can show error text to user.
} R3ModuleDispatchResult;

#pragma pack(push, 1)
typedef struct R3ModuleEventContext {
  uint32_t abi_version;
  uint32_t event_id;
  uint32_t flags;
  uint32_t reserved;
  uint64_t pid;
  uint64_t address;
  uint32_t size;
  uint32_t timeout_ms;
  const uint8_t* input_buf;
  uint32_t input_len;
} R3ModuleEventContext;
#pragma pack(pop)

typedef int32_t (*R3ModuleEventCallbackFn)(const R3ModuleEventContext* ctx,
                                           void* user_ctx,
                                           uint8_t** out_buf,
                                           uint32_t* out_len);

typedef struct R3ModuleHostApiV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  int32_t (*register_callback)(uint32_t event_id,
                               R3ModuleEventCallbackFn callback,
                               void* user_ctx);
  void* (*alloc)(uint32_t bytes);
  void (*free_ptr)(void* p);
  void (*log_utf8)(const char* text);
} R3ModuleHostApiV1;

// C-style metadata macros (IDA-like development workflow).
#define module_name(name_literal)                                                     \
  R3_MODULE_EXTERN_C R3_PLUGIN_API const char* module_name_export(void) {            \
    return (name_literal);                                                            \
  }

#define module_version(version_literal)                                               \
  R3_MODULE_EXTERN_C R3_PLUGIN_API const char* module_version_export(void) {          \
    return (version_literal);                                                         \
  }

#define module_author(author_literal)                                                 \
  R3_MODULE_EXTERN_C R3_PLUGIN_API const char* module_author_export(void) {           \
    return (author_literal);                                                          \
  }

#define init_module(init_fn)                                                          \
  R3_MODULE_EXTERN_C R3_PLUGIN_API int init_module_export(void) {                     \
    return (init_fn)();                                                               \
  }

// Optional helper for one-call callback registration.
#define register_module_events(register_fn)                                           \
  R3_MODULE_EXTERN_C R3_PLUGIN_API int register_module_events_export(                 \
      const R3ModuleHostApiV1* host) {                                                \
    return (register_fn)(host);                                                       \
  }

