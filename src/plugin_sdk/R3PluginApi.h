#pragma once

#include <stdint.h>

#if defined(_WIN32)
  #if defined(R3_PLUGIN_EXPORTS)
    #define R3_PLUGIN_API __declspec(dllexport)
  #else
    #define R3_PLUGIN_API __declspec(dllimport)
  #endif
#else
  #define R3_PLUGIN_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum R3PluginCapability : uint32_t {
  R3_CAP_MEMORY_PROVIDER = 1u << 0,
  R3_CAP_SYSCALL_BRIDGE = 1u << 1,
  R3_CAP_ANALYSIS_TRANSLATE = 1u << 2,
  R3_CAP_ANALYSIS_VMP = 1u << 3,
  R3_CAP_ANALYSIS_ANNOTATION = 1u << 4,
};

enum R3MemOpCode : uint32_t {
  R3_MEM_OP_READ = 1u,
  R3_MEM_OP_WRITE = 2u,
};

enum R3MemOpResult : int32_t {
  R3_MEM_OK = 0,
  R3_MEM_E_INVALID = -1,
  R3_MEM_E_UNSUPPORTED = -2,
  R3_MEM_E_TIMEOUT = -3,
  R3_MEM_E_DENIED = -4,
  R3_MEM_E_UNREACHABLE = -5,
  R3_MEM_E_INTERNAL = -6,
  R3_MEM_E_FALLBACK = -7,
};

#pragma pack(push, 1)
typedef struct R3PluginInfo {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t capability_flags;
  uint32_t reserved;
  const char* plugin_id;
  const char* plugin_name;
  const char* plugin_version;
} R3PluginInfo;

typedef struct R3SysMemReqV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t op;
  uint32_t flags;
  uint32_t pid;
  uint32_t tid_hint;
  uint64_t address;
  uint32_t size;
  uint32_t timeout_ms;
  uint64_t trace_id;
  uint32_t user_ctx_off;
  uint32_t user_ctx_len;
  uint32_t write_data_off;
  uint32_t write_data_len;
  uint32_t reserved0;
  uint32_t reserved1;
} R3SysMemReqV1;

typedef struct R3SysMemRspV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  int32_t code;
  int32_t provider_errno;
  int32_t sys_errno;
  uint32_t bytes_done;
  uint64_t elapsed_us;
  uint64_t trace_id;
  uint32_t read_data_off;
  uint32_t read_data_len;
  uint32_t extra_off;
  uint32_t extra_len;
} R3SysMemRspV1;

typedef struct R3AnalysisReqV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t arch;          // 1=ARM64, 2=ARM32
  uint32_t reserved;
  uint64_t address;
  uint32_t flags;
  uint32_t bytes_off;
  uint32_t bytes_len;
  uint32_t regs_off;
  uint32_t regs_len;
  uint32_t memory_off;
  uint32_t memory_len;
  uint32_t reserved0;
  uint32_t reserved1;
  uint8_t payload[1];     // bytes + regs + memory
} R3AnalysisReqV1;

typedef struct R3AnalysisRspV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  int32_t code;
  int32_t confidence;     // 0..100
  uint32_t primary_off;   // utf8
  uint32_t primary_len;
  uint32_t ir_off;        // utf8
  uint32_t ir_len;
  uint32_t tags_off;      // utf8 comma-separated
  uint32_t tags_len;
  uint32_t reserved0;
  uint32_t reserved1;
  uint8_t payload[1];
} R3AnalysisRspV1;
#pragma pack(pop)

typedef void* (*R3HostAllocFn)(uint32_t bytes);
typedef void (*R3HostFreeFn)(void* p);

typedef struct R3HostApi {
  uint32_t abi_version;
  uint32_t struct_size;
  R3HostAllocFn alloc;
  R3HostFreeFn free_ptr;
  void (*log_utf8)(const char* text);
} R3HostApi;

R3_PLUGIN_API int R3Plugin_Query(R3PluginInfo* out_info);
R3_PLUGIN_API int R3Plugin_Init(const R3HostApi* host);
R3_PLUGIN_API int R3Plugin_Start(void);
R3_PLUGIN_API int R3Plugin_Stop(void);
R3_PLUGIN_API int R3Plugin_MemOp(const uint8_t* req_buf,
                                 uint32_t req_len,
                                 uint8_t** rsp_buf,
                                 uint32_t* rsp_len);
// Optional. Host will call when analysis capabilities are declared.
R3_PLUGIN_API int R3Plugin_Analyze(const uint8_t* req_buf,
                                   uint32_t req_len,
                                   uint8_t** rsp_buf,
                                   uint32_t* rsp_len);
R3_PLUGIN_API void R3Plugin_Free(void* p);

#ifdef __cplusplus
}
#endif
