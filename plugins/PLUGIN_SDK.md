# R3 Plugin SDK

## 1. Goals
- Keep core app stable while allowing feature extensions.
- Support memory syscall bridge plugins and analysis plugins.
- Keep tester onboarding simple with `quickstart.json`.

## 2. Package Layout
Required:
- `plugin.json`
- `quickstart.json` (or `schema/quickstart.json`)

Optional:
- `bin/win64/<plugin>.dll` for `in_process` mode
- `docs/README.md`
- `third_party/`
- `licenses/third_party_licenses.txt`

## 3. Lifecycle
Host lifecycle:
- `Discover -> Validate -> Load -> Init -> Start -> Serve -> Stop -> Unload`

Failure policy:
- Error count reaches threshold then plugin is fused.
- Host auto falls back to built-in memory provider when fallback enabled.

## 4. plugin.json
Recommended schema:
```json
{
  "id": "com.company.syscall.bridge.demo",
  "name": "Demo Syscall Bridge",
  "version": "1.0.0",
  "description": "Read/Write through custom syscall",
  "mode": "manifest",
  "priority": 100,
  "abi": "r3.plugin.v1",
  "supported_arch": ["arm64", "arm32"],
  "capabilities": [
    "memory.provider",
    "memory.syscall_bridge",
    "analysis.annotation"
  ],
  "entry": "bin/win64/demo_plugin.dll",
  "quickstart": "quickstart.json",
  "memory_provider": {
    "syscall_read": 451,
    "syscall_write": 452,
    "timeout_ms": 1200,
    "user_ctx_hex": "01 00 00 00 2A 00 00 00 00 00 00 00 00 00 00 00"
  }
}
```

`mode`:
- `manifest`: metadata + defaults only
- `in_process`: load plugin DLL and call `R3Plugin_*`
- `out_of_process`: reserved for external worker mode

## 5. quickstart.json
Tester-facing auto form:
```json
{
  "fields": [
    {"id":"policy","label":"Policy","type":"u32","default":"1","description":"security policy bitmask"},
    {"id":"token","label":"Token","type":"u64","default":"42","description":"auth token"}
  ]
}
```

Supported field types:
- `u8/u16/u32/u64`
- `s32/s64`
- `string`
- `hexbytes`

## 6. Syscall `user_ctx` Rules
- little-endian
- packed struct (`#pragma pack(push,1)`)
- include version field
- encoded into `user_ctx_hex`

Example:
```c
#pragma pack(push, 1)
typedef struct VendorMemCtxV1 {
  uint32_t version;
  uint32_t policy;
  uint64_t token;
} VendorMemCtxV1;
#pragma pack(pop)
```

## 7. C ABI
Defined in `src/plugin_sdk/R3PluginApi.h`.

Required exports:
- `R3Plugin_Query`
- `R3Plugin_Init`
- `R3Plugin_Start`
- `R3Plugin_Stop`
- `R3Plugin_MemOp`
- `R3Plugin_Free`

Optional export:
- `R3Plugin_Analyze` (for `analysis.translate / analysis.vmp / analysis.annotation`)

## 8. IDA/C-Style Macro Layer
For C-style plugin development, use:
- `src/plugin_sdk/R3ModuleCompat.h`

Required metadata macros:
- `init_module(...)`
- `module_name(...)`
- `module_version(...)`
- `module_author(...)`

Example:
```c
#include "src/plugin_sdk/R3ModuleCompat.h"

static int PluginInit(void) { return 0; }
module_name("com.example.demo");
module_version("1.0.0");
module_author("QA");
init_module(PluginInit);
```

## 9. Callback/Event Override
`R3ModuleCompat.h` defines event ids and callback return semantics:
- `R3_MODULE_DISPATCH_PASS`: continue host default flow
- `R3_MODULE_DISPATCH_HANDLED`: plugin handled; host skips default flow
- `R3_MODULE_DISPATCH_ERROR`: host shows plugin error directly to user

This enables plugin return values to override default read/write/analysis behavior.

## 10. Build + Packaging Tools
Recommended full flow:
1. Generate plugin project:
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\plugin_new.ps1 `
  -PluginId com.example.demo `
  -Name DemoPlugin `
  -Author QA
```
2. Build and package in one step:
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\plugin_compile_pack.ps1 `
  -PluginProjectRoot .\plugin_projects\com.example.demo
```

If DLL is already built, use pure packager:
- `tools/plugin_packager.ps1`

Generated package layout:
- `plugin.json`
- `schema/quickstart.json`
- `docs/README.md`
- `bin/win64/*.dll`

## 11. Runtime Notes
- Client sends `CMD_CUSTOM_MEM_OP` with syscall ids + `user_ctx`.
- Android agent executes syscall and returns normalized result.
- If custom path fails and fallback enabled, host falls back to built-in chain.
- UI shows plugin load count, load-failure count, average latency, and failure output window.
