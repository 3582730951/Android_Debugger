param(
  [Parameter(Mandatory = $true)]
  [string]$PluginId,
  [string]$Name = "",
  [string]$Version = "1.0.0",
  [string]$Author = "QA",
  [string]$Description = "",
  [string]$OutRoot = "",
  [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$coreRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutRoot)) {
  $OutRoot = Join-Path $coreRoot "plugin_projects"
}
if ([string]::IsNullOrWhiteSpace($Name)) {
  $parts = $PluginId.Split('.')
  $Name = if ($parts.Count -gt 0) { $parts[$parts.Count - 1] } else { "PluginDemo" }
}
if ([string]::IsNullOrWhiteSpace($Description)) {
  $Description = "Plugin project for $PluginId"
}

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$outRootAbs = (Resolve-Path $OutRoot).Path
$safeId = ($PluginId -replace '[^A-Za-z0-9._-]', '_')
$targetName = "r3_plugin_" + (($safeId -replace '[\.-]', '_'))
$projectDir = Join-Path $outRootAbs $safeId

if (Test-Path $projectDir) {
  if (-not $Force) {
    throw "project directory exists: $projectDir (use -Force to overwrite)"
  }
  Remove-Item -Recurse -Force $projectDir
}

foreach ($d in @(
    $projectDir,
    (Join-Path $projectDir "src"),
    (Join-Path $projectDir "schema"),
    (Join-Path $projectDir "docs")
  )) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
}

$meta = [ordered]@{
  plugin_id = $PluginId
  name = $Name
  version = $Version
  author = $Author
  description = $Description
  target = $targetName
  mode = "in_process"
  capabilities = @("memory.provider", "memory.syscall_bridge")
  syscall_read = -1
  syscall_write = -1
  timeout_ms = 1000
  user_ctx_hex = ""
}
($meta | ConvertTo-Json -Depth 8) | Set-Content -Path (Join-Path $projectDir "plugin_meta.json") -Encoding UTF8

$cmakeText = @'
cmake_minimum_required(VERSION 3.18)
project(__TARGET__ LANGUAGES C CXX)

if(NOT DEFINED R3_CORE_ROOT)
  message(FATAL_ERROR "R3_CORE_ROOT is required. Example: -DR3_CORE_ROOT=D:/Code/R3_Code/android_debug/core")
endif()
if(NOT EXISTS "${R3_CORE_ROOT}/src/plugin_sdk/R3ModuleCompat.h")
  message(FATAL_ERROR "R3_CORE_ROOT invalid: ${R3_CORE_ROOT}")
endif()

add_library(__TARGET__ SHARED
  src/PluginMain.cpp
)

target_compile_features(__TARGET__ PRIVATE cxx_std_17)
target_compile_definitions(__TARGET__ PRIVATE R3_PLUGIN_EXPORTS)
target_include_directories(__TARGET__ PRIVATE
  "${R3_CORE_ROOT}/src"
)
target_compile_options(__TARGET__ PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
  $<$<CXX_COMPILER_ID:GNU>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
  $<$<CXX_COMPILER_ID:Clang>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
)
set_target_properties(__TARGET__ PROPERTIES
  PREFIX ""
  OUTPUT_NAME "__TARGET__"
)
'@
$cmakeText = $cmakeText.Replace("__TARGET__", $targetName)
$cmakeText | Set-Content -Path (Join-Path $projectDir "CMakeLists.txt") -Encoding UTF8

$pluginCpp = @'
#include <cstdint>

#include "plugin_sdk/R3ModuleCompat.h"

namespace {

int32_t OnReadMem(const R3ModuleEventContext* ctx, void* user_ctx, uint8_t** out_buf, uint32_t* out_len) {
  (void)ctx;
  (void)user_ctx;
  (void)out_buf;
  (void)out_len;
  return R3_MODULE_DISPATCH_PASS;
}

int32_t OnWriteMem(const R3ModuleEventContext* ctx, void* user_ctx, uint8_t** out_buf, uint32_t* out_len) {
  (void)ctx;
  (void)user_ctx;
  (void)out_buf;
  (void)out_len;
  return R3_MODULE_DISPATCH_PASS;
}

int RegisterEvents(const R3ModuleHostApiV1* host) {
  if (!host || !host->register_callback) {
    return -1;
  }
  if (host->register_callback(R3_MODULE_EVENT_READ_MEM, &OnReadMem, nullptr) != 0) {
    return -2;
  }
  if (host->register_callback(R3_MODULE_EVENT_WRITE_MEM, &OnWriteMem, nullptr) != 0) {
    return -3;
  }
  return 0;
}

int PluginInit(void) {
  return 0;
}

}  // namespace

module_name("__PLUGIN_ID__");
module_version("__PLUGIN_VERSION__");
module_author("__PLUGIN_AUTHOR__");
init_module(PluginInit);
register_module_events(RegisterEvents);
'@
$pluginCpp = $pluginCpp.Replace("__PLUGIN_ID__", $PluginId)
$pluginCpp = $pluginCpp.Replace("__PLUGIN_VERSION__", $Version)
$pluginCpp = $pluginCpp.Replace("__PLUGIN_AUTHOR__", $Author)
$pluginCpp | Set-Content -Path (Join-Path $projectDir "src/PluginMain.cpp") -Encoding UTF8

$quickstart = @'
{
  "fields": [
    {
      "id": "policy",
      "label": "Policy",
      "type": "u32",
      "default": "1",
      "description": "policy bitmask"
    },
    {
      "id": "token",
      "label": "Token",
      "type": "u64",
      "default": "42",
      "description": "auth token"
    }
  ]
}
'@
$quickstart | Set-Content -Path (Join-Path $projectDir "schema/quickstart.json") -Encoding UTF8

$readme = @'
# Plugin Project

## Fast path
1. Edit `src/PluginMain.cpp`.
2. Run:
   powershell -ExecutionPolicy Bypass -File .\tools\plugin_compile_pack.ps1 -PluginProjectRoot <this_project_path>
3. In client UI:
   - Open `插件与自定义syscall`
   - Set plugin root to repo `plugins` directory
   - Scan + enable plugin

## IDA-like style
- Keep module metadata in macros:
  - `module_name`
  - `module_version`
  - `module_author`
  - `init_module`
- Use callback return value to control default host flow.
'@
$readme | Set-Content -Path (Join-Path $projectDir "docs/README.md") -Encoding UTF8

$buildPack = @'
param(
  [string]$CMakeRoot = "D:\CMake",
  [string]$BuildType = "Release",
  [string]$OutPluginsRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$coreRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$tool = Join-Path $coreRoot "tools\plugin_compile_pack.ps1"
if (-not (Test-Path $tool)) {
  throw "tool not found: $tool"
}

$args = @(
  "-PluginProjectRoot", $PSScriptRoot,
  "-CMakeRoot", $CMakeRoot,
  "-BuildType", $BuildType
)
if (-not [string]::IsNullOrWhiteSpace($OutPluginsRoot)) {
  $args += @("-OutPluginsRoot", $OutPluginsRoot)
}

& $tool @args
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
'@
$buildPack | Set-Content -Path (Join-Path $projectDir "build_pack.ps1") -Encoding UTF8

Write-Host "Plugin project generated:"
Write-Host "  $projectDir"
Write-Host "Key files:"
Write-Host "  $(Join-Path $projectDir 'plugin_meta.json')"
Write-Host "  $(Join-Path $projectDir 'CMakeLists.txt')"
Write-Host "  $(Join-Path $projectDir 'src/PluginMain.cpp')"
Write-Host ""
Write-Host "Next:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\\tools\\plugin_compile_pack.ps1 -PluginProjectRoot `"$projectDir`""
