param(
  [string]$CoreRoot = "",
  [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($CoreRoot)) {
  $CoreRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path $CoreRoot "build\ui_regression_plugin_provider"
}

function Add-Result {
  param(
    [System.Collections.Generic.List[object]]$List,
    [string]$Name,
    [bool]$Passed,
    [string]$Detail
  )
  $List.Add([pscustomobject]@{
    name = $Name
    passed = $Passed
    detail = $Detail
  })
  $mark = if ($Passed) { "[PASS]" } else { "[FAIL]" }
  Write-Host "$mark $Name - $Detail"
}

function Has-Regex {
  param([string]$Text, [string]$Pattern)
  return [regex]::IsMatch($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
}

$protocolPath = Join-Path $CoreRoot "src\protocol\Protocol.h"
$serviceH = Join-Path $CoreRoot "src\windows_client_ng\services\ClientService.h"
$serviceCpp = Join-Path $CoreRoot "src\windows_client_ng\services\ClientService.cpp"
$agentMain = Join-Path $CoreRoot "src\android_agent\main.cpp"
$mainCpp = Join-Path $CoreRoot "src\windows_client_qt\ui\MainWindow.cpp"
$settingsH = Join-Path $CoreRoot "src\windows_client_qt\ui\SettingsDialog.h"
$settingsCpp = Join-Path $CoreRoot "src\windows_client_qt\ui\SettingsDialog.cpp"
$pluginCatalogH = Join-Path $CoreRoot "src\windows_client_qt\plugins\PluginCatalog.h"
$pluginCatalogCpp = Join-Path $CoreRoot "src\windows_client_qt\plugins\PluginCatalog.cpp"
$pluginRuntimeH = Join-Path $CoreRoot "src\windows_client_qt\plugins\PluginRuntime.h"
$pluginRuntimeCpp = Join-Path $CoreRoot "src\windows_client_qt\plugins\PluginRuntime.cpp"
$sdkHeader = Join-Path $CoreRoot "src\plugin_sdk\R3PluginApi.h"
$pluginSample = Join-Path $CoreRoot "plugins\example_syscall_bridge\plugin.json"
$quickstartSample = Join-Path $CoreRoot "plugins\example_syscall_bridge\quickstart.json"

foreach ($f in @($protocolPath, $serviceH, $serviceCpp, $agentMain, $mainCpp, $settingsH, $settingsCpp, $pluginCatalogH, $pluginCatalogCpp, $pluginRuntimeH, $pluginRuntimeCpp, $sdkHeader, $pluginSample, $quickstartSample)) {
  if (-not (Test-Path $f)) {
    throw "missing required file: $f"
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path

$results = New-Object 'System.Collections.Generic.List[object]'

$protocol = Get-Content -Raw $protocolPath
$serviceHText = Get-Content -Raw $serviceH
$serviceCppText = Get-Content -Raw $serviceCpp
$agentText = Get-Content -Raw $agentMain
$mainText = Get-Content -Raw $mainCpp
$settingsHText = Get-Content -Raw $settingsH
$settingsCppText = Get-Content -Raw $settingsCpp
$catalogHText = Get-Content -Raw $pluginCatalogH
$catalogCppText = Get-Content -Raw $pluginCatalogCpp
$runtimeHText = Get-Content -Raw $pluginRuntimeH
$runtimeCppText = Get-Content -Raw $pluginRuntimeCpp
$sdkText = Get-Content -Raw $sdkHeader

Add-Result -List $results -Name "protocol_commands" -Passed (Has-Regex $protocol 'CMD_GET_CAPS[\s\S]*CMD_CUSTOM_MEM_OP') -Detail "new protocol commands exist"
Add-Result -List $results -Name "protocol_structs" -Passed (Has-Regex $protocol 'struct AgentCapabilitiesResponse[\s\S]*struct CustomMemOpRequest[\s\S]*struct CustomMemOpResponse') -Detail "new protocol structs exist"
Add-Result -List $results -Name "service_provider_api" -Passed (Has-Regex $serviceHText 'CustomMemoryProviderConfig[\s\S]*SetCustomMemoryProviderConfig') -Detail "service provider config API exists"
Add-Result -List $results -Name "service_provider_impl" -Passed (Has-Regex $serviceCppText 'ReadMemoryViaCustomProvider[\s\S]*CMD_CUSTOM_MEM_OP') -Detail "service provider impl exists"
Add-Result -List $results -Name "service_provider_runtime" -Passed (Has-Regex $serviceHText 'ProviderRuntimeSnapshot[\s\S]*ForceProviderFallback' -and Has-Regex $serviceCppText 'RecordProviderFailure[\s\S]*fused') -Detail "provider runtime/fuse API exists"
Add-Result -List $results -Name "agent_custom_memop_case" -Passed (Has-Regex $agentText 'CMD_GET_CAPS[\s\S]*CMD_CUSTOM_MEM_OP') -Detail "agent command handlers exist"
Add-Result -List $results -Name "mainwindow_settings_bind" -Passed (Has-Regex $mainText 'plugin_root_path_[\s\S]*ApplyCustomProviderConfig\(\)') -Detail "mainwindow binds plugin settings"
$panelLegacy = Has-Regex $mainText 'plugin_provider_status_label_[\s\S]*plugin_self_check_button_[\s\S]*plugin_force_fallback_button_'
$panelNew = Has-Regex $mainText 'plugin_load_count_label_[\s\S]*plugin_load_failed_count_label_[\s\S]*plugin_avg_latency_label_[\s\S]*plugin_failure_output_button_[\s\S]*plugin_self_check_button_[\s\S]*plugin_force_fallback_button_'
Add-Result -List $results -Name "mainwindow_plugin_panel" -Passed ($panelLegacy -or $panelNew) -Detail "mainwindow plugin status panel exists"
Add-Result -List $results -Name "settings_dialog_plugin_fields" -Passed (Has-Regex $settingsHText 'plugin_root_path[\s\S]*plugin_user_ctx_hex') -Detail "settings data includes plugin fields"
Add-Result -List $results -Name "settings_dialog_plugin_ui" -Passed ((Has-Regex $settingsCppText '插件与自定义syscall[\s\S]*扫描插件') -and (Has-Regex $settingsCppText 'plugin_syscall_read_spin_[\s\S]*plugin_user_ctx_edit_')) -Detail "settings UI includes plugin provider controls"
Add-Result -List $results -Name "plugin_catalog" -Passed (Has-Regex $catalogHText 'class PluginCatalog' -and Has-Regex $catalogCppText 'LoadFromRoot') -Detail "plugin catalog parser exists"
Add-Result -List $results -Name "plugin_runtime" -Passed (Has-Regex $runtimeHText 'class PluginRuntime' -and Has-Regex $runtimeCppText 'ActivateInProcess[\s\S]*R3Plugin_Analyze') -Detail "plugin runtime exists"
Add-Result -List $results -Name "plugin_sdk_header" -Passed (Has-Regex $sdkText 'R3SysMemReqV1[\s\S]*R3AnalysisReqV1[\s\S]*R3Plugin_Analyze') -Detail "plugin sdk header exists"
Add-Result -List $results -Name "plugin_examples" -Passed ((Test-Path $pluginSample) -and (Test-Path $quickstartSample)) -Detail "example plugin package exists"

$failed = @($results | Where-Object { -not $_.passed }).Count
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("plugin_provider_regression_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("plugin_provider_regression_" + $stamp + ".md")

$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add("# Plugin Provider Regression")
$lines.Add("")
$lines.Add("- failed: $failed")
$lines.Add("")
$lines.Add("| Check | Result | Detail |")
$lines.Add("|---|---|---|")
foreach ($r in $results) {
  $state = if ($r.passed) { "PASS" } else { "FAIL" }
  $lines.Add("| $($r.name) | $state | $($r.detail) |")
}
$lines | Set-Content -Path $mdPath -Encoding UTF8

Write-Host ""
Write-Host ("Report JSON: " + $jsonPath)
Write-Host ("Report MD:   " + $mdPath)
Write-Host ("Summary: failed=" + $failed + " total=" + $results.Count)

if ($failed -gt 0) {
  exit 1
}
