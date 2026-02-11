param(
  [string]$MainWindowSource = "",
  [string]$SettingsSource = "",
  [string]$OutDir = "",
  [string]$ClientExe = "",
  [switch]$SkipRuntime,
  [switch]$NoExitOnFail
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$coreRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($MainWindowSource)) {
  $MainWindowSource = Join-Path $coreRoot "src\windows_client_qt\ui\MainWindow.cpp"
}
if ([string]::IsNullOrWhiteSpace($SettingsSource)) {
  $SettingsSource = Join-Path $coreRoot "src\windows_client_qt\ui\SettingsDialog.cpp"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path $coreRoot "build\ui_regression_quick_add"
}
if ([string]::IsNullOrWhiteSpace($ClientExe)) {
  $ClientExe = Join-Path $coreRoot "build\windows_client\src\windows_client_qt\r3_windows_client_qt.exe"
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

foreach ($f in @($MainWindowSource, $SettingsSource)) {
  if (-not (Test-Path $f)) {
    throw "source file not found: $f"
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'

$main = Get-Content -Raw $MainWindowSource
$settings = Get-Content -Raw $SettingsSource

Add-Result -List $results -Name "has_quick_add_slot" -Passed ($main.Contains("OnQuickAddSelected")) -Detail "OnQuickAddSelected exists"
Add-Result -List $results -Name "has_quick_add_edit_slot" -Passed ($main.Contains("OnQuickAddAndEditSelected")) -Detail "OnQuickAddAndEditSelected exists"

$dblclickAdd = Has-Regex -Text $main -Pattern 'OnScanResultDoubleClicked[\s\S]{0,900}AltModifier[\s\S]{0,500}OpenMemoryViewAt[\s\S]{0,500}AddAddressEntry'
Add-Result -List $results -Name "dblclick_add_or_open" -Passed $dblclickAdd -Detail "double-click add + Alt open logic exists"

$insertShortcut = Has-Regex -Text $main -Pattern 'QShortcut\s*\(\s*QKeySequence\(\s*Qt::Key_Insert\s*\)'
Add-Result -List $results -Name "insert_shortcut" -Passed $insertShortcut -Detail "Insert shortcut exists"

$ctrlEnterShortcut = Has-Regex -Text $main -Pattern 'QShortcut\s*\(\s*QKeySequence\(\s*QStringLiteral\("Ctrl\+Return"\)\s*\)'
Add-Result -List $results -Name "ctrl_enter_shortcut" -Passed $ctrlEnterShortcut -Detail "Ctrl+Return shortcut exists"

$scanMenuQuickAdd = Has-Regex -Text $main -Pattern 'OnScanContextMenuRequested[\s\S]{0,2500}picked == add[\s\S]{0,1200}picked == add_batch[\s\S]{0,1200}picked == add_edit'
Add-Result -List $results -Name "scan_context_quick_add" -Passed $scanMenuQuickAdd -Detail "scan context quick-add branches exist"

$settingsHasAutoStart = $settings.Contains("auto_start_check_") -and $settings.Contains("auto_start =")
$settingsHasRefresh = $settings.Contains("refresh_interval_spin_") -and $settings.Contains("value_refresh_ms")
Add-Result -List $results -Name "settings_contains_startup_refresh" -Passed ($settingsHasAutoStart -and $settingsHasRefresh) -Detail "settings includes startup + refresh fields"

if ($SkipRuntime) {
  Add-Result -List $results -Name "runtime_smoke" -Passed $true -Detail "skipped by -SkipRuntime"
} else {
  $runtimeScript = Join-Path $scriptRoot "run_memoryview_jump_regression.ps1"
  if ((-not (Test-Path $runtimeScript)) -or (-not (Test-Path $ClientExe))) {
    Add-Result -List $results -Name "runtime_smoke" -Passed $false -Detail "runtime dependency missing"
  } else {
    $runtimeOut = Join-Path $resolvedOut "runtime_smoke"
    New-Item -ItemType Directory -Force -Path $runtimeOut | Out-Null
    $ok = $false
    $detail = ""
    try {
      $output = & powershell -STA -ExecutionPolicy Bypass -File $runtimeScript -ClientExe $ClientExe -OutDir $runtimeOut 2>&1
      $text = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine)
      $match = [regex]::Match($text, 'RunDir:\s*(.+)')
      if ($match.Success) {
        $runDir = $match.Groups[1].Value.Trim()
        $ok = Test-Path $runDir
        $detail = if ($ok) { "run_dir=$runDir" } else { "run_dir missing: $runDir" }
      } else {
        $detail = "RunDir not found"
      }
    } catch {
      $detail = "runtime error: " + ($_ | Out-String).Trim()
    }
    Add-Result -List $results -Name "runtime_smoke" -Passed $ok -Detail $detail
  }
}

$failed = @($results | Where-Object { -not $_.passed }).Count
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("ui_quick_add_regression_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("ui_quick_add_regression_" + $stamp + ".md")

$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  main_source = $MainWindowSource
  settings_source = $SettingsSource
  results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add("# UI Quick-Add Regression (Qt)")
$lines.Add("")
$lines.Add("- main: `"$MainWindowSource`"")
$lines.Add("- settings: `"$SettingsSource`"")
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

if ($failed -gt 0 -and -not $NoExitOnFail) {
  exit 1
}
