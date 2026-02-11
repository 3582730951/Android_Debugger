param(
  [string]$MainWindowSource = "",
  [string]$MemoryViewSource = "",
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
if ([string]::IsNullOrWhiteSpace($MemoryViewSource)) {
  $MemoryViewSource = Join-Path $coreRoot "src\windows_client_qt\ui\MemoryViewWindow.cpp"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path $coreRoot "build\ui_regression_contextmenu"
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

foreach ($f in @($MainWindowSource, $MemoryViewSource)) {
  if (-not (Test-Path $f)) {
    throw "source file not found: $f"
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'

$main = Get-Content -Raw $MainWindowSource
$mv = Get-Content -Raw $MemoryViewSource

$scanCtx = Has-Regex -Text $main -Pattern 'OnScanContextMenuRequested[\s\S]{0,3000}picked == add[\s\S]{0,1200}picked == add_batch[\s\S]{0,1200}picked == add_edit[\s\S]{0,1200}picked == open_mem[\s\S]{0,1200}picked == copy_addr[\s\S]{0,1200}picked == copy_addr_val'
Add-Result -List $results -Name "scan_contextmenu_items" -Passed $scanCtx -Detail "scan context menu branches exist"

$addrCtx = Has-Regex -Text $main -Pattern 'OnAddressContextMenuRequested[\s\S]{0,3200}picked == edit_value[\s\S]{0,1400}picked == jump_mem[\s\S]{0,1400}picked == freeze_selected[\s\S]{0,1400}picked == unfreeze_selected[\s\S]{0,1400}picked == copy_row[\s\S]{0,1400}picked == del'
Add-Result -List $results -Name "address_contextmenu_items" -Passed $addrCtx -Detail "address list context menu branches exist"

$mvCtx = Has-Regex -Text $mv -Pattern 'OnShowContextMenu[\s\S]{0,6000}picked == copy_addr[\s\S]{0,3200}picked == copy_bytes[\s\S]{0,3200}picked == add_addr'
Add-Result -List $results -Name "memoryview_contextmenu_items" -Passed $mvCtx -Detail "memory view context menu branches exist"

$hasCopy = Has-Regex -Text $mv -Pattern 'QApplication::clipboard\(\)->setText'
Add-Result -List $results -Name "memoryview_copy_handlers" -Passed $hasCopy -Detail "memoryview copy handlers exist"

$hasJumpAction = $main.Contains("OpenMemoryViewAt")
Add-Result -List $results -Name "jump_to_memoryview_handler" -Passed $hasJumpAction -Detail "jump/open memory view handler exists"

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
      $match = [regex]::Match($text, 'Report:\s*(.+)')
      if ($match.Success) {
        $reportPath = $match.Groups[1].Value.Trim()
        $ok = Test-Path $reportPath
        $detail = if ($ok) { "memoryview_report=$reportPath" } else { "report missing: $reportPath" }
      } else {
        $detail = "Report path not found"
      }
    } catch {
      $detail = "runtime error: " + ($_ | Out-String).Trim()
    }
    Add-Result -List $results -Name "runtime_smoke" -Passed $ok -Detail $detail
  }
}

$failed = @($results | Where-Object { -not $_.passed }).Count
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("ui_contextmenu_regression_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("ui_contextmenu_regression_" + $stamp + ".md")

$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  main_source = $MainWindowSource
  memoryview_source = $MemoryViewSource
  results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add("# UI Context-Menu Regression (Qt)")
$lines.Add("")
$lines.Add("- main: `"$MainWindowSource`"")
$lines.Add("- memoryview: `"$MemoryViewSource`"")
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
