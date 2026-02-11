param(
  [string]$ClientExe = "",
  [string]$OutDir = "",
  [int]$Runs = 20,
  [int]$WarmupRuns = 1,
  [int]$MainWindowTimeoutMs = 15000,
  [int]$PickerTimeoutMs = 10000,
  [string]$MainTitleKeyword = "R3 Android Debug Client",
  [string]$PickerTitleKeyword = "进程列表",
  [int]$StartupP95ThresholdMs = 1200,
  [int]$PickerP95ThresholdMs = 1000,
  [switch]$RequirePicker,
  [switch]$SkipRuntime,
  [switch]$NoExitOnFail
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$coreRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ClientExe)) {
  $ClientExe = Join-Path $coreRoot "build\windows_client\src\windows_client_qt\r3_windows_client_qt.exe"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path $coreRoot "build\ui_perf_benchmark"
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

function Get-Percentile {
  param(
    [double[]]$Values,
    [double]$P
  )
  if ($null -eq $Values -or $Values.Count -eq 0) {
    return [double]::NaN
  }
  $sorted = @($Values | Sort-Object)
  $index = [int][Math]::Ceiling($P * $sorted.Count) - 1
  if ($index -lt 0) { $index = 0 }
  if ($index -ge $sorted.Count) { $index = $sorted.Count - 1 }
  return [double]$sorted[$index]
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class UiPerfNative {
  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern int GetWindowTextLength(IntPtr hWnd);

  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool IsWindow(IntPtr hWnd);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool SetForegroundWindow(IntPtr hWnd);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}
"@

Add-Type -AssemblyName System.Windows.Forms

$WM_CLOSE = 0x0010
$SW_RESTORE = 9

function Get-TopWindows {
  $list = New-Object 'System.Collections.Generic.List[System.IntPtr]'
  $callback = [UiPerfNative+EnumWindowsProc]{
    param([IntPtr]$hWnd, [IntPtr]$lParam)
    $gc = [System.Runtime.InteropServices.GCHandle]::FromIntPtr($lParam)
    $target = [System.Collections.Generic.List[System.IntPtr]]$gc.Target
    $target.Add($hWnd)
    return $true
  }
  $holder = [System.Runtime.InteropServices.GCHandle]::Alloc($list)
  try {
    [void][UiPerfNative]::EnumWindows($callback, [System.Runtime.InteropServices.GCHandle]::ToIntPtr($holder))
  } finally {
    $holder.Free()
  }
  return $list
}

function Get-WindowText {
  param([IntPtr]$Hwnd)
  $len = [UiPerfNative]::GetWindowTextLength($Hwnd)
  if ($len -le 0) {
    return ""
  }
  $sb = New-Object System.Text.StringBuilder ($len + 2)
  [void][UiPerfNative]::GetWindowText($Hwnd, $sb, $sb.Capacity)
  return $sb.ToString()
}

function Wait-WindowByTitleContains {
  param(
    [int]$ProcessId,
    [string]$Keyword,
    [int]$TimeoutMs
  )
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
    foreach ($h in (Get-TopWindows)) {
      if ($h -eq [IntPtr]::Zero -or -not [UiPerfNative]::IsWindow($h)) {
        continue
      }
      $windowPid = 0
      [void][UiPerfNative]::GetWindowThreadProcessId($h, [ref]$windowPid)
      if ($windowPid -ne $ProcessId) {
        continue
      }
      $title = Get-WindowText -Hwnd $h
      if (-not [string]::IsNullOrWhiteSpace($title) -and $title.Contains($Keyword)) {
        return $h
      }
    }
    Start-Sleep -Milliseconds 60
  }
  return [IntPtr]::Zero
}

function Try-CloseWindow {
  param([IntPtr]$Hwnd)
  if ($Hwnd -eq [IntPtr]::Zero -or -not [UiPerfNative]::IsWindow($Hwnd)) {
    return
  }
  [void][UiPerfNative]::PostMessage($Hwnd, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
}

function Send-CtrlP {
  param([IntPtr]$Hwnd)
  if ($Hwnd -eq [IntPtr]::Zero -or -not [UiPerfNative]::IsWindow($Hwnd)) {
    return
  }
  [void][UiPerfNative]::ShowWindow($Hwnd, $SW_RESTORE)
  [void][UiPerfNative]::SetForegroundWindow($Hwnd)
  Start-Sleep -Milliseconds 120
  [System.Windows.Forms.SendKeys]::SendWait("^p")
  Start-Sleep -Milliseconds 180
}

function Try-OpenPicker {
  param(
    [IntPtr]$MainHwnd,
    [int]$ProcessId,
    [string]$Keyword,
    [int]$TimeoutMs
  )
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
    Send-CtrlP -Hwnd $MainHwnd
    $left = [Math]::Max(400, $TimeoutMs - [int]$watch.ElapsedMilliseconds)
    $slice = [Math]::Min(1200, $left)
    $picker = Wait-WindowByTitleContains -ProcessId $ProcessId -Keyword $Keyword -TimeoutMs $slice
    if ($picker -ne [IntPtr]::Zero) {
      return $picker
    }
    Start-Sleep -Milliseconds 120
  }
  return [IntPtr]::Zero
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'
$runRecords = New-Object 'System.Collections.Generic.List[object]'

if ($SkipRuntime) {
  Add-Result -List $results -Name "runtime" -Passed $true -Detail "skipped by -SkipRuntime"
} elseif (-not (Test-Path $ClientExe)) {
  Add-Result -List $results -Name "runtime" -Passed $false -Detail ("client exe not found: " + $ClientExe)
} else {
  if ($Runs -lt 1) {
    $Runs = 1
  }
  $procName = [System.IO.Path]::GetFileNameWithoutExtension($ClientExe)

  for ($i = 1; $i -le $Runs; $i++) {
    Get-Process -Name $procName -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 250

    $startupMs = [double]::NaN
    $pickerMs = [double]::NaN
    $okMain = $false
    $okPicker = $false
    $err = ""
    $proc = $null
    $main = [IntPtr]::Zero
    $picker = [IntPtr]::Zero

    try {
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $proc = Start-Process -FilePath $ClientExe -PassThru
      $main = Wait-WindowByTitleContains -ProcessId $proc.Id -Keyword $MainTitleKeyword -TimeoutMs $MainWindowTimeoutMs
      if ($main -eq [IntPtr]::Zero) {
        $err = "main window timeout"
      } else {
        $startupMs = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        $okMain = $true

        $swPicker = [System.Diagnostics.Stopwatch]::StartNew()
        $picker = Try-OpenPicker -MainHwnd $main -ProcessId $proc.Id -Keyword $PickerTitleKeyword -TimeoutMs $PickerTimeoutMs
        if ($picker -eq [IntPtr]::Zero) {
          if ($RequirePicker) {
            $err = "process picker timeout"
          } else {
            $err = "process picker timeout (non-fatal)"
          }
        } else {
          $pickerMs = [Math]::Round($swPicker.Elapsed.TotalMilliseconds, 2)
          $okPicker = $true
        }
      }
    } catch {
      $err = ($_ | Out-String).Trim()
    } finally {
      Try-CloseWindow -Hwnd $picker
      Try-CloseWindow -Hwnd $main
      if ($null -ne $proc -and -not $proc.HasExited) {
        $proc.WaitForExit(2500) | Out-Null
        if (-not $proc.HasExited) {
          $proc.Kill()
        }
      }
    }

    $record = [pscustomobject]@{
      run = $i
      ok_main = $okMain
      ok_picker = $okPicker
      startup_ms = $startupMs
      picker_ms = $pickerMs
      error = $err
    }
    $runRecords.Add($record)
    $runPassed = $okMain -and ($okPicker -or -not $RequirePicker)
    Add-Result -List $results -Name ("run_" + $i) -Passed $runPassed -Detail ("run=" + $i + " startup_ms=" + $startupMs + " picker_ms=" + $pickerMs + " err=" + $err)
  }
}

$effectiveRecords = @($runRecords | Where-Object { $_.run -gt $WarmupRuns })
if ($effectiveRecords.Count -eq 0) {
  $effectiveRecords = [object[]]$runRecords
}
$startupVals = @($effectiveRecords | Where-Object { $_.ok_main -and -not [double]::IsNaN($_.startup_ms) } | ForEach-Object { [double]$_.startup_ms })
$pickerVals = @($effectiveRecords | Where-Object { $_.ok_picker -and -not [double]::IsNaN($_.picker_ms) } | ForEach-Object { [double]$_.picker_ms })

$startupP50 = Get-Percentile -Values $startupVals -P 0.50
$startupP95 = Get-Percentile -Values $startupVals -P 0.95
$startupP99 = Get-Percentile -Values $startupVals -P 0.99
$pickerP50 = Get-Percentile -Values $pickerVals -P 0.50
$pickerP95 = Get-Percentile -Values $pickerVals -P 0.95
$pickerP99 = Get-Percentile -Values $pickerVals -P 0.99

if (-not [double]::IsNaN($startupP95)) {
  Add-Result -List $results -Name "startup_p95_gate" -Passed ($startupP95 -le $StartupP95ThresholdMs) -Detail ("p95=" + $startupP95 + "ms threshold=" + $StartupP95ThresholdMs + "ms")
}
if (-not [double]::IsNaN($pickerP95)) {
  Add-Result -List $results -Name "picker_p95_gate" -Passed ($pickerP95 -le $PickerP95ThresholdMs) -Detail ("p95=" + $pickerP95 + "ms threshold=" + $PickerP95ThresholdMs + "ms")
} else {
  Add-Result -List $results -Name "picker_samples" -Passed (-not $RequirePicker) -Detail "no picker samples collected"
}

$failed = @($results | Where-Object { -not $_.passed }).Count
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("ui_perf_benchmark_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("ui_perf_benchmark_" + $stamp + ".md")

$summary = [ordered]@{
  startup = [ordered]@{
    count = $startupVals.Count
    p50_ms = $startupP50
    p95_ms = $startupP95
    p99_ms = $startupP99
  }
  process_picker = [ordered]@{
    count = $pickerVals.Count
    p50_ms = $pickerP50
    p95_ms = $pickerP95
    p99_ms = $pickerP99
  }
}

$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  client_exe = $ClientExe
  runs = $Runs
  warmup_runs = $WarmupRuns
  effective_runs = $effectiveRecords.Count
  title_keywords = [ordered]@{
    main = $MainTitleKeyword
    picker = $PickerTitleKeyword
  }
  thresholds = [ordered]@{
    startup_p95_ms = $StartupP95ThresholdMs
    picker_p95_ms = $PickerP95ThresholdMs
  }
  summary = $summary
  run_records = $runRecords
  results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add("# UI Performance Benchmark (Qt)")
$lines.Add("")
$lines.Add("- client: `"$ClientExe`"")
$lines.Add("- runs: " + $Runs)
$lines.Add("- warmup runs ignored: " + $WarmupRuns)
$lines.Add("- startup p50/p95/p99(ms): " + $startupP50 + "/" + $startupP95 + "/" + $startupP99)
$lines.Add("- picker p50/p95/p99(ms): " + $pickerP50 + "/" + $pickerP95 + "/" + $pickerP99)
$lines.Add("- failed: " + $failed)
$lines.Add("")
$lines.Add("| Check | Result | Detail |")
$lines.Add("|---|---|---|")
foreach ($r in $results) {
  $state = if ($r.passed) { "PASS" } else { "FAIL" }
  $lines.Add("| " + $r.name + " | " + $state + " | " + $r.detail + " |")
}
$lines.Add("")
$lines.Add("## Per-Run Data")
$lines.Add("")
$lines.Add("| Run | Main | Picker | Startup(ms) | Picker(ms) | Error |")
$lines.Add("|---|---|---|---|---|---|")
foreach ($row in $runRecords) {
  $lines.Add("| " + $row.run + " | " + $row.ok_main + " | " + $row.ok_picker + " | " + $row.startup_ms + " | " + $row.picker_ms + " | " + $row.error + " |")
}
$lines | Set-Content -Path $mdPath -Encoding UTF8

Write-Host ""
Write-Host ("Report JSON: " + $jsonPath)
Write-Host ("Report MD:   " + $mdPath)
Write-Host ("Summary: failed=" + $failed + " total=" + $results.Count)

if ($failed -gt 0 -and -not $NoExitOnFail) {
  exit 1
}
