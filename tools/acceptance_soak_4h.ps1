param(
  [string]$Adb = "E:\gjzs\adb.exe",
  [int]$Port = 12345,
  [string]$Package = "com.r3.debugprobe",
  [string]$Activity = "android.app.NativeActivity",
  [int]$DurationSeconds = 14400,
  [int]$PauseMs = 2000,
  [string]$OutDir = "build\acceptance",
  [switch]$NoExitOnFail
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Adb {
  param([string[]]$AdbArgs)
  return & $Adb @AdbArgs
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

function Get-ProcStatusSample {
  param([string]$TargetPid)
  if ([string]::IsNullOrWhiteSpace($TargetPid)) {
    return @{
      rss_kb = 0
      threads = 0
    }
  }
  $lines = Invoke-Adb -AdbArgs @("shell", "su", "-c", ("cat /proc/" + $TargetPid + "/status"))
  if ($LASTEXITCODE -ne 0 -or -not $lines) {
    return @{
      rss_kb = 0
      threads = 0
    }
  }
  $rss = 0
  $thr = 0
  foreach ($line in $lines) {
    if ($line -match '^VmRSS:\s+(\d+)\s+kB') {
      $rss = [int]$Matches[1]
      continue
    }
    if ($line -match '^Threads:\s+(\d+)') {
      $thr = [int]$Matches[1]
      continue
    }
  }
  return @{
    rss_kb = $rss
    threads = $thr
  }
}

function Get-Pid {
  param([string]$ProcName)
  $raw = ((Invoke-Adb -AdbArgs @("shell", "pidof", $ProcName)) | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($raw)) {
    return ""
  }
  return ($raw -split '\s+')[0]
}

function Parse-ProbeMarkers {
  param([object[]]$Lines)
  $state = [ordered]@{
    rwAddr = [UInt64]0
    rwSize = [UInt64]0
  }
  foreach ($lineRaw in $Lines) {
    $line = [string]$lineRaw
    if ($line -match "rw_region=0x([0-9a-fA-F]+)\s+size=(\d+)") {
      $state.rwAddr = [Convert]::ToUInt64($Matches[1], 16)
      $state.rwSize = [Convert]::ToUInt64($Matches[2], 10)
      continue
    }
  }
  return $state
}

function Run-TestAgent {
  param(
    [string]$RepoRoot,
    [hashtable]$Params
  )
  $script = Join-Path $RepoRoot "tools\test_agent.ps1"
  $out = & $script @Params 2>&1
  return (($out | ForEach-Object { "$_" }) -join [Environment]::NewLine)
}

if (-not (Test-Path $Adb)) {
  throw "adb not found: $Adb"
}

$repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path
$pushAgent = Join-Path $repoRoot "tools\push_run_agent.ps1"
$forward = Join-Path $repoRoot "tools\adb_forward.ps1"

if (-not (Test-Path $pushAgent)) { throw "missing script: $pushAgent" }
if (-not (Test-Path $forward)) { throw "missing script: $forward" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("soak_4h_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("soak_4h_" + $stamp + ".md")
$logPath = Join-Path $resolvedOut ("soak_4h_" + $stamp + ".log")

$logLines = New-Object System.Collections.Generic.List[string]
$results = New-Object 'System.Collections.Generic.List[object]'
$samples = New-Object 'System.Collections.Generic.List[object]'

$devices = Invoke-Adb -AdbArgs @("devices")
if (($devices | Out-String) -notmatch "device") {
  throw "no online adb device"
}

Invoke-Adb -AdbArgs @("logcat", "-c") | Out-Null
Invoke-Adb -AdbArgs @("shell", "am", "force-stop", $Package) | Out-Null
Start-Sleep -Milliseconds 600
Invoke-Adb -AdbArgs @("shell", "am", "start", "-n", "$Package/$Activity") | Out-Null
Start-Sleep -Seconds 2

& powershell -ExecutionPolicy Bypass -File $pushAgent -Adb $Adb -Port $Port -Run | Out-Null
& powershell -ExecutionPolicy Bypass -File $forward -Adb $Adb -Port $Port | Out-Null

$probePid = Get-Pid -ProcName $Package
if ($probePid -notmatch '^\d+$') {
  for ($i = 0; $i -lt 12 -and $probePid -notmatch '^\d+$'; $i++) {
    if ($i -eq 4) {
      try {
        Invoke-Adb -AdbArgs @("shell", "monkey", "-p", $Package, "-c", "android.intent.category.LAUNCHER", "1") | Out-Null
      } catch {
      }
    }
    Start-Sleep -Milliseconds 500
    $probePid = Get-Pid -ProcName $Package
  }
}
if ($probePid -notmatch '^\d+$') {
  throw "target process not found: $Package"
}
$agentPid = Get-Pid -ProcName "r3_android_agent"
if ($agentPid -notmatch '^\d+$') {
  throw "agent process not found: r3_android_agent"
}

$rwAddr = [UInt64]0
$rwSize = [UInt64]0
for ($i = 0; $i -lt 20; $i++) {
  $lines = Invoke-Adb -AdbArgs @("logcat", "-d", "-s", "R3Probe:D", "*:S")
  $parsed = Parse-ProbeMarkers -Lines $lines
  $rwAddr = [UInt64]$parsed.rwAddr
  $rwSize = [UInt64]$parsed.rwSize
  if ($rwAddr -ne 0 -and $rwSize -gt 0) {
    break
  }
  Start-Sleep -Milliseconds 500
}
if ($rwAddr -eq 0 -or $rwSize -eq 0) {
  throw "failed to parse rw_region from R3Probe logcat"
}

$writeAddr = $rwAddr + 0x120
$writeBytes = [byte[]](0x12, 0x34, 0x56, 0x78)

$start = Get-Date
$end = $start.AddSeconds($DurationSeconds)
$iteration = 0
$failureCount = 0
$restartCount = 0
$maxConsecutiveFail = 0
$consecutiveFail = 0

$logLines.Add("start=" + $start.ToString("o"))
$logLines.Add("duration_seconds=" + $DurationSeconds)
$logLines.Add("rw_addr=0x" + $rwAddr.ToString("X"))
$logLines.Add("rw_size=" + $rwSize)

while ((Get-Date) -lt $end) {
  $iteration++
  $now = Get-Date

  $probePidNow = Get-Pid -ProcName $Package
  $agentPidNow = Get-Pid -ProcName "r3_android_agent"
  if ($probePidNow -notmatch '^\d+$' -or $agentPidNow -notmatch '^\d+$') {
    $restartCount++
    $failureCount++
    $consecutiveFail++
    if ($consecutiveFail -gt $maxConsecutiveFail) { $maxConsecutiveFail = $consecutiveFail }
    $logLines.Add("[" + $now.ToString("o") + "] restart detected pid_app=" + $probePidNow + " pid_agent=" + $agentPidNow)

    try {
      Invoke-Adb -AdbArgs @("shell", "am", "start", "-n", "$Package/$Activity") | Out-Null
      Start-Sleep -Seconds 2
      & powershell -ExecutionPolicy Bypass -File $pushAgent -Adb $Adb -Port $Port -Run | Out-Null
      & powershell -ExecutionPolicy Bypass -File $forward -Adb $Adb -Port $Port | Out-Null
    } catch {
      $logLines.Add("[" + (Get-Date).ToString("o") + "] restart flow failed: " + ($_ | Out-String).Trim())
    }
    Start-Sleep -Milliseconds 800
    continue
  }

  $probePid = $probePidNow
  $agentPid = $agentPidNow
  $appSampleBefore = Get-ProcStatusSample -TargetPid $probePid
  $agentSampleBefore = Get-ProcStatusSample -TargetPid $agentPid

  $common = @{
    RemoteHost = "127.0.0.1"
    Port = $Port
    TargetPid = [int]$probePid
    SkipDebug = $true
  }

  $okCycle = $true
  $detail = ""

  try {
    $readOut = Run-TestAgent -RepoRoot $repoRoot -Params ($common + @{
      ReadAddr = $rwAddr
      ReadSize = 16
    })
    $readOk = $readOut -match "read size=\d+ code=0 bytes=(\d+)" -and ([int]$Matches[1] -ge 8)
    if (-not $readOk) {
      $okCycle = $false
      $detail += "read_fail;"
    }

    $writeOut = Run-TestAgent -RepoRoot $repoRoot -Params ($common + @{
      ReadAddr = $writeAddr
      ReadSize = 4
      WriteAddr = $writeAddr
      WriteBytes = $writeBytes
      VerifyAfterWrite = $true
    })
    $writeOk = ($writeOut -match "write size=\d+ code=0 bytes=4") -and ($writeOut -match "verify hex=12 34 56 78")
    if (-not $writeOk) {
      $okCycle = $false
      $detail += "write_fail;"
    }

    if (($iteration % 10) -eq 0) {
      $scanOut = Run-TestAgent -RepoRoot $repoRoot -Params ($common + @{
        ScanU8 = 0x5A
        ScanStart = $rwAddr
        ScanEnd = ($rwAddr + $rwSize)
        ScanPageStart = 0
        ScanPageMax = 16
      })
      $scanOk = $scanOut -match "scan count=(\d+)" -and ([UInt64]$Matches[1] -gt 0)
      if (-not $scanOk) {
        $okCycle = $false
        $detail += "scan_fail;"
      }
    }
  } catch {
    $okCycle = $false
    $detail += "exception;"
    $logLines.Add("[" + (Get-Date).ToString("o") + "] cycle exception: " + ($_ | Out-String).Trim())
  }

  $appSampleAfter = Get-ProcStatusSample -TargetPid $probePid
  $agentSampleAfter = Get-ProcStatusSample -TargetPid $agentPid

  if (-not $okCycle) {
    $failureCount++
    $consecutiveFail++
    if ($consecutiveFail -gt $maxConsecutiveFail) { $maxConsecutiveFail = $consecutiveFail }
  } else {
    $consecutiveFail = 0
  }

  $samples.Add([pscustomobject]@{
    ts = $now.ToString("o")
    iteration = $iteration
    ok = $okCycle
    detail = $detail
    app_pid = $probePid
    agent_pid = $agentPid
    app_rss_kb_before = $appSampleBefore.rss_kb
    app_rss_kb_after = $appSampleAfter.rss_kb
    app_threads_before = $appSampleBefore.threads
    app_threads_after = $appSampleAfter.threads
    agent_rss_kb_before = $agentSampleBefore.rss_kb
    agent_rss_kb_after = $agentSampleAfter.rss_kb
    agent_threads_before = $agentSampleBefore.threads
    agent_threads_after = $agentSampleAfter.threads
  })

  $status = if ($okCycle) { "OK" } else { "FAIL" }
  $logLines.Add(
    "[" + $now.ToString("o") + "] #" + $iteration + " " + $status +
    " app_rss_kb=" + $appSampleAfter.rss_kb +
    " app_threads=" + $appSampleAfter.threads +
    " agent_rss_kb=" + $agentSampleAfter.rss_kb +
    " agent_threads=" + $agentSampleAfter.threads +
    " detail=" + $detail
  )

  Start-Sleep -Milliseconds $PauseMs
}

$finish = Get-Date
$elapsed = [math]::Round(($finish - $start).TotalSeconds, 2)

$appRssSeries = @($samples | ForEach-Object { [int]$_.app_rss_kb_after })
$agentRssSeries = @($samples | ForEach-Object { [int]$_.agent_rss_kb_after })
$appThrSeries = @($samples | ForEach-Object { [int]$_.app_threads_after })
$agentThrSeries = @($samples | ForEach-Object { [int]$_.agent_threads_after })

$appRssStart = if ($appRssSeries.Count -gt 0) { $appRssSeries[0] } else { 0 }
$appRssEnd = if ($appRssSeries.Count -gt 0) { $appRssSeries[-1] } else { 0 }
$agentRssStart = if ($agentRssSeries.Count -gt 0) { $agentRssSeries[0] } else { 0 }
$agentRssEnd = if ($agentRssSeries.Count -gt 0) { $agentRssSeries[-1] } else { 0 }

$appRssDelta = $appRssEnd - $appRssStart
$agentRssDelta = $agentRssEnd - $agentRssStart

$appThrMin = if ($appThrSeries.Count -gt 0) { ($appThrSeries | Measure-Object -Minimum).Minimum } else { 0 }
$appThrMax = if ($appThrSeries.Count -gt 0) { ($appThrSeries | Measure-Object -Maximum).Maximum } else { 0 }
$agentThrMin = if ($agentThrSeries.Count -gt 0) { ($agentThrSeries | Measure-Object -Minimum).Minimum } else { 0 }
$agentThrMax = if ($agentThrSeries.Count -gt 0) { ($agentThrSeries | Measure-Object -Maximum).Maximum } else { 0 }

# Release gate style thresholds (conservative, can be tuned by team baseline)
$rssDeltaGateKb = 64 * 1024
$threadLeakGate = 12

$okNoCrash = ($restartCount -eq 0)
$okNoFailCycle = ($failureCount -eq 0)
$okAppRss = ($appRssDelta -le $rssDeltaGateKb)
$okAgentRss = ($agentRssDelta -le $rssDeltaGateKb)
$okAppThreads = (($appThrMax - $appThrMin) -le $threadLeakGate)
$okAgentThreads = (($agentThrMax - $agentThrMin) -le $threadLeakGate)

Add-Result -List $results -Name "duration_reached" -Passed ($elapsed -ge ($DurationSeconds - 5)) -Detail ("elapsed=" + $elapsed + "s target=" + $DurationSeconds + "s")
Add-Result -List $results -Name "no_restart" -Passed $okNoCrash -Detail ("restart_count=" + $restartCount)
Add-Result -List $results -Name "no_cycle_fail" -Passed $okNoFailCycle -Detail ("failure_count=" + $failureCount + " max_consecutive=" + $maxConsecutiveFail)
Add-Result -List $results -Name "app_rss_growth_gate" -Passed $okAppRss -Detail ("delta_kb=" + $appRssDelta + " gate_kb=" + $rssDeltaGateKb)
Add-Result -List $results -Name "agent_rss_growth_gate" -Passed $okAgentRss -Detail ("delta_kb=" + $agentRssDelta + " gate_kb=" + $rssDeltaGateKb)
Add-Result -List $results -Name "app_thread_leak_gate" -Passed $okAppThreads -Detail ("min=" + $appThrMin + " max=" + $appThrMax + " gate_delta=" + $threadLeakGate)
Add-Result -List $results -Name "agent_thread_leak_gate" -Passed $okAgentThreads -Detail ("min=" + $agentThrMin + " max=" + $agentThrMax + " gate_delta=" + $threadLeakGate)

$report = [ordered]@{
  created_at = (Get-Date -Format o)
  start_at = $start.ToString("o")
  end_at = $finish.ToString("o")
  elapsed_sec = $elapsed
  duration_target_sec = $DurationSeconds
  package = $Package
  pid_last = @{
    app = $probePid
    agent = $agentPid
  }
  rw_region = ("0x" + $rwAddr.ToString("X"))
  rw_size = $rwSize
  summary = @{
    iterations = $iteration
    restart_count = $restartCount
    failure_count = $failureCount
    max_consecutive_fail = $maxConsecutiveFail
    app_rss_start_kb = $appRssStart
    app_rss_end_kb = $appRssEnd
    app_rss_delta_kb = $appRssDelta
    agent_rss_start_kb = $agentRssStart
    agent_rss_end_kb = $agentRssEnd
    agent_rss_delta_kb = $agentRssDelta
    app_threads_min = $appThrMin
    app_threads_max = $appThrMax
    agent_threads_min = $agentThrMin
    agent_threads_max = $agentThrMax
  }
  results = $results
  samples = $samples
  log = $logPath
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
$logLines | Set-Content -Path $logPath -Encoding UTF8

$failed = @($results | Where-Object { -not $_.passed }).Count
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# 4h Soak Acceptance Report")
$lines.Add("")
$lines.Add("- start: " + $start.ToString("yyyy-MM-dd HH:mm:ss"))
$lines.Add("- end: " + $finish.ToString("yyyy-MM-dd HH:mm:ss"))
$lines.Add("- elapsed(s): " + $elapsed)
$lines.Add("- iterations: " + $iteration)
$lines.Add("- restarts: " + $restartCount)
$lines.Add("- failures: " + $failureCount)
$lines.Add("- failed checks: " + $failed)
$lines.Add("- json: " + $jsonPath)
$lines.Add("- log: " + $logPath)
$lines.Add("")
$lines.Add("| Check | Result | Detail |")
$lines.Add("|---|---|---|")
foreach ($r in $results) {
  $state = if ($r.passed) { "PASS" } else { "FAIL" }
  $lines.Add("| " + $r.name + " | " + $state + " | " + $r.detail + " |")
}
$lines | Set-Content -Path $mdPath -Encoding UTF8

Write-Host ("Report JSON: " + $jsonPath)
Write-Host ("Report MD:   " + $mdPath)
Write-Host ("Report LOG:  " + $logPath)
Write-Host ("Summary: failed=" + $failed + " total=" + $results.Count)

if ($failed -gt 0 -and -not $NoExitOnFail) {
  exit 1
}
