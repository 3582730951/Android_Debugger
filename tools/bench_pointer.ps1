param(
  [int]$Seconds = 600,
  [int]$Depth = 5,
  [ValidateSet("all","scan","scan_raw","scan_index","compare","verify")]
  [string]$Mode = "all",
  [ValidateSet("strict","relaxed","both")]
  [string]$Strict = "strict",
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$Exe = "D:\Code\R3_Code\android_debug\core\build\windows_client\src\windows_client\r3_windows_client.exe",
  [string]$File = "",
  [string]$Stage = "P0",
  [string]$OutJson = "..\\memory\\bench_pointer_summary.json"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Get-CpuSample([string]$adbPath, [string]$pidLocal) {
  $statLines = & $adbPath shell "cat /proc/stat"
  $statLineRaw = ($statLines | Select-Object -First 1)
  if ([string]::IsNullOrWhiteSpace($statLineRaw)) {
    return @{ Total = 0; Proc = 0 }
  }
  $statLine = $statLineRaw.Trim()
  $parts = ($statLine -split '\s+') | Where-Object { $_ -ne "" }
  $total = 0
  for ($i = 1; $i -lt $parts.Length; $i++) {
    $total += [long]$parts[$i]
  }
  $pstatRaw = (& $adbPath shell "su -c 'cat /proc/$pidLocal/stat'" 2>$null | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($pstatRaw)) {
    return @{ Total = $total; Proc = 0 }
  }
  $pstat = $pstatRaw
  if ($pstat -match '^\s*\d+\s+\(.+\)\s+(.+)$') {
    $rest = $Matches[1]
    $fields = ($rest -split '\s+') | Where-Object { $_ -ne "" }
    $utime = [long]$fields[10]
    $stime = [long]$fields[11]
    return @{ Total = $total; Proc = ($utime + $stime) }
  }
  return @{ Total = $total; Proc = 0 }
}

function Get-RssSample([string]$adbPath, [string]$pidLocal) {
  $status = & $adbPath shell "su -c 'cat /proc/$pidLocal/status'" 2>$null
  if (-not $status) {
    return 0
  }
  $rssLine = $status | Where-Object { $_ -match '^VmRSS:' } | Select-Object -First 1
  if ($rssLine -match 'VmRSS:\s+(\d+)\s+kB') {
    return [long]$Matches[1] * 1024
  }
  return 0
}

if (-not (Test-Path $Adb)) { throw "adb not found: $Adb" }
if (-not (Test-Path $Exe)) { throw "bench exe not found: $Exe" }

$targetPid = ((& $Adb shell pidof com.r3.debugprobe) -join "").Trim()
if (-not $targetPid) {
  & $Adb shell am start -n com.r3.debugprobe/android.app.NativeActivity | Out-Null
  Start-Sleep -Seconds 2
  $targetPid = ((& $Adb shell pidof com.r3.debugprobe) -join "").Trim()
}
if (-not $targetPid) {
  throw "target process not found: com.r3.debugprobe"
}
$targetPid = ($targetPid -split '\s+')[0]
$agentPidLine = (& $Adb shell pidof r3_android_agent).Trim()
if (-not $agentPidLine) {
  throw "agent process not found: r3_android_agent"
}
$agentPid = ($agentPidLine -split '\s+')[0]

if ($targetPid -match '^\d+$') {
  & $Adb shell "su -c 'kill -CONT $targetPid'" | Out-Null
}

if ([string]::IsNullOrWhiteSpace($File)) {
  $File = "seach_point/bench_ptr_d$Depth.r3p"
}

$modes = @()
switch ($Mode) {
  "scan" { $modes = @("scan_raw") }
  "scan_raw" { $modes = @("scan_raw") }
  "scan_index" { $modes = @("scan_index") }
  "compare" { $modes = @("compare") }
  "verify" { $modes = @("verify") }
  default { $modes = @("scan_raw","scan_index","compare","verify") }
}

foreach ($mode in $modes) {
  $strictModes = @()
  if ($mode -like "scan*") {
    switch ($Strict) {
      "strict" { $strictModes = @(@{ label = "strict"; value = 1 }) }
      "relaxed" { $strictModes = @(@{ label = "relaxed"; value = 0 }) }
      default { $strictModes = @(@{ label = "strict"; value = 1 }, @{ label = "relaxed"; value = 0 }) }
    }
  } else {
    $strictModes = @(@{ label = "strict"; value = 1 })
  }

  foreach ($strictMode in $strictModes) {
    $cpuStart = Get-CpuSample -adbPath $Adb -pidLocal $agentPid
    $rssStart = Get-RssSample -adbPath $Adb -pidLocal $agentPid

    $benchOut = & $Exe --bench-pointer --bench-pointer-mode=$mode --bench-pointer-strict=$($strictMode.value) --bench-seconds=$Seconds --bench-depth=$Depth --bench-pointer-file=$File

    $cpuEnd = Get-CpuSample -adbPath $Adb -pidLocal $agentPid
    $rssEnd = Get-RssSample -adbPath $Adb -pidLocal $agentPid

    $benchLine = ($benchOut | Where-Object { $_ -match "BENCHPTR mode=$mode" } | Select-Object -First 1)
    if (-not $benchLine) {
      throw "bench output missing for mode=$mode strict=$($strictMode.label)"
    }

    $ops = [double]([regex]::Match($benchLine, 'ops=([0-9.]+)').Groups[1].Value)
    $secondsOut = [double]([regex]::Match($benchLine, 'seconds=([0-9.]+)').Groups[1].Value)
    $iterations = [long]([regex]::Match($benchLine, 'iterations=(\d+)').Groups[1].Value)
    $chains = [long]([regex]::Match($benchLine, 'chains=(\d+)').Groups[1].Value)
    $useIndex = [int]([regex]::Match($benchLine, 'use_index=(\d+)').Groups[1].Value)
    $strictOut = [int]([regex]::Match($benchLine, 'strict=(\d+)').Groups[1].Value)
    $connectMs = [double]([regex]::Match($benchLine, 'connect_ms=([0-9.]+)').Groups[1].Value)
    $attachMs = [double]([regex]::Match($benchLine, 'attach_ms=([0-9.]+)').Groups[1].Value)
    $scanMs = [double]([regex]::Match($benchLine, 'scan_ms=([0-9.]+)').Groups[1].Value)
    $verifyMs = [double]([regex]::Match($benchLine, 'verify_ms=([0-9.]+)').Groups[1].Value)
    $packets = [long]([regex]::Match($benchLine, 'packets=(\d+)').Groups[1].Value)
    $reqBytes = [long]([regex]::Match($benchLine, 'req_bytes=(\d+)').Groups[1].Value)
    $rspBytes = [long]([regex]::Match($benchLine, 'rsp_bytes=(\d+)').Groups[1].Value)
    $readCalls = [long]([regex]::Match($benchLine, 'read_calls=(\d+)').Groups[1].Value)
    $readBytes = [long]([regex]::Match($benchLine, 'read_bytes=(\d+)').Groups[1].Value)
    $avgChunk = [double]([regex]::Match($benchLine, 'avg_chunk=([0-9.]+)').Groups[1].Value)

    $deltaProc = [double]($cpuEnd.Proc - $cpuStart.Proc)
    $deltaTotal = [double]($cpuEnd.Total - $cpuStart.Total)
    $avgCpu = 0.0
    if ($deltaTotal -gt 0) {
      $avgCpu = ($deltaProc / $deltaTotal) * 100.0
    }
    $avgRes = ($rssStart + $rssEnd) / 2.0
    $maxRes = [math]::Max($rssStart, $rssEnd)

    $avgResMB = $avgRes / (1024 * 1024)
    $maxResMB = $maxRes / (1024 * 1024)
    Write-Host ("MODE={0} Strict={1} Depth={2} Seconds={3:N2} Iter={4} Chains={5} Ops={6:N2}/s AvgCPU={7:N1}% AvgRES={8:N1}MB MaxRES={9:N1}MB" -f `
                $mode, $strictMode.label, $Depth, $secondsOut, $iterations, $chains, $ops, $avgCpu, $avgResMB, $maxResMB)

    if (-not $script:summary) {
      $script:summary = @()
    }
    $script:summary += [ordered]@{
      stage = $Stage
      mode = $mode
      use_index = ($useIndex -ne 0)
      strict_mode = ($strictOut -ne 0)
      depth = $Depth
      seconds = $secondsOut
      iterations = $iterations
      chains = $chains
      ops_per_sec = $ops
      connect_ms = [math]::Round($connectMs, 3)
      attach_ms = [math]::Round($attachMs, 3)
      scan_ms = [math]::Round($scanMs, 3)
      verify_ms = [math]::Round($verifyMs, 3)
      net_packets = $packets
      net_req_bytes = $reqBytes
      net_rsp_bytes = $rspBytes
      read_calls = $readCalls
      read_bytes = $readBytes
      avg_chunk_bytes = [math]::Round($avgChunk, 3)
      avg_cpu_pct = [math]::Round($avgCpu, 3)
      avg_res_mb = [math]::Round($avgResMB, 3)
      max_res_mb = [math]::Round($maxResMB, 3)
      target_pid = $targetPid
      agent_pid = $agentPid
      timestamp = (Get-Date -Format o)
    }
  }
}

if ($summary.Count -gt 0) {
  $outObj = [ordered]@{
    stage = $Stage
    created_at = (Get-Date -Format o)
    benchmark = "pointer"
    entries = $summary
  }
  $outDir = Split-Path -Parent $OutJson
  if ($outDir) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
  }
  $outObj | ConvertTo-Json -Depth 6 | Set-Content -Path $OutJson -Encoding UTF8
  Write-Host "JSON=$OutJson"
}
