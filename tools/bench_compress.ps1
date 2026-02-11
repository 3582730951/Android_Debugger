param(
  [int]$Seconds = 10,
  [int]$Size = 1048576,
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$Exe = "D:\Code\R3_Code\android_debug\core\build\windows_client\src\windows_client\r3_windows_client.exe",
  [ValidateSet("on","off","both")]
  [string]$Mode = "both",
  [switch]$DebugSamples
)

$ErrorActionPreference = "Stop"

function Parse-SizeToken([string]$token) {
  if (-not $token) { return 0 }
  $t = $token.Trim()
  if ($t -match '^(\d+(?:\.\d+)?)([KMG])$') {
    $num = [double]$Matches[1]
    $unit = $Matches[2]
    switch ($unit) {
      "K" { return [long]($num * 1024) }
      "M" { return [long]($num * 1024 * 1024) }
      "G" { return [long]($num * 1024 * 1024 * 1024) }
    }
  }
  if ($t -match '^\d+$') {
    return [long]$t
  }
  return 0
}

function Get-CpuSample([string]$adbPath, [string]$pidLocal) {
  $statLines = & $adbPath shell "cat /proc/stat"
  $statLine = ($statLines | Select-Object -First 1).Trim()
  $parts = ($statLine -split '\s+') | Where-Object { $_ -ne "" }
  $total = 0
  for ($i = 1; $i -lt $parts.Length; $i++) {
    $total += [long]$parts[$i]
  }
  $pstat = (& $adbPath shell "su -c 'cat /proc/$pidLocal/stat'").Trim()
  if ($pstat -match '^\s*\d+\s+\(.+\)\s+(.+)$') {
    $rest = $Matches[1]
    $fields = ($rest -split '\s+') | Where-Object { $_ -ne "" }
    # rest[0] is field4 (ppid), utime is field14 => rest[10]; stime is field15 => rest[11]
    $utime = [long]$fields[10]
    $stime = [long]$fields[11]
    return @{ Total = $total; Proc = ($utime + $stime) }
  }
  return @{ Total = $total; Proc = 0 }
}

function Get-RssSample([string]$adbPath, [string]$pidLocal) {
  $status = & $adbPath shell "su -c 'cat /proc/$pidLocal/status'"
  $rssLine = $status | Where-Object { $_ -match '^VmRSS:' } | Select-Object -First 1
  if ($rssLine -match 'VmRSS:\s+(\d+)\s+kB') {
    return [long]$Matches[1] * 1024
  }
  return 0
}

if (-not (Test-Path $Adb)) { throw "adb not found: $Adb" }
if (-not (Test-Path $Exe)) { throw "bench exe not found: $Exe" }

$targetPid = (& $Adb shell pidof com.r3.debugprobe).Trim()
if (-not $targetPid) {
  throw "target process not found: com.r3.debugprobe"
}
$agentPidLine = (& $Adb shell pidof r3_android_agent).Trim()
if (-not $agentPidLine) {
  throw "agent process not found: r3_android_agent"
}
$agentPid = ($agentPidLine -split '\s+')[0]

# Ensure target process is running (may be stopped by previous ptrace attach)
& $Adb shell "su -c 'kill -CONT $targetPid'" | Out-Null

$results = @()
$modes = @()
switch ($Mode) {
  "on" { $modes = @("on") }
  "off" { $modes = @("off") }
  default { $modes = @("off","on") }
}
foreach ($mode in $modes) {
  $cpuStart = Get-CpuSample -adbPath $Adb -pidLocal $agentPid
  $rssStart = Get-RssSample -adbPath $Adb -pidLocal $agentPid
  $benchOut = & $Exe --bench-compress --bench-mode=$mode --bench-seconds=$Seconds --bench-size=$Size
  $cpuEnd = Get-CpuSample -adbPath $Adb -pidLocal $agentPid
  $rssEnd = Get-RssSample -adbPath $Adb -pidLocal $agentPid
  if ($DebugSamples) {
    Write-Host ("DEBUG mode={0} cpuStartTotal={1} cpuStartProc={2} cpuEndTotal={3} cpuEndProc={4} rssStart={5} rssEnd={6}" -f `
                $mode, $cpuStart.Total, $cpuStart.Proc, $cpuEnd.Total, $cpuEnd.Proc, $rssStart, $rssEnd)
  }

  $benchLine = ($benchOut | Where-Object { $_ -match "BENCH mode=$mode" } | Select-Object -First 1)
  if (-not $benchLine) {
    throw "bench output missing for mode=$mode"
  }
  $mbps = [double]([regex]::Match($benchLine, 'mbps=([0-9.]+)').Groups[1].Value)
  $bytes = [long]([regex]::Match($benchLine, 'bytes=(\d+)').Groups[1].Value)
  $secs = [double]([regex]::Match($benchLine, 'seconds=([0-9.]+)').Groups[1].Value)
  $deltaProc = [double]($cpuEnd.Proc - $cpuStart.Proc)
  $deltaTotal = [double]($cpuEnd.Total - $cpuStart.Total)
  $avgCpu = 0.0
  if ($deltaTotal -gt 0) {
    $avgCpu = ($deltaProc / $deltaTotal) * 100.0
  }
  $avgRes = ($rssStart + $rssEnd) / 2.0
  $maxRes = [math]::Max($rssStart, $rssEnd)

  $results += [pscustomobject]@{
    Mode = $mode
    MBps = $mbps
    Bytes = $bytes
    Seconds = $secs
    AvgCpu = $avgCpu
    MaxCpu = $avgCpu
    AvgRes = $avgRes
    MaxRes = $maxRes
  }
}

$results | ForEach-Object {
  $avgResMB = $_.AvgRes / (1024 * 1024)
  $maxResMB = $_.MaxRes / (1024 * 1024)
  Write-Host ("MODE={0} MBps={1:N2} Seconds={2:N2} AvgCPU={3:N1}% MaxCPU={4:N1}% AvgRES={5:N1}MB MaxRES={6:N1}MB" -f `
              $_.Mode, $_.MBps, $_.Seconds, $_.AvgCpu, $_.MaxCpu, $avgResMB, $maxResMB)
}
