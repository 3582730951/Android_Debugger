param(
  [string]$Adb = "E:\\gjzs\\adb.exe",
  [string]$Exe = ".\\build\\windows_client\\src\\windows_client\\r3_windows_client.exe",
  [int]$BenchSeconds = 20,
  [int]$BenchDepth = 5,
  [int]$CompareDepthSmall = 3,
  [int]$CompareDepthLarge = 10,
  [string]$StageTag = "P0",
  [string]$OutLog = "..\\memory\\2026-02-06_metrics_segments.txt",
  [string]$OutJson = "..\\memory\\2026-02-06_metrics_segments.json"
)

$ErrorActionPreference = "Stop"

$log = New-Object System.Collections.Generic.List[string]
$stageResults = New-Object System.Collections.Generic.List[object]

function Get-Pids {
  $pidApp = (& $Adb shell pidof com.r3.debugprobe) -join ""
  $pidAgent = (& $Adb shell pidof r3_android_agent) -join ""
  return @($pidApp.Trim(), $pidAgent.Trim())
}

function Sample-Android([string]$pidApp, [string]$pidAgent) {
  $sample = [ordered]@{
    ts = (Get-Date -Format o)
    app_pid = $pidApp
    agent_pid = $pidAgent
    app_top = ""
    agent_top = ""
  }
  if ($pidApp) {
    $top = (& $Adb shell top -b -n 1 -p $pidApp) -join "`n"
    $sample.app_top = $top
    $log.Add("android app pid=$pidApp")
    $log.Add($top)
  }
  if ($pidAgent) {
    $top = (& $Adb shell top -b -n 1 -p $pidAgent) -join "`n"
    $sample.agent_top = $top
    $log.Add("android agent pid=$pidAgent")
    $log.Add($top)
  }
  return [pscustomobject]$sample
}

function Parse-BenchLine([string]$line) {
  if ([string]::IsNullOrWhiteSpace($line)) {
    return $null
  }
  $mode = ([regex]::Match($line, 'mode=([^\s]+)').Groups[1].Value)
  $seconds = [double]([regex]::Match($line, 'seconds=([0-9.]+)').Groups[1].Value)
  $iterations = [long]([regex]::Match($line, 'iterations=(\d+)').Groups[1].Value)
  $chains = [long]([regex]::Match($line, 'chains=(\d+)').Groups[1].Value)
  $ops = [double]([regex]::Match($line, 'ops=([0-9.]+)').Groups[1].Value)
  $useIndex = [int]([regex]::Match($line, 'use_index=(\d+)').Groups[1].Value)
  $strict = [int]([regex]::Match($line, 'strict=(\d+)').Groups[1].Value)
  $connectMs = [double]([regex]::Match($line, 'connect_ms=([0-9.]+)').Groups[1].Value)
  $attachMs = [double]([regex]::Match($line, 'attach_ms=([0-9.]+)').Groups[1].Value)
  $scanMs = [double]([regex]::Match($line, 'scan_ms=([0-9.]+)').Groups[1].Value)
  $verifyMs = [double]([regex]::Match($line, 'verify_ms=([0-9.]+)').Groups[1].Value)
  $packets = [long]([regex]::Match($line, 'packets=(\d+)').Groups[1].Value)
  $reqBytes = [long]([regex]::Match($line, 'req_bytes=(\d+)').Groups[1].Value)
  $rspBytes = [long]([regex]::Match($line, 'rsp_bytes=(\d+)').Groups[1].Value)
  $readCalls = [long]([regex]::Match($line, 'read_calls=(\d+)').Groups[1].Value)
  $readBytes = [long]([regex]::Match($line, 'read_bytes=(\d+)').Groups[1].Value)
  $avgChunk = [double]([regex]::Match($line, 'avg_chunk=([0-9.]+)').Groups[1].Value)
  return [pscustomobject]@{
    mode = $mode
    use_index = ($useIndex -ne 0)
    strict_mode = ($strict -ne 0)
    seconds = $seconds
    iterations = $iterations
    chains = $chains
    ops_per_sec = $ops
    connect_ms = $connectMs
    attach_ms = $attachMs
    scan_ms = $scanMs
    verify_ms = $verifyMs
    net_packets = $packets
    net_req_bytes = $reqBytes
    net_rsp_bytes = $rspBytes
    read_calls = $readCalls
    read_bytes = $readBytes
    avg_chunk_bytes = $avgChunk
    line = $line
  }
}

function Run-StageProcess([string]$name, [string]$argLine, [int]$durationSec, [string]$outFile, [string]$errFile) {
  $start = Get-Date
  $log.Add("stage=$name start time=$($start.ToString('o'))")
  if (Test-Path $outFile) { Remove-Item -Force $outFile }
  if (Test-Path $errFile) { Remove-Item -Force $errFile }

  $proc = Start-Process -FilePath $Exe -ArgumentList $argLine -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
  $samples = New-Object System.Collections.Generic.List[object]

  for ($i = 0; $i -lt $durationSec; $i++) {
    Start-Sleep -Seconds 1
    $log.Add("=== sample $name $i time $(Get-Date -Format o) ===")

    $win = [ordered]@{
      ts = (Get-Date -Format o)
      exited = $false
      cpu = 0.0
      ws = 0
      pm = 0
    }
    $p = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if ($p) {
      $win.cpu = $p.CPU
      $win.ws = $p.WorkingSet64
      $win.pm = $p.PrivateMemorySize64
      $log.Add("win: CPU=$($p.CPU) WS=$($p.WorkingSet64) PM=$($p.PrivateMemorySize64)")
    } else {
      $win.exited = $true
      $log.Add("win: exited")
    }
    $pids = Get-Pids
    $android = Sample-Android $pids[0] $pids[1]
    $samples.Add([pscustomobject]@{
      win = [pscustomobject]$win
      android = $android
    })
  }

  if (-not $proc.HasExited) { $proc.WaitForExit() }
  $exitCode = $null
  try {
    $exitCode = [int]$proc.ExitCode
  } catch {
    $exitCode = -999
  }
  $end = Get-Date
  $log.Add("stage=$name end time=$($end.ToString('o')) exit=$exitCode")

  $bench = $null
  if (Test-Path $outFile) {
    $log.Add("stage=$name output:")
    $lines = Get-Content -Path $outFile -ErrorAction SilentlyContinue
    if ($null -ne $lines) {
      $log.AddRange([string[]]$lines)
      $benchLine = ($lines | Where-Object { $_ -match "^BENCHPTR mode=" } | Select-Object -First 1)
      $bench = Parse-BenchLine $benchLine
    }
  }
  if (Test-Path $errFile) {
    $log.Add("stage=$name error:")
    $lines = Get-Content -Path $errFile -ErrorAction SilentlyContinue
    if ($null -ne $lines) {
      $log.AddRange([string[]]$lines)
    }
  }

  $stageResults.Add([pscustomobject]([ordered]@{
    stage = $name
    stage_tag = $StageTag
    started_at = $start.ToString("o")
    ended_at = $end.ToString("o")
    duration_sec = [math]::Round(($end - $start).TotalSeconds, 3)
    exit_code = $exitCode
    bench = $bench
    stdout = $outFile
    stderr = $errFile
    samples = $samples
  }))
}

if (-not (Test-Path $Adb)) {
  throw "adb not found: $Adb"
}
if (-not (Test-Path $Exe)) {
  throw "bench exe not found: $Exe"
}

# ensure app + agent
& $Adb shell monkey -p com.r3.debugprobe -c android.intent.category.LAUNCHER 1 | Out-Null
Start-Sleep -Seconds 1

# Stage 1: Pointer scan bench (raw/strict)
Run-StageProcess -name "ptr_scan_raw_strict" `
  -argLine "--bench-pointer --bench-pointer-mode=scan_raw --bench-pointer-strict=1 --bench-seconds=$BenchSeconds --bench-depth=$BenchDepth --bench-port=12345" `
  -durationSec $BenchSeconds `
  -outFile "..\\memory\\bench_ptr_scan_raw_strict.txt" `
  -errFile "..\\memory\\bench_ptr_scan_raw_strict.err.txt"

# Stage 2: Pointer scan bench (raw/relaxed)
Run-StageProcess -name "ptr_scan_raw_relaxed" `
  -argLine "--bench-pointer --bench-pointer-mode=scan_raw --bench-pointer-strict=0 --bench-seconds=$BenchSeconds --bench-depth=$BenchDepth --bench-port=12345" `
  -durationSec $BenchSeconds `
  -outFile "..\\memory\\bench_ptr_scan_raw_relaxed.txt" `
  -errFile "..\\memory\\bench_ptr_scan_raw_relaxed.err.txt"

# Stage 3: Pointer scan bench (index/strict)
Run-StageProcess -name "ptr_scan_index_strict" `
  -argLine "--bench-pointer --bench-pointer-mode=scan_index --bench-pointer-strict=1 --bench-seconds=$BenchSeconds --bench-depth=$BenchDepth --bench-port=12345" `
  -durationSec $BenchSeconds `
  -outFile "..\\memory\\bench_ptr_scan_index_strict.txt" `
  -errFile "..\\memory\\bench_ptr_scan_index_strict.err.txt"

# Stage 4: Pointer scan bench (index/relaxed)
Run-StageProcess -name "ptr_scan_index_relaxed" `
  -argLine "--bench-pointer --bench-pointer-mode=scan_index --bench-pointer-strict=0 --bench-seconds=$BenchSeconds --bench-depth=$BenchDepth --bench-port=12345" `
  -durationSec $BenchSeconds `
  -outFile "..\\memory\\bench_ptr_scan_index_relaxed.txt" `
  -errFile "..\\memory\\bench_ptr_scan_index_relaxed.err.txt"

# Stage 5: Pointer compare bench (small)
Run-StageProcess -name "ptr_compare_small" `
  -argLine "--bench-pointer --bench-pointer-mode=compare --bench-pointer-strict=1 --bench-seconds=$BenchSeconds --bench-depth=$CompareDepthSmall --bench-port=12345" `
  -durationSec $BenchSeconds `
  -outFile "..\\memory\\bench_ptr_compare_small.txt" `
  -errFile "..\\memory\\bench_ptr_compare_small.err.txt"

# Stage 6: Pointer compare bench (large)
Run-StageProcess -name "ptr_compare_large" `
  -argLine "--bench-pointer --bench-pointer-mode=compare --bench-pointer-strict=1 --bench-seconds=$BenchSeconds --bench-depth=$CompareDepthLarge --bench-port=12345" `
  -durationSec $BenchSeconds `
  -outFile "..\\memory\\bench_ptr_compare_large.txt" `
  -errFile "..\\memory\\bench_ptr_compare_large.err.txt"

# Stage 7: Breakpoint stage (perf write + ptrace exec)
$bpStart = Get-Date
$log.Add("stage=breakpoints start time=$($bpStart.ToString('o'))")

$targets = Get-Content -Path ".\\build\\windows_client\\src\\windows_client\\seach_point\\auto_targets.txt"
$map = @{}
foreach ($line in $targets) {
  if ($line -match "^(\w+)=0x([0-9a-fA-F]+)$") {
    $map[$matches[1]] = "0x$($matches[2])"
  }
}
$rw = $map["rw_region"]
$exec = $map["ptrace_exec_addr"]

$pidApp = (Get-Pids)[0]
$pidAgent = (Get-Pids)[1]

$client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 12345)
$client.ReceiveTimeout = 8000
$client.SendTimeout = 8000
$stream = $client.GetStream()
$bw = New-Object System.IO.BinaryWriter($stream)
$br = New-Object System.IO.BinaryReader($stream)

function Send-Packet([UInt16]$cmd, [byte[]]$payload) {
  $bw.Write([UInt32]0x52444441)
  $bw.Write($cmd)
  $bw.Write([UInt16]0)
  $bw.Write([UInt32]$payload.Length)
  if ($payload.Length -gt 0) { $bw.Write($payload) }
  $bw.Flush()
}
function Recv-Packet() {
  $magic = $br.ReadUInt32()
  $cmd = $br.ReadUInt16()
  $res = $br.ReadUInt16()
  $size = $br.ReadUInt32()
  $payload = if ($size -gt 0) { $br.ReadBytes($size) } else { @() }
  return @{ magic = $magic; cmd = $cmd; size = $size; payload = $payload }
}
function Send-And-Recv([UInt16]$cmd, [byte[]]$payload) {
  Send-Packet $cmd $payload
  return Recv-Packet
}

$attachPayload = New-Object byte[] 8
[BitConverter]::GetBytes([UInt32]$pidApp).CopyTo($attachPayload, 0)
[BitConverter]::GetBytes([UInt32]0).CopyTo($attachPayload, 4)
$resp = Send-And-Recv 0x0002 $attachPayload
$log.Add("breakpoints: attach resp size=$($resp.size)")

$perfAddr = [UInt64]$rw + 0x100
$bpPayload = New-Object byte[] 16
[BitConverter]::GetBytes([UInt32]$pidApp).CopyTo($bpPayload, 0)
$bpPayload[4] = 1
$bpPayload[5] = 1
$bpPayload[6] = 4
$bpPayload[7] = 0
[BitConverter]::GetBytes([UInt64]$perfAddr).CopyTo($bpPayload, 8)
$resp = Send-And-Recv 0x0013 $bpPayload
$log.Add("breakpoints: perf set resp size=$($resp.size)")

$execAddr = [UInt64]$exec
$bpPayload2 = New-Object byte[] 16
[BitConverter]::GetBytes([UInt32]$pidApp).CopyTo($bpPayload2, 0)
$bpPayload2[4] = 0
$bpPayload2[5] = 0
$bpPayload2[6] = 4
$bpPayload2[7] = 0
[BitConverter]::GetBytes([UInt64]$execAddr).CopyTo($bpPayload2, 8)
$resp = Send-And-Recv 0x0013 $bpPayload2
$log.Add("breakpoints: ptrace set resp size=$($resp.size)")

$readPayload = New-Object byte[] 16
[BitConverter]::GetBytes([UInt64]$perfAddr).CopyTo($readPayload, 0)
[BitConverter]::GetBytes([UInt32]4).CopyTo($readPayload, 8)
$readResp = Send-And-Recv 0x0005 $readPayload
$orig = 0
if ($readResp.payload.Length -ge 8) {
  $bytes = [BitConverter]::ToUInt32($readResp.payload, 4)
  if ($bytes -ge 4) {
    $orig = [BitConverter]::ToUInt32($readResp.payload, 8)
  }
}

$perfHits = 0
$ptraceHits = 0
$bpSamples = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt 15; $i++) {
  Start-Sleep -Seconds 1
  if ($i % 3 -eq 0) {
    $val = $orig -bxor 0x01010101
    $writePayload = New-Object byte[] 20
    [BitConverter]::GetBytes([UInt64]$perfAddr).CopyTo($writePayload, 0)
    [BitConverter]::GetBytes([UInt32]4).CopyTo($writePayload, 8)
    [BitConverter]::GetBytes([UInt32]0).CopyTo($writePayload, 12)
    [BitConverter]::GetBytes([UInt32]$val).CopyTo($writePayload, 16)
    $null = Send-And-Recv 0x0006 $writePayload
  }

  $pollPayload = New-Object byte[] 12
  [BitConverter]::GetBytes([UInt32]$pidApp).CopyTo($pollPayload, 0)
  $pollPayload[4] = 1
  $pollPayload[5] = 0
  [BitConverter]::GetBytes([UInt16]0).CopyTo($pollPayload, 6)
  [BitConverter]::GetBytes([UInt32]64).CopyTo($pollPayload, 8)
  $pollResp = Send-And-Recv 0x0015 $pollPayload
  if ($pollResp.payload.Length -ge 8) {
    $cnt = [BitConverter]::ToUInt32($pollResp.payload, 0)
    if ($cnt -gt 0) {
      for ($j = 0; $j -lt $cnt; $j++) {
        $off = 8 + $j * 24
        if ($pollResp.payload.Length -ge ($off + 24)) {
          $c = [BitConverter]::ToUInt64($pollResp.payload, $off + 16)
          $perfHits += $c
        }
      }
    }
  }

  $pollPayload[4] = 0
  $pollResp2 = Send-And-Recv 0x0015 $pollPayload
  if ($pollResp2.payload.Length -ge 8) {
    $cnt2 = [BitConverter]::ToUInt32($pollResp2.payload, 0)
    if ($cnt2 -gt 0) {
      for ($j = 0; $j -lt $cnt2; $j++) {
        $off = 8 + $j * 24
        if ($pollResp2.payload.Length -ge ($off + 24)) {
          $c2 = [BitConverter]::ToUInt64($pollResp2.payload, $off + 16)
          $ptraceHits += $c2
        }
      }
    }
  }

  $log.Add("=== sample breakpoints $i time $(Get-Date -Format o) ===")
  $log.Add("win: none")
  $pids = Get-Pids
  $android = Sample-Android $pids[0] $pids[1]
  $bpSamples.Add([pscustomobject]@{
    ts = (Get-Date -Format o)
    perf_hits = $perfHits
    ptrace_hits = $ptraceHits
    android = $android
  })
}

$writePayload2 = New-Object byte[] 20
[BitConverter]::GetBytes([UInt64]$perfAddr).CopyTo($writePayload2, 0)
[BitConverter]::GetBytes([UInt32]4).CopyTo($writePayload2, 8)
[BitConverter]::GetBytes([UInt32]0).CopyTo($writePayload2, 12)
[BitConverter]::GetBytes([UInt32]$orig).CopyTo($writePayload2, 16)
$null = Send-And-Recv 0x0006 $writePayload2

$clrPayload = New-Object byte[] 16
[BitConverter]::GetBytes([UInt32]$pidApp).CopyTo($clrPayload, 0)
$clrPayload[4] = 1
$clrPayload[5] = 0
$clrPayload[6] = 0
$clrPayload[7] = 1
[BitConverter]::GetBytes([UInt64]0).CopyTo($clrPayload, 8)
$null = Send-And-Recv 0x0014 $clrPayload
$clrPayload[4] = 0
$null = Send-And-Recv 0x0014 $clrPayload

$client.Close()

$bpEnd = Get-Date
$log.Add("breakpoints: perf_hits=$perfHits ptrace_hits=$ptraceHits")
$log.Add("stage=breakpoints end time=$($bpEnd.ToString('o'))")
$stageResults.Add([pscustomobject]([ordered]@{
  stage = "breakpoints"
  stage_tag = $StageTag
  started_at = $bpStart.ToString("o")
  ended_at = $bpEnd.ToString("o")
  duration_sec = [math]::Round(($bpEnd - $bpStart).TotalSeconds, 3)
  perf_hits = $perfHits
  ptrace_hits = $ptraceHits
  samples = $bpSamples
}))

$pids = Get-Pids
if ($pids[0]) {
  $log.Add("android app meminfo pid=$($pids[0])")
  $log.Add((& $Adb shell dumpsys meminfo $pids[0]) -join "`n")
}
if ($pids[1]) {
  $log.Add("android agent meminfo pid=$($pids[1])")
  $log.Add((& $Adb shell dumpsys meminfo $pids[1]) -join "`n")
}

$outDirLog = Split-Path -Parent $OutLog
if ($outDirLog) {
  New-Item -ItemType Directory -Force -Path $outDirLog | Out-Null
}
$log | Set-Content -Path $OutLog -Encoding UTF8

$summary = [ordered]@{
  stage_tag = $StageTag
  created_at = (Get-Date -Format o)
  app_pid = $pids[0]
  agent_pid = $pids[1]
  stages = $stageResults
  text_log = $OutLog
}
$outDirJson = Split-Path -Parent $OutJson
if ($outDirJson) {
  New-Item -ItemType Directory -Force -Path $outDirJson | Out-Null
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $OutJson -Encoding UTF8
Write-Host "LOG=$OutLog"
Write-Host "JSON=$OutJson"
