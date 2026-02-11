param(
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$Device = "",
  [string]$RemoteHost = "127.0.0.1",
  [int]$Port = 12345,
  [string]$Package = "com.r3.debugprobe",
  [string]$Activity = "android.app.NativeActivity",
  [string]$OutDir = "build\adb_full_test",
  [switch]$RunPointerBench
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Adb {
  param([string[]]$AdbArgs)
  if ([string]::IsNullOrWhiteSpace($Device)) {
    return & $Adb @AdbArgs
  }
  return & $Adb -s $Device @AdbArgs
}

function To-Hex64([UInt64]$value) {
  return ("0x{0:X}" -f $value)
}

function Strip-Tag64([UInt64]$value) {
  return ($value -band 0x00FFFFFFFFFFFFFF)
}

function Parse-HexBytes {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) {
    return @()
  }
  $parts = $Text.Trim().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
  $bytes = New-Object System.Collections.Generic.List[byte]
  foreach ($part in $parts) {
    try {
      $bytes.Add([Convert]::ToByte($part, 16))
    } catch {
      return @()
    }
  }
  return ,$bytes.ToArray()
}

function Invoke-TestAgent {
  param(
    [string]$Name,
    [hashtable]$Params,
    [string]$ScriptPath,
    [string]$Dir
  )
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
  $path = Join-Path $Dir ($Name + "_" + $stamp + ".log")
  try {
    $output = & $ScriptPath @Params 2>&1
    $text = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine)
    Set-Content -Path $path -Value $text -Encoding UTF8
    return @{
      ok = $true
      text = $text
      path = $path
    }
  } catch {
    $text = $_ | Out-String
    Set-Content -Path $path -Value $text -Encoding UTF8
    return @{
      ok = $false
      text = $text
      path = $path
    }
  }
}

function Add-Result {
  param(
    [System.Collections.Generic.List[object]]$List,
    [string]$Name,
    [bool]$Passed,
    [string]$Detail,
    [string]$LogPath = ""
  )
  $item = [ordered]@{
    name = $Name
    passed = $Passed
    detail = $Detail
    log = $LogPath
  }
  $List.Add([pscustomobject]$item)
  $mark = if ($Passed) { "[PASS]" } else { "[FAIL]" }
  Write-Host "$mark $Name - $Detail"
}

function Get-ProbePid {
  $pidRaw = ((Invoke-Adb -AdbArgs @("shell", "pidof", $Package)) | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($pidRaw)) {
    return ""
  }
  return ($pidRaw -split '\s+')[0]
}

function Parse-ProbeMarkers {
  param([object[]]$Lines)
  $state = [ordered]@{
    rwAddr = [UInt64]0
    rwSize = [UInt64]0
    roAddr = [UInt64]0
    roSize = [UInt64]0
    ptraceAddr = [UInt64]0
    chains = @{}
  }
  foreach ($lineRaw in $Lines) {
    $line = [string]$lineRaw
    if ($line -match "rw_region=0x([0-9a-fA-F]+)\s+size=(\d+)") {
      $state.rwAddr = [Convert]::ToUInt64($Matches[1], 16)
      $state.rwSize = [Convert]::ToUInt64($Matches[2], 10)
      continue
    }
    if ($line -match "ro_region=0x([0-9a-fA-F]+)\s+size=(\d+)") {
      $state.roAddr = [Convert]::ToUInt64($Matches[1], 16)
      $state.roSize = [Convert]::ToUInt64($Matches[2], 10)
      continue
    }
    if ($line -match "ptr_chain_(\d+)\s+depth=(\d+)\s+base=0x([0-9a-fA-F]+)\s+value_addr=0x([0-9a-fA-F]+)\s+value=0x([0-9a-fA-F]+)") {
      $depth = [int]$Matches[2]
      $state.chains[$depth] = [pscustomobject]@{
        depth = $depth
        base = [Convert]::ToUInt64($Matches[3], 16)
        value_addr = [Convert]::ToUInt64($Matches[4], 16)
        value_seed = [Convert]::ToUInt64($Matches[5], 16)
      }
      continue
    }
    if ($line -match "ptrace_exec_addr=0x([0-9a-fA-F]+)") {
      $state.ptraceAddr = [Convert]::ToUInt64($Matches[1], 16)
      continue
    }
  }
  return $state
}

if (-not (Test-Path $Adb)) {
  throw "adb not found: $Adb"
}

$repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path
$testAgentPath = Join-Path $repoRoot "tools\test_agent.ps1"
$testBpPath = Join-Path $repoRoot "tools\test_ptrace_bp.ps1"
$pushAgentPath = Join-Path $repoRoot "tools\push_run_agent.ps1"
$forwardPath = Join-Path $repoRoot "tools\adb_forward.ps1"
$benchPointerPath = Join-Path $repoRoot "tools\bench_pointer.ps1"

if (-not (Test-Path $testAgentPath)) { throw "missing script: $testAgentPath" }
if (-not (Test-Path $testBpPath)) { throw "missing script: $testBpPath" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'

# 1) Device/App/Agent ready
$devices = Invoke-Adb -AdbArgs @("devices")
if (($devices | Out-String) -notmatch "device") {
  throw "no online adb device"
}

# Clear stale logs and restart app so parsed markers are from current process/session only.
Invoke-Adb -AdbArgs @("logcat", "-c") | Out-Null
Invoke-Adb -AdbArgs @("shell", "am", "force-stop", $Package) | Out-Null
Start-Sleep -Milliseconds 600
Invoke-Adb -AdbArgs @("shell", "am", "start", "-n", "$Package/$Activity") | Out-Null
Start-Sleep -Seconds 2

$probePid = Get-ProbePid
if ($probePid -notmatch '^\d+$') {
  Start-Sleep -Seconds 1
  $probePid = Get-ProbePid
}
if ($probePid -notmatch '^\d+$') {
  throw "target process not found after restart: $Package"
}
Add-Result -List $results -Name "app_running" -Passed $true -Detail ("pid=" + $probePid + " (fresh start)")

# 2) Start agent and forward
& powershell -ExecutionPolicy Bypass -File $pushAgentPath -Adb $Adb -Port $Port -Run | Out-Null
& powershell -ExecutionPolicy Bypass -File $forwardPath -Adb $Adb -Port $Port | Out-Null
Add-Result -List $results -Name "agent_forward_ready" -Passed $true -Detail ("tcp:" + $Port)

# 3) Parse current-session probe logs for addresses
$rwAddr = [UInt64]0
$rwSize = [UInt64]0
$roAddr = [UInt64]0
$roSize = [UInt64]0
$ptraceAddr = [UInt64]0
$chains = @{}

$markersReady = $false
for ($try = 0; $try -lt 20; $try++) {
  $logLines = Invoke-Adb -AdbArgs @("logcat", "-d", "-s", "R3Probe:D", "*:S")
  $parsed = Parse-ProbeMarkers -Lines $logLines
  $rwAddr = [UInt64]$parsed.rwAddr
  $rwSize = [UInt64]$parsed.rwSize
  $roAddr = [UInt64]$parsed.roAddr
  $roSize = [UInt64]$parsed.roSize
  $ptraceAddr = [UInt64]$parsed.ptraceAddr
  $chains = $parsed.chains
  $okChains = $true
  foreach ($d in @(3, 5, 7, 10)) {
    if (-not $chains.ContainsKey($d)) {
      $okChains = $false
      break
    }
  }
  if ($rwAddr -ne 0 -and $rwSize -gt 0 -and $ptraceAddr -ne 0 -and $okChains) {
    $markersReady = $true
    break
  }
  Start-Sleep -Milliseconds 500
}

if ($rwAddr -eq 0 -or $rwSize -eq 0) {
  throw "failed to parse rw_region from R3Probe logcat"
}
if ($ptraceAddr -eq 0) {
  throw "failed to parse ptrace_exec_addr from R3Probe logcat"
}
foreach ($d in @(3, 5, 7, 10)) {
  if (-not $chains.ContainsKey($d)) {
    throw "failed to parse ptr_chain_$d from R3Probe logcat"
  }
}

Add-Result -List $results -Name "parse_r3probe_log" -Passed $true -Detail ("rw=" + (To-Hex64 $rwAddr) + " size=" + $rwSize + " ptrace=" + (To-Hex64 $ptraceAddr))

$common = @{
  RemoteHost = $RemoteHost
  Port = $Port
  TargetPid = [int]$probePid
  SkipDebug = $true
}

# 4) List processes
$rList = Invoke-TestAgent -Name "list_processes" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{ ListProcesses = $true })
$okList = $rList.ok -and ($rList.text -match "process count=(\d+)")
$detailList = if ($okList) { "count=" + $Matches[1] } else { "test_agent list failed" }
Add-Result -List $results -Name "list_processes" -Passed $okList -Detail $detailList -LogPath $rList.path

# 5) Read RW + RO
$rReadRw = Invoke-TestAgent -Name "read_rw" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
  ReadAddr = $rwAddr
  ReadSize = 16
})
$okReadRw = $rReadRw.ok -and ($rReadRw.text -match "read size=\d+ code=0 bytes=(\d+)") -and ([int]$Matches[1] -ge 8)
Add-Result -List $results -Name "read_rw" -Passed $okReadRw -Detail ("addr=" + (To-Hex64 $rwAddr)) -LogPath $rReadRw.path

if ($roAddr -ne 0 -and $roSize -gt 0) {
  $rReadRo = Invoke-TestAgent -Name "read_ro" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
    ReadAddr = $roAddr
    ReadSize = 16
  })
  $okReadRo = $rReadRo.ok -and ($rReadRo.text -match "read size=\d+ code=0 bytes=(\d+)") -and ([int]$Matches[1] -ge 8)
  Add-Result -List $results -Name "read_ro" -Passed $okReadRo -Detail ("addr=" + (To-Hex64 $roAddr)) -LogPath $rReadRo.path
}

# 6) Write RW + verify + restore
$writeAddr = $rwAddr + 0x120
$rReadOrig = Invoke-TestAgent -Name "read_before_write" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
  ReadAddr = $writeAddr
  ReadSize = 4
})
$origBytes = @()
if ($rReadOrig.ok -and $rReadOrig.text -match "read hex=([0-9A-F ]+)") {
  $origBytes = Parse-HexBytes -Text $Matches[1]
}
$okReadOrig = $rReadOrig.ok -and ($origBytes.Length -eq 4)
Add-Result -List $results -Name "read_before_write" -Passed $okReadOrig -Detail ("addr=" + (To-Hex64 $writeAddr)) -LogPath $rReadOrig.path

$writeBytes = [byte[]](0x12, 0x34, 0x56, 0x78)
$rWrite = Invoke-TestAgent -Name "write_verify_rw" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
  ReadAddr = $writeAddr
  ReadSize = 4
  WriteAddr = $writeAddr
  WriteBytes = $writeBytes
  VerifyAfterWrite = $true
})
$okWrite = $rWrite.ok -and ($rWrite.text -match "write size=\d+ code=0 bytes=4") -and ($rWrite.text -match "verify hex=12 34 56 78")
Add-Result -List $results -Name "write_verify_rw" -Passed $okWrite -Detail ("addr=" + (To-Hex64 $writeAddr)) -LogPath $rWrite.path

if ($origBytes.Length -eq 4) {
  $rRestore = Invoke-TestAgent -Name "restore_rw" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
    ReadAddr = $writeAddr
    ReadSize = 4
    WriteAddr = $writeAddr
    WriteBytes = [byte[]]$origBytes
    VerifyAfterWrite = $true
  })
  $expectRestore = ($origBytes | ForEach-Object { $_.ToString("X2") }) -join " "
  $okRestore = $rRestore.ok -and ($rRestore.text -match "write size=\d+ code=0 bytes=4") -and ($rRestore.text -match ("verify hex=" + [regex]::Escape($expectRestore)))
  Add-Result -List $results -Name "restore_rw" -Passed $okRestore -Detail ("expect=" + $expectRestore) -LogPath $rRestore.path
}

# 7) Scan in rw region
$scanStart = $rwAddr
$scanEnd = $rwAddr + $rwSize
$rScan = Invoke-TestAgent -Name "scan_u8_5A" -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
  ScanU8 = 0x5A
  ScanStart = $scanStart
  ScanEnd = $scanEnd
  ScanPageStart = 0
  ScanPageMax = 32
})
$okScan = $rScan.ok -and ($rScan.text -match "scan count=(\d+)") -and ([UInt64]$Matches[1] -gt 0)
Add-Result -List $results -Name "scan_u8" -Passed $okScan -Detail ("range=" + (To-Hex64 $scanStart) + "~" + (To-Hex64 $scanEnd)) -LogPath $rScan.path

# 8) Pointer chain depth 3/5/7/10 (offsets all zero)
foreach ($d in @(3, 5, 7, 10)) {
  $chain = $chains[$d]
  $offsets = New-Object UInt64[] $d
  for ($i = 0; $i -lt $d; $i++) { $offsets[$i] = 0 }
  $rChain = Invoke-TestAgent -Name ("ptr_chain_" + $d) -ScriptPath $testAgentPath -Dir $resolvedOut -Params ($common + @{
    PointerBase = [UInt64]$chain.base
    PointerOffsets = [UInt64[]]$offsets
    PointerSize = 8
    PointerReadSize = 8
  })
  $okCode = $rChain.ok -and ($rChain.text -match "pointer chain code=0 addr=0x([0-9A-F]+)")
  $resolved = [UInt64]0
  if ($okCode) {
    $resolved = [Convert]::ToUInt64($Matches[1], 16)
  }
  $expect = Strip-Tag64([UInt64]$chain.value_addr)
  $okAddr = $okCode -and ($resolved -eq $expect)
  $okRead = $rChain.text -match "pointer read code=0 bytes=8"
  $okFinal = $okAddr -and $okRead
  $detail = "resolved=" + (To-Hex64 $resolved) + " expect=" + (To-Hex64 $expect)
  Add-Result -List $results -Name ("pointer_chain_depth_" + $d) -Passed $okFinal -Detail $detail -LogPath $rChain.path
}

# 9) ptrace breakpoint smoke
$bpLog = Join-Path $resolvedOut ("ptrace_bp_" + (Get-Date -Format "yyyyMMdd_HHmmss_fff") + ".log")
try {
  $bpExecAddr = [UInt64]$ptraceAddr
  # ARM32 Thumb addresses may carry bit0=1; ptrace breakpoint expects aligned address.
  if (($bpExecAddr -band 1) -ne 0) {
    $bpExecAddr = ($bpExecAddr -band 0xFFFFFFFFFFFFFFFE)
  }
  $bpOut = & $testBpPath -TargetPid ([int]$probePid) -ExecAddr $bpExecAddr -RemoteHost $RemoteHost -Port $Port 2>&1
  $bpText = (($bpOut | ForEach-Object { "$_" }) -join [Environment]::NewLine)
  Set-Content -Path $bpLog -Value $bpText -Encoding UTF8
  $okBp = ($bpText -match "set bp code=0") -and ($bpText -match "read code=0 bytes=(\d+)")
  $bpDetail = "exec=" + (To-Hex64 $ptraceAddr)
  if ($bpExecAddr -ne $ptraceAddr) {
    $bpDetail += " aligned=" + (To-Hex64 $bpExecAddr)
  }
  Add-Result -List $results -Name "ptrace_breakpoint" -Passed $okBp -Detail $bpDetail -LogPath $bpLog
} catch {
  $bpText = $_ | Out-String
  Set-Content -Path $bpLog -Value $bpText -Encoding UTF8
  Add-Result -List $results -Name "ptrace_breakpoint" -Passed $false -Detail "script failed" -LogPath $bpLog
}

# 10) Optional pointer bench (scan_raw/index/compare/verify)
if ($RunPointerBench) {
  $benchJson = Join-Path $resolvedOut "bench_pointer_summary.json"
  $benchLog = Join-Path $resolvedOut ("bench_pointer_" + (Get-Date -Format "yyyyMMdd_HHmmss_fff") + ".log")
  try {
    Invoke-Adb -AdbArgs @("shell", "am", "start", "-n", "$Package/$Activity") | Out-Null
    Start-Sleep -Seconds 2
    $probePidRaw = ((Invoke-Adb -AdbArgs @("shell", "pidof", $Package)) | Out-String).Trim()
    $probePidNow = ($probePidRaw -split '\s+')[0]
    if ($probePidNow -notmatch '^\d+$') {
      Invoke-Adb -AdbArgs @("shell", "am", "force-stop", $Package) | Out-Null
      Start-Sleep -Seconds 1
      Invoke-Adb -AdbArgs @("shell", "am", "start", "-n", "$Package/$Activity") | Out-Null
      Start-Sleep -Seconds 2
      $probePidRaw = ((Invoke-Adb -AdbArgs @("shell", "pidof", $Package)) | Out-String).Trim()
      $probePidNow = ($probePidRaw -split '\s+')[0]
    }
    if ($probePidNow -notmatch '^\d+$') {
      throw "target process not found before pointer bench (after restart)"
    }
    Invoke-Adb -AdbArgs @("shell", "su", "-c", ("kill -CONT " + $probePidNow)) | Out-Null
    $benchOut = & powershell -ExecutionPolicy Bypass -File $benchPointerPath `
      -Seconds 6 -Depth 5 -Mode all -Strict both -Adb $Adb `
      -OutJson $benchJson 2>&1
    $benchText = (($benchOut | ForEach-Object { "$_" }) -join [Environment]::NewLine)
    Set-Content -Path $benchLog -Value $benchText -Encoding UTF8
    $okBench = (Test-Path $benchJson) -and ($benchText -match "MODE=scan_raw") -and ($benchText -match "MODE=scan_index") -and ($benchText -match "MODE=compare") -and ($benchText -match "MODE=verify")
    Add-Result -List $results -Name "pointer_bench_all_modes" -Passed $okBench -Detail "scan_raw/scan_index/compare/verify" -LogPath $benchLog
  } catch {
    $benchText = $_ | Out-String
    Set-Content -Path $benchLog -Value $benchText -Encoding UTF8
    Add-Result -List $results -Name "pointer_bench_all_modes" -Passed $false -Detail "bench failed" -LogPath $benchLog
  }
}

# Emit report files
$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  adb = $Adb
  device = if ([string]::IsNullOrWhiteSpace($Device)) { "default" } else { $Device }
  package = $Package
  pid = $probePid
  rw_region = (To-Hex64 $rwAddr)
  rw_size = $rwSize
  ro_region = (To-Hex64 $roAddr)
  ro_size = $roSize
  ptrace_exec_addr = (To-Hex64 $ptraceAddr)
  results = $results
}

$jsonPath = Join-Path $resolvedOut "full_test_report.json"
$mdPath = Join-Path $resolvedOut "full_test_report.md"
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$passed = ($results | Where-Object { $_.passed }).Count
$total = $results.Count
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# ADB Full Functional Test")
$lines.Add("")
$lines.Add("- time: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
$lines.Add("- package: " + $Package + " (pid " + $probePid + ")")
$lines.Add("- rw_region: " + (To-Hex64 $rwAddr) + " size=" + $rwSize)
$lines.Add("- ptrace_exec_addr: " + (To-Hex64 $ptraceAddr))
$lines.Add("- pass: " + $passed + "/" + $total)
$lines.Add("")
$lines.Add("| Item | Result | Detail | Log |")
$lines.Add("|---|---|---|---|")
foreach ($r in $results) {
  $state = if ($r.passed) { "PASS" } else { "FAIL" }
  $logName = if ([string]::IsNullOrWhiteSpace($r.log)) { "" } else { [System.IO.Path]::GetFileName($r.log) }
  $lines.Add("| " + $r.name + " | " + $state + " | " + $r.detail + " | " + $logName + " |")
}
Set-Content -Path $mdPath -Value ($lines -join [Environment]::NewLine) -Encoding UTF8

Write-Host ""
Write-Host ("Report JSON: " + $jsonPath)
Write-Host ("Report MD:   " + $mdPath)
Write-Host ("Summary: " + $passed + "/" + $total + " passed")
