param(
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$RemoteHost = "127.0.0.1",
  [int]$Port = 12345,
  [string]$Package = "com.r3.debugprobe",
  [string]$Activity = "android.app.NativeActivity",
  [string]$OutRoot = "build",
  [switch]$SkipUiPerf,
  [switch]$RunUiRuntime,
  [switch]$RunPointerBench,
  [switch]$NoExitOnFail
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Add-Result {
  param(
    [System.Collections.Generic.List[object]]$List,
    [string]$Name,
    [bool]$Passed,
    [string]$Detail,
    [string]$Log = "",
    [string]$Report = ""
  )
  $item = [ordered]@{
    name = $Name
    passed = $Passed
    detail = $Detail
    log = $Log
    report = $Report
  }
  $List.Add([pscustomobject]$item)
  $mark = if ($Passed) { "[PASS]" } else { "[FAIL]" }
  Write-Host "$mark $Name - $Detail"
}

function Invoke-Tool {
  param(
    [string]$ScriptPath,
    [hashtable]$ToolArgs,
    [string]$LogPath
  )
  $argv = @("-ExecutionPolicy", "Bypass", "-File", $ScriptPath)
  foreach ($k in $ToolArgs.Keys) {
    $v = $ToolArgs[$k]
    if ($v -is [switch] -or $v -is [bool]) {
      if ([bool]$v) {
        $argv += ("-" + $k)
      }
      continue
    }
    if ($null -ne $v -and "$v" -ne "") {
      $argv += ("-" + $k)
      $argv += ("$v")
    }
  }

  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $raw = (& powershell @argv 2>&1 | ForEach-Object { "$_" })
  $exitCode = $LASTEXITCODE
  $ErrorActionPreference = $prevEap

  $text = ($raw -join [Environment]::NewLine)
  if ($LogPath) {
    Set-Content -Path $LogPath -Value $text -Encoding UTF8
  }
  return [pscustomobject]@{
    ok = ($exitCode -eq 0)
    exit_code = $exitCode
    text = $text
    log = $LogPath
  }
}

function Get-LatestFile {
  param(
    [string]$Dir,
    [string]$Pattern
  )
  if (-not (Test-Path $Dir)) {
    return ""
  }
  $f = Get-ChildItem -Path $Dir -Filter $Pattern -File -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 1
  if ($null -eq $f) {
    return ""
  }
  return $f.FullName
}

if (-not (Test-Path $Adb)) {
  throw "adb not found: $Adb"
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$coreRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path

$testFullProbe = Join-Path $coreRoot "tools\test_full_probe.ps1"
$pluginProvider = Join-Path $coreRoot "tools\plugin_provider_regression.ps1"
$pluginOverride = Join-Path $coreRoot "tools\plugin_override_regression.ps1"
$uiQuickAdd = Join-Path $coreRoot "tools\ui_quick_add_regression.ps1"
$uiContext = Join-Path $coreRoot "tools\ui_contextmenu_regression.ps1"
$uiPerf = Join-Path $coreRoot "tools\ui_perf_benchmark.ps1"

foreach ($p in @($testFullProbe, $pluginProvider, $pluginOverride, $uiQuickAdd, $uiContext, $uiPerf)) {
  if (-not (Test-Path $p)) {
    throw "missing script: $p"
  }
}

$runStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutRoot ("acceptance_arm64_" + $runStamp)
$fullDir = Join-Path $runDir "full"
$regDir = Join-Path $runDir "regression"
$pluginDir = Join-Path $regDir "plugin_provider"
$pluginOverrideDir = Join-Path $regDir "plugin_override"
$quickDir = Join-Path $regDir "ui_quick_add"
$ctxDir = Join-Path $regDir "ui_contextmenu"
$uiDir = Join-Path $runDir "ui"

foreach ($d in @($runDir, $fullDir, $pluginDir, $pluginOverrideDir, $quickDir, $ctxDir, $uiDir)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
}
$resolvedRunDir = (Resolve-Path $runDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'

# Environment checks
$devices = (& $Adb devices | Out-String)
$deviceOk = $devices -match '(?m)^[^\r\n]+\tdevice\s*$'
$deviceDetail = if ($deviceOk) { "device online" } else { "no online device" }
Add-Result -List $results -Name "env_device" -Passed $deviceOk -Detail $deviceDetail
if (-not $deviceOk) {
  $failed = @($results | Where-Object { -not $_.passed }).Count
  if ($failed -gt 0 -and -not $NoExitOnFail) {
    exit 1
  }
}

$abiList = ((& $Adb shell getprop ro.product.cpu.abilist) | Out-String).Trim()
$abiOk = $abiList -match "arm64-v8a"
Add-Result -List $results -Name "env_arm64" -Passed $abiOk -Detail ("abilist=" + $abiList)

$rootText = ((& $Adb shell su -c id) | Out-String).Trim()
$rootOk = $rootText -match "uid=0"
Add-Result -List $results -Name "env_root" -Passed $rootOk -Detail $rootText

$cpuCores = ((& $Adb shell nproc) | Out-String).Trim()
$cpuOk = $cpuCores -match '^\d+$'
Add-Result -List $results -Name "env_cpu_core_count" -Passed $cpuOk -Detail ("cores=" + $cpuCores)

# Start app once for process-path validation.
# Some emulators return a warning on stderr when the target is already top-most;
# treat it as non-fatal and rely on process checks below.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$startRaw = (& $Adb shell am start -n "$Package/$Activity" 2>&1 | ForEach-Object { "$_" })
$startExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
$startLog = Join-Path $resolvedRunDir "probe_start.log"
Set-Content -Path $startLog -Value ($startRaw -join [Environment]::NewLine) -Encoding UTF8
$startOk = ($startExit -eq 0)
$startDetail = if ($startOk) { "activity started" } else { "activity start failed" }
Add-Result -List $results -Name "probe_start" -Passed $startOk -Detail $startDetail -Log $startLog

$probePidRaw = ((& $Adb shell pidof $Package) | Out-String).Trim()
$probePid = ""
if ($probePidRaw -match '^\d+(\s+\d+)*$') {
  $probePid = ($probePidRaw -split '\s+')[0]
}
$pidOk = $probePid -match '^\d+$'
$pidDetail = if ($pidOk) { "pid=" + $probePid } else { "pid not found" }
Add-Result -List $results -Name "probe_pid" -Passed $pidOk -Detail $pidDetail

$procPathLine = ""
if ($pidOk) {
  $procPathLine = ((& $Adb shell su -c ("cat /proc/" + $probePid + "/maps | grep app_process64 | head -n 1")) | Out-String).Trim()
}
$procPathOk = (-not $pidOk) -or ($procPathLine -match "app_process64")
$procPathDetail = if ($procPathLine -eq "") { "not checked" } else { $procPathLine }
Add-Result -List $results -Name "env_process64_path" -Passed $procPathOk -Detail $procPathDetail

# 1) Full probe
$fullLog = Join-Path $fullDir ("run_full_" + $runStamp + ".log")
$fullRun = Invoke-Tool -ScriptPath $testFullProbe -ToolArgs @{
  Adb = $Adb
  RemoteHost = $RemoteHost
  Port = $Port
  Package = $Package
  Activity = $Activity
  OutDir = $fullDir
  RunPointerBench = $RunPointerBench
} -LogPath $fullLog
$fullReport = Join-Path $fullDir "full_test_report.md"
$fullDetail = if ($fullRun.ok) { "script pass" } else { "exit=" + $fullRun.exit_code }
Add-Result -List $results -Name "full_probe" -Passed $fullRun.ok -Detail $fullDetail -Log $fullLog -Report $fullReport

# 2) Plugin provider regression
$providerLog = Join-Path $pluginDir ("plugin_provider_" + $runStamp + ".log")
$providerRun = Invoke-Tool -ScriptPath $pluginProvider -ToolArgs @{
  CoreRoot = $coreRoot
  OutDir = $pluginDir
} -LogPath $providerLog
$providerReport = Get-LatestFile -Dir $pluginDir -Pattern "plugin_provider_regression_*.md"
$providerDetail = if ($providerRun.ok) { "pass" } else { "exit=" + $providerRun.exit_code }
Add-Result -List $results -Name "plugin_provider_regression" -Passed $providerRun.ok -Detail $providerDetail -Log $providerLog -Report $providerReport

# 3) Plugin override regression (new default gate)
$overrideLog = Join-Path $pluginOverrideDir ("plugin_override_" + $runStamp + ".log")
$overrideRun = Invoke-Tool -ScriptPath $pluginOverride -ToolArgs @{
  Adb = $Adb
  RemoteHost = $RemoteHost
  Port = $Port
  Package = $Package
  Activity = $Activity
  OutDir = $pluginOverrideDir
} -LogPath $overrideLog
$overrideReport = Get-LatestFile -Dir $pluginOverrideDir -Pattern "plugin_override_regression_*.md"
$overrideDetail = if ($overrideRun.ok) { "pass" } else { "exit=" + $overrideRun.exit_code }
Add-Result -List $results -Name "plugin_override_regression" -Passed $overrideRun.ok -Detail $overrideDetail -Log $overrideLog -Report $overrideReport

# 4) UI quick add regression
$quickLog = Join-Path $quickDir ("ui_quick_add_" + $runStamp + ".log")
$quickArgs = @{
  OutDir = $quickDir
  NoExitOnFail = $false
}
if (-not $RunUiRuntime) {
  $quickArgs["SkipRuntime"] = $true
}
$quickRun = Invoke-Tool -ScriptPath $uiQuickAdd -ToolArgs $quickArgs -LogPath $quickLog
$quickReport = Get-LatestFile -Dir $quickDir -Pattern "ui_quick_add_regression_*.md"
$quickDetail = if ($quickRun.ok) { "pass" } else { "exit=" + $quickRun.exit_code }
Add-Result -List $results -Name "ui_quick_add_regression" -Passed $quickRun.ok -Detail $quickDetail -Log $quickLog -Report $quickReport

# 5) UI context menu regression
$ctxLog = Join-Path $ctxDir ("ui_contextmenu_" + $runStamp + ".log")
$ctxArgs = @{
  OutDir = $ctxDir
  NoExitOnFail = $false
}
if (-not $RunUiRuntime) {
  $ctxArgs["SkipRuntime"] = $true
}
$ctxRun = Invoke-Tool -ScriptPath $uiContext -ToolArgs $ctxArgs -LogPath $ctxLog
$ctxReport = Get-LatestFile -Dir $ctxDir -Pattern "ui_contextmenu_regression_*.md"
$ctxDetail = if ($ctxRun.ok) { "pass" } else { "exit=" + $ctxRun.exit_code }
Add-Result -List $results -Name "ui_contextmenu_regression" -Passed $ctxRun.ok -Detail $ctxDetail -Log $ctxLog -Report $ctxReport

# 6) UI perf benchmark (optional)
if ($SkipUiPerf) {
  Add-Result -List $results -Name "ui_perf_benchmark" -Passed $true -Detail "skipped by -SkipUiPerf"
} else {
  $perfLog = Join-Path $uiDir ("ui_perf_" + $runStamp + ".log")
  $perfArgs = @{
    OutDir = $uiDir
    NoExitOnFail = $false
  }
  if (-not $RunUiRuntime) {
    $perfArgs["SkipRuntime"] = $true
  }
  $perfRun = Invoke-Tool -ScriptPath $uiPerf -ToolArgs $perfArgs -LogPath $perfLog
  $perfReport = Get-LatestFile -Dir $uiDir -Pattern "ui_perf_benchmark_*.md"
  $perfDetail = if ($perfRun.ok) { "pass" } else { "exit=" + $perfRun.exit_code }
  Add-Result -List $results -Name "ui_perf_benchmark" -Passed $perfRun.ok -Detail $perfDetail -Log $perfLog -Report $perfReport
}

$failed = @($results | Where-Object { -not $_.passed }).Count
$total = $results.Count
$verdict = if ($failed -eq 0) { "PASS" } else { "FAIL" }

$summary = [ordered]@{
  generated_at = (Get-Date -Format o)
  verdict = $verdict
  environment = [ordered]@{
    adb = $Adb
    host = $RemoteHost
    port = $Port
    package = $Package
    activity = $Activity
    abilist = $abiList
    root = $rootText
    cpu_cores = $cpuCores
    probe_pid = $probePid
  }
  out_dir = $resolvedRunDir
  results = $results
}

$summaryStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$summaryJson = Join-Path $resolvedRunDir ("acceptance_arm64_summary_" + $summaryStamp + ".json")
$summaryMd = Join-Path $resolvedRunDir ("acceptance_arm64_summary_" + $summaryStamp + ".md")
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJson -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# ARM64 Acceptance Summary")
$lines.Add("")
$lines.Add("- verdict: " + $verdict)
$lines.Add("- failed: " + $failed + "/" + $total)
$lines.Add("- out_dir: " + $resolvedRunDir)
$lines.Add("- abilist: " + $abiList)
$lines.Add("- root: " + $rootText)
$lines.Add("- cpu_cores: " + $cpuCores)
$lines.Add("")
$lines.Add("| Item | Result | Detail | Report | Log |")
$lines.Add("|---|---|---|---|---|")
foreach ($r in $results) {
  $state = if ($r.passed) { "PASS" } else { "FAIL" }
  $reportName = if ([string]::IsNullOrWhiteSpace($r.report)) { "" } else { [System.IO.Path]::GetFileName($r.report) }
  $logName = if ([string]::IsNullOrWhiteSpace($r.log)) { "" } else { [System.IO.Path]::GetFileName($r.log) }
  $lines.Add("| " + $r.name + " | " + $state + " | " + $r.detail + " | " + $reportName + " | " + $logName + " |")
}
$lines | Set-Content -Path $summaryMd -Encoding UTF8

Write-Host ""
Write-Host ("Summary JSON: " + $summaryJson)
Write-Host ("Summary MD:   " + $summaryMd)
Write-Host ("Summary: failed=" + $failed + " total=" + $total + " verdict=" + $verdict)

if ($failed -gt 0 -and -not $NoExitOnFail) {
  exit 1
}
