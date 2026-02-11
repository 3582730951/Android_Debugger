param(
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$RemoteHost = "127.0.0.1",
  [int]$Port = 12345,
  [string]$Package = "com.r3.debugprobe",
  [string]$Activity = "android.app.NativeActivity",
  [string]$OutDir = "build\ui_regression_plugin_override",
  [switch]$SkipRuntime
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

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

function Has-Regex {
  param([string]$Text, [string]$Pattern)
  return [regex]::IsMatch($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
}

function Invoke-Step {
  param(
    [scriptblock]$Body,
    [string]$LogPath
  )
  try {
    $output = & $Body 2>&1
    $text = (($output | ForEach-Object { "$_" }) -join [Environment]::NewLine)
    if ($LogPath) {
      Set-Content -Path $LogPath -Value $text -Encoding UTF8
    }
    return @{
      ok = $true
      text = $text
      log = $LogPath
    }
  } catch {
    $text = $_ | Out-String
    if ($LogPath) {
      Set-Content -Path $LogPath -Value $text -Encoding UTF8
    }
    return @{
      ok = $false
      text = $text
      log = $LogPath
    }
  }
}

$coreRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'

$runnerSrc = Join-Path $coreRoot "src\windows_client_qt\tests\PluginOverrideE2ERunner.cpp"
$pluginSrc = Join-Path $coreRoot "src\windows_client_qt\tests\OverrideE2EPlugin.cpp"
$qtCmake = Join-Path $coreRoot "src\windows_client_qt\CMakeLists.txt"

if (-not (Test-Path $runnerSrc)) { throw "missing file: $runnerSrc" }
if (-not (Test-Path $pluginSrc)) { throw "missing file: $pluginSrc" }
if (-not (Test-Path $qtCmake)) { throw "missing file: $qtCmake" }

$runnerText = Get-Content -Raw $runnerSrc
$pluginText = Get-Content -Raw $pluginSrc
$cmakeText = Get-Content -Raw $qtCmake

Add-Result -List $results -Name "runner_source" -Passed (Has-Regex $runnerText 'scenario_pass_summary[\s\S]*scenario_handled_summary[\s\S]*scenario_error_summary') -Detail "runner contains PASS/HANDLED/ERROR checks"
Add-Result -List $results -Name "plugin_source" -Passed (Has-Regex $pluginText 'OnReadEvent[\s\S]*OnWriteEvent[\s\S]*register_module_events') -Detail "plugin exports read/write callbacks"
Add-Result -List $results -Name "cmake_targets" -Passed (Has-Regex $cmakeText 'r3_plugin_override_e2e[\s\S]*r3_plugin_override_e2e_runner') -Detail "cmake contains plugin + runner targets"

if ($SkipRuntime) {
  Add-Result -List $results -Name "runtime_e2e" -Passed $true -Detail "skipped by -SkipRuntime"
} else {
  if (-not (Test-Path $Adb)) {
    Add-Result -List $results -Name "adb_exists" -Passed $false -Detail ("adb not found: " + $Adb)
  } else {
    Add-Result -List $results -Name "adb_exists" -Passed $true -Detail $Adb

    $devicesLog = Join-Path $resolvedOut ("plugin_override_devices_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
    $rDevices = Invoke-Step -LogPath $devicesLog -Body { & $Adb devices }
    $deviceOk = $rDevices.ok -and ($rDevices.text -match '(?m)^[^\r\n]+\tdevice\s*$')
    $deviceDetail = if ($deviceOk) { "device online" } else { "no adb device" }
    Add-Result -List $results -Name "adb_device_online" -Passed $deviceOk -Detail $deviceDetail -LogPath $devicesLog

    if ($deviceOk) {
      $pushScript = Join-Path $coreRoot "tools\push_run_agent.ps1"
      $forwardScript = Join-Path $coreRoot "tools\adb_forward.ps1"
      $pushLog = Join-Path $resolvedOut ("plugin_override_push_agent_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      $rPush = Invoke-Step -LogPath $pushLog -Body {
        & powershell -ExecutionPolicy Bypass -File $pushScript -Adb $Adb -Port $Port -Run
      }
      $pushDetail = if ($rPush.ok) { "agent started" } else { "push/run failed" }
      Add-Result -List $results -Name "agent_push_run" -Passed $rPush.ok -Detail $pushDetail -LogPath $pushLog

      $forwardLog = Join-Path $resolvedOut ("plugin_override_forward_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      $rForward = Invoke-Step -LogPath $forwardLog -Body {
        & powershell -ExecutionPolicy Bypass -File $forwardScript -Adb $Adb -Port $Port
      }
      $forwardOk = $rForward.ok -and ($rForward.text -match ("tcp:" + $Port))
      $forwardDetail = if ($forwardOk) { "tcp:" + $Port } else { "forward failed" }
      Add-Result -List $results -Name "agent_forward" -Passed $forwardOk -Detail $forwardDetail -LogPath $forwardLog

      $startLog = Join-Path $resolvedOut ("plugin_override_start_app_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      $prevEap = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      $startLines = (& $Adb shell am start -n "$Package/$Activity" 2>&1 | ForEach-Object { "$_" })
      $startExit = $LASTEXITCODE
      $ErrorActionPreference = $prevEap
      $startText = ($startLines -join [Environment]::NewLine)
      Set-Content -Path $startLog -Value $startText -Encoding UTF8
      $startOk = ($startExit -eq 0)
      $startDetail = if ($startOk) { "activity started" } else { "activity start failed" }
      Add-Result -List $results -Name "probe_start" -Passed $startOk -Detail $startDetail -LogPath $startLog

      $pidLog = Join-Path $resolvedOut ("plugin_override_pid_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      $probePid = ""
      $pidTrace = New-Object System.Collections.Generic.List[string]
      if ($startOk) {
        for ($try = 0; $try -lt 20; $try++) {
          $pidRaw = ((& $Adb shell pidof $Package) | Out-String).Trim()
          $pidTrace.Add("try=" + $try + " raw=" + $pidRaw)
          if ($pidRaw -match '^\d+(\s+\d+)*$') {
            $probePid = (($pidRaw -split '\s+')[0]).Trim()
            if ($probePid -match '^\d+$') {
              break
            }
          }
          Start-Sleep -Milliseconds 300
        }
      } else {
        $pidTrace.Add("skip pid probe because activity start failed")
      }
      Set-Content -Path $pidLog -Value ($pidTrace -join [Environment]::NewLine) -Encoding UTF8
      $pidOk = $probePid -match '^\d+$'
      $pidDetail = if ($pidOk) { "pid=" + $probePid } else { "pid not found" }
      Add-Result -List $results -Name "probe_pid" -Passed $pidOk -Detail $pidDetail -LogPath $pidLog

      $buildLog = Join-Path $resolvedOut ("plugin_override_build_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      $rBuild = Invoke-Step -LogPath $buildLog -Body {
        & cmake --build (Join-Path $coreRoot "build/windows_client_qt") --target r3_plugin_override_e2e r3_plugin_override_e2e_runner -j 8
      }
      $buildDetail = if ($rBuild.ok) { "targets built" } else { "build failed" }
      Add-Result -List $results -Name "build_targets" -Passed $rBuild.ok -Detail $buildDetail -LogPath $buildLog

      if ($pidOk -and $rBuild.ok) {
        $runnerExe = Join-Path $coreRoot "build\windows_client_qt\src\windows_client_qt\r3_plugin_override_e2e_runner.exe"
        $pluginDll = Join-Path $coreRoot "build\windows_client_qt\src\windows_client_qt\r3_plugin_override_e2e.dll"
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $runtimeJson = Join-Path $resolvedOut ("plugin_override_runtime_" + $stamp + ".json")
        $runtimeLog = Join-Path $resolvedOut ("plugin_override_runtime_" + $stamp + ".log")

        $rRuntime = Invoke-Step -LogPath $runtimeLog -Body {
          & $runnerExe --plugin-dll $pluginDll --pid $probePid --host $RemoteHost --port $Port --out $runtimeJson
        }

        $runtimeOk = $rRuntime.ok -and (Test-Path $runtimeJson)
        $summaryText = "runner failed"
        if ($runtimeOk) {
          try {
            $obj = Get-Content -Raw $runtimeJson | ConvertFrom-Json
            $pass = [int]$obj.pass_count
            $total = [int]$obj.total_count
            $runtimeOk = ($total -ge 16) -and ($pass -eq $total)
            $summaryText = ("pass=" + $pass + "/" + $total)
          } catch {
            $runtimeOk = $false
            $summaryText = "runtime json parse failed"
          }
        }
        Add-Result -List $results -Name "runtime_e2e" -Passed $runtimeOk -Detail $summaryText -LogPath $runtimeLog
      }
    }
  }
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("plugin_override_regression_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("plugin_override_regression_" + $stamp + ".md")

$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  adb = $Adb
  host = $RemoteHost
  port = $Port
  package = $Package
  results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$failed = @($results | Where-Object { -not $_.passed }).Count
$total = $results.Count
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Plugin Override Regression")
$lines.Add("")
$lines.Add("- time: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
$lines.Add("- host: " + $RemoteHost + ":" + $Port)
$lines.Add("- package: " + $Package)
$lines.Add("- failed: " + $failed + "/" + $total)
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
Write-Host ("Summary: failed=" + $failed + " total=" + $total)
if ($failed -gt 0) {
  exit 1
}
