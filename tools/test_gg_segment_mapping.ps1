param(
  [string]$SourceFile = "",
  [string]$OutDir = "",
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$Device = "",
  [string]$Package = "com.r3.debugprobe",
  [string]$Activity = "android.app.NativeActivity",
  [switch]$SkipDevice,
  [switch]$NoExitOnFail
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$coreRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($SourceFile)) {
  $SourceFile = Join-Path $coreRoot "src\windows_client_qt\ui\MainWindow.cpp"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $OutDir = Join-Path $coreRoot "build\ui_regression_gg_segment"
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

function Invoke-Adb {
  param([string[]]$Args)
  if ([string]::IsNullOrWhiteSpace($Device)) {
    return & $Adb @Args
  }
  return & $Adb -s $Device @Args
}

function Classify-MapLine {
  param([string]$Line)
  $m = [regex]::Match($Line, '^[0-9a-fA-F]+-[0-9a-fA-F]+\s+([rwxps\-]{4})\s+[0-9a-fA-F]+\s+[0-9a-fA-F:]+\s+\d+\s*(.*)$')
  if (-not $m.Success) {
    return ""
  }
  $perms = $m.Groups[1].Value
  $path = $m.Groups[2].Value.Trim()
  $p = $path.ToLowerInvariant()

  $exec = $perms.Contains("x")
  $read = $perms.Contains("r")
  $write = $perms.Contains("w")

  $hasPath = -not [string]::IsNullOrWhiteSpace($path)
  $anon = (-not $hasPath) -or $path.StartsWith("[") -or $p.Contains("anon")
  $file = $hasPath -and (-not $path.StartsWith("[")) -and (-not $p.StartsWith("/dev"))

  if (-not $read) { return "B" }
  if ($p.Contains("ppsspp")) { return "PS" }
  if ($p.Contains("dalvik-heap") -or $p.Contains("dalvik main") -or $p.Contains("zygote space") -or $p.Contains("alloc space") -or $p.Contains("main space")) {
    return "JH"
  }
  if ($p.Contains("[heap]") -or $p.Contains("libc_malloc") -or $p.Contains("scudo") -or $p.Contains("malloc")) { return "CH" }
  if ($p.Contains("alloc")) { return "CA" }
  if ($anon -and $write -and (-not $exec) -and (-not $file)) { return ".BSS" }
  if ($p.Contains("dalvik") -or $p.Contains("art") -or $p.Contains(".oat") -or $p.Contains(".vdex") -or $p.Contains(".dex")) { return "J" }
  if ($p.Contains("[stack")) { return "S" }
  if ($p.Contains("ashmem") -or $p.Contains("memfd")) { return "AS" }

  $isApp = $p.StartsWith("/data/app") -or $p.StartsWith("/data/user") -or $p.StartsWith("/data/data") -or $p.StartsWith("/mnt/asec")
  $isSystem = $p.StartsWith("/system") -or $p.StartsWith("/apex") -or $p.StartsWith("/vendor") -or $p.StartsWith("/product") -or $p.StartsWith("/odm") -or $p.StartsWith("/system_ext")
  if ($exec -and $isApp) { return "XA" }
  if ($exec -and $isSystem) { return "XS" }

  if ($p.StartsWith("/dev") -and ($p.Contains("video") -or $p.Contains("kgsl") -or $p.Contains("gpu") -or $p.Contains("graphics"))) {
    return "V"
  }
  if ($anon) { return "A" }
  return "O"
}

function Has-RegionOption {
  param(
    [string]$SourceText,
    [string]$Label,
    [string]$EnumName
  )
  $pat = 'scan_region_combo_->addItem\(\s*QStringLiteral\("' + [regex]::Escape($Label) + '"\)\s*,\s*static_cast<int>\(protocol::' + [regex]::Escape($EnumName) + '\)\s*\)'
  if ([regex]::IsMatch($SourceText, $pat, [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
    return $true
  }
  return $SourceText.Contains($EnumName) -and $SourceText.Contains('"' + $Label + '"')
}

if (-not (Test-Path $SourceFile)) {
  throw "source file not found: $SourceFile"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$resolvedOut = (Resolve-Path $OutDir).Path
$results = New-Object 'System.Collections.Generic.List[object]'

$sourceText = Get-Content -Raw $SourceFile
$requiredRegions = @(
  @{ code = "XA"; label = "XA"; enum = "GG_REGION_XA" },
  @{ code = "A"; label = "A"; enum = "GG_REGION_A" },
  @{ code = "O"; label = "O"; enum = "GG_REGION_O" },
  @{ code = ".BSS"; label = ".bss"; enum = "GG_REGION_BSS" },
  @{ code = "JH"; label = "jh"; enum = "GG_REGION_JH" },
  @{ code = "CH"; label = "ch"; enum = "GG_REGION_CH" },
  @{ code = "CA"; label = "ca"; enum = "GG_REGION_CA" },
  @{ code = "PS"; label = "ps"; enum = "GG_REGION_PS" },
  @{ code = "J"; label = "J"; enum = "GG_REGION_J" },
  @{ code = "S"; label = "S"; enum = "GG_REGION_S" },
  @{ code = "AS"; label = "As"; enum = "GG_REGION_AS" },
  @{ code = "V"; label = "V"; enum = "GG_REGION_V" },
  @{ code = "XS"; label = "XS"; enum = "GG_REGION_XS" }
)

$foundCodes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $requiredRegions) {
  $ok = Has-RegionOption -SourceText $sourceText -Label $entry.label -EnumName $entry.enum
  if ($ok) {
    [void]$foundCodes.Add([string]$entry.code)
  }
  Add-Result -List $results -Name ("source_has_" + [string]$entry.code.Replace(".", "dot")) -Passed $ok -Detail ("label=" + $entry.label + " enum=" + $entry.enum)
}

$deviceStats = [ordered]@{
  pid = ""
  sampled_lines = 0
  classified = @{}
}

if ($SkipDevice) {
  Add-Result -List $results -Name "device_check" -Passed $true -Detail "skipped by -SkipDevice"
} elseif (-not (Test-Path $Adb)) {
  Add-Result -List $results -Name "device_check" -Passed $true -Detail ("skipped, adb missing: " + $Adb)
} else {
  $devices = (Invoke-Adb -Args @("devices") | Out-String)
  if ($devices -notmatch "\bdevice\b") {
    Add-Result -List $results -Name "device_check" -Passed $true -Detail "skipped, no online device"
  } else {
    $pidRaw = ((Invoke-Adb -Args @("shell", "pidof", $Package)) | Out-String).Trim()
    $targetPid = ""
    if (-not [string]::IsNullOrWhiteSpace($pidRaw)) {
      $targetPid = ($pidRaw -split '\s+')[0]
    }
    if ($targetPid -notmatch '^\d+$') {
      try {
        Invoke-Adb -Args @("shell", "am", "start", "-n", ($Package + "/" + $Activity)) | Out-Null
      } catch {
      }
      Start-Sleep -Milliseconds 1000
      for ($try = 0; $try -lt 10 -and $targetPid -notmatch '^\d+$'; $try++) {
        $pidRaw = ((Invoke-Adb -Args @("shell", "pidof", $Package)) | Out-String).Trim()
        if (-not [string]::IsNullOrWhiteSpace($pidRaw)) {
          $targetPid = ($pidRaw -split '\s+')[0]
          break
        }
        if ($try -eq 4) {
          try {
            Invoke-Adb -Args @("shell", "monkey", "-p", $Package, "-c", "android.intent.category.LAUNCHER", "1") | Out-Null
          } catch {
          }
        }
        Start-Sleep -Milliseconds 500
      }
    }
    if ($targetPid -notmatch '^\d+$') {
      Add-Result -List $results -Name "device_process" -Passed $true -Detail ("skipped, pid not found for " + $Package)
    } else {
      $deviceStats.pid = $targetPid
      $maps = @(Invoke-Adb -Args @("shell", "su", "-c", ("cat /proc/" + $targetPid + "/maps")) | ForEach-Object { "$_" })
      if (@($maps).Count -eq 0) {
        $maps = @(Invoke-Adb -Args @("shell", "cat", ("/proc/" + $targetPid + "/maps")) | ForEach-Object { "$_" })
      }
      if (@($maps).Count -eq 0) {
        Add-Result -List $results -Name "device_maps" -Passed $false -Detail "maps is empty"
      } else {
        $counts = @{}
        $sampled = 0
        foreach ($line in $maps) {
          $sampled++
          $code = Classify-MapLine -Line ([string]$line)
          if ([string]::IsNullOrWhiteSpace($code)) {
            continue
          }
          if (-not $counts.ContainsKey($code)) {
            $counts[$code] = 0
          }
          $counts[$code]++
        }
        $deviceStats.sampled_lines = $sampled
        $deviceStats.classified = $counts
        $observed = @($counts.Keys) | Sort-Object
        $observedText = if ($observed.Count -gt 0) { ($observed -join ",") } else { "<none>" }
        Add-Result -List $results -Name "device_maps_classified" -Passed ($observed.Count -gt 0) -Detail ("observed=" + $observedText)
      }
    }
  }
}

$failed = @($results | Where-Object { -not $_.passed }).Count
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jsonPath = Join-Path $resolvedOut ("gg_segment_mapping_" + $stamp + ".json")
$mdPath = Join-Path $resolvedOut ("gg_segment_mapping_" + $stamp + ".md")

$requiredCodes = @($requiredRegions | ForEach-Object { $_.code })
$report = [ordered]@{
  generated_at = (Get-Date -Format o)
  source_file = $SourceFile
  required_codes = $requiredCodes
  found_codes = @($foundCodes)
  device = $deviceStats
  results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add("# GG Segment Mapping Regression (Qt)")
$lines.Add("")
$lines.Add("- source: `"$SourceFile`"")
$lines.Add("- required codes: " + ($requiredCodes -join ", "))
$lines.Add("- found codes: " + ((@($foundCodes) | Sort-Object) -join ", "))
$lines.Add("- failed: " + $failed)
$lines.Add("")
$lines.Add("| Check | Result | Detail |")
$lines.Add("|---|---|---|")
foreach ($r in $results) {
  $state = if ($r.passed) { "PASS" } else { "FAIL" }
  $lines.Add("| " + $r.name + " | " + $state + " | " + $r.detail + " |")
}
if ($deviceStats.sampled_lines -gt 0) {
  $lines.Add("")
  $lines.Add("## Device Classification")
  $lines.Add("")
  $lines.Add("- pid: " + $deviceStats.pid)
  $lines.Add("- sampled_lines: " + $deviceStats.sampled_lines)
  $lines.Add("")
  $lines.Add("| Code | Count |")
  $lines.Add("|---|---|")
  foreach ($k in ($deviceStats.classified.Keys | Sort-Object)) {
    $lines.Add("| " + $k + " | " + $deviceStats.classified[$k] + " |")
  }
}
$lines | Set-Content -Path $mdPath -Encoding UTF8

Write-Host ""
Write-Host ("Report JSON: " + $jsonPath)
Write-Host ("Report MD:   " + $mdPath)
Write-Host ("Summary: failed=" + $failed + " total=" + $results.Count)

if ($failed -gt 0 -and -not $NoExitOnFail) {
  exit 1
}
