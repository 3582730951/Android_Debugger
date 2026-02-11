param(
  [string]$Exe = "core/build/windows_client/src/windows_client_qt/r3_windows_client_qt.exe",
  [string]$BaselineDir = "core/png_t",
  [string]$OutDir = "core/build/gui_compare",
  [string]$WindowSize = "1280x820",
  [double]$Threshold = 70.0,
  [string]$PointsJson = "",
  [switch]$NoRun
)

$argsList = @(
  "core/tools/gui_compare.py",
  "--exe", $Exe,
  "--baseline-dir", $BaselineDir,
  "--out-dir", $OutDir,
  "--window-size", $WindowSize,
  "--threshold", "$Threshold"
)

if ($PointsJson -ne "") {
  $argsList += @("--points-json", $PointsJson)
}
if ($NoRun) {
  $argsList += "--no-run"
}

python @argsList
