param(
  [string]$Exe = "core/build/windows_client_qt/src/windows_client_qt/r3_windows_client_qt.exe",
  [string]$OutDir = "core/build/gui_touch_audit",
  [string]$WindowSize = "1280x820",
  [int]$Rounds = 2
)

$argsList = @(
  "core/tools/gui_touch_audit.py",
  "--exe", $Exe,
  "--out-dir", $OutDir,
  "--window-size", $WindowSize,
  "--rounds", $Rounds
)

python @argsList

