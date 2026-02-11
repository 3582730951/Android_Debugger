param(
  [int]$Port = 12345,
  [string]$Adb = "E:\gjzs\adb.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Adb)) {
  throw "adb not found: $Adb"
}

& $Adb forward tcp:$Port tcp:$Port
& $Adb forward --list
