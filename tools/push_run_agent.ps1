param(
  [int]$Port = 12345,
  [string]$Adb = "E:\gjzs\adb.exe",
  [string]$OutRoot = "D:\Code\R3_Code\android_debug\core\build\android_agent",
  [string]$RemotePath = "/data/local/tmp/r3_android_agent",
  [switch]$Run
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Adb)) {
  throw "adb not found: $Adb"
}

$abiList = & $Adb shell getprop ro.product.cpu.abilist
$abi = "armeabi-v7a"
if ($abiList -match "arm64") {
  $abi = "arm64-v8a"
}

$agent = Join-Path $OutRoot $abi
$agent = Join-Path $agent "src\android_agent\r3_android_agent"
if (-not (Test-Path $agent)) {
  throw "agent binary not found: $agent"
}

$running = & $Adb shell "su -c 'pidof r3_android_agent'"
if ($null -ne $running) {
  $running = $running.Trim()
} else {
  $running = ""
}
if ($running) {
  & $Adb shell "su -c 'kill -9 $running'" | Out-Null
}

& $Adb push $agent $RemotePath | Out-Null
& $Adb shell "su -c 'chmod 755 $RemotePath'"

if ($Run) {
  & $Adb shell "su -c '$RemotePath $Port > /data/local/tmp/r3_android_agent.log 2>&1 &'"
}

Write-Host "Pushed $abi -> $RemotePath"
if ($Run) {
  Write-Host "Started on port $Port"
}
