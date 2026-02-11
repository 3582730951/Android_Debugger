param(
  [string]$NdkRoot = "D:\android-ndk-r27-windows\android-ndk-r27",
  [string]$CMakeRoot = "D:\CMake",
  [string]$ApiLevel = "21",
  [string]$BuildType = "Release",
  [string]$OutRoot = "",
  [bool]$UseCompilerCache = $true,
  [string]$CompilerCacheExe = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-ExecutablePath {
  param(
    [string]$PreferredPath,
    [string]$CommandName
  )
  if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and (Test-Path $PreferredPath)) {
    return (Resolve-Path $PreferredPath).Path
  }
  $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
  if ($cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source) -and (Test-Path $cmd.Source)) {
    return $cmd.Source
  }
  throw "$CommandName not found. Preferred path: $PreferredPath"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutRoot)) {
  $OutRoot = Join-Path $repoRoot "build\android_agent"
}

$cmake = Resolve-ExecutablePath -PreferredPath (Join-Path $CMakeRoot "bin\cmake.exe") -CommandName "cmake"
$ninja = Resolve-ExecutablePath -PreferredPath (Join-Path $CMakeRoot "bin\ninja.exe") -CommandName "ninja"
$toolchain = Join-Path $NdkRoot "build\cmake\android.toolchain.cmake"

if (-not (Test-Path $cmake)) { throw "cmake not found: $cmake" }
if (-not (Test-Path $ninja)) { throw "ninja not found: $ninja" }
if (-not (Test-Path $toolchain)) { throw "NDK toolchain not found: $toolchain" }

function Resolve-CompilerCache {
  param([string]$ExplicitPath)
  if (-not [string]::IsNullOrWhiteSpace($ExplicitPath) -and (Test-Path $ExplicitPath)) {
    return (Resolve-Path $ExplicitPath).Path
  }
  if (-not [string]::IsNullOrWhiteSpace($env:SCCACHE) -and (Test-Path $env:SCCACHE)) {
    return (Resolve-Path $env:SCCACHE).Path
  }
  $cmd = Get-Command sccache -ErrorAction SilentlyContinue
  if ($cmd -and (Test-Path $cmd.Source)) {
    return $cmd.Source
  }
  return ""
}

$cacheExe = ""
if ($UseCompilerCache) {
  $cacheExe = Resolve-CompilerCache -ExplicitPath $CompilerCacheExe
  if (-not [string]::IsNullOrWhiteSpace($cacheExe)) {
    Write-Host "Using compiler cache launcher: $cacheExe"
  } else {
    Write-Host "Compiler cache launcher not found, continue without cache"
  }
}

$abis = @("armeabi-v7a", "arm64-v8a")

foreach ($abi in $abis) {
  $buildDir = Join-Path $OutRoot $abi
  New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

  $cmakeArgs = @(
    "-S", $repoRoot,
    "-B", $buildDir,
    "-G", "Ninja",
    "-DCMAKE_MAKE_PROGRAM=$ninja",
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain",
    "-DANDROID_ABI=$abi",
    "-DANDROID_PLATFORM=android-$ApiLevel",
    "-DANDROID_STL=c++_static",
    "-DCMAKE_BUILD_TYPE=$BuildType"
  )

  if (-not [string]::IsNullOrWhiteSpace($cacheExe)) {
    $cmakeArgs += "-DCMAKE_C_COMPILER_LAUNCHER=$cacheExe"
    $cmakeArgs += "-DCMAKE_CXX_COMPILER_LAUNCHER=$cacheExe"
  }

  & $cmake @cmakeArgs
  if ($LASTEXITCODE -ne 0) { throw "cmake configure failed for ${abi}: exit=$LASTEXITCODE" }

  & $cmake --build $buildDir --config $BuildType
  if ($LASTEXITCODE -ne 0) { throw "cmake build failed for ${abi}: exit=$LASTEXITCODE" }
}
