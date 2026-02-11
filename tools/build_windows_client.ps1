param(
  [string]$CMakeRoot = "D:\CMake",
  [string]$NdkRoot = "D:\android-ndk-r27-windows\android-ndk-r27",
  [string]$AdbRoot = "E:\gjzs",
  [string]$QtRoot = "D:\Qt",
  [string]$QtKit = "",
  [string]$BuildType = "Release",
  [string]$OutRoot = "",
  [string]$AgentOutRoot = "",
  [string]$AdbZipUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
  [string]$ClientTarget = "r3_windows_client_qt",
  [bool]$BuildLegacyWin32 = $false,
  [bool]$CleanBuild = $true,
  [bool]$BundleAdb = $true,
  [bool]$BundleAgent = $true,
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
  $OutRoot = Join-Path $repoRoot "build\windows_client"
}
if ([string]::IsNullOrWhiteSpace($AgentOutRoot)) {
  $AgentOutRoot = Join-Path $repoRoot "build\android_agent"
}

$cmake = Resolve-ExecutablePath -PreferredPath (Join-Path $CMakeRoot "bin\cmake.exe") -CommandName "cmake"
$ninja = Resolve-ExecutablePath -PreferredPath (Join-Path $CMakeRoot "bin\ninja.exe") -CommandName "ninja"

if (-not (Test-Path $cmake)) { throw "cmake not found: $cmake" }
if (-not (Test-Path $ninja)) { throw "ninja not found: $ninja" }
if (-not (Test-Path $repoRoot)) { throw "repo root not found: $repoRoot" }

if ($CleanBuild -and (Test-Path $OutRoot)) {
  Write-Host "Cleaning build output: $OutRoot"
  Remove-Item -Path $OutRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

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

function Resolve-QtKitRoot {
  param(
    [string]$QtRootPath,
    [string]$PreferredKit
  )

  if (-not (Test-Path $QtRootPath)) {
    throw "Qt root not found: $QtRootPath"
  }

  if (-not [string]::IsNullOrWhiteSpace($PreferredKit)) {
    $explicit = Get-ChildItem -Path $QtRootPath -Directory -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue } |
      Where-Object { $_.Name -eq $PreferredKit } |
      Select-Object -First 1
    if ($explicit) {
      return $explicit.FullName
    }
    throw "Qt kit not found: $PreferredKit under $QtRootPath"
  }

  $priority = @("mingw_64", "msvc2022_64", "msvc2022_arm64", "llvm-mingw_64")
  foreach ($name in $priority) {
    $kit = Get-ChildItem -Path $QtRootPath -Directory -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue } |
      Where-Object { $_.Name -eq $name } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($kit) {
      return $kit.FullName
    }
  }

  throw "No supported Qt kit found in $QtRootPath (expected mingw_64/msvc2022_64/msvc2022_arm64/llvm-mingw_64)"
}

function Resolve-QtToolchain {
  param([string]$QtKitRoot)
  $qtCmake = Join-Path $QtKitRoot "lib\cmake\Qt6\Qt6Config.cmake"
  if (-not (Test-Path $qtCmake)) {
    throw "Qt6Config.cmake not found: $qtCmake"
  }

  $result = [ordered]@{
    QtKitRoot = $QtKitRoot
    Qt6Dir = (Split-Path $qtCmake -Parent)
    CCompiler = ""
    CxxCompiler = ""
    WinDeployQt = ""
  }

  if ($QtKitRoot -match "mingw") {
    $base = Join-Path $QtRoot "Tools\mingw1310_64\bin"
    $gcc = Join-Path $base "gcc.exe"
    $gxx = Join-Path $base "g++.exe"
    if ((Test-Path $gcc) -and (Test-Path $gxx)) {
      $result.CCompiler = $gcc
      $result.CxxCompiler = $gxx
    }
  }

  $windeployqt = Join-Path $QtKitRoot "bin\windeployqt.exe"
  if (Test-Path $windeployqt) {
    $result.WinDeployQt = $windeployqt
  }
  return $result
}

$qtKitRoot = Resolve-QtKitRoot -QtRootPath $QtRoot -PreferredKit $QtKit
$qtInfo = Resolve-QtToolchain -QtKitRoot $qtKitRoot
Write-Host "Using Qt kit: $($qtInfo.QtKitRoot)"

$cmakeArgs = @(
  "-S", $repoRoot,
  "-B", $OutRoot,
  "-G", "Ninja",
  "-DCMAKE_MAKE_PROGRAM=$ninja",
  "-DCMAKE_BUILD_TYPE=$BuildType",
  "-DQt6_DIR=$($qtInfo.Qt6Dir)",
  "-DCMAKE_PREFIX_PATH=$($qtInfo.QtKitRoot)",
  "-DR3_BUILD_LEGACY_WIN32_UI=$(([bool]$BuildLegacyWin32).ToString().ToUpper())"
)

if (-not [string]::IsNullOrWhiteSpace($qtInfo.CCompiler) -and -not [string]::IsNullOrWhiteSpace($qtInfo.CxxCompiler)) {
  $cmakeArgs += "-DCMAKE_C_COMPILER=$($qtInfo.CCompiler)"
  $cmakeArgs += "-DCMAKE_CXX_COMPILER=$($qtInfo.CxxCompiler)"
}

if ($UseCompilerCache) {
  $cacheExe = Resolve-CompilerCache -ExplicitPath $CompilerCacheExe
  if (-not [string]::IsNullOrWhiteSpace($cacheExe)) {
    Write-Host "Using compiler cache launcher: $cacheExe"
    $cmakeArgs += "-DCMAKE_C_COMPILER_LAUNCHER=$cacheExe"
    $cmakeArgs += "-DCMAKE_CXX_COMPILER_LAUNCHER=$cacheExe"
  } else {
    Write-Host "Compiler cache launcher not found, continue without cache"
  }
}

$configureArgs = @("--fresh") + $cmakeArgs
& $cmake @configureArgs
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed: exit=$LASTEXITCODE" }
& $cmake --build $OutRoot --config $BuildType --target $ClientTarget
if ($LASTEXITCODE -ne 0) { throw "cmake build failed: exit=$LASTEXITCODE" }

function Deploy-QtRuntime {
  param(
    [string]$WinDeployQtExe,
    [string]$BuildRoot,
    [string]$TargetName
  )
  if ([string]::IsNullOrWhiteSpace($WinDeployQtExe) -or -not (Test-Path $WinDeployQtExe)) {
    Write-Host "windeployqt not found, skip runtime deploy"
    return
  }
  $exe = Join-Path $BuildRoot ("src\" + $TargetName.Replace("r3_windows_client_", "windows_client_") + "\" + $TargetName + ".exe")
  if (-not (Test-Path $exe)) {
    $exe = Join-Path $BuildRoot ("src\windows_client_qt\" + $TargetName + ".exe")
  }
  if (-not (Test-Path $exe)) {
    Write-Host "target exe not found for windeployqt, skip: $TargetName"
    return
  }
  & $WinDeployQtExe --no-compiler-runtime --no-translations $exe
}

Deploy-QtRuntime -WinDeployQtExe $qtInfo.WinDeployQt -BuildRoot $OutRoot -TargetName $ClientTarget

function Copy-ToolsForRuntime {
  param([string]$RepoRoot, [string]$DstRoot)
  $dst = Join-Path $DstRoot "tools"
  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  $scripts = @("push_run_agent.ps1", "adb_forward.ps1")
  foreach ($name in $scripts) {
    $src = Join-Path $RepoRoot ("tools\" + $name)
    if (Test-Path $src) {
      Copy-Item -Path $src -Destination (Join-Path $dst $name) -Force
    }
  }
}

function Ensure-AdbBundle {
  param(
    [string]$AdbRootPath,
    [string]$DstRoot,
    [string]$ZipUrl
  )
  if (-not $BundleAdb) {
    return
  }
  $dst = Join-Path $DstRoot "adb_bundle"
  New-Item -ItemType Directory -Force -Path $dst | Out-Null

  $sourceAdb = Join-Path $AdbRootPath "adb.exe"
  if (Test-Path $sourceAdb) {
    Write-Host "Bundling local adb tools from $AdbRootPath"
    Copy-Item -Path (Join-Path $AdbRootPath "*") -Destination $dst -Recurse -Force
    return
  }

  Write-Host "Local adb not found, downloading platform-tools..."
  $zipPath = Join-Path $DstRoot "platform-tools-latest-windows.zip"
  Invoke-WebRequest -Uri $ZipUrl -OutFile $zipPath
  if (Test-Path (Join-Path $dst "platform-tools")) {
    Remove-Item (Join-Path $dst "platform-tools") -Recurse -Force
  }
  Expand-Archive -Path $zipPath -DestinationPath $dst -Force
}

function Build-AndCopy-Agent {
  param(
    [string]$RepoRoot,
    [string]$Ndk,
    [string]$CMake,
    [string]$AgentBuildRoot,
    [string]$DstRoot
  )
  if (-not $BundleAgent) {
    return
  }

  $abis = @("arm64-v8a", "armeabi-v7a")
  $needBuild = $false
  foreach ($abi in $abis) {
    $candidate = Join-Path $AgentBuildRoot ($abi + "\src\android_agent\r3_android_agent")
    if (-not (Test-Path $candidate)) {
      $needBuild = $true
      break
    }
  }

  if ($needBuild) {
    $builder = Join-Path $RepoRoot "tools\build_android_agent.ps1"
    if ((Test-Path $builder) -and (Test-Path $Ndk)) {
      Write-Host "Building android agent for runtime bundle..."
      & powershell -ExecutionPolicy Bypass -File $builder -NdkRoot $Ndk -CMakeRoot $CMake -OutRoot $AgentBuildRoot
    } else {
      Write-Host "Skip agent build: build script or NDK missing"
    }
  }

  $agentDstRoot = Join-Path $DstRoot "android_agent"
  foreach ($abi in $abis) {
    $src = Join-Path $AgentBuildRoot ($abi + "\src\android_agent\r3_android_agent")
    if (-not (Test-Path $src)) {
      continue
    }
    $abiDst = Join-Path $agentDstRoot $abi
    New-Item -ItemType Directory -Force -Path $abiDst | Out-Null
    Copy-Item -Path $src -Destination (Join-Path $abiDst "r3_android_agent") -Force
  }
}

$cmakeRootForAgent = $CMakeRoot
if (-not [string]::IsNullOrWhiteSpace($cmakeRootForAgent)) {
  $cmakeCheck = Join-Path $cmakeRootForAgent "bin\cmake.exe"
  if (-not (Test-Path $cmakeCheck)) {
    $cmakeRootForAgent = ""
  }
}
if ([string]::IsNullOrWhiteSpace($cmakeRootForAgent)) {
  $cmakeRootCandidate = Split-Path (Split-Path $cmake -Parent) -Parent
  $cmakeCheck = Join-Path $cmakeRootCandidate "bin\cmake.exe"
  if (Test-Path $cmakeCheck) {
    $cmakeRootForAgent = $cmakeRootCandidate
  }
}

Copy-ToolsForRuntime -RepoRoot $repoRoot -DstRoot $OutRoot
Ensure-AdbBundle -AdbRootPath $AdbRoot -DstRoot $OutRoot -ZipUrl $AdbZipUrl
Build-AndCopy-Agent -RepoRoot $repoRoot -Ndk $NdkRoot -CMake $cmakeRootForAgent -AgentBuildRoot $AgentOutRoot -DstRoot $OutRoot

Write-Host "Build finished: $OutRoot"
