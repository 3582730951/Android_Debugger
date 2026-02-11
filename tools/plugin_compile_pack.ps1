param(
  [Parameter(Mandatory = $true)]
  [string]$PluginProjectRoot,
  [string]$CoreRoot = "",
  [string]$CMakeRoot = "D:\CMake",
  [string]$BuildType = "Release",
  [string]$BuildRoot = "",
  [string]$OutPluginsRoot = "",
  [bool]$CleanBuild = $true
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Read-MetaValue {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Meta,
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [object]$DefaultValue = $null
  )
  $prop = $Meta.PSObject.Properties[$Name]
  if ($null -eq $prop) {
    return $DefaultValue
  }
  return $prop.Value
}

if ([string]::IsNullOrWhiteSpace($CoreRoot)) {
  $CoreRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
} else {
  $CoreRoot = (Resolve-Path $CoreRoot).Path
}

$projectRootAbs = (Resolve-Path $PluginProjectRoot).Path
$metaPath = Join-Path $projectRootAbs "plugin_meta.json"
if (-not (Test-Path $metaPath)) {
  throw "plugin_meta.json not found: $metaPath"
}

$meta = Get-Content -Raw $metaPath | ConvertFrom-Json
$pluginId = [string](Read-MetaValue -Meta $meta -Name "plugin_id" -DefaultValue "")
$pluginId = $pluginId.Trim()
if ([string]::IsNullOrWhiteSpace($pluginId)) {
  throw "plugin_meta.json missing required field: plugin_id"
}

$name = [string](Read-MetaValue -Meta $meta -Name "name" -DefaultValue $pluginId)
$name = $name.Trim()
if ([string]::IsNullOrWhiteSpace($name)) {
  $name = $pluginId
}

$version = [string](Read-MetaValue -Meta $meta -Name "version" -DefaultValue "1.0.0")
$version = $version.Trim()
if ([string]::IsNullOrWhiteSpace($version)) {
  $version = "1.0.0"
}

$author = [string](Read-MetaValue -Meta $meta -Name "author" -DefaultValue "QA")
$author = $author.Trim()
if ([string]::IsNullOrWhiteSpace($author)) {
  $author = "QA"
}

$description = [string](Read-MetaValue -Meta $meta -Name "description" -DefaultValue "")
$description = $description.Trim()

$target = [string](Read-MetaValue -Meta $meta -Name "target" -DefaultValue "")
$target = $target.Trim()
$safeId = ($pluginId -replace '[^A-Za-z0-9._-]', '_')
if ([string]::IsNullOrWhiteSpace($target)) {
  $target = "r3_plugin_" + ($safeId -replace '[\.-]', '_')
}

$mode = [string](Read-MetaValue -Meta $meta -Name "mode" -DefaultValue "in_process")
$mode = $mode.Trim().ToLower()
if ([string]::IsNullOrWhiteSpace($mode)) {
  $mode = "in_process"
}

$syscallRead = [int](Read-MetaValue -Meta $meta -Name "syscall_read" -DefaultValue -1)
$syscallWrite = [int](Read-MetaValue -Meta $meta -Name "syscall_write" -DefaultValue -1)
$timeoutMs = [int](Read-MetaValue -Meta $meta -Name "timeout_ms" -DefaultValue 1000)
$timeoutMs = [Math]::Max(1, $timeoutMs)
$userCtxHex = [string](Read-MetaValue -Meta $meta -Name "user_ctx_hex" -DefaultValue "")
$userCtxHex = $userCtxHex.Trim()

$capabilitiesValue = Read-MetaValue -Meta $meta -Name "capabilities" -DefaultValue @("memory.provider", "memory.syscall_bridge")
$capabilities = @()
if ($capabilitiesValue -is [System.Array]) {
  foreach ($c in $capabilitiesValue) {
    $s = [string]$c
    if (-not [string]::IsNullOrWhiteSpace($s)) {
      $capabilities += $s.Trim()
    }
  }
} else {
  $single = [string]$capabilitiesValue
  if (-not [string]::IsNullOrWhiteSpace($single)) {
    $capabilities += $single.Trim()
  }
}
if ($capabilities.Count -eq 0) {
  $capabilities = @("memory.provider", "memory.syscall_bridge")
}

if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
  $BuildRoot = Join-Path $CoreRoot "build/plugin_compile"
}
if ([string]::IsNullOrWhiteSpace($OutPluginsRoot)) {
  $OutPluginsRoot = Join-Path $CoreRoot "plugins"
}

$cmake = Join-Path $CMakeRoot "bin/cmake.exe"
$ninja = Join-Path $CMakeRoot "bin/ninja.exe"
if (-not (Test-Path $cmake)) { throw "cmake not found: $cmake" }
if (-not (Test-Path $ninja)) { throw "ninja not found: $ninja" }

New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null
$buildRootAbs = (Resolve-Path $BuildRoot).Path
$buildDir = Join-Path $buildRootAbs $safeId
if ($CleanBuild -and (Test-Path $buildDir)) {
  Write-Host "Cleaning plugin build directory: $buildDir"
  Remove-Item -Recurse -Force $buildDir
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

New-Item -ItemType Directory -Force -Path $OutPluginsRoot | Out-Null
$outPluginsRootAbs = (Resolve-Path $OutPluginsRoot).Path

$configureArgs = @(
  "-S", $projectRootAbs,
  "-B", $buildDir,
  "-G", "Ninja",
  "-DCMAKE_MAKE_PROGRAM=$ninja",
  "-DCMAKE_BUILD_TYPE=$BuildType",
  "-DR3_CORE_ROOT=$CoreRoot"
)
& $cmake @configureArgs
if ($LASTEXITCODE -ne 0) {
  throw "plugin cmake configure failed: exit=$LASTEXITCODE"
}

& $cmake --build $buildDir --config $BuildType --target $target
if ($LASTEXITCODE -ne 0) {
  throw "plugin build failed: exit=$LASTEXITCODE"
}

$dllCandidates = @(Get-ChildItem -Path $buildDir -Recurse -File -Filter "*.dll" |
  Where-Object { $_.Name -ieq ($target + ".dll") -or $_.Name -like ($target + "*.dll") })
if ($dllCandidates.Count -eq 0) {
  $dllCandidates = @(Get-ChildItem -Path $buildDir -Recurse -File -Filter "*.dll")
}
if ($dllCandidates.Count -eq 0) {
  throw "no plugin dll generated in: $buildDir"
}
$dllPath = ($dllCandidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
Write-Host "Plugin DLL: $dllPath"

$packager = Join-Path $CoreRoot "tools/plugin_packager.ps1"
if (-not (Test-Path $packager)) {
  throw "packager tool not found: $packager"
}

& $packager `
  -PluginId $pluginId `
  -Name $name `
  -Version $version `
  -Author $author `
  -Description $description `
  -DllPath $dllPath `
  -OutRoot $outPluginsRootAbs `
  -Mode $mode `
  -Capabilities $capabilities `
  -SyscallRead $syscallRead `
  -SyscallWrite $syscallWrite `
  -TimeoutMs $timeoutMs `
  -UserCtxHex $userCtxHex `
  -Force
if ($LASTEXITCODE -ne 0) {
  throw "plugin packager failed: exit=$LASTEXITCODE"
}

$pkgDir = Join-Path $outPluginsRootAbs $safeId
$projectQuickstartA = Join-Path $projectRootAbs "schema/quickstart.json"
$projectQuickstartB = Join-Path $projectRootAbs "quickstart.json"
if (Test-Path $projectQuickstartA) {
  Copy-Item -Path $projectQuickstartA -Destination (Join-Path $pkgDir "schema/quickstart.json") -Force
} elseif (Test-Path $projectQuickstartB) {
  Copy-Item -Path $projectQuickstartB -Destination (Join-Path $pkgDir "schema/quickstart.json") -Force
}

$projectReadme = Join-Path $projectRootAbs "docs/README.md"
if (Test-Path $projectReadme) {
  Copy-Item -Path $projectReadme -Destination (Join-Path $pkgDir "docs/README.md") -Force
}

Write-Host "Plugin package ready:"
Write-Host "  $pkgDir"
Write-Host "Enable flow:"
Write-Host "  1) Open client -> 插件与自定义syscall"
Write-Host "  2) 插件根目录 = $outPluginsRootAbs"
Write-Host "  3) 扫描插件 -> 选择插件 -> 启用插件内存Provider"
