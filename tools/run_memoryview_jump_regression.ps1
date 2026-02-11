param(
  [string]$ClientExe = "D:\Code\R3_Code\android_debug\core\build\windows_client\src\windows_client_qt\r3_windows_client_qt.exe",
  [string]$OutDir = "D:\Code\R3_Code\android_debug\core\build\ui_regression_memoryview",
  [string]$MainTitleKeyword = "R3 Android Debug Client",
  [string]$MemoryViewTitleKeyword = "Memory View"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Win32QtReg {
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT {
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
  }

  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern int GetWindowTextLength(IntPtr hWnd);

  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool IsWindow(IntPtr hWnd);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool SetForegroundWindow(IntPtr hWnd);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}
"@

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$SW_RESTORE = 9
$WM_CLOSE = 0x0010

function Get-TopWindows {
  $list = New-Object 'System.Collections.Generic.List[System.IntPtr]'
  $callback = [Win32QtReg+EnumWindowsProc]{
    param([IntPtr]$hWnd, [IntPtr]$lParam)
    $gc = [System.Runtime.InteropServices.GCHandle]::FromIntPtr($lParam)
    $target = [System.Collections.Generic.List[System.IntPtr]]$gc.Target
    $target.Add($hWnd)
    return $true
  }
  $holder = [System.Runtime.InteropServices.GCHandle]::Alloc($list)
  try {
    [void][Win32QtReg]::EnumWindows($callback, [System.Runtime.InteropServices.GCHandle]::ToIntPtr($holder))
  } finally {
    $holder.Free()
  }
  return $list
}

function Get-WindowText {
  param([IntPtr]$Hwnd)
  $len = [Win32QtReg]::GetWindowTextLength($Hwnd)
  if ($len -le 0) { return "" }
  $sb = New-Object System.Text.StringBuilder ($len + 2)
  [void][Win32QtReg]::GetWindowText($Hwnd, $sb, $sb.Capacity)
  return $sb.ToString()
}

function Wait-WindowByTitleContains {
  param(
    [int]$ProcessId,
    [string]$Keyword,
    [int]$TimeoutMs = 15000
  )
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
    foreach ($h in (Get-TopWindows)) {
      if ($h -eq [IntPtr]::Zero -or -not [Win32QtReg]::IsWindow($h)) { continue }
      $windowPid = 0
      [void][Win32QtReg]::GetWindowThreadProcessId($h, [ref]$windowPid)
      if ($windowPid -ne $ProcessId) { continue }
      $title = Get-WindowText -Hwnd $h
      if (-not [string]::IsNullOrWhiteSpace($title) -and $title.Contains($Keyword)) {
        return $h
      }
    }
    Start-Sleep -Milliseconds 80
  }
  return [IntPtr]::Zero
}

function Save-WindowScreenshot {
  param([IntPtr]$Hwnd, [string]$Path)
  if ($Hwnd -eq [IntPtr]::Zero -or -not [Win32QtReg]::IsWindow($Hwnd)) {
    throw "invalid hwnd for screenshot"
  }
  [void][Win32QtReg]::ShowWindow($Hwnd, $SW_RESTORE)
  [void][Win32QtReg]::SetForegroundWindow($Hwnd)
  Start-Sleep -Milliseconds 200

  $rect = New-Object Win32QtReg+RECT
  if (-not [Win32QtReg]::GetWindowRect($Hwnd, [ref]$rect)) {
    throw "GetWindowRect failed"
  }
  $width = [Math]::Max(1, $rect.Right - $rect.Left)
  $height = [Math]::Max(1, $rect.Bottom - $rect.Top)

  $bmp = New-Object System.Drawing.Bitmap $width, $height
  $gfx = [System.Drawing.Graphics]::FromImage($bmp)
  try {
    $gfx.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bmp.Size)
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
  } finally {
    $gfx.Dispose()
    $bmp.Dispose()
  }
}

function Press-Shortcut {
  param([IntPtr]$Hwnd, [string]$Shortcut)
  [void][Win32QtReg]::ShowWindow($Hwnd, $SW_RESTORE)
  [void][Win32QtReg]::SetForegroundWindow($Hwnd)
  Start-Sleep -Milliseconds 120
  [System.Windows.Forms.SendKeys]::SendWait($Shortcut)
  Start-Sleep -Milliseconds 220
}

function Try-OpenMemoryViewWindow {
  param(
    [IntPtr]$MainHwnd,
    [int]$ProcessId,
    [string]$Keyword,
    [int]$Attempts = 6
  )
  for ($i = 0; $i -lt $Attempts; $i++) {
    Press-Shortcut -Hwnd $MainHwnd -Shortcut "^m"
    $hwnd = Wait-WindowByTitleContains -ProcessId $ProcessId -Keyword $Keyword -TimeoutMs 1200
    if ($hwnd -ne [IntPtr]::Zero) {
      return $hwnd
    }
    Start-Sleep -Milliseconds 120
  }
  return [IntPtr]::Zero
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutDir ("run_" + $stamp)
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

if (-not (Test-Path $ClientExe)) {
  throw "Client executable not found: $ClientExe"
}

$proc = Start-Process -FilePath $ClientExe -PassThru
$main = [IntPtr]::Zero
$memoryView = [IntPtr]::Zero

try {
  $main = Wait-WindowByTitleContains -ProcessId $proc.Id -Keyword $MainTitleKeyword -TimeoutMs 20000
  if ($main -eq [IntPtr]::Zero) {
    throw "Main window not found by title keyword: $MainTitleKeyword"
  }
  Save-WindowScreenshot -Hwnd $main -Path (Join-Path $runDir "01_main_window.png")

  $memoryView = Try-OpenMemoryViewWindow -MainHwnd $main -ProcessId $proc.Id -Keyword $MemoryViewTitleKeyword -Attempts 6
  if ($memoryView -eq [IntPtr]::Zero) {
    throw "Memory View window not found by shortcut Ctrl+M"
  }
  Save-WindowScreenshot -Hwnd $memoryView -Path (Join-Path $runDir "02_memoryview_window.png")

  Press-Shortcut -Hwnd $memoryView -Shortcut "%{F4}"
  Start-Sleep -Milliseconds 200

  $reportPath = Join-Path $runDir "memoryview_jump_regression.md"
  @(
    "# MemoryView Qt Regression",
    "",
    "- time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "- exe: `"$ClientExe`"",
    '- main: "01_main_window.png"',
    '- memoryview: "02_memoryview_window.png"',
    "- action: Ctrl+M 打开 Memory View"
  ) | Set-Content -Path $reportPath -Encoding UTF8

  Write-Output ("RunDir: " + $runDir)
  Write-Output ("Report: " + $reportPath)
}
finally {
  if ($memoryView -ne [IntPtr]::Zero -and [Win32QtReg]::IsWindow($memoryView)) {
    [void][Win32QtReg]::PostMessage($memoryView, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  if ($main -ne [IntPtr]::Zero -and [Win32QtReg]::IsWindow($main)) {
    [void][Win32QtReg]::PostMessage($main, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  if ($null -ne $proc -and -not $proc.HasExited) {
    $proc.WaitForExit(2500) | Out-Null
    if (-not $proc.HasExited) {
      $proc.Kill()
    }
  }
}
