param(
  [string]$RemoteHost = "127.0.0.1",
  [int]$Port = 12345,
  [int]$TargetPid,
  [UInt64]$ReadAddr = 0,
  [int]$ReadSize = 4,
  [UInt64]$WriteAddr = 0,
  [byte[]]$WriteBytes = @(),
  [UInt64]$PointerBase = 0,
  [UInt64[]]$PointerOffsets = @(),
  [int]$PointerSize = 8,
  [int]$PointerReadSize = 8,
  [switch]$ListProcesses,
  [int]$ScanU8 = -1,
  [UInt64]$ScanStart = 0,
  [UInt64]$ScanEnd = 0,
  [UInt64]$ScanPageStart = 0,
  [int]$ScanPageMax = 16,
  [switch]$SkipDebug,
  [switch]$SkipAttach,
  [switch]$GetCaps,
  [switch]$CustomRead,
  [int]$CustomReadSyscall = -1,
  [int]$CustomWriteSyscall = -1,
  [string]$CustomUserCtxHex = "",
  [switch]$VerifyAfterWrite,
  [int]$TimeoutMs = 8000
)

$ErrorActionPreference = "Stop"

if (-not $TargetPid) {
  throw "TargetPid is required"
}

try {
  $client = New-Object System.Net.Sockets.TcpClient($RemoteHost, $Port)
  $client.ReceiveTimeout = $TimeoutMs
  $client.SendTimeout = $TimeoutMs
  $stream = $client.GetStream()
  $stream.ReadTimeout = $TimeoutMs
  $stream.WriteTimeout = $TimeoutMs
  $bw = New-Object System.IO.BinaryWriter($stream)
  $br = New-Object System.IO.BinaryReader($stream)

function Send-Packet([UInt16]$cmd, [byte[]]$payload) {
  $bw.Write([UInt32]0x52444441)
  $bw.Write($cmd)
  $bw.Write([UInt16]0)
  $bw.Write([UInt32]$payload.Length)
  if ($payload.Length -gt 0) {
    $bw.Write($payload)
  }
  $bw.Flush()
}

function Recv-Packet() {
  $magic = $br.ReadUInt32()
  $cmd = $br.ReadUInt16()
  $res = $br.ReadUInt16()
  $size = $br.ReadUInt32()
  $payload = if ($size -gt 0) { $br.ReadBytes($size) } else { @() }
  return @{ magic = $magic; cmd = $cmd; size = $size; payload = $payload }
}

function Send-And-Recv([UInt16]$cmd, [byte[]]$payload) {
  Send-Packet $cmd $payload
  return Recv-Packet
}

function Bytes-ToHex([byte[]]$data, [int]$count) {
  if (-not $data -or $count -le 0) {
    return ""
  }
  $max = [Math]::Min($count, $data.Length)
  return ($data[0..($max-1)] | ForEach-Object { $_.ToString("X2") }) -join " "
}

function Parse-HexBytes([string]$text) {
  if ([string]::IsNullOrWhiteSpace($text)) { return @() }
  $parts = $text.Trim().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
  $out = New-Object System.Collections.Generic.List[byte]
  foreach ($p in $parts) {
    $token = $p.Trim()
    if ($token.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
      $token = $token.Substring(2)
    }
    if ($token.Length -eq 0) { continue }
    $out.Add([Convert]::ToByte($token, 16))
  }
  return $out.ToArray()
}

if (-not $SkipAttach) {
  Write-Output "CMD_ATTACH"
  $attachPayload = New-Object byte[] 8
  [BitConverter]::GetBytes([UInt32]$TargetPid).CopyTo($attachPayload,0)
  $resp = Send-And-Recv 0x0002 $attachPayload
  Write-Output ("attach resp size=" + $resp.size)
} else {
  $attachPayload = New-Object byte[] 8
  [BitConverter]::GetBytes([UInt32]$TargetPid).CopyTo($attachPayload,0)
}

if (-not $SkipDebug) {
  Write-Output "CMD_DEBUG_ATTACH"
  $resp = Send-And-Recv 0x000B $attachPayload
  Write-Output ("debug attach resp size=" + $resp.size)

  Write-Output "CMD_GET_REGS"
  $resp = Send-And-Recv 0x000A $attachPayload
  Write-Output ("get regs size=" + $resp.size)

  Write-Output "CMD_DEBUG_DETACH"
  $resp = Send-And-Recv 0x000C @()
  Write-Output ("debug detach size=" + $resp.size)
}

if ($GetCaps) {
  Write-Output "CMD_GET_CAPS"
  $req = New-Object byte[] 8
  [BitConverter]::GetBytes([UInt32]1).CopyTo($req, 0)
  $resp = Send-And-Recv 0x001A $req
  if ($resp.payload.Length -ge 32) {
    $code = [BitConverter]::ToInt32($resp.payload, 0)
    $proto = [BitConverter]::ToUInt32($resp.payload, 4)
    $flags = [BitConverter]::ToUInt64($resp.payload, 8)
    $maxBatch = [BitConverter]::ToUInt32($resp.payload, 16)
    $maxCustom = [BitConverter]::ToUInt32($resp.payload, 20)
    Write-Output ("caps code=" + $code + " proto=" + $proto + " flags=0x" + $flags.ToString("X") + " maxBatch=" + $maxBatch + " maxCustom=" + $maxCustom)
  } else {
    Write-Output ("caps resp size=" + $resp.size)
  }
}

if ($ListProcesses) {
  Write-Output "CMD_LIST_PROCESSES"
  $req = New-Object byte[] 8
  [BitConverter]::GetBytes([UInt32]64).CopyTo($req, 0)
  $resp = Send-And-Recv 0x0009 $req
  if ($resp.payload.Length -ge 8) {
    $count = [BitConverter]::ToUInt32($resp.payload, 0)
    Write-Output ("process count=" + $count)
    $offset = 8
    $printed = 0
    while ($offset + 8 -le $resp.payload.Length -and $printed -lt 10) {
    $procId = [BitConverter]::ToUInt32($resp.payload, $offset)
      $nameLen = [BitConverter]::ToUInt16($resp.payload, $offset + 4)
      $offset += 8
      if ($nameLen -gt 0 -and $offset + $nameLen -le $resp.payload.Length) {
        $name = [System.Text.Encoding]::UTF8.GetString($resp.payload[$offset..($offset + $nameLen - 1)])
        $offset += $nameLen
      } else {
        $name = ""
      }
      Write-Output ("pid=" + $procId + " name=" + $name)
      $printed++
    }
  } else {
    Write-Output ("process list size=" + $resp.size)
  }
}

if ($PointerBase -ne 0 -and $PointerOffsets.Length -gt 0) {
  Write-Output "CMD_GET_POINTER_CHAIN"
  $count = [UInt32]$PointerOffsets.Length
  $headerSize = 16
  $payload = New-Object byte[] ($headerSize + ($count * 8))
  [BitConverter]::GetBytes([UInt64]$PointerBase).CopyTo($payload, 0)
  [BitConverter]::GetBytes([UInt32]$count).CopyTo($payload, 8)
  [BitConverter]::GetBytes([UInt32]$PointerSize).CopyTo($payload, 12)
  for ($i = 0; $i -lt $PointerOffsets.Length; $i++) {
    [BitConverter]::GetBytes([UInt64]$PointerOffsets[$i]).CopyTo($payload, $headerSize + ($i * 8))
  }
  $resp = Send-And-Recv 0x0007 $payload
  if ($resp.payload.Length -ge 16) {
    $code = [BitConverter]::ToInt32($resp.payload, 0)
    $addr = [BitConverter]::ToUInt64($resp.payload, 8)
    Write-Output ("pointer chain code=" + $code + " addr=0x" + $addr.ToString("X"))
    if ($code -eq 0 -and $PointerReadSize -gt 0) {
      Write-Output "CMD_READ_MEM (pointer)"
      $readPayload = New-Object byte[] 16
      [BitConverter]::GetBytes([UInt64]$addr).CopyTo($readPayload,0)
      [BitConverter]::GetBytes([UInt32]$PointerReadSize).CopyTo($readPayload,8)
      $r = Send-And-Recv 0x0005 $readPayload
      if ($r.payload.Length -ge 8) {
        $rcode = [BitConverter]::ToInt32($r.payload, 0)
        $rbytes = [BitConverter]::ToUInt32($r.payload, 4)
        $rdata = if ($rbytes -gt 0 -and $r.payload.Length -ge (8 + $rbytes)) { $r.payload[8..(7 + $rbytes)] } else { @() }
        Write-Output ("pointer read code=" + $rcode + " bytes=" + $rbytes)
        if ($rbytes -gt 0) {
          Write-Output ("pointer hex=" + (Bytes-ToHex $rdata $rbytes))
        }
      } else {
        Write-Output ("pointer read size=" + $r.size)
      }
    }
  } else {
    Write-Output ("pointer chain size=" + $resp.size)
  }
}

if ($ScanU8 -ge 0 -and $ScanU8 -le 255) {
  Write-Output "CMD_SCAN_FIRST (U8)"
  $valueLen = 1
  $headerSize = 24
  $payload = New-Object byte[] ($headerSize + $valueLen)
  $payload[0] = 0 # ValueType U8
  $payload[1] = 0 # Comparison EQ
  # reserved 2 bytes
  [BitConverter]::GetBytes([UInt64]$ScanStart).CopyTo($payload, 4)
  [BitConverter]::GetBytes([UInt64]$ScanEnd).CopyTo($payload, 12)
  [BitConverter]::GetBytes([UInt32]$valueLen).CopyTo($payload, 20)
  $payload[$headerSize] = [byte]$ScanU8

  $resp = Send-And-Recv 0x0003 $payload
  if ($resp.payload.Length -ge 8) {
    $count = [BitConverter]::ToUInt64($resp.payload, 0)
    Write-Output ("scan count=" + $count)
    if ($resp.payload.Length -ge 16) {
      $addr = [BitConverter]::ToUInt64($resp.payload, 8)
      Write-Output ("scan first addr=0x" + $addr.ToString("X"))
    }
  } else {
    Write-Output ("scan resp size=" + $resp.size)
  }

  Write-Output "CMD_SCAN_PAGE"
  $pageReq = New-Object byte[] 16
  [BitConverter]::GetBytes([UInt64]$ScanPageStart).CopyTo($pageReq, 0)
  [BitConverter]::GetBytes([UInt32]$ScanPageMax).CopyTo($pageReq, 8)
  $resp = Send-And-Recv 0x0008 $pageReq
  if ($resp.payload.Length -ge 8) {
    $count = [BitConverter]::ToUInt64($resp.payload, 0)
    Write-Output ("scan page count=" + $count)
    if ($resp.payload.Length -ge 16) {
      $addr = [BitConverter]::ToUInt64($resp.payload, 8)
      Write-Output ("scan page first addr=0x" + $addr.ToString("X"))
    }
  } else {
    Write-Output ("scan page resp size=" + $resp.size)
  }
}

if ($ReadAddr -ne 0) {
  Write-Output "CMD_READ_MEM"
  $readPayload = New-Object byte[] 16
  [BitConverter]::GetBytes([UInt64]$ReadAddr).CopyTo($readPayload,0)
  [BitConverter]::GetBytes([UInt32]$ReadSize).CopyTo($readPayload,8)
  $resp = Send-And-Recv 0x0005 $readPayload
  if ($resp.payload.Length -ge 8) {
    $code = [BitConverter]::ToInt32($resp.payload, 0)
    $bytes = [BitConverter]::ToUInt32($resp.payload, 4)
    $data = if ($bytes -gt 0 -and $resp.payload.Length -ge (8 + $bytes)) { $resp.payload[8..(7 + $bytes)] } else { @() }
    Write-Output ("read size=" + $resp.size + " code=" + $code + " bytes=" + $bytes)
    if ($bytes -gt 0) {
      Write-Output ("read hex=" + (Bytes-ToHex $data $bytes))
    }
  } else {
    Write-Output ("read size=" + $resp.size)
  }
}

if ($CustomRead -and $ReadAddr -ne 0 -and $ReadSize -gt 0) {
  Write-Output "CMD_CUSTOM_MEM_OP (READ)"
  $ctx = Parse-HexBytes $CustomUserCtxHex
  $hdr = 56
  $payload = New-Object byte[] ($hdr + $ctx.Length)
  [BitConverter]::GetBytes([UInt32]$TargetPid).CopyTo($payload, 0)
  [BitConverter]::GetBytes([UInt32]1).CopyTo($payload, 4)    # abi
  [BitConverter]::GetBytes([UInt32]1).CopyTo($payload, 8)    # op read
  [BitConverter]::GetBytes([UInt32]1).CopyTo($payload, 12)   # allow fallback
  [BitConverter]::GetBytes([UInt64]$ReadAddr).CopyTo($payload, 16)
  [BitConverter]::GetBytes([UInt32]$ReadSize).CopyTo($payload, 24)
  [BitConverter]::GetBytes([UInt32]$TimeoutMs).CopyTo($payload, 28)
  [BitConverter]::GetBytes([UInt64]1).CopyTo($payload, 32)   # trace
  [BitConverter]::GetBytes([Int32]$CustomReadSyscall).CopyTo($payload, 40)
  [BitConverter]::GetBytes([Int32]$CustomWriteSyscall).CopyTo($payload, 44)
  [BitConverter]::GetBytes([UInt32]$ctx.Length).CopyTo($payload, 48)
  [BitConverter]::GetBytes([UInt32]0).CopyTo($payload, 52)
  if ($ctx.Length -gt 0) {
    $ctx.CopyTo($payload, $hdr)
  }
  $resp = Send-And-Recv 0x001B $payload
  if ($resp.payload.Length -ge 40) {
    $code = [BitConverter]::ToInt32($resp.payload, 0)
    $providerErr = [BitConverter]::ToInt32($resp.payload, 4)
    $sysErr = [BitConverter]::ToInt32($resp.payload, 8)
    $bytesDone = [BitConverter]::ToUInt32($resp.payload, 12)
    $elapsed = [BitConverter]::ToUInt64($resp.payload, 16)
    $trace = [BitConverter]::ToUInt64($resp.payload, 24)
    $dataLen = [BitConverter]::ToUInt32($resp.payload, 32)
    Write-Output ("custom read code=" + $code + " providerErr=" + $providerErr + " sysErr=" + $sysErr + " bytesDone=" + $bytesDone + " elapsedUs=" + $elapsed + " trace=" + $trace + " dataLen=" + $dataLen)
    if ($dataLen -gt 0 -and $resp.payload.Length -ge (40 + $dataLen)) {
      $data = $resp.payload[40..(39 + $dataLen)]
      Write-Output ("custom read hex=" + (Bytes-ToHex $data $dataLen))
    }
  } else {
    Write-Output ("custom read resp size=" + $resp.size)
  }
}

if ($WriteAddr -ne 0 -and $WriteBytes.Length -gt 0) {
  Write-Output "CMD_WRITE_MEM"
  $headerSize = 16
  $payload = New-Object byte[] ($headerSize + $WriteBytes.Length)
  [BitConverter]::GetBytes([UInt64]$WriteAddr).CopyTo($payload,0)
  [BitConverter]::GetBytes([UInt32]$WriteBytes.Length).CopyTo($payload,8)
  # reserved 4 bytes already zero
  $WriteBytes.CopyTo($payload, $headerSize)
  $resp = Send-And-Recv 0x0006 $payload
  if ($resp.payload.Length -ge 8) {
    $code = [BitConverter]::ToInt32($resp.payload, 0)
    $bytes = [BitConverter]::ToUInt32($resp.payload, 4)
    Write-Output ("write size=" + $resp.size + " code=" + $code + " bytes=" + $bytes)
  } else {
    Write-Output ("write size=" + $resp.size)
  }

  if ($VerifyAfterWrite -and $ReadAddr -ne 0 -and $ReadSize -gt 0) {
    Write-Output "CMD_READ_MEM (verify)"
    $readPayload = New-Object byte[] 16
    [BitConverter]::GetBytes([UInt64]$ReadAddr).CopyTo($readPayload,0)
    [BitConverter]::GetBytes([UInt32]$ReadSize).CopyTo($readPayload,8)
    $resp = Send-And-Recv 0x0005 $readPayload
    if ($resp.payload.Length -ge 8) {
      $code = [BitConverter]::ToInt32($resp.payload, 0)
      $bytes = [BitConverter]::ToUInt32($resp.payload, 4)
      $data = if ($bytes -gt 0 -and $resp.payload.Length -ge (8 + $bytes)) { $resp.payload[8..(7 + $bytes)] } else { @() }
      Write-Output ("verify size=" + $resp.size + " code=" + $code + " bytes=" + $bytes)
      if ($bytes -gt 0) {
        Write-Output ("verify hex=" + (Bytes-ToHex $data $bytes))
      }
    } else {
      Write-Output ("verify size=" + $resp.size)
    }
  }
}

} finally {
  if ($client) {
    $client.Close()
  }
}
