param(
  [int]$TargetPid,
  [UInt64]$ExecAddr,
  [string]$RemoteHost = "127.0.0.1",
  [int]$Port = 12345,
  [int]$ReadSize = 8
)

$ErrorActionPreference = "Stop"
if (-not $TargetPid -or $ExecAddr -eq 0) {
  throw "TargetPid and ExecAddr are required"
}

$client = New-Object System.Net.Sockets.TcpClient($RemoteHost, $Port)
$client.ReceiveTimeout = 8000
$client.SendTimeout = 8000
$stream = $client.GetStream()
$stream.ReadTimeout = 8000
$stream.WriteTimeout = 8000
$bw = New-Object System.IO.BinaryWriter($stream)
$br = New-Object System.IO.BinaryReader($stream)

function Send-Packet([UInt16]$cmd, [byte[]]$payload) {
  $bw.Write([UInt32]0x52444441)
  $bw.Write($cmd)
  $bw.Write([UInt16]0)
  $bw.Write([UInt32]$payload.Length)
  if ($payload.Length -gt 0) { $bw.Write($payload) }
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

function Bytes-ToHex([byte[]]$data) {
  if (-not $data) { return "" }
  return ($data | ForEach-Object { $_.ToString("X2") }) -join " "
}

try {
  # CMD_ATTACH (0x0002)
  $attachPayload = New-Object byte[] 8
  [BitConverter]::GetBytes([UInt32]$TargetPid).CopyTo($attachPayload,0)
  $resp = Send-And-Recv 0x0002 $attachPayload
  Write-Output ("attach resp size=" + $resp.size)

  # CMD_DEBUG_SET_BP (0x0013)
  $bpPayload = New-Object byte[] 16
  [BitConverter]::GetBytes([UInt32]$TargetPid).CopyTo($bpPayload,0)
  $bpPayload[4] = 0 # backend ptrace
  $bpPayload[5] = 0 # type exec
  $bpPayload[6] = 4 # size
  $bpPayload[7] = 0 # flags
  [BitConverter]::GetBytes([UInt64]$ExecAddr).CopyTo($bpPayload,8)
  $resp = Send-And-Recv 0x0013 $bpPayload
  if ($resp.payload.Length -ge 4) {
    $code = [BitConverter]::ToInt32($resp.payload,0)
    Write-Output ("set bp code=" + $code)
  } else {
    Write-Output ("set bp resp size=" + $resp.size)
  }

  # CMD_READ_MEM (0x0005)
  $readPayload = New-Object byte[] 16
  [BitConverter]::GetBytes([UInt64]$ExecAddr).CopyTo($readPayload,0)
  [BitConverter]::GetBytes([UInt32]$ReadSize).CopyTo($readPayload,8)
  $resp = Send-And-Recv 0x0005 $readPayload
  if ($resp.payload.Length -ge 8) {
    $code = [BitConverter]::ToInt32($resp.payload,0)
    $bytes = [BitConverter]::ToUInt32($resp.payload,4)
    $data = if ($bytes -gt 0 -and $resp.payload.Length -ge (8 + $bytes)) { $resp.payload[8..(7 + $bytes)] } else { @() }
    Write-Output ("read code=" + $code + " bytes=" + $bytes)
    if ($bytes -gt 0) {
      Write-Output ("read hex=" + (Bytes-ToHex $data))
    }
  } else {
    Write-Output ("read resp size=" + $resp.size)
  }
} finally {
  if ($client) { $client.Close() }
}
