<#
.SYNOPSIS
  สตาร์ท Security Monitor แล้วเปิดหน้าแดชบอร์ดในเบราว์เซอร์อัตโนมัติ

.DESCRIPTION
  รวมขั้นตอนเดียวกันให้สั้นที่สุด:
    1. อ่านพอร์ตจาก .env ให้ตรงกับที่ docker compose publish จริง
    2. docker compose up -d
    3. รอจน /api/health ตอบ 200 (ไม่เปิดเบราว์เซอร์ทั้งที่ยังไม่พร้อม)
    4. เปิดเบราว์เซอร์

  ไม่ build ใหม่โดยค่าเริ่มต้น เพราะส่วนใหญ่แค่เปิดดูข้อมูล ไม่ได้แก้โค้ด
  ใช้ -Build เมื่อแก้ pb_public/ หรือ pb_hooks/ เสร็จแล้ว

.EXAMPLE
  .\start.ps1
.EXAMPLE
  .\start.ps1 -Build
.EXAMPLE
  .\start.ps1 -NoOpen
#>
[CmdletBinding()]
param(
  # บังคับ build image ใหม่ (ใช้หลังแก้ pb_public/ หรือ pb_hooks/)
  [switch]$Build,
  # รันแล้วรายงาน URL อย่างเดียว ไม่เปิดเบราว์เซอร์ (ใช้ตอนรันบนเครื่องอื่น / CI)
  [switch]$NoOpen,
  # จำนวนวินาทีที่ยอมรอให้ server ตอบ
  [int]$TimeoutSec = 60
)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$envFile = Join-Path $root '.env'

if (-not (Test-Path -LiteralPath $envFile)) {
  Write-Host 'ไม่พบไฟล์ .env' -ForegroundColor Red
  Write-Host 'สร้างก่อน:' -ForegroundColor Yellow
  Write-Host '  Copy-Item .env.example .env' -ForegroundColor Yellow
  exit 1
}

# อ่านพอร์ตจาก .env ถ้าไม่ตรงกับที่ compose publish ไว้ ลิงก์ที่เปิดจะใช้ไม่ได้
$port = 8090
$match = Select-String -LiteralPath $envFile -Pattern '^\s*POCKETBASE_PORT\s*=\s*(\d+)' |
  Select-Object -First 1
if ($match) { $port = [int]$match.Matches[0].Groups[1].Value }

$url = "http://127.0.0.1:$port"

Write-Host ''
Write-Host '==> docker compose up' -ForegroundColor Cyan
$composeArgs = @('compose', 'up', '-d')
if ($Build) { $composeArgs += '--build' }

Push-Location $root
try {
  # docker compose รายงานความคืบหน้าผ่าน stderr ซึ่ง PowerShell จะจับเป็น
  # NativeCommandError ถ้า ErrorActionPreference เป็น Stop — ปล่อยให้ผ่านไป
  # แล้วตัดสินด้วย $LASTEXITCODE แทน ซึ่งเป็นสัญญาณที่ถูกต้องกว่า
  $ErrorActionPreference = 'Continue'
  & docker @composeArgs
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'

  if ($code -ne 0) {
    Write-Host "docker compose up ล้มเหลว (exit $code)" -ForegroundColor Red
    exit 1
  }
} finally {
  Pop-Location
}

Write-Host ''
Write-Host "==> รอ /api/health (timeout ${TimeoutSec}s)" -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$ready = $false

while ((Get-Date) -lt $deadline) {
  try {
    $response = Invoke-WebRequest -Uri "$url/api/health" -UseBasicParsing -TimeoutSec 3
    if ($response.StatusCode -eq 200) { $ready = $true; break }
  } catch {
    # ยังไม่พร้อม — หลักการแรกคือ PocketBase ยัง migrate/seed อยู่
  }
  Start-Sleep -Milliseconds 500
}

if (-not $ready) {
  Write-Host "ยังไม่ตอบภายใน ${TimeoutSec}s" -ForegroundColor Red
  Write-Host 'ดู log:  docker compose logs -f' -ForegroundColor Yellow
  exit 1
}

Write-Host ''
Write-Host 'พร้อมใช้งาน' -ForegroundColor Green
Write-Host "  Dashboard : $url"
Write-Host "  Admin UI  : $url/_/"
Write-Host '  Login     : SUPERUSER_EMAIL / SUPERUSER_PASSWORD ในไฟล์ .env'
Write-Host ''

if (-not $NoOpen) { Start-Process $url }