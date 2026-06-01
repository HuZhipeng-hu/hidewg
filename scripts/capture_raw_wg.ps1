#Requires -RunAsAdministrator
<#
.SYNOPSIS
    捕获真实原始 WireGuard 流量（不含 HideWG 封装）
.DESCRIPTION
    本脚本在 WireGuard 隧道运行期间，捕获 WireGuard 内层 UDP 端口的流量，
    生成真实的 raw WireGuard pcap 文件，用于评测基线。
    同时捕获 HideWG 外层端口流量，生成 HideWG pcap。

    前置条件：
    - 以管理员身份运行 PowerShell
    - WireGuard 隧道已通过 real_wg_test.ps1 启动，或手动配置并运行
    - HideWG 代理已启动

    用法：.\scripts\capture_raw_wg.ps1
          .\scripts\capture_raw_wg.ps1 -Duration 60
#>

param(
    [int]$Duration = 60,
    [string]$OutputDir = "",
    [int]$WgClientPort = 51820,
    [int]$WgServerPort = 51821,
    [int]$HwClientOuterPort = 55820,
    [int]$HwServerOuterPort = 55821
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir ".hidewg\captures"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$rawWgPcap = Join-Path $OutputDir "raw_wireguard_${timestamp}.pcap"
$hidewgPcap = Join-Path $OutputDir "hidewg_outer_${timestamp}.pcap"

function Write-Step { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Fail { param([string]$Msg) Write-Host "[-] $Msg" -ForegroundColor Red }

# 检查 tcpdump 或 windump 是否可用
$capTool = $null
$capArgs = @()

if (Get-Command tcpdump -ErrorAction SilentlyContinue) {
    $capTool = "tcpdump"
} elseif (Test-Path "C:\Program Files\Wireshark\dumpcap.exe") {
    $capTool = "C:\Program Files\Wireshark\dumpcap.exe"
} else {
    Write-Fail "未找到 tcpdump 或 dumpcap。请安装 Wireshark 或 Npcap。"
    exit 1
}
Write-Ok "抓包工具: $capTool"

# ── 捕获 1：原始 WireGuard 流量（内层端口） ──
Write-Step "启动原始 WireGuard 流量抓包 (端口 $WgClientPort,$WgServerPort, ${Duration}s)..."

$wgFilter = "udp port $WgClientPort or udp port $WgServerPort"
$wgProc = $null
if ($capTool -eq "tcpdump") {
    $wgProc = Start-Process tcpdump -ArgumentList @("-i", "any", "-w", $rawWgPcap, $wgFilter) `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $null -RedirectStandardError $null
} else {
    $wgProc = Start-Process $capTool -ArgumentList @("-i", "any", "-w", $rawWgPcap, "-f", $wgFilter) `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $null -RedirectStandardError $null
}
Write-Ok "WireGuard 抓包 PID=$($wgProc.Id)"

# ── 捕获 2：HideWG 外层流量 ──
Write-Step "启动 HideWG 外层流量抓包 (端口 $HwClientOuterPort,$HwServerOuterPort, ${Duration}s)..."

$hwFilter = "udp port $HwClientOuterPort or udp port $HwServerOuterPort"
$hwProc = $null
if ($capTool -eq "tcpdump") {
    $hwProc = Start-Process tcpdump -ArgumentList @("-i", "any", "-w", $hidewgPcap, $hwFilter) `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $null -RedirectStandardError $null
} else {
    $hwProc = Start-Process $capTool -ArgumentList @("-i", "any", "-w", $hidewgPcap, "-f", $hwFilter) `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $null -RedirectStandardError $null
}
Write-Ok "HideWG 抓包 PID=$($hwProc.Id)"

# ── 生成流量 ──
Write-Step "请在 ${Duration} 秒内通过 WireGuard 隧道生成流量..."
Write-Host "  建议操作："
Write-Host "    - ping 10.99.0.1（或你的 WireGuard 对端 IP）"
Write-Host "    - 通过隧道传输文件"
Write-Host "    - 使用 SSH 连接"
Write-Host ""

$endTime = (Get-Date).AddSeconds($Duration)
while ((Get-Date) -lt $endTime) {
    $remaining = [int]($endTime - (Get-Date)).TotalSeconds
    Write-Host "`r  剩余时间: ${remaining}s  " -NoNewline
    Start-Sleep -Seconds 1
}
Write-Host ""

# ── 停止抓包 ──
Write-Step "停止抓包..."
Start-Sleep -Seconds 1

foreach ($proc in @($wgProc, $hwProc)) {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1

# ── 验证输出 ──
Write-Host ""
Write-Host "═════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " 捕获结果" -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════" -ForegroundColor Cyan

if (Test-Path $rawWgPcap) {
    $wgSize = (Get-Item $rawWgPcap).Length
    Write-Ok "原始 WireGuard pcap: $rawWgPcap ($wgSize bytes)"
} else {
    Write-Fail "原始 WireGuard pcap 未生成"
}

if (Test-Path $hidewgPcap) {
    $hwSize = (Get-Item $hidewgPcap).Length
    Write-Ok "HideWG 外层 pcap: $hidewgPcap ($hwSize bytes)"
} else {
    Write-Fail "HideWG 外层 pcap 未生成"
}

Write-Host ""
Write-Host "用法："
Write-Host "  python real_eval.py --raw-pcap `"$rawWgPcap`" --hidewg-pcap `"$hidewgPcap`" --port $HwServerOuterPort"
Write-Host "  python diagnose_misclass.py --raw-pcap `"$rawWgPcap`" --hidewg-pcap `"$hidewgPcap`" --port $HwServerOuterPort"
