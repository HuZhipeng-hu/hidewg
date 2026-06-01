#Requires -RunAsAdministrator
<#
.SYNOPSIS
    HideWG + WireGuard 真实隧道集成测试（一键脚本）
.DESCRIPTION
    本脚本自动完成：
    1. 生成 WireGuard 密钥对与隧道配置
    2. 启动两个 WireGuard 隧道（client / server）
    3. 启动 HideWG client 和 server 代理
    4. 通过隧道执行 ping 连通性测试
    5. 输出测试结果
    6. 等待用户确认后清理所有资源

    前置条件：以管理员身份运行 PowerShell
    用法：    .\scripts\real_wg_test.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$WgDir = Join-Path $RootDir ".hidewg\real_wg"
$WgExe = "C:\Program Files\WireGuard\wg.exe"
$WgSvcExe = "C:\Program Files\WireGuard\wireguard.exe"

# ── 端口分配 ──
$WgClientPort  = 51820   # WireGuard client listen port
$WgServerPort  = 51821   # WireGuard server listen port
$HwClientInner = 51830   # HideWG client inner listen port (WG client sends here)
$HwServerInner = 51831   # HideWG server inner listen port (WG server sends here)
$HwClientOuter = 55820   # HideWG client outer listen port
$HwServerOuter = 55821   # HideWG server outer listen port

# ── 隧道 IP ──
$WgClientIP = "10.99.0.2"
$WgServerIP = "10.99.0.1"

# ── 颜色输出 ──
function Write-Step { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Fail { param([string]$Msg) Write-Host "[-] $Msg" -ForegroundColor Red }
function Write-Warn { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }

# ══════════════════════════════════════════
# 阶段 0：检查环境
# ══════════════════════════════════════════
Write-Step "检查环境..."

if (-not (Test-Path $WgExe)) {
    Write-Fail "WireGuard 未安装：$WgExe 不存在"
    exit 1
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Fail "Python 不在 PATH 中"
    exit 1
}

$pythonVersion = python --version 2>&1
Write-Ok "Python: $pythonVersion"
Write-Ok "WireGuard: $WgExe"

# ══════════════════════════════════════════
# 阶段 1：生成密钥和配置
# ══════════════════════════════════════════
Write-Step "生成 WireGuard 密钥对..."

New-Item -ItemType Directory -Force -Path $WgDir | Out-Null

$WgClientPriv = & $WgExe genkey
$WgClientPub  = $WgClientPriv | & $WgExe pubkey
$WgServerPriv = & $WgExe genkey
$WgServerPub  = $WgServerPriv | & $WgExe pubkey

Write-Ok "Client pubkey: $WgClientPub"
Write-Ok "Server pubkey: $WgServerPub"

# 写 WireGuard client 配置
$WgClientConf = @"
[Interface]
PrivateKey = $WgClientPriv
Address = $WgClientIP/24
ListenPort = $WgClientPort
MTU = 1280

[Peer]
PublicKey = $WgServerPub
AllowedIPs = $WgServerIP/32
Endpoint = 127.0.0.1:$HwClientInner
PersistentKeepalive = 25
"@

# 写 WireGuard server 配置
$WgServerConf = @"
[Interface]
PrivateKey = $WgServerPriv
Address = $WgServerIP/24
ListenPort = $WgServerPort
MTU = 1280

[Peer]
PublicKey = $WgClientPub
AllowedIPs = $WgClientIP/32
Endpoint = 127.0.0.1:$HwServerInner
"@

$WgClientConfPath = Join-Path $WgDir "hide-client.conf"
$WgServerConfPath = Join-Path $WgDir "hide-server.conf"
$WgClientConf | Out-File -Encoding ascii -FilePath $WgClientConfPath
$WgServerConf | Out-File -Encoding ascii -FilePath $WgServerConfPath
Write-Ok "WireGuard 配置已写入 $WgDir"

# 写 HideWG 配置
$HwClientConf = @"
shared_secret: hidewg-real-test-secret
session_id: 0x48445747

inner_listen_host: 127.0.0.1
inner_listen_port: $HwClientInner

outer_listen_host: 0.0.0.0
outer_listen_port: $HwClientOuter
peer_host: 127.0.0.1
peer_port: $HwServerOuter

max_fragment_payload: 900
padding_buckets: [96, 128, 192, 256, 384, 512, 768, 1024, 1280]
padding_jitter_chance: 0.20
timing_jitter_ms: 2.5
state_path: .hidewg/real_client_state.json
log_path: .hidewg/real_client_runtime.jsonl
pid_path: .hidewg/real_client.pid
"@

$HwServerConf = @"
shared_secret: hidewg-real-test-secret
session_id: 0x48445747

inner_listen_host: 127.0.0.1
inner_listen_port: $HwServerInner

outer_listen_host: 0.0.0.0
outer_listen_port: $HwServerOuter
peer_host: 127.0.0.1
peer_port: $HwClientOuter

wireguard_host: 127.0.0.1
wireguard_port: $WgServerPort

max_fragment_payload: 900
padding_buckets: [96, 128, 192, 256, 384, 512, 768, 1024, 1280]
padding_jitter_chance: 0.20
timing_jitter_ms: 2.5
state_path: .hidewg/real_server_state.json
log_path: .hidewg/real_server_runtime.jsonl
pid_path: .hidewg/real_server.pid
"@

$HwClientConfPath = Join-Path $RootDir "configs\real-client.yaml"
$HwServerConfPath = Join-Path $RootDir "configs\real-server.yaml"
$HwClientConf | Out-File -Encoding utf8 -FilePath $HwClientConfPath
$HwServerConf | Out-File -Encoding utf8 -FilePath $HwServerConfPath
Write-Ok "HideWG 配置已写入 configs\real-*.yaml"

# ══════════════════════════════════════════
# 阶段 2：启动 WireGuard 隧道
# ══════════════════════════════════════════
Write-Step "启动 WireGuard 隧道..."

& $WgSvcExe /installtunnelservice $WgClientConfPath 2>&1
Start-Sleep -Seconds 1
& $WgSvcExe /installtunnelservice $WgServerConfPath 2>&1
Start-Sleep -Seconds 2

# 验证隧道是否启动
$tunnelInterfaces = netsh interface ipv4 show interfaces | Out-String
if ($tunnelInterfaces -match "hide-client|hide-server") {
    Write-Ok "WireGuard 隧道已启动"
} else {
    Write-Warn "隧道接口可能需要几秒初始化..."
    Start-Sleep -Seconds 3
}

# 显示接口信息
Write-Host ""
netsh interface ipv4 show interfaces | Select-String "hide"
Write-Host ""

# ══════════════════════════════════════════
# 阶段 3：启动 HideWG 代理
# ══════════════════════════════════════════
Write-Step "启动 HideWG server 代理..."
$HwServerProc = Start-Process python -ArgumentList @(
    (Join-Path $RootDir "hidewg"),
    "run", "--role", "server", "--config", $HwServerConfPath
) -WorkingDirectory $RootDir -PassThru -WindowStyle Hidden
Write-Ok "HideWG server PID=$($HwServerProc.Id)"

Start-Sleep -Seconds 1

Write-Step "启动 HideWG client 代理..."
$HwClientProc = Start-Process python -ArgumentList @(
    (Join-Path $RootDir "hidewg"),
    "run", "--role", "client", "--config", $HwClientConfPath
) -WorkingDirectory $RootDir -PassThru -WindowStyle Hidden
Write-Ok "HideWG client PID=$($HwClientProc.Id)"

Write-Step "等待隧道握手建立..."
Start-Sleep -Seconds 5

# ══════════════════════════════════════════
# 阶段 4：连通性测试
# ══════════════════════════════════════════
Write-Host ""
Write-Host "═════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " 连通性测试" -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# 测试 1: ping 隧道对端
Write-Step "Test 1: Ping $WgServerIP (通过 WireGuard + HideWG 隧道)..."
$pingResult = ping -n 4 -w 3000 $WgServerIP 2>&1
Write-Host $pingResult
$pingSuccess = $pingResult -match "Reply from"

# 测试 2: 导出状态
Write-Step "Test 2: 导出 HideWG 运行状态..."
& python (Join-Path $RootDir "hidewg") status --output (Join-Path $RootDir "artifacts\real_state.json") 2>&1
if (Test-Path (Join-Path $RootDir "artifacts\real_state.json")) {
    Write-Ok "状态已导出到 artifacts\real_state.json"
    Get-Content (Join-Path $RootDir "artifacts\real_state.json") | Write-Host
}

# 测试 3: 显示 WireGuard 状态
Write-Step "Test 3: WireGuard 接口状态..."
netsh interface ipv4 show addresses "hide-client" 2>&1
Write-Host "---"
netsh interface ipv4 show addresses "hide-server" 2>&1

# ══════════════════════════════════════════
# 阶段 5：结果汇总
# ══════════════════════════════════════════
Write-Host ""
Write-Host "═════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " 测试结果" -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════" -ForegroundColor Cyan

if ($pingSuccess) {
    Write-Host "  Ping 测试     : " -NoNewline; Write-Host "通过" -ForegroundColor Green
} else {
    Write-Host "  Ping 测试     : " -NoNewline; Write-Host "失败" -ForegroundColor Red
}

Write-Host "  架构          : WireGuard → HideWG → WireGuard"
Write-Host "  隧道网络      : $WgClientIP <-> $WgServerIP"
Write-Host "  WG Client端口 : $WgClientPort (listen)"
Write-Host "  WG Server端口 : $WgServerPort (listen)"
Write-Host "  HideWG 内端口 : client=$HwClientInner / server=$HwServerInner"
Write-Host "  HideWG 外端口 : client=$HwClientOuter / server=$HwServerOuter"
Write-Host ""

# ══════════════════════════════════════════
# 清理
# ══════════════════════════════════════════
Write-Host "按 Enter 键清理所有资源（停止隧道、终止进程）..." -ForegroundColor Yellow
Read-Host

Write-Step "停止 HideWG 代理..."
foreach ($proc in @($HwClientProc, $HwServerProc)) {
    if ($proc -and -not $proc.HasExited) {
        $proc.Kill()
        Write-Ok "已终止 PID=$($proc.Id)"
    }
}

Write-Step "停止 WireGuard 隧道..."
& $WgSvcExe /uninstalltunnelservice "hide-client" 2>&1
& $WgSvcExe /uninstalltunnelservice "hide-server" 2>&1
Start-Sleep -Seconds 1

Write-Ok "清理完成"
