# HideWG — 基于 WireGuard 的协议特征隐藏传输系统

HideWG 在 WireGuard 外侧增加一层传输封装，消除 WireGuard 的固定头部、固定长度、握手时序和 keepalive 模式等可识别特征，使外部观察者难以通过规则或机器学习识别 WireGuard 流量。

## 系统架构

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  应用层       │     │  WireGuard   │     │  HideWG      │
│  ping/HTTP   │ ──► │  隧道加密     │ ──► │  WS 封装     │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                           WSS:443 (TLS 1.3)
                                                  │
                                           ┌──────▼───────┐
                                           │  nginx 反代   │
                                           │  TLS 终止     │
                                           └──────┬───────┘
                                                  │
                                           WS:8443 (明文)
                                                  │
                                           ┌──────▼───────┐
                                           │  对端 HideWG  │
                                           │  WS 解封装    │
                                           └──────┬───────┘
                                                  ▼
                                           WireGuard → 应用
```

外层传输固定为 WebSocket-over-TLS，通过 nginx 反向代理实现标准 HTTPS 接入。Wireshark 抓包看到的是标准 WebSocket over TLS 1.3 流量，与普通 Web 应用（聊天、流媒体、通知推送）无法区分。

端口分配：

| 组件 | 客户端 | 服务端 |
|------|--------|--------|
| WireGuard 监听 | 51820 | 51820 |
| HideWG 内层 (面向 WG) | 51830 | 51831 |
| HideWG 外层 (WS 监听) | — | 8443 |
| nginx (TLS 接入) | — | 443 |

## 快速开始（本地验证，无需网络）

不需要管理员权限，不需要 WireGuard，不需要两台机器。

```bash
# 1. 安装依赖
pip install cryptography numpy

# 2. 克隆项目
git clone <repo-url> safewg
cd safewg

# 3. 运行验证套件
python hidewg verify --config configs/lab.yaml --output artifacts

# 4. 查看结果
cat artifacts/verify_report.json
```

预期输出：所有 7 项功能测试 `"passed": true`。

| 测试项 | 说明 |
|--------|------|
| `basic_connectivity` | WireGuard 风格载荷往返还原 |
| `tcp_file_integrity` | 分块传输 SHA256 一致 |
| `udp_stream` | UDP 报文顺序与字节保留 |
| `adapter_loopback` | 本地 UDP 代理转发 |
| `large_packet_fragmentation` | 乱序分片重组 |
| `abnormal_packet_handling` | 重放/篡改/畸形包丢弃 |
| `state_observability` | 运行时计数器导出 |

## 真实部署（两台机器）

详见 [docs/操作流程指南.md](docs/操作流程指南.md)。

### 环境要求

**服务端（Linux）：**
- Ubuntu 20.04+ / Debian 11+
- Python 3.8+，wireguard-tools，tcpdump
- 公网 IP，安全组放通 UDP 55821

```bash
apt update && apt install -y wireguard-tools python3 tcpdump
pip3 install cryptography
```

**客户端（Windows）：**
- Windows 10/11
- Python 3.9+，WireGuard for Windows

```powershell
pip install cryptography numpy
```

**客户端（Linux）：**
- Ubuntu 20.04+，Python 3.8+，wireguard-tools

```bash
pip3 install cryptography numpy
```

### 第一步：生成密钥

```bash
# 服务端密钥对
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

# 客户端密钥对
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
```

### 第二步：配置 WireGuard

编辑 `configs/wg-server.conf` 和 `configs/wg-client.conf`，填入密钥。

客户端 Endpoint 必须指向 HideWG 内层端口：
```ini
[Peer]
Endpoint = 127.0.0.1:51830    # ← 不是服务端公网地址
```

### 第三步：配置 HideWG

编辑 `configs/server.yaml` 和 `configs/client.yaml`：

- `shared_secret`：两端一致（`openssl rand -hex 16` 生成）
- `peer_host`：客户端填服务端公网 IP，服务端填 `127.0.0.1`
- `wireguard_port`：必须与 `wg show` 显示的实际端口一致

### 第四步：按顺序启动

```bash
# ① 服务端启动 HideWG
nohup ./hidewg run --role server --config configs/server.yaml &

# ② 客户端启动 HideWG
python hidewg run --role client --config configs/client.yaml

# ③ 客户端启动 WireGuard
wg-quick up configs/wg-client.conf

# ④ 验证
ping 10.7.0.1
```

### 启动前自检

```powershell
# 客户端 (Windows)
# 依赖
python -c "import cryptography"
# 残留进程
netstat -ano | findstr "51830"
netstat -ano | findstr "55820"
# 端口保留范围（避开 Hyper-V 预留）
netsh interface ipv4 show excludedportrange protocol=udp
```

```bash
# 服务端 (Linux)
# 残留进程
ss -ulnp | grep -E '51831|55821'
# WireGuard 端口一致性
wg show wg0 | grep "listening port"
```

## 反检测技术

| 技术 | 对抗目标 | 实现 |
|------|---------|------|
| ChaCha20Poly1305 AEAD | 加密头部 + 认证，消除 WG 固定字节签名 | `protocol.py` |
| 连续化填充 | 消除离散桶指纹，包长分布模拟真实 UDP 混合流量 | `ContinuousPaddingPolicy` |
| 自适应桶填充 | 均匀化桶选择频率 + 高斯抖动打破精确桶对齐 | `AdaptivePaddingPolicy` |
| 随机碎片化 | 碎片大小随机，打破等长序列模式（CNN 自相关检测） | `_random_split()` |
| S4 双层噪声前缀 | S4 随机前填充 + 噪声字节，偏移整体包长 | `JunkInjector` |
| 泊松掩护流量 | 指数分布间隔 + 连续包长，模拟真实 UDP 空闲模式 | `_inject_cover()` |
| 突发感知时序抖动 | 方向切换间长延迟，打破方向马尔科夫指纹 | `_apply_timing()` |

## 深度学习对抗评估

```bash
# 运行 DL 评估（生成 4 种分类器 × 4 类流量的评估结果）
python eval_dl.py

# 查看结果
cat artifacts/dl_eval.json
```

4 种流量类型：Raw-WG / HWG-adaptive / HWG-continuous / Normal-UDP

| 分类器 | 准确率 | 随机基线 | 说明 |
|--------|--------|---------|------|
| CNN-1D | **20.8%** | 25% | **低于随机** |
| MLP-256 | 44.6% | 25% | 接近随机 |
| RandomForest-50 | 47.9% | 25% | 接近随机 |
| NearestCentroid | 67.1% | 25% | 简单统计分类器 |

HWG-adaptive 对 CNN 的召回率从 94% 降至 **24%**，低于随机水平。

## 真实流量评测

使用真实抓包数据与合成 WireGuard 基线对比：

```bash
# 自动远程抓包 + 生成流量 + 分析
python evaluate.py --server root@<服务器IP> --port 55821 --target 10.7.0.1 --duration 90
```

或手动在服务端抓包：

```bash
# 服务端抓取外层流量
tcpdump -i any udp port 55821 -w .hidewg/real_capture.pcap &
# 客户端生成流量
ping -n 30 10.7.0.1
# 停止抓包后分析
python hidewg verify --config configs/lab.yaml --output artifacts
```

用 Wireshark 对比：

```
artifacts/raw_wireguard.pcap   ← 原始 WireGuard（首字节 01/02/04 特征）
artifacts/capture.pcap         ← HideWG 封装后（首字节随机）
```

## 配置说明

### 核心配置项

```yaml
shared_secret: <32位hex密钥>           # 两端一致
max_fragment_payload: 1300            # 最大分片载荷

# 填充模式
padding_mode: adaptive                # adaptive / continuous
padding_buckets: [96, 128, 192, 256, 384, 512, 768, 1024, 1280]
adaptive_padding: true
bucket_jitter_sigma: 15.0             # 高斯抖动打破桶对齐

# AmneziaWG 借鉴
junk_count: 3                         # 会话初始垃圾包
noise_prefix_max: 24                  # 噪声前缀
s4_padding_max: 48                    # S4 随机前填充
cover_traffic: true                   # 泊松掩护流量
cover_rate_hz: 0.5
burst_timing: true                    # 突发时序抖动
bucket_drift: 8                       # 桶边界随机化
```

### 两端必须一致的字段

| 字段 | 说明 |
|------|------|
| `shared_secret` | 加密密钥来源 |
| `session_id` | 会话标识 |
| `max_fragment_payload` | 分片阈值 |
| `padding_buckets` | 填充桶 |
| `adaptive_padding` | 防御策略 |

### 各端独立的字段

| 字段 | 客户端 | 服务端 |
|------|--------|--------|
| `inner_listen_port` | 51830 | 51831 |
| `outer_listen_port` | 55820 | 55821 |
| `peer_host` | 服务端公网 IP | 127.0.0.1 |
| `peer_port` | 55821 | 55820 |

### 传输层：WebSocket-over-TLS + nginx 反代

外层传输固定为 WebSocket-over-TLS。部署时配合 nginx 反向代理：

```
客户端 ──WSS (TLS 1.3)──► nginx:443 ──WS (明文)──► HideWG:8443
```

nginx 负责 TLS 终止，将 WebSocket 请求转发到 HideWG 的 WS 端口。Wireshark 在公网链路上只能看到标准 HTTPS 流量。

生成 TLS 证书（自签名，测试用）：

```bash
python hidewg cert --cn <服务器IP> --output-dir .hidewg/tls
```

或使用 Let's Encrypt（生产环境推荐）：

```bash
certbot --nginx -d your-domain.com
```

nginx 配置模板见 `configs/nginx-hidewg.conf`。

## CLI 命令

| 命令 | 说明 |
|------|------|
| `python hidewg run --role server --config configs/server.yaml` | 启动服务端 |
| `python hidewg run --role client --config configs/client.yaml` | 启动客户端 |
| `python hidewg verify --config configs/lab.yaml --output artifacts` | 运行验证 |
| `python hidewg status --output state.json` | 导出状态 |
| `python hidewg stop` | 停止所有代理 |
| `python eval_dl.py` | DL 分类器对抗评估 |
| `python evaluate.py` | 真实抓包评测 |

## 验证输出

| 文件 | 说明 |
|------|------|
| `artifacts/verify_report.json` | 功能正确性报告 |
| `artifacts/stealth_report.json` | 隐匿性报告（规则检测 + 分类器） |
| `artifacts/performance_report.csv` | 效率报告（吞吐/延迟/带宽） |
| `artifacts/dl_eval.json` | DL 对抗评估结果 |
| `artifacts/capture.pcap` | HideWG 外层流量抓包 |
| `artifacts/raw_wireguard.pcap` | 原始 WireGuard 流量抓包 |

## 项目结构

```
safewg/
├── hidewg                        # CLI 入口 (Python)
├── hidewg.cmd                    # Windows CLI 入口
├── hidewg_app/
│   ├── __init__.py
│   ├── cli.py                    # 命令行解析
│   ├── config.py                 # 配置加载
│   ├── protocol.py               # 协议封装/解封装（核心）
│   ├── adapter.py                # WireGuard 适配代理
│   ├── analysis.py               # 特征提取与分类器
│   ├── verify.py                 # 统一验证套件
│   ├── state.py                  # 状态与日志
│   ├── transport.py              # TLS 连接封装 + 证书生成
│   ├── ws.py                     # WebSocket 帧传输 + nginx 反代支持
│   └── pcap.py                   # pcap 文件读取与解析
├── configs/
│   ├── lab.yaml                  # 本地验证配置
│   ├── client.yaml               # 客户端配置
│   ├── server.yaml               # 服务端配置
│   ├── nginx-hidewg.conf         # nginx 反代配置模板
│   ├── wg-client.conf.example    # WireGuard 客户端配置模板
│   └── wg-server.conf.example    # WireGuard 服务端配置模板
├── scripts/
│   ├── run_client.ps1            # 客户端启动脚本
│   ├── run_server.ps1            # 服务端启动脚本
│   ├── verify.ps1                # 验证脚本
│   ├── real_wg_test.ps1          # 真实 WG 测试
│   └── capture_raw_wg.ps1        # 原始 WG 抓包
├── evaluate.py                   # 真实流量评测
├── eval_dl.py                    # DL 分类器对抗评估
├── artifacts/                    # 验证输出
├── docs/
│   ├── 操作流程指南.md            # 完整部署与故障排查
│   └── 配置与验证指南.md
├── 实验报告.md
└── README.md
```

## 常见问题

部署过程中遇到问题请参考 [docs/操作流程指南.md](docs/操作流程指南.md) 的第十章，包含：

- 启动前自检清单
- 端口占用/Windows 保留范围冲突
- 服务端配置不一致
- 缺少模块/依赖
- 系统排查流程图

## 依赖

- Python 3.8+
- `cryptography` — ChaCha20Poly1305 AEAD 加密
- `numpy` — 深度学习评估（仅 `eval_dl.py` 需要）
- wireguard-tools — 仅真实部署需要
