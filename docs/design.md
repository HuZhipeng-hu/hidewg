# HideWG 设计文档

## 目标与边界

HideWG 位于 WireGuard 外侧，只处理 WireGuard UDP 报文的封装、隐藏、转发、恢复和观测。系统不修改 WireGuard 的握手、密钥协商、计数器、AEAD 或隧道语义。

## 模块映射

| 课程模块 | 本实现 |
| --- | --- |
| WireGuard 基线环境 | `configs/*.yaml` 给出真实 WireGuard 接入点；`verify` 生成 `raw_wireguard.pcap` 作为规则检测基线 |
| WireGuard 适配模块 | `hidewg_app/adapter.py` 的双 UDP socket 代理 |
| HideWG 协议封装 | `hidewg_app/protocol.py` 的 `HideWGCodec` |
| 隐藏策略模块 | `PaddingPolicy`、分片、外层 nonce 随机化、发送时序扰动 |
| 解封装与恢复 | `Reassembler` 支持乱序分片、重放丢弃、非法报文丢弃 |
| 状态与日志 | `RuntimeStats` 输出 JSON state 和 JSONL runtime log |
| 统一验证模块 | `hidewg_app/verify.py` 和 `hidewg verify` |

## 外层记录格式

外层 UDP payload 没有固定 magic，也不暴露 WireGuard `message_type`。记录格式如下：

```text
nonce[12] || encrypted_header[26] || encrypted_body[*] || tag[16]
```

`encrypted_header` 解密后包含：

```text
version
flags
session_id
sequence_number
message_id
fragment_index
fragment_count
payload_length
padding_length
```

`encrypted_body` 是原始 WireGuard payload 分片加随机填充。`tag` 是 HMAC-SHA256 截断标签，覆盖 nonce、加密头和加密体。

## 隐藏策略

1. 头部隐藏：WireGuard 明文 UDP payload 被放入加密体，外部看不到 `1/2/3/4 || 00 00 00`。
2. 长度填充：内层包长度填充到 `[96,128,192,256,384,512,768,1024,1280]` 等桶，并有概率上跳一个桶。
3. 分片重组：超过 `max_fragment_payload` 的内层包拆为多个外层记录，接收端按 `message_id` 和分片号重组。
4. 时序扰动：运行态可配置 `timing_jitter_ms`，对外层发送加入轻微随机延迟。
5. 重放与篡改处理：接收端记录 sequence，重复包丢弃；标签不匹配的包计入认证失败。

## 真实 WireGuard 接入方式

客户端侧：

```text
WireGuard peer endpoint -> 127.0.0.1:51830
HideWG inner_listen     -> 127.0.0.1:51830
HideWG outer peer       -> server_ip:55821
```

服务器侧：

```text
WireGuard peer endpoint -> 127.0.0.1:51831
HideWG inner_listen     -> 127.0.0.1:51831
HideWG outer peer       -> client_ip:55820
```

如果 WireGuard 实例监听端口固定，可在 `wireguard_host` 和 `wireguard_port` 指定解封装后转发目标。

## 验证设计

`hidewg verify` 自动完成：

1. 功能正确性测试：连通性形态报文、文件完整性、UDP 流、大包分片、异常包、状态导出。
2. 隐匿性测试：R1-R5 规则检测，以及基于包长、方向、时间、burst、启动阶段序列的最近质心分类器。
3. 效率测试：吞吐保持率、延迟增加、带宽膨胀率、CPU、内存、丢包场景完成率和并发稳定性。
4. 产物导出：JSON 报告、CSV 性能数据、JSONL 日志和 pcap 抓包。

## 安全说明

本项目外层封装的目的首先是协议特征隐藏和实验可验证性。标准库实现使用 SHAKE 派生流和 HMAC-SHA256 认证标签，便于无依赖运行课程验收；生产系统应替换为经过审计的 AEAD，例如 ChaCha20-Poly1305 或 AES-GCM。WireGuard 仍然是端到端安全边界。
