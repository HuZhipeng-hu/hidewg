# HideWG 答辩提纲

## 1. 问题背景

- WireGuard 安全、高效，但 UDP payload 前 4 字节、握手长度、方向时序和 keepalive 模式容易形成协议指纹。
- HideWG 的目标是不改 WireGuard，只在外侧增加可验证封装。

## 2. 系统架构

```text
WireGuard UDP -> WG Adapter -> HideWG Encode/Policy -> UDP Network
UDP Network   -> HideWG Decode/Reassemble -> WG Adapter -> WireGuard UDP
```

## 3. 核心设计

- 外层记录：随机 nonce、加密头、加密体、认证标签。
- 隐藏策略：头部隐藏、长度桶填充、分片重组、时序扰动、重放丢弃。
- 状态观测：内外层包计数、填充字节、分片数、认证失败、重放丢弃、吞吐和延迟估计。

## 4. 验证方法

- 功能测试：ping 形态报文、文件 SHA256、UDP 流、大包乱序分片、异常包。
- 隐匿性：R1-R5 规则命中率；最近质心分类器输出 Accuracy、Precision、Recall、F1、AUC、Confusion Matrix。
- 效率：吞吐保持率、延迟增加、带宽膨胀、CPU、内存、丢包完成率。

## 5. 演示命令

```bash
./hidewg verify --config configs/lab.yaml --output artifacts/
./hidewg status --output state.json
```

## 6. 结果解读

- 对比 `raw_wireguard.pcap` 与 `capture.pcap` 的规则命中率。
- 查看 `stealth_report.json` 的分类器混淆矩阵。
- 查看 `performance_report.csv` 的带宽膨胀与吞吐保持率。

## 7. 局限与改进

- 当前本地验证使用可复现模拟流量，真实评测应接入两端 WireGuard namespace/VM。
- 外层加密建议替换为正式 AEAD。
- 可进一步加入 cover traffic、拥塞自适应长度桶和更接近普通应用的时序模型。
