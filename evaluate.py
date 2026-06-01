#!/usr/bin/env python3
"""
HideWG 真实流量评测工具
========================
功能：
  1. 通过 SSH 在服务端 tcpdump 抓包（外层 UDP 端口）
  2. 在客户端通过 WireGuard 隧道生成真实流量（ping / 大包 / 随机间隔）
  3. 下载 pcap，提取 UDP 载荷，与真实基线对比
  4. 输出：规则检测、统计分类器、DL 模拟特征、性能估计
  5. 生成 JSON 报告 + 终端可读摘要

用法：
  python evaluate.py                                    # 默认参数（抓包 + 分析）
  python evaluate.py --server root@1.95.65.51 --port 55821
  python evaluate.py --skip-capture --pcap .hidewg/server_outer.pcap
  python evaluate.py --skip-capture --pcap .hidewg/captures/hidewg_outer.pcap \
                     --raw-pcap .hidewg/captures/raw_wireguard.pcap
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── 项目模块 ──────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hidewg_app.analysis import (
    FlowPacket,
    detect_wireguard_rules,
    evaluate_classifier,
    extract_features,
)
from hidewg_app.pcap import extract_flow_from_pcap, windows


# ═══════════════════════════════════════════════════════════════════════════
#  1. 抓包与流量生成
# ═══════════════════════════════════════════════════════════════════════════

def ssh_run(host: str, cmd: str, timeout: int = 10) -> str:
    """执行远程命令并返回 stdout。"""
    r = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=5", host, cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.stdout.strip()


def start_server_capture(host: str, port: int, count: int, pcap_path: str) -> int:
    """在服务端启动 tcpdump，返回 PID。"""
    ssh_run(host, "killall tcpdump 2>/dev/null", timeout=5)
    time.sleep(0.5)
    pid_str = ssh_run(
        host,
        f"nohup tcpdump -i any udp port {port} -w {pcap_path} -c {count} "
        f">/dev/null 2>&1 & echo $!",
        timeout=8,
    )
    return int(pid_str) if pid_str.isdigit() else 0


def generate_traffic(target_ip: str, duration: int = 90) -> dict:
    """通过 WireGuard 隧道生成多种真实流量。"""
    stats = {"ping_small": 0, "ping_large": 0, "ping_burst": 0}
    end = time.time() + duration

    # 阶段 1：小包 ping
    n = min(100, int(duration * 1.5))
    try:
        subprocess.run(
            ["ping", "-n", str(n), "-w", "200", "-l", "32", target_ip],
            capture_output=True, timeout=min(n * 0.3 + 5, duration),
        )
    except subprocess.TimeoutExpired:
        pass
    stats["ping_small"] = n

    # 阶段 2：大包 ping
    remaining = end - time.time()
    if remaining > 5:
        n2 = min(80, int(remaining * 1.5))
        try:
            subprocess.run(
                ["ping", "-n", str(n2), "-w", "300", "-l", "1024", target_ip],
                capture_output=True, timeout=min(n2 * 0.4 + 5, remaining),
            )
        except subprocess.TimeoutExpired:
            pass
        stats["ping_large"] = n2

    # 阶段 3：突发小包 + 随机间隔
    remaining = end - time.time()
    if remaining > 3:
        sent = 0
        while time.time() < end:
            burst = random.randint(3, 10)
            for _ in range(burst):
                if time.time() >= end:
                    break
                size = random.choice([32, 64, 128, 256, 512])
                try:
                    subprocess.run(
                        ["ping", "-n", "1", "-w", "150", "-l", str(size), target_ip],
                        capture_output=True, timeout=2,
                    )
                except subprocess.TimeoutExpired:
                    pass
                sent += 1
            remaining = end - time.time()
            if remaining > 0.5:
                time.sleep(random.uniform(0.2, min(1.5, remaining)))
        stats["ping_burst"] = sent

    return stats


def download_pcap(host: str, remote_path: str, local_path: str) -> bool:
    r = subprocess.run(
        ["scp", f"{host}:{remote_path}", local_path],
        capture_output=True, timeout=30,
    )
    return r.returncode == 0


def stop_capture(host: str):
    ssh_run(host, "killall tcpdump 2>/dev/null", timeout=5)


# ═══════════════════════════════════════════════════════════════════════════
#  2. 窗口化特征提取（使用共享模块）
# ═══════════════════════════════════════════════════════════════════════════

def window_flow(flow: list[FlowPacket], size: int = 64, step: int = 32) -> list[list[FlowPacket]]:
    return windows(flow, size, step)


# ═══════════════════════════════════════════════════════════════════════════
#  3. 评测主逻辑
# ═══════════════════════════════════════════════════════════════════════════

def run_evaluation(
    pcap_path: str,
    port: int,
    output_dir: str,
    raw_wg_pcap: str = "",
    raw_wg_port: int = 51821,
    num_baseline: int = 25,
) -> dict:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # ── 读取 HideWG 真实抓包 ──
    hidewg = extract_flow_from_pcap(pcap_path, port)
    if len(hidewg) < 20:
        print(f"ERROR: 只提取到 {len(hidewg)} 个包，至少需要 20 个")
        sys.exit(1)
    n = len(hidewg)
    sizes = [len(p.payload) for p in hidewg]
    up = sum(1 for p in hidewg if p.direction == 1)

    # ── 读取真实原始 WireGuard 抓包（基线）──
    raw_wg = None
    if raw_wg_pcap and Path(raw_wg_pcap).exists():
        raw_wg = extract_flow_from_pcap(raw_wg_pcap, raw_wg_port)
        if raw_wg:
            print(f"  已加载真实 WireGuard 基线: {raw_wg_pcap} ({len(raw_wg)} 包)")

    # ── 打印捕获概览 ──
    print(f"\n{'=' * 64}")
    print(f"  HideWG 真实流量评测")
    print(f"{'=' * 64}")
    print(f"  抓包文件   : {pcap_path}")
    print(f"  总包数     : {n}")
    print(f"  上行/下行  : {up}/{n - up}  ({up / n:.1%} / {(n - up) / n:.1%})")
    print(f"  总字节     : {sum(sizes):,}")
    print(f"  包大小范围 : {min(sizes)}–{max(sizes)} B ({len(set(sizes))} 种)")
    print(f"  持续时间   : {hidewg[-1].ts:.1f} s")
    if raw_wg:
        print(f"  WG 基线    : {raw_wg_pcap} ({len(raw_wg)} 包)")
    else:
        print(f"  WG 基线    : 未提供 (--raw-pcap)")

    # ── 规则检测 ──
    print(f"\n{'─' * 64}")
    print(f"  [1] WireGuard 规则检测")
    print(f"{'─' * 64}")

    # 加载真实 HTTPS 流量作为对照基线
    normal_pcap = Path("artifacts/real_normal.pcap")
    if normal_pcap.exists():
        ctrl = _load_control_from_pcap(str(normal_pcap))
    else:
        ctrl = []

    rule_results = {}
    flows_to_check = []
    if raw_wg:
        flows_to_check.append(("原始 WireGuard (真实)", raw_wg))
    flows_to_check.append(("HideWG (真实)", hidewg))
    flows_to_check.append(("普通 UDP 对照", ctrl))

    for label, flow in flows_to_check:
        r = detect_wireguard_rules(flow)
        rule_results[label] = r
        print(f"  {label:<24s}  命中率={r['overall_rule_hit_rate']:.4f}  "
              f"R1={r['per_rule']['R1_message_type_first_byte']:.3f}  "
              f"R2={r['per_rule']['R2_reserved_zero_bytes']:.3f}  "
              f"R3={r['per_rule']['R3_typical_wireguard_lengths']:.3f}  "
              f"R4={r['per_rule']['R4_handshake_direction_timing']}  "
              f"R5={r['per_rule']['R5_fixed_keepalive_pattern']}")

    hwg_rate = rule_results["HideWG (真实)"]["overall_rule_hit_rate"]
    if raw_wg:
        raw_rate = rule_results["原始 WireGuard (真实)"]["overall_rule_hit_rate"]
        reduction = raw_rate - hwg_rate
        print(f"\n  → 签名命中率: {raw_rate:.4f} → {hwg_rate:.4f}  "
              f"(降幅 {reduction:.4f}, {(reduction / max(raw_rate, 1e-9)) * 100:.1f}%)")
    else:
        raw_rate = -1
        print(f"\n  → HideWG 命中率: {hwg_rate:.4f}  (无原始 WG 基线对比)")

    # ── 统计分类器 ──
    print(f"\n{'─' * 64}")
    print(f"  [2] 统计分类器 (nearest-centroid, 3 类)")
    print(f"{'─' * 64}")

    dataset: list[tuple[str, list[float]]] = []
    hwg_windows = window_flow(hidewg)

    for off in range(num_baseline):
        if raw_wg:
            # 从真实 pcap 子采样生成变体
            raw_sampled = _subsample_flow(raw_wg, 20260525 + off * 10, window_size=180)
            dataset.extend(("raw_wireguard", extract_features(w)) for w in window_flow(raw_sampled))
        dataset.extend(("hidewg", extract_features(w)) for w in hwg_windows)
        ctrl_s = ctrl  # 使用真实 HTTPS 流量作为对照
        dataset.extend(("control", extract_features(w)) for w in window_flow(ctrl_s))

    clf = evaluate_classifier(dataset, seed=20260525)
    print(f"  准确率       : {clf['accuracy']:.4f}")
    print(f"  Precision 宏 : {clf['precision_macro']:.4f}")
    print(f"  Recall 宏    : {clf['recall_macro']:.4f}")
    print(f"  F1 宏        : {clf['f1_macro']:.4f}")
    print(f"  AUC 宏       : {clf['auc_macro']:.4f}")

    labels = clf["labels"]
    cm = clf["confusion_matrix"]
    print(f"\n  混淆矩阵 (行=真实, 列=预测):")
    hdr = "  " + " " * 14 + "  ".join(f"{l:>12s}" for l in labels)
    print(hdr)
    for actual in labels:
        row = f"  {actual:>12s}  "
        for predicted in labels:
            row += f"{cm[actual][predicted]:>12d}  "
        print(row)

    print(f"\n  各类别指标:")
    for label in labels:
        m = clf["per_label"][label]
        print(f"    {label:14s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}")

    hwg_total = sum(cm["hidewg"].values()) if "hidewg" in cm else 1
    hwg_as_raw = cm.get("hidewg", {}).get("raw_wireguard", 0)
    leak_rate = hwg_as_raw / max(1, hwg_total)
    print(f"\n  → HideWG 泄露率 (被判为 raw_wireguard): {leak_rate:.1%}  "
          f"({'PASS' if leak_rate < 0.1 else 'FAIL'})")

    # ── DL 模拟特征 ──
    print(f"\n{'─' * 64}")
    print(f"  [3] 深度学习模拟特征 (真实捕获)")
    print(f"{'─' * 64}")

    feat = extract_features(hidewg)
    feat_names = [
        ("包长自相关 lag1-4", feat[14:18]),
        ("方向马尔科夫 uu,ud,du,dd", feat[18:22]),
        ("窗口方差 w=4,8,16", feat[22:25]),
        ("间隔自相关 lag1-3", feat[25:28]),
    ]
    for name, vals in feat_names:
        print(f"  {name:<24s}  {[round(v, 4) for v in vals]}")
    print(f"  {'突发长度方差':<24s}  {feat[28]:.4f}")

    max_ac = max(abs(v) for v in feat[14:18])
    print(f"\n  → 最大自相关: {max_ac:.4f}  "
          f"({'PASS (<0.15)' if max_ac < 0.15 else 'WARN (<0.30)' if max_ac < 0.30 else 'HIGH (≥0.30)'})")

    # ── 性能估计 ──
    print(f"\n{'─' * 64}")
    print(f"  [4] 性能估计 (基于真实流量)")
    print(f"{'─' * 64}")

    duration = max(1e-6, hidewg[-1].ts)
    intervals = [hidewg[i + 1].ts - hidewg[i].ts for i in range(n - 1)]
    avg_int = sum(intervals) / max(1, len(intervals))
    print(f"  持续时间       : {duration:.1f} s")
    print(f"  平均吞吐       : {sum(sizes) / duration:,.0f} B/s  ({sum(sizes) / duration * 8 / 1000:.1f} kbps)")
    print(f"  平均包速率     : {n / duration:.1f} pkt/s")
    print(f"  平均包间隔     : {avg_int * 1000:.1f} ms")
    print(f"  峰值内存       : (本地无代理运行，不适用)")

    # ── 综合评估 ──
    print(f"\n{'=' * 64}")
    print(f"  综合评估")
    print(f"{'=' * 64}")

    checks = [
        ("WireGuard 签名消除", hwg_rate < 0.05, f"命中率 {hwg_rate:.4f}"),
        ("分类器无法识别为 WG", leak_rate < 0.15, f"泄露率 {leak_rate:.1%}"),
        ("包大小多样性", len(set(sizes)) >= 5, f"{len(set(sizes))} 种"),
        ("双向流量均衡", 0.2 < up / n < 0.8, f"上行 {up / n:.1%}"),
    ]

    all_pass = True
    for name, passed, detail in checks:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  [{status}] {name:<24s}  {detail}")

    print(f"\n  总结: {'全部通过' if all_pass else '存在未通过项'}")
    print(f"{'=' * 64}")

    # ── 保存 JSON 报告 ──
    report = {
        "capture": {
            "source": pcap_path,
            "packets": n,
            "bytes": sum(sizes),
            "duration_s": round(duration, 2),
            "up_ratio": round(up / n, 4),
            "distinct_sizes": len(set(sizes)),
            "size_range": [min(sizes), max(sizes)],
        },
        "data_source": {
            "hidewg_pcap": pcap_path,
            "raw_wireguard_pcap": raw_wg_pcap if raw_wg else "not provided",
            "note": "All traffic from real pcap captures. Control baseline from artifacts/real_normal.pcap (real HTTPS).",
        },
        "rule_detection": {
            k: {
                "overall": v["overall_rule_hit_rate"],
                "per_rule": v["per_rule"],
            }
            for k, v in rule_results.items()
        },
        "classifier": {
            "accuracy": clf["accuracy"],
            "precision_macro": clf["precision_macro"],
            "recall_macro": clf["recall_macro"],
            "f1_macro": clf["f1_macro"],
            "auc_macro": clf["auc_macro"],
            "confusion_matrix": cm,
            "per_label": clf["per_label"],
            "hidewg_leak_rate": leak_rate,
        },
        "dl_features": {
            "autocorrelation_lag1_4": [round(v, 4) for v in feat[14:18]],
            "direction_markov": [round(v, 4) for v in feat[18:22]],
            "window_variance": [round(v, 2) for v in feat[22:25]],
            "interval_autocorrelation": [round(v, 4) for v in feat[25:28]],
            "burst_variance": round(feat[28], 4),
            "max_autocorrelation": round(max_ac, 4),
        },
        "performance": {
            "throughput_Bps": round(sum(sizes) / duration),
            "packet_rate": round(n / duration, 1),
            "avg_interval_ms": round(avg_int * 1000, 1),
        },
        "verdict": {name: passed for name, passed, _ in checks},
        "passed": all_pass,
    }

    report_path = output / "evaluation_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  报告已保存 → {report_path}")

    return report


def _load_control_from_pcap(pcap_path: str, server_port: int = 443) -> list[FlowPacket]:
    """从真实 HTTPS 抓包加载「正常流量」对照 — 替代合成数据."""
    from pcap_utils import read_pcap
    pkts = read_pcap(pcap_path)
    if not pkts:
        return []
    flow = []
    for p in pkts:
        if p["proto"] != "tcp":
            continue
        if p["dst_port"] == server_port:
            direction = 1
        elif p["src_port"] == server_port:
            direction = -1
        else:
            continue
        flow.append(FlowPacket(ts=p["ts"], direction=direction,
                               payload=b"\x00" * min(p["len"], 1500)))
    return flow


def _subsample_flow(flow: list[FlowPacket], seed: int, window_size: int = 180) -> list[FlowPacket]:
    """从真实流量中子采样，为分类器生成变体。"""
    rng = random.Random(seed)
    if len(flow) <= window_size:
        return list(flow)
    start = rng.randint(0, len(flow) - window_size)
    sub = flow[start:start + window_size]
    base_ts = sub[0].ts
    return [FlowPacket(ts=p.ts - base_ts, direction=p.direction, payload=p.payload) for p in sub]


def _randbytes(rng: random.Random, length: int) -> bytes:
    if hasattr(rng, "randbytes"):
        return rng.randbytes(length)
    return bytes(rng.randrange(0, 256) for _ in range(length))


# ═══════════════════════════════════════════════════════════════════════════
#  4. 入口
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="HideWG 真实流量评测工具")
    parser.add_argument("--server", default="root@1.95.65.51", help="SSH 登录地址")
    parser.add_argument("--port", type=int, default=55821, help="服务端 HideWG 外层端口")
    parser.add_argument("--target", default="10.7.0.1", help="WireGuard 隧道对端 IP")
    parser.add_argument("--duration", type=int, default=90, help="流量生成时长 (秒)")
    parser.add_argument("--packets", type=int, default=3000, help="最大抓包数")
    parser.add_argument("--output", default=".hidewg/evaluate", help="输出目录")
    parser.add_argument("--skip-capture", action="store_true", help="跳过抓包，直接分析已有 pcap")
    parser.add_argument("--pcap", default="", help="HideWG pcap 文件路径")
    parser.add_argument("--raw-pcap", default="", help="真实原始 WireGuard pcap 文件路径（基线）")
    parser.add_argument("--raw-port", type=int, default=51821, help="原始 WireGuard pcap 对应端口")
    args = parser.parse_args()

    if args.skip_capture:
        pcap_path = args.pcap or ".hidewg/real_capture.pcap"
        if not Path(pcap_path).exists():
            print(f"ERROR: {pcap_path} 不存在"); sys.exit(1)
    else:
        pcap_path = os.path.join(tempfile.gettempdir(), "hidewg_eval.pcap")
        remote_pcap = "/tmp/hidewg_eval.pcap"

        print(f"[1/4] 启动服务端抓包 (最多 {args.packets} 包) ...")
        pid = start_server_capture(args.server, args.port, args.packets, remote_pcap)
        if pid:
            print(f"       tcpdump PID = {pid}")
        else:
            print("       WARNING: 无法确认 PID，继续...")

        print(f"[2/4] 生成真实流量 ({args.duration} 秒) ...")
        traffic = generate_traffic(args.target, args.duration)
        print(f"       ping_small={traffic['ping_small']}  "
              f"ping_large={traffic['ping_large']}  "
              f"ping_burst={traffic['ping_burst']}")

        print(f"[3/4] 停止抓包并下载 ...")
        time.sleep(2)
        stop_capture(args.server)
        time.sleep(1)

        if not download_pcap(args.server, remote_pcap, pcap_path):
            print("ERROR: pcap 下载失败")
            sys.exit(1)

        fsize = Path(pcap_path).stat().st_size
        print(f"       已下载 {fsize:,} bytes")

    print(f"[4/4] 分析中 ...")
    run_evaluation(pcap_path, args.port, args.output,
                   raw_wg_pcap=args.raw_pcap, raw_wg_port=args.raw_port)


if __name__ == "__main__":
    main()
