#!/usr/bin/env python3
"""Real-capture evaluation: analyze server-side HideWG pcap against real WireGuard baselines."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hidewg_app.analysis import (
    FlowPacket, detect_wireguard_rules, evaluate_classifier,
    extract_features,
)
from hidewg_app.pcap import extract_flow_from_pcap, windows


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
    """Sub-sample a real flow to create variations for classifier training."""
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


# ── main ─────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="HideWG Real-Capture Evaluation")
    parser.add_argument("--hidewg-pcap", default=".hidewg/real_capture.pcap",
                        help="HideWG outer-layer pcap file")
    parser.add_argument("--raw-pcap", default="",
                        help="Real raw WireGuard pcap file (baseline)")
    parser.add_argument("--port", type=int, default=55821, help="HideWG outer port")
    parser.add_argument("--raw-port", type=int, default=51821, help="Raw WireGuard port")
    args = parser.parse_args()

    pcap_path = args.hidewg_pcap
    if not Path(pcap_path).exists():
        print(f"ERROR: {pcap_path} not found")
        sys.exit(1)

    print("=" * 60)
    print("  HideWG Real-Capture Evaluation")
    print("=" * 60)

    # 1 ─ read real HideWG capture
    hidewg_flow = extract_flow_from_pcap(pcap_path, args.port)
    if not hidewg_flow:
        print("ERROR: no HideWG packets extracted")
        sys.exit(1)

    n = len(hidewg_flow)
    up = sum(1 for p in hidewg_flow if p.direction == 1)
    dn = n - up
    sizes = [len(p.payload) for p in hidewg_flow]

    print(f"\n[1] Capture overview")
    print(f"    Packets : {n}")
    print(f"    Up/Down : {up}/{dn}  ({up/n:.1%}/{dn/n:.1%})")
    print(f"    Bytes   : {sum(sizes):,}")
    print(f"    Sizes   : {len(set(sizes))} distinct  {min(sizes)}–{max(sizes)} B")
    print(f"    Duration: {hidewg_flow[-1].ts:.1f} s")

    # 2 ─ load real raw WireGuard baseline
    raw_flow = None
    if args.raw_pcap and Path(args.raw_pcap).exists():
        raw_flow = extract_flow_from_pcap(args.raw_pcap, args.raw_port)
        if raw_flow:
            print(f"\n[2] Real WireGuard baseline loaded: {args.raw_pcap} ({len(raw_flow)} packets)")
        else:
            print(f"\n[2] WARNING: {args.raw_pcap} contains no packets on port {args.raw_port}")
    else:
        print(f"\n[2] No raw WireGuard pcap provided. Use --raw-pcap to supply a real baseline.")
        print(f"    Run scripts/capture_raw_wg.ps1 to capture real WireGuard traffic.")

    # 3 ─ rule detection
    print(f"\n[3] WireGuard rule detection")
    flows_to_check = []
    if raw_flow:
        flows_to_check.append(("raw_wireguard_real", raw_flow))
    flows_to_check.append(("hidewg_real", hidewg_flow))

    for label, flow in flows_to_check:
        r = detect_wireguard_rules(flow)
        print(f"    {label:22s}  overall={r['overall_rule_hit_rate']:.4f}  "
              f"R1={r['per_rule']['R1_message_type_first_byte']:.3f}  "
              f"R2={r['per_rule']['R2_reserved_zero_bytes']:.3f}  "
              f"R3={r['per_rule']['R3_typical_wireguard_lengths']:.3f}  "
              f"R4={r['per_rule']['R4_handshake_direction_timing']}  "
              f"R5={r['per_rule']['R5_fixed_keepalive_pattern']}")

    # 4 ─ feature extraction + classifier
    print(f"\n[4] Statistical classifier (nearest-centroid, 70/30 split)")
    dataset: list[tuple[str, list[float]]] = []
    base_seed = 20260525
    # 加载真实 HTTPS 流量作为对照
    normal_pcap = Path("artifacts/real_normal.pcap")
    ctrl = _load_control_from_pcap(str(normal_pcap)) if normal_pcap.exists() else []
    for seed_off in range(20):
        if raw_flow:
            raw_w = _subsample_flow(raw_flow, base_seed + seed_off * 10, window_size=180)
            dataset.extend(("raw_wireguard", extract_features(w)) for w in windows(raw_w))
        dataset.extend(("hidewg", extract_features(w)) for w in windows(hidewg_flow))
        ctrl_w = ctrl  # 使用真实 HTTPS 流量
        dataset.extend(("control", extract_features(w)) for w in windows(ctrl_w))

    report = evaluate_classifier(dataset, seed=20260525)
    print(f"    Accuracy       : {report['accuracy']:.4f}")
    print(f"    Precision macro: {report['precision_macro']:.4f}")
    print(f"    Recall macro   : {report['recall_macro']:.4f}")
    print(f"    F1 macro       : {report['f1_macro']:.4f}")
    print(f"    AUC macro      : {report['auc_macro']:.4f}")

    print(f"\n    Confusion matrix (rows=actual, cols=predicted):")
    labels = report["labels"]
    header = "              " + "  ".join(f"{l:>12s}" for l in labels)
    print(header)
    for actual in labels:
        row = f"    {actual:>10s}  "
        for predicted in labels:
            row += f"{report['confusion_matrix'][actual][predicted]:>12d}  "
        print(row)

    print(f"\n    Per-label:")
    for label in labels:
        m = report["per_label"][label]
        print(f"      {label:14s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}")

    # 5 ─ DL-simulating features
    print(f"\n[5] Deep-learning-simulating features (real capture)")
    feat = extract_features(hidewg_flow)
    print(f"    Packet-length autocorrelation (lag 1-4): {[round(v, 4) for v in feat[14:18]]}")
    print(f"    Direction Markov (uu,ud,du,dd)          : {[round(v, 4) for v in feat[18:22]]}")
    print(f"    Window variance  (w=4,8,16)             : {[round(v, 2) for v in feat[22:25]]}")
    print(f"    Interval autocorr (lag 1-3)             : {[round(v, 4) for v in feat[25:28]]}")
    print(f"    Burst variance                          : {feat[28]:.2f}")

    # 6 ─ performance estimate (from real packet sizes)
    print(f"\n[6] Real-traffic performance estimate")
    inner_bytes = sum(sizes)
    duration = max(1e-6, hidewg_flow[-1].ts)
    print(f"    Duration          : {duration:.1f} s")
    print(f"    Avg throughput    : {inner_bytes / duration:,.0f} B/s  ({inner_bytes / duration * 8 / 1000:.1f} kbps)")
    print(f"    Avg packet rate   : {n / duration:.1f} pkt/s")
    intervals = [hidewg_flow[i + 1].ts - hidewg_flow[i].ts for i in range(n - 1)]
    avg_int = sum(intervals) / len(intervals)
    print(f"    Avg inter-packet  : {avg_int * 1000:.1f} ms")
    print(f"    Padding overhead  : {sum(1 for s in sizes if s > 200) / n:.1%} packets padded beyond 200 B")

    # 7 ─ summary
    hwg_rate = detect_wireguard_rules(hidewg_flow)["overall_rule_hit_rate"]
    print(f"\n{'=' * 60}")
    print(f"  Summary")
    print(f"{'=' * 60}")
    if raw_flow:
        raw_rate = detect_wireguard_rules(raw_flow)["overall_rule_hit_rate"]
        print(f"  WireGuard rule hit rate : {raw_rate:.4f} (raw) → {hwg_rate:.4f} (HideWG)")
        print(f"  Rule reduction          : {raw_rate - hwg_rate:.4f}  ({(raw_rate - hwg_rate) / max(raw_rate, 1e-9) * 100:.1f}%)")
    else:
        print(f"  HideWG rule hit rate    : {hwg_rate:.4f}")
        print(f"  (No raw WG baseline — use --raw-pcap for comparison)")
    print(f"  Classifier can hide WG  : {'YES' if report['confusion_matrix'].get('hidewg', {}).get('raw_wireguard', 0) == 0 else 'NO'}")
    print(f"  Classifier accuracy     : {report['accuracy']:.1%}  (3-class)")
    print(f"  AUC                     : {report['auc_macro']:.4f}")

    # save
    out = Path(".hidewg/verify/real_eval_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "data_source": {
            "hidewg_pcap": pcap_path,
            "raw_wireguard_pcap": args.raw_pcap or "not provided",
            "note": "All baselines from real pcap captures. Control from artifacts/real_normal.pcap (real HTTPS).",
        },
        "capture_packets": n,
        "rule_detection": {
            **({"raw_wireguard_real": detect_wireguard_rules(raw_flow)} if raw_flow else {}),
            "hidewg_real": detect_wireguard_rules(hidewg_flow),
        },
        "classifier": report,
        "dl_features": {
            "autocorrelation_lag1_4": [round(v, 4) for v in feat[14:18]],
            "direction_markov": [round(v, 4) for v in feat[18:22]],
            "window_variance": [round(v, 2) for v in feat[22:25]],
        },
        "performance": {
            "duration_s": round(duration, 2),
            "avg_throughput_bps": round(inner_bytes / duration * 8),
            "avg_packet_rate": round(n / duration, 1),
            "avg_interval_ms": round(avg_int * 1000, 1),
        },
    }, indent=2, ensure_ascii=False))
    print(f"\n  Report saved → {out}")


if __name__ == "__main__":
    main()
