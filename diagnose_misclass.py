#!/usr/bin/env python3
"""Diagnose why some HideWG windows are misclassified as raw_wireguard.

Uses real pcap captures for both HideWG and raw WireGuard baselines.

Usage:
  python diagnose_misclass.py
  python diagnose_misclass.py --hidewg-pcap .hidewg/real_capture.pcap \
                              --raw-pcap .hidewg/captures/raw_wireguard.pcap \
                              --port 55821 --raw-port 51821
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hidewg_app.analysis import (
    FlowPacket, extract_features,
    train_nearest_centroid, evaluate_classifier,
    _fit_scaler, _scale, _predict,
)
from hidewg_app.pcap import extract_flow_from_pcap, windows


def _subsample_flow(flow: list[FlowPacket], seed: int, window_size: int = 180) -> list[FlowPacket]:
    """Sub-sample a real flow to create variations for classifier training."""
    rng = random.Random(seed)
    if len(flow) <= window_size:
        return list(flow)
    start = rng.randint(0, len(flow) - window_size)
    sub = flow[start:start + window_size]
    base_ts = sub[0].ts
    return [FlowPacket(ts=p.ts - base_ts, direction=p.direction, payload=p.payload) for p in sub]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Diagnose HideWG misclassification")
    parser.add_argument("--hidewg-pcap", default=".hidewg/real_capture.pcap",
                        help="HideWG outer-layer pcap file")
    parser.add_argument("--raw-pcap", default="",
                        help="Real raw WireGuard pcap file (baseline)")
    parser.add_argument("--port", type=int, default=55821, help="HideWG outer port")
    parser.add_argument("--raw-port", type=int, default=51821, help="Raw WireGuard port")
    args = parser.parse_args()

    # Load real HideWG traffic
    hidewg_pcap = args.hidewg_pcap
    if not Path(hidewg_pcap).exists():
        print(f"ERROR: {hidewg_pcap} not found")
        sys.exit(1)

    hidewg = extract_flow_from_pcap(hidewg_pcap, args.port)
    if not hidewg:
        print("ERROR: no HideWG packets extracted")
        sys.exit(1)

    hwg_windows = windows(hidewg)

    # Load real raw WireGuard traffic
    raw_windows = []
    raw_flow = None
    if args.raw_pcap and Path(args.raw_pcap).exists():
        raw_flow = extract_flow_from_pcap(args.raw_pcap, args.raw_port)
        if raw_flow:
            # Generate multiple windows by sub-sampling the real capture
            for i in range(20):
                sampled = _subsample_flow(raw_flow, 20260525 + i * 10, window_size=180)
                raw_windows.extend(windows(sampled))
            print(f"Loaded real WireGuard baseline: {args.raw_pcap} ({len(raw_flow)} packets, {len(raw_windows)} windows)")
        else:
            print(f"WARNING: {args.raw_pcap} contains no packets on port {args.raw_port}")
    else:
        print("No raw WireGuard pcap provided. Use --raw-pcap to supply a real baseline.")
        print("Run scripts/capture_raw_wg.ps1 to capture real WireGuard traffic.")
        sys.exit(1)

    # Compute avg features per class
    hwg_feats = [extract_features(w) for w in hwg_windows]
    raw_feats = [extract_features(w) for w in raw_windows]

    feat_names = [
        "avg_len", "max_len", "min_len", "var_len", "total_bytes",
        "up_ratio", "down_ratio", "up_byte_ratio", "down_byte_ratio",
        "avg_int", "var_int", "p95_int", "burst_avg", "burst_max",
        "hist_64", "hist_128", "hist_256", "hist_512", "hist_768",
        "hist_1024", "hist_1500", "hist_3000",
        "autocorr_lag1", "autocorr_lag2", "autocorr_lag3", "autocorr_lag4",
        "markov_uu", "markov_ud", "markov_du", "markov_dd",
        "winvar_4", "winvar_8", "winvar_16",
        "int_autocorr_1", "int_autocorr_2", "int_autocorr_3",
        "burst_var",
    ]

    print("=" * 70)
    print(f"  Feature comparison: HideWG (real) vs Raw WireGuard (real)")
    print(f"  Data: {hidewg_pcap} vs {args.raw_pcap}")
    print("=" * 70)
    print(f"  {'Feature':<20s}  {'HideWG':>10s}  {'RawWG':>10s}  {'Delta':>10s}")
    print("-" * 70)

    for i, name in enumerate(feat_names):
        if i >= len(hwg_feats[0]) or i >= len(raw_feats[0]):
            continue
        hwg_avg = sum(f[i] for f in hwg_feats) / len(hwg_feats)
        raw_avg = sum(f[i] for f in raw_feats) / len(raw_feats)
        delta = hwg_avg - raw_avg
        marker = " <<<<" if abs(delta) > max(abs(hwg_avg), abs(raw_avg)) * 0.5 and max(abs(hwg_avg), abs(raw_avg)) > 0.01 else ""
        print(f"  {name:<20s}  {hwg_avg:>10.4f}  {raw_avg:>10.4f}  {delta:>+10.4f}{marker}")

    # Find the misclassified windows
    dataset = [("hidewg", f) for f in hwg_feats] + [("raw_wireguard", f) for f in raw_feats]
    report = evaluate_classifier(dataset, seed=20260525)

    print(f"\n{'=' * 70}")
    print(f"  2-class classifier (hidewg vs raw_wireguard, real pcap data)")
    print(f"{'=' * 70}")
    print(f"  Accuracy: {report['accuracy']:.4f}")
    for label in report["labels"]:
        m = report["per_label"][label]
        print(f"  {label:14s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}")

    cm = report["confusion_matrix"]
    print(f"\n  Confusion:")
    print(f"                hidewg  raw_wg")
    print(f"  hidewg        {cm.get('hidewg',{}).get('hidewg',0):>6d}  {cm.get('hidewg',{}).get('raw_wireguard',0):>6d}")
    print(f"  raw_wg        {cm.get('raw_wireguard',{}).get('hidewg',0):>6d}  {cm.get('raw_wireguard',{}).get('raw_wireguard',0):>6d}")

    # Which specific real windows are misclassified?
    scaler = _fit_scaler([f for _, f in dataset])
    model = train_nearest_centroid([(l, _scale(f, scaler)) for l, f in dataset])

    print(f"\n  Misclassified HideWG windows:")
    miscount = 0
    for idx, feat in enumerate(hwg_feats):
        scaled = _scale(feat, scaler)
        pred, _ = _predict(model, scaled)
        if pred != "hidewg":
            miscount += 1
            if miscount <= 5:
                start_pkt = idx * 32
                print(f"    window {idx} (pkt {start_pkt}-{start_pkt+63}): avg_len={feat[0]:.0f} "
                      f"autocorr={[round(v,3) for v in feat[22:26]]} "
                      f"markov={[round(v,3) for v in feat[26:30]]}")
    print(f"  Total misclassified: {miscount}/{len(hwg_feats)} ({miscount/max(1,len(hwg_feats)):.1%})")


if __name__ == "__main__":
    main()
