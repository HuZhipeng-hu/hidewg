#!/usr/bin/env python3
"""Analyze captured HideWG outer-layer traffic against WireGuard detection rules."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hidewg_app.analysis import FlowPacket, detect_wireguard_rules, extract_features


def read_pcap(path: str) -> tuple[int, list[dict]]:
    packets = []
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("Not a pcap file")
        little = magic == b"\xd4\xc3\xb2\xa1"
        endian = "<" if little else ">"
        f.read(16)  # version_major, version_minor, thiszone, sigfigs, snaplen
        link_type_bytes = f.read(4)
        link_type = struct.unpack(endian + "I", link_type_bytes)[0] & 0xFFFF
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, cap_len, orig_len = struct.unpack(endian + "IIII", hdr)
            data = f.read(cap_len)
            if len(data) < cap_len:
                break
            ts = ts_sec + ts_usec / 1_000_000
            packets.append({"ts": ts, "raw": data})
    return link_type, packets


def extract_udp_payloads(pcap_packets: list[dict], target_port: int = 55821, link_type: int = 1) -> list[FlowPacket]:
    flows = []
    for pkt in pcap_packets:
        raw = pkt["raw"]
        # Determine IP start based on link type
        if link_type == 1:  # Ethernet
            if len(raw) < 34:
                continue
            eth_type = struct.unpack("!H", raw[12:14])[0]
            if eth_type != 0x0800:
                continue
            ip_start = 14
        elif link_type == 113:  # Linux cooked capture (SLL)
            if len(raw) < 24:
                continue
            proto = struct.unpack("!H", raw[14:16])[0]
            if proto != 0x0800:
                continue
            ip_start = 16
        else:
            ip_start = 0  # raw IP

        if len(raw) < ip_start + 28:
            continue
        ihl = (raw[ip_start] & 0x0F) * 4
        proto = raw[ip_start + 9]
        if proto != 17:  # UDP
            continue
        udp_start = ip_start + ihl
        if len(raw) < udp_start + 8:
            continue
        src_port = struct.unpack("!H", raw[udp_start:udp_start + 2])[0]
        dst_port = struct.unpack("!H", raw[udp_start + 2:udp_start + 4])[0]
        udp_len = struct.unpack("!H", raw[udp_start + 4:udp_start + 6])[0]
        payload = raw[udp_start + 8: udp_start + udp_len]

        if dst_port == target_port:
            direction = 1  # client -> server (incoming)
        elif src_port == target_port:
            direction = -1  # server -> client (outgoing)
        else:
            continue

        flows.append(FlowPacket(ts=pkt["ts"], direction=direction, payload=payload))
    return flows


def main():
    pcap_path = ".hidewg/server_outer.pcap"
    if not Path(pcap_path).exists():
        print(f"ERROR: {pcap_path} not found")
        sys.exit(1)

    print("=== Reading pcap ===")
    link_type, raw_packets = read_pcap(pcap_path)
    print(f"Link type: {link_type}, Total pcap frames: {len(raw_packets)}")

    flow = extract_udp_payloads(raw_packets, target_port=55821, link_type=link_type)
    print(f"HideWG UDP packets: {len(flow)}")

    if not flow:
        print("No HideWG packets found, trying raw parse...")
        # Fallback: scan for UDP protocol bytes
        for pkt in raw_packets:
            raw = pkt["raw"]
            for offset in range(0, min(len(raw) - 28, 40)):
                if offset + 9 < len(raw) and raw[offset + 9] == 17:
                    ihl = (raw[offset] & 0x0F) * 4
                    udp_start = offset + ihl
                    if udp_start + 8 <= len(raw):
                        udp_len = struct.unpack("!H", raw[udp_start + 4:udp_start + 6])[0]
                        payload = raw[udp_start + 8: udp_start + udp_len]
                        if len(payload) > 20:
                            flow.append(FlowPacket(ts=pkt["ts"], direction=1, payload=payload))
                            break
        print(f"Fallback extracted: {len(flow)} packets")

    if not flow:
        print("ERROR: No packets extracted")
        sys.exit(1)

    # Normalize timestamps
    base_ts = flow[0].ts
    flow = [FlowPacket(ts=p.ts - base_ts, direction=p.direction, payload=p.payload) for p in flow]

    print(f"\n=== Packet size distribution ===")
    sizes = [len(p.payload) for p in flow]
    for s in sorted(set(sizes)):
        count = sizes.count(s)
        print(f"  {s:5d} bytes: {count:4d} packets")

    print(f"\n=== Direction breakdown ===")
    up = sum(1 for p in flow if p.direction == 1)
    down = sum(1 for p in flow if p.direction == -1)
    print(f"  Client→Server (incoming):  {up}")
    print(f"  Server→Client (outgoing):  {down}")

    # Rule detection on captured traffic
    print(f"\n=== WireGuard rule detection ===")
    rules = detect_wireguard_rules(flow)
    print(f"  Overall rule hit rate: {rules['overall_rule_hit_rate']:.4f}")
    for rule, rate in rules["per_rule"].items():
        print(f"  {rule}: {rate:.4f}")

    # Feature extraction
    print(f"\n=== Feature extraction ===")
    features = extract_features(flow)
    print(f"  Feature vector length: {len(features)}")
    print(f"  Avg packet length: {features[0]:.1f}")
    print(f"  Max packet length: {features[1]:.0f}")
    print(f"  Min packet length: {features[2]:.0f}")
    print(f"  Length variance: {features[3]:.1f}")
    print(f"  Total bytes: {features[4]:.0f}")
    print(f"  Up ratio: {features[5]:.3f}")
    print(f"  Down ratio: {features[6]:.3f}")
    print(f"  Avg interval: {features[9]:.4f}s")
    print(f"  Interval variance: {features[10]:.6f}")

    # Autocorrelation (lags 1-4)
    autocorr = features[14:18]
    print(f"  Length autocorrelation (lags 1-4): {[f'{v:.4f}' for v in autocorr]}")

    # Direction transitions
    trans = features[18:22]
    print(f"  Direction transitions (uu,ud,du,dd): {[f'{v:.4f}' for v in trans]}")

    # Window variance
    win_var = features[22:25]
    print(f"  Window variance (w=4,8,16): {[f'{v:.1f}' for v in win_var]}")

    # Assessment
    print(f"\n=== Assessment ===")
    hit_rate = rules["overall_rule_hit_rate"]
    if hit_rate < 0.1:
        print(f"  PASS: Rule hit rate {hit_rate:.4f} < 0.1 (WireGuard signatures effectively hidden)")
    elif hit_rate < 0.3:
        print(f"  WARN: Rule hit rate {hit_rate:.4f} (some WireGuard features detectable)")
    else:
        print(f"  FAIL: Rule hit rate {hit_rate:.4f} (WireGuard signatures clearly visible)")

    # Check length diversity
    unique_sizes = len(set(sizes))
    if unique_sizes >= 10:
        print(f"  PASS: {unique_sizes} distinct packet sizes (good padding diversity)")
    elif unique_sizes >= 5:
        print(f"  WARN: {unique_sizes} distinct packet sizes (moderate diversity)")
    else:
        print(f"  FAIL: Only {unique_sizes} distinct packet sizes (poor padding diversity)")

    # Check autocorrelation (should be near 0 for random-looking traffic)
    max_autocorr = max(abs(v) for v in autocorr)
    if max_autocorr < 0.15:
        print(f"  PASS: Max autocorrelation {max_autocorr:.4f} < 0.15 (no sequential patterns)")
    elif max_autocorr < 0.3:
        print(f"  WARN: Max autocorrelation {max_autocorr:.4f} (weak sequential patterns)")
    else:
        print(f"  FAIL: Max autocorrelation {max_autocorr:.4f} (clear sequential patterns)")


if __name__ == "__main__":
    main()
