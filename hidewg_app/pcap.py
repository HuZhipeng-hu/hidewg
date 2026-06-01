"""Shared pcap parsing utilities for reading real captured traffic."""
from __future__ import annotations

import struct
from pathlib import Path

from .analysis import FlowPacket


def read_pcap(path: str | Path) -> tuple[int, list[dict]]:
    """Read a pcap file and return (link_type, packets).

    Each packet dict has keys: 'ts' (float seconds) and 'raw' (bytes).
    Supports both little-endian and big-endian pcap formats.
    """
    path = Path(path)
    with path.open("rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError(f"{path} is not a valid pcap file")
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        f.read(16)  # version_major, version_minor, thiszone, sigfigs, snaplen
        link_type = struct.unpack(endian + "I", f.read(4))[0] & 0xFFFF
        packets = []
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, cap_len, _orig_len = struct.unpack(endian + "IIII", hdr)
            data = f.read(cap_len)
            if len(data) < cap_len:
                break
            packets.append({"ts": ts_sec + ts_usec / 1_000_000, "raw": data})
    return link_type, packets


def extract_udp_payloads(
    pcap_packets: list[dict],
    target_port: int,
    link_type: int,
) -> list[FlowPacket]:
    """Extract UDP payloads from pcap packets matching a target port.

    Packets where dst_port == target_port get direction=1 (inbound to target).
    Packets where src_port == target_port get direction=-1 (outbound from target).
    """
    flows = []
    for pkt in pcap_packets:
        raw = pkt["raw"]
        # Determine IP header start based on link-layer type
        if link_type == 113:  # Linux cooked capture (SLL)
            if len(raw) < 24:
                continue
            proto = struct.unpack("!H", raw[14:16])[0]
            if proto != 0x0800:
                continue
            ip_start = 16
        elif link_type == 1:  # Ethernet
            if len(raw) < 34:
                continue
            eth_type = struct.unpack("!H", raw[12:14])[0]
            if eth_type != 0x0800:
                continue
            ip_start = 14
        else:  # Raw IP
            ip_start = 0

        if len(raw) < ip_start + 28:
            continue
        ihl = (raw[ip_start] & 0x0F) * 4
        if raw[ip_start + 9] != 17:  # Not UDP
            continue
        udp_start = ip_start + ihl
        if len(raw) < udp_start + 8:
            continue
        src_port = struct.unpack("!H", raw[udp_start:udp_start + 2])[0]
        dst_port = struct.unpack("!H", raw[udp_start + 2:udp_start + 4])[0]
        udp_len = struct.unpack("!H", raw[udp_start + 4:udp_start + 6])[0]
        payload = raw[udp_start + 8:udp_start + udp_len]

        if dst_port == target_port:
            direction = 1
        elif src_port == target_port:
            direction = -1
        else:
            continue

        flows.append(FlowPacket(ts=pkt["ts"], direction=direction, payload=payload))
    return flows


def extract_flow_from_pcap(
    pcap_path: str | Path,
    target_port: int,
) -> list[FlowPacket]:
    """Convenience: read a pcap file and return a normalized flow (ts starting at 0)."""
    link_type, packets = read_pcap(pcap_path)
    flow = extract_udp_payloads(packets, target_port, link_type)
    if not flow:
        return []
    base_ts = flow[0].ts
    return [FlowPacket(ts=p.ts - base_ts, direction=p.direction, payload=p.payload) for p in flow]


def windows(flow: list[FlowPacket], size: int = 64, step: int = 32) -> list[list[FlowPacket]]:
    """Sliding window over a flow for feature extraction."""
    ws = []
    for start in range(0, max(1, len(flow) - size + 1), step):
        w = flow[start:start + size]
        if len(w) >= 16:
            base = w[0].ts
            ws.append([FlowPacket(ts=p.ts - base, direction=p.direction, payload=p.payload) for p in w])
    return ws or [flow]
