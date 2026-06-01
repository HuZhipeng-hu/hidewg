"""纯 Python pcap 解析 + 流量提取工具模块.

所有评估脚本共用，消除重复代码和虚拟数据生成。
"""
from __future__ import annotations

import struct
from pathlib import Path

import numpy as np


# ──────────────────────────────────────────────
# pcap 解析
# ──────────────────────────────────────────────

def read_pcap(path: str | Path) -> list[dict]:
    """读取 pcap 文件，返回包列表 [{ts, len, src_port, dst_port, proto, src_ip, dst_ip}]."""
    pkts = []
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return pkts
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            magic_ns = struct.unpack("<I", hdr[:4])[0]
            endian = "<" if magic_ns == 0xA1B23C4D else ">"
        link_type = struct.unpack(f"{endian}I", hdr[20:24])[0]

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            ts = ts_sec + ts_usec / 1e6
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            src_port = dst_port = 0
            src_ip = dst_ip = ""
            proto = "other"

            if link_type == 1:  # EN10MB (Ethernet)
                if len(pkt_data) < 14:
                    continue
                eth_proto = struct.unpack("!H", pkt_data[12:14])[0]
                ip_start = 14
            elif link_type == 113:  # LINUX_SLL
                if len(pkt_data) < 16:
                    continue
                eth_proto = struct.unpack("!H", pkt_data[14:16])[0]
                ip_start = 16
            else:
                continue

            if eth_proto == 0x0800 and len(pkt_data) >= ip_start + 20:
                ip = pkt_data[ip_start:]
                ihl = (ip[0] & 0x0F) * 4
                ip_proto = ip[9]
                src_ip = f"{ip[12]}.{ip[13]}.{ip[14]}.{ip[15]}"
                dst_ip = f"{ip[16]}.{ip[17]}.{ip[18]}.{ip[19]}"
                payload_start = ip_start + ihl
                if ip_proto == 6 and len(pkt_data) >= payload_start + 20:
                    tcp = pkt_data[payload_start:]
                    src_port = struct.unpack("!H", tcp[0:2])[0]
                    dst_port = struct.unpack("!H", tcp[2:4])[0]
                    proto = "tcp"
                elif ip_proto == 17 and len(pkt_data) >= payload_start + 8:
                    udp = pkt_data[payload_start:]
                    src_port = struct.unpack("!H", udp[0:2])[0]
                    dst_port = struct.unpack("!H", udp[2:4])[0]
                    proto = "udp"

            pkts.append({
                "ts": ts, "len": orig_len,
                "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "src_ip": src_ip, "dst_ip": dst_ip,
            })
    return pkts


# ──────────────────────────────────────────────
# 流量序列提取
# ──────────────────────────────────────────────

def extract_tcp_flow(pkts: list[dict], server_port: int = 443,
                     direction: str = "client_to_server") -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """从 pcap 包列表提取单向 TCP 流量序列."""
    lengths, directions, timestamps = [], [], []
    for p in pkts:
        if p["proto"] != "tcp":
            continue
        if direction == "client_to_server" and p["dst_port"] == server_port:
            lengths.append(p["len"]); directions.append(1); timestamps.append(p["ts"])
        elif direction == "server_to_client" and p["src_port"] == server_port:
            lengths.append(p["len"]); directions.append(-1); timestamps.append(p["ts"])
        elif direction == "both":
            if p["dst_port"] == server_port:
                lengths.append(p["len"]); directions.append(1); timestamps.append(p["ts"])
            elif p["src_port"] == server_port:
                lengths.append(p["len"]); directions.append(-1); timestamps.append(p["ts"])
    return _to_arrays(lengths, directions, timestamps)


def extract_udp_flow(pkts: list[dict], port_a: int, port_b: int = 0
                     ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """从 pcap 包列表提取 UDP 流量（双向）."""
    lengths, directions, timestamps = [], [], []
    for p in pkts:
        if p["proto"] != "udp":
            continue
        if p["src_port"] == port_a:
            lengths.append(p["len"]); directions.append(1); timestamps.append(p["ts"])
        elif p["dst_port"] == port_a:
            lengths.append(p["len"]); directions.append(-1); timestamps.append(p["ts"])
        elif port_b and p["src_port"] == port_b:
            lengths.append(p["len"]); directions.append(-1); timestamps.append(p["ts"])
        elif port_b and p["dst_port"] == port_b:
            lengths.append(p["len"]); directions.append(1); timestamps.append(p["ts"])
    return _to_arrays(lengths, directions, timestamps)


def extract_wg_flow(pkts: list[dict], wg_port: int = 51831
                    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """从内层抓包提取 WireGuard 流量."""
    return extract_udp_flow(pkts, wg_port)


def _to_arrays(lengths, directions, timestamps) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if not lengths:
        return np.array([]), np.array([]), np.array([])
    lengths = np.array(lengths, dtype=np.float64)
    directions = np.array(directions, dtype=np.float64)
    ts = np.array(timestamps, dtype=np.float64)
    iats = np.diff(ts, prepend=ts[0])
    iats[0] = 0.0
    return lengths, directions, iats


# ──────────────────────────────────────────────
# 滑动窗口 + 统计特征
# ──────────────────────────────────────────────

def make_windows(lengths: np.ndarray, directions: np.ndarray, iats: np.ndarray,
                 win: int = 50, stride: int = 10) -> np.ndarray:
    """从流量序列切出滑动窗口, 输出 (N, 3, win)."""
    seq_len = len(lengths)
    if seq_len < win:
        pad = win - seq_len
        lengths = np.pad(lengths, (0, pad))
        directions = np.pad(directions, (0, pad))
        iats = np.pad(iats, (0, pad))
        seq_len = win

    windows = []
    for start in range(0, seq_len - win + 1, stride):
        windows.append(np.stack([
            lengths[start:start+win],
            directions[start:start+win],
            iats[start:start+win],
        ], axis=0))
    return np.array(windows, dtype=np.float64) if windows else np.zeros((0, 3, win))


def stat_features(lengths, directions, iats) -> np.ndarray:
    """提取 36 维统计特征向量."""
    if len(lengths) == 0:
        return np.zeros(36)
    feats = []
    for arr in [lengths, directions, iats]:
        feats.extend([np.mean(arr), np.std(arr), np.min(arr), np.max(arr),
                      np.median(arr), np.percentile(arr, 25), np.percentile(arr, 75),
                      float(np.std(arr) / (np.mean(arr) + 1e-9))])
    if len(lengths) > 1:
        m, s = np.mean(lengths), np.std(lengths)
        ac = np.mean((lengths[1:] - m) * (lengths[:-1] - m)) / (s * s) if s > 0 else 0.0
    else:
        ac = 0.0
    feats.append(ac)
    feats.append(len(set(int(x) for x in lengths)) / max(1, len(lengths)))
    dchg = np.sum(np.diff(directions) != 0) / max(1, len(directions) - 1)
    feats.append(dchg)
    bursts = np.sum(np.diff(directions) != 0) + 1 if len(directions) > 1 else 1
    feats.append(bursts / len(directions))
    feats.append(float(np.mean(np.abs(np.diff(lengths)))))
    feats.append(float(np.std(np.diff(lengths))) if len(lengths) > 1 else 0.0)
    feats.append(float(np.mean(iats[iats > 0])) if np.any(iats > 0) else 0.0)
    return np.array(feats[:36], dtype=np.float64)
