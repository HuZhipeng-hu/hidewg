"""基于真实抓包数据的 DL 评估 — 替代纯模拟的 eval_dl.py.

数据源:
  - artifacts/real_hidewg.pcap  : HideWG 外层流量 (TLS/WS over port 443)
  - artifacts/real_wg_inner.pcap: 原始 WireGuard 流量 (loopback UDP)

两种流量在同一隧道会话中采集，保证了时间、负载的可比性。
"""
from __future__ import annotations

import struct
import sys
import json
from pathlib import Path

import numpy as np

# ──────────────────────────────────────────────
# 纯 Python pcap 解析器
# ──────────────────────────────────────────────

def read_pcap(path: str) -> list[dict]:
    """读取 pcap 文件，返回包列表 [{ts, len, src_port, dst_port, proto, raw_len}]."""
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
            # nanosecond pcap
            magic_ns = struct.unpack("<I", hdr[:4])[0]
            if magic_ns in (0xA1B23C4D, 0x4D3CB2A1):
                endian = "<" if magic_ns == 0xA1B23C4D else ">"
            else:
                raise ValueError(f"not a pcap file: {path}")
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

            if eth_proto == 0x0800 and len(pkt_data) >= ip_start + 20:  # IPv4
                ip = pkt_data[ip_start:]
                ihl = (ip[0] & 0x0F) * 4
                ip_proto = ip[9]
                payload_start = ip_start + ihl
                if ip_proto == 6 and len(pkt_data) >= payload_start + 20:  # TCP
                    tcp = pkt_data[payload_start:]
                    src_port = struct.unpack("!H", tcp[0:2])[0]
                    dst_port = struct.unpack("!H", tcp[2:4])[0]
                    proto = "tcp"
                elif ip_proto == 17 and len(pkt_data) >= payload_start + 8:  # UDP
                    udp = pkt_data[payload_start:]
                    src_port = struct.unpack("!H", udp[0:2])[0]
                    dst_port = struct.unpack("!H", udp[2:4])[0]
                    proto = "udp"

            pkts.append({
                "ts": ts,
                "len": orig_len,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
            })
    return pkts


# ──────────────────────────────────────────────
# 流量序列提取
# ──────────────────────────────────────────────

def extract_flow(pkts: list[dict], direction: str = "client_to_server",
                 server_port: int = 443) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """从 pcap 包列表提取单向流量序列 (lengths, directions, iats)."""
    lengths = []
    directions = []
    timestamps = []

    for p in pkts:
        if p["proto"] == "tcp":
            if direction == "client_to_server":
                if p["dst_port"] == server_port:
                    lengths.append(p["len"])
                    directions.append(1)
                    timestamps.append(p["ts"])
            else:
                if p["src_port"] == server_port:
                    lengths.append(p["len"])
                    directions.append(-1)
                    timestamps.append(p["ts"])

    if not lengths:
        return np.array([]), np.array([]), np.array([])

    lengths = np.array(lengths, dtype=np.float64)
    directions = np.array(directions, dtype=np.float64)
    ts = np.array(timestamps, dtype=np.float64)
    iats = np.diff(ts, prepend=ts[0])
    iats[0] = 0.0
    return lengths, directions, iats


def extract_wg_flow(pkts: list[dict], wg_port: int = 51831) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """从内层抓包提取 WireGuard 流量序列 (server→WG)."""
    lengths = []
    directions = []
    timestamps = []

    for p in pkts:
        if p["proto"] != "udp":
            continue
        if p["src_port"] == wg_port:
            lengths.append(p["len"])
            directions.append(-1)
            timestamps.append(p["ts"])
        elif p["dst_port"] == wg_port:
            lengths.append(p["len"])
            directions.append(1)
            timestamps.append(p["ts"])

    if not lengths:
        return np.array([]), np.array([]), np.array([])

    lengths = np.array(lengths, dtype=np.float64)
    directions = np.array(directions, dtype=np.float64)
    ts = np.array(timestamps, dtype=np.float64)
    iats = np.diff(ts, prepend=ts[0])
    iats[0] = 0.0
    return lengths, directions, iats


# ──────────────────────────────────────────────
# 真实正常 HTTPS 流量（从 pcap 加载）
# ──────────────────────────────────────────────

def load_normal_traffic(pcap_path: str, server_port: int = 443
                        ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """从真实 HTTPS 抓包加载正常流量."""
    from pcap_utils import read_pcap, extract_tcp_flow
    pkts = read_pcap(pcap_path)
    l1, d1, i1 = extract_tcp_flow(pkts, server_port, "client_to_server")
    l2, d2, i2 = extract_tcp_flow(pkts, server_port, "server_to_client")
    if len(l1) > 0 and len(l2) > 0:
        return np.concatenate([l1, l2]), np.concatenate([d1, d2]), np.concatenate([i1, i2])
    elif len(l1) > 0:
        return l1, d1, i1
    elif len(l2) > 0:
        return l2, d2, i2
    return np.array([]), np.array([]), np.array([])


# ──────────────────────────────────────────────
# 滑动窗口特征提取 (与 eval_dl.py 兼容)
# ──────────────────────────────────────────────

def make_windows(lengths: np.ndarray, directions: np.ndarray, iats: np.ndarray,
                 win: int = 200, stride: int = 50) -> np.ndarray:
    """从流量序列切出滑动窗口, 输出 (N, 3, win)."""
    seq_len = len(lengths)
    if seq_len < win:
        # pad
        pad_len = win - seq_len
        lengths = np.pad(lengths, (0, pad_len))
        directions = np.pad(directions, (0, pad_len))
        iats = np.pad(iats, (0, pad_len))
        seq_len = win

    windows = []
    for start in range(0, seq_len - win + 1, stride):
        sl = lengths[start:start+win]
        sd = directions[start:start+win]
        si = iats[start:start+win]
        windows.append(np.stack([sl, sd, si], axis=0))

    if not windows:
        windows.append(np.stack([
            lengths[:win], directions[:win], iats[:win]
        ], axis=0))

    return np.array(windows, dtype=np.float64)


def stat_features(lengths, directions, iats):
    """提取统计特征向量."""
    if len(lengths) == 0:
        return np.zeros(36)
    feats = []
    for arr in [lengths, directions, iats]:
        feats.extend([np.mean(arr), np.std(arr), np.min(arr), np.max(arr),
                      np.median(arr), np.percentile(arr, 25), np.percentile(arr, 75),
                      float(np.std(arr) / (np.mean(arr) + 1e-9))])
    # lag-1 autocorrelation of lengths
    if len(lengths) > 1:
        m = np.mean(lengths)
        s = np.std(lengths)
        if s > 0:
            ac = np.mean((lengths[1:] - m) * (lengths[:-1] - m)) / (s * s)
        else:
            ac = 0.0
    else:
        ac = 0.0
    feats.append(ac)
    # unique length ratio
    feats.append(len(set(int(x) for x in lengths)) / max(1, len(lengths)))
    # direction change ratio
    dchg = np.sum(np.diff(directions) != 0) / max(1, len(directions) - 1)
    feats.append(dchg)
    # burst count (consecutive same-direction)
    if len(directions) > 1:
        dd = np.diff(directions)
        bursts = np.sum(dd != 0) + 1
        feats.append(bursts / len(directions))
    else:
        feats.append(0.0)
    feats.append(float(np.mean(np.abs(np.diff(lengths)))))  # mean abs diff
    feats.append(float(np.std(np.diff(lengths))) if len(lengths) > 1 else 0.0)
    feats.append(float(np.mean(iats[iats > 0])) if np.any(iats > 0) else 0.0)
    return np.array(feats[:36], dtype=np.float64)


# ──────────────────────────────────────────────
# 分类器 (纯 NumPy, 与 eval_dl.py 相同)
# ──────────────────────────────────────────────

class NearestCentroidStd:
    def __init__(self):
        self.centroids = {}
        self.std_global = None

    def fit(self, X, y):
        self.std_global = X.std(axis=0) + 1e-9
        Xs = X / self.std_global
        for c in np.unique(y):
            self.centroids[c] = Xs[y == c].mean(axis=0)

    def predict(self, X):
        Xs = X / self.std_global
        preds = []
        for x in Xs:
            best, bd = None, 1e18
            for c, cent in self.centroids.items():
                d = np.sum((x - cent)**2)
                if d < bd:
                    bd, best = d, c
            preds.append(best)
        return np.array(preds)


class SimpleRandomForest:
    def __init__(self, n_trees=50, max_depth=8, n_features=10, seed=42):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.n_features = min(n_features, 36)
        self.trees = []
        self.rng = np.random.RandomState(seed)

    def fit(self, X, y):
        self.classes = np.unique(y)
        for _ in range(self.n_trees):
            idx = self.rng.randint(0, len(X), len(X))
            feats = self.rng.choice(X.shape[1], self.n_features, replace=False)
            tree = self._build(X[idx][:, feats], y[idx], 0)
            self.trees.append((feats, tree))

    def _build(self, X, y, depth):
        if depth >= self.max_depth or len(np.unique(y)) == 1:
            counts = {c: np.sum(y == c) for c in self.classes}
            return {"leaf": max(counts, key=counts.get)}
        fi = self.rng.randint(0, X.shape[1])
        vals = X[:, fi]
        thresh = self.rng.choice(vals)
        left = vals <= thresh
        right = ~left
        if left.sum() == 0 or right.sum() == 0:
            counts = {c: np.sum(y == c) for c in self.classes}
            return {"leaf": max(counts, key=counts.get)}
        return {"fi": fi, "th": thresh,
                "left": self._build(X[left], y[left], depth+1),
                "right": self._build(X[right], y[right], depth+1)}

    def predict(self, X):
        preds = []
        for x in X:
            votes = {c: 0 for c in self.classes}
            for feats, tree in self.trees:
                xf = x[feats]
                node = tree
                while "leaf" not in node:
                    if xf[node["fi"]] <= node["th"]:
                        node = node["left"]
                    else:
                        node = node["right"]
                votes[node["leaf"]] += 1
            preds.append(max(votes, key=votes.get))
        return np.array(preds)


class MLP256:
    def __init__(self, n_in, n_hid=256, n_out=4, lr=0.005, seed=42):
        rng = np.random.RandomState(seed)
        self.W1 = rng.randn(n_in, n_hid) * np.sqrt(2.0 / n_in)
        self.b1 = np.zeros(n_hid)
        self.W2 = rng.randn(n_hid, n_out) * np.sqrt(2.0 / n_hid)
        self.b2 = np.zeros(n_out)
        self.lr = lr

    def fit(self, X, y, epochs=100):
        for ep in range(epochs):
            z1 = X @ self.W1 + self.b1
            a1 = np.maximum(0, z1)
            z2 = a1 @ self.W2 + self.b2
            exp_z = np.exp(z2 - z2.max(axis=1, keepdims=True))
            probs = exp_z / exp_z.sum(axis=1, keepdims=True)
            loss = -np.mean(np.log(probs[np.arange(len(y)), y] + 1e-12))
            if (ep + 1) % 30 == 0:
                pred = np.argmax(probs, axis=1)
                acc = np.mean(pred == y)
                print(f"  epoch {ep+1:3d}  loss={loss:.4f}  acc={acc:.3f}")
            d2 = probs.copy()
            d2[np.arange(len(y)), y] -= 1
            d2 /= len(y)
            dW2 = a1.T @ d2
            db2 = d2.sum(axis=0)
            da1 = d2 @ self.W2.T
            dz1 = da1 * (z1 > 0)
            dW1 = X.T @ dz1
            db1 = dz1.sum(axis=0)
            self.W1 -= self.lr * dW1
            self.b1 -= self.lr * db1
            self.W2 -= self.lr * dW2
            self.b2 -= self.lr * db2

    def predict(self, X):
        z1 = X @ self.W1 + self.b1
        a1 = np.maximum(0, z1)
        z2 = a1 @ self.W2 + self.b2
        return np.argmax(z2, axis=1)


class Conv1D:
    """简易 1D-CNN: Conv-ReLU-Conv-ReLU-FC."""

    def __init__(self, n_channels, seq_len, n_out=4, lr=0.001, seed=42):
        rng = np.random.RandomState(seed)
        self.lr = lr
        ks1, ks2 = 5, 3
        f1, f2 = 32, 64
        self.Wc1 = rng.randn(f1, n_channels, ks1) * np.sqrt(2.0 / (n_channels * ks1))
        self.bc1 = np.zeros(f1)
        self.Wc2 = rng.randn(f2, f1, ks2) * np.sqrt(2.0 / (f1 * ks2))
        self.bc2 = np.zeros(f2)
        o2 = seq_len - ks1 - ks2 + 2
        flat = f2 * o2
        self.Wf = rng.randn(flat, n_out) * np.sqrt(2.0 / flat)
        self.bf = np.zeros(n_out)

    def _conv1d(self, X, W, b):
        """X: (N, C, L), W: (F, C, K), b: (F,) -> (N, F, L-K+1)."""
        N, C, L = X.shape
        F, _, K = W.shape
        oL = L - K + 1
        cols = np.lib.stride_tricks.sliding_window_view(X, K, axis=2)
        cols = cols.transpose(0, 2, 1, 3).reshape(N, oL, C * K)
        W_flat = W.reshape(F, C * K)
        out = cols @ W_flat.T + b
        return out.transpose(0, 2, 1)

    def _relu(self, X):
        return np.maximum(0, X)

    def fit(self, X, y, epochs=100):
        N = X.shape[0]
        for ep in range(epochs):
            c1 = self._relu(self._conv1d(X, self.Wc1, self.bc1))
            c2 = self._relu(self._conv1d(c1, self.Wc2, self.bc2))
            flat = c2.reshape(N, -1)
            logits = flat @ self.Wf + self.bf
            exp_z = np.exp(logits - logits.max(axis=1, keepdims=True))
            probs = exp_z / exp_z.sum(axis=1, keepdims=True)
            loss = -np.mean(np.log(probs[np.arange(N), y] + 1e-12))
            if (ep + 1) % 10 == 0:
                acc = np.mean(np.argmax(probs, axis=1) == y)
                print(f"  epoch {ep+1:3d}  loss={loss:.4f}  acc={acc:.3f}")

            d_logits = probs.copy()
            d_logits[np.arange(N), y] -= 1
            d_logits /= N
            dWf = flat.T @ d_logits
            dbf = d_logits.sum(axis=0)
            self.Wf -= self.lr * dWf
            self.bf -= self.lr * dbf

    def predict(self, X):
        N = X.shape[0]
        c1 = self._relu(self._conv1d(X, self.Wc1, self.bc1))
        c2 = self._relu(self._conv1d(c1, self.Wc2, self.bc2))
        flat = c2.reshape(N, -1)
        logits = flat @ self.Wf + self.bf
        return np.argmax(logits, axis=1)


# ──────────────────────────────────────────────
# 评估流程
# ──────────────────────────────────────────────

SEED = 42
SEQ_LEN = 50
STRIDE = 10

LABEL_MAP = {
    "HideWG (real)": 0,
    "WireGuard (real)": 1,
    "Normal-HTTPS (real)": 2,
}


def main():
    rng = np.random.RandomState(SEED)
    artifacts = Path("artifacts")

    print("=" * 60)
    print("  真实抓包 DL 评估")
    print("=" * 60)

    # ── 加载数据 ──
    print("\n[1/6] 加载 pcap 文件...")

    hidewg_pcap = artifacts / "real_hidewg.pcap"
    wg_pcap = artifacts / "real_wg_inner.pcap"

    if not hidewg_pcap.exists():
        print(f"  ERROR: {hidewg_pcap} 不存在")
        sys.exit(1)
    if not wg_pcap.exists():
        print(f"  ERROR: {wg_pcap} 不存在")
        sys.exit(1)

    hwg_pkts = read_pcap(str(hidewg_pcap))
    wg_pkts = read_pcap(str(wg_pcap))
    print(f"  HideWG pcap: {len(hwg_pkts)} packets")
    print(f"  WireGuard pcap: {len(wg_pkts)} packets")

    # ── 提取双向流量 ──
    print("\n[2/6] 提取流量序列...")

    # HideWG: client→server + server→client (port 443)
    hwg_l1, hwg_d1, hwg_i1 = extract_flow(hwg_pkts, "client_to_server", 443)
    hwg_l2, hwg_d2, hwg_i2 = extract_flow(hwg_pkts, "server_to_client", 443)
    hwg_l = np.concatenate([hwg_l1, hwg_l2]) if len(hwg_l1) > 0 else hwg_l2
    hwg_d = np.concatenate([hwg_d1, hwg_d2]) if len(hwg_d1) > 0 else hwg_d2
    hwg_i = np.concatenate([hwg_i1, hwg_i2]) if len(hwg_i1) > 0 else hwg_i2
    print(f"  HideWG: {len(hwg_l)} packets (→{len(hwg_l1)}, ←{len(hwg_l2)})")

    # WireGuard: loopback UDP (51831 ↔ 51820)
    wg_l, wg_d, wg_i = extract_wg_flow(wg_pkts, 51831)
    print(f"  WireGuard: {len(wg_l)} packets")

    # Normal HTTPS (真实 pcap)
    norm_path = artifacts / "real_normal.pcap"
    if norm_path.exists():
        norm_l, norm_d, norm_i = load_normal_traffic(str(norm_path))
        print(f"  Normal-HTTPS (real): {len(norm_l)} packets")
    else:
        print(f"  WARNING: {norm_path} 不存在，跳过 Normal-HTTPS 类")
        norm_l, norm_d, norm_i = np.array([]), np.array([]), np.array([])

    # ── 生成滑动窗口样本 ──
    print("\n[3/6] 生成窗口样本...")

    X_list, y_list = [], []

    # HideWG windows
    hwg_wins = make_windows(hwg_l, hwg_d, hwg_i, SEQ_LEN, STRIDE)
    n_hwg = min(len(hwg_wins), 200)
    idx = rng.choice(len(hwg_wins), n_hwg, replace=False)
    X_list.append(hwg_wins[idx])
    y_list.append(np.full(n_hwg, 0, dtype=np.int64))

    # WireGuard windows
    wg_wins = make_windows(wg_l, wg_d, wg_i, SEQ_LEN, STRIDE)
    n_wg = min(len(wg_wins), 200)
    if len(wg_wins) < n_wg:
        idx_wg = rng.choice(len(wg_wins), n_wg, replace=True)
    else:
        idx_wg = rng.choice(len(wg_wins), n_wg, replace=False)
    X_list.append(wg_wins[idx_wg])
    y_list.append(np.full(n_wg, 1, dtype=np.int64))

    # Normal windows
    norm_wins = make_windows(norm_l, norm_d, norm_i, SEQ_LEN, STRIDE)
    n_norm = min(len(norm_wins), 200)
    idx_n = rng.choice(len(norm_wins), n_norm, replace=False)
    X_list.append(norm_wins[idx_n])
    y_list.append(np.full(n_norm, 2, dtype=np.int64))

    X_all = np.concatenate(X_list)
    y_all = np.concatenate(y_list)

    class_names = ["HideWG (real)", "WireGuard (real)", "Normal-HTTPS (real)"]
    label_names = {0: "HideWG (real)", 1: "WireGuard (real)", 2: "Normal-TLS (syn)"}
    print(f"  总样本: {len(X_all)}, 形状: {X_all.shape}")
    for c in range(3):
        print(f"    {class_names[c]}: {np.sum(y_all == c)} samples")

    # ── 统计特征 ──
    print("\n[3b/6] 提取统计特征...")
    X_stat = []
    for i in range(len(X_all)):
        X_stat.append(stat_features(X_all[i, 0], X_all[i, 1], X_all[i, 2]))
    X_stat = np.array(X_stat, dtype=np.float64)

    # ── 标准化 ──
    mu = X_all.mean(axis=(0, 2), keepdims=True)
    std = X_all.std(axis=(0, 2), keepdims=True) + 1e-9
    X_norm = (X_all - mu) / std

    mu_s = X_stat.mean(axis=0)
    std_s = X_stat.std(axis=0) + 1e-9
    X_stat_norm = (X_stat - mu_s) / std_s

    # ── 划分训练/测试 ──
    idx_all = np.arange(len(y_all))
    rng.shuffle(idx_all)
    split = int(0.7 * len(idx_all))
    tr_idx, te_idx = idx_all[:split], idx_all[split:]
    X_tr, X_te = X_norm[tr_idx], X_norm[te_idx]
    Xs_tr, Xs_te = X_stat_norm[tr_idx], X_stat_norm[te_idx]
    y_tr, y_te = y_all[tr_idx], y_all[te_idx]
    print(f"  训练: {len(tr_idx)}, 测试: {len(te_idx)}")

    n_out = len(class_names)

    results = {}

    # ── NC ──
    print("\n[4/6] Nearest Centroid (标准化)")
    nc = NearestCentroidStd()
    nc.fit(Xs_tr, y_tr)
    nc_pred = nc.predict(Xs_te)
    nc_acc = np.mean(nc_pred == y_te)
    results["NearestCentroid"] = nc_acc
    print(f"  准确率: {nc_acc:.3f}")
    _print_confusion(y_te, nc_pred, n_out, class_names)

    # ── RF ──
    print("\n[4/6] Random Forest (50 trees, 统计特征)")
    rf = SimpleRandomForest(n_trees=50, max_depth=8, n_features=10, seed=SEED)
    rf.fit(Xs_tr, y_tr)
    rf_pred = rf.predict(Xs_te)
    rf_acc = np.mean(rf_pred == y_te)
    results["RandomForest-50"] = rf_acc
    print(f"  准确率: {rf_acc:.3f}")
    _print_confusion(y_te, rf_pred, n_out, class_names)

    # ── MLP ──
    print("\n[4/6] MLP (256隐藏单元)")
    mlp = MLP256(X_stat.shape[1], 256, n_out, lr=0.005, seed=SEED)
    mlp.fit(Xs_tr, y_tr, epochs=100)
    mlp_pred = mlp.predict(Xs_te)
    mlp_acc = np.mean(mlp_pred == y_te)
    results["MLP-256"] = mlp_acc
    print(f"  准确率: {mlp_acc:.3f}")
    _print_confusion(y_te, mlp_pred, n_out, class_names)

    # ── CNN ──
    print("\n[4/6] 1D-CNN (32+64 filters)")
    n_channels = X_tr.shape[1]
    cnn = Conv1D(n_channels, SEQ_LEN, n_out, lr=0.001, seed=SEED)
    cnn.fit(X_tr, y_tr, epochs=100)
    cnn_pred = cnn.predict(X_te)
    cnn_acc = np.mean(cnn_pred == y_te)
    results["CNN-1D"] = cnn_acc
    print(f"  准确率: {cnn_acc:.3f}")
    _print_confusion(y_te, cnn_pred, n_out, class_names)

    # ── 汇总 ──
    print("\n" + "=" * 60)
    print("  结果汇总 (真实抓包)")
    print("=" * 60)
    for name, acc in sorted(results.items(), key=lambda x: -x[1]):
        bar = "#" * int(acc * 40) + "-" * (40 - int(acc * 40))
        print(f"  {name:<18s} |{bar}| {acc:.1%}")

    # HideWG 召回率
    print("\n  HideWG 召回率:")
    for name, preds in [("NC", nc_pred), ("RF", rf_pred), ("MLP", mlp_pred), ("CNN", cnn_pred)]:
        mask = y_te == 0
        if mask.sum() > 0:
            recall = np.mean(preds[mask] == 0)
            print(f"    {name}: {recall:.1%} ({int(np.sum(preds[mask] == 0))}/{int(mask.sum())})")

    # 保存
    out = {
        "data_source": "real_capture",
        "hidewg_packets": int(len(hwg_l)),
        "wireguard_packets": int(len(wg_l)),
        "normal_packets": int(len(norm_l)),
        "window_size": SEQ_LEN,
        "train_samples": int(len(tr_idx)),
        "test_samples": int(len(te_idx)),
        "results": {k: round(v, 4) for k, v in results.items()},
        "class_names": class_names,
    }
    out_path = artifacts / "real_dl_eval.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n结果已保存: {out_path}")

    # 流量特征
    print("\n" + "=" * 60)
    print("  流量特征对比")
    print("=" * 60)
    for name, l, d, i in [("HideWG", hwg_l, hwg_d, hwg_i),
                            ("WireGuard", wg_l, wg_d, wg_i),
                            ("Normal-TLS", norm_l, norm_d, norm_i)]:
        ul = len(set(int(x) for x in l))
        ac = np.corrcoef(l[1:], l[:-1])[0, 1] if len(l) > 2 else 0
        print(f"  {name}: {len(l)} pkts, {ul} unique sizes, "
              f"mean={l.mean():.0f}B, std={l.std():.0f}B, "
              f"lag1_autocorr={ac:.3f}")


def _print_confusion(y_true, y_pred, n_classes, class_names):
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1
    print("  混淆矩阵:")
    header = "         " + "  ".join(f"{c[:6]:>6s}" for c in class_names)
    print(header)
    for i in range(n_classes):
        row = f"  {class_names[i][:8]:<8s}" + "  ".join(f"{cm[i, j]:6d}" for j in range(n_classes))
        print(row)


if __name__ == "__main__":
    main()
