"""深度学习评估：CNN vs MLP vs RF vs NC — 全部基于真实抓包数据.

数据源（均为真实流量，无合成）:
  - artifacts/real_hidewg.pcap   : HideWG 外层 UDP 流量
  - artifacts/real_wg_inner.pcap : 原始 WireGuard 流量 (loopback)
  - artifacts/real_normal.pcap   : 正常 HTTPS 流量 (curl/browser)
"""
from __future__ import annotations

import json
import time as _time
from pathlib import Path

import numpy as np

from pcap_utils import (
    read_pcap, extract_tcp_flow, extract_wg_flow,
    make_windows, stat_features,
)


# ──────────────────────────────────────────────
# 分类器（纯 NumPy）
# ──────────────────────────────────────────────

class NearestCentroidStd:
    def __init__(self):
        self.centroids, self.std_global = {}, None

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
        self.n_trees, self.max_depth = n_trees, max_depth
        self.n_features = min(n_features, 36)
        self.rng = np.random.RandomState(seed)
        self.trees = []

    def fit(self, X, y):
        self.classes = np.unique(y)
        for _ in range(self.n_trees):
            idx = self.rng.randint(0, len(X), len(X))
            feats = self.rng.choice(X.shape[1], self.n_features, replace=False)
            self.trees.append((feats, self._build(X[idx][:, feats], y[idx], 0)))

    def _build(self, X, y, depth):
        if depth >= self.max_depth or len(np.unique(y)) == 1:
            counts = {c: np.sum(y == c) for c in self.classes}
            return {"leaf": max(counts, key=counts.get)}
        fi = self.rng.randint(0, X.shape[1])
        thresh = self.rng.choice(X[:, fi])
        left = X[:, fi] <= thresh
        if left.sum() == 0 or (~left).sum() == 0:
            counts = {c: np.sum(y == c) for c in self.classes}
            return {"leaf": max(counts, key=counts.get)}
        return {"fi": fi, "th": thresh,
                "left": self._build(X[left], y[left], depth+1),
                "right": self._build(X[~left], y[~left], depth+1)}

    def predict(self, X):
        preds = []
        for x in X:
            votes = {c: 0 for c in self.classes}
            for feats, tree in self.trees:
                xf, node = x[feats], tree
                while "leaf" not in node:
                    node = node["left"] if xf[node["fi"]] <= node["th"] else node["right"]
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
            if (ep + 1) % 25 == 0:
                print(f"  epoch {ep+1:3d}  loss={loss:.4f}  acc={np.mean(np.argmax(probs, axis=1) == y):.3f}")
            d2 = probs.copy(); d2[np.arange(len(y)), y] -= 1; d2 /= len(y)
            self.W2 -= self.lr * a1.T @ d2
            self.b2 -= self.lr * d2.sum(axis=0)
            dz1 = (d2 @ self.W2.T) * (z1 > 0)
            self.W1 -= self.lr * X.T @ dz1
            self.b1 -= self.lr * dz1.sum(axis=0)

    def predict(self, X):
        a1 = np.maximum(0, X @ self.W1 + self.b1)
        return np.argmax(a1 @ self.W2 + self.b2, axis=1)


class Conv1D:
    def __init__(self, n_channels, seq_len, n_out=4, lr=0.001, seed=42):
        rng = np.random.RandomState(seed)
        self.lr = lr
        f1, f2, k1, k2 = 32, 64, 5, 3
        self.Wc1 = rng.randn(f1, n_channels, k1) * np.sqrt(2.0 / (n_channels * k1))
        self.bc1 = np.zeros(f1)
        self.Wc2 = rng.randn(f2, f1, k2) * np.sqrt(2.0 / (f1 * k2))
        self.bc2 = np.zeros(f2)
        o2 = seq_len - k1 - k2 + 2
        flat = f2 * o2
        self.Wf = rng.randn(flat, n_out) * np.sqrt(2.0 / flat)
        self.bf = np.zeros(n_out)

    def _conv1d(self, X, W, b):
        N, C, L = X.shape
        F, _, K = W.shape
        oL = L - K + 1
        cols = np.lib.stride_tricks.sliding_window_view(X, K, axis=2)
        cols = cols.transpose(0, 2, 1, 3).reshape(N, oL, C * K)
        return (cols @ W.reshape(F, C * K).T + b).transpose(0, 2, 1)

    def fit(self, X, y, epochs=100):
        N = X.shape[0]
        for ep in range(epochs):
            c1 = np.maximum(0, self._conv1d(X, self.Wc1, self.bc1))
            c2 = np.maximum(0, self._conv1d(c1, self.Wc2, self.bc2))
            flat = c2.reshape(N, -1)
            logits = flat @ self.Wf + self.bf
            exp_z = np.exp(logits - logits.max(axis=1, keepdims=True))
            probs = exp_z / exp_z.sum(axis=1, keepdims=True)
            loss = -np.mean(np.log(probs[np.arange(N), y] + 1e-12))
            if (ep + 1) % 10 == 0:
                print(f"  epoch {ep+1:3d}  loss={loss:.4f}  acc={np.mean(np.argmax(probs, axis=1) == y):.3f}")
            d = probs.copy(); d[np.arange(N), y] -= 1; d /= N
            self.Wf -= self.lr * flat.T @ d
            self.bf -= self.lr * d.sum(axis=0)

    def predict(self, X):
        N = X.shape[0]
        c1 = np.maximum(0, self._conv1d(X, self.Wc1, self.bc1))
        c2 = np.maximum(0, self._conv1d(c1, self.Wc2, self.bc2))
        return np.argmax(c2.reshape(N, -1) @ self.Wf + self.bf, axis=1)


# ──────────────────────────────────────────────
# 评估
# ──────────────────────────────────────────────

def _print_confusion(y_true, y_pred, class_names):
    n = len(class_names)
    cm = np.zeros((n, n), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1
    print("  混淆矩阵:")
    hdr = "         " + "  ".join(f"{c[:6]:>6s}" for c in class_names)
    print(hdr)
    for i in range(n):
        print(f"  {class_names[i][:8]:<8s}" + "  ".join(f"{cm[i,j]:6d}" for j in range(n)))


def main():
    SEED = 42
    SEQ_LEN = 50
    STRIDE = 10
    rng = np.random.RandomState(SEED)
    artifacts = Path("artifacts")

    print("=" * 60)
    print("  深度学习评估 — 全部基于真实抓包数据")
    print("=" * 60)

    # ── 加载 3 份真实 pcap ──
    print("\n[1/6] 加载真实 pcap 文件...")
    hwg_path = artifacts / "real_hidewg.pcap"
    wg_path = artifacts / "real_wg_inner.pcap"
    norm_path = artifacts / "real_normal.pcap"

    for p in [hwg_path, wg_path, norm_path]:
        if not p.exists():
            print(f"  ERROR: {p} 不存在")
            return

    hwg_pkts = read_pcap(hwg_path)
    wg_pkts = read_pcap(wg_path)
    norm_pkts = read_pcap(norm_path)
    print(f"  real_hidewg.pcap:   {len(hwg_pkts)} pkts")
    print(f"  real_wg_inner.pcap: {len(wg_pkts)} pkts")
    print(f"  real_normal.pcap:   {len(norm_pkts)} pkts")

    # ── 提取流量序列 ──
    print("\n[2/6] 提取流量序列...")

    # HideWG: WS 模式 (TCP 443/8443)，取 TCP 双向
    # 也支持旧的 UDP 模式 (55820/55821)
    ws_ports = [443, 8443, 55821, 55820]
    hwg_l, hwg_d, hwg_i = np.array([]), np.array([]), np.array([])
    for port in ws_ports:
        l1, d1, i1 = extract_tcp_flow(hwg_pkts, port, "client_to_server")
        l2, d2, i2 = extract_tcp_flow(hwg_pkts, port, "server_to_client")
        if len(l1) > 0 or len(l2) > 0:
            hwg_l = np.concatenate([l1, l2]) if len(l1) > 0 else l2
            hwg_d = np.concatenate([d1, d2]) if len(d1) > 0 else d2
            hwg_i = np.concatenate([i1, i2]) if len(i1) > 0 else i2
            print(f"  HideWG (TCP port {port}): {len(hwg_l)} pkts")
            break
    if len(hwg_l) == 0:
        # 尝试 UDP 提取
        udp_ports = set()
        for p in hwg_pkts:
            if p["proto"] == "udp":
                udp_ports.add(p["src_port"])
                udp_ports.add(p["dst_port"])
        if udp_ports:
            port = min(udp_ports)
            hwg_l, hwg_d, hwg_i = extract_tcp_flow(hwg_pkts, port, "both")
            if len(hwg_l) == 0:
                from pcap_utils import extract_udp_flow
                hwg_l, hwg_d, hwg_i = extract_udp_flow(hwg_pkts, port)
            print(f"  HideWG (UDP port {port}): {len(hwg_l)} pkts")
    if len(hwg_l) == 0:
        print("  HideWG: 无法提取流量")
        return

    # WireGuard
    wg_l, wg_d, wg_i = extract_wg_flow(wg_pkts, 51831)
    print(f"  WireGuard: {len(wg_l)} pkts")

    # Normal HTTPS: 提取 HTTPS 端口 (443) 双向
    norm_l, norm_d, norm_i = extract_tcp_flow(norm_pkts, 443, "both")
    if len(norm_l) < 50:
        # 可能 pcap 包含其他 TCP 端口，取所有 TCP 包
        norm_l, norm_d, norm_i_list = [], [], []
        prev_ts = None
        for p in norm_pkts:
            if p["proto"] == "tcp":
                norm_l.append(p["len"])
                norm_d.append(1 if "100.125" in p.get("src_ip", "") else -1)
                ts = p["ts"]
                norm_i_list.append(ts - prev_ts if prev_ts else 0.0)
                prev_ts = ts
        norm_l = np.array(norm_l, dtype=np.float64)
        norm_d = np.array(norm_d, dtype=np.float64)
        norm_i = np.array(norm_i_list, dtype=np.float64)
    print(f"  Normal-HTTPS: {len(norm_l)} pkts")

    # ── 生成窗口 ──
    print("\n[3/6] 生成滑动窗口样本...")
    X_list, y_list = [], []

    class_names = ["HideWG (real)", "WireGuard (real)", "Normal-HTTPS (real)"]

    for idx, (l, d, i, label) in enumerate([
        (hwg_l, hwg_d, hwg_i, 0),
        (wg_l, wg_d, wg_i, 1),
        (norm_l, norm_d, norm_i, 2),
    ]):
        wins = make_windows(l, d, i, SEQ_LEN, STRIDE)
        if len(wins) == 0:
            print(f"  WARNING: {class_names[idx]} 样本不足，跳过")
            continue
        n_take = min(len(wins), 200)
        sel = rng.choice(len(wins), n_take, replace=False) if len(wins) >= n_take else rng.choice(len(wins), n_take, replace=True)
        X_list.append(wins[sel])
        y_list.append(np.full(n_take, label, dtype=np.int64))
        print(f"  {class_names[idx]}: {n_take} windows")

    X_all = np.concatenate(X_list)
    y_all = np.concatenate(y_list)

    # ── 统计特征 ──
    X_stat = np.array([stat_features(X_all[i, 0], X_all[i, 1], X_all[i, 2])
                        for i in range(len(X_all))])

    # ── 标准化 + 划分 ──
    mu = X_all.mean(axis=(0, 2), keepdims=True)
    std = X_all.std(axis=(0, 2), keepdims=True) + 1e-9
    X_norm = (X_all - mu) / std
    X_stat_n = (X_stat - X_stat.mean(axis=0)) / (X_stat.std(axis=0) + 1e-9)

    idx_all = np.arange(len(y_all)); rng.shuffle(idx_all)
    split = int(0.7 * len(idx_all))
    tr, te = idx_all[:split], idx_all[split:]
    print(f"\n  总样本: {len(X_all)}, 训练: {len(tr)}, 测试: {len(te)}")

    n_out = len(class_names)
    results = {}

    # ── NC ──
    print(f"\n[4/6] Nearest Centroid")
    nc = NearestCentroidStd(); nc.fit(X_stat_n[tr], y_all[tr])
    nc_p = nc.predict(X_stat_n[te])
    nc_a = np.mean(nc_p == y_all[te]); results["NearestCentroid"] = nc_a
    print(f"  准确率: {nc_a:.3f}"); _print_confusion(y_all[te], nc_p, class_names)

    # ── RF ──
    print(f"\n[4/6] Random Forest")
    rf = SimpleRandomForest(50, 8, 10, SEED); rf.fit(X_stat_n[tr], y_all[tr])
    rf_p = rf.predict(X_stat_n[te])
    rf_a = np.mean(rf_p == y_all[te]); results["RandomForest-50"] = rf_a
    print(f"  准确率: {rf_a:.3f}"); _print_confusion(y_all[te], rf_p, class_names)

    # ── MLP ──
    print(f"\n[4/6] MLP (256)")
    mlp = MLP256(X_stat.shape[1], 256, n_out, 0.005, SEED)
    mlp.fit(X_stat_n[tr], y_all[tr], 100)
    mlp_p = mlp.predict(X_stat_n[te])
    mlp_a = np.mean(mlp_p == y_all[te]); results["MLP-256"] = mlp_a
    print(f"  准确率: {mlp_a:.3f}"); _print_confusion(y_all[te], mlp_p, class_names)

    # ── CNN ──
    print(f"\n[4/6] 1D-CNN")
    cnn = Conv1D(X_norm.shape[1], SEQ_LEN, n_out, 0.001, SEED)
    cnn.fit(X_norm[tr], y_all[tr], 100)
    cnn_p = cnn.predict(X_norm[te])
    cnn_a = np.mean(cnn_p == y_all[te]); results["CNN-1D"] = cnn_a
    print(f"  准确率: {cnn_a:.3f}"); _print_confusion(y_all[te], cnn_p, class_names)

    # ── 汇总 ──
    print("\n" + "=" * 60)
    print("  结果汇总 (全部真实抓包)")
    print("=" * 60)
    for name, acc in sorted(results.items(), key=lambda x: -x[1]):
        bar = "#" * int(acc * 40) + "-" * (40 - int(acc * 40))
        print(f"  {name:<18s} |{bar}| {acc:.1%}")

    for label, name in enumerate(class_names):
        mask = y_all[te] == label
        if mask.sum() == 0:
            continue
        print(f"\n  {name} 召回率:")
        for pn, preds in [("NC", nc_p), ("RF", rf_p), ("MLP", mlp_p), ("CNN", cnn_p)]:
            r = np.mean(preds[mask] == label)
            print(f"    {pn}: {r:.1%} ({int(np.sum(preds[mask]==label))}/{int(mask.sum())})")

    # 流量特征对比
    print("\n" + "=" * 60)
    print("  流量特征对比 (真实数据)")
    print("=" * 60)
    for name, l, d, i in [("HideWG", hwg_l, hwg_d, hwg_i),
                            ("WireGuard", wg_l, wg_d, wg_i),
                            ("Normal-HTTPS", norm_l, norm_d, norm_i)]:
        ul = len(set(int(x) for x in l))
        ac = np.corrcoef(l[1:], l[:-1])[0, 1] if len(l) > 2 else 0
        print(f"  {name}: {len(l)} pkts, {ul} unique sizes, "
              f"mean={l.mean():.0f}B, std={l.std():.0f}B, lag1_autocorr={ac:.3f}")

    # 保存
    out = {
        "data_source": "all_real_capture",
        "description": "所有流量类别均来自真实抓包，无任何合成数据",
        "pcap_files": {
            "hideg": str(hwg_path),
            "wireguard": str(wg_path),
            "normal_https": str(norm_path),
        },
        "hideg_packets": int(len(hwg_l)),
        "wireguard_packets": int(len(wg_l)),
        "normal_packets": int(len(norm_l)),
        "window_size": SEQ_LEN,
        "train_samples": int(len(tr)),
        "test_samples": int(len(te)),
        "results": {k: round(v, 4) for k, v in results.items()},
        "class_names": class_names,
        "synthetic_data_used": False,
    }
    out_path = artifacts / "dl_eval.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n结果已保存: {out_path}")


if __name__ == "__main__":
    t0 = _time.time()
    main()
    print(f"\n总耗时: {_time.time()-t0:.1f}s")
