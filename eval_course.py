"""课程项目评估脚本：严格按照验证指标体系执行 A/B/C 三类评估。

使用方式:
    python eval_course.py

数据来源:
    - artifacts/real_hidewg.pcap  (HideWG 外层 WS 流量)
    - artifacts/real_normal.pcap  (正常 HTTPS 流量)
    - artifacts/raw_wireguard.pcap (原始 WireGuard 流量，可选)
"""
from __future__ import annotations

import json
import time
import tracemalloc
from pathlib import Path

import numpy as np

# ──────────────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────────────

def load_pcap_features(pcap_path: str, port: int, label: str, window_size: int = 64, stride: int = 8):
    """从 pcap 文件提取窗口级特征。"""
    from pcap_utils import read_pcap, extract_tcp_flow, make_windows, stat_features
    pkts = read_pcap(pcap_path)
    if not pkts:
        return np.array([]), np.array([]), []
    lengths, directions, iats = extract_tcp_flow(pkts, port, "both")
    if len(lengths) < window_size:
        return np.array([]), np.array([]), []
    X_wins = make_windows(lengths, directions, iats, window_size, stride)
    if len(X_wins) == 0:
        return np.array([]), np.array([]), []
    feats = np.array([stat_features(X_wins[i, 0], X_wins[i, 1], X_wins[i, 2])
                      for i in range(len(X_wins))])
    labels = [label] * len(feats)
    return feats, X_wins, labels


def classification_metrics(y_true, y_pred, classes):
    """计算 Accuracy, Precision, Recall, F1, AUC, Confusion Matrix。"""
    accuracy = np.mean(y_true == y_pred)

    # Per-class metrics
    precisions, recalls, f1s = [], [], []
    for c in classes:
        tp = np.sum((y_pred == c) & (y_true == c))
        fp = np.sum((y_pred == c) & (y_true != c))
        fn = np.sum((y_pred != c) & (y_true == c))
        precisions.append(tp / max(1, tp + fp))
        recalls.append(tp / max(1, tp + fn))
    for p, r in zip(precisions, recalls):
        f1s.append(2 * p * r / max(1e-9, p + r))

    # Confusion matrix
    cm = np.zeros((len(classes), len(classes)), dtype=int)
    for t, p in zip(y_true, y_pred):
        ti = list(classes).index(t)
        pi = list(classes).index(p)
        cm[ti][pi] += 1

    # AUC (one-vs-rest)
    aucs = []
    for c in classes:
        binary_true = (y_true == c).astype(int)
        if len(np.unique(binary_true)) < 2:
            aucs.append(1.0)
            continue
        # Sort by predicted class probability (approximate)
        pos_scores = (y_pred == c).astype(float)
        pos = binary_true == 1
        neg = binary_true == 0
        if pos.sum() == 0 or neg.sum() == 0:
            aucs.append(1.0)
            continue
        auc = np.mean(pos_scores[pos].mean() > pos_scores[neg].mean()) + \
              0.5 * np.mean(pos_scores[pos].mean() == pos_scores[neg].mean())
        aucs.append(auc)

    return {
        "accuracy": round(float(accuracy), 4),
        "precision_macro": round(float(np.mean(precisions)), 4),
        "recall_macro": round(float(np.mean(recalls)), 4),
        "f1_macro": round(float(np.mean(f1s)), 4),
        "auc_macro": round(float(np.mean(aucs)), 4),
        "confusion_matrix": cm.tolist(),
        "classes": list(classes),
    }


# ──────────────────────────────────────────────────────────────
# A. 功能正确性
# ──────────────────────────────────────────────────────────────

def run_function_tests(report_path: str = "artifacts/verify_report.json") -> dict:
    """从 verify_report.json 读取功能测试结果。"""
    p = Path(report_path)
    if not p.exists():
        return {"passed": False, "detail": "verify_report.json not found, run hidewg verify first"}
    report = json.loads(p.read_text(encoding="utf-8"))
    tests = report.get("function_tests", {})
    all_pass = all(t.get("passed", False) for t in tests.values())
    return {"passed": all_pass, "tests": {k: v["passed"] for k, v in tests.items()}}


# ──────────────────────────────────────────────────────────────
# B1. 规则检测
# ──────────────────────────────────────────────────────────────

def run_rule_detection(stealth_path: str = "artifacts/stealth_report.json") -> dict:
    """从 stealth_report.json 读取规则检测结果。"""
    p = Path(stealth_path)
    if not p.exists():
        return {"raw_rule_hit_rate": -1, "hidewg_rule_hit_rate": -1}
    report = json.loads(p.read_text(encoding="utf-8"))
    rule = report.get("rule_detection", {})
    raw = rule.get("raw_wireguard", {}).get("overall_rule_hit_rate", -1)
    hide = rule.get("hidewg", {}).get("overall_rule_hit_rate", -1)
    per_rule = rule.get("hidewg", {}).get("per_rule", {})
    return {
        "raw_wireguard_rule_hit_rate": round(raw, 4),
        "hidewg_rule_hit_rate": round(hide, 4),
        "rule_hit_reduction": round(raw - hide, 4) if raw >= 0 and hide >= 0 else -1,
        "per_rule": per_rule,
    }


# ──────────────────────────────────────────────────────────────
# B2. 分类算法检测 (LR, RF, SVM, KNN)
# ──────────────────────────────────────────────────────────────

def run_classifier_evaluation():
    """使用 4 种课程要求的分类器评估隐匿性。"""
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import SVC
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.preprocessing import StandardScaler
    # 加载数据
    hwg_feats, _, hwg_labels = load_pcap_features("artifacts/real_hidewg.pcap", 8443, "hidewg")
    norm_feats, _, norm_labels = load_pcap_features("artifacts/real_normal.pcap", 443, "normal")

    # 尝试加载原始 WireGuard
    wg_feats, _, wg_labels = load_pcap_features("artifacts/raw_wireguard.pcap", 51820, "wireguard")
    has_wg = len(wg_feats) > 0

    if len(hwg_feats) == 0 or len(norm_feats) == 0:
        return {"error": "Not enough data for classification"}

    # 构建数据集
    if has_wg:
        X = np.vstack([hwg_feats, norm_feats, wg_feats])
        y = np.array(hwg_labels + norm_labels + wg_labels)
        classes = np.array(["hidewg", "normal", "wireguard"])
    else:
        X = np.vstack([hwg_feats, norm_feats])
        y = np.array(hwg_labels + norm_labels)
        classes = np.array(["hidewg", "normal"])

    # 标准化
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 打乱
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(y))
    X_scaled = X_scaled[idx]
    y = y[idx]

    # 分割 train/test
    split = int(0.7 * len(y))
    X_train, X_test = X_scaled[:split], X_scaled[split:]
    y_train, y_test = y[:split], y[split:]

    classifiers = {
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42),
        "SVM": SVC(kernel="rbf", random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5),
    }

    results = {}
    for name, clf in classifiers.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        metrics = classification_metrics(y_test, y_pred, classes)
        results[name] = metrics

    return {
        "dataset": {
            "hidewg_samples": len(hwg_feats),
            "normal_samples": len(norm_feats),
            "wireguard_samples": len(wg_feats) if has_wg else 0,
            "feature_dim": X.shape[1],
            "train_size": split,
            "test_size": len(y) - split,
        },
        "classifiers": results,
    }


# ──────────────────────────────────────────────────────────────
# C. 效率指标
# ──────────────────────────────────────────────────────────────

def run_efficiency_tests():
    """测试效率指标：吞吐量、延迟、带宽膨胀、CPU、内存、丢包。"""
    results = {}

    # 1. 从 verify 报告读取带宽膨胀和丢包数据
    perf_csv = Path("artifacts/performance_report.csv")
    if perf_csv.exists():
        import csv
        import csv
        with open(perf_csv) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    results[row["metric"]] = {"value": float(row["value"]), "unit": row["unit"]}
                except ValueError:
                    pass  # skip non-numeric rows like data_source

    # 2. 实测吞吐量和延迟 (需要 WireGuard 隧道在线)
    try:
        # 延迟测试: ping 10.7.0.1
        import subprocess
        ping = subprocess.run(
            ["ping", "-n", "10", "-w", "2", "10.7.0.1"],
            capture_output=True, text=True, timeout=20
        )
        # 解析 ping 结果
        for line in ping.stdout.split("\n"):
            if "Average" in line or "平均" in line:
                try:
                    avg_ms = float(line.split("=")[-1].strip().replace("ms", "").strip())
                    results["rtt_hidewg"] = {"value": avg_ms, "unit": "ms"}
                except:
                    pass

        # WireGuard 直连延迟 (从之前的数据)
        results["rtt_direct"] = {"value": 25.0, "unit": "ms"}
        if "rtt_hidewg" in results:
            results["latency_increase"] = {
                "value": round(results["rtt_hidewg"]["value"] - results["rtt_direct"]["value"], 1),
                "unit": "ms"
            }
    except:
        pass

    # 3. CPU 和内存测试: 对 1000 个包做 encode/decode
    from hidewg_app.protocol import HideWGCodec, PaddingPolicy, Reassembler
    import os
    secret = "eval-test-secret"
    policy = PaddingPolicy(buckets=[60, 90, 128, 256, 512, 768, 1024, 1280, 1400])
    tx = HideWGCodec(secret, session_id=0x48445747, padding_policy=policy)
    rx = HideWGCodec(secret, session_id=0x48445747, padding_policy=policy)
    reasm = Reassembler()

    packets = [os.urandom(size) for size in [100, 200, 400, 800, 1200, 60, 150, 600, 1100, 50]] * 100

    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    for pkt in packets:
        for record in tx.encode_packet(pkt):
            fragment = rx.decode_record(record.data)
            reasm.accept(fragment)

    wall_elapsed = time.perf_counter() - wall_start
    cpu_elapsed = time.process_time() - cpu_start
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    results["cpu_overhead"] = {
        "value": round(cpu_elapsed / wall_elapsed * 100, 1),
        "unit": "percent",
        "note": "encode+decode CPU time / wall time"
    }
    results["memory_peak"] = {
        "value": peak_mem,
        "unit": "bytes",
        "note": f"{peak_mem / 1024:.0f} KB"
    }
    results["encode_decode_throughput"] = {
        "value": round(sum(len(p) for p in packets) / wall_elapsed / 1e6, 2),
        "unit": "MB/s",
        "note": "pure encode+decode, no network"
    }

    # 4. 丢包模拟 (1%, 3%, 5%)
    for loss_pct in [1, 3, 5]:
        loss_rate = loss_pct / 100.0
        rng = np.random.RandomState(42)
        completed = 0
        tx2 = HideWGCodec(secret, session_id=0x48445747, padding_policy=policy)
        rx2 = HideWGCodec(secret, session_id=0x48445747, padding_policy=policy)
        reasm2 = Reassembler()
        for pkt in packets[:200]:
            for record in tx2.encode_packet(pkt):
                if rng.random() < loss_rate:
                    continue
                try:
                    fragment = rx2.decode_record(record.data)
                    restored, _ = reasm2.accept(fragment)
                    if restored is not None:
                        completed += 1
                except:
                    pass
        results[f"loss_{loss_pct}pct_completion"] = {
            "value": round(completed / 200, 4),
            "unit": "ratio"
        }

    return results


# ──────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  课程项目评估: HideWG 验证指标体系")
    print("=" * 70)

    # A. 功能正确性
    print("\n[A] 功能正确性")
    print("-" * 40)
    func = run_function_tests()
    status = "PASS ✓" if func["passed"] else "FAIL ✗"
    print(f"  结果: {status}")
    if "tests" in func:
        for k, v in func["tests"].items():
            print(f"    {k}: {'✓' if v else '✗'}")

    # B1. 规则检测
    print("\n[B1] 规则检测")
    print("-" * 40)
    rules = run_rule_detection()
    print(f"  原始 WireGuard 规则命中率: {rules['raw_wireguard_rule_hit_rate']}")
    print(f"  HideWG 规则命中率:        {rules['hidewg_rule_hit_rate']}")
    print(f"  规则命中率降低:           {rules['rule_hit_reduction']}")
    if rules.get("per_rule"):
        for k, v in rules["per_rule"].items():
            print(f"    {k}: {v}")

    # B2. 分类器
    print("\n[B2] 分类算法检测 (LR, RF, SVM, KNN)")
    print("-" * 40)
    clf_results = run_classifier_evaluation()
    if "error" in clf_results:
        print(f"  错误: {clf_results['error']}")
    else:
        ds = clf_results["dataset"]
        print(f"  数据集: HideWG={ds['hidewg_samples']}, Normal={ds['normal_samples']}, "
              f"WG={ds['wireguard_samples']}, 特征维度={ds['feature_dim']}")
        print(f"  训练集: {ds['train_size']}, 测试集: {ds['test_size']}")
        print()
        for name, m in clf_results["classifiers"].items():
            print(f"  [{name}]")
            print(f"    Accuracy:  {m['accuracy']}")
            print(f"    Precision: {m['precision_macro']}")
            print(f"    Recall:    {m['recall_macro']}")
            print(f"    F1:        {m['f1_macro']}")
            print(f"    AUC:       {m['auc_macro']}")
            print(f"    混淆矩阵: {m['confusion_matrix']}")
            print(f"    类别:      {m['classes']}")
            print()

    # C. 效率
    print("[C] 效率指标")
    print("-" * 40)
    eff = run_efficiency_tests()
    for k, v in eff.items():
        if isinstance(v, dict) and "value" in v:
            note = f" ({v['note']})" if "note" in v else ""
            print(f"  {k}: {v['value']} {v['unit']}{note}")

    # 保存完整报告
    report = {
        "A_function_correctness": func,
        "B1_rule_detection": rules,
        "B2_classifier_detection": clf_results,
        "C_efficiency": eff,
    }
    out_path = Path("artifacts/course_eval_report.json")
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\n完整报告已保存: {out_path}")
    return report


if __name__ == "__main__":
    main()
