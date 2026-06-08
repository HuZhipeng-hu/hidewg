"""课程评估数据可视化脚本。

生成 6 张图表，覆盖 A/B/C 三类指标：
  1. 功能正确性概览
  2. 规则检测命中率对比
  3. 分类器性能雷达图
  4. 混淆矩阵热力图
  5. 效率指标仪表盘
  6. 丢包鲁棒性曲线

使用方式:
    python visualize.py
    输出: artifacts/course_eval_*.png
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ── 中文字体 ──
plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "WenQuanYi Micro Hei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

REPORT = json.loads(Path("artifacts/course_eval_report.json").read_text(encoding="utf-8"))
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)


# ============================================================
# 图 1: 功能正确性概览
# ============================================================
def plot_function_tests():
    tests = REPORT["A_function_correctness"]["tests"]
    names = list(tests.keys())
    passed = [1 if v else 0 for v in tests.values()]

    fig, ax = plt.subplots(figsize=(10, 4))
    colors = ["#2ecc71" if p else "#e74c3c" for p in passed]
    bars = ax.barh(range(len(names)), passed, color=colors, edgecolor="white", height=0.6)

    ax.set_yticks(range(len(names)))
    ax.set_yticklabels([n.replace("_", " ").title() for n in names], fontsize=11)
    ax.set_xlim(-0.1, 1.5)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["FAIL", "PASS"], fontsize=12, fontweight="bold")
    ax.invert_yaxis()

    for i, (bar, p) in enumerate(zip(bars, passed)):
        ax.text(1.05, i, "PASS" if p else "FAIL", va="center", fontsize=12,
                color="#2ecc71" if p else "#e74c3c", fontweight="bold")

    all_pass = all(tests.values())
    status = "ALL PASSED" if all_pass else "SOME FAILED"
    color = "#2ecc71" if all_pass else "#e74c3c"
    ax.set_title(f"A. 功能正确性  [{status}]", fontsize=14, fontweight="bold", color=color, pad=15)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    fig.savefig(OUT / "course_eval_A_function.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → artifacts/course_eval_A_function.png")


# ============================================================
# 图 2: 规则检测命中率对比
# ============================================================
def plot_rule_detection():
    b1 = REPORT["B1_rule_detection"]
    per_rule = b1.get("per_rule", {})

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={"width_ratios": [1, 2]})

    # 左: 总体对比
    labels = ["WireGuard", "HideWG"]
    rates = [b1["raw_wireguard_rule_hit_rate"], b1["hidewg_rule_hit_rate"]]
    colors = ["#e74c3c", "#2ecc71"]
    bars = ax1.bar(labels, rates, color=colors, width=0.5, edgecolor="white")
    for bar, rate in zip(bars, rates):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                 f"{rate:.1%}", ha="center", va="bottom", fontsize=13, fontweight="bold")
    ax1.set_ylabel("规则命中率", fontsize=12)
    ax1.set_title("总体命中率", fontsize=13, fontweight="bold")
    ax1.set_ylim(0, max(rates) * 1.3)
    ax1.spines[["top", "right"]].set_visible(False)

    # 右: 逐条规则
    rule_names = list(per_rule.keys())
    rule_labels = [r.split("_", 1)[0] + ": " + r.split("_", 1)[1].replace("_", " ") for r in rule_names]
    rule_values = [per_rule[r] * 100 for r in rule_names]
    colors_r = ["#e74c3c" if v > 1 else "#2ecc71" for v in rule_values]
    bars2 = ax2.barh(range(len(rule_names)), rule_values, color=colors_r, edgecolor="white", height=0.5)
    ax2.set_yticks(range(len(rule_names)))
    ax2.set_yticklabels(rule_labels, fontsize=10)
    ax2.set_xlabel("命中率 (%)", fontsize=12)
    ax2.set_title("HideWG 逐条规则命中率", fontsize=13, fontweight="bold")
    ax2.invert_yaxis()
    for bar, val in zip(bars2, rule_values):
        ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                 f"{val:.2f}%", va="center", fontsize=11)
    ax2.spines[["top", "right"]].set_visible(False)

    reduction = b1["rule_hit_reduction"]
    fig.suptitle(f"B1. 规则检测  [命中率降低 {reduction:.1%}]", fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    fig.savefig(OUT / "course_eval_B1_rules.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → artifacts/course_eval_B1_rules.png")


# ============================================================
# 图 3: 分类器性能雷达图
# ============================================================
def plot_classifier_radar():
    clfs = REPORT["B2_classifier_detection"]["classifiers"]
    metrics = ["accuracy", "precision_macro", "recall_macro", "f1_macro", "auc_macro"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1", "AUC"]

    angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    colors = ["#3498db", "#e74c3c", "#2ecc71", "#f39c12"]

    for (name, data), color in zip(clfs.items(), colors):
        values = [data[m] for m in metrics]
        values += values[:1]
        ax.plot(angles, values, "o-", linewidth=2, label=name, color=color, markersize=6)
        ax.fill(angles, values, alpha=0.1, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metric_labels, fontsize=12)
    ax.set_ylim(0, 1.1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], fontsize=9)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=11)
    ax.set_title("B2. 分类器性能对比", fontsize=14, fontweight="bold", pad=20)

    fig.savefig(OUT / "course_eval_B2_radar.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → artifacts/course_eval_B2_radar.png")


# ============================================================
# 图 4: 混淆矩阵热力图
# ============================================================
def plot_confusion_matrices():
    clfs = REPORT["B2_classifier_detection"]["classifiers"]
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))

    for ax, (name, data) in zip(axes, clfs.items()):
        cm = np.array(data["confusion_matrix"])
        classes = data["classes"]
        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=cm.max())

        for i in range(len(classes)):
            for j in range(len(classes)):
                color = "white" if cm[i, j] > cm.max() / 2 else "black"
                ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                        fontsize=16, fontweight="bold", color=color)

        ax.set_xticks(range(len(classes)))
        ax.set_yticks(range(len(classes)))
        ax.set_xticklabels(classes, fontsize=9, rotation=45)
        ax.set_yticklabels(classes, fontsize=9)
        ax.set_xlabel("预测", fontsize=10)
        ax.set_ylabel("真实", fontsize=10)
        ax.set_title(f"{name}\nAcc={data['accuracy']:.0%}", fontsize=11, fontweight="bold")

    fig.suptitle("B2. 混淆矩阵", fontsize=14, fontweight="bold", y=1.05)
    plt.tight_layout()
    fig.savefig(OUT / "course_eval_B2_confusion.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → artifacts/course_eval_B2_confusion.png")


# ============================================================
# 图 5: 效率指标仪表盘
# ============================================================
def plot_efficiency_dashboard():
    eff = REPORT["C_efficiency"]

    fig, axes = plt.subplots(2, 3, figsize=(15, 9))

    def gauge(ax, value, title, unit, color, max_val=None, note=""):
        if max_val is None:
            max_val = value * 1.5
        theta = np.linspace(0, np.pi, 100)
        r_outer = 1.0
        r_inner = 0.7

        # Background arc
        ax.fill_between(theta, r_inner, r_outer, color="#ecf0f1", alpha=0.5)
        # Value arc
        frac = min(1.0, value / max_val)
        theta_val = np.linspace(0, np.pi * frac, 100)
        ax.fill_between(theta_val, r_inner, r_outer, color=color, alpha=0.8)

        # Text
        ax.text(np.pi / 2, 0.35, f"{value:.1f}", ha="center", va="center",
                fontsize=24, fontweight="bold", color=color)
        ax.text(np.pi / 2, 0.1, unit, ha="center", va="center", fontsize=11, color="#7f8c8d")
        ax.set_title(title, fontsize=13, fontweight="bold", pad=15)
        if note:
            ax.text(np.pi / 2, -0.15, note, ha="center", va="center", fontsize=9, color="#95a5a6")
        ax.set_xlim(-0.2, np.pi + 0.2)
        ax.set_ylim(-0.3, 1.3)
        ax.axis("off")

    gauge(axes[0, 0], eff["bandwidth_expansion"]["value"],
          "带宽膨胀率", "x", "#3498db", 2.0, "越接近 1.0 越好")
    gauge(axes[0, 1], eff["cpu_overhead"]["value"],
          "CPU 开销", "%", "#e67e22", 100, "encode+decode")
    gauge(axes[0, 2], eff["memory_peak"]["value"] / 1024,
          "内存峰值", "KB", "#9b59b6", 500)
    gauge(axes[1, 0], eff["latency_increase"]["value"],
          "延迟增加", "ms", "#e74c3c", 100, "RTT 差值")
    gauge(axes[1, 1], eff["encode_decode_throughput"]["value"],
          "编解码吞吐", "MB/s", "#2ecc71", 20, "纯编解码")
    gauge(axes[1, 2], eff["throughput_retention"]["value"] * 100,
          "吞吐量保持率", "%", "#1abc9c", 100, "vs 本地回环基线")

    fig.suptitle("C. 效率指标仪表盘", fontsize=16, fontweight="bold", y=1.02)
    plt.tight_layout()
    fig.savefig(OUT / "course_eval_C_efficiency.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → artifacts/course_eval_C_efficiency.png")


# ============================================================
# 图 6: 丢包鲁棒性曲线
# ============================================================
def plot_loss_robustness():
    eff = REPORT["C_efficiency"]
    loss_rates = [0, 1, 3, 5]
    completions = [
        1.0,
        eff["loss_1pct_completion"]["value"],
        eff["loss_3pct_completion"]["value"],
        eff["loss_5pct_completion"]["value"],
    ]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(loss_rates, completions, "o-", color="#2ecc71", linewidth=3, markersize=10, label="HideWG")
    ax.fill_between(loss_rates, completions, alpha=0.15, color="#2ecc71")

    for x, y in zip(loss_rates, completions):
        ax.annotate(f"{y:.1%}", (x, y), textcoords="offset points",
                    xytext=(0, 15), ha="center", fontsize=12, fontweight="bold")

    ax.set_xlabel("网络丢包率 (%)", fontsize=13)
    ax.set_ylabel("数据包完成率 (%)", fontsize=13)
    ax.set_title("C. 丢包鲁棒性", fontsize=14, fontweight="bold")
    ax.set_xticks(loss_rates)
    ax.set_xticklabels([f"{r}%" for r in loss_rates])
    ax.set_ylim(0.85, 1.05)
    ax.set_yticks([0.86, 0.90, 0.94, 0.98, 1.00])
    ax.set_yticklabels(["86%", "90%", "94%", "98%", "100%"])
    ax.grid(True, alpha=0.3)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    fig.savefig(OUT / "course_eval_C_loss.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → artifacts/course_eval_C_loss.png")


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    print("生成可视化图表...")
    plot_function_tests()
    plot_rule_detection()
    plot_classifier_radar()
    plot_confusion_matrices()
    plot_efficiency_dashboard()
    plot_loss_robustness()
    print(f"\n全部图表已保存到 {OUT}/")
