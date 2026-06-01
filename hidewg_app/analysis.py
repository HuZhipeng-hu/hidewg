from __future__ import annotations

import bisect
import math
import random
from dataclasses import dataclass
from statistics import mean
from typing import Iterable


@dataclass(frozen=True)
class FlowPacket:
    ts: float
    direction: int
    payload: bytes


def detect_wireguard_rules(flow: list[FlowPacket]) -> dict[str, object]:
    payloads = [packet.payload for packet in flow]
    total = max(1, len(payloads))
    r1_hits = sum(1 for payload in payloads if len(payload) >= 1 and payload[0] in {1, 2, 3, 4})
    r2_hits = sum(1 for payload in payloads if len(payload) >= 4 and payload[1:4] == b"\x00\x00\x00")
    typical_lengths = {32, 64, 92, 148}
    r3_hits = sum(1 for payload in payloads if len(payload) in typical_lengths)
    r4_hit = 0
    for first, second in zip(flow, flow[1:]):
        if (
            first.direction == 1
            and second.direction == -1
            and len(first.payload) == 148
            and len(second.payload) == 92
            and first.payload[:4] == b"\x01\x00\x00\x00"
            and second.payload[:4] == b"\x02\x00\x00\x00"
            and 0 <= second.ts - first.ts <= 2.0
        ):
            r4_hit = 1
            break
    keepalive_candidates = [
        packet for packet in flow if len(packet.payload) == 32 and packet.payload[:4] == b"\x04\x00\x00\x00"
    ]
    r5_hit = 1 if len(keepalive_candidates) >= 3 else 0
    per_rule = {
        "R1_message_type_first_byte": r1_hits / total,
        "R2_reserved_zero_bytes": r2_hits / total,
        "R3_typical_wireguard_lengths": r3_hits / total,
        "R4_handshake_direction_timing": r4_hit,
        "R5_fixed_keepalive_pattern": r5_hit,
    }
    overall = sum(per_rule.values()) / len(per_rule)
    return {"overall_rule_hit_rate": overall, "per_rule": per_rule, "packet_count": len(flow)}


def extract_features(flow: list[FlowPacket], startup_count: int = 16) -> list[float]:
    if not flow:
        return [0.0] * (37 + startup_count * 2)
    n = len(flow)
    # Single-pass: collect lengths, dirs, times; compute running sums
    lengths = [0] * n
    dirs = [0] * n
    times = [0.0] * n
    up_packets = 0
    up_bytes = 0
    for i, packet in enumerate(flow):
        l = len(packet.payload)
        lengths[i] = l
        dirs[i] = packet.direction
        times[i] = packet.ts
        if packet.direction == 1:
            up_packets += 1
            up_bytes += l
    down_packets = n - up_packets
    total_bytes = sum(lengths)
    down_bytes = total_bytes - up_bytes
    # Intervals
    intervals = [max(0.0, times[i + 1] - times[i]) for i in range(n - 1)]
    # Burst lengths
    burst_lengths = _burst_lengths(dirs)
    # Histogram bins
    bins = [64, 128, 256, 512, 768, 1024, 1500, 3000]
    histogram = [0.0] * len(bins)
    for length in lengths:
        for j, upper in enumerate(bins):
            if length <= upper:
                histogram[j] += 1.0
    histogram = [h / n for h in histogram]
    # Stats
    avg_len = total_bytes / n
    var_len = sum((l - avg_len) ** 2 for l in lengths) / n
    int_len = len(intervals)
    if int_len:
        avg_int = sum(intervals) / int_len
        var_int = sum((x - avg_int) ** 2 for x in intervals) / int_len
        p95_int = _percentile(intervals, 95)
    else:
        avg_int = var_int = p95_int = 0.0
    burst_avg = sum(burst_lengths) / len(burst_lengths)

    # === DL-simulating features: sequence patterns a CNN/LSTM would learn ===
    # 1. Packet-length autocorrelation at lags 1-4
    autocorr = _autocorrelation(lengths, max_lag=4)
    # 2. Direction transition probabilities (Markov features)
    trans = _direction_transitions(dirs)
    # 3. Sliding-window variance (simulates CNN local feature extraction)
    win_var = _window_variance(lengths, window_sizes=[4, 8, 16])
    # 4. Interval autocorrelation (periodicity in timing)
    int_autocorr = _autocorrelation(intervals, max_lag=3) if intervals else [0.0, 0.0, 0.0]
    # 5. Burst length variance
    burst_var = _variance(burst_lengths) if burst_lengths else 0.0

    features = [
        avg_len, max(lengths), min(lengths), var_len, total_bytes,
        up_packets / n, down_packets / n,
        up_bytes / max(1, up_bytes + down_bytes),
        down_bytes / max(1, up_bytes + down_bytes),
        avg_int, var_int, p95_int,
        burst_avg, max(burst_lengths),
    ]
    features.extend(histogram)
    # DL features
    features.extend(autocorr)
    features.extend(trans)
    features.extend(win_var)
    features.extend(int_autocorr)
    features.append(burst_var)
    for index in range(startup_count):
        if index < n:
            features.append(lengths[index] / 1500.0)
            features.append(float(dirs[index]))
        else:
            features.extend([0.0, 0.0])
    return features


def _autocorrelation(values: list[float] | list[int], max_lag: int = 4) -> list[float]:
    """Pearson autocorrelation at lags 1..max_lag. Captures sequential patterns a CNN would learn."""
    n = len(values)
    if n <= max_lag:
        return [0.0] * max_lag
    avg = sum(values) / n
    var = sum((v - avg) ** 2 for v in values) / n
    if var < 1e-12:
        return [0.0] * max_lag
    result = []
    for lag in range(1, max_lag + 1):
        cov = sum((values[i] - avg) * (values[i + lag] - avg) for i in range(n - lag)) / (n - lag)
        result.append(cov / var)
    return result


def _direction_transitions(directions: list[int]) -> list[float]:
    """Markov transition probabilities: P(up->up), P(up->down), P(down->up), P(down->down)."""
    counts = {"uu": 0, "ud": 0, "du": 0, "dd": 0}
    for i in range(len(directions) - 1):
        a, b = directions[i], directions[i + 1]
        key = ("u" if a == 1 else "d") + ("u" if b == 1 else "d")
        counts[key] += 1
    total = max(1, len(directions) - 1)
    return [counts[k] / total for k in ("uu", "ud", "du", "dd")]


def _window_variance(lengths: list[int], window_sizes: list[int]) -> list[float]:
    """Variance of lengths within sliding windows — simulates CNN local feature extraction."""
    n = len(lengths)
    result = []
    for ws in window_sizes:
        if n < ws:
            result.append(0.0)
            continue
        vars_list = []
        for start in range(0, n - ws + 1, ws):
            window = lengths[start:start + ws]
            avg = sum(window) / ws
            vars_list.append(sum((v - avg) ** 2 for v in window) / ws)
        result.append(sum(vars_list) / len(vars_list) if vars_list else 0.0)
    return result


def _variance(values: list[float] | list[int]) -> float:
    if not values:
        return 0.0
    avg = sum(values) / len(values)
    return sum((v - avg) ** 2 for v in values) / len(values)


def train_nearest_centroid(samples: list[tuple[str, list[float]]]) -> dict[str, list[float]]:
    grouped: dict[str, list[list[float]]] = {}
    for label, features in samples:
        grouped.setdefault(label, []).append(features)
    return {label: _column_mean(rows) for label, rows in grouped.items()}


def evaluate_classifier(dataset: list[tuple[str, list[float]]], seed: int = 20260511) -> dict[str, object]:
    rng = random.Random(seed)
    shuffled = list(dataset)
    rng.shuffle(shuffled)
    split = max(1, int(len(shuffled) * 0.7))
    train = shuffled[:split]
    test = shuffled[split:] or shuffled[-1:]
    scaler = _fit_scaler([features for _label, features in train])
    train_scaled = [(label, _scale(features, scaler)) for label, features in train]
    test_scaled = [(label, _scale(features, scaler)) for label, features in test]
    model = train_nearest_centroid(train_scaled)
    labels = sorted(model)
    confusion = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    predictions: list[tuple[str, str, dict[str, float]]] = []
    for actual, features in test_scaled:
        predicted, scores = _predict(model, features)
        if actual in confusion and predicted in confusion[actual]:
            confusion[actual][predicted] += 1
        predictions.append((actual, predicted, scores))
    accuracy = sum(1 for actual, predicted, _scores in predictions if actual == predicted) / max(1, len(predictions))
    per_label = {}
    for label in labels:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in labels if other != label)
        fn = sum(confusion[label][other] for other in labels if other != label)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        per_label[label] = {"precision": precision, "recall": recall, "f1": f1}
    return {
        "model": "nearest_centroid_std_scaled",
        "train_samples": len(train),
        "test_samples": len(test),
        "accuracy": accuracy,
        "precision_macro": mean(item["precision"] for item in per_label.values()),
        "recall_macro": mean(item["recall"] for item in per_label.values()),
        "f1_macro": mean(item["f1"] for item in per_label.values()),
        "auc_macro": _macro_auc(labels, predictions),
        "labels": labels,
        "confusion_matrix": confusion,
        "per_label": per_label,
    }


def _predict(model: dict[str, list[float]], features: list[float]) -> tuple[str, dict[str, float]]:
    distances = {
        label: math.sqrt(sum((value - centroid[index]) ** 2 for index, value in enumerate(features)))
        for label, centroid in model.items()
    }
    predicted = min(distances, key=distances.get)
    scores = {label: 1.0 / (distance + 1e-9) for label, distance in distances.items()}
    return predicted, scores


def _macro_auc(labels: list[str], predictions: list[tuple[str, str, dict[str, float]]]) -> float:
    aucs = []
    for label in labels:
        positives = [scores[label] for actual, _predicted, scores in predictions if actual == label]
        negatives = [scores[label] for actual, _predicted, scores in predictions if actual != label]
        if not positives or not negatives:
            continue
        # Mann-Whitney U via binary search — O((n+m) log m) instead of O(n*m)
        neg_sorted = sorted(negatives)
        n_neg = len(negatives)
        wins = 0.0
        for p in positives:
            lo = bisect.bisect_left(neg_sorted, p)
            hi = bisect.bisect_right(neg_sorted, p)
            wins += lo + 0.5 * (hi - lo)
        aucs.append(wins / (len(positives) * n_neg))
    return mean(aucs) if aucs else 0.0


def _fit_scaler(rows: list[list[float]]) -> tuple[list[float], list[float]]:
    means = _column_mean(rows)
    stds = []
    for index, avg in enumerate(means):
        variance = sum((row[index] - avg) ** 2 for row in rows) / max(1, len(rows))
        stds.append(math.sqrt(variance) or 1.0)
    return means, stds


def _scale(features: list[float], scaler: tuple[list[float], list[float]]) -> list[float]:
    means, stds = scaler
    return [(value - means[index]) / stds[index] for index, value in enumerate(features)]


def _column_mean(rows: list[list[float]]) -> list[float]:
    if not rows:
        return []
    width = len(rows[0])
    return [sum(row[index] for row in rows) / len(rows) for index in range(width)]


def _burst_lengths(directions: Iterable[int]) -> list[int]:
    bursts: list[int] = []
    last = None
    count = 0
    for direction in directions:
        if direction == last:
            count += 1
        else:
            if count:
                bursts.append(count)
            last = direction
            count = 1
    if count:
        bursts.append(count)
    return bursts or [0]


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((percentile / 100) * (len(ordered) - 1)))))
    return ordered[index]
