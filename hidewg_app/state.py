from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RuntimeStats:
    role: str = "standalone"
    session_state: str = "INIT"
    inner_packets_sent: int = 0
    inner_packets_received: int = 0
    outer_packets_sent: int = 0
    outer_packets_received: int = 0
    inner_bytes_sent: int = 0
    inner_bytes_received: int = 0
    outer_bytes_sent: int = 0
    outer_bytes_received: int = 0
    padding_bytes: int = 0
    fragment_count: int = 0
    reassembly_failures: int = 0
    authentication_failures: int = 0
    replay_drops: int = 0
    latency_samples_ms: list[float] = field(default_factory=list)
    start_time: float = field(default_factory=time.monotonic)
    last_update: float = field(default_factory=time.monotonic)
    _dirs_created: set = field(default_factory=set, repr=False)

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        elapsed = max(0.001, now - self.start_time)
        transferred = self.inner_bytes_sent + self.inner_bytes_received
        latency = sum(self.latency_samples_ms) / len(self.latency_samples_ms) if self.latency_samples_ms else 0.0
        return {
            "pid": os.getpid(),
            "role": self.role,
            "session_state": self.session_state,
            "uptime_seconds": round(elapsed, 3),
            "inner_packets_sent": self.inner_packets_sent,
            "inner_packets_received": self.inner_packets_received,
            "outer_packets_sent": self.outer_packets_sent,
            "outer_packets_received": self.outer_packets_received,
            "inner_bytes_sent": self.inner_bytes_sent,
            "inner_bytes_received": self.inner_bytes_received,
            "outer_bytes_sent": self.outer_bytes_sent,
            "outer_bytes_received": self.outer_bytes_received,
            "padding_bytes": self.padding_bytes,
            "fragment_count": self.fragment_count,
            "reassembly_failures": self.reassembly_failures,
            "authentication_failures": self.authentication_failures,
            "replay_drops": self.replay_drops,
            "current_throughput_bps": round((transferred * 8) / elapsed, 2),
            "current_latency_estimate_ms": round(latency, 3),
        }

    def _ensure_dir(self, path: Path) -> None:
        parent = str(path.parent)
        if parent not in self._dirs_created:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._dirs_created.add(parent)

    def write_state(self, path: str | Path) -> None:
        state_path = Path(path)
        self._ensure_dir(state_path)
        state_path.write_text(json.dumps(self.snapshot(), indent=2, ensure_ascii=False), encoding="utf-8")

    def append_log(self, path: str | Path, event: str, extra: dict[str, Any] | None = None) -> None:
        log_path = Path(path)
        self._ensure_dir(log_path)
        record = {"ts": time.time(), "event": event, **self.snapshot()}
        if extra:
            record.update(extra)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
