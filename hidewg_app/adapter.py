from __future__ import annotations

import hashlib
import os
import random
import selectors
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Any

from .config import as_float, as_int, as_list
from .protocol import (
    AuthenticationError,
    HideWGCodec,
    JunkInjector,
    PaddingPolicy,
    ProtocolError,
    Reassembler,
    AdaptivePaddingPolicy,
    ContinuousPaddingPolicy,
    TrafficMimicryPolicy,
)
from .state import RuntimeStats
from .ws import WSTransport, HTTPMultiplexer


class HideWGProxy:
    def __init__(self, role: str, config: dict[str, Any]):
        self.role = role
        self.config = config
        self.stats = RuntimeStats(role=role, session_state="STARTING")
        buckets = as_list(config, "padding_buckets", [96, 128, 192, 256, 384, 512, 768, 1024, 1280])
        jitter = as_float(config, "padding_jitter_chance", 0.2)
        bucket_drift = as_int(config, "bucket_drift", 0)
        padding_mode = str(config.get("padding_mode", "adaptive"))

        if padding_mode == "continuous":
            policy = ContinuousPaddingPolicy(
                min_len=min(buckets),
                max_len=max(buckets),
                distribution=str(config.get("padding_distribution", "multimodal")),
                reshape_interval=as_int(config, "padding_reshape_interval", 64),
            )
        elif padding_mode == "mimicry":
            policy = TrafficMimicryPolicy(
                min_size=min(buckets),
                max_size=max(buckets),
                jitter_std=as_float(config, "mimicry_jitter_std", 8.0),
            )
        elif padding_mode == "adaptive" or config.get("adaptive_padding", False):
            policy = AdaptivePaddingPolicy(
                buckets=buckets,
                jitter_bucket_chance=jitter,
                window_size=as_int(config, "adapt_window_size", 128),
                adapt_strength=as_float(config, "adapt_strength", 0.6),
                bucket_drift=bucket_drift,
                bucket_jitter_sigma=as_float(config, "bucket_jitter_sigma", 15.0),
            )
        else:
            policy = PaddingPolicy(buckets=buckets, jitter_bucket_chance=jitter, bucket_drift=bucket_drift)
        self.codec = HideWGCodec(
            shared_secret=str(config.get("shared_secret", "hidewg-demo-secret")),
            session_id=as_int(config, "session_id", 0x48445747),
            max_fragment_payload=as_int(config, "max_fragment_payload", 1300),
            min_fragment_payload=as_int(config, "min_fragment_payload", 0),
            padding_policy=policy,
        )
        self.reassembler = Reassembler(
            replay_window=as_int(config, "replay_window", 4096),
            fragment_ttl=as_float(config, "fragment_ttl_seconds", 30.0),
        )
        self.inner_bind = (
            str(config.get("inner_listen_host", config.get("listen_host", "127.0.0.1"))),
            as_int(config, "inner_listen_port", as_int(config, "listen_port", 51830)),
        )
        self.outer_bind = (
            str(config.get("outer_listen_host", "0.0.0.0")),
            as_int(config, "outer_listen_port", 55820),
        )
        self.peer_outer = (
            str(config.get("peer_host", "127.0.0.1")),
            as_int(config, "peer_port", 55821),
        )
        configured_inner_host = config.get("wireguard_host")
        configured_inner_port = config.get("wireguard_port")
        self.inner_forward: tuple[str, int] | None = None
        if configured_inner_host is not None and configured_inner_port is not None:
            self.inner_forward = (str(configured_inner_host), int(configured_inner_port))
        self.learned_inner_addr: tuple[str, int] | None = None
        self.learned_peer_outer: tuple[str, int] | None = None
        # Role detection: server sets tls_terminate, client sets ws_path
        self.is_server = bool(config.get("tls_terminate", False))
        self.timing_jitter_ms = as_float(config, "timing_jitter_ms", 0.0)
        # Junk packet injection (AmneziaWG Jc/Jmin/Jmax)
        self.junk_injector = JunkInjector(
            count=as_int(config, "junk_count", 0),
            min_size=as_int(config, "junk_min_size", 64),
            max_size=as_int(config, "junk_max_size", 384),
            noise_prefix_range=(as_int(config, "noise_prefix_min", 0), as_int(config, "noise_prefix_max", 0)),
            s4_padding_max=as_int(config, "s4_padding_max", 0),
        )
        # Cover traffic: continuous low-rate dummies (AmneziaWG-inspired)
        self.cover_enabled = config.get("cover_traffic", False)
        self.cover_rate_hz = as_float(config, "cover_rate_hz", 0.0)
        if self.cover_rate_hz > 0 and self.cover_enabled:
            self._cover_interval_s = 1.0 / self.cover_rate_hz
        else:
            self._cover_interval_s = as_float(config, "cover_interval_s", 3.0)
        self.cover_burst_max = as_int(config, "cover_burst_max", 3)
        self.cover_bidirectional = config.get("cover_bidirectional", True)
        self._last_cover_time = 0.0
        self._cover_key = hashlib.sha256(
            str(config.get("shared_secret", "")).encode() + b":cover"
        ).digest() if self.cover_enabled else b""
        self.state_path = Path(str(config.get("state_path", f".hidewg/{role}_state.json")))
        self.log_path = Path(str(config.get("log_path", f".hidewg/{role}_runtime.jsonl")))
        self.pid_path = Path(str(config.get("pid_path", f".hidewg/{role}.pid")))
        self._running = True

    def run(self) -> None:
        self.pid_path.parent.mkdir(parents=True, exist_ok=True)
        self.pid_path.write_text(str(os.getpid()), encoding="utf-8")
        self.stats.session_state = "RUNNING"
        self.stats.append_log(self.log_path, "start")

        selector = selectors.DefaultSelector()
        inner_sock = self._udp_socket(self.inner_bind)
        outer_transport = self._create_outer_transport()
        outer_transport.bind()
        selector.register(inner_sock, selectors.EVENT_READ, "inner")
        selector.register(outer_transport.fileno(), selectors.EVENT_READ, "outer")
        outer_fileno = outer_transport.fileno()
        outer_conn_fd = None  # HTTPMultiplexer connection fd (registered after WS accept)

        def handle_signal(_signum: int, _frame: object) -> None:
            self._running = False

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, handle_signal)
            signal.signal(signal.SIGINT, handle_signal)

        last_flush = 0.0
        try:
            while self._running:
                events = selector.select(timeout=0.05)
                for key, _mask in events:
                    if key.data == "inner":
                        for _ in range(64):
                            try:
                                self._handle_inner(inner_sock, outer_transport)
                            except (BlockingIOError, OSError):
                                break
                    else:
                        for _ in range(64):
                            try:
                                self._handle_outer(outer_transport, inner_sock)
                            except (BlockingIOError, OSError):
                                break
                # Re-register outer transport if its fd changed (TLS accept/close)
                try:
                    new_fd = outer_transport.fileno()
                except RuntimeError:
                    new_fd = None
                if new_fd is not None and new_fd != outer_fileno:
                    selector.unregister(outer_fileno)
                    try:
                        selector.register(new_fd, selectors.EVENT_READ, "outer")
                    except (ValueError, KeyError):
                        pass
                    outer_fileno = new_fd
                # Register HTTPMultiplexer connection fd (WebSocket/TLS after accept)
                try:
                    conn_fd = outer_transport.connection_fileno()
                except AttributeError:
                    conn_fd = None
                if conn_fd is not None and conn_fd != outer_fileno and conn_fd != outer_conn_fd:
                    if outer_conn_fd is not None:
                        try:
                            selector.unregister(outer_conn_fd)
                        except (ValueError, KeyError):
                            pass
                    try:
                        selector.register(conn_fd, selectors.EVENT_READ, "outer")
                        outer_conn_fd = conn_fd
                    except (ValueError, KeyError):
                        pass
                # Inject cover traffic during idle periods
                self._inject_cover(outer_transport)
                now = time.monotonic()
                if now - last_flush >= 5.0:
                    self.stats.write_state(self.state_path)
                    self.stats.append_log(self.log_path, "tick")
                    last_flush = now
        finally:
            self.stats.session_state = "STOPPED"
            self.stats.write_state(self.state_path)
            self.stats.append_log(self.log_path, "stop")
            selector.close()
            inner_sock.close()
            outer_transport.close()
            try:
                self.pid_path.unlink()
            except (FileNotFoundError, PermissionError):
                pass

    def _create_outer_transport(self):
        """Create the WebSocket-over-TLS outer transport."""
        tls_certfile = self.config.get("tls_certfile")
        tls_keyfile = self.config.get("tls_keyfile")
        tls_ca_certs = self.config.get("tls_ca_certs")

        if self.role == "server":
            return HTTPMultiplexer(
                self.outer_bind,
                certfile=tls_certfile,
                keyfile=tls_keyfile,
                ca_certs=tls_ca_certs,
                tls_terminate=self.config.get("tls_terminate", False),
            )
        return WSTransport(
            self.outer_bind,
            server_side=False,
            certfile=tls_certfile,
            keyfile=tls_keyfile,
            ca_certs=tls_ca_certs,
            peer_addr=self.peer_outer,
            ws_path=str(self.config.get("ws_path", "/ws")),
        )

    def stop(self) -> None:
        self._running = False

    def _udp_socket(self, bind_addr: tuple[str, int]) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Increase OS-level buffers for higher throughput
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        except OSError:
            pass
        sock.bind(bind_addr)
        sock.setblocking(False)
        return sock

    def _handle_inner(self, inner_sock: socket.socket, outer_transport) -> None:
        data, addr = inner_sock.recvfrom(65535)
        self.learned_inner_addr = addr
        self.stats.inner_packets_sent += 1
        self.stats.inner_bytes_sent += len(data)
        records = self.codec.encode_packet(data)
        if len(records) > 1:
            self.stats.fragment_count += len(records)
        peer = self.learned_peer_outer or self.peer_outer
        # Inject junk packets before first real send (AmneziaWG Jc/Jmin/Jmax)
        for junk in self.junk_injector.generate():
            outer_transport.send(junk, peer)
            self.stats.outer_packets_sent += 1
            self.stats.outer_bytes_sent += len(junk)
        for record in records:
            self._apply_timing()
            # Wrap with noise prefix to break discrete bucket pattern (AmneziaWG S4)
            wrapped = self.junk_injector.wrap_with_noise(record.data)
            outer_transport.send(wrapped, peer)
            self.stats.outer_packets_sent += 1
            self.stats.outer_bytes_sent += len(wrapped)
            self.stats.padding_bytes += record.padding_bytes

    def _apply_timing(self) -> None:
        """Apply minimal timing jitter.

        Real HTTPS traffic timing is controlled by TCP congestion control and
        application-level request/response patterns. Adding large artificial
        delays (24ms median) makes traffic distinguishable from normal HTTPS
        (median IAT ~0ms). Let TCP handle timing naturally.
        """
        jitter = self.timing_jitter_ms
        if jitter <= 0:
            return
        # Minimal jitter only — TCP stack handles real timing
        delay_ms = random.uniform(0.1, jitter)
        time.sleep(delay_ms / 1000.0)

    def _inject_cover(self, outer_transport) -> None:
        """Send cover traffic with realistic HTTPS-like burst model.

        Real HTTPS pattern: browser sends rapid request bursts, server
        responds with large data streams. Short idle gaps (100-500ms)
        between page loads, not long "human think time" pauses.
        """
        if not self.cover_enabled:
            return
        now = time.monotonic()
        if not hasattr(self, '_cover_burst_remaining'):
            self._cover_burst_remaining = 0
            self._cover_mode = 'OFF'

        if self._cover_mode == 'OFF':
            # Short idle: 100-800ms (like page load gaps, not human think time)
            idle = random.uniform(0.1, 0.8)
            if now - self._last_cover_time < idle:
                return
            self._cover_mode = 'ON'
            self._cover_burst_remaining = random.randint(5, max(8, self.cover_burst_max * 4))
            self._last_cover_time = now

        peer = self.learned_peer_outer or self.peer_outer
        if peer is None:
            return

        size = self._cover_packet_size()
        dummy = hashlib.shake_256(self._cover_key + os.urandom(12)).digest(size)
        outer_transport.send(dummy, peer)
        self.stats.outer_packets_sent += 1
        self.stats.outer_bytes_sent += len(dummy)

        self._cover_burst_remaining -= 1
        if self._cover_burst_remaining <= 0:
            self._cover_mode = 'OFF'
            self._last_cover_time = now
        else:
            # Intra-burst: near-zero delay (TCP controls real pacing)
            delay = random.uniform(0.001, 0.01)
            self._last_cover_time = now + delay

    def _cover_packet_size(self) -> int:
        """Sample cover packet size based on role to simulate real HTTPS asymmetry.

        Real HTTPS pattern: client sends small requests (60-200B),
        server sends large responses (1200-1400B TCP segments).
        Direction ratio should be ~0.25 (client:server bytes).
        """
        # Use the padding policy's pool for consistent size distribution
        policy = self.codec.padding_policy
        if hasattr(policy, '_pool') and policy._pool:
            r = random.random()
            cum = 0.0
            for size, w in zip(policy._pool, policy._weights):
                cum += w
                if r <= cum:
                    return size
            return policy._pool[-1]

        # Fallback: role-based sizing
        if self.is_server:
            # Server: mostly large packets (simulate HTTPS responses)
            r = random.random()
            if r < 0.75:
                s = int(random.gauss(1400, 30))
            elif r < 0.85:
                s = int(random.gauss(500, 100))
            else:
                s = int(random.gauss(60, 8))
        else:
            # Client: mostly small packets (simulate HTTPS requests)
            r = random.random()
            if r < 0.70:
                s = int(random.gauss(60, 8))
            elif r < 0.85:
                s = int(random.gauss(200, 60))
            else:
                s = int(random.gauss(500, 100))
        s = (max(40, min(s, 1400)) // 4) * 4
        return s

    def _generate_cover_response(self, outer_transport, peer_addr: tuple) -> None:
        """Send a fake response when receiving a cover dummy, making cover traffic bidirectional."""
        if not self.cover_bidirectional or not self.cover_enabled:
            return
        # Response delay: minimal (TCP controls real timing)
        time.sleep(random.uniform(0.001, 0.01))
        size = self._cover_packet_size()
        dummy = hashlib.shake_256(self._cover_key + os.urandom(12)).digest(size)
        outer_transport.send(dummy, peer_addr)
        self.stats.outer_packets_sent += 1
        self.stats.outer_bytes_sent += len(dummy)

    def _handle_outer(self, outer_transport, inner_sock: socket.socket) -> None:
        data, addr = outer_transport.recv()
        if self.learned_peer_outer is None and addr:
            self.learned_peer_outer = addr
            print(f"[{self.role}] learned peer endpoint from first packet: {addr[0]}:{addr[1]}")
        self.stats.outer_packets_received += 1
        self.stats.outer_bytes_received += len(data)
        # Strip noise prefix (AmneziaWG S4) before decoding
        data = self.junk_injector.strip_noise(data)
        try:
            fragment = self.codec.decode_record(data)
            packet, status = self.reassembler.accept(fragment)
        except AuthenticationError:
            self.stats.authentication_failures += 1
            return
        except ProtocolError:
            self.stats.reassembly_failures += 1
            return
        if status == "replay":
            self.stats.replay_drops += 1
            return
        if packet is None:
            return
        target = self.inner_forward or self.learned_inner_addr
        if target is None:
            self.stats.reassembly_failures += 1
            return
        inner_sock.sendto(packet, target)
        self.stats.inner_packets_received += 1
        self.stats.inner_bytes_received += len(packet)
