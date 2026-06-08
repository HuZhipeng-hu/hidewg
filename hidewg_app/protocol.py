from __future__ import annotations

import hashlib
import os
import random
import struct
import time
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


VERSION = 1
FLAG_FRAGMENTED = 0x01
NONCE_LEN = 12
TAG_LEN = 16
HEADER = struct.Struct("!BBIQIHHHH")


class ProtocolError(Exception):
    """Raised for malformed HideWG records."""


class AuthenticationError(ProtocolError):
    """Raised when a HideWG record fails authentication."""


@dataclass(frozen=True)
class EncodedRecord:
    data: bytes
    sequence: int
    message_id: int
    fragment_index: int
    fragment_count: int
    padding_bytes: int


@dataclass(frozen=True)
class DecodedFragment:
    sequence: int
    session_id: int
    message_id: int
    fragment_index: int
    fragment_count: int
    payload: bytes
    padding_bytes: int


class PaddingPolicy:
    def __init__(self, buckets: Iterable[int] | None = None, jitter_bucket_chance: float = 0.20,
                 bucket_drift: int = 0):
        self.base_buckets = sorted({int(bucket) for bucket in (buckets or [96, 128, 192, 256, 384, 512, 768, 1024, 1280])})
        self.buckets = list(self.base_buckets)
        if not self.buckets:
            raise ValueError("padding buckets must not be empty")
        self.jitter_bucket_chance = max(0.0, min(1.0, float(jitter_bucket_chance)))
        self.bucket_drift = max(0, int(bucket_drift))
        self._drift_counter = 0

    def _maybe_drift(self) -> None:
        """Periodically randomize bucket boundaries to defeat exact-size clustering."""
        if self.bucket_drift <= 0:
            return
        self._drift_counter += 1
        # Re-drift every 32 packets to avoid a static pattern
        if self._drift_counter % 32 == 0:
            self.buckets = sorted(
                max(64, b + random.randint(-self.bucket_drift, self.bucket_drift))
                for b in self.base_buckets
            )

    def padded_length(self, payload_len: int) -> int:
        self._maybe_drift()
        for index, bucket in enumerate(self.buckets):
            if payload_len <= bucket:
                if index + 1 < len(self.buckets) and random.random() < self.jitter_bucket_chance:
                    return self.buckets[index + 1]
                return bucket
        return payload_len


class AdaptivePaddingPolicy(PaddingPolicy):
    """Padding policy that adapts bucket selection to flatten the output length distribution.

    Tracks recent bucket choices in a sliding window and biases toward
    under-represented buckets, making the output distribution closer to uniform.
    This defeats ML classifiers that learn from packet-length histograms.

    AmneziaWG S4-inspired: applies Gaussian jitter around the chosen bucket
    target to break exact bucket alignment that statistical classifiers (Random
    Forest) exploit via histogram bin counts.
    """

    def __init__(
        self,
        buckets: Iterable[int] | None = None,
        jitter_bucket_chance: float = 0.15,
        window_size: int = 128,
        adapt_strength: float = 0.6,
        bucket_drift: int = 0,
        bucket_jitter_sigma: float = 15.0,
    ):
        super().__init__(buckets, jitter_bucket_chance, bucket_drift)
        self.window_size = window_size
        self.adapt_strength = max(0.0, min(1.0, adapt_strength))
        self.bucket_jitter_sigma = max(0.0, float(bucket_jitter_sigma))
        self._history: list[int] = []
        self._bucket_counts: dict[int, int] = {b: 0 for b in self.buckets}
        self._total = 0

    def padded_length(self, payload_len: int) -> int:
        # Find the natural bucket for this payload
        natural_bucket = None
        for bucket in self.buckets:
            if payload_len <= bucket:
                natural_bucket = bucket
                break
        if natural_bucket is None:
            return payload_len

        # With adapt_strength probability, choose an alternative bucket to flatten distribution
        if random.random() < self.adapt_strength:
            chosen = self._balanced_choice(natural_bucket, payload_len)
        else:
            idx = self.buckets.index(natural_bucket)
            if idx + 1 < len(self.buckets) and random.random() < self.jitter_bucket_chance:
                chosen = self.buckets[idx + 1]
            else:
                chosen = natural_bucket

        # AmneziaWG S4-style: Gaussian jitter around bucket target
        # Breaks exact bucket alignment for statistical classifiers
        if self.bucket_jitter_sigma > 0:
            jitter = int(random.gauss(0, self.bucket_jitter_sigma))
            chosen = max(payload_len, chosen + jitter)

        self._record(chosen)
        return chosen

    def _balanced_choice(self, natural_bucket: int, payload_len: int) -> int:
        """Pick a bucket (>= payload_len) weighted inversely by its recent frequency."""
        # Only consider buckets that can fit the payload
        valid_buckets = [b for b in self.buckets if b >= payload_len]
        if not valid_buckets:
            return natural_bucket
        if self._total == 0:
            return natural_bucket
        expected = self._total / len(self.buckets)
        weights = []
        for b in valid_buckets:
            count = self._bucket_counts.get(b, 0)
            w = max(0.5, (expected + 1.0) / (count + 1.0))
            if b == natural_bucket:
                w *= 1.5
            weights.append(w)
        total_w = sum(weights)
        r = random.random() * total_w
        cumulative = 0.0
        for b, w in zip(valid_buckets, weights):
            cumulative += w
            if r <= cumulative:
                return b
        return valid_buckets[-1]

    def _record(self, bucket: int) -> None:
        self._history.append(bucket)
        self._bucket_counts[bucket] = self._bucket_counts.get(bucket, 0) + 1
        self._total += 1
        # Evict old entries when window is full
        while len(self._history) > self.window_size:
            old = self._history.pop(0)
            self._bucket_counts[old] = max(0, self._bucket_counts.get(old, 0) - 1)
            self._total -= 1


class ContinuousPaddingPolicy(PaddingPolicy):
    """Continuous padding distribution to defeat discrete-bucket fingerprinting.

    Instead of padding to fixed bucket boundaries, samples target lengths from
    a continuous distribution.  The default "multimodal" distribution mimics
    real UDP traffic (QUIC, DNS, game, VoIP) which has multiple size peaks,
    making the output indistinguishable from normal internet traffic.

    Other distributions (uniform / triangular / beta) are available for
    experimentation.  The distribution is periodically reshaped to avoid
    a static pattern.
    """

    def __init__(
        self,
        min_len: int = 64,
        max_len: int = 1280,
        distribution: str = "multimodal",
        reshape_interval: int = 64,
    ):
        # Still call parent init for compatibility (buckets used as fallback)
        super().__init__(buckets=[min_len, max_len], jitter_bucket_chance=0.0)
        self.min_len = max(1, min_len)
        self.max_len = max(self.min_len + 1, max_len)
        self.distribution = distribution
        self.reshape_interval = reshape_interval
        self._counter = 0
        self._mode = random.uniform(self.min_len, self.max_len)  # triangular mode

    def _maybe_reshape(self) -> None:
        """Periodically shift the distribution shape to avoid static patterns."""
        self._counter += 1
        if self._counter % self.reshape_interval == 0:
            self._mode = random.uniform(self.min_len, self.max_len)

    def padded_length(self, payload_len: int) -> int:
        self._maybe_reshape()
        target = self._sample_target()
        return max(payload_len, target)

    def _sample_target(self) -> int:
        if self.distribution == "multimodal":
            # Mimic real UDP mix: peaks at ~85B (ACK/DNS), ~200B (game),
            # ~900B (QUIC data), with ~120B (VoIP) fill.
            # Extra Gaussian jitter smooths peaks into a continuous distribution,
            # defeating histogram-binning classifiers (Random Forest).
            r = random.random()
            if r < 0.25:
                base = random.gauss(85, 30)
            elif r < 0.55:
                base = random.gauss(900, 300)
            elif r < 0.75:
                base = random.gauss(200, 80)
            elif r < 0.90:
                base = random.gauss(120, 40)
            else:
                base = random.uniform(64, 1350)
            # Continuous jitter to smooth distribution peaks
            target = int(base + random.gauss(0, 25))
            return max(self.min_len, min(target, self.max_len))
        elif self.distribution == "uniform":
            return random.randint(self.min_len, self.max_len)
        elif self.distribution == "triangular":
            return int(random.triangular(self.min_len, self.max_len, self._mode))
        elif self.distribution == "beta":
            a = random.uniform(0.5, 2.0)
            b = random.uniform(0.5, 2.0)
            sample = random.betavariate(a, b)
            return int(self.min_len + sample * (self.max_len - self.min_len))
        else:
            return random.randint(self.min_len, self.max_len)


class HideWGCodec:
    # Pre-allocated random buffer size (avoids per-packet os.urandom calls)
    _RAND_BUF_SIZE = 65536

    def __init__(
        self,
        shared_secret: str | bytes,
        session_id: int = 0x48445747,
        max_fragment_payload: int = 1300,
        min_fragment_payload: int = 0,
        padding_policy: PaddingPolicy | None = None,
    ):
        if isinstance(shared_secret, str):
            secret_bytes = shared_secret.encode("utf-8")
        else:
            secret_bytes = shared_secret
        if not secret_bytes:
            raise ValueError("shared_secret must not be empty")
        self.key = hashlib.sha256(b"hidewg-v1:" + secret_bytes).digest()
        self.session_id = int(session_id) & 0xFFFFFFFF
        self.max_fragment_payload = int(max_fragment_payload)
        if self.max_fragment_payload <= 0 or self.max_fragment_payload > 65535:
            raise ValueError("max_fragment_payload must be in 1..65535")
        # Random byte buffer: pre-generate and slice to avoid per-packet syscalls
        self._rand_buf = os.urandom(self._RAND_BUF_SIZE)
        self._rand_pos = self._RAND_BUF_SIZE
        if min_fragment_payload > 0:
            self.min_fragment_payload = min(int(min_fragment_payload), self.max_fragment_payload)
        else:
            self.min_fragment_payload = max(64, self.max_fragment_payload // 3)
        self.padding_policy = padding_policy or PaddingPolicy()
        self._sequence = random.getrandbits(32)
        self._message_id = random.getrandbits(32)
        # ChaCha20Poly1305 AEAD for encryption + authentication in a single call (~682 MB/s)
        self._aead = ChaCha20Poly1305(self.key)
        self._header_size = HEADER.size

    def _random_split(self, payload: bytes) -> list[bytes]:
        """Split payload into randomly-sized fragments to break equal-length patterns."""
        if len(payload) <= self.max_fragment_payload:
            return [payload]  # No copy needed for small packets
        chunks = []
        offset = 0
        remaining = len(payload)
        while remaining > self.max_fragment_payload:
            size = random.randint(self.min_fragment_payload, self.max_fragment_payload)
            chunks.append(payload[offset:offset + size])
            offset += size
            remaining -= size
        if remaining > 0:
            chunks.append(payload[offset:])
        return chunks

    def encode_packet(self, payload: bytes) -> list[EncodedRecord]:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        chunks = self._random_split(payload) or [b""]
        message_id = self._next_message_id()
        records: list[EncodedRecord] = []
        for fragment_index, chunk in enumerate(chunks):
            sequence = self._next_sequence()
            padded_len = self.padding_policy.padded_length(len(chunk))
            padding_len = padded_len - len(chunk)
            body_plain = chunk + self._fast_urandom(padding_len)
            flags = FLAG_FRAGMENTED if len(chunks) > 1 else 0
            header_plain = HEADER.pack(
                VERSION,
                flags,
                self.session_id,
                sequence,
                message_id,
                fragment_index,
                len(chunks),
                len(chunk),
                padding_len,
            )
            nonce = self._nonce()
            # Single AEAD call encrypts header + body, produces ciphertext + 16-byte tag
            plaintext = header_plain + body_plain
            ct_tag = self._aead.encrypt(nonce, plaintext, b"")
            records.append(
                EncodedRecord(
                    data=nonce + ct_tag,
                    sequence=sequence,
                    message_id=message_id,
                    fragment_index=fragment_index,
                    fragment_count=len(chunks),
                    padding_bytes=padding_len,
                )
            )
        return records

    def decode_record(self, record: bytes) -> DecodedFragment:
        min_len = NONCE_LEN + HEADER.size + TAG_LEN
        if len(record) < min_len:
            raise ProtocolError("record is too short")
        nonce = record[:NONCE_LEN]
        ct_tag = record[NONCE_LEN:]
        try:
            plaintext = self._aead.decrypt(nonce, ct_tag, b"")
        except Exception:
            raise AuthenticationError("AEAD decryption failed")

        header_plain = plaintext[:HEADER.size]
        try:
            (
                version,
                flags,
                session_id,
                sequence,
                message_id,
                fragment_index,
                fragment_count,
                payload_len,
                padding_len,
            ) = HEADER.unpack(header_plain)
        except struct.error as exc:
            raise ProtocolError("invalid header") from exc
        if version != VERSION:
            raise ProtocolError("unsupported version")
        if session_id != self.session_id:
            raise ProtocolError("unexpected session id")
        if fragment_count == 0 or fragment_index >= fragment_count:
            raise ProtocolError("invalid fragment index")
        if fragment_count == 1 and (flags & FLAG_FRAGMENTED):
            raise ProtocolError("single fragment marked as fragmented")
        body_plain = plaintext[HEADER.size:]
        if payload_len + padding_len != len(body_plain):
            raise ProtocolError("body length does not match header")
        return DecodedFragment(
            sequence=sequence,
            session_id=session_id,
            message_id=message_id,
            fragment_index=fragment_index,
            fragment_count=fragment_count,
            payload=body_plain[:payload_len],
            padding_bytes=padding_len,
        )

    def _next_sequence(self) -> int:
        self._sequence = (self._sequence + 1) & 0xFFFFFFFFFFFFFFFF
        return self._sequence

    def _next_message_id(self) -> int:
        self._message_id = (self._message_id + 1) & 0xFFFFFFFF
        return self._message_id

    def _nonce(self) -> bytes:
        return self._fast_urandom(NONCE_LEN)

    def _fast_urandom(self, n: int) -> bytes:
        """Fast random bytes: slice from pre-generated buffer, refill when exhausted."""
        if n <= 0:
            return b""
        if self._rand_pos + n > self._RAND_BUF_SIZE:
            self._rand_buf = os.urandom(self._RAND_BUF_SIZE)
            self._rand_pos = 0
        result = self._rand_buf[self._rand_pos:self._rand_pos + n]
        self._rand_pos += n
        return result


class Reassembler:
    def __init__(self, replay_window: int = 4096, fragment_ttl: float = 30.0):
        self.replay_window = int(replay_window)
        self.fragment_ttl = float(fragment_ttl)
        self._seen: set[int] = set()
        self._seen_order: list[int] = []
        self._pending: dict[tuple[int, int], tuple[float, dict[int, bytes], int]] = {}

    def accept(self, fragment: DecodedFragment) -> tuple[bytes | None, str]:
        self._expire()
        if fragment.sequence in self._seen:
            return None, "replay"
        self._seen.add(fragment.sequence)
        self._seen_order.append(fragment.sequence)
        if len(self._seen_order) > self.replay_window:
            old = self._seen_order.pop(0)
            self._seen.discard(old)

        if fragment.fragment_count == 1:
            return fragment.payload, "complete"

        key = (fragment.session_id, fragment.message_id)
        created, chunks, expected = self._pending.get(key, (time.monotonic(), {}, fragment.fragment_count))
        if expected != fragment.fragment_count or fragment.fragment_index in chunks:
            return None, "replay"
        chunks[fragment.fragment_index] = fragment.payload
        if len(chunks) == expected:
            payload = b"".join(chunks[index] for index in range(expected))
            self._pending.pop(key, None)
            return payload, "complete"
        self._pending[key] = (created, chunks, expected)
        return None, "pending"

    def _expire(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, (created, _chunks, _expected) in self._pending.items()
            if now - created > self.fragment_ttl
        ]
        for key in expired:
            self._pending.pop(key, None)

    @property
    def pending_count(self) -> int:
        self._expire()
        return len(self._pending)


class TrafficMimicryPolicy(PaddingPolicy):
    """Mimic real VoIP/WebSocket-chat traffic size distribution.

    Instead of creating hundreds of unique sizes through random jitter,
    this policy pre-computes a finite set of ~60 realistic sizes and
    samples from them with weighted probabilities, matching the unique
    size count of real HTTPS traffic (~70).

    Size clusters modeled after real WebSocket/HTTPS traffic:
    - ~60B: ACK/keepalive/control messages
    - ~200B: chat messages, JSON API responses
    - ~500B: small file chunks, rich messages
    - ~1200B: large data frames, image thumbnails
    """

    # Real traffic clusters: (mean, std, weight)
    # 来源: 真实 HTTPS 抓包统计 (tcp port 443, 34k packets)
    #   1440B: 71.8%, 54B: 9.2%, 60B: 4.1%, 66B: 4.3%, 90B: 1.3%
    CLUSTERS = [
        (60, 8, 0.15),      # TCP ACK/keepalive (~15%)
        (200, 60, 0.05),    # small data frames (~5%)
        (500, 100, 0.05),   # medium data (~5%)
        (1400, 30, 0.75),   # TCP MSS segments (~75%, 真实HTTPS主导包长)
    ]

    def __init__(self, min_size: int = 40, max_size: int = 1400,
                 jitter_std: float = 8.0, pool_size: int = 60):
        super().__init__(buckets=[min_size, max_size], jitter_bucket_chance=0.0)
        self.min_size = max(40, min_size)
        self.max_size = max(self.min_size + 1, max_size)
        # Pre-compute a finite pool of sizes and their weights
        self._pool, self._weights = self._build_pool(pool_size, jitter_std)

    def _build_pool(self, pool_size: int, jitter_std: float) -> tuple[list[int], list[float]]:
        """Generate a finite set of realistic packet sizes with weights."""
        raw_sizes = set()
        # Generate candidates from each cluster
        for mean, std, _weight in self.CLUSTERS:
            n = pool_size // len(self.CLUSTERS) + 2
            for _ in range(n * 3):
                s = int(random.gauss(mean, std))
                if jitter_std > 0:
                    s += int(random.gauss(0, jitter_std))
                s = max(self.min_size, min(s, self.max_size))
                # Quantize to 4-byte boundaries (real network stacks do this)
                s = (s // 4) * 4
                raw_sizes.add(s)
                if len(raw_sizes) >= pool_size:
                    break
            if len(raw_sizes) >= pool_size:
                break

        # Sort and limit
        pool = sorted(raw_sizes)[:pool_size]
        if not pool:
            pool = [self.min_size]

        # Assign weights proportional to cluster density
        weights = []
        for s in pool:
            w = 0.0
            for mean, std, cluster_w in self.CLUSTERS:
                dist = abs(s - mean) / max(std, 1.0)
                w += cluster_w * max(0.01, 2.0 - dist)  # Gaussian-like weight
            weights.append(w)

        total = sum(weights)
        weights = [w / total for w in weights]
        return pool, weights

    def padded_length(self, payload_len: int) -> int:
        # Weighted random sample from the pre-computed pool
        r = random.random()
        cum = 0.0
        for size, w in zip(self._pool, self._weights):
            cum += w
            if r <= cum:
                return max(payload_len, size)
        return max(payload_len, self._pool[-1])


class JunkInjector:
    """Inject random junk packets before real data, mimicking AmneziaWG's Jc/Jmin/Jmax.

    Also handles noise-prefix wrapping/unwrapping of HideWG records
    to break the discrete bucket size pattern (AmneziaWG S4).

    AmneziaWG S4-inspired random pre-padding adds extra random bytes (0 to
    s4_max) BEFORE the noise prefix, shifting the entire packet size and
    breaking exact bucket alignment that statistical classifiers exploit.
    The receiver strips both layers deterministically.
    """

    def __init__(self, count: int = 0, min_size: int = 64, max_size: int = 384,
                 noise_prefix_range: tuple[int, int] = (0, 0),
                 s4_padding_max: int = 0):
        self.count = count
        self.min_size = min_size
        self.max_size = max_size
        self.noise_prefix_range = noise_prefix_range
        self.s4_padding_max = max(0, int(s4_padding_max))
        self._sent = False

    def generate(self) -> list[bytes]:
        """Generate junk packets once at session start."""
        if self._sent or self.count <= 0:
            return []
        self._sent = True
        return [os.urandom(random.randint(self.min_size, self.max_size)) for _ in range(self.count)]

    def wrap_with_noise(self, record: bytes) -> bytes:
        """Prepend random noise bytes to break the discrete bucket pattern.

        Format: [1 byte: s4_len][s4 random bytes][1 byte: noise_len][noise bytes][record]

        Two layers:
        - S4 pre-padding (AmneziaWG-style): shifts the outer size continuously
        - Noise prefix: inner random bytes inside the shifted envelope

        The two 1-byte length indicators let the receiver strip both layers.
        """
        lo, hi = self.noise_prefix_range
        has_noise = hi > 0
        has_s4 = self.s4_padding_max > 0

        # S4 pre-padding layer (AmneziaWG S4)
        s4 = random.randint(0, self.s4_padding_max) if has_s4 else 0
        # Noise prefix layer
        n = random.randint(lo, hi) if has_noise else 0

        if s4 <= 0 and n <= 0:
            return record

        # Build format depends on which layers are active:
        # Both:   [s4_len][s4_bytes][noise_len][noise_bytes][record]
        # S4 only: [s4_len][s4_bytes][record]
        # Noise only: [noise_len][noise_bytes][record]
        parts = []
        if has_s4:
            parts.append(bytes([s4]))
            if s4 > 0:
                parts.append(os.urandom(s4))
        if has_noise:
            parts.append(bytes([n]))
            if n > 0:
                parts.append(os.urandom(n))
        parts.append(record)
        return b"".join(parts)

    def strip_noise(self, data: bytes) -> bytes:
        """Strip noise prefix (and S4 pre-padding) using length indicators.

        Format: [s4_len][s4_bytes][noise_len][noise_bytes][record]

        Strips both layers if present, otherwise falls back to single-layer.
        """
        lo, hi = self.noise_prefix_range
        has_noise = hi > 0
        has_s4 = self.s4_padding_max > 0

        if not has_noise and not has_s4:
            return data
        if len(data) < 2:
            return data

        # Try two-layer format: s4 + noise
        if has_s4 and has_noise:
            s4_len = data[0]
            if s4_len <= self.s4_padding_max and len(data) > 1 + s4_len:
                after_s4 = data[1 + s4_len:]
                if len(after_s4) >= 2:
                    noise_len = after_s4[0]
                    if lo <= noise_len <= hi and len(after_s4) > 1 + noise_len:
                        return after_s4[1 + noise_len:]

        # Single-layer: noise only
        if has_noise:
            noise_len = data[0]
            if lo <= noise_len <= hi and len(data) > 1 + noise_len:
                return data[1 + noise_len:]

        # Single-layer: S4 only
        if has_s4:
            s4_len = data[0]
            if s4_len <= self.s4_padding_max and len(data) > 1 + s4_len:
                return data[1 + s4_len:]

        return data
