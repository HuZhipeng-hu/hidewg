"""WebSocket framing transport for HideWG.

Wraps HideWG records inside WebSocket binary frames over TLS,
making traffic indistinguishable from real-time web applications
(chat, streaming, notifications) to any network observer.

Frame format (RFC 6455):
  [FIN+OpCode][MASK+Len][Extended Len][Masking Key][Payload]
"""
from __future__ import annotations

import base64
import hashlib
import os
import random
import re
import socket
import struct
import time
from typing import Any

from .transport import TLSConnection

WS_MAGIC_GUID = b"258EAFA5-E914-47DA-95CA-5AB923F1E65B"
WS_OPCODE_BINARY = 0x2
WS_OPCODE_TEXT = 0x1
WS_OPCODE_CLOSE = 0x8
WS_OPCODE_PING = 0x9
WS_OPCODE_PONG = 0xA
WS_FIN = 0x80


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

def ws_encode_frame(opcode: int, payload: bytes, masked: bool = True) -> bytes:
    """Build a single WebSocket frame."""
    header = bytes([WS_FIN | opcode])
    mask_bit = 0x80 if masked else 0x00
    length = len(payload)

    if length < 126:
        header += bytes([mask_bit | length])
    elif length < 65536:
        header += bytes([mask_bit | 126]) + struct.pack("!H", length)
    else:
        header += bytes([mask_bit | 127]) + struct.pack("!Q", length)

    if masked:
        mask_key = os.urandom(4)
        masked_payload = bytearray(length)
        for i in range(length):
            masked_payload[i] = payload[i] ^ mask_key[i % 4]
        return header + mask_key + bytes(masked_payload)
    return header + payload


def ws_decode_frame(data: bytes) -> tuple[int, bytes, int]:
    """Decode a WebSocket frame. Returns (opcode, payload, total_bytes_consumed)."""
    if len(data) < 2:
        raise ValueError("incomplete frame header")
    byte1 = data[0]
    byte2 = data[1]
    opcode = byte1 & 0x0F
    masked = bool(byte2 & 0x80)
    payload_len = byte2 & 0x7F
    offset = 2

    if payload_len == 126:
        if len(data) < 4:
            raise ValueError("incomplete extended length")
        payload_len = struct.unpack("!H", data[2:4])[0]
        offset = 4
    elif payload_len == 127:
        if len(data) < 10:
            raise ValueError("incomplete extended length (64-bit)")
        payload_len = struct.unpack("!Q", data[2:10])[0]
        offset = 10

    if masked:
        if len(data) < offset + 4:
            raise ValueError("incomplete masking key")
        mask_key = data[offset : offset + 4]
        offset += 4

    if len(data) < offset + payload_len:
        raise ValueError("incomplete payload")

    payload = data[offset : offset + payload_len]
    if masked:
        payload = bytearray(payload)
        for i in range(len(payload)):
            payload[i] ^= mask_key[i % 4]
        payload = bytes(payload)

    return opcode, payload, offset + payload_len


def ws_client_handshake(host: str, path: str = "/ws") -> bytes:
    """Build an HTTP Upgrade request for the WebSocket handshake."""
    key = base64.b64encode(os.urandom(16)).decode()
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: chat\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        f"AppleWebKit/537.36\r\n"
        f"\r\n"
    ).encode()


def ws_compute_accept(key: str) -> str:
    """Compute Sec-WebSocket-Accept from the client key."""
    raw = key.encode() + WS_MAGIC_GUID
    return base64.b64encode(hashlib.sha1(raw).digest()).decode()


def ws_server_response(accept_key: str) -> bytes:
    """Build the HTTP 101 Switching Protocols response."""
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept_key.encode() + b"\r\n"
        b"\r\n"
    )


# ---------------------------------------------------------------------------
# Fake HTTP page served to non-WebSocket requests
# ---------------------------------------------------------------------------

FAKE_HTML = (
    b"<!DOCTYPE html><html><head><title>Welcome</title></head>"
    b"<body><h1>It works!</h1><p>Apache/2.4.58 (Unix)</p></body></html>"
)

HTTP_200_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: " + str(len(FAKE_HTML)).encode() + b"\r\n"
    b"Server: Apache/2.4.58 (Unix)\r\n"
    b"Connection: close\r\n"
    b"\r\n" + FAKE_HTML
)

HTTP_404_RESPONSE = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


# ---------------------------------------------------------------------------
# WebSocket Transport (client side)
# ---------------------------------------------------------------------------

class WSTransport:
    """WebSocket-over-TLS transport for HideWG.

    Client side: connects via TLS, performs WS upgrade, sends/receives binary frames.
    Server side: use HTTPMultiplexer which handles WS upgrade automatically.
    """

    def __init__(
        self,
        bind_addr: tuple[str, int] | None = None,
        *,
        server_side: bool = False,
        certfile: str | None = None,
        keyfile: str | None = None,
        ca_certs: str | None = None,
        peer_addr: tuple[str, int] | None = None,
        ws_path: str = "/ws",
    ):
        self._bind_addr = bind_addr
        self._server_side = server_side
        self._peer_addr = peer_addr
        self._ws_path = ws_path
        self._tls = TLSConnection(
            bind_addr,
            server_side=server_side,
            certfile=certfile,
            keyfile=keyfile,
            ca_certs=ca_certs,
            peer_addr=peer_addr,
        )
        self._upgraded = False
        self._recv_buf = bytearray()

    def bind(self) -> None:
        self._tls.bind()
        if not self._server_side and self._peer_addr:
            self._do_client_handshake()

    def _do_client_handshake(self) -> None:
        """Perform WebSocket upgrade after TLS connection."""
        handshake = ws_client_handshake(self._peer_addr[0], self._ws_path)
        try:
            self._tls._conn.sendall(handshake)
            # Read upgrade response (blocking, short timeout)
            self._tls._conn.setblocking(True)
            self._tls._conn.settimeout(5.0)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = self._tls._conn.recv(4096)
                if not chunk:
                    break
                resp += chunk
            self._tls._conn.setblocking(False)
            if b"101" in resp:
                self._upgraded = True
                print(f"[ws-client] WebSocket upgrade OK on {self._ws_path}")
            else:
                print(f"[ws-client] WebSocket upgrade failed: {resp[:80]}")
        except (OSError, TimeoutError) as exc:
            print(f"[ws-client] WebSocket handshake error: {exc}")

    def recv(self) -> tuple[bytes, tuple[str, int]]:
        if not self._upgraded:
            raise BlockingIOError

        # Read raw TLS data directly (bypass TLSConnection framing)
        try:
            while True:
                raw = self._tls._conn.recv(65535)
                if not raw:
                    raise ConnectionError("connection closed")
                self._recv_buf.extend(raw)
        except (BlockingIOError, ssl.SSLError):
            pass
        except (OSError, AttributeError):
            raise BlockingIOError

        # Try to decode a WebSocket frame from the buffer
        try:
            opcode, payload, consumed = ws_decode_frame(bytes(self._recv_buf))
            del self._recv_buf[:consumed]

            if opcode == WS_OPCODE_BINARY:
                return payload, self._tls._peer_name or ("", 0)
            elif opcode == WS_OPCODE_PING:
                pong = ws_encode_frame(WS_OPCODE_PONG, payload, masked=True)
                self._tls._conn.sendall(pong)
                raise BlockingIOError
            elif opcode == WS_OPCODE_PONG:
                raise BlockingIOError
            elif opcode == WS_OPCODE_CLOSE:
                raise ConnectionError("WebSocket closed")
            else:
                raise BlockingIOError
        except ValueError:
            # Incomplete frame — need more data
            raise BlockingIOError

    def send(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        if not self._upgraded:
            return
        frame = ws_encode_frame(WS_OPCODE_BINARY, data, masked=True)
        try:
            self._tls._conn.sendall(frame)
        except (OSError, AttributeError):
            pass

    def fileno(self) -> int:
        return self._tls.fileno()

    def close(self) -> None:
        if self._upgraded:
            try:
                close_frame = ws_encode_frame(WS_OPCODE_CLOSE, b"", masked=True)
                self._tls._conn.sendall(close_frame)
            except OSError:
                pass
        self._tls.close()
        self._upgraded = False


# Need ssl import for recv()
import ssl


# ---------------------------------------------------------------------------
# HTTP Multiplexer — auto-detect TLS / WebSocket / HTTP
# ---------------------------------------------------------------------------

_TLS_FIRST_BYTES = frozenset(
    {bytes([0x16, v]) for v in range(0x01, 0x05)}
)


class HTTPMultiplexer:
    """TCP listener that auto-detects incoming connections.

    Detection order:
    1. TLS Client Hello (0x16 0x03) → TLS handshake
       a. WebSocket Upgrade → binary frame transport (HideWG)
       b. Direct TLS → HideWG (backward compatible)
    2. HTTP request → serve fake webpage
    3. Other → close
    """

    def __init__(
        self,
        bind_addr: tuple[str, int],
        certfile: str | None = None,
        keyfile: str | None = None,
        ca_certs: str | None = None,
        tls_terminate: bool = False,
    ):
        self._bind_addr = bind_addr
        self._certfile = certfile
        self._keyfile = keyfile
        self._ca_certs = ca_certs
        self._tls_terminate = tls_terminate  # True = TLS handled by upstream (nginx)
        self._listen_sock: socket.socket | None = None
        self._active_tls: TLSConnection | None = None
        self._active_ws: _ServerWSHandler | None = None

    def bind(self) -> None:
        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind(self._bind_addr)
        self._listen_sock.listen(16)
        self._listen_sock.setblocking(False)
        print(f"[http-mux] listening on {self._bind_addr[0]}:{self._bind_addr[1]}")

    def recv(self) -> tuple[bytes, tuple[str, int]]:
        # Try reading from active WebSocket connection
        if self._active_ws is not None:
            try:
                return self._active_ws.recv()
            except BlockingIOError:
                pass
            except (ConnectionError, OSError):
                self._active_ws.close()
                self._active_ws = None

        # Try reading from active direct-TLS connection
        if self._active_tls is not None:
            try:
                return self._active_tls.recv()
            except BlockingIOError:
                pass
            except (ConnectionError, OSError):
                self._active_tls.close()
                self._active_tls = None

        # Accept new connections
        self._accept_new_connections()

        # Retry reading
        if self._active_ws is not None:
            try:
                return self._active_ws.recv()
            except BlockingIOError:
                pass
        if self._active_tls is not None:
            try:
                return self._active_tls.recv()
            except BlockingIOError:
                pass

        raise BlockingIOError

    def send(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        if self._active_ws is not None:
            self._active_ws.send(data)
        elif self._active_tls is not None:
            self._active_tls.send(data, addr)

    def fileno(self) -> int:
        if self._listen_sock is None:
            raise RuntimeError("not bound")
        return self._listen_sock.fileno()

    def connection_fileno(self) -> int | None:
        """Return the active connection fd (for selector registration)."""
        if self._active_ws is not None:
            try:
                return self._active_ws._conn.fileno()
            except (OSError, AttributeError, ValueError):
                return None
        if self._active_tls is not None and self._active_tls.has_connection:
            try:
                return self._active_tls._conn.fileno()
            except (OSError, AttributeError):
                return None
        return None

    def close(self) -> None:
        if self._active_ws is not None:
            self._active_ws.close()
            self._active_ws = None
        if self._active_tls is not None:
            self._active_tls.close()
            self._active_tls = None
        if self._listen_sock is not None:
            self._listen_sock.close()
            self._listen_sock = None

    # -- internal --

    def _accept_new_connections(self) -> None:
        if self._listen_sock is None:
            return
        for _ in range(16):
            try:
                conn, addr = self._listen_sock.accept()
            except BlockingIOError:
                break

            # Peek at first bytes
            try:
                conn.setblocking(True)
                conn.settimeout(0.5)
                first = conn.recv(5, socket.MSG_PEEK)
            except OSError:
                conn.close()
                continue

            if len(first) >= 2 and first[:2] in _TLS_FIRST_BYTES:
                self._handle_tls_connection(conn, addr)
            elif len(first) >= 3 and first[:3] in (
                b"GET", b"HEA", b"POS", b"PUT", b"DEL",
                b"OPT", b"PAT", b"TRA", b"CON",
            ):
                if self._tls_terminate:
                    # TLS terminated by upstream (nginx) — check for WS upgrade
                    self._handle_plain_ws_upgrade(conn, addr)
                else:
                    self._handle_http_connection(conn, addr)
            else:
                conn.close()

    def _handle_tls_connection(self, conn: socket.socket, addr: tuple) -> None:
        """Accept TLS, then detect WebSocket upgrade vs direct TLS."""
        from .transport import _ensure_self_signed_cert

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if self._certfile and self._keyfile:
                ctx.load_cert_chain(certfile=self._certfile, keyfile=self._keyfile)
            else:
                cert_path, key_path = _ensure_self_signed_cert()
                ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            tls_conn.setblocking(True)
            tls_conn.settimeout(3.0)
        except ssl.SSLError:
            conn.close()
            return

        # Try to read first application data to detect WebSocket upgrade
        try:
            data = tls_conn.recv(4096)
            if not data:
                tls_conn.close()
                return
        except (OSError, TimeoutError):
            tls_conn.close()
            return

        # Check if it's a WebSocket upgrade request
        if b"websocket" in data.lower() and b"upgrade" in data.lower():
            print(f"[http-mux] WebSocket detected from {addr[0]}:{addr[1]}")
            self._handle_ws_upgrade(tls_conn, addr, data)
        else:
            # Direct TLS (backward compatible with existing HideWG clients)
            print(f"[http-mux] TLS (direct) detected from {addr[0]}:{addr[1]}")
            tls_conn.setblocking(False)
            transport = TLSConnection(conn=tls_conn, server_side=True)
            transport._conn = tls_conn
            transport._peer_name = addr
            self._active_tls = transport

    def _handle_ws_upgrade(self, tls_conn: ssl.SSLSocket, addr: tuple, initial_data: bytes) -> None:
        """Complete WebSocket upgrade and create frame handler."""
        # Parse Sec-WebSocket-Key from the request
        match = re.search(rb"Sec-WebSocket-Key:\s*(\S+)", initial_data)
        if not match:
            tls_conn.close()
            return

        key = match.group(1).decode()
        accept = ws_compute_accept(key)
        response = ws_server_response(accept)

        try:
            tls_conn.sendall(response)
            tls_conn.setblocking(False)
        except OSError:
            tls_conn.close()
            return

        ws_handler = _ServerWSHandler(tls_conn, addr)
        # Pass any data that came after the HTTP headers
        header_end = initial_data.find(b"\r\n\r\n")
        if header_end >= 0:
            leftover = initial_data[header_end + 4:]
            if leftover:
                ws_handler._recv_buf.extend(leftover)
        self._active_ws = ws_handler
        print(f"[http-mux] WebSocket upgrade complete for {addr[0]}:{addr[1]}")

    def _handle_http_connection(self, conn: socket.socket, addr: tuple) -> None:
        """Serve a fake webpage to regular HTTP requests."""
        try:
            conn.setblocking(True)
            conn.settimeout(3.0)
            conn.recv(8192)  # drain request
            conn.sendall(HTTP_200_RESPONSE)
            print(f"[http-mux] HTTP request from {addr[0]}:{addr[1]} → served fake page")
        except OSError:
            pass
        finally:
            conn.close()

    def _handle_plain_ws_upgrade(self, conn: socket.socket, addr: tuple) -> None:
        """Handle plain HTTP WebSocket upgrade (TLS terminated by upstream nginx)."""
        try:
            conn.setblocking(True)
            conn.settimeout(3.0)
            data = conn.recv(4096)
            if not data:
                conn.close()
                return

            # Check if it's a WebSocket upgrade
            if b"websocket" not in data.lower() or b"upgrade" not in data.lower():
                # Not a WebSocket upgrade — serve fake page
                conn.sendall(HTTP_200_RESPONSE)
                conn.close()
                return

            # Parse Sec-WebSocket-Key and send upgrade response
            match = re.search(rb"Sec-WebSocket-Key:\s*(\S+)", data)
            if not match:
                conn.close()
                return

            key = match.group(1).decode()
            accept = ws_compute_accept(key)
            response = ws_server_response(accept)
            conn.sendall(response)

            conn.setblocking(False)
            ws_handler = _ServerWSHandler(conn, addr)
            # Pass any data after the HTTP headers
            header_end = data.find(b"\r\n\r\n")
            if header_end >= 0:
                leftover = data[header_end + 4:]
                if leftover:
                    ws_handler._recv_buf.extend(leftover)
            self._active_ws = ws_handler
            print(f"[http-mux] WebSocket (plain, via nginx) from {addr[0]}:{addr[1]}")
        except (OSError, TimeoutError):
            conn.close()


# ---------------------------------------------------------------------------
# Server-side WebSocket frame handler
# ---------------------------------------------------------------------------

class _ServerWSHandler:
    """Handles WebSocket binary frames on the server side (unmasked)."""

    def __init__(self, conn: ssl.SSLSocket, addr: tuple):
        self._conn = conn
        self._addr = addr
        self._recv_buf = bytearray()

    def recv(self) -> tuple[bytes, tuple[str, int]]:
        # Read raw TLS data
        try:
            while True:
                raw = self._conn.recv(65535)
                if not raw:
                    raise ConnectionError("closed")
                self._recv_buf.extend(raw)
        except (BlockingIOError, ssl.SSLError):
            pass
        except OSError:
            raise BlockingIOError

        # Decode WebSocket frame
        try:
            opcode, payload, consumed = ws_decode_frame(bytes(self._recv_buf))
            del self._recv_buf[:consumed]

            if opcode == WS_OPCODE_BINARY:
                return payload, self._addr
            elif opcode == WS_OPCODE_PING:
                pong = ws_encode_frame(WS_OPCODE_PONG, payload, masked=False)
                self._conn.sendall(pong)
                raise BlockingIOError
            elif opcode == WS_OPCODE_PONG:
                raise BlockingIOError
            elif opcode == WS_OPCODE_CLOSE:
                raise ConnectionError("WebSocket closed")
            raise BlockingIOError
        except ValueError:
            raise BlockingIOError

    def send(self, data: bytes) -> None:
        frame = ws_encode_frame(WS_OPCODE_BINARY, data, masked=False)
        try:
            self._conn.sendall(frame)
        except OSError:
            pass

    def close(self) -> None:
        try:
            close_frame = ws_encode_frame(WS_OPCODE_CLOSE, b"", masked=False)
            self._conn.sendall(close_frame)
        except OSError:
            pass
        self._conn.close()
