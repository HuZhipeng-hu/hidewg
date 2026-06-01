"""TLS 基础类 + 自签名证书生成 — 供 WebSocket 传输层使用。

其他传输模式 (UDP / TLS-direct / TLS-mux) 已移除，项目固定使用 WebSocket-over-TLS。
"""
from __future__ import annotations

import socket
import ssl
import struct
from pathlib import Path


# ---------------------------------------------------------------------------
# TLS 连接封装 — WebSocket 传输层的底层载体
# ---------------------------------------------------------------------------

class TLSConnection:
    """管理一条 TLS 连接的生命周期。

    服务端模式：监听 → accept → TLS 握手 → 读写。
    客户端模式：连接 → TLS 握手 → 读写。
    使用 2 字节大端长度前缀帧格式收发消息。
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
        conn: socket.socket | None = None,
    ):
        self._bind_addr = bind_addr
        self._server_side = server_side
        self._certfile = certfile
        self._keyfile = keyfile
        self._ca_certs = ca_certs
        self._peer_addr = peer_addr
        self._provided_conn = conn

        self._listen_sock: socket.socket | None = None
        self._conn: ssl.SSLSocket | None = None
        self._peer_name: tuple[str, int] | None = None
        self._recv_buf = bytearray()

    def _build_ssl_context(self) -> ssl.SSLContext:
        if self._server_side:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if self._certfile and self._keyfile:
                ctx.load_cert_chain(certfile=self._certfile, keyfile=self._keyfile)
            else:
                cert_path, key_path = _ensure_self_signed_cert()
                ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if self._ca_certs:
                ctx.load_verify_locations(self._ca_certs)
            else:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def bind(self) -> None:
        if self._provided_conn is not None:
            ctx = self._build_ssl_context()
            self._conn = ctx.wrap_socket(self._provided_conn, server_side=True)
            self._peer_name = self._provided_conn.getpeername()
            self._provided_conn.setblocking(False)
            return

        if self._server_side:
            self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self._bind_addr:
                self._listen_sock.bind(self._bind_addr)
            self._listen_sock.listen(8)
            self._listen_sock.setblocking(False)
        else:
            self._connect()

    def _connect(self) -> None:
        ctx = self._build_ssl_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(self._peer_addr)
        except OSError:
            sock.close()
            return
        self._conn = ctx.wrap_socket(sock, server_side=False, server_hostname=self._peer_addr[0])
        self._conn.setblocking(False)
        self._peer_name = self._peer_addr
        print(f"[tls] connected to {self._peer_addr[0]}:{self._peer_addr[1]}")

    def recv(self) -> tuple[bytes, tuple[str, int]]:
        if self._conn is None:
            if self._server_side and self._listen_sock is not None:
                self._accept_server()
            elif not self._server_side:
                self._connect()
            raise BlockingIOError

        try:
            chunk = self._conn.recv(65535)
            if not chunk:
                raise ConnectionError("TLS connection closed")
            self._recv_buf.extend(chunk)
        except (ssl.SSLError, OSError) as exc:
            if isinstance(exc, ssl.SSLWantReadError):
                raise BlockingIOError
            self._conn.close()
            self._conn = None
            raise BlockingIOError

        while len(self._recv_buf) >= 2:
            msg_len = struct.unpack("!H", self._recv_buf[:2])[0]
            if len(self._recv_buf) < 2 + msg_len:
                break
            msg = bytes(self._recv_buf[2 : 2 + msg_len])
            del self._recv_buf[: 2 + msg_len]
            return msg, self._peer_name or ("", 0)

        raise BlockingIOError

    def send(self, data: bytes, _addr: tuple[str, int] | None = None) -> None:
        if self._conn is None:
            return
        frame = struct.pack("!H", len(data)) + data
        try:
            self._conn.sendall(frame)
        except (ssl.SSLError, OSError):
            self._conn.close()
            self._conn = None

    def fileno(self) -> int:
        if self._conn is not None:
            return self._conn.fileno()
        if self._listen_sock is not None:
            return self._listen_sock.fileno()
        raise RuntimeError("no socket available")

    @property
    def has_connection(self) -> bool:
        return self._conn is not None

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._listen_sock is not None:
            self._listen_sock.close()
            self._listen_sock = None

    def _accept_server(self) -> None:
        if self._listen_sock is None:
            return
        ctx = self._build_ssl_context()
        conn, addr = self._listen_sock.accept()
        try:
            self._conn = ctx.wrap_socket(conn, server_side=True)
            self._conn.setblocking(False)
            self._peer_name = addr
            print(f"[tls] accepted from {addr[0]}:{addr[1]}")
        except ssl.SSLError:
            conn.close()


# ---------------------------------------------------------------------------
# 自签名证书生成
# ---------------------------------------------------------------------------

def _ensure_self_signed_cert() -> tuple[Path, Path]:
    """在 .hidewg/tls/ 下生成自签名证书（如不存在）。"""
    cert_dir = Path(".hidewg/tls")
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "server.pem"
    key_path = cert_dir / "server-key.pem"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HideWG"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[tls] generated self-signed cert: {cert_path}")
    except ImportError:
        import subprocess
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost/O=HideWG",
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[tls] generated self-signed cert via openssl: {cert_path}")

    return cert_path, key_path


def generate_cert(output_dir: str = ".hidewg/tls", days: int = 365, cn: str = "localhost") -> tuple[str, str]:
    """生成自签名 TLS 证书。返回 (cert_path, key_path)。"""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / "server.pem"
    key_path = out / "server-key.pem"

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HideWG"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        import subprocess
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", str(days), "-nodes",
            f"/CN={cn}/O=HideWG",
        ]
        subprocess.run(cmd, check=True, capture_output=True)

    return str(cert_path), str(key_path)
