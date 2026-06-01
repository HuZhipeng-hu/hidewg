from __future__ import annotations

import argparse
import json
import os
import signal
from pathlib import Path

from .adapter import HideWGProxy
from .config import load_config
from .transport import generate_cert
from .verify import run_verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hidewg", description="HideWG protocol feature hiding prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run HideWG client or server")
    run_parser.add_argument("--role", choices=["client", "server"], required=True)
    run_parser.add_argument("--config", required=True)

    verify_parser = subparsers.add_parser("verify", help="run unified verification")
    verify_parser.add_argument("--config", default=None)
    verify_parser.add_argument("--output", default="artifacts")

    status_parser = subparsers.add_parser("status", help="export current runtime state")
    status_parser.add_argument("--output", default="state.json")
    status_parser.add_argument("--state", default=None, help="state file to read; defaults to .hidewg/*_state.json")

    stop_parser = subparsers.add_parser("stop", help="stop foreground proxy started earlier")
    stop_parser.add_argument("--role", choices=["client", "server"], default=None)

    cert_parser = subparsers.add_parser("cert", help="generate self-signed TLS certificate")
    cert_parser.add_argument("--output-dir", default=".hidewg/tls")
    cert_parser.add_argument("--days", type=int, default=365)
    cert_parser.add_argument("--cn", default="localhost")

    args = parser.parse_args(argv)
    if args.command == "run":
        config = load_config(args.config)
        proxy = HideWGProxy(args.role, config)
        proxy.run()
        return 0
    if args.command == "verify":
        config = load_config(args.config)
        report = run_verify(config, args.output)
        print(json.dumps({"passed": report["passed"], "artifacts": report["artifacts"], "summary": report["summary"]}, indent=2))
        return 0 if report["passed"] else 2
    if args.command == "status":
        state = _read_state(args.state)
        Path(args.output).write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(state, indent=2, ensure_ascii=False))
        return 0
    if args.command == "stop":
        stopped = _stop(args.role)
        print(json.dumps({"stopped": stopped}, indent=2))
        return 0 if stopped else 1
    if args.command == "cert":
        cert_path, key_path = generate_cert(args.output_dir, args.days, args.cn)
        print(json.dumps({"certfile": cert_path, "keyfile": key_path}, indent=2))
        return 0
    return 1


def _read_state(path: str | None) -> dict[str, object]:
    candidates: list[Path]
    if path:
        candidates = [Path(path)]
    else:
        state_dir = Path(".hidewg")
        candidates = []
        if state_dir.exists():
            candidates.extend(state_dir.glob("*_state.json"))
        candidates.extend(Path("artifacts").glob("state.json"))
        candidates = sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True)
    for candidate in candidates:
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8"))
    return {"session_state": "UNKNOWN", "detail": "no state file found"}


def _stop(role: str | None) -> bool:
    pid_dir = Path(".hidewg")
    if not pid_dir.exists():
        return False
    patterns = [f"{role}.pid"] if role else ["client.pid", "server.pid"]
    stopped = False
    for pattern in patterns:
        pid_path = pid_dir / pattern
        if not pid_path.exists():
            continue
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            stopped = True
        except (OSError, ValueError):
            pass
    return stopped


if __name__ == "__main__":
    raise SystemExit(main())
