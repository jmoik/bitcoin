#!/usr/bin/env python3
"""Small loopback-only faucet for the disposable gsr-net Signet."""

from __future__ import annotations

import html
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs


HOST = "127.0.0.1"
PORT = int(os.environ.get("GSR_FAUCET_PORT", "8081"))
AMOUNT = os.environ.get("GSR_FAUCET_AMOUNT", "1.0")
COOLDOWN = int(os.environ.get("GSR_FAUCET_COOLDOWN", "3600"))
STATE_PATH = Path(os.environ.get("GSR_FAUCET_STATE", "/var/lib/gsr-net/faucet-state.json"))
CLI = os.environ.get("GSR_BITCOIN_CLI", "/opt/gsr-net/bin/bitcoin-cli")
CLI_ARGS = [
    CLI,
    "-conf=/etc/gsr-net/bitcoin.conf",
    "-datadir=/var/lib/gsr-net",
    "-rpcwallet=miner",
]
LOCK = threading.Lock()


def rpc(*args: str) -> str:
    result = subprocess.run(
        [*CLI_ARGS, *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result.stdout.strip()


def load_state() -> dict[str, dict[str, float]]:
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(state, dict):
            return state
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {"addresses": {}, "ips": {}}


def save_state(state: dict[str, dict[str, float]]) -> None:
    STATE_PATH.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    STATE_PATH.chmod(0o600)


def page(message: str = "", success: bool = False) -> bytes:
    notice = ""
    if message:
        kind = "success" if success else "error"
        notice = f'<p class="{kind}">{html.escape(message)}</p>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gsr-net faucet</title>
  <style>
    :root {{ color-scheme: dark; font-family: system-ui, sans-serif; }}
    body {{ margin: 0; background: #11131a; color: #eef1f7; }}
    main {{ max-width: 42rem; margin: 8vh auto; padding: 2rem; }}
    section {{ background: #1b1f2a; border: 1px solid #32394b; border-radius: 14px; padding: 2rem; }}
    h1 {{ margin-top: 0; }}
    label {{ display: block; margin-bottom: .5rem; }}
    input {{ box-sizing: border-box; width: 100%; padding: .85rem; border-radius: 8px; border: 1px solid #4a536b; background: #0e1016; color: inherit; }}
    button {{ margin-top: 1rem; padding: .8rem 1.2rem; border: 0; border-radius: 8px; background: #f5a623; color: #17120a; font-weight: 700; cursor: pointer; }}
    .muted {{ color: #aeb6c8; }} .success {{ color: #6fe3a1; overflow-wrap: anywhere; }} .error {{ color: #ff8b8b; }}
    a {{ color: #7db7ff; }}
  </style>
</head>
<body><main><section>
  <h1>gsr-net faucet</h1>
  <p class="muted">Request {html.escape(AMOUNT)} experimental BTC on gsr-net. These coins have no value.</p>
  {notice}
  <form method="post" action="/faucet/claim">
    <label for="address">Your gsr-net address</label>
    <input id="address" name="address" placeholder="tb1..." required maxlength="100" autocomplete="off">
    <button type="submit">Send {html.escape(AMOUNT)} BTC</button>
  </form>
  <p class="muted">One request per address and IP every {COOLDOWN // 60} minutes.</p>
  <p><a href="/">Open block explorer</a></p>
</section></main></body></html>""".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "gsr-net-faucet/1"

    def client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",")[-1].strip() if forwarded else self.client_address[0]

    def respond(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/healthz":
            self.respond(200, b"ok\n", "text/plain; charset=utf-8")
        elif self.path.rstrip("/") in ("", "/faucet"):
            self.respond(200, page())
        else:
            self.respond(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if self.path.rstrip("/") not in ("/claim", "/faucet/claim"):
            self.respond(404, b"not found\n", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self.respond(400, page("Invalid request."))
            return
        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "application/json" in content_type:
            try:
                address = str(json.loads(body).get("address", "")).strip()
            except (json.JSONDecodeError, AttributeError):
                address = ""
        else:
            address = parse_qs(body).get("address", [""])[0].strip()
        if not address or len(address) > 100:
            self.respond(400, page("Enter a valid gsr-net address."))
            return

        try:
            validation = json.loads(rpc("validateaddress", address))
            if not validation.get("isvalid"):
                raise ValueError("invalid address")
        except (RuntimeError, ValueError, json.JSONDecodeError):
            self.respond(400, page("That is not a valid Signet address."))
            return

        now = time.time()
        ip = self.client_ip()
        with LOCK:
            state = load_state()
            addresses = state.setdefault("addresses", {})
            ips = state.setdefault("ips", {})
            last = max(float(addresses.get(address, 0)), float(ips.get(ip, 0)))
            remaining = int(COOLDOWN - (now - last))
            if remaining > 0:
                self.respond(429, page(f"Please wait about {(remaining + 59) // 60} minutes before requesting again."))
                return
            try:
                txid = rpc("sendtoaddress", address, AMOUNT, "gsr-net faucet")
            except RuntimeError as error:
                self.respond(503, page(f"Faucet payment failed: {error}"))
                return
            addresses[address] = now
            ips[ip] = now
            cutoff = now - 7 * 24 * 60 * 60
            state["addresses"] = {key: value for key, value in addresses.items() if float(value) >= cutoff}
            state["ips"] = {key: value for key, value in ips.items() if float(value) >= cutoff}
            save_state(state)
        self.respond(200, page(f"Sent {AMOUNT} BTC. Transaction: {txid}", True))

    def log_message(self, message: str, *args: object) -> None:
        print(f"{self.client_ip()} - {message % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
