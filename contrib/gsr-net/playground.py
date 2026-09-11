#!/usr/bin/env python3
"""Disposable custodial browser playground for the gsr-net Signet."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_BYTEREV, OP_EQUAL, taproot_construct


HOST = "127.0.0.1"
PORT = int(os.environ.get("GSR_PLAYGROUND_PORT", "8082"))
STATE_PATH = Path(os.environ.get("GSR_PLAYGROUND_STATE", "/var/lib/gsr-net/playground-state.json"))
CLI = os.environ.get("GSR_BITCOIN_CLI", "/opt/gsr-net/bin/bitcoin-cli")
BASE_ARGS = [CLI, "-conf=/etc/gsr-net/bitcoin.conf", "-datadir=/var/lib/gsr-net"]
WALLET = "playground"
CLAIM_AMOUNT = Decimal("1.0")
GSR_FUND_SATS = 1_000_000
GSR_FEE_SATS = 10_000
LOCK = threading.Lock()


def run_cli(*args: str, wallet: str | None = None) -> str:
    command = [*BASE_ARGS]
    if wallet:
        command.append(f"-rpcwallet={wallet}")
    result = subprocess.run(command + list(args), check=False, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result.stdout.strip()


def rpc_json(*args: str, wallet: str | None = None):
    return json.loads(run_cli(*args, wallet=wallet))


def ensure_wallet() -> None:
    loaded = rpc_json("listwallets")
    if WALLET in loaded:
        return
    try:
        run_cli("loadwallet", WALLET)
    except RuntimeError:
        run_cli("createwallet", WALLET, "false", "false", "", "false", "true", "true")


def load_state() -> dict:
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(state, dict) and isinstance(state.get("sessions"), dict):
            return state
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {"sessions": {}}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    STATE_PATH.chmod(0o600)


def session_for(state: dict, token: str) -> dict:
    session = state["sessions"].get(token)
    if not session:
        raise ValueError("Unknown session. Create a new playground wallet.")
    return session


def create_session() -> dict:
    ensure_wallet()
    token = secrets.token_urlsafe(32)
    address = run_cli("getnewaddress", f"play-{token[:10]}", "bech32m", wallet=WALLET)
    with LOCK:
        state = load_state()
        state["sessions"][token] = {
            "address": address,
            "balance": "0",
            "claimed": False,
            "created": int(time.time()),
        }
        save_state(state)
    return {"token": token, "address": address, "balance": "0"}


def claim(token: str) -> dict:
    with LOCK:
        state = load_state()
        session = session_for(state, token)
        if session.get("claimed"):
            raise ValueError("This playground wallet already used its faucet claim.")
        txid = run_cli("sendtoaddress", session["address"], str(CLAIM_AMOUNT), "playground faucet", wallet="miner")
        session["claimed"] = True
        session["balance"] = str(Decimal(session["balance"]) + CLAIM_AMOUNT)
        save_state(state)
        return {"txid": txid, "balance": session["balance"]}


def send_payment(token: str, address: str, amount_text: str) -> dict:
    try:
        amount = Decimal(amount_text)
    except InvalidOperation as error:
        raise ValueError("Invalid amount.") from error
    if amount <= 0 or amount > Decimal("1.0"):
        raise ValueError("Amount must be greater than zero and at most 1 BTC.")
    validation = rpc_json("validateaddress", address)
    if not validation.get("isvalid"):
        raise ValueError("Invalid Signet destination address.")
    with LOCK:
        state = load_state()
        session = session_for(state, token)
        balance = Decimal(session["balance"])
        if amount > balance:
            raise ValueError("Playground balance is too low.")
        txid = run_cli("sendtoaddress", address, str(amount), "playground send", wallet=WALLET)
        session["balance"] = str(balance - amount)
        save_state(state)
        return {"txid": txid, "balance": session["balance"]}


def make_gsr_demo(token: str) -> dict:
    """Fund and spend a real 0xc2 leaf executing OP_BYTEREV."""
    with LOCK:
        state = load_state()
        session = session_for(state, token)
        destination = rpc_json("validateaddress", session["address"])["scriptPubKey"]

        internal_key = generate_privkey()
        internal_pubkey = compute_xonly_pubkey(internal_key)[0]
        script = CScript([bytes.fromhex("010203"), OP_BYTEREV, bytes.fromhex("030201"), OP_EQUAL])
        tap = taproot_construct(internal_pubkey, [("demo", script, 0xC2)])
        leaf = tap.leaves["demo"]
        control = bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch

        unspents = rpc_json("listunspent", "101", "9999999", wallet="miner")
        if not unspents:
            raise RuntimeError("No mature mining output is available.")
        selected = max(unspents, key=lambda item: Decimal(str(item["amount"])))
        selected_sats = int(Decimal(str(selected["amount"])) * 100_000_000)
        funding_fee = 10_000
        change_sats = selected_sats - GSR_FUND_SATS - funding_fee
        if change_sats <= 0:
            raise RuntimeError("Mining output is too small for the demo.")
        change_address = run_cli("getrawchangeaddress", "bech32", wallet="miner")
        change_script = bytes.fromhex(rpc_json("validateaddress", change_address)["scriptPubKey"])

        locked_output = json.dumps([{"txid": selected["txid"], "vout": selected["vout"]}])
        run_cli("lockunspent", "false", locked_output, wallet="miner")
        funding_sent = False
        try:
            funding = CTransaction()
            funding.vin = [CTxIn(COutPoint(int(selected["txid"], 16), int(selected["vout"])))]
            funding.vout = [CTxOut(GSR_FUND_SATS, tap.scriptPubKey), CTxOut(change_sats, change_script)]
            signed = rpc_json("signrawtransactionwithwallet", funding.serialize().hex(), wallet="miner")
            if not signed.get("complete"):
                raise RuntimeError("Miner wallet could not sign the demo funding transaction.")
            funding_txid = run_cli("sendrawtransaction", signed["hex"], "0")
            funding_sent = True
        finally:
            if not funding_sent:
                run_cli("lockunspent", "true", locked_output, wallet="miner")

        spending = CTransaction()
        spending.vin = [CTxIn(COutPoint(int(funding_txid, 16), 0))]
        spending.vout = [CTxOut(GSR_FUND_SATS - GSR_FEE_SATS, bytes.fromhex(destination))]
        spending.wit.vtxinwit = [CTxInWitness()]
        spending.wit.vtxinwit[0].scriptWitness.stack = [bytes(script), control]
        raw_spend = spending.serialize().hex()
        acceptance = rpc_json("testmempoolaccept", json.dumps([raw_spend]), "0")
        if not acceptance[0].get("allowed"):
            reason = acceptance[0].get("reject-reason", "unknown rejection")
            raise RuntimeError(f"GSR demo spend rejected: {reason}")
        spend_txid = run_cli("sendrawtransaction", raw_spend, "0")
        credited = Decimal(GSR_FUND_SATS - GSR_FEE_SATS) / Decimal(100_000_000)
        session["balance"] = str(Decimal(session["balance"]) + credited)
        save_state(state)
        return {
            "funding_txid": funding_txid,
            "spend_txid": spend_txid,
            "script": bytes(script).hex(),
            "leaf_version": "c2",
            "opcode": "OP_BYTEREV",
            "balance": session["balance"],
        }


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>gsr-net playground</title><style>:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:0;background:#10131a;color:#eef1f7}main{max-width:52rem;margin:5vh auto;padding:1.5rem}section{background:#1a1f2a;border:1px solid #343c50;border-radius:14px;padding:1.5rem;margin:1rem 0}button,input{padding:.75rem;border-radius:8px;border:1px solid #505a73}button{background:#f5a623;color:#17120a;font-weight:700;cursor:pointer}input{box-sizing:border-box;width:100%;background:#0d1016;color:inherit;margin:.3rem 0}.muted{color:#acb5c8}.out{white-space:pre-wrap;overflow-wrap:anywhere;color:#7ee2a8}a{color:#7db7ff}</style></head>
<body><main><h1>gsr-net playground</h1><p class="muted">Disposable, server-managed test wallet. Never use real keys or funds here.</p>
<section><h2>1. Wallet</h2><button onclick="createWallet()">Create disposable wallet</button><p id="wallet" class="out"></p><button onclick="claim()">Claim 1 test BTC</button></section>
<section><h2>2. Send payment</h2><input id="to" placeholder="Destination tb1..."><input id="amount" value="0.01" type="number" step="0.00000001"><button onclick="sendPayment()">Send</button></section>
<section><h2>3. Make a real GSR transaction</h2><p class="muted">Creates and spends a Taproot leaf version 0xc2 transaction whose script executes OP_BYTEREV.</p><button onclick="gsrDemo()">Run OP_BYTEREV demo</button></section>
<section><h2>Result</h2><p id="result" class="out">Ready.</p><p><a href="/faucet/">Faucet</a> · <a href="/">Explorer</a></p></section>
<script>
let token=localStorage.getItem('gsrToken')||'';let address=localStorage.getItem('gsrAddress')||'';
const out=x=>document.getElementById('result').textContent=typeof x==='string'?x:JSON.stringify(x,null,2);
const show=()=>document.getElementById('wallet').textContent=address?`Address: ${address}`:'No wallet yet.';show();
async function call(path,body={}){let r=await fetch('/playground/api/'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,token})});let x=await r.json();if(!r.ok)throw Error(x.error||'Request failed');return x}
async function createWallet(){try{let x=await call('create');token=x.token;address=x.address;localStorage.setItem('gsrToken',token);localStorage.setItem('gsrAddress',address);show();out(x)}catch(e){out(e.message)}}
async function claim(){try{out(await call('claim'))}catch(e){out(e.message)}}
async function sendPayment(){try{out(await call('send',{address:document.getElementById('to').value,amount:document.getElementById('amount').value}))}catch(e){out(e.message)}}
async function gsrDemo(){try{out('Building and broadcasting two transactions...');out(await call('gsr-demo'))}catch(e){out(e.message)}}
</script></main></body></html>""".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "gsr-net-playground/1"

    def respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, status: int, value: dict) -> None:
        self.respond(status, json.dumps(value).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/healthz":
            self.respond(200, b"ok\n", "text/plain; charset=utf-8")
        elif self.path.rstrip("/") in ("", "/playground"):
            self.respond(200, PAGE, "text/html; charset=utf-8")
        else:
            self.respond(404, b"not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if not self.path.startswith("/api/"):
            self.json_response(404, {"error": "Not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                raise ValueError("Invalid request size.")
            request = json.loads(self.rfile.read(length))
            action = self.path.removeprefix("/api/").rstrip("/")
            if action == "create":
                result = create_session()
            elif action == "claim":
                result = claim(str(request.get("token", "")))
            elif action == "send":
                result = send_payment(str(request.get("token", "")), str(request.get("address", "")), str(request.get("amount", "")))
            elif action == "gsr-demo":
                result = make_gsr_demo(str(request.get("token", "")))
            else:
                self.json_response(404, {"error": "Unknown action."})
                return
            self.json_response(200, result)
        except (ValueError, RuntimeError, json.JSONDecodeError) as error:
            self.json_response(400, {"error": str(error)})
        except Exception as error:
            print(f"unexpected error: {error!r}", flush=True)
            self.json_response(500, {"error": "Unexpected playground error."})

    def log_message(self, message: str, *args: object) -> None:
        print(f"{self.client_address[0]} - {message % args}", flush=True)


if __name__ == "__main__":
    ensure_wallet()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
