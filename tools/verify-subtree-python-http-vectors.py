"""Test-only Python witness peer and real Node HTTP client, using frozen wires."""

import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import subprocess
from threading import Thread

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).hexdigest()
vector = json.loads(read("vectors/subtree-python-http-interop.json"))
live_data = read("vectors/subtree-live-sign.json")
cross_data = read("vectors/subtree-cross-runtime.json")
checkpoint_bytes = read("vectors/subtree-cross-runtime-checkpoint.json")
checkpoint_data = json.loads(checkpoint_bytes)
proof_data = read("vectors/subtree-consistency.json")
live = json.loads(live_data)
proof_source = json.loads(proof_data)
assert sha(live_data) == vector["sourceLiveVectorSha256"]
assert sha(cross_data) == vector["sourceCrossRuntimeVectorSha256"]
assert sha(checkpoint_bytes) == vector["sourceCheckpointVectorSha256"]
assert vector["producer"] == {
    "package": "pqcrypto", "version": "1.0.0",
    "windowsWheelSha256": "d65d0fdbd2bfcfd80193d1d499142e63dd8ea6a072e1dc68b1b36fd49f9fdc8f",
}


def wire(item):
    data = bytes.fromhex(item["utf8Hex"])
    assert len(data) == item["bytes"] and sha(data) == item["sha256"]
    return data


name = bytes.fromhex(vector["nameUtf8Hex"])
spki = bytes.fromhex(live["witness"]["spkiHex"])
pkcs8 = bytes.fromhex(live["witness"]["pkcs8Hex"])
assert len(spki) == 2614 and len(pkcs8) == 4962 and sha(spki) == vector["spkiSha256"]
assert spki[:22] == bytes.fromhex("30820a32300b060960864801650304031303820a2100")
assert pkcs8[:30] == bytes.fromhex("3082135e020100300b06096086480165030403130482134a308213460420")
public = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
private = pkcs8[-ml_dsa_87.SECRET_KEY_SIZE:]
hint = hashlib.sha256(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki).digest()[:4]
assert hint.hex() == vector["keyHintHex"] == live["witness"]["keyIDHex"]
assert name == live["witness"]["name"].encode("ascii")
leaves = [bytes.fromhex(item) for item in proof_source["leafUtf8Hex"]]
assert leaves == [f"leaf-{i}".encode() for i in range(14)]


def digest(data):
    return hashlib.sha256(data).digest()


def mth(items):
    if not items:
        return digest(b"")
    if len(items) == 1:
        return digest(b"\0" + items[0])
    split = 1 << ((len(items) - 1).bit_length() - 1)
    return digest(b"\1" + mth(items[:split]) + mth(items[split:]))


def proof(start, end, items, omit=True):
    if start == 0 and end == len(items):
        return [] if omit else [mth(items)]
    split = 1 << ((len(items) - 1).bit_length() - 1)
    if end <= split:
        return proof(start, end, items[:split], omit) + [mth(items[split:])]
    if start >= split:
        return proof(start - split, end - split, items[split:], omit) + [mth(items[:split])]
    assert start == 0
    return proof(0, end - split, items[split:], False) + [mth(items[:split])]


class Rejected(Exception):
    def __init__(self, status):
        self.status = status


def decimal(data):
    if not re.fullmatch(rb"0|[1-9][0-9]*", data):
        raise Rejected(400)
    return int(data)


def b64(data, size):
    try:
        raw = base64.b64decode(data, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Rejected(400) from None
    if len(raw) != size or base64.b64encode(raw) != data:
        raise Rejected(400)
    return raw


def signed_input(origin, start, end, root, timestamp):
    return (b"subtree/v1\n\0" + bytes([len(name)]) + name + timestamp.to_bytes(8, "big")
            + bytes([len(origin)]) + origin + start.to_bytes(8, "big")
            + end.to_bytes(8, "big") + root)


def accept_request(data):
    if b"\r" in data or not data.endswith(b"\n") or len(data) > 8192:
        raise Rejected(400)
    try:
        prelude, note = data.split(b"\n\n", 1)
        body, signature_line = note.split(b"\n\n", 1)
        header, subtree_line, *proof_lines = prelude.split(b"\n")
        label, start_line, end_line = header.split(b" ")
        origin, size_line, root_line = body.split(b"\n")
    except ValueError:
        raise Rejected(400) from None
    if label != b"subtree" or len(proof_lines) > 63 or not proof_lines:
        raise Rejected(400)
    start, end, size = decimal(start_line), decimal(end_line), decimal(size_line)
    if origin != b"log.example/response" or size != 14 or (start, end) != (8, 13):
        raise Rejected(403)
    if not signature_line.startswith(b"\xe2\x80\x94 " + name + b" ") or not signature_line.endswith(b"\n"):
        raise Rejected(400)
    if b"\n" in signature_line[:-1]:
        raise Rejected(400)
    payload = b64(signature_line[len(b"\xe2\x80\x94 " + name + b" "):-1], 4 + 8 + 4627)
    checkpoint_root = b64(root_line, 32)
    if payload[:4] != hint:
        raise Rejected(403)
    timestamp = int.from_bytes(payload[4:12], "big")
    if timestamp > live["witness"]["at"] + 30:
        raise Rejected(403)
    checkpoint_message = signed_input(origin, 0, size, checkpoint_root, timestamp)
    try:
        ml_dsa_87.verify(public, checkpoint_message, payload[12:], context=b"")
    except InvalidSignatureError:
        raise Rejected(403) from None
    if checkpoint_root != mth(leaves):
        raise Rejected(422)
    subtree_root = b64(subtree_line, 32)
    proof_hashes = [b64(line, 32) for line in proof_lines]
    if subtree_root != mth(leaves[start:end]) or proof_hashes != proof(start, end, leaves):
        raise Rejected(422)
    message = signed_input(origin, start, end, subtree_root, 0)
    assert message.hex() == vector["signerInputHex"]
    return message


class Peer(BaseHTTPRequestHandler):
    seen = []
    mode = None

    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "-1"))
        data = self.rfile.read(length) if 0 <= length <= 8192 else b""
        self.seen.append((self.command, self.path, data))
        try:
            if self.path != vector["endpoint"]["path"] or length < 0 or length > 8192:
                raise Rejected(400)
            message = accept_request(data)
            if self.mode == "live":
                signature = ml_dsa_87.sign(private, message, context=b"")
                assert len(signature) == vector["liveSignatureBytes"]
                ml_dsa_87.verify(public, message, signature, context=b"")
                body = base64.b64encode(signature) + b"\n"
                assert len(body) == vector["liveResponseBytes"]
                status = 200
            elif self.mode == "status-403":
                status, body = 403, wire(vector["bodies"]["status403"])
            else:
                body = wire(vector["bodies"][{
                    "frozen": "frozen", "wrong-message": "wrongMessage",
                    "missing-lf": "missingLf",
                }[self.mode]])
                status = 200
        except Rejected as error:
            status, body = error.status, b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_case(case):
    Peer.seen = []
    Peer.mode = case["mode"]
    server = HTTPServer(("127.0.0.1", 0), Peer)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if case["mode"].startswith("raw-"):
            source = checkpoint_data
            if case["mode"] == "raw-bad-checkpoint":
                item = next(x for x in source["negativeRequests"] if x["id"].endswith("bad-signature"))
            elif case["mode"] == "raw-bad-proof":
                item = next(x for x in source["wireFailures"] if x["id"].endswith("bad-proof"))
            else:
                item = next(x for x in source["wireFailures"] if x["id"].endswith("carriage-return"))
            data = wire(item["request"])
            assert data == wire(case["request"])
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            connection.request("POST", vector["endpoint"]["path"], body=data)
            response = connection.getresponse()
            assert (response.status, response.read()) == (case["status"], b"")
            connection.close()
        else:
            result = subprocess.run(
                ["node", "tools/python-http-interop-client.mjs", str(server.server_port), case["mode"]],
                cwd=ROOT, capture_output=True, text=True, timeout=30, check=True)
            actual = json.loads(result.stdout)
            assert actual["result"] == case["expected"], (case["id"], actual)
            if "status" in case:
                assert actual["status"] == case["status"]
        assert len(Peer.seen) == int(case["sent"]), case["id"]
        if Peer.seen:
            method, path, data = Peer.seen[0]
            assert (method, path) == (vector["endpoint"]["method"], vector["endpoint"]["path"])
            assert data == wire(case.get("request", vector["request"]))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


assert wire(vector["request"]) == wire(checkpoint_data["request"])
assert wire(vector["badProofRequest"]) == wire(next(
    x["request"] for x in checkpoint_data["wireFailures"] if x["id"].endswith("bad-proof")))
assert wire(vector["bodies"]["frozen"]) == wire(json.loads(cross_data)["pythonResponse"])
wrong = b64(wire(vector["bodies"]["wrongMessage"])[:-1], 4627)
assert sha(wrong) == vector["wrongMessageSignatureSha256"]
ml_dsa_87.verify(public, bytes.fromhex(vector["badSignerInputHex"]), wrong, context=b"")
try:
    ml_dsa_87.verify(public, bytes.fromhex(vector["signerInputHex"]), wrong, context=b"")
except InvalidSignatureError:
    pass
else:
    raise AssertionError("wrong-message signature accepted")
for case in vector["cases"]:
    run_case(case)
print(f"Python witness peer and Node HTTP client: {len(vector['cases'])} exact cases verified")
