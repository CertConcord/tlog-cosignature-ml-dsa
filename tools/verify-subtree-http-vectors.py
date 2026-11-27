"""Independently reconstruct exact stateless sign-subtree status and body bytes."""

import base64
import hashlib
import json
from pathlib import Path


def sha(value):
    return hashlib.sha256(value).hexdigest()


def wire(item):
    value = bytes.fromhex(item["utf8Hex"])
    assert len(value) == item["bytes"] and sha(value) == item["sha256"]
    return value


root = Path(__file__).resolve().parent.parent
vector = json.loads((root / "vectors/subtree-http.json").read_text(encoding="utf-8"))
source_bytes = (root / "vectors/subtree-response-auth.json").read_bytes()
assert sha(source_bytes) == vector["sourceResponseVectorSha256"]
source = json.loads(source_bytes)
assert vector["witness"] == {key: source["witness"][key] for key in ("name", "spkiHex", "otherSpkiHex", "at")}
assert len(bytes.fromhex(vector["witness"]["spkiHex"])) == 2614
assert len(bytes.fromhex(vector["witness"]["otherSpkiHex"])) == 2614

valid = wire(source["requests"]["valid"])
assert wire(vector["requests"]["valid"]) == valid
assert wire(vector["requests"]["badRange"]) == valid.replace(b"subtree 8 13\n", b"subtree 08 13\n", 1)
assert wire(vector["requests"]["badProof"]) == wire(source["requests"]["alteredProof"])

marker = b"\n\xe2\x80\x94 " + vector["witness"]["name"].encode("ascii") + b" "
start = valid.rfind(marker)
assert start >= 0
payload_start = start + len(marker)
payload_end = valid.index(b"\n", payload_start)
payload = bytearray(base64.b64decode(valid[payload_start:payload_end], validate=True))
assert len(payload) == 4 + 8 + 4627
payload[12] ^= 1
bad_checkpoint = valid[:payload_start] + base64.b64encode(payload) + valid[payload_end:]
assert wire(vector["requests"]["badCheckpoint"]) == bad_checkpoint

success = wire(source["responses"]["valid"])
assert wire(vector["bodies"]["success"]) == success
assert wire(vector["bodies"]["empty"]) == b""
assert success.endswith(b"\n") and len(success) == 6173
valid_signature = base64.b64decode(success[:-1], validate=True)
other_signature = base64.b64decode(wire(source["responses"]["otherKey"])[:-1], validate=True)
assert len(valid_signature) == len(other_signature) == 4627
assert sha(valid_signature) == vector["signer"]["validSignatureSha256"]
assert sha(other_signature) == vector["signer"]["otherKeySignatureSha256"]

cases = vector["cases"]
assert len(cases) == 9 and len({case["id"] for case in cases}) == 9
assert {case.get("status") for case in cases} == {200, 400, 422, 403, 404, None}
assert sum(case.get("status") == 200 for case in cases) == 1
assert sum("error" in case for case in cases) == 2
for case in cases:
    assert case["request"] in vector["requests"]
    if "status" in case:
        assert case["expected"] == f"HTTP_{case['status']}"
        assert case["body"] == ("success" if case["status"] == 200 else "empty")
        assert case["signer"] == "valid"
    else:
        assert case["error"] in ("SUBTREE_SIGNER_SIGNATURE", "SUBTREE_SIGNATURE_LENGTH")
        assert case["expected"] == case["error"]
        assert "body" not in case
print("independent HTTP bytes: 1 success, 6 failure cases, 2 signer errors; exact request/body bytes")
