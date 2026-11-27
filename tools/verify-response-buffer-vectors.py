"""Independently replay native signature bytes and exact subtree response lines."""

import base64
import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent
vectors = json.loads((root / "vectors/response-buffer.json").read_bytes())
transport = json.loads((root / "vectors/transport.json").read_bytes())
source = next(case["wire"] for case in transport["cases"] if case["id"] == "raw-subtree-response")
assert source.endswith("\n")
native = base64.b64decode(source[:-1], validate=True)
assert len(native) == 4627 and native.hex() == vectors["signatures"]["original"]
assert base64.b64encode(native).decode() + "\n" == source

def wire(name):
    raw = bytes.fromhex(vectors["wires"][name]["hex"])
    assert hashlib.sha256(raw).hexdigest() == vectors["wires"][name]["sha256"]
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    return raw


assert wire("valid") == source.encode()
short = bytes.fromhex(vectors["signatures"]["short"])
long = bytes.fromhex(vectors["signatures"]["long"])
assert short == bytes([0x5A]) * 16 and long == bytes([0x5A]) * 4630
assert bytes.fromhex(vectors["signatures"]["typed16"]) == bytes([0x5A]) * 4628
assert wire("priorShort") == base64.b64encode(short) + b"\n"
assert wire("priorLong") == base64.b64encode(long) + b"\n"
assert len(base64.b64decode(wire("priorShort")[:-1], validate=True)) == 16
assert len(base64.b64decode(wire("priorLong")[:-1], validate=True)) == 4630

expected = {
    "response-buffer-plain": ("original", "none", "VALID"),
    "response-buffer-shadow-length-16": ("original", "length-16", "VALID"),
    "response-buffer-shadow-length-throws": ("original", "length-throws", "VALID"),
    "response-buffer-shadow-byte-length-throws": ("original", "byte-length-throws", "VALID"),
    "response-buffer-native-short-spoof": ("short", "length-4627", "SUBTREE_SIGNATURE_LENGTH"),
    "response-buffer-native-long-spoof": ("long", "length-4627", "SUBTREE_SIGNATURE_LENGTH"),
    "response-buffer-uint16-buffer-prototype": ("typed16", "uint16-buffer-prototype", "SUBTREE_SIGNATURE_LENGTH"),
    "response-buffer-proxy": ("original", "proxy", "SUBTREE_SIGNATURE_LENGTH"),
    "response-buffer-revoked-proxy": ("original", "revoked-proxy", "SUBTREE_SIGNATURE_LENGTH"),
}
assert len(vectors["cases"]) == len(expected)
for case in vectors["cases"]:
    signature, decoration, outcome = expected.pop(case["id"])
    assert (case["signature"], case["decoration"], case["expected"]) == (signature, decoration, outcome)
    raw = bytes.fromhex(vectors["signatures"][signature])
    assert len(raw) == {"original": 4627, "short": 16, "long": 4630, "typed16": 4628}[signature]
    if outcome == "VALID":
        assert case["wire"] == "valid" and "noWire" not in case and raw == native
        assert wire(case["wire"]) == source.encode()
    else:
        assert case["noWire"] is True and "wire" not in case
        if signature in ("short", "long"):
            assert wire(case["priorWire"]) == base64.b64encode(raw) + b"\n"
        else:
            assert "priorWire" not in case
assert not expected
print("Response Buffer bytes: 3 full wires and 9 native-byte cases independently replayed")
