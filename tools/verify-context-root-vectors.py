"""Independently reconstruct signed subtree inputs and root-byte rejection cases."""

import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent
vectors = json.loads((root / "vectors/context-root.json").read_bytes())
prefix = json.loads((root / "vectors/prefix.json").read_bytes())
context = vectors["context"]
assert context == {key: prefix["context"][key] for key in ("name", "origin", "start", "end", "timestamp")}


def text(value):
    raw = value.encode("ascii")
    assert 1 <= len(raw) <= 255
    return bytes([len(raw)]) + raw


def u64(value):
    assert isinstance(value, int) and 0 <= value <= 2**64 - 1
    return value.to_bytes(8, "big")


def preimage(name):
    raw = bytes.fromhex(vectors["preimages"][name]["hex"])
    assert hashlib.sha256(raw).hexdigest() == vectors["preimages"][name]["sha256"]
    return raw


front = (b"subtree/v1\n\x00" + text(context["name"]) + u64(context["timestamp"]) +
         text(context["origin"]) + u64(context["start"]) + u64(context["end"]))
native = bytes.fromhex(vectors["roots"]["original"])
assert native.hex() == prefix["context"]["root"] and len(native) == 32
assert preimage("valid") == front + native == bytes.fromhex(prefix["input"])
short = bytes.fromhex(vectors["roots"]["short"])
long = bytes.fromhex(vectors["roots"]["long"])
assert short == bytes([0x5A]) * 16 and long == bytes([0x5A]) * 48
assert preimage("priorShort") == front + short and len(preimage("priorShort")) == len(preimage("valid")) - 16

expected = {
    "context-root-plain": ("original", "none", "VALID"),
    "context-root-shadow-length-16": ("original", "length-16", "VALID"),
    "context-root-shadow-length-throws": ("original", "length-throws", "VALID"),
    "context-root-shadow-byte-length-throws": ("original", "byte-length-throws", "VALID"),
    "context-root-native-short-spoof": ("short", "length-32", "SUBTREE_CONTEXT"),
    "context-root-native-long-spoof": ("long", "length-32", "SUBTREE_CONTEXT"),
    "context-root-uint16-buffer-prototype": ("original", "uint16-buffer-prototype", "SUBTREE_CONTEXT"),
    "context-root-proxy": ("original", "proxy", "SUBTREE_CONTEXT"),
    "context-root-revoked-proxy": ("original", "revoked-proxy", "SUBTREE_CONTEXT"),
}
assert len(vectors["cases"]) == len(expected)
for case in vectors["cases"]:
    root_name, decoration, outcome = expected.pop(case["id"])
    assert (case["root"], case["decoration"], case["expected"]) == (root_name, decoration, outcome)
    native_root = bytes.fromhex(vectors["roots"][root_name])
    assert len(native_root) == {"original": 32, "short": 16, "long": 48}[root_name]
    if outcome == "VALID":
        assert case["preimage"] == "valid" and "noPreimage" not in case
        assert native_root == native and preimage(case["preimage"]) == front + native
    else:
        assert case["noPreimage"] is True and "preimage" not in case
        if case["id"] == "context-root-native-short-spoof":
            assert case["priorPreimage"] == "priorShort"
        else:
            assert "priorPreimage" not in case
assert not expected
print("Context root bytes: 2 full preimages and 9 native-byte cases independently replayed")
