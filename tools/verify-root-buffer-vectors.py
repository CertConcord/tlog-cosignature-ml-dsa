"""Independently replay root-hash native bytes and the canonical subtree request."""

import base64
import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent
vectors = json.loads((root / "vectors/root-buffer.json").read_bytes())
sparse = json.loads((root / "vectors/sparse-proof.json").read_bytes())
transport = json.loads((root / "vectors/transport.json").read_bytes())
empty = next(case["wire"] for case in transport["cases"] if case["id"] == "one-witness-request").encode()
cut = empty.index(b"\n\n")
proof = bytes.fromhex(sparse["hashes"]["a"])
one_wire = empty[:cut] + b"\n" + base64.b64encode(proof) + empty[cut:]
frozen = vectors["wires"]["one"]
assert one_wire.hex() == frozen["hex"] == sparse["wires"]["one"]["hex"]
assert hashlib.sha256(one_wire).hexdigest() == frozen["sha256"] == sparse["wires"]["one"]["sha256"]

native_root = base64.b64decode(one_wire.split(b"\n")[1], validate=True)
assert native_root.hex() == vectors["roots"]["original"] and len(native_root) == 32
assert bytes.fromhex(vectors["roots"]["short"]) == bytes([0x5A]) * 16
assert bytes.fromhex(vectors["roots"]["long"]) == bytes([0x5A]) * 48
expected = {
    "root-buffer-plain": ("original", "none", "VALID"),
    "root-buffer-shadow-length-16": ("original", "length-16", "VALID"),
    "root-buffer-shadow-length-throws": ("original", "length-throws", "VALID"),
    "root-buffer-shadow-byte-length-throws": ("original", "byte-length-throws", "VALID"),
    "root-buffer-native-short-spoof": ("short", "length-32", "SUBTREE_REQUEST"),
    "root-buffer-native-long-spoof": ("long", "length-32", "SUBTREE_REQUEST"),
    "root-buffer-uint16-buffer-prototype": ("original", "uint16-buffer-prototype", "SUBTREE_REQUEST"),
    "root-buffer-uint32-buffer-prototype": ("original", "uint32-buffer-prototype", "SUBTREE_REQUEST"),
    "root-buffer-proxy": ("original", "proxy", "SUBTREE_REQUEST"),
    "root-buffer-revoked-proxy": ("original", "revoked-proxy", "SUBTREE_REQUEST"),
}
assert len(vectors["cases"]) == len(expected)
for case in vectors["cases"]:
    root_name, decoration, outcome = expected.pop(case["id"])
    assert case["root"] == root_name and case["decoration"] == decoration and case["expected"] == outcome
    native = bytes.fromhex(vectors["roots"][root_name])
    assert len(native) == (32 if root_name == "original" else 16 if root_name == "short" else 48)
    if outcome == "VALID":
        assert case["wire"] == "one" and "noWire" not in case
        assert native == native_root
        assert one_wire.hex() == vectors["wires"][case["wire"]]["hex"]
    else:
        assert case["noWire"] is True and "wire" not in case
assert not expected
print("Root Buffer bytes: 1 full wire and 10 native-byte cases independently replayed")
