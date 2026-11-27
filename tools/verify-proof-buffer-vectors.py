"""Independently replay proof-hash native bytes and the canonical request wire."""

import base64
import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent
vectors = json.loads((root / "vectors/proof-buffer.json").read_bytes())
sparse = json.loads((root / "vectors/sparse-proof.json").read_bytes())
transport = json.loads((root / "vectors/transport.json").read_bytes())
base = next(case["wire"] for case in transport["cases"] if case["id"] == "one-witness-request").encode()
cut = base.index(b"\n\n")

hash32 = bytes.fromhex(vectors["hashes"]["a"])
assert hash32 == bytes([0x5A]) * 32
assert bytes.fromhex(vectors["hashes"]["short"]) == bytes([0x5A]) * 16
assert bytes.fromhex(vectors["hashes"]["long"]) == bytes([0x5A]) * 48
one_wire = base[:cut] + b"\n" + base64.b64encode(hash32) + base[cut:]
frozen = vectors["wires"]["one"]
assert one_wire.hex() == frozen["hex"] == sparse["wires"]["one"]["hex"]
assert hashlib.sha256(one_wire).hexdigest() == frozen["sha256"] == sparse["wires"]["one"]["sha256"]

expected = {
    "proof-buffer-plain": ("a", "none", "VALID"),
    "proof-buffer-shadow-length-16": ("a", "length-16", "VALID"),
    "proof-buffer-shadow-length-throws": ("a", "length-throws", "VALID"),
    "proof-buffer-shadow-byte-length-throws": ("a", "byte-length-throws", "VALID"),
    "proof-buffer-native-short-spoof": ("short", "length-32", "SUBTREE_REQUEST"),
    "proof-buffer-native-long-spoof": ("long", "length-32", "SUBTREE_REQUEST"),
    "proof-buffer-proxy": ("a", "proxy", "SUBTREE_REQUEST"),
    "proof-buffer-revoked-proxy": ("a", "revoked-proxy", "SUBTREE_REQUEST"),
}
assert len(vectors["cases"]) == len(expected)
for case in vectors["cases"]:
    hash_name, decoration, outcome = expected.pop(case["id"])
    assert case["hash"] == hash_name and case["decoration"] == decoration and case["expected"] == outcome
    native = bytes.fromhex(vectors["hashes"][hash_name])
    assert len(native) == (32 if hash_name == "a" else 16 if hash_name == "short" else 48)
    if outcome == "VALID":
        assert case["wire"] == "one" and "noWire" not in case
        assert native == hash32
        assert one_wire.hex() == vectors["wires"][case["wire"]]["hex"]
    else:
        assert case["noWire"] is True and "wire" not in case
assert not expected
print("Proof Buffer bytes: 1 full wire and 8 native-byte cases independently replayed")
