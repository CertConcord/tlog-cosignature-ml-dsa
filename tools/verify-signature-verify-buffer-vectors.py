"""Independently rebuild direct signature verification bytes and case fixtures."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--prefix", type=Path)
parser.add_argument("--vector", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
prefix = json.loads((args.prefix or root / "vectors/prefix.json").read_bytes())
vector = json.loads((args.vector or root / "vectors/signature-verify-buffer.json").read_bytes())
sha = lambda data: hashlib.sha256(data).hexdigest()
spki = bytes.fromhex(prefix["spki"])
signature = bytes.fromhex(prefix["signature"])
context = prefix["context"]
name, origin = context["name"].encode(), context["origin"].encode()
signed = (b"subtree/v1\n\0" + bytes([len(name)]) + name + struct.pack(">Q", context["timestamp"])
          + bytes([len(origin)]) + origin + struct.pack(">QQ", context["start"], context["end"])
          + bytes.fromhex(context["root"]))
assert len(signature) == 4627 and len(signed) == 103
assert vector["selectedSpkiHex"] == spki.hex() and vector["selectedSpkiSha256"] == sha(spki)
assert vector["signedInputHex"] == signed.hex() and vector["signedInputSha256"] == sha(signed)
corrupted = bytes([signature[0] ^ 1]) + signature[1:]
expected = {"valid": signature, "corrupted": corrupted, "short": b"\x5a" * 16,
            "long": b"\x5a" * 4630, "disguised": b"\x5a" * 4628}
assert set(vector["inputs"]) == set(expected)
for name, data in expected.items():
    item = vector["inputs"][name]
    assert item == {"hex": data.hex(), "bytes": len(data), "sha256": sha(data)}
expected_cases = [
    ("valid", "none", True), ("valid", "length-16", True),
    ("valid", "length-throws", True), ("valid", "byte-length-throws", True),
    ("corrupted", "none", False), ("short", "length-4627", False),
    ("long", "length-4627", False), ("disguised", "uint16-buffer-prototype", False),
    ("valid", "proxy", False), ("valid", "revoked-proxy", False),
]
assert [(x["input"], x["decoration"], x["verified"]) for x in vector["cases"]] == expected_cases
assert all(x["expected"] == ("VALID" if x["verified"] else "VERIFY_FALSE") for x in vector["cases"])
assert len({x["id"] for x in vector["cases"]}) == len(expected_cases)
print("Signature verifier bytes: full SPKI, 103-byte signed input, 5 signatures and 10 cases independently replayed")
