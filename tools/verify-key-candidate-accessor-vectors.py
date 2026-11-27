"""Independently replay candidate admission from frozen bytes, without Node code."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
source = json.loads((ROOT / "vectors/key-discovery.json").read_text())
vector = json.loads((ROOT / "vectors/key-candidate-accessors.json").read_text())
spki = {name: bytes.fromhex(value) for name, value in source["keys"].items()}
requested = bytes.fromhex(vector["requestedNameUtf8Hex"])
other = bytes.fromhex(vector["otherNameUtf8Hex"])
assert requested == source["name"].encode("utf-8")
assert other == b"other.example/witness"
assert vector["keyHintHex"] == source["keyHint"]

for key_name, key_bytes in spki.items():
    assert hashlib.sha256(key_bytes).hexdigest() == vector["spkiSha256"][key_name]

def hint(name, key_bytes):
    payload = b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + key_bytes
    return hashlib.sha256(payload).digest()[:4]

assert hint(requested, spki["primary"]).hex() == vector["keyHintHex"]
assert hint(requested, spki["second"]).hex() != vector["keyHintHex"]
oid87 = bytes.fromhex("0609608648016503040313")
oid44 = bytes.fromhex("0609608648016503040311")
assert all(oid87 in spki[name] for name in ("primary", "second"))
assert oid44 in spki["legacy44"]

def read(sequence, index):
    return sequence[min(index, len(sequence) - 1)]

def matches(name_label, key_label):
    name_bytes = requested if name_label == "requested" else other
    key_bytes = spki[key_label]
    return (name_bytes == requested and oid87 in key_bytes
            and hint(requested, key_bytes).hex() == vector["keyHintHex"])

for case in vector["cases"]:
    admitted = matches(read(case["nameReads"], 0), read(case["keyReads"], 0))
    expected = read(case["keyReads"], 0) if admitted else "NOTE_KEY_UNKNOWN"
    assert case["expected"] == expected, case["id"]
    previous_matches = matches(read(case["nameReads"], 1), read(case["keyReads"], 3))
    previous = read(case["keyReads"], 4) if previous_matches else "NOTE_KEY_UNKNOWN"
    assert case["previousResult"] == previous, case["id"]

print(f"independent candidate byte replay: {len(vector['cases'])} cases passed")
