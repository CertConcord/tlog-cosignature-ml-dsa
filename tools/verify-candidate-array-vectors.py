"""Independently replay frozen candidate-array admission bytes without Node code."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
source = json.loads((ROOT / "vectors/key-discovery.json").read_text())
vector = json.loads((ROOT / "vectors/candidate-array.json").read_text())
assert vector["sourceSpkiVector"] == "vectors/key-discovery.json"
assert vector["profile"] == source["profile"]
assert vector["keyHintHex"] == source["keyHint"]

names = {
    "requested": bytes.fromhex(vector["requestedNameUtf8Hex"]),
    "other": bytes.fromhex(vector["otherNameUtf8Hex"]),
}
assert names["requested"] == source["name"].encode("utf-8")
assert names["other"] == b"unrelated.example"
keys = {label: bytes.fromhex(hex_bytes) for label, hex_bytes in source["keys"].items()}
for label, key_bytes in keys.items():
    assert hashlib.sha256(key_bytes).hexdigest() == vector["spkiSha256"][label]

oid87 = bytes.fromhex("0609608648016503040313")
oid44 = bytes.fromhex("0609608648016503040311")
assert oid87 in keys["primary"] and oid87 in keys["second"]
assert oid44 in keys["legacy44"]

def hint(name, spki):
    return hashlib.sha256(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki).digest()[:4]

assert hint(names["requested"], keys["primary"]).hex() == vector["keyHintHex"]
assert hint(names["requested"], keys["second"]).hex() != vector["keyHintHex"]

def select(items):
    matches = []
    for item in items:
        name, key = names[item["name"]], keys[item["key"]]
        if name == names["requested"] and oid87 in key and hint(name, key).hex() == vector["keyHintHex"]:
            matches.append(item["key"])
    if len(matches) > 1:
        return "NOTE_KEY_AMBIGUOUS"
    return matches[0] if matches else "NOTE_KEY_UNKNOWN"

for case in vector["cases"]:
    initial = case["initial"]
    assert 1 <= len(initial) <= 64, case["id"]
    current = list(initial)
    mutation = case.get("mutation")
    if mutation == "pop-on-first-name":
        current.pop()
    elif mutation == "replace-on-first-name":
        current[1] = {"name": "other", "key": "second"}
    elif mutation == "append-on-first-name":
        current.append({"name": "requested", "key": "primary"})
        assert len(initial) == 64 and len(current) == 65
    else:
        assert mutation is None, case["id"]
    expected = select(initial) if case["slotKind"] == "data" else "NOTE_KEY_CANDIDATES"
    previous = select(current)
    assert case["expected"] == expected, case["id"]
    assert case["previousResult"] == previous, case["id"]

print(f"independent candidate-array byte replay: {len(vector['cases'])} cases passed")
