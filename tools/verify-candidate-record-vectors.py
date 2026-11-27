"""Independently replay frozen candidate-record admission bytes without Node code."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
source = json.loads((ROOT / "vectors/key-discovery.json").read_text(encoding="utf-8"))
vector = json.loads((ROOT / "vectors/candidate-record.json").read_text(encoding="utf-8"))
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


def select(items, admitted_hint):
    matches = []
    for item in items:
        name, key = names[item["name"]], keys[item["key"]]
        if name == names["requested"] and oid87 in key and hint(name, key) == admitted_hint:
            matches.append(item["key"])
    if len(matches) > 1:
        return "NOTE_KEY_AMBIGUOUS"
    return matches[0] if matches else "NOTE_KEY_UNKNOWN"


seen = set()
for case in vector["cases"]:
    assert case["id"] not in seen
    seen.add(case["id"])
    initial = [dict(item) for item in case["initial"]]
    assert 1 <= len(initial) <= 64
    shape = case["shape"]
    mutation = case.get("mutation")
    expected = select(initial, bytes.fromhex(vector["keyHintHex"]))
    if shape in {"two-accessors", "inherited-name", "proxy"}:
        expected = "NOTE_KEY_CANDIDATES"
    else:
        assert shape in {"data", "single-accessor"}
    assert case["expected"] == expected, case["id"]

    prior_items = [dict(item) for item in initial]
    prior_hint = bytes.fromhex(vector["keyHintHex"])
    if mutation == "rewrite-second-name":
        prior_items[1]["name"] = "other"
    elif mutation == "replace-second-key":
        prior_items[1]["key"] = "second"
    elif mutation == "zero-hint":
        prior_hint = bytes(4)
    else:
        assert mutation is None, case["id"]
    assert case["previousResult"] == select(prior_items, prior_hint), case["id"]

print(f"independent candidate-record byte replay: {len(vector['cases'])} cases passed")
