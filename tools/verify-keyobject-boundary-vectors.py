"""Independently replay fixed SPKI, hint and algorithm-boundary bytes without Node."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
source = json.loads((ROOT / "vectors/key-discovery.json").read_text(encoding="utf-8"))
prefix = json.loads((ROOT / "vectors/prefix.json").read_text(encoding="utf-8"))
vector = json.loads((ROOT / "vectors/keyobject-boundary.json").read_text(encoding="utf-8"))
assert vector["profile"] == source["profile"]
assert vector["sourceSpkiVector"] == "vectors/key-discovery.json"
assert vector["sourceSignatureVector"] == "vectors/prefix.json"
name = bytes.fromhex(vector["requestedNameUtf8Hex"])
assert name == source["name"].encode("utf-8") == prefix["context"]["name"].encode("utf-8")
signature = bytes.fromhex(prefix["signature"])
assert len(signature) == 4627
assert hashlib.sha256(signature).hexdigest() == vector["signatureSha256"]

keys = {label: bytes.fromhex(hex_bytes) for label, hex_bytes in source["keys"].items()}
oid87 = bytes.fromhex("0609608648016503040313")
oid44 = bytes.fromhex("0609608648016503040311")


def actual_algorithm(spki):
    assert (oid87 in spki) != (oid44 in spki)
    return "ml-dsa-87" if oid87 in spki else "ml-dsa-44"


def hint(spki):
    return hashlib.sha256(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki).digest()[:4].hex()


for label, spki in keys.items():
    assert hashlib.sha256(spki).hexdigest() == vector["spkiSha256"][label]
    assert hint(spki) == vector["hintHex"][label]
assert vector["hintHex"]["primary"] == source["keyHint"] == prefix["keyHint"]
assert actual_algorithm(keys["primary"]) == actual_algorithm(keys["second"]) == "ml-dsa-87"
assert actual_algorithm(keys["legacy44"]) == "ml-dsa-44"

seen = set()
for case in vector["cases"]:
    assert case["id"] not in seen
    seen.add(case["id"])
    actual_key = case["actualKey"]
    actual_spki = keys[actual_key]
    actual = actual_algorithm(actual_spki)
    operation = case["operation"]
    observed_role = case.get("shadowType", "public")
    observed_algorithm = case.get("sharedPrototypeAlgorithm", case.get("prototypeAlgorithm", case.get("shadowAlgorithm", actual)))
    observed_spki = keys[case.get("sharedPrototypeExport", case.get("prototypeExport", case.get("shadowExport", actual_key)))]

    if operation == "select":
        admitted_hint = vector["hintHex"][case["hint"]]
        expected = actual_key if actual == "ml-dsa-87" and hint(actual_spki) == admitted_hint else "NOTE_KEY_UNKNOWN"
        if case.get("proxy") or case.get("prototypeAlgorithm"):
            expected = "NOTE_KEY_CANDIDATES"
        if observed_role != "public":
            previous = "NOTE_KEY_CANDIDATES"
        elif observed_algorithm != "ml-dsa-87" or hint(observed_spki) != admitted_hint:
            previous = "NOTE_KEY_UNKNOWN"
        else:
            previous = actual_key
    elif operation == "hint":
        expected = actual_key if actual == "ml-dsa-87" else "NOTE_KEY_SCHEME"
        previous = case.get("shadowExport", actual_key) if observed_algorithm == "ml-dsa-87" else "NOTE_KEY_SCHEME"
    elif operation == "verify":
        expected = actual_key if actual == "ml-dsa-87" else "NOTE_KEY_SCHEME"
        previous = "NOTE_KEY_SCHEME" if observed_algorithm != "ml-dsa-87" else (actual_key if actual == "ml-dsa-87" else "false")
    else:
        raise AssertionError(case["id"])
    assert case["expected"] == expected, case["id"]
    assert case["previousResult"] == previous, case["id"]

print(f"independent KeyObject SPKI and hint byte replay: {len(vector['cases'])} cases passed")
