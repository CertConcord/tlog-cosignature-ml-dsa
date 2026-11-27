"""Independent byte replay for proof-array admission and wire comparisons."""

import base64
import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent
vectors = json.loads((root / "vectors/sparse-proof.json").read_bytes())
source = json.loads((root / "vectors/transport.json").read_bytes())
source_wire = next(case["wire"] for case in source["cases"] if case["id"] == "one-witness-request").encode()
cut = source_wire.index(b"\n\n")


def wire(hashes):
    lines = b"".join(b"\n" + base64.b64encode(bytes.fromhex(vectors["hashes"][item])) for item in hashes)
    return source_wire[:cut] + lines + source_wire[cut:]


expected_wires = {"empty": [], "one": ["a"], "two": ["a", "b"], "short": ["short"]}
for name, hashes in expected_wires.items():
    raw = wire(hashes)
    frozen = vectors["wires"][name]
    assert raw.hex() == frozen["hex"], name
    assert hashlib.sha256(raw).hexdigest() == frozen["sha256"], name

expected_cases = {
    "proof-dense-empty": ("VALID", "empty", []),
    "proof-dense-one": ("VALID", "one", ["a"]),
    "proof-sparse-one": ("SUBTREE_REQUEST", "empty", []),
    "proof-sparse-middle": ("SUBTREE_REQUEST", "two", ["a", "b"]),
    "proof-accessor-changing": ("SUBTREE_REQUEST", "short", ["short"]),
    "proof-proxy-length-flip": ("SUBTREE_REQUEST", "empty", []),
    "proof-proxy-transparent": ("SUBTREE_REQUEST", "one", ["a"]),
    "proof-proxy-revoked": ("SUBTREE_REQUEST", "one", ["a"]),
}
assert len(vectors["cases"]) == len(expected_cases)
for case in vectors["cases"]:
    expected, key, wire_hashes = expected_cases.pop(case["id"])
    assert case["expected"] == expected, case["id"]
    if case["id"] == "proof-proxy-revoked":
        assert case["comparisonWire"] == key
        assert case["previousOutcome"] == {"kind": "error", "name": "TypeError", "wire": None}
        assert "forbiddenWire" not in case and "emittedHashes" not in case
    else:
        assert case.get("wire", case.get("forbiddenWire")) == key, case["id"]
    assert [entry["index"] for entry in case["entries"]] == sorted(entry["index"] for entry in case["entries"]), case["id"]
    assert all(0 <= entry["index"] < case["length"] for entry in case["entries"]), case["id"]
    if expected == "VALID":
        assert len(case["entries"]) == case["length"], case["id"]
        assert [entry["hash"] for entry in case["entries"]] == wire_hashes, case["id"]
    elif case["id"] != "proof-proxy-revoked":
        assert case["emittedHashes"] == wire_hashes, case["id"]
    else:
        assert [entry["hash"] for entry in case["entries"]] == wire_hashes, case["id"]
    assert wire(wire_hashes).hex() == vectors["wires"][key]["hex"], case["id"]

assert not expected_cases
assert vectors["cases"][-3]["slotKind"] == "proxy-length-flip"
assert vectors["cases"][-3]["length"] == 1 and vectors["cases"][-3]["entries"][0]["hash"] == "a"
assert vectors["cases"][-2]["slotKind"] == "proxy-transparent"
assert vectors["cases"][-1]["slotKind"] == "proxy-revoked"
print("Proof-array bytes: 4 wires and 8 cases independently replayed")
