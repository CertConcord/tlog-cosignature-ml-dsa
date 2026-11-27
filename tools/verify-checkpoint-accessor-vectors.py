"""Rebuild the checkpoint accessor transport fixtures independently."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
fixture = json.loads((root / "vectors/checkpoint-accessor.json").read_text(encoding="utf-8"))
transport = json.loads((root / fixture["sourceVector"]).read_text(encoding="utf-8"))
wire = next(item["wire"] for item in transport["cases"] if item["id"] == fixture["sourceCase"])

def check_bytes(value, length, digest):
    encoded = value.encode("utf-8")
    assert len(encoded) == length
    assert hashlib.sha256(encoded).hexdigest() == digest

check_bytes(wire, fixture["sourceWireBytes"], fixture["sourceWireSha256"])
note = wire[wire.index("\n\n") + 2:]
check_bytes(note, fixture["sourceCheckpointBytes"], fixture["sourceCheckpointSha256"])
assert fixture["manySignatureLine"] == chr(0x2014) + " w{index} AAAAAAA=\n"
cut = note.index("\n\n")
many = note[:cut + 2] + "".join(
    fixture["manySignatureLine"].replace("{index}", str(index))
    for index in range(fixture["manySignatureCount"])
)
check_bytes(many, fixture["manyCheckpointBytes"], fixture["manyCheckpointSha256"])
assert many.count("\n", cut + 2) == fixture["manySignatureCount"]
assert len(fixture["cases"]) == 2
assert {case["id"] for case in fixture["cases"]} == {
    "checkpoint-getter-one-then-many", "checkpoint-getter-many-then-one"
}
for case in fixture["cases"]:
    assert case["getterReads"] == 1
    assert {case["first"], case["later"]} == {"one", "many"}
    if case["expected"] == "VALID":
        assert case["first"] == "one"
        check_bytes(wire, case["expectedWireBytes"], case["expectedWireSha256"])
    else:
        assert case["first"] == "many"
        assert case["expected"] == "SUBTREE_ONE_WITNESS"
        assert case["noBase64Decode"] is True

print("Checkpoint accessor wire and two case fixtures verified")
