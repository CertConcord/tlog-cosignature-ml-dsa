"""Reconstruct exact experimental sign-subtree request/response bytes independently."""

import base64
import hashlib
import json
from pathlib import Path


def sha(value):
    return hashlib.sha256(value).digest()


def tree_hash(leaves):
    if not leaves:
        return sha(b"")
    if len(leaves) == 1:
        return sha(b"\0" + leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return sha(b"\1" + tree_hash(leaves[:split]) + tree_hash(leaves[split:]))


def subtree_proof(start, end, leaves, omit=True):
    if start == end or (start == 0 and end == len(leaves) and omit):
        return []
    if start == 0 and end == len(leaves):
        return [tree_hash(leaves)]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if end <= split:
        return subtree_proof(start, end, leaves[:split], omit) + [tree_hash(leaves[split:])]
    if start >= split:
        return subtree_proof(start - split, end - split, leaves[split:], omit) + [tree_hash(leaves[:split])]
    assert start == 0
    return subtree_proof(0, end - split, leaves[split:], False) + [tree_hash(leaves[:split])]


def wire(item):
    value = bytes.fromhex(item["utf8Hex"])
    assert len(value) == item["bytes"] and sha(value).hex() == item["sha256"]
    return value


def signed_input(context):
    name = context["name"].encode("ascii")
    origin = context["origin"].encode("ascii")
    assert 1 <= len(name) <= 255 and 1 <= len(origin) <= 255
    return (b"subtree/v1\n\0" + bytes([len(name)]) + name
            + context["timestamp"].to_bytes(8, "big")
            + bytes([len(origin)]) + origin
            + context["start"].to_bytes(8, "big") + context["end"].to_bytes(8, "big")
            + bytes.fromhex(context["rootHex"]))


root = Path(__file__).resolve().parent.parent
fixture = json.loads((root / "vectors/subtree-response-auth.json").read_text(encoding="utf-8"))
prior_path = root / "vectors/subtree-consistency.json"
prior_bytes = prior_path.read_bytes()
prior = json.loads(prior_bytes)
assert sha(prior_bytes).hex() == fixture["sourceProofVectorSha256"]
example = next(item for item in prior["cases"] if item["id"] == "n14-range8-13")
leaves = [bytes.fromhex(value) for value in prior["leafUtf8Hex"]]
assert leaves == [f"leaf-{i}".encode() for i in range(14)]
checkpoint_root = tree_hash(leaves)
assert checkpoint_root.hex() == fixture["checkpoint"]["rootHex"] == prior["checkpoint"]["rootHex"]

subtree = fixture["subtree"]
assert (subtree["start"], subtree["end"]) == (8, 13)
subtree_hash = tree_hash(leaves[8:13])
assert subtree_hash.hex() == subtree["rootHex"] == example["subtreeHashHex"]
proof = subtree_proof(8, 13, leaves)
assert [value.hex() for value in proof] == subtree["proofHex"] == example["proofHex"]

witness = fixture["witness"]
name = witness["name"].encode("ascii")
origin = fixture["checkpoint"]["origin"].encode("ascii")
spki = bytes.fromhex(witness["spkiHex"])
other_spki = bytes.fromhex(witness["otherSpkiHex"])
assert len(spki) == len(other_spki) == 2614 and spki != other_spki
hint = sha(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki)[:4]
assert hint.hex() == witness["keyHintHex"]
checkpoint_context = {
    "name": witness["name"], "origin": fixture["checkpoint"]["origin"], "start": 0,
    "end": 14, "rootHex": checkpoint_root.hex(), "timestamp": witness["timestamp"],
}
assert signed_input(checkpoint_context).hex() == fixture["checkpoint"]["signedInputHex"]
body = origin + b"\n14\n" + base64.b64encode(checkpoint_root) + b"\n"
marker = "\u2014 ".encode("utf-8") + name + b" "
note = wire(fixture["checkpoint"]["note"])
assert note.startswith(body + b"\n" + marker) and note.endswith(b"\n")
payload = base64.b64decode(note[len(body + b"\n" + marker):-1], validate=True)
assert payload[:4] == hint and payload[4:12] == witness["timestamp"].to_bytes(8, "big")
assert len(payload[12:]) == fixture["checkpoint"]["signatureBytes"] == 4627
assert sha(payload[12:]).hex() == fixture["checkpoint"]["signatureSha256"]

prefix = (b"subtree 8 13\n" + base64.b64encode(subtree_hash) + b"\n"
          + b"".join(base64.b64encode(item) + b"\n" for item in proof) + b"\n")
valid_request = wire(fixture["requests"]["valid"])
assert valid_request == prefix + note
changed_proof = bytearray(proof[0])
changed_proof[0] ^= 1
bad_prefix = (b"subtree 8 13\n" + base64.b64encode(subtree_hash) + b"\n"
              + base64.b64encode(changed_proof) + b"\n"
              + b"".join(base64.b64encode(item) + b"\n" for item in proof[1:]) + b"\n")
assert wire(fixture["requests"]["alteredProof"]) == bad_prefix + note

contexts = fixture["signatureContexts"]
assert set(contexts) == {"valid", "alteredOrigin", "alteredRange", "alteredName", "alteredRoot", "otherKey"}
for key, context in contexts.items():
    assert signed_input(context).hex() == context["signedInputHex"], key
    assert context["key"] == ("otherSpkiHex" if key == "otherKey" else "spkiHex")
assert contexts["valid"]["signedInputHex"] == contexts["otherKey"]["signedInputHex"] == subtree["signedInputHex"]
assert {contexts[key]["signedInputHex"] for key in ("alteredOrigin", "alteredRange", "alteredName", "alteredRoot")}.isdisjoint({subtree["signedInputHex"]})

responses = fixture["responses"]
decoded = {}
for key, item in responses.items():
    data = wire(item)
    if key == "missingLF":
        assert not data.endswith(b"\n")
        continue
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    decoded[key] = base64.b64decode(data[:-1], validate=True)
    assert base64.b64encode(decoded[key]) + b"\n" == data
assert len(decoded["valid"]) == 4627
assert sha(decoded["valid"]).hex() == subtree["validSignatureSha256"]
assert wire(responses["missingLF"]) == wire(responses["valid"])[:-1]
assert decoded["legacyHintPrefix"] == hint + decoded["valid"]
assert len(decoded["legacyHintPrefix"]) == 4631
altered = bytearray(decoded["valid"])
altered[0] ^= 1
assert decoded["alteredSignature"] == altered
for key in ("alteredOrigin", "alteredRange", "alteredName", "alteredRoot", "otherKey"):
    assert len(decoded[key]) == 4627 and decoded[key] != decoded["valid"]

cases = fixture["cases"]
assert len(cases) == 10 and sum(item["expected"] == "VALID" for item in cases) == 1
assert len({item["id"] for item in cases}) == 10
assert all(item["request"] in fixture["requests"] and item["response"] in responses for item in cases)
print("independent response bytes: 1 positive, 9 negative, 2 request wires, 9 response wires, 6 signed contexts")
