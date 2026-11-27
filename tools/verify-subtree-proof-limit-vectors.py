"""Independently replay signed 63/64-line MTC proofs and C2SP request bytes."""

import base64
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).digest()
vector = json.loads(read("vectors/subtree-proof-limit.json"))
source_bytes = read("vectors/subtree-live-sign.json")
source = json.loads(source_bytes)
assert sha(source_bytes).hex() == vector["sourceLiveVectorSha256"]
assert vector["wireProfile"] == "C2SP-20261007-MLDSA87-v2"
assert vector["selectedProofRule"] == "MTC draft-07 Section 4.4.3"
assert vector["maxTransportProofLines"] == 63

leaf = sha(b"\x00" + vector["virtualLeafAscii"].encode("ascii"))


@lru_cache(maxsize=None)
def tree(size):
    if size == 1:
        return leaf
    split = 1 << ((size - 1).bit_length() - 1)
    return sha(b"\x01" + tree(split) + tree(size - split))


def proof(start, end, size, include_root=False):
    if start == 0 and end == size:
        return [tree(size)] if include_root else []
    split = 1 << ((size - 1).bit_length() - 1)
    if end <= split:
        return proof(start, end, split, include_root) + [tree(size - split)]
    if start >= split:
        return proof(start - split, end - split, size - split, include_root) + [tree(split)]
    raise AssertionError("unaligned range")


def mtc_verify(start, end, size, subtree, root, nodes):
    fn, sn, tn = start, end - 1, size - 1
    if sn == tn:
        while fn != sn:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    else:
        while fn != sn and sn & 1:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    if fn == sn:
        fr = sr = subtree
        remaining = nodes
    else:
        if not nodes:
            return False
        fr = sr = nodes[0]
        remaining = nodes[1:]
    for current in remaining:
        if tn == 0:
            return False
        if sn & 1 or sn == tn:
            if fn < sn:
                fr = sha(b"\x01" + current + fr)
            sr = sha(b"\x01" + current + sr)
            while not sn & 1:
                fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
        else:
            sr = sha(b"\x01" + sr + current)
        fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    return tn == 0 and fr == subtree and sr == root


name = vector["witness"]["name"].encode("ascii")
origin = vector["checkpointOrigin"].encode("ascii")
spki = bytes.fromhex(source["witness"]["spkiHex"])
assert sha(spki).hex() == vector["witness"]["spkiSha256"]
hint = sha(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki)[:4]
assert hint.hex() == vector["witness"]["keyHintHex"]
public_key = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
trees = {}
for item in vector["trees"]:
    size = int(item["size"])
    assert size in (2**63, 2**63 + 1, 2**64 - 1)
    root = tree(size)
    assert root.hex() == item["rootHex"]
    note = bytes.fromhex(item["noteUtf8Hex"])
    assert len(note) == item["noteBytes"] and sha(note).hex() == item["noteSha256"]
    prefix = origin + b"\n" + str(size).encode() + b"\n" + base64.b64encode(root) + b"\n\n" + "\u2014 ".encode() + name + b" "
    assert note.startswith(prefix) and note.endswith(b"\n")
    encoded = note[len(prefix):-1]
    payload = base64.b64decode(encoded, validate=True)
    assert base64.b64encode(payload) == encoded
    timestamp = int(vector["witness"]["timestamp"])
    assert payload[:12] == hint + timestamp.to_bytes(8, "big")
    signature = payload[12:]
    assert len(signature) == ml_dsa_87.SIGNATURE_SIZE == 4627
    signed = (b"subtree/v1\n\x00" + bytes([len(name)]) + name + timestamp.to_bytes(8, "big")
              + bytes([len(origin)]) + origin + (0).to_bytes(8, "big") + size.to_bytes(8, "big") + root)
    ml_dsa_87.verify(public_key, signed, signature)
    trees[item["id"]] = (size, root, note)

expected = [(63, "VALID"), (63, "SUBTREE_PROOF"), (64, "SUBTREE_REQUEST"), (64, "SUBTREE_REQUEST")]
assert [(len(x["proofHex"]), x["expected"]) for x in vector["cases"]] == expected
for item in vector["cases"]:
    size, root, note = trees[item["tree"]]
    nodes = [bytes.fromhex(value) for value in item["proofHex"]]
    canonical = proof(0, 1, size)
    assert len(canonical) == len(nodes)
    if item["mutation"] is None:
        assert nodes == canonical and mtc_verify(0, 1, size, leaf, root, nodes)
    else:
        assert item["mutation"] == "bad-proof-byte" and size == 2**63
        assert nodes[0] == bytes([canonical[0][0] ^ 1]) + canonical[0][1:]
        assert nodes[1:] == canonical[1:]
        assert not mtc_verify(0, 1, size, leaf, root, nodes)
    prefix = (b"subtree 0 1\n" + base64.b64encode(leaf) + b"\n"
              + b"".join(base64.b64encode(value) + b"\n" for value in nodes) + b"\n")
    assert prefix.hex() == item["requestPrefixUtf8Hex"]
    assert item["subtreeHashHex"] == leaf.hex()
    wire = prefix + note
    assert len(wire) == item["wireBytes"] and sha(wire).hex() == item["wireSha256"]
    assert len(nodes) <= vector["maxTransportProofLines"] if item["expected"] != "SUBTREE_REQUEST" else len(nodes) > vector["maxTransportProofLines"]

print("independent proof-limit wire replay: one 63-line positive, one changed-byte proof negative, two mathematically valid 64-line transport negatives")
