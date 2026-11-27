"""Independently reconstruct original large-u64 Merkle and signed wire bytes."""

import base64
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).digest()
vector = json.loads(read("vectors/subtree-large-u64.json"))
source_bytes = read("vectors/subtree-live-sign.json")
source = json.loads(source_bytes)
assert sha(source_bytes).hex() == vector["sourceLiveVectorSha256"]
assert vector["wireProfile"] == "C2SP-20261007-MLDSA87-v2"
assert vector["upstreamRangeShape"]["sha256"] == "7fcc6d9d0283ecf7d19e221049f477964dfbf048ef43601a640a8c5a62e47d9f"


@lru_cache(maxsize=None)
def power_hash(exponent: int) -> bytes:
    if exponent == 0:
        return sha(b"\x00" + vector["virtualLeafAscii"].encode("ascii"))
    child = power_hash(exponent - 1)
    return sha(b"\x01" + child + child)


@lru_cache(maxsize=None)
def virtual_root(size: int) -> bytes:
    assert size > 0
    if size & (size - 1) == 0:
        return power_hash(size.bit_length() - 1)
    split = 1 << (size.bit_length() - 1)
    return sha(b"\x01" + power_hash(split.bit_length() - 1) + virtual_root(size - split))


def verify(start: int, end: int, size: int, subtree: bytes, tree: bytes, proof: list[bytes]) -> bool:
    if not (0 <= start < end <= size <= 2**64 - 1):
        return False
    width = 1 << (end - start - 1).bit_length()
    if start % width:
        return False
    fn, sn, tn = start, end - 1, size - 1
    if sn == tn:
        while fn != sn:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    else:
        while fn != sn and sn & 1:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    if fn == sn:
        fr = sr = subtree
        remaining = proof
    else:
        if not proof:
            return False
        fr = sr = proof[0]
        remaining = proof[1:]
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
    return tn == 0 and fr == subtree and sr == tree


name = vector["witness"]["name"].encode("ascii")
origin = vector["checkpointOrigin"].encode("ascii")
spki = bytes.fromhex(source["witness"]["spkiHex"])
assert sha(spki).hex() == vector["witness"]["spkiSha256"]
hint = sha(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki)[:4]
assert hint.hex() == vector["witness"]["keyHintHex"]
trees = {}
for item in vector["trees"]:
    size = int(item["size"])
    root = virtual_root(size)
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
    ml_dsa_87.verify(spki[-ml_dsa_87.PUBLIC_KEY_SIZE:], signed, signature)
    trees[item["id"]] = (size, root, note)


positive = negative = 0
for item in vector["cases"]:
    size, tree_root, note = trees[item["tree"]]
    start, end = int(item["start"]), int(item["end"])
    assert 0 <= start < end <= size
    normal_root = virtual_root(end - start)
    root = bytes.fromhex(item["subtreeHashHex"])
    proof = [bytes.fromhex(value) for value in item["proofHex"]]
    assert len(proof) <= 63
    mutation = item["mutation"]
    if mutation is None:
        assert item["expected"] == "VALID" and root == normal_root
        assert verify(start, end, size, root, tree_root, proof)
        positive += 1
    elif mutation == "bad-root":
        assert item["expected"] == "SUBTREE_PROOF"
        assert root == bytes([normal_root[0] ^ 1]) + normal_root[1:]
        assert verify(start, end, size, normal_root, tree_root, proof)
        assert not verify(start, end, size, root, tree_root, proof)
        negative += 1
    elif mutation == "bad-proof":
        assert item["expected"] == "SUBTREE_PROOF" and root == normal_root
        normal_proof = [bytes([proof[0][0] ^ 1]) + proof[0][1:], *proof[1:]]
        assert verify(start, end, size, root, tree_root, normal_proof)
        assert not verify(start, end, size, root, tree_root, proof)
        negative += 1
    else:
        raise AssertionError(mutation)
    raw_prefix = (f"subtree {start} {end}\n".encode() + base64.b64encode(root) + b"\n"
                  + b"".join(base64.b64encode(value) + b"\n" for value in proof) + b"\n")
    assert raw_prefix.hex() == item["requestPrefixUtf8Hex"]
    wire = raw_prefix + note
    assert len(wire) == item["wireBytes"] and sha(wire).hex() == item["wireSha256"]

assert (positive, negative) == (9, 6)
assert sorted({len(case["proofHex"]) for case in vector["cases"] if case["mutation"] is None}) == [0, 24, 32, 36, 47, 48]
print(f"independent large-u64 signed wire replay: {positive} positive, {negative} negative, 3 checkpoint signatures")
