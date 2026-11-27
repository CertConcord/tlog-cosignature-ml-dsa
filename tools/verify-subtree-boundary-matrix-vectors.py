"""Independently reconstruct the 257-leaf subtree bytes and ML-DSA-87 note."""

import base64
import hashlib
import json
from pathlib import Path

from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).digest()
vector = json.loads(read("vectors/subtree-boundary-matrix.json"))
source_bytes = read("vectors/subtree-live-sign.json")
source = json.loads(source_bytes)
assert sha(source_bytes).hex() == vector["sourceLiveVectorSha256"]
assert vector["wireProfile"] == "C2SP-20261007-MLDSA87-v2"


def tree_hash(leaves):
    if not leaves:
        return sha(b"")
    if len(leaves) == 1:
        return sha(b"\x00" + leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return sha(b"\x01" + tree_hash(leaves[:split]) + tree_hash(leaves[split:]))


def branch(start, end, leaves, include_root=False):
    if start == end:
        return []
    if start == 0 and end == len(leaves):
        return [tree_hash(leaves)] if include_root else []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if end <= split:
        return branch(start, end, leaves[:split], include_root) + [tree_hash(leaves[split:])]
    if start >= split:
        return branch(start - split, end - split, leaves[split:], include_root) + [tree_hash(leaves[:split])]
    assert start == 0
    return branch(0, end - split, leaves[split:], True) + [tree_hash(leaves[:split])]


name = vector["witness"]["name"].encode("ascii")
origin = vector["checkpoint"]["origin"].encode("ascii")
spki = bytes.fromhex(source["witness"]["spkiHex"])
assert len(spki) == 2614 and sha(spki).hex() == vector["witness"]["spkiSha256"]
assert spki[:22] == bytes.fromhex("30820a32300b060960864801650304031303820a2100")
hint = sha(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki)[:4]
assert hint.hex() == vector["witness"]["keyHintHex"]
leaves = [f"boundary-leaf-{index}".encode("ascii") for index in range(257)]
assert vector["leafPattern"] == "boundary-leaf-{index}" and vector["leafCount"] == len(leaves)
root = tree_hash(leaves)
checkpoint = vector["checkpoint"]
assert checkpoint["size"] == 257 and root.hex() == checkpoint["rootHex"]
note = bytes.fromhex(checkpoint["noteUtf8Hex"])
assert len(note) == checkpoint["noteBytes"] and sha(note).hex() == checkpoint["noteSha256"]
body = origin + b"\n257\n" + base64.b64encode(root) + b"\n"
line_prefix = body + b"\n" + "\u2014 ".encode() + name + b" "
assert note.startswith(line_prefix) and note.endswith(b"\n")
payload = base64.b64decode(note[len(line_prefix):-1], validate=True)
assert base64.b64encode(payload) == note[len(line_prefix):-1]
assert payload[:4] == hint
timestamp = vector["witness"]["timestamp"]
assert payload[4:12] == timestamp.to_bytes(8, "big")
signature = payload[12:]
assert len(signature) == ml_dsa_87.SIGNATURE_SIZE == 4627
signed = (b"subtree/v1\n\x00" + bytes([len(name)]) + name + timestamp.to_bytes(8, "big")
          + bytes([len(origin)]) + origin + (0).to_bytes(8, "big")
          + (257).to_bytes(8, "big") + root)
ml_dsa_87.verify(spki[-ml_dsa_87.PUBLIC_KEY_SIZE:], signed, signature)

positive = negative = 0
for case in vector["cases"]:
    start, end = case["start"], case["end"]
    assert 0 <= start <= end <= len(leaves)
    width = 1 << (end - start - 1).bit_length() if end > start else 1
    assert start % width == 0
    normal_root = tree_hash(leaves[start:end])
    normal_proof = branch(start, end, leaves)
    root_bytes = bytes.fromhex(case["subtreeHashHex"])
    proof_bytes = [bytes.fromhex(value) for value in case["proofHex"]]
    mutation = case["mutation"]
    if mutation is None:
        assert case["expected"] == "VALID"
        assert root_bytes == normal_root and proof_bytes == normal_proof
        positive += 1
    else:
        assert case["expected"] == "SUBTREE_PROOF"
        if mutation == "bad-root":
            assert root_bytes == bytes([normal_root[0] ^ 1]) + normal_root[1:]
            assert proof_bytes == normal_proof
        elif mutation == "bad-proof":
            assert normal_proof
            altered = bytes([normal_proof[0][0] ^ 1]) + normal_proof[0][1:]
            assert root_bytes == normal_root and proof_bytes == [altered, *normal_proof[1:]]
        elif mutation == "short-proof":
            assert normal_proof and root_bytes == normal_root and proof_bytes == normal_proof[:-1]
        elif mutation == "extra-proof":
            assert root_bytes == normal_root and proof_bytes == normal_proof + [bytes(32)]
        else:
            raise AssertionError(mutation)
        negative += 1
    prefix = (f"subtree {start} {end}\n".encode() + base64.b64encode(root_bytes) + b"\n"
              + b"".join(base64.b64encode(value) + b"\n" for value in proof_bytes) + b"\n")
    assert prefix.hex() == case["requestPrefixUtf8Hex"]
    wire = prefix + note
    assert len(wire) == case["wireBytes"] and sha(wire).hex() == case["wireSha256"]

assert (positive, negative) == (6, 6)
sizes = [0, 1, 2, 3, 4, 7, 8, 9, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65,
         127, 128, 129, 255, 256, 257]
count = sum(1 for size in sizes for start in range(size + 1) for end in range(start, size + 1)
            if start % (1 << (end - start - 1).bit_length() if end > start else 1) == 0)
assert count == 8465
print(f"independent boundary matrix: {positive} positive, {negative} negative frozen wires; {count} aligned ranges")
