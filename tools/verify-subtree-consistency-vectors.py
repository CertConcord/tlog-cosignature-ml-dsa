"""Rebuild the frozen SHA-256/MTC proof and sign-subtree request bytes independently."""

import base64
import hashlib
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).digest()


def join(left, right):
    return digest(b"\x01" + left + right)


def mth(leaves):
    if not leaves:
        return digest(b"")
    if len(leaves) == 1:
        return digest(b"\x00" + leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return join(mth(leaves[:split]), mth(leaves[split:]))


def proof(start, end, leaves, omit=True):
    if start == end:
        return []
    if start == 0 and end == len(leaves):
        return [] if omit else [mth(leaves)]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if end <= split:
        return proof(start, end, leaves[:split], omit) + [mth(leaves[split:])]
    if start >= split:
        return proof(start - split, end - split, leaves[split:], omit) + [mth(leaves[:split])]
    assert start == 0
    return proof(0, end - split, leaves[split:], False) + [mth(leaves[:split])]


def verify(start, end, node_hash, items, size, root_hash):
    if not (0 <= start <= end <= size):
        return False
    width = 1 << (end - start - 1).bit_length() if end > start else 1
    if start % width or any(len(x) != 32 for x in [node_hash, root_hash, *items]):
        return False
    if start == end:
        return len(items) == 0 and node_hash == digest(b"")
    fn, sn, tn = start, end - 1, size - 1
    if sn == tn:
        while fn != sn:
            fn >>= 1
            sn >>= 1
            tn >>= 1
    else:
        while fn != sn and sn & 1:
            fn >>= 1
            sn >>= 1
            tn >>= 1
    rest = list(items)
    if fn == sn:
        fr = sr = node_hash
    else:
        if not rest:
            return False
        fr = sr = rest.pop(0)
    for value in rest:
        if tn == 0:
            return False
        if sn & 1 or sn == tn:
            if fn < sn:
                fr = join(value, fr)
            sr = join(value, sr)
            while not sn & 1:
                fn >>= 1
                sn >>= 1
                tn >>= 1
        else:
            sr = join(sr, value)
        fn >>= 1
        sn >>= 1
        tn >>= 1
    return tn == 0 and fr == node_hash and sr == root_hash


data = json.loads((Path(__file__).resolve().parent.parent / "vectors/subtree-consistency.json").read_text(encoding="utf-8"))
leaves = [bytes.fromhex(value) for value in data["leafUtf8Hex"]]
assert leaves == [f"leaf-{index}".encode("ascii") for index in range(14)]
root = mth(leaves)
assert root.hex() == data["checkpoint"]["rootHex"]

witness = data["witness"]
checkpoint = data["checkpoint"]
name = witness["name"].encode("ascii")
origin = checkpoint["origin"].encode("ascii")
spki = bytes.fromhex(witness["spkiHex"])
assert len(spki) == 2614
hint = digest(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki)[:4]
assert hint.hex() == witness["keyHintHex"]
signed = (b"subtree/v1\n\0" + bytes([len(name)]) + name + witness["timestamp"].to_bytes(8, "big")
          + bytes([len(origin)]) + origin + (0).to_bytes(8, "big") + (14).to_bytes(8, "big") + root)
assert signed.hex() == witness["signedInputHex"]
assert digest(signed).hex() == witness["signedInputSha256"]
body = origin + b"\n14\n" + base64.b64encode(root) + b"\n"
assert body.hex() == checkpoint["bodyUtf8Hex"]
note = bytes.fromhex(checkpoint["noteUtf8Hex"])
assert len(note) == checkpoint["noteBytes"] and digest(note).hex() == checkpoint["noteSha256"]
assert note.startswith(body + b"\n" + "— ".encode() + name + b" ") and note.endswith(b"\n")
payload = base64.b64decode(note[len(body + b"\n" + "— ".encode() + name + b" "):-1], validate=True)
assert payload[:4] == hint and payload[4:12] == witness["timestamp"].to_bytes(8, "big")
signature = payload[12:]
assert len(signature) == witness["signatureBytes"] == 4627
assert digest(signature).hex() == witness["signatureSha256"]

positive = negative = 0
for case in data["cases"]:
    assert case["start"] <= case["end"] <= checkpoint["size"]
    node_hash = bytes.fromhex(case["subtreeHashHex"])
    nodes = [bytes.fromhex(value) for value in case["proofHex"]]
    assert len(nodes) <= 63
    prefix = (f"subtree {case['start']} {case['end']}\n".encode("ascii") + base64.b64encode(node_hash) + b"\n"
              + b"".join(base64.b64encode(item) + b"\n" for item in nodes) + b"\n")
    assert prefix.hex() == case["requestPrefixUtf8Hex"], case["id"]
    wire = prefix + note
    assert len(wire) == case["wireBytes"] and digest(wire).hex() == case["wireSha256"], case["id"]
    actual = verify(case["start"], case["end"], node_hash, nodes, checkpoint["size"], root)
    assert actual == (case["expected"] == "VALID"), case["id"]
    if actual:
        assert node_hash == mth(leaves[case["start"]:case["end"]]), case["id"]
        assert nodes == proof(case["start"], case["end"], leaves), case["id"]
        positive += 1
    else:
        negative += 1

assert (positive, negative) == (6, 7)
print(f"independent subtree consistency bytes and proof cases: {positive} positive, {negative} negative")
