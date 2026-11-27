"""Build frozen boundary-tree request bytes with the published test-only key."""

import base64
import hashlib
import json
from pathlib import Path

from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "vectors/subtree-live-sign.json"
DEST = ROOT / "vectors/subtree-boundary-matrix.json"


def digest(data):
    return hashlib.sha256(data).digest()


def mth(leaves):
    if not leaves:
        return digest(b"")
    if len(leaves) == 1:
        return digest(b"\x00" + leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return digest(b"\x01" + mth(leaves[:split]) + mth(leaves[split:]))


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


source_bytes = SOURCE.read_bytes()
source = json.loads(source_bytes)
source_witness = source["witness"]
name = source_witness["name"].encode("ascii")
spki = bytes.fromhex(source_witness["spkiHex"])
pkcs8 = bytes.fromhex(source_witness["pkcs8Hex"])
assert len(spki) == 2614 and len(pkcs8) == 4962
assert spki[:22] == bytes.fromhex("30820a32300b060960864801650304031303820a2100")
assert pkcs8[:30] == bytes.fromhex("3082135e020100300b06096086480165030403130482134a308213460420")
public = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
private = pkcs8[-ml_dsa_87.SECRET_KEY_SIZE:]
hint = digest(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki)[:4]
assert hint.hex() == source_witness["keyIDHex"]

leaves = [f"boundary-leaf-{index}".encode("ascii") for index in range(257)]
origin = b"log.example/boundary-matrix"
root = mth(leaves)
timestamp = 1700000000
signed = (b"subtree/v1\n\x00" + bytes([len(name)]) + name + timestamp.to_bytes(8, "big")
          + bytes([len(origin)]) + origin + (0).to_bytes(8, "big")
          + len(leaves).to_bytes(8, "big") + root)
signature = ml_dsa_87.sign(private, signed)
ml_dsa_87.verify(public, signed, signature)
body = origin + b"\n257\n" + base64.b64encode(root) + b"\n"
note = body + b"\n" + "\u2014 ".encode() + name + b" " + base64.b64encode(
    hint + timestamp.to_bytes(8, "big") + signature) + b"\n"


def case(id, start, end, mutation=None):
    node_hash = mth(leaves[start:end])
    nodes = proof(start, end, leaves)
    if mutation == "bad-root":
        node_hash = bytes([node_hash[0] ^ 1]) + node_hash[1:]
    elif mutation == "bad-proof":
        assert nodes
        nodes[0] = bytes([nodes[0][0] ^ 1]) + nodes[0][1:]
    elif mutation == "short-proof":
        assert nodes
        nodes = nodes[:-1]
    elif mutation == "extra-proof":
        nodes = nodes + [bytes(32)]
    else:
        assert mutation is None
    prefix = (f"subtree {start} {end}\n".encode() + base64.b64encode(node_hash) + b"\n"
              + b"".join(base64.b64encode(node) + b"\n" for node in nodes) + b"\n")
    wire = prefix + note
    return {"id": id, "start": start, "end": end,
            "subtreeHashHex": node_hash.hex(), "proofHex": [node.hex() for node in nodes],
            "requestPrefixUtf8Hex": prefix.hex(), "wireBytes": len(wire),
            "wireSha256": digest(wire).hex(), "expected": "VALID" if mutation is None else "SUBTREE_PROOF",
            "mutation": mutation}


specs = [
    ("boundary-n257-full", 0, 257, None),
    ("boundary-n257-left-256", 0, 256, None),
    ("boundary-n257-right-leaf", 256, 257, None),
    ("boundary-n257-prefix-129", 0, 129, None),
    ("boundary-n257-middle-128", 128, 256, None),
    ("boundary-n257-empty-right", 257, 257, None),
    ("boundary-n257-full-bad-root", 0, 257, "bad-root"),
    ("boundary-n257-left-256-bad-proof", 0, 256, "bad-proof"),
    ("boundary-n257-right-leaf-bad-root", 256, 257, "bad-root"),
    ("boundary-n257-prefix-129-short-proof", 0, 129, "short-proof"),
    ("boundary-n257-middle-128-extra-proof", 128, 256, "extra-proof"),
    ("boundary-n257-empty-right-bad-root", 257, 257, "bad-root"),
]
vector = {
    "schemaVersion": 1,
    "wireProfile": "C2SP-20261007-MLDSA87-v2",
    "sourceLiveVectorSha256": digest(source_bytes).hex(),
    "leafPattern": "boundary-leaf-{index}",
    "leafCount": 257,
    "witness": {"name": name.decode(), "spkiSha256": digest(spki).hex(),
                "keyHintHex": hint.hex(), "timestamp": timestamp,
                "at": source_witness["at"]},
    "checkpoint": {"origin": origin.decode(), "size": 257, "rootHex": root.hex(),
                   "noteUtf8Hex": note.hex(), "noteBytes": len(note),
                   "noteSha256": digest(note).hex()},
    "cases": [case(*spec) for spec in specs],
}
DEST.write_text(json.dumps(vector, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"{len(specs)} frozen request cases, checkpoint {len(note)} bytes, vector {DEST.stat().st_size} bytes")
