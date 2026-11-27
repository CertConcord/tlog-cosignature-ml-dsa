"""Freeze Python-signed HTTP responses for the original large-u64 request."""

import base64
import hashlib
import json
from pathlib import Path

from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
source_bytes = (ROOT / "vectors/subtree-large-u64.json").read_bytes()
source = json.loads(source_bytes)
key_source = json.loads((ROOT / "vectors/subtree-live-sign.json").read_bytes())
sha = lambda data: hashlib.sha256(data).hexdigest()
size = "18446744069414649856"
tree = next(item for item in source["trees"] if item["size"] == size)
case_id = f"large-u64-{size}-last"
valid = next(item for item in source["cases"] if item["id"] == case_id)
bad_proof = next(item for item in source["cases"] if item["id"] == case_id + "-bad-proof")
note = bytes.fromhex(tree["noteUtf8Hex"])
wire = lambda item: bytes.fromhex(item["requestPrefixUtf8Hex"]) + note
assert len(wire(valid)) == valid["wireBytes"] == 8563
assert sha(wire(valid)) == valid["wireSha256"]
assert len(valid["proofHex"]) == 48
assert sha(wire(bad_proof)) == bad_proof["wireSha256"]

name = source["witness"]["name"].encode("ascii")
origin = source["checkpointOrigin"].encode("ascii")
root = bytes.fromhex(valid["subtreeHashHex"])


def signed_input(message_root):
    return (b"subtree/v1\n\x00" + bytes([len(name)]) + name + bytes(8)
            + bytes([len(origin)]) + origin + int(valid["start"]).to_bytes(8, "big")
            + int(valid["end"]).to_bytes(8, "big") + message_root)


spki = bytes.fromhex(key_source["witness"]["spkiHex"])
pkcs8 = bytes.fromhex(key_source["witness"]["pkcs8Hex"])
assert sha(spki) == source["witness"]["spkiSha256"]
assert len(spki) == 2614 and len(pkcs8) == 4962
public = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
private = pkcs8[-ml_dsa_87.SECRET_KEY_SIZE:]
message = signed_input(root)
wrong_message = message[:-1] + bytes([message[-1] ^ 1])


def body(signed):
    signature = ml_dsa_87.sign(private, signed, context=b"")
    ml_dsa_87.verify(public, signed, signature, context=b"")
    assert len(signature) == 4627
    data = base64.b64encode(signature) + b"\n"
    assert len(data) == 6173
    return {"utf8Hex": data.hex(), "bytes": len(data), "sha256": sha(data),
            "signatureSha256": sha(signature)}


vector = {
    "schemaVersion": 1,
    "wireProfile": "C2SP-20261007-MLDSA87-v2",
    "producer": {"package": "pqcrypto", "version": "1.0.0"},
    "sourceLargeVectorSha256": sha(source_bytes),
    "sourceLiveVectorSha256": sha((ROOT / "vectors/subtree-live-sign.json").read_bytes()),
    "endpointPath": "/witness/sign-subtree",
    "requestSourceCase": case_id,
    "badProofSourceCase": bad_proof["id"],
    "requestBytes": valid["wireBytes"],
    "requestSha256": valid["wireSha256"],
    "badProofRequestSha256": bad_proof["wireSha256"],
    "proofLines": len(valid["proofHex"]),
    "signerInputHex": message.hex(),
    "wrongSignerInputHex": wrong_message.hex(),
    "responses": {"valid": body(message), "wrongMessage": body(wrong_message)},
    "cases": [
        {"id": "large-u64-http-frozen-valid", "mode": "frozen", "expected": "VALID", "sent": 1},
        {"id": "large-u64-http-live-valid", "mode": "live", "expected": "VALID", "sent": 1},
        {"id": "large-u64-http-wrong-response", "mode": "wrong-response",
         "expected": "SUBTREE_SIGNATURE", "sent": 1},
        {"id": "large-u64-http-bad-proof-local", "mode": "bad-proof-local",
         "expected": "SUBTREE_PROOF", "sent": 0},
        {"id": "large-u64-http-raw-bad-proof", "mode": "raw-bad-proof",
         "expected": "HTTP_422", "sent": 1, "status": 422},
    ],
}
dest = ROOT / "vectors/subtree-large-u64-http.json"
dest.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"cases": len(vector["cases"]), "requestBytes": valid["wireBytes"],
                  "responseBytes": [item["bytes"] for item in vector["responses"].values()],
                  "vectorBytes": dest.stat().st_size}))
