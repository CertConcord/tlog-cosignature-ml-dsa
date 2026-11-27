"""Verify Node and Python ML-DSA-87 signatures with an independent engine."""

import base64
import hashlib
import json
from pathlib import Path

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import ml_dsa_87


def sha(value):
    return hashlib.sha256(value).hexdigest()


def wire(item):
    value = bytes.fromhex(item["utf8Hex"])
    assert len(value) == item["bytes"] and sha(value) == item["sha256"]
    return value


def rejects(public, message, signature, context):
    try:
        ml_dsa_87.verify(public, message, signature, context=context)
    except InvalidSignatureError:
        return
    raise AssertionError("an invalid ML-DSA-87 signature was accepted")


root = Path(__file__).resolve().parent.parent
source_bytes = (root / "vectors/subtree-live-sign.json").read_bytes()
source = json.loads(source_bytes)
vector = json.loads((root / "vectors/subtree-cross-runtime.json").read_bytes())
assert sha(source_bytes) == vector["sourceLiveVectorSha256"]
assert vector["producer"]["package"] == "pqcrypto"
assert vector["producer"]["version"] == "1.0.0"
assert vector["producer"]["windowsWheelSha256"] == "d65d0fdbd2bfcfd80193d1d499142e63dd8ea6a072e1dc68b1b36fd49f9fdc8f"

spki = bytes.fromhex(source["witness"]["spkiHex"])
pkcs8 = bytes.fromhex(source["witness"]["pkcs8Hex"])
assert len(spki) == 2614 and len(pkcs8) == 4962
assert spki[:22] == bytes.fromhex("30820a32300b060960864801650304031303820a2100")
public = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
private = pkcs8[-ml_dsa_87.SECRET_KEY_SIZE:]
assert len(public) == 2592 and len(private) == 4896
assert ml_dsa_87.SIGNATURE_SIZE == 4627

message = bytes.fromhex(vector["signedInputHex"])
bad_message = bytes.fromhex(vector["badSignedInputHex"])
assert message.hex() == source["signerInputHex"] and len(message) == 114
assert bad_message.hex() == source["badSignerInputHex"]
assert bad_message == message[:-1] + bytes([message[-1] ^ 1])
wrong_context = bytes.fromhex(vector["wrongContextHex"])
assert wrong_context == b"\x01"

node_response = wire(source["frozenResponse"])
assert node_response.endswith(b"\n") and len(node_response) == 6173
node_signature = base64.b64decode(node_response[:-1], validate=True)
assert len(node_signature) == 4627
ml_dsa_87.verify(public, message, node_signature, context=b"")
checkpoint_message = bytes.fromhex(source["checkpoint"]["signedInputHex"])
checkpoint_signature = bytes.fromhex(source["checkpoint"]["signatureHex"])
ml_dsa_87.verify(public, checkpoint_message, checkpoint_signature, context=b"")

python_signature = bytes.fromhex(vector["pythonSignatureHex"])
python_response = wire(vector["pythonResponse"])
assert len(python_signature) == 4627 and len(python_response) == 6173
assert python_response == base64.b64encode(python_signature) + b"\n"
ml_dsa_87.verify(public, message, python_signature, context=b"")
rejects(public, bad_message, python_signature, b"")
rejects(public, message, python_signature, wrong_context)
rejects(public, bad_message, node_signature, b"")
rejects(public, message, node_signature, wrong_context)

# Fresh signing confirms the test-only PKCS#8 payload matches the pinned SPKI.
fresh_signature = ml_dsa_87.sign(private, message, context=b"")
assert len(fresh_signature) == 4627
ml_dsa_87.verify(public, message, fresh_signature, context=b"")
assert vector["cases"] == [
    {"id": "cross-node-response-python-verify", "expected": "VALID"},
    {"id": "cross-node-checkpoint-python-verify", "expected": "VALID"},
    {"id": "cross-python-response-node-verify", "expected": "VALID"},
    {"id": "cross-python-signature-bad-message", "expected": "INVALID_SIGNATURE"},
    {"id": "cross-python-signature-bad-context", "expected": "INVALID_SIGNATURE"},
]
print("independent ML-DSA-87: Node checkpoint/response and Python response accepted; one-byte message and nonempty context rejected")
