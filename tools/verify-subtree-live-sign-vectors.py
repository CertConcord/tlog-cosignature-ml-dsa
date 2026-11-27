"""Independently reconstruct the frozen live-signer HTTP byte fixtures."""

import base64
import hashlib
import json
from pathlib import Path


def sha(value):
    return hashlib.sha256(value).hexdigest()


def wire(item):
    value = bytes.fromhex(item["utf8Hex"])
    assert len(value) == item["bytes"] and sha(value) == item["sha256"]
    return value


def signed_input(name, origin, start, end, root, timestamp):
    name, origin = name.encode("ascii"), origin.encode("ascii")
    assert 1 <= len(name) <= 255 and 1 <= len(origin) <= 255
    return (b"subtree/v1\n\0" + bytes([len(name)]) + name
            + timestamp.to_bytes(8, "big") + bytes([len(origin)]) + origin
            + start.to_bytes(8, "big") + end.to_bytes(8, "big") + root)


root = Path(__file__).resolve().parent.parent
data = json.loads((root / "vectors/subtree-live-sign.json").read_bytes())
raw_source = (root / "vectors/subtree-http-interop.json").read_bytes()
assert sha(raw_source) == data["sourceInteropVectorSha256"]
source = json.loads(raw_source)
auth = json.loads((root / "vectors/subtree-response-auth.json").read_bytes())
name = data["witness"]["name"]
at = data["witness"]["at"]
assert name == source["witness"]["name"] and at == source["witness"]["at"]
assert bytes.fromhex(data["witness"]["spkiHex"])[:14] == bytes.fromhex("30820a32300b0609608648016503")
assert len(bytes.fromhex(data["witness"]["spkiHex"])) == 2614
assert len(bytes.fromhex(data["witness"]["pkcs8Hex"])) == 4962
assert len(bytes.fromhex(data["witness"]["keyIDHex"])) == 4

cp = auth["checkpoint"]
origin = cp["origin"]
checkpoint_root = bytes.fromhex(cp["rootHex"])
checkpoint_input = signed_input(name, origin, 0, cp["size"], checkpoint_root,
                                data["checkpoint"]["timestamp"])
assert checkpoint_input.hex() == data["checkpoint"]["signedInputHex"]
checkpoint_signature = bytes.fromhex(data["checkpoint"]["signatureHex"])
assert len(checkpoint_signature) == 4627
payload = (bytes.fromhex(data["witness"]["keyIDHex"])
           + data["checkpoint"]["timestamp"].to_bytes(8, "big") + checkpoint_signature)
body = (origin.encode("ascii") + b"\n" + str(cp["size"]).encode("ascii") + b"\n"
        + base64.b64encode(checkpoint_root) + b"\n")
note = body + b"\n" + "— ".encode("utf8") + name.encode("ascii") + b" " + base64.b64encode(payload) + b"\n"
assert note == wire(data["checkpoint"]["note"])

subtree = auth["subtree"]
node_root = bytes.fromhex(subtree["rootHex"])
proof = [bytes.fromhex(value) for value in subtree["proofHex"]]
request = (f"subtree {subtree['start']} {subtree['end']}\n".encode("ascii")
           + base64.b64encode(node_root) + b"\n"
           + b"".join(base64.b64encode(value) + b"\n" for value in proof)
           + b"\n" + note)
assert request == wire(data["request"]) and len(request) == 6527
input_bytes = signed_input(name, origin, subtree["start"], subtree["end"], node_root, 0)
assert input_bytes.hex() == data["signerInputHex"] and len(input_bytes) == 114
bad_input = bytes.fromhex(data["badSignerInputHex"])
assert bad_input == input_bytes[:-1] + bytes([input_bytes[-1] ^ 1])

response = wire(data["frozenResponse"])
assert len(response) == 6173 and response.endswith(b"\n")
signature = base64.b64decode(response[:-1], validate=True)
assert len(signature) == 4627 and base64.b64encode(signature) + b"\n" == response
bad_signature = bytes.fromhex(data["badSignatureHex"])
assert len(bad_signature) == 4627 and bad_signature != signature
assert data["cases"] == [
    {"id": "live-signer-loopback", "expected": "VALID"},
    {"id": "frozen-signer-response", "expected": "VALID"},
    {"id": "wrong-message-signer", "expected": "SUBTREE_SIGNER_SIGNATURE"},
    {"id": "wrong-message-response", "expected": "SUBTREE_SIGNATURE"},
]
print("independent live-signer bytes: 6527-byte request, 6173-byte frozen response, 114-byte positive and one-byte negative inputs")
