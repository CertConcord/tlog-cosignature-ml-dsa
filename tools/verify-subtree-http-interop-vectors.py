"""Independently reconstruct the exact loopback client/witness byte fixtures."""

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


root = Path(__file__).resolve().parent.parent
vector = json.loads((root / "vectors/subtree-http-interop.json").read_bytes())
raw_server = (root / "vectors/subtree-http.json").read_bytes()
raw_client = (root / "vectors/subtree-http-client.json").read_bytes()
raw_auth = (root / "vectors/subtree-response-auth.json").read_bytes()
assert sha(raw_server) == vector["sourceServerVectorSha256"]
assert sha(raw_client) == vector["sourceClientVectorSha256"]
assert sha(raw_auth) == vector["sourceResponseAuthVectorSha256"]
server, client, auth = map(json.loads, (raw_server, raw_client, raw_auth))
assert vector["endpoint"] == client["request"] == {"method": "POST", "path": "/witness/sign-subtree"}
assert vector["witness"] == {key: server["witness"][key] for key in
                             ("name", "spkiHex", "otherSpkiHex", "at")}
assert all(vector["witness"][key] == client["witness"][key] for key in ("name", "spkiHex", "at"))
assert vector["expectedOrigin"] == auth["checkpoint"]["origin"]
assert wire(vector["requests"]["valid"]) == wire(server["requests"]["valid"]) == wire(client["requests"]["valid"])
assert wire(vector["requests"]["badProof"]) == wire(server["requests"]["badProof"]) == wire(client["requests"]["badProof"])
assert wire(vector["bodies"]["success"]) == wire(server["bodies"]["success"]) == wire(client["responses"]["valid"])
assert wire(vector["bodies"]["empty"]) == wire(server["bodies"]["empty"]) == b""

subtree = auth["subtree"]
name = vector["witness"]["name"].encode("ascii")
origin = vector["expectedOrigin"].encode("ascii")
signed_input = (b"subtree/v1\n\0" + bytes([len(name)]) + name + (0).to_bytes(8, "big")
                + bytes([len(origin)]) + origin + subtree["start"].to_bytes(8, "big")
                + subtree["end"].to_bytes(8, "big") + bytes.fromhex(subtree["rootHex"]))
assert signed_input.hex() == vector["signerInputHex"] == subtree["signedInputHex"]
root_hash = bytes.fromhex(subtree["rootHex"])
proof = [bytes.fromhex(item) for item in subtree["proofHex"]]
prefix = (f"subtree {subtree['start']} {subtree['end']}\n".encode("ascii")
          + base64.b64encode(root_hash) + b"\n"
          + b"".join(base64.b64encode(item) + b"\n" for item in proof) + b"\n")
note = wire(auth["checkpoint"]["note"])
assert wire(vector["requests"]["valid"]) == prefix + note
bad_first = bytearray(proof[0])
bad_first[0] ^= 1
bad_prefix = (f"subtree {subtree['start']} {subtree['end']}\n".encode("ascii")
              + base64.b64encode(root_hash) + b"\n"
              + base64.b64encode(bad_first) + b"\n"
              + b"".join(base64.b64encode(item) + b"\n" for item in proof[1:]) + b"\n")
assert wire(vector["requests"]["badProof"]) == bad_prefix + note
success = wire(vector["bodies"]["success"])
assert len(success) == 6173 and success.endswith(b"\n")
signature = base64.b64decode(success[:-1], validate=True)
assert len(signature) == 4627 and base64.b64encode(signature) + b"\n" == success
assert sha(signature) == auth["subtree"]["validSignatureSha256"]

cases = vector["cases"]
assert len(cases) == 4 and len({case["id"] for case in cases}) == 4
by_id = {case["id"]: case for case in cases}
assert by_id == {
    "interop-valid": {"id": "interop-valid", "request": "valid", "serverKey": "selected",
                      "originKnown": True, "serverStatus": 200, "body": "success", "expected": "VALID", "sent": True},
    "interop-unknown-origin": {"id": "interop-unknown-origin", "request": "valid", "serverKey": "selected",
                               "originKnown": False, "serverStatus": 404, "body": "empty",
                               "expected": "SUBTREE_HTTP_STATUS", "sent": True},
    "interop-wrong-server-key": {"id": "interop-wrong-server-key", "request": "valid", "serverKey": "other",
                                 "originKnown": True, "serverStatus": 403, "body": "empty",
                                 "expected": "SUBTREE_HTTP_STATUS", "sent": True},
    "interop-bad-proof-local": {"id": "interop-bad-proof-local", "request": "badProof", "serverKey": "selected",
                                "originKnown": True, "serverStatus": None, "body": None,
                                "expected": "SUBTREE_PROOF", "sent": False},
}
print("independent loopback bytes: 1 success, 2 witnessed HTTP statuses, 1 no-send, exact 6527/6173-byte bodies")
