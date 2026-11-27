"""Independently replay Python-produced witness checkpoint and request bytes."""

import base64
import hashlib
import json
from pathlib import Path

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import ml_dsa_87


root = Path(__file__).resolve().parent.parent
sha = lambda data: hashlib.sha256(data).hexdigest()
read = lambda name: (root / name).read_bytes()
source_bytes = read("vectors/subtree-live-sign.json")
cross_bytes = read("vectors/subtree-cross-runtime.json")
discovery_bytes = read("vectors/key-discovery.json")
source, cross, discovery = (json.loads(data) for data in
                            (source_bytes, cross_bytes, discovery_bytes))
vector = json.loads(read("vectors/subtree-cross-runtime-checkpoint.json"))
assert sha(source_bytes) == vector["sourceLiveVectorSha256"]
assert sha(cross_bytes) == vector["sourceCrossRuntimeVectorSha256"]
assert sha(discovery_bytes) == vector["sourceDiscoveryVectorSha256"]
assert vector["producer"] == {
    "package": "pqcrypto", "version": "1.0.0",
    "windowsWheelSha256": "d65d0fdbd2bfcfd80193d1d499142e63dd8ea6a072e1dc68b1b36fd49f9fdc8f",
}


def wire(item):
    data = bytes.fromhex(item["utf8Hex"])
    assert len(data) == item["bytes"] and sha(data) == item["sha256"]
    return data


def rejects(public, message, signature):
    try:
        ml_dsa_87.verify(public, message, signature, context=b"")
    except InvalidSignatureError:
        return
    raise AssertionError("invalid ML-DSA-87 signature was accepted")


name = bytes.fromhex(vector["nameUtf8Hex"])
assert name.decode("ascii") == source["witness"]["name"]
spki = bytes.fromhex(source["witness"]["spkiHex"])
pkcs8 = bytes.fromhex(source["witness"]["pkcs8Hex"])
assert sha(spki) == vector["spkiSha256"]
assert len(spki) == 2614 and len(pkcs8) == 4962
assert spki[:22] == bytes.fromhex("30820a32300b060960864801650304031303820a2100")
public = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
private = pkcs8[-ml_dsa_87.SECRET_KEY_SIZE:]
hint = hashlib.sha256(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki).digest()[:4]
assert hint.hex() == vector["keyHintHex"] == source["witness"]["keyIDHex"]

request = wire(vector["request"])
note = wire(vector["checkpointNote"])
assert len(request) == 6527 and len(note) == 6288 and request.endswith(note)
old_request = wire(source["request"])
old_note = wire(source["checkpoint"]["note"])
assert request[:-len(note)] == old_request[:-len(old_note)]
body, line = note.split(b"\n\n", 1)
old_body, _ = old_note.split(b"\n\n", 1)
assert body == old_body
origin, size_line, root_line = body.split(b"\n")
size = int(size_line)
root_hash = base64.b64decode(root_line, validate=True)
assert len(root_hash) == 32
prefix = b"\xe2\x80\x94 " + name + b" "
assert line.startswith(prefix) and line.endswith(b"\n")
payload = base64.b64decode(line[len(prefix):-1], validate=True)
assert base64.b64encode(payload) == line[len(prefix):-1]
assert len(payload) == 4 + 8 + 4627 and payload[:4] == hint
timestamp = int.from_bytes(payload[4:12], "big")
assert timestamp == vector["checkpointTimestamp"] == source["checkpoint"]["timestamp"]
checkpoint_message = (b"subtree/v1\n\x00" + bytes([len(name)]) + name + payload[4:12]
                      + bytes([len(origin)]) + origin + bytes(8) + size.to_bytes(8, "big")
                      + root_hash)
assert checkpoint_message.hex() == vector["checkpointSignedInputHex"]
assert checkpoint_message.hex() == source["checkpoint"]["signedInputHex"]
assert len(checkpoint_message) == 114 and sha(payload[12:]) == vector["checkpointSignatureSha256"]
ml_dsa_87.verify(public, checkpoint_message, payload[12:], context=b"")
fresh = ml_dsa_87.sign(private, checkpoint_message, context=b"")
assert len(fresh) == 4627
ml_dsa_87.verify(public, checkpoint_message, fresh, context=b"")

prelude = request[:-len(note)]
head, root_line, *proof_lines = prelude[:-2].split(b"\n")
label, start_line, end_line = head.split(b" ")
assert label == b"subtree"
start, end = int(start_line), int(end_line)
subtree_root = base64.b64decode(root_line, validate=True)
assert len(subtree_root) == 32 and len(proof_lines) <= 63
assert all(len(base64.b64decode(line, validate=True)) == 32 for line in proof_lines)
response_message = (b"subtree/v1\n\x00" + bytes([len(name)]) + name + bytes(8)
                    + bytes([len(origin)]) + origin + start.to_bytes(8, "big")
                    + end.to_bytes(8, "big") + subtree_root)
assert response_message.hex() == cross["signedInputHex"]
response = wire(cross["pythonResponse"])
assert sha(response) == vector["pythonResponseSha256"]
response_signature = base64.b64decode(response[:-1], validate=True)
assert response == base64.b64encode(response_signature) + b"\n"
ml_dsa_87.verify(public, response_message, response_signature, context=b"")

expected = {
    "cross-python-checkpoint-bad-key-id": (0, "SUBTREE_WITNESS_KEY"),
    "cross-python-checkpoint-bad-timestamp": (11, "CHECKPOINT_SIGNATURE"),
    "cross-python-checkpoint-future-timestamp": (4, "CHECKPOINT_FUTURE"),
    "cross-python-checkpoint-bad-signature": (12, "CHECKPOINT_SIGNATURE"),
}
assert len(vector["negativeRequests"]) == len(expected)
for item in vector["negativeRequests"]:
    offset, error = expected[item["id"]]
    assert (item["payloadByteOffset"], item["expected"]) == (offset, error)
    changed = bytearray(payload)
    assert f"{changed[offset]:02x}" == item["beforeHex"]
    changed[offset] ^= 1
    assert f"{changed[offset]:02x}" == item["afterHex"]
    bad_request = request[:-len(line)] + prefix + base64.b64encode(changed) + b"\n"
    assert wire(item["request"]) == bad_request
    if offset == 0:
        assert bytes(changed[:4]) != hint
        ml_dsa_87.verify(public, checkpoint_message, bytes(changed[12:]), context=b"")
    elif offset == 4:
        assert int.from_bytes(changed[4:12], "big") > source["witness"]["at"] + 30
    elif offset == 11:
        changed_message = (b"subtree/v1\n\x00" + bytes([len(name)]) + name + bytes(changed[4:12])
                           + bytes([len(origin)]) + origin + bytes(8) + size.to_bytes(8, "big")
                           + root_hash)
        rejects(public, changed_message, bytes(changed[12:]))
    else:
        rejects(public, checkpoint_message, bytes(changed[12:]))

base64_line = line[len(prefix):-1]
url_byte = b"+" if b"+" in base64_line else b"/"
url_replacement = b"-" if url_byte == b"+" else b"_"
second = bytearray(payload)
second[0] ^= 1
prelude_lines = prelude.split(b"\n")
assert prelude_lines[-2:] == [b"", b""]
proof = bytearray(base64.b64decode(prelude_lines[2], validate=True))
proof[0] ^= 1
prelude_lines[2] = base64.b64encode(proof)
expected_wire = {
    "cross-python-checkpoint-short-signature": (
        "signature-truncation", request[:-len(line)] + prefix + base64.b64encode(payload[:-1]) + b"\n",
        "CHECKPOINT_SIGNATURE"),
    "cross-python-checkpoint-missing-padding": (
        "base64-padding", request[:-len(line)] + prefix + base64_line.rstrip(b"=") + b"\n",
        "SUBTREE_BASE64"),
    "cross-python-checkpoint-base64url": (
        "base64url-character", request[:-len(line)] + prefix
        + base64_line.replace(url_byte, url_replacement, 1) + b"\n", "CHECKPOINT_SIGNATURE"),
    "cross-python-checkpoint-carriage-return": (
        "cr-in-request", request.replace(b"\n", b"\r\n", 1), "SUBTREE_REQUEST"),
    "cross-python-checkpoint-second-signature": (
        "second-witness-line", request + prefix + base64.b64encode(second) + b"\n", "SUBTREE_ONE_WITNESS"),
    "cross-python-checkpoint-duplicate-signature": (
        "duplicate-witness-line", request + line, "CHECKPOINT_DUPLICATE_SIGNATURE"),
    "cross-python-checkpoint-bad-proof": (
        "first-proof-byte", b"\n".join(prelude_lines) + note, "SUBTREE_PROOF"),
}
assert len(vector["wireFailures"]) == len(expected_wire)
for item in vector["wireFailures"]:
    kind, expected_bytes, error = expected_wire[item["id"]]
    assert (item["kind"], item["expected"]) == (kind, error)
    assert wire(item["request"]) == expected_bytes

legacy = bytes.fromhex(vector["legacyMlDsa44SpkiHex"])
assert legacy == bytes.fromhex(discovery["keys"]["legacy44"])
assert len(legacy) == 1334 and sha(legacy) == vector["legacyMlDsa44SpkiSha256"]
assert legacy[:22] == bytes.fromhex("30820532300b06096086480165030403110382052100")
assert legacy[:22] != spki[:22]
assert [case["id"] for case in vector["cases"]] == [
    "cross-python-checkpoint-node-verify",
    "cross-python-checkpoint-and-response-node-verify",
    *expected,
    *expected_wire,
    "cross-python-checkpoint-mldsa44-key",
]
assert [case["expected"] for case in vector["cases"]] == [
    "VALID", "VALID", *[value[1] for value in expected.values()],
    *[value[2] for value in expected_wire.values()], "NOTE_KEY_SCHEME",
]
print("independent Python checkpoint request, key hint, response and eleven exact negative wires verified")
