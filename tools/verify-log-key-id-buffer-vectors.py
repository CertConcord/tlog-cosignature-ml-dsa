"""Independently replay exact checkpoint and external log key ID bytes."""

import argparse
import base64
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path)
parser.add_argument("--vector", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
source = json.loads((args.source or root / "vectors/transport.json").read_bytes())
vector = json.loads((args.vector or root / "vectors/log-key-id-buffer.json").read_bytes())
sha = lambda data: hashlib.sha256(data).hexdigest()
wire = next(item["wire"] for item in source["cases"] if item["id"] == "log-checkpoint")
body = wire[:wire.index("\n\n") + 1]
assert vector["checkpointWire"] == wire
assert vector["checkpointWireUtf8Bytes"] == len(wire.encode())
assert vector["checkpointWireSha256"] == sha(wire.encode())
assert vector["checkpointBodyHex"] == body.encode().hex()
assert vector["checkpointBodySha256"] == sha(body.encode())
assert vector["logName"] == source["log"]["name"]
spki = bytes.fromhex(source["log"]["spki"])
assert vector["logSpkiHex"] == spki.hex() and vector["logSpkiSha256"] == sha(spki)
key_id = bytes.fromhex(source["log"]["keyHint"])
assert len(key_id) == 4
expected = {"valid": key_id, "short": key_id[:2], "long": key_id + b"\x5a\x5a",
            "wrong": b"\x5a" * 4, "disguised": b"\x5a" * 4}
for name, data in expected.items():
    assert vector["inputs"][name] == {"hex": data.hex(), "bytes": len(data), "sha256": sha(data)}
lines = wire.split("\n")
log_line = next(line for line in lines if line.startswith("— " + source["log"]["name"] + " "))
payload = base64.b64decode(log_line.split(" ", 2)[2], validate=True)
assert payload[:4] == key_id and len(payload) == 68
assert vector["logSignaturePayloadHex"] == payload.hex()
assert vector["logSignaturePayloadSha256"] == sha(payload)
expected_cases = [
    ("valid", "none", "VALID"), ("valid", "length-2", "VALID"),
    ("valid", "length-throws", "VALID"), ("valid", "byte-length-throws", "VALID"),
    ("short", "length-4", "CHECKPOINT_LOG_KEY"), ("long", "length-4", "CHECKPOINT_LOG_KEY"),
    ("disguised", "uint16-buffer-prototype", "CHECKPOINT_LOG_KEY"),
    ("valid", "proxy", "CHECKPOINT_LOG_KEY"), ("valid", "revoked-proxy", "CHECKPOINT_LOG_KEY"),
    ("wrong", "none", "CHECKPOINT_LOG_SIGNATURE_REQUIRED"),
]
assert [(x["input"], x["decoration"], x["expected"]) for x in vector["cases"]] == expected_cases
assert len({x["id"] for x in vector["cases"]}) == len(expected_cases)
print("Log key ID bytes: full checkpoint, body, SPKI, five ID strings and ten cases independently replayed")
