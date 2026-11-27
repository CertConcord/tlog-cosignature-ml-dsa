"""Rebuild fixed KeyObject admission bytes without the JavaScript implementation."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
fixture = json.loads((root / "vectors/revoked-keyobject.json").read_text(encoding="utf-8"))
discovery = json.loads((root / fixture["sourceSpkiVector"]).read_text(encoding="utf-8"))
prefix = json.loads((root / fixture["sourceSignatureVector"]).read_text(encoding="utf-8"))

name = bytes.fromhex(fixture["sourceNameUtf8Hex"])
spki = bytes.fromhex(discovery["keys"]["primary"])
signature = bytes.fromhex(prefix["signature"])
context = prefix["context"]
assert name.decode("ascii") == discovery["name"] == context["name"]
assert spki == bytes.fromhex(prefix["spki"])
assert len(spki) == fixture["sourceSpkiBytes"]
assert hashlib.sha256(spki).hexdigest() == fixture["sourceSpkiSha256"]
hint = hashlib.sha256(b"certconcord/tlog-ml-dsa-87/v1\n" + name + b"\n" + spki).digest()[:4]
assert hint.hex() == fixture["sourceHintHex"] == discovery["keyHint"] == prefix["keyHint"]

origin = context["origin"].encode("ascii")
assert len(name) <= 255 and len(origin) <= 255
u64 = lambda n: int(n).to_bytes(8, "big")
signed = (b"subtree/v1\n\0" + bytes([len(name)]) + name + u64(context["timestamp"])
          + bytes([len(origin)]) + origin + u64(context["start"]) + u64(context["end"])
          + bytes.fromhex(context["root"]))
assert signed == bytes.fromhex(prefix["input"])
assert len(signed) == fixture["sourceInputBytes"]
assert hashlib.sha256(signed).hexdigest() == fixture["sourceInputSha256"]
assert len(signature) == fixture["sourceSignatureBytes"]
assert hashlib.sha256(signature).hexdigest() == fixture["sourceSignatureSha256"]

cases = fixture["cases"]
assert len(cases) == 6 and len({case["id"] for case in cases}) == 6
for operation in ("hint", "select", "verify"):
    pair = [case for case in cases if case["operation"] == operation]
    assert len(pair) == 2
    assert {(case["shape"], case["expected"]) for case in pair} == {
        ("ordinary", "VALID"),
        ("revoked-proxy", "NOTE_KEY_CANDIDATES" if operation == "select" else "NOTE_KEY_SCHEME"),
    }
print("Revoked KeyObject SPKI, hint, signed input, signature and six cases verified")
