"""Independently reconstruct the admitted key hint and native-byte cases."""

import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent
vectors = json.loads((root / "vectors/key-hint-buffer.json").read_bytes())
prefix = json.loads((root / "vectors/prefix.json").read_bytes())
assert vectors["name"] == prefix["context"]["name"]
spki = bytes.fromhex(vectors["selectedSpkiHex"])
assert spki.hex() == prefix["spki"]
assert hashlib.sha256(spki).hexdigest() == vectors["selectedSpkiSha256"]
derived = hashlib.sha256(b"certconcord/tlog-ml-dsa-87/v1\n" + vectors["name"].encode("ascii") + b"\n" + spki).digest()[:4]
assert derived.hex() == vectors["hints"]["original"] == prefix["keyHint"]
assert bytes.fromhex(vectors["hints"]["short"]) == derived[:2]
assert bytes.fromhex(vectors["hints"]["long"]) == derived + b"ZZ"

expected = {
    "key-hint-buffer-plain": ("original", "none", "VALID"),
    "key-hint-buffer-shadow-length-2": ("original", "length-2", "VALID"),
    "key-hint-buffer-shadow-length-throws": ("original", "length-throws", "VALID"),
    "key-hint-buffer-shadow-byte-length-throws": ("original", "byte-length-throws", "VALID"),
    "key-hint-buffer-native-short-spoof": ("short", "length-4", "NOTE_KEY_ID"),
    "key-hint-buffer-native-long-spoof": ("long", "length-4", "NOTE_KEY_ID"),
    "key-hint-buffer-uint16-buffer-prototype": ("original", "uint16-buffer-prototype", "NOTE_KEY_ID"),
    "key-hint-buffer-proxy": ("original", "proxy", "NOTE_KEY_ID"),
    "key-hint-buffer-revoked-proxy": ("original", "revoked-proxy", "NOTE_KEY_ID"),
}
assert len(vectors["cases"]) == len(expected)
for case in vectors["cases"]:
    hint, decoration, outcome = expected.pop(case["id"])
    assert (case["hint"], case["decoration"], case["expected"]) == (hint, decoration, outcome)
    native = bytes.fromhex(vectors["hints"][hint])
    assert len(native) == {"original": 4, "short": 2, "long": 6}[hint]
    if outcome == "VALID":
        assert case["selectedSpki"] == "selectedSpkiHex" and "noSelection" not in case
        assert native == derived
    else:
        assert case["noSelection"] is True and "selectedSpki" not in case
assert not expected
print("Key hint Buffer bytes: exact SPKI, derived hint and 9 native-byte cases independently replayed")
