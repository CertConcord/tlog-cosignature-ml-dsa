"""Independently reconstruct exact HTTP client request and response body fixtures."""

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit


def sha(value):
    return hashlib.sha256(value).hexdigest()


def wire(item):
    value = bytes.fromhex(item["utf8Hex"])
    assert len(value) == item["bytes"] and sha(value) == item["sha256"]
    return value


root = Path(__file__).resolve().parent.parent
vector = json.loads((root / "vectors/subtree-http-client.json").read_text(encoding="utf-8"))
source_bytes = (root / "vectors/subtree-response-auth.json").read_bytes()
assert sha(source_bytes) == vector["sourceResponseVectorSha256"]
source = json.loads(source_bytes)
assert vector["witness"] == {key: source["witness"][key] for key in ("name", "spkiHex", "at")}
assert len(bytes.fromhex(vector["witness"]["spkiHex"])) == 2614
assert vector["request"] == {"method": "POST", "path": "/witness/sign-subtree"}

assert wire(vector["requests"]["valid"]) == wire(source["requests"]["valid"])
assert wire(vector["requests"]["badProof"]) == wire(source["requests"]["alteredProof"])
assert wire(vector["responses"]["valid"]) == wire(source["responses"]["valid"])
assert wire(vector["responses"]["alteredSignature"]) == wire(source["responses"]["alteredSignature"])
assert wire(vector["responses"]["missingLF"]) == wire(source["responses"]["missingLF"])
assert wire(vector["responses"]["leadingBOM"]) == b"\xef\xbb\xbf" + wire(source["responses"]["valid"])
assert wire(vector["responses"]["oversized"]) == b"A" * 8193
assert wire(vector["responses"]["error"]) == b"error\n"
assert wire(vector["responses"]["redirect"]) == b"redirect\n"

valid_body = wire(vector["responses"]["valid"])
assert valid_body.endswith(b"\n") and len(valid_body) == 6173
signature = base64.b64decode(valid_body[:-1], validate=True)
assert len(signature) == 4627 and base64.b64encode(signature) + b"\n" == valid_body
assert wire(vector["responses"]["missingLF"]) == valid_body[:-1]
bad = bytearray(signature)
bad[0] ^= 1
assert base64.b64decode(wire(vector["responses"]["alteredSignature"])[:-1], validate=True) == bad

cases = vector["cases"]
assert len(cases) == 13 and len({case["id"] for case in cases}) == 13
assert sum(case["expected"] == "VALID" for case in cases) == 1
assert sum(not case["sent"] for case in cases) == 4
assert {case["httpStatus"] for case in cases} == {200, 302, 403, 404, 422}
assert {case["expected"] for case in cases} == {
    "VALID", "SUBTREE_SIGNATURE", "SUBTREE_RESPONSE_ENCODING", "SUBTREE_HTTP_BODY_LIMIT",
    "SUBTREE_PROOF", "SUBTREE_HTTP_STATUS", "SUBTREE_HTTP_URL",
}
by_id = {case["id"]: case for case in cases}
assert by_id["client-redirect-status-no-follow"] == {
    "id": "client-redirect-status-no-follow", "request": "valid", "response": "redirect",
    "httpStatus": 302, "expected": "SUBTREE_HTTP_STATUS", "sent": True,
}
for case_id, suffix in (("client-empty-query-before-send", "?"),
                        ("client-empty-fragment-before-send", "#")):
    item = by_id[case_id]
    assert item["prefix"].endswith("/witness" + suffix)
    assert item["expected"] == "SUBTREE_HTTP_URL" and item["sent"] is False
for case in cases:
    assert case["request"] in vector["requests"] and case["response"] in vector["responses"]
    if not case["sent"]:
        assert case["expected"] in ("SUBTREE_PROOF", "SUBTREE_HTTP_URL")
    if case["expected"] == "SUBTREE_HTTP_URL":
        url = urlsplit(case["prefix"])
        assert url.scheme == "http"
        assert url.username == "user" or case["prefix"].endswith(("?", "#"))
print("independent HTTP client bytes: 1 success, 12 negatives, 4 no-send, exact 6527/6173-byte bodies")
