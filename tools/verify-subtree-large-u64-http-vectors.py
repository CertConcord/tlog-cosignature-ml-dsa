"""Independently replay frozen large-u64 bytes through a Python HTTP peer."""

import base64
from functools import lru_cache
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json
from pathlib import Path
import subprocess
from threading import Thread

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import ml_dsa_87

ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).hexdigest()
vector = json.loads(read('vectors/subtree-large-u64-http.json'))
large_bytes = read('vectors/subtree-large-u64.json')
large = json.loads(large_bytes)
source_bytes = read('vectors/subtree-live-sign.json')
source = json.loads(source_bytes)
assert sha(large_bytes) == vector['sourceLargeVectorSha256']
assert sha(source_bytes) == vector['sourceLiveVectorSha256']
assert vector['wireProfile'] == large['wireProfile'] == 'C2SP-20261007-MLDSA87-v2'
assert vector['producer'] == {'package': 'pqcrypto', 'version': '1.0.0'}
size = '18446744069414649856'
tree = next(item for item in large['trees'] if item['size'] == size)
case = next(item for item in large['cases'] if item['id'] == vector['requestSourceCase'])
bad = next(item for item in large['cases'] if item['id'] == vector['badProofSourceCase'])
name = large['witness']['name'].encode()
origin = large['checkpointOrigin'].encode()
spki = bytes.fromhex(source['witness']['spkiHex'])
pkcs8 = bytes.fromhex(source['witness']['pkcs8Hex'])
assert sha(spki) == large['witness']['spkiSha256']
assert len(spki) == 2614 and len(pkcs8) == 4962
public = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
private = pkcs8[-ml_dsa_87.SECRET_KEY_SIZE:]
wire = lambda item: bytes.fromhex(item['requestPrefixUtf8Hex']) + bytes.fromhex(tree['noteUtf8Hex'])
expected = wire(case)
assert len(expected) == case['wireBytes'] == vector['requestBytes'] == 8563
assert sha(expected) == case['wireSha256'] == vector['requestSha256']
assert sha(wire(bad)) == bad['wireSha256'] == vector['badProofRequestSha256']
assert len(case['proofHex']) == vector['proofLines'] == 48
assert vector['endpointPath'] == '/witness/sign-subtree'


def signed_input(start, end, root, timestamp=0):
    return (b'subtree/v1\n\0' + bytes([len(name)]) + name + timestamp.to_bytes(8, 'big')
            + bytes([len(origin)]) + origin + start.to_bytes(8, 'big')
            + end.to_bytes(8, 'big') + root)


def node(left, right):
    return hashlib.sha256(b'\x01' + left + right).digest()


@lru_cache(maxsize=None)
def virtual_root(width):
    if width == 1:
        return hashlib.sha256(b'\x00' + large['virtualLeafAscii'].encode()).digest()
    split = 1 << ((width - 1).bit_length() - 1)
    return node(virtual_root(split), virtual_root(width - split))


def verify_proof(start, end, size, subtree, tree_root, proof):
    fn, sn, tn = start, end - 1, size - 1
    if sn == tn:
        while fn != sn:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    else:
        while fn != sn and sn & 1:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    if fn == sn:
        fr = sr = subtree
        remaining = proof
    elif proof:
        fr = sr = proof[0]
        remaining = proof[1:]
    else:
        return False
    for current in remaining:
        if tn == 0:
            return False
        if sn & 1 or sn == tn:
            if fn < sn:
                fr = node(current, fr)
            sr = node(current, sr)
            while not sn & 1:
                fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
        else:
            sr = node(sr, current)
        fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    return tn == 0 and fr == subtree and sr == tree_root


class Rejected(Exception):
    def __init__(self, status):
        self.status = status


def decoded(line, length):
    try:
        data = base64.b64decode(line, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Rejected(400) from None
    if len(data) != length or base64.b64encode(data) != line:
        raise Rejected(400)
    return data


def accept(data):
    if b'\r' in data or len(data) > 10000:
        raise Rejected(400)
    try:
        prelude, note = data.split(b'\n\n', 1)
        body, signature_line = note.split(b'\n\n', 1)
        range_line, subtree_line, *proof_lines = prelude.split(b'\n')
        marker, start_line, end_line = range_line.split(b' ')
        note_origin, size_line, tree_line = body.split(b'\n')
        if marker != b'subtree' or note_origin != origin:
            raise Rejected(400)
        start, end, size = int(start_line), int(end_line), int(size_line)
        if any(str(n).encode() != line for n, line in
               [(start, start_line), (end, end_line), (size, size_line)]):
            raise Rejected(400)
    except (ValueError, OverflowError):
        raise Rejected(400) from None
    if not (0 <= start < end <= size <= 2**64 - 1) or len(proof_lines) > 63:
        raise Rejected(422)
    width = 1 << (end - start - 1).bit_length()
    if start % width:
        raise Rejected(422)
    tree_root = decoded(tree_line, 32)
    subtree = decoded(subtree_line, 32)
    proof = [decoded(line, 32) for line in proof_lines]
    signature_prefix = b'\xe2\x80\x94 ' + name + b' '
    if not signature_line.startswith(signature_prefix) or not signature_line.endswith(b'\n'):
        raise Rejected(400)
    payload = decoded(signature_line[len(signature_prefix):-1], 4 + 8 + 4627)
    hint = hashlib.sha256(b'certconcord/tlog-ml-dsa-87/v1\n' + name + b'\n' + spki).digest()[:4]
    if payload[:4] != hint:
        raise Rejected(403)
    timestamp = int.from_bytes(payload[4:12], 'big')
    if timestamp > source['witness']['at'] + 30:
        raise Rejected(403)
    try:
        ml_dsa_87.verify(public, signed_input(0, size, tree_root, timestamp),
                         payload[12:], context=b'')
    except InvalidSignatureError:
        raise Rejected(403) from None
    if tree_root != virtual_root(size) or subtree != virtual_root(end - start):
        raise Rejected(422)
    if not verify_proof(start, end, size, subtree, tree_root, proof):
        raise Rejected(422)
    return signed_input(start, end, subtree)


def response(which, message):
    item = vector['responses'][which]
    data = bytes.fromhex(item['utf8Hex'])
    assert len(data) == item['bytes'] == 6173 and sha(data) == item['sha256']
    assert data.endswith(b'\n')
    signature = decoded(data[:-1], 4627)
    assert sha(signature) == item['signatureSha256']
    ml_dsa_87.verify(public, message, signature, context=b'')
    return data


expected_message = signed_input(int(case['start']), int(case['end']),
                                bytes.fromhex(case['subtreeHashHex']))
wrong_message = expected_message[:-1] + bytes([expected_message[-1] ^ 1])
assert expected_message.hex() == vector['signerInputHex']
assert wrong_message.hex() == vector['wrongSignerInputHex']
frozen_valid = response('valid', expected_message)
frozen_wrong = response('wrongMessage', wrong_message)
try:
    ml_dsa_87.verify(public, expected_message, decoded(frozen_wrong[:-1], 4627), context=b'')
except InvalidSignatureError:
    pass
else:
    raise AssertionError('wrong-message response verified under the correct message')


class Peer(BaseHTTPRequestHandler):
    seen = []
    mode = None

    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '-1'))
        data = self.rfile.read(length) if length >= 0 else b''
        self.seen.append((self.path, data))
        assert self.path == vector['endpointPath']
        try:
            message = accept(data)
            assert data == expected
            assert message == expected_message
            if self.mode == 'frozen':
                body = frozen_valid
            elif self.mode == 'wrong-response':
                body = frozen_wrong
            else:
                assert self.mode == 'live'
                signature = ml_dsa_87.sign(private, message, context=b'')
                ml_dsa_87.verify(public, message, signature, context=b'')
                assert len(signature) == 4627
                body = base64.b64encode(signature) + b'\n'
                assert len(body) == 6173
            status = 200
        except Rejected as error:
            status, body = error.status, b''
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


assert len(vector['cases']) == 5
for item in vector['cases']:
    mode = item['mode']
    Peer.seen = []
    Peer.mode = mode
    server = HTTPServer(('127.0.0.1', 0), Peer)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if mode == 'raw-bad-proof':
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
            connection.request('POST', vector['endpointPath'], body=wire(bad))
            response = connection.getresponse()
            assert response.status == item['status'] == 422 and response.read() == b''
            connection.close()
        else:
            result = subprocess.run(['node', 'tools/large-u64-http-client.mjs',
                                     str(server.server_port), item['id']], cwd=ROOT,
                                    capture_output=True, text=True, timeout=30, check=True)
            data = json.loads(result.stdout)
            assert data['outcome'] == item['expected'], (item['id'], data)
            if item['expected'] == 'VALID':
                assert data['signatureBytes'] == 4627
        assert len(Peer.seen) == item['sent']
        if item['sent']:
            assert Peer.seen[0] == (vector['endpointPath'],
                                   wire(bad) if mode == 'raw-bad-proof' else expected)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)

print(json.dumps({'cases': len(vector['cases']), 'wireBytes': len(expected),
                  'proofLines': len(case['proofHex']),
                  'sent': [item['sent'] for item in vector['cases']],
                  'validResponseBytes': len(frozen_valid),
                  'wrongResponseBytes': len(frozen_wrong)}))
