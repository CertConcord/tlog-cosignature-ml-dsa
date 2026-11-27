"""Independent Python replay of the signed maximum selected request carriage."""

import base64
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from pqcrypto.sign import ml_dsa_87


ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).digest()
vector = json.loads(read('vectors/subtree-max-carriage.json'))
source_bytes = read('vectors/subtree-live-sign.json')
source = json.loads(source_bytes)
assert sha(source_bytes).hex() == vector['sourceLiveVectorSha256']
assert vector['wireProfile'] == 'C2SP-20261007-MLDSA87-v2'
assert vector['selectedProofRule'] == 'MTC draft-07 Section 4.4.3'

name = vector['witness']['name'].encode('ascii')
origin = vector['origin'].encode('ascii')
size, start, end = (int(vector[field]) for field in ('size', 'start', 'end'))
assert len(name) == len(origin) == 255
assert (size, start, end) == (2**64 - 1, 2**64 - 4, 2**64 - 2)
leaf = sha(b'\x00' + vector['leafAscii'].encode('ascii'))


@lru_cache(maxsize=None)
def tree(n):
    if n == 1:
        return leaf
    split = 1 << ((n - 1).bit_length() - 1)
    return sha(b'\x01' + tree(split) + tree(n - split))


def proof(a, b, n, include_root=False):
    if a == 0 and b == n:
        return [tree(n)] if include_root else []
    split = 1 << ((n - 1).bit_length() - 1)
    if b <= split:
        return proof(a, b, split, include_root) + [tree(n - split)]
    if a >= split:
        return proof(a - split, b - split, n - split, include_root) + [tree(split)]
    assert a == 0
    return proof(0, b - split, n - split, True) + [tree(split)]


def mtc_verify(a, b, n, subtree, root, nodes):
    fn, sn, tn = a, b - 1, n - 1
    if sn == tn:
        while fn != sn:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    else:
        while fn != sn and sn & 1:
            fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    if fn == sn:
        fr = sr = subtree
        remaining = nodes
    else:
        assert nodes
        fr = sr = nodes[0]
        remaining = nodes[1:]
    for current in remaining:
        if tn == 0:
            return False
        if sn & 1 or sn == tn:
            if fn < sn:
                fr = sha(b'\x01' + current + fr)
            sr = sha(b'\x01' + current + sr)
            while not sn & 1:
                fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
        else:
            sr = sha(b'\x01' + sr + current)
        fn, sn, tn = fn >> 1, sn >> 1, tn >> 1
    return tn == 0 and fr == subtree and sr == root


checkpoint_root = tree(size)
subtree_root = tree(end - start)
nodes = proof(start, end, size)
assert len(nodes) == 63
assert checkpoint_root.hex() == vector['checkpointRootHex']
assert subtree_root.hex() == vector['subtreeRootHex']
assert [value.hex() for value in nodes] == vector['proofHex']
assert mtc_verify(start, end, size, subtree_root, checkpoint_root, nodes)

spki = bytes.fromhex(source['witness']['spkiHex'])
assert sha(spki).hex() == vector['witness']['spkiSha256']
public_key = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
hint = sha(b'certconcord/tlog-ml-dsa-87/v1\n' + name + b'\n' + spki)[:4]
assert hint.hex() == vector['witness']['keyHintHex']
timestamp = int(vector['witness']['timestamp'])
note = bytes.fromhex(vector['noteUtf8Hex'])
assert len(note) == vector['noteBytes'] == 6772 and sha(note).hex() == vector['noteSha256']
note_prefix = (origin + b'\n' + str(size).encode() + b'\n' + base64.b64encode(checkpoint_root)
               + b'\n\n' + '\u2014 '.encode() + name + b' ')
assert note.startswith(note_prefix) and note.endswith(b'\n')
encoded = note[len(note_prefix):-1]
payload = base64.b64decode(encoded, validate=True)
assert base64.b64encode(payload) == encoded
assert payload[:12] == hint + timestamp.to_bytes(8, 'big')
checkpoint_signature = payload[12:]
assert len(checkpoint_signature) == ml_dsa_87.SIGNATURE_SIZE == 4627
checkpoint_input = (b'subtree/v1\n\x00' + bytes([len(name)]) + name + timestamp.to_bytes(8, 'big')
                    + bytes([len(origin)]) + origin + (0).to_bytes(8, 'big')
                    + size.to_bytes(8, 'big') + checkpoint_root)
ml_dsa_87.verify(public_key, checkpoint_input, checkpoint_signature)

range_line = f'subtree {start} {end}'.encode()
assert len(range_line) == 49
prefix = (range_line + b'\n' + base64.b64encode(subtree_root) + b'\n'
          + b''.join(base64.b64encode(node) + b'\n' for node in nodes) + b'\n')
assert prefix.hex() == vector['requestPrefixUtf8Hex']
assert len(prefix) == vector['prefixBytes'] == 2931
assert prefix.index(b'\n\n') == vector['preCheckpointCut'] == 2929
assert [item['expected'] for item in vector['cases']] == [
    'VALID', 'SUBTREE_PROOF', 'SUBTREE_RANGE', 'SUBTREE_REQUEST']
for item in vector['cases']:
    raw = bytes.fromhex(item['wireUtf8Hex'])
    assert len(raw) == item['wireBytes'] and sha(raw).hex() == item['wireSha256']
    assert raw.endswith(note)
    if item['mutation'] is None:
        assert raw == prefix + note and len(raw) == 9703
    elif item['mutation'] == 'first-proof-byte':
        changed = [bytes([nodes[0][0] ^ 1]) + nodes[0][1:], *nodes[1:]]
        assert not mtc_verify(start, end, size, subtree_root, checkpoint_root, changed)
        mutated = (range_line + b'\n' + base64.b64encode(subtree_root) + b'\n'
                   + b''.join(base64.b64encode(node) + b'\n' for node in changed) + b'\n' + note)
        assert raw == mutated and len(raw) == 9703
    elif item['mutation'] == 'range-leading-zero':
        assert raw == b'subtree 0' + str(start).encode() + b' ' + str(end).encode() + prefix[49:] + note
        assert len(raw) == 9704
    elif item['mutation'] == 'extra-proof-line':
        extra = (range_line + b'\n' + base64.b64encode(subtree_root) + b'\n'
                 + b''.join(base64.b64encode(node) + b'\n' for node in [*nodes, nodes[0]]) + b'\n' + note)
        assert raw == extra and len(raw) == 9748
    else:
        raise AssertionError(item['mutation'])

response_input = (b'subtree/v1\n\x00' + bytes([len(name)]) + name + (0).to_bytes(8, 'big')
                  + bytes([len(origin)]) + origin + start.to_bytes(8, 'big')
                  + end.to_bytes(8, 'big') + subtree_root)
assert response_input.hex() == vector['response']['signingInputHex']
assert len(response_input) == vector['response']['signingInputBytes']
assert sha(response_input).hex() == vector['response']['signingInputSha256']
for field, signed_input in [('response', response_input), ('wrongMessageResponse', bytes.fromhex(vector['wrongMessageResponse']['signingInputHex']))]:
    record = vector[field]
    wire = bytes.fromhex(record['wireUtf8Hex'])
    assert len(wire) == record['wireBytes'] == 6173 and sha(wire).hex() == record['wireSha256']
    assert wire.endswith(b'\n')
    signature = base64.b64decode(wire[:-1], validate=True)
    assert len(signature) == 4627 and base64.b64encode(signature) + b'\n' == wire
    ml_dsa_87.verify(public_key, signed_input, signature)
    if field == 'wrongMessageResponse':
        assert sum(a != b for a, b in zip(signed_input, response_input)) == 1
        try:
            ml_dsa_87.verify(public_key, response_input, signature)
        except ValueError:
            pass
        else:
            raise AssertionError('wrong-message signature verified against original request')

print('independent max-carriage replay: 9703-byte signed request, 2929-character pre-checkpoint cut, 63 valid proof hashes, four request wires, two 6173-byte response wires')
