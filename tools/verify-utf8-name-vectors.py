"""Independent Python byte and ML-DSA-87 replay of UTF-8 name carriage."""

import base64
import hashlib
import json
import unicodedata
from pathlib import Path

from pqcrypto.sign import ml_dsa_87

ROOT = Path(__file__).resolve().parent.parent
read = lambda path: (ROOT / path).read_bytes()
sha = lambda data: hashlib.sha256(data).digest()
vector = json.loads(read('vectors/utf8-names.json'))
source_bytes = read('vectors/subtree-live-sign.json')
source = json.loads(source_bytes)
sources = json.loads(read('sources.json'))
assert sha(source_bytes).hex() == vector['sources']['sourceLiveVectorSha256']
unicode_source = next(item for item in sources['sources'] if item['id'] == 'unicodeWhiteSpace')
assert unicode_source['sha256'] == vector['sources']['unicodeWhiteSpaceSha256']
assert vector['wireProfile'] == 'C2SP-20261007-MLDSA87-v2'

white_space = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680,
               *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000}
assert len(white_space) == 25
assert {int(value, 16) for value in vector['whiteSpaceCodePoints']} == white_space


def valid_name(text):
    raw = text.encode('utf-8')
    return (1 <= len(raw) <= 255 and all(ord(char) >= 0x20 and ord(char) != 0x2b
                                           and ord(char) not in white_space for char in text))


for item in vector['nameSamples']:
    value = bytes.fromhex(item['utf16CodeUnitsHex']).decode('utf-16-be')
    assert value.encode('utf-8').hex() == item['utf8Hex'], item['id']
    assert ('VALID' if valid_name(value) else 'SUBTREE_NAME') == item['expected'], item['id']
try:
    bytes.fromhex(vector['unpairedSurrogate']['utf16CodeUnitsHex']).decode('utf-16-be')
except UnicodeDecodeError:
    pass
else:
    raise AssertionError('unpaired surrogate decoded as a Unicode scalar string')

spki = bytes.fromhex(vector['publicSpkiHex'])
assert spki == bytes.fromhex(source['witness']['spkiHex'])
assert sha(spki).hex() == vector['publicSpkiSha256']
assert len(spki) > ml_dsa_87.PUBLIC_KEY_SIZE
public_key = spki[-ml_dsa_87.PUBLIC_KEY_SIZE:]
leaf = vector['leafAscii'].encode('ascii')
root = sha(b'\x00' + leaf)
assert root.hex() == vector['rootHex']
timestamp = vector['timestamp']
assert timestamp == source['checkpoint']['timestamp'] == 1700000000
assert vector['at'] == source['witness']['at']


def signed_input(name, origin, stamp):
    assert valid_name(name) and valid_name(origin)
    name_bytes, origin_bytes = name.encode('utf-8'), origin.encode('utf-8')
    return (b'subtree/v1\n\x00' + bytes([len(name_bytes)]) + name_bytes
            + stamp.to_bytes(8, 'big') + bytes([len(origin_bytes)]) + origin_bytes
            + (0).to_bytes(8, 'big') + (1).to_bytes(8, 'big') + root)


def check_checkpoint(record):
    name, origin = record['name'], record['origin']
    name_bytes, origin_bytes = name.encode('utf-8'), origin.encode('utf-8')
    assert valid_name(name) and valid_name(origin)
    assert name_bytes.hex() == record['nameUtf8Hex']
    assert origin_bytes.hex() == record['originUtf8Hex']
    hint = sha(b'certconcord/tlog-ml-dsa-87/v1\n' + name_bytes + b'\n' + spki)[:4]
    assert hint.hex() == record['keyHintHex']
    message = signed_input(name, origin, timestamp)
    assert message.hex() == record['checkpointInputHex']
    signature = bytes.fromhex(record['checkpointSignatureHex'])
    assert len(signature) == ml_dsa_87.SIGNATURE_SIZE == 4627
    ml_dsa_87.verify(public_key, message, signature)
    payload = hint + timestamp.to_bytes(8, 'big') + signature
    note = (origin_bytes + b'\n1\n' + base64.b64encode(root) + b'\n\n'
            + '\u2014 '.encode('utf-8') + name_bytes + b' ' + base64.b64encode(payload) + b'\n')
    request = b'subtree 0 1\n' + base64.b64encode(root) + b'\n\n' + note
    assert note.hex() == record['noteUtf8Hex']
    assert request.hex() == record['requestUtf8Hex']
    assert sha(request).hex() == record['requestSha256']
    return request, payload, signature


primary, payload, checkpoint_signature = check_checkpoint(vector['primary'])
boundary, _, _ = check_checkpoint(vector['boundary'])
assert len(vector['boundary']['name'].encode()) == len(vector['boundary']['origin'].encode()) == 255
assert sha(b'certconcord/tlog-ml-dsa-87/v1\n' + vector['asciiBaseline']['name'].encode()
           + b'\n' + spki)[:4].hex() == vector['asciiBaseline']['keyHintHex']
assert unicodedata.normalize('NFD', vector['primary']['name']) != vector['primary']['name']
assert sha(b'certconcord/tlog-ml-dsa-87/v1\n' + unicodedata.normalize('NFD', vector['primary']['name']).encode()
           + b'\n' + spki)[:4].hex() != vector['primary']['keyHintHex']


def replace_once(wire, old, new):
    assert wire.count(old) == 1
    return wire.replace(old, new, 1)


name = vector['primary']['name'].encode('utf-8')
origin = vector['primary']['origin'].encode('utf-8')
boundary_name = vector['boundary']['name'].encode('utf-8')
changed_hint = bytes([payload[0] ^ 1]) + payload[1:]
expected = {
    'utf8-name-valid': primary,
    'utf8-name-boundary-valid': boundary,
    'utf8-name-wrong-origin': replace_once(primary, origin, 'cafè.example/árbol'.encode()),
    'utf8-name-nfd': replace_once(primary, name,
                                  unicodedata.normalize('NFD', vector['primary']['name']).encode()),
    'utf8-name-space': replace_once(primary, name,
                                    vector['primary']['name'].replace('é', '\u00a0', 1).encode()),
    'utf8-name-plus': replace_once(primary, name,
                                   vector['primary']['name'].replace('é', '+', 1).encode()),
    'utf8-name-wrong-hint': replace_once(primary, base64.b64encode(payload),
                                         base64.b64encode(changed_hint)),
    'utf8-name-overlong': replace_once(boundary, boundary_name, ('é' * 128).encode()),
}
assert len(vector['cases']) == len(expected) == 8
for case in vector['cases']:
    raw = bytes.fromhex(case['wireUtf8Hex'])
    assert raw == expected[case['id']], case['id']
    assert len(raw) == case['wireBytes'] and sha(raw).hex() == case['wireSha256']
    assert raw.decode('utf-8').encode('utf-8') == raw
    if case['id'] == 'utf8-name-wrong-origin':
        changed_message = signed_input(vector['primary']['name'], 'cafè.example/árbol', timestamp)
        try:
            ml_dsa_87.verify(public_key, changed_message, checkpoint_signature)
        except ValueError:
            pass
        else:
            raise AssertionError('changed origin retained checkpoint signature')
    elif case['id'] == 'utf8-name-nfd':
        assert valid_name(unicodedata.normalize('NFD', vector['primary']['name']))
    elif case['id'] == 'utf8-name-space':
        assert not valid_name(vector['primary']['name'].replace('é', '\u00a0', 1))
    elif case['id'] == 'utf8-name-plus':
        assert not valid_name(vector['primary']['name'].replace('é', '+', 1))
    elif case['id'] == 'utf8-name-wrong-hint':
        assert changed_hint[:4] != bytes.fromhex(vector['primary']['keyHintHex'])
    elif case['id'] == 'utf8-name-overlong':
        assert not valid_name('é' * 128)

response_message = signed_input(vector['primary']['name'], vector['primary']['origin'], 0)
wrong_message = signed_input(vector['primary']['name'], 'cafè.example/árbol', 0)
assert response_message.hex() == vector['response']['signingInputHex']
assert wrong_message.hex() == vector['wrongResponse']['signingInputHex']
for field, message in [('response', response_message), ('wrongResponse', wrong_message)]:
    record = vector[field]
    signature = bytes.fromhex(record['signatureHex'])
    wire = base64.b64encode(signature) + b'\n'
    assert len(signature) == 4627 and len(wire) == record['wireBytes'] == 6173
    assert wire.hex() == record['wireUtf8Hex'] and sha(wire).hex() == record['wireSha256']
    ml_dsa_87.verify(public_key, message, signature)
try:
    ml_dsa_87.verify(public_key, response_message,
                     bytes.fromhex(vector['wrongResponse']['signatureHex']))
except ValueError:
    pass
else:
    raise AssertionError('wrong-response signature verified under the original Unicode origin')

print('independent UTF-8 name replay: two signed requests, six negative request wires, 34 scalar-name samples and two 6173-byte response wires')
