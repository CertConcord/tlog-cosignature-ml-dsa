import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { mlDsa87KeyID, selectMlDsa87Key, subtreeInput } from './extension.mjs';
import { parseSubtreeRequest, verifySubtreeRequest, verifySubtreeResponse } from './transport.mjs';

const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const crossBytes = readFileSync(new URL('../vectors/subtree-cross-runtime.json', import.meta.url));
const discoveryBytes = readFileSync(new URL('../vectors/key-discovery.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const cross = JSON.parse(crossBytes);
const discovery = JSON.parse(discoveryBytes);
const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-cross-runtime-checkpoint.json', import.meta.url)));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(sourceBytes), vector.sourceLiveVectorSha256);
assert.equal(sha(crossBytes), vector.sourceCrossRuntimeVectorSha256);
assert.equal(sha(discoveryBytes), vector.sourceDiscoveryVectorSha256);
const wire = item => {
  const bytes = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const publicKey = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'), format: 'der', type: 'spki' });
const witness = { name: source.witness.name, publicKey, at: source.witness.at };
const requestBytes = wire(vector.request);
const request = requestBytes.toString('utf8');
const noteBytes = wire(vector.checkpointNote);
const note = noteBytes.toString('utf8');
const response = wire(cross.pythonResponse).toString('ascii');
const prefix = `— ${source.witness.name} `;
const line = note.slice(note.indexOf(prefix) + prefix.length, -1);
const payload = Buffer.from(line, 'base64');

test('cross-python-checkpoint-node-verify', () => {
  assert.equal(sha(Buffer.from(source.witness.spkiHex, 'hex')), vector.spkiSha256);
  assert.equal(mlDsa87KeyID(witness.name, publicKey).toString('hex'), vector.keyHintHex);
  assert.equal(Buffer.from(witness.name).toString('hex'), vector.nameUtf8Hex);
  assert.equal(requestBytes.subarray(-noteBytes.length).equals(noteBytes), true);
  const oldNote = Buffer.from(source.checkpoint.note.utf8Hex, 'hex');
  const oldRequest = wire(source.request);
  assert.equal(requestBytes.subarray(0, -noteBytes.length).equals(oldRequest.subarray(0, -oldNote.length)), true);
  assert.deepEqual(noteBytes.subarray(0, noteBytes.indexOf(Buffer.from('\n\n')) + 2),
    oldNote.subarray(0, oldNote.indexOf(Buffer.from('\n\n')) + 2));
  assert.equal(payload.length, 4 + 8 + 4627);
  assert.equal(payload.subarray(0, 4).toString('hex'), vector.keyHintHex);
  assert.equal(Number(payload.readBigUInt64BE(4)), vector.checkpointTimestamp);
  assert.equal(sha(payload.subarray(12)), vector.checkpointSignatureSha256);
  assert.equal(payload.toString('base64'), line);
  const parsed = parseSubtreeRequest(request);
  assert.deepEqual(subtreeInput({name: witness.name, origin: parsed.origin, start: 0n,
    end: BigInt(note.split('\n')[1]), root: Buffer.from(note.split('\n')[2], 'base64'),
    timestamp: vector.checkpointTimestamp}),
    Buffer.from(vector.checkpointSignedInputHex, 'hex'));
  assert.deepEqual(verifySubtreeRequest(request, witness), parsed);
});

test('cross-python-checkpoint-and-response-node-verify', () => {
  const signature = verifySubtreeResponse(request, response, witness);
  assert.equal(signature.length, 4627);
  assert.equal(sha(signature), sha(Buffer.from(cross.pythonSignatureHex, 'hex')));
  assert.equal(sha(Buffer.from(response)), vector.pythonResponseSha256);
});

for (const item of vector.negativeRequests) {
  test(item.id, () => {
    const changed = wire(item.request);
    const marker = changed.indexOf(Buffer.from(prefix));
    assert.notEqual(marker, -1);
    const start = marker + Buffer.byteLength(prefix);
    const end = changed.indexOf(10, start);
    const changedPayload = Buffer.from(changed.subarray(start, end).toString('ascii'), 'base64');
    assert.equal(changedPayload.length, payload.length);
    const copy = Buffer.from(payload);
    assert.equal(copy[item.payloadByteOffset].toString(16).padStart(2, '0'), item.beforeHex);
    copy[item.payloadByteOffset] ^= 1;
    assert.equal(copy[item.payloadByteOffset].toString(16).padStart(2, '0'), item.afterHex);
    assert.deepEqual(changedPayload, copy);
    const expected = Buffer.concat([requestBytes.subarray(0, start),
      Buffer.from(copy.toString('base64')), requestBytes.subarray(end)]);
    assert.deepEqual(changed, expected);
    assert.throws(() => verifySubtreeRequest(changed.toString('utf8'), witness), { message: item.expected });
  });
}

for (const item of vector.wireFailures) {
  test(item.id, () => {
    const changed = wire(item.request);
    assert.throws(() => verifySubtreeRequest(changed.toString('utf8'), witness),
      { message: item.expected });
  });
}

test('cross-python-checkpoint-mldsa44-key', () => {
  const legacy = Buffer.from(vector.legacyMlDsa44SpkiHex, 'hex');
  assert.equal(legacy.equals(Buffer.from(discovery.keys.legacy44, 'hex')), true);
  assert.equal(sha(legacy), vector.legacyMlDsa44SpkiSha256);
  const legacyKey = createPublicKey({ key: legacy, format: 'der', type: 'spki' });
  assert.equal(legacyKey.asymmetricKeyType, 'ml-dsa-44');
  assert.throws(() => mlDsa87KeyID(witness.name, legacyKey), { message: 'NOTE_KEY_SCHEME' });
  assert.throws(() => selectMlDsa87Key(witness.name, Buffer.from(vector.keyHintHex, 'hex'),
    [{ name: witness.name, publicKey: legacyKey }]), { message: 'NOTE_KEY_UNKNOWN' });
});
