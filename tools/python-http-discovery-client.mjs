import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { postSignSubtree } from '../reference/client.mjs';
import { mlDsa87KeyID, selectMlDsa87Key } from '../reference/extension.mjs';
import { parseCheckpointEnvelope, parseSubtreeRequest } from '../reference/transport.mjs';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url));
const json = path => JSON.parse(read(path));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const vector = json('vectors/subtree-python-http-discovery.json');
const live = json('vectors/subtree-live-sign.json');
const http = json('vectors/subtree-python-http-interop.json');
const discovery = json('vectors/key-discovery.json');
assert.equal(sha(read('vectors/subtree-live-sign.json')), vector.sourceLiveVectorSha256);
assert.equal(sha(read('vectors/subtree-python-http-interop.json')), vector.sourcePythonHttpVectorSha256);
assert.equal(sha(read('vectors/key-discovery.json')), vector.sourceKeyDiscoveryVectorSha256);
assert.equal(vector.profile, http.profile);
assert.equal(vector.name, live.witness.name);
assert.equal(Buffer.from(vector.name, 'ascii').toString('hex'), vector.nameUtf8Hex);

const sources = {
  live87: live.witness.spkiHex,
  other87: discovery.keys.second,
  legacy44: discovery.keys.legacy44,
};
const keys = {};
for (const [id, hex] of Object.entries(sources)) {
  const spki = Buffer.from(hex, 'hex');
  const recorded = vector.keys[id];
  assert.equal(spki.length, recorded.spkiBytes);
  assert.equal(sha(spki), recorded.spkiSha256);
  const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(publicKey.asymmetricKeyType, recorded.algorithm);
  if (recorded.algorithm === 'ml-dsa-87') {
    const independentHint = createHash('sha256').update(Buffer.concat([
      Buffer.from('certconcord/tlog-ml-dsa-87/v1\n'), Buffer.from(vector.name + '\n'), spki,
    ])).digest().subarray(0, 4);
    assert.equal(independentHint.toString('hex'), recorded.experimentalHintHex);
    assert.deepEqual(mlDsa87KeyID(vector.name, publicKey), independentHint);
  }
  keys[id] = publicKey;
}

const requestBytes = Buffer.from(vector.request.utf8Hex, 'hex');
assert.equal(requestBytes.length, vector.request.bytes);
assert.equal(sha(requestBytes), vector.request.sha256);
assert.deepEqual(requestBytes, Buffer.from(http.request.utf8Hex, 'hex'));
assert.equal(vector.signerInputHex, http.signerInputHex);
assert.equal(vector.frozenResponseSha256, http.bodies.frozen.sha256);
assert.equal(vector.frozenResponseBytes, http.bodies.frozen.bytes);

const [port, caseId] = process.argv.slice(2);
assert.match(port ?? '', /^[0-9]+$/);
const selected = vector.cases.find(item => item.id === caseId);
assert(selected);
const candidates = selected.candidates.map(item => ({ name: item.name, publicKey: keys[item.key] }));
const input = selected.inputRequest === 'original' ? vector.request : vector.alteredRequests[selected.inputRequest];
assert(input);
const requestBytesForCase = Buffer.from(input.utf8Hex, 'hex');
assert.equal(requestBytesForCase.length, input.bytes);
assert.equal(sha(requestBytesForCase), input.sha256);
const requestText = requestBytesForCase.toString('utf8');
const parsed = parseSubtreeRequest(requestText);
const checkpoint = parseCheckpointEnvelope(parsed.checkpoint);
assert.equal(checkpoint.signatures.length, 1);
const hint = Buffer.from(checkpoint.signatures[0].keyID);
assert.equal(hint.toString('hex'), selected.hintHex);
const prefix = `http://127.0.0.1:${port}/witness`;
let outcome;
try {
  const publicKey = selectMlDsa87Key(vector.name, hint, candidates);
  assert(selected.selectedKey);
  assert.equal(sha(publicKey.export({ format: 'der', type: 'spki' })),
    vector.keys[selected.selectedKey].spkiSha256);
  const signature = await postSignSubtree(prefix, requestText, {
    name: vector.name, publicKey, at: live.witness.at,
  });
  assert.equal(selected.expected, 'VALID');
  assert.equal(signature.length, 4627);
  assert.equal(verify(null, Buffer.from(vector.signerInputHex, 'hex'),
    { key: publicKey, context: Buffer.alloc(0) }, signature), true);
  if (selected.mode === 'frozen') {
    const frozen = Buffer.from(http.bodies.frozen.utf8Hex, 'hex');
    assert.equal(sha(frozen), vector.frozenResponseSha256);
    assert.deepEqual(signature, Buffer.from(frozen.subarray(0, -1).toString('ascii'), 'base64'));
  }
  outcome = { result: 'VALID', signatureBytes: signature.length };
} catch (error) {
  if (selected.expected === 'VALID') throw error;
  assert.equal(error.code, selected.expected);
  outcome = { result: error.code };
}
process.stdout.write(JSON.stringify(outcome) + '\n');
