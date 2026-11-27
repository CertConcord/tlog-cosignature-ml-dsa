import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseSubtreeResponse, verifySubtreeRequest, verifySubtreeResponse } from './transport.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-large-u64-http.json', import.meta.url)));
const largeBytes = readFileSync(new URL('../vectors/subtree-large-u64.json', import.meta.url));
const large = JSON.parse(largeBytes);
const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const tree = large.trees.find(item => item.size === '18446744069414649856');
const normal = large.cases.find(item => item.id === vector.requestSourceCase);
const bad = large.cases.find(item => item.id === vector.badProofSourceCase);
const requestBytes = item => Buffer.concat([Buffer.from(item.requestPrefixUtf8Hex, 'hex'),
  Buffer.from(tree.noteUtf8Hex, 'hex')]);
const publicKey = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'),
  type: 'spki', format: 'der' });
const witness = { name: large.witness.name, publicKey, at: large.witness.at };
const response = item => Buffer.from(item.utf8Hex, 'hex');

test('large-u64 HTTP vector binds the original 48-hash signed request bytes', () => {
  assert.equal(sha(largeBytes), vector.sourceLargeVectorSha256);
  assert.equal(sha(sourceBytes), vector.sourceLiveVectorSha256);
  assert(tree && normal && bad);
  const request = requestBytes(normal);
  const rejected = requestBytes(bad);
  assert.equal(request.length, vector.requestBytes);
  assert.equal(sha(request), vector.requestSha256);
  assert.equal(sha(rejected), vector.badProofRequestSha256);
  assert.equal(normal.proofHex.length, vector.proofLines);
  assert.equal(verifySubtreeRequest(request.toString('utf8'), witness).end, BigInt(normal.end));
  assert.throws(() => verifySubtreeRequest(rejected.toString('utf8'), witness),
    { code: 'SUBTREE_PROOF' });
});

test('Python frozen HTTP response authenticates the large-u64 request', () => {
  const body = response(vector.responses.valid);
  assert.equal(body.length, vector.responses.valid.bytes);
  assert.equal(sha(body), vector.responses.valid.sha256);
  const signature = parseSubtreeResponse(body.toString('ascii'));
  assert.equal(sha(signature), vector.responses.valid.signatureSha256);
  assert.equal(verify(null, Buffer.from(vector.signerInputHex, 'hex'),
    { key: publicKey, context: Buffer.alloc(0) }, signature), true);
  assert.deepEqual(verifySubtreeResponse(requestBytes(normal).toString('utf8'),
    body.toString('ascii'), witness), signature);
});

test('Python wrong-message HTTP response preserves bytes but fails request authentication', () => {
  const body = response(vector.responses.wrongMessage);
  assert.equal(body.length, vector.responses.wrongMessage.bytes);
  assert.equal(sha(body), vector.responses.wrongMessage.sha256);
  const signature = parseSubtreeResponse(body.toString('ascii'));
  assert.equal(sha(signature), vector.responses.wrongMessage.signatureSha256);
  assert.equal(verify(null, Buffer.from(vector.wrongSignerInputHex, 'hex'),
    { key: publicKey, context: Buffer.alloc(0) }, signature), true);
  assert.equal(verify(null, Buffer.from(vector.signerInputHex, 'hex'),
    { key: publicKey, context: Buffer.alloc(0) }, signature), false);
  assert.throws(() => verifySubtreeResponse(requestBytes(normal).toString('utf8'),
    body.toString('ascii'), witness), { code: 'SUBTREE_SIGNATURE' });
});

test('large-u64 HTTP case registry covers live and raw peer outcomes', () => {
  assert.deepEqual(vector.cases.map(item => [item.mode, item.expected, item.sent]), [
    ['frozen', 'VALID', 1], ['live', 'VALID', 1],
    ['wrong-response', 'SUBTREE_SIGNATURE', 1],
    ['bad-proof-local', 'SUBTREE_PROOF', 0], ['raw-bad-proof', 'HTTP_422', 1],
  ]);
});
