import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { subtreeInput, verifyCosignature } from './extension.mjs';
import { parseSubtreeRequest, verifySubtreeResponse } from './transport.mjs';

const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-cross-runtime.json', import.meta.url)));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(sourceBytes), vector.sourceLiveVectorSha256);
const wire = item => {
  const bytes = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const publicKey = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'), format: 'der', type: 'spki' });
const witness = { name: source.witness.name, publicKey, at: source.witness.at };
const request = wire(source.request).toString('utf8');
const parsed = parseSubtreeRequest(request);
const context = { name: witness.name, origin: parsed.origin, start: parsed.start,
  end: parsed.end, root: parsed.root, timestamp: 0n };
const message = Buffer.from(vector.signedInputHex, 'hex');
const badMessage = Buffer.from(vector.badSignedInputHex, 'hex');
const pythonSignature = Buffer.from(vector.pythonSignatureHex, 'hex');
const pythonResponse = wire(vector.pythonResponse).toString('ascii');

test('cross-python-response-node-verify', () => {
  assert.deepEqual(subtreeInput(context), message);
  assert.equal(message.toString('hex'), source.signerInputHex);
  assert.equal(pythonSignature.length, 4627);
  assert.equal(pythonResponse, pythonSignature.toString('base64') + '\n');
  assert.deepEqual(verifySubtreeResponse(request, pythonResponse, witness), pythonSignature);
  assert.equal(verifyCosignature(context, pythonSignature, publicKey), true);
  assert.equal(verify(null, message, { key: publicKey, context: Buffer.alloc(0) }, pythonSignature), true);
});

test('cross-python-signature-bad-message', () => {
  assert.equal(badMessage.toString('hex'), source.badSignerInputHex);
  assert.equal(badMessage.length, message.length);
  assert.equal(badMessage.subarray(0, -1).equals(message.subarray(0, -1)), true);
  assert.equal(badMessage.at(-1), message.at(-1) ^ 1);
  assert.equal(verify(null, badMessage, { key: publicKey, context: Buffer.alloc(0) }, pythonSignature), false);
  const wrongRoot = Buffer.from(parsed.root);
  wrongRoot[wrongRoot.length - 1] ^= 1;
  const altered = { ...context, root: wrongRoot };
  assert.deepEqual(subtreeInput(altered), badMessage);
  assert.equal(verifyCosignature(altered, pythonSignature, publicKey), false);
});

test('cross-python-signature-bad-context', () => {
  const wrongContext = Buffer.from(vector.wrongContextHex, 'hex');
  assert.deepEqual(wrongContext, Buffer.from([1]));
  assert.equal(verify(null, message, { key: publicKey, context: wrongContext }, pythonSignature), false);
});
