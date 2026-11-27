import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { postSignSubtree } from './client.mjs';
import { mlDsa87KeyID } from './extension.mjs';
import { processSignSubtree } from './http.mjs';
import { parseSubtreeRequest, verifySubtreeRequest, verifySubtreeResponse } from './transport.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url)));
const old = readFileSync(new URL('../vectors/subtree-http-interop.json', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(old), vector.sourceInteropVectorSha256);
const wire = item => {
  const bytes = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const privateKey = createPrivateKey({ key: Buffer.from(vector.witness.pkcs8Hex, 'hex'), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
assert.equal(publicKey.export({ format: 'der', type: 'spki' }).toString('hex'), vector.witness.spkiHex);
assert.equal(mlDsa87KeyID(vector.witness.name, publicKey).toString('hex'), vector.witness.keyIDHex);
const admitted = { name: vector.witness.name, publicKey, at: vector.witness.at };
const request = wire(vector.request).toString('utf8');
const frozenResponse = wire(vector.frozenResponse).toString('ascii');
const signerInput = Buffer.from(vector.signerInputHex, 'hex');
const badSignerInput = Buffer.from(vector.badSignerInputHex, 'hex');
const badSignature = Buffer.from(vector.badSignatureHex, 'hex');
const fixedSignature = Buffer.from(frozenResponse.trimEnd(), 'base64');

test('frozen-signer-response', () => {
  assert.equal(verifySubtreeRequest(request, admitted).origin, JSON.parse(old).expectedOrigin);
  assert.deepEqual(verifySubtreeResponse(request, frozenResponse, admitted), fixedSignature);
  assert.equal(verify(null, signerInput, { key: publicKey, context: Buffer.alloc(0) }, fixedSignature), true);
});

test('live-signer-loopback', async () => {
  const seen = [];
  let serverError = null;
  const server = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const requestBytes = Buffer.concat(chunks);
      const result = processSignSubtree(requestBytes.toString('utf8'), {
        ...admitted,
        originKnown: origin => origin === JSON.parse(old).expectedOrigin,
        sign(input) {
          const message = Buffer.from(input);
          seen.push({ method: req.method, path: req.url, requestBytes, message });
          return sign(null, message, { key: privateKey, context: Buffer.alloc(0) });
        },
      });
      res.writeHead(result.status);
      res.end(result.body);
    } catch (error) {
      serverError = error;
      res.writeHead(500);
      res.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const signature = await postSignSubtree(`http://127.0.0.1:${server.address().port}/witness`, request, admitted);
    assert.equal(signature.length, 4627);
    assert.equal(verify(null, signerInput, { key: publicKey, context: Buffer.alloc(0) }, signature), true);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
  assert.equal(serverError, null);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, 'POST');
  assert.equal(seen[0].path, '/witness/sign-subtree');
  assert.deepEqual(seen[0].requestBytes, wire(vector.request));
  assert.deepEqual(seen[0].message, signerInput);
});

test('wrong-message-signer', () => {
  assert.equal(badSignerInput.length, signerInput.length);
  assert.equal(badSignerInput.subarray(0, -1).equals(signerInput.subarray(0, -1)), true);
  assert.equal(badSignerInput.at(-1), signerInput.at(-1) ^ 1);
  assert.equal(verify(null, badSignerInput, { key: publicKey, context: Buffer.alloc(0) }, badSignature), true);
  assert.equal(verify(null, signerInput, { key: publicKey, context: Buffer.alloc(0) }, badSignature), false);
  assert.throws(() => processSignSubtree(request, {
    ...admitted, originKnown: () => true, sign: () => badSignature,
  }), { code: 'SUBTREE_SIGNER_SIGNATURE' });
});

test('wrong-message-response', async () => {
  const server = createServer(async (req, res) => {
    for await (const _chunk of req) { /* drain request */ }
    res.writeHead(200);
    res.end(badSignature.toString('base64') + '\n');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(postSignSubtree(`http://127.0.0.1:${server.address().port}/witness`, request, admitted),
      { code: 'SUBTREE_SIGNATURE' });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
