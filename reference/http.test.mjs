import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { processSignSubtree } from './http.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-http.json', import.meta.url)));
const source = readFileSync(new URL('../vectors/subtree-response-auth.json', import.meta.url));
assert.equal(createHash('sha256').update(source).digest('hex'), vector.sourceResponseVectorSha256);
const prior = JSON.parse(source);
const publicKey = createPublicKey({ key: Buffer.from(vector.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const otherPublicKey = createPublicKey({ key: Buffer.from(vector.witness.otherSpkiHex, 'hex'), type: 'spki', format: 'der' });
const raw = key => Buffer.from(Buffer.from(prior.responses[key].utf8Hex, 'hex').toString('ascii').trimEnd(), 'base64');
const signatures = { valid: raw('valid'), otherKey: raw('otherKey'), short: Buffer.alloc(4626) };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const from = item => {
  const value = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(value.length, item.bytes);
  assert.equal(sha(value), item.sha256);
  return value.toString('utf8');
};

for (const item of vector.cases) {
  test(item.id, () => {
    let signerCalls = 0;
    let originCalls = 0;
    const request = from(vector.requests[item.request]);
    const settings = {
      name: vector.witness.name,
      publicKey: item.witnessKey === 'other' ? otherPublicKey : publicKey,
      at: item.at ?? vector.witness.at,
      originKnown(origin) { originCalls++; assert.equal(origin, prior.checkpoint.origin); return item.originKnown; },
      sign(input) { signerCalls++; assert.equal(input.toString('hex'), prior.subtree.signedInputHex); return signatures[item.signer]; },
    };
    if (item.error) {
      assert.throws(() => processSignSubtree(request, settings), error => error.code === item.error);
      assert.equal(signerCalls, 1);
      assert.equal(originCalls, 1);
    } else {
      const result = processSignSubtree(request, settings);
      assert.equal(result.status, item.status);
      assert.equal(result.body, from(vector.bodies[item.body]));
      assert.equal(signerCalls, item.status === 200 ? 1 : 0);
      assert.equal(originCalls, item.status === 200 || item.status === 404 ? 1 : 0);
    }
  });
}

test('the admitted witness key is captured once across checkpoint and signer verification', () => {
  let reads = 0;
  const settings = {
    name: vector.witness.name,
    at: vector.witness.at,
    get publicKey() { return ++reads === 1 ? publicKey : otherPublicKey; },
    originKnown() { return true; },
    sign() { return signatures.valid; },
  };
  const result = processSignSubtree(from(vector.requests.valid), settings);
  assert.equal(result.status, 200);
  assert.equal(result.body, from(vector.bodies.success));
  assert.equal(reads, 1);
});
