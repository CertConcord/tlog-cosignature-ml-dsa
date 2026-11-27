import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parseSubtreeResponse, verifySubtreeResponse } from './transport.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-response-auth.json', import.meta.url)));
const publicKey = createPublicKey({ key: Buffer.from(vector.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const otherPublicKey = createPublicKey({ key: Buffer.from(vector.witness.otherSpkiHex, 'hex'), type: 'spki', format: 'der' });
const witness = { name: vector.witness.name, publicKey, at: vector.witness.at };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fromHex = item => {
  const bytes = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes.toString('utf8');
};

for (const item of vector.cases) {
  test(`authenticated response ${item.id}`, () => {
    const request = fromHex(vector.requests[item.request]);
    const response = fromHex(vector.responses[item.response]);
    if (item.expected === 'VALID') {
      const parsed = parseSubtreeResponse(response);
      assert.equal(parsed.length, 4627);
      assert.deepEqual(verifySubtreeResponse(request, response, witness), parsed);
    } else {
      assert.throws(() => verifySubtreeResponse(request, response, witness), error => error.code === item.expected);
    }
  });
}

for (const [id, context] of Object.entries(vector.signatureContexts)) {
  test(`fixture signature authenticates its recorded ${id} context`, () => {
    const key = context.key === 'otherSpkiHex' ? otherPublicKey : publicKey;
    const signature = parseSubtreeResponse(fromHex(vector.responses[id]));
    assert.equal(verify(null, Buffer.from(context.signedInputHex, 'hex'),
      { key, context: Buffer.alloc(0) }, signature), true);
  });
}

test('admitted public key is read once for both checkpoint and response', () => {
  let reads = 0;
  const mutableWitness = {
    name: vector.witness.name,
    at: vector.witness.at,
    get publicKey() { return ++reads === 1 ? publicKey : otherPublicKey; },
  };
  const result = verifySubtreeResponse(fromHex(vector.requests.valid), fromHex(vector.responses.valid), mutableWitness);
  assert.equal(result.length, 4627);
  assert.equal(reads, 1);
});
