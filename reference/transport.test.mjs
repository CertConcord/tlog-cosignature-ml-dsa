import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey, verify, generateKeyPairSync } from 'node:crypto';
import { verifyCosignature } from './extension.mjs';
import { SUBTREE_WIRE_PROFILE, parseSubtreeRequest, encodeSubtreeRequest, parseSubtreeResponse, encodeSubtreeResponse, verifySubtreeCheckpoint, assertCheckpointLogSignature } from './transport.mjs';
const vectors = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url)));
const key = hex => createPublicKey({ key: Buffer.from(hex, 'hex'), format: 'der', type: 'spki' });
const witness = { name: vectors.witness.name, publicKey: key(vectors.witness.spki), at: vectors.at };
for (const vector of vectors.cases) test('serialized transport: ' + vector.id, () => {
  function evaluate() {
    if (vector.operation === 'response') {
      const signature = parseSubtreeResponse(vector.wire);
      assert.equal(encodeSubtreeResponse(signature), vector.wire);
      assert(verifyCosignature({ name: witness.name, origin: vectors.log.name, start: 0, end: 3, root: Buffer.from(vectors.root, 'hex'), timestamp: 0 }, signature, witness.publicKey));
    } else if (vector.operation === 'request') {
      const request = parseSubtreeRequest(vector.wire);
      verifySubtreeCheckpoint(request.checkpoint, witness);
      assert.equal(encodeSubtreeRequest(request), vector.wire);
    } else {
      const checkpoint = assertCheckpointLogSignature(vector.wire, { name: vectors.log.name, keyID: Buffer.from(vectors.log.keyHint, 'hex') });
      const signature = checkpoint.signatures.find(value => value.name === vectors.log.name);
      assert(verify(null, Buffer.from(checkpoint.body), key(vectors.log.spki), signature.signature));
    }
  }
  if (vector.expected === 'VALID') evaluate();
  else assert.throws(evaluate, { code: vector.expected });
});
test('the selected wire profile and same admitted witness key are explicit', () => {
  assert.equal(SUBTREE_WIRE_PROFILE, vectors.wireProfile);
  const request = parseSubtreeRequest(vectors.cases.find(value => value.id === 'one-witness-request').wire);
  assert.throws(() => verifySubtreeCheckpoint(request.checkpoint, { ...witness, publicKey: generateKeyPairSync('ml-dsa-87').publicKey }), { code: 'SUBTREE_WITNESS_KEY' });
  assert.throws(() => verifySubtreeCheckpoint(request.checkpoint, { ...witness, at: vectors.at - 31 }), { code: 'CHECKPOINT_FUTURE' });
  assert.throws(() => encodeSubtreeResponse(Buffer.alloc(2420)), { code: 'SUBTREE_SIGNATURE_LENGTH' });
});
