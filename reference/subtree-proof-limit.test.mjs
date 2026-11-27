import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { encodeSubtreeRequest, parseSubtreeRequest, verifySubtreeCheckpoint, verifySubtreeRequest } from './transport.mjs';
import { mlDsa87KeyID } from './extension.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-proof-limit.json', import.meta.url)));
const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const spki = Buffer.from(source.witness.spkiHex, 'hex');
const publicKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
const admitted = { name: vector.witness.name, publicKey, at: vector.witness.at };
const trees = new Map(vector.trees.map(value => [value.id, value]));

test('proof-limit fixture preserves the experimental key and fixed 63-line carriage', () => {
  assert.equal(vector.wireProfile, 'C2SP-20261007-MLDSA87-v2');
  assert.equal(vector.selectedProofRule, 'MTC draft-07 Section 4.4.3');
  assert.equal(vector.maxTransportProofLines, 63);
  assert.equal(sha(sourceBytes), vector.sourceLiveVectorSha256);
  assert.equal(sha(spki), vector.witness.spkiSha256);
  assert.equal(mlDsa87KeyID(admitted.name, publicKey).toString('hex'), vector.witness.keyHintHex);
  assert.deepEqual(vector.trees.map(value => value.size),
    ['9223372036854775808', '9223372036854775809', '18446744073709551615']);
});

for (const tree of vector.trees) test(`signed proof-limit checkpoint: ${tree.size}`, () => {
  const note = Buffer.from(tree.noteUtf8Hex, 'hex');
  assert.equal(note.length, tree.noteBytes);
  assert.equal(sha(note), tree.noteSha256);
  const checkpoint = verifySubtreeCheckpoint(note.toString('utf8'), admitted);
  assert.equal(checkpoint.size, BigInt(tree.size));
  assert.equal(checkpoint.root.toString('hex'), tree.rootHex);
});

for (const item of vector.cases) test(`complete proof-limit request: ${item.id}`, () => {
  const tree = trees.get(item.tree);
  assert(tree);
  const prefix = Buffer.from(item.requestPrefixUtf8Hex, 'hex');
  const note = Buffer.from(tree.noteUtf8Hex, 'hex');
  const wire = Buffer.concat([prefix, note]);
  assert.equal(wire.length, item.wireBytes);
  assert.equal(sha(wire), item.wireSha256);
  const request = wire.toString('utf8');
  const input = { start: 0n, end: 1n, root: Buffer.from(item.subtreeHashHex, 'hex'),
    proof: item.proofHex.map(value => Buffer.from(value, 'hex')),
    checkpoint: note.toString('utf8') };
  if (item.expected === 'SUBTREE_REQUEST') {
    assert.equal(item.proofHex.length, 64);
    assert.throws(() => parseSubtreeRequest(request), { code: 'SUBTREE_REQUEST' });
    assert.throws(() => verifySubtreeRequest(request, admitted), { code: 'SUBTREE_REQUEST' });
    assert.throws(() => encodeSubtreeRequest(input), { code: 'SUBTREE_REQUEST' });
  } else {
    assert.equal(item.proofHex.length, 63);
    assert.equal(encodeSubtreeRequest(input), request);
    const parsed = parseSubtreeRequest(request);
    assert.equal(parsed.start, 0n);
    assert.equal(parsed.end, 1n);
    assert.deepEqual(parsed.proof.map(value => value.toString('hex')), item.proofHex);
    if (item.expected === 'VALID') {
      assert.equal(verifySubtreeRequest(request, admitted).checkpoint, note.toString('utf8'));
    } else {
      assert.equal(item.expected, 'SUBTREE_PROOF');
      assert.throws(() => verifySubtreeRequest(request, admitted), { code: 'SUBTREE_PROOF' });
    }
  }
});
