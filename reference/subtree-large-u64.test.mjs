import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mlDsa87KeyID } from './extension.mjs';
import { parseSubtreeRequest, verifySubtreeRequest } from './transport.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-large-u64.json', import.meta.url)));
const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const key = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const admitted = { name: vector.witness.name, publicKey: key, at: vector.witness.at };
const trees = new Map(vector.trees.map(value => [value.id, value]));

test('large u64 vector reuses the admitted test key and original range shapes', () => {
  assert.equal(sha(sourceBytes), vector.sourceLiveVectorSha256);
  assert.equal(sha(Buffer.from(source.witness.spkiHex, 'hex')), vector.witness.spkiSha256);
  assert.equal(mlDsa87KeyID(admitted.name, key).toString('hex'), vector.witness.keyHintHex);
  assert.equal(vector.virtualLeafAscii, 'certconcord-large-u64-leaf-v1');
  assert.deepEqual(vector.trees.map(value => value.size),
    ['281474959937536', '9223372034707324928', '18446744069414649856']);
  assert.equal(vector.cases.filter(value => value.expected === 'VALID').length, 9);
  assert.equal(vector.cases.filter(value => value.expected === 'SUBTREE_PROOF').length, 6);
});

for (const tree of vector.trees) test(`frozen large u64 checkpoint: ${tree.id}`, () => {
  const note = Buffer.from(tree.noteUtf8Hex, 'hex');
  assert.equal(note.length, tree.noteBytes);
  assert.equal(sha(note), tree.noteSha256);
  assert(note.toString('utf8').includes(`\n${tree.size}\n${Buffer.from(tree.rootHex, 'hex').toString('base64')}\n`));
});

for (const item of vector.cases) test(`frozen large u64 request: ${item.id}`, () => {
  const tree = trees.get(item.tree);
  assert(tree);
  const prefix = Buffer.from(item.requestPrefixUtf8Hex, 'hex');
  const note = Buffer.from(tree.noteUtf8Hex, 'hex');
  const wire = Buffer.concat([prefix, note]);
  assert.equal(wire.length, item.wireBytes);
  assert.equal(sha(wire), item.wireSha256);
  assert(item.proofHex.length <= 63);
  const request = wire.toString('utf8');
  const parsed = parseSubtreeRequest(request);
  assert.equal(parsed.start, BigInt(item.start));
  assert.equal(parsed.end, BigInt(item.end));
  assert.equal(parsed.root.toString('hex'), item.subtreeHashHex);
  assert.deepEqual(parsed.proof.map(value => value.toString('hex')), item.proofHex);
  if (item.expected === 'VALID') {
    const verified = verifySubtreeRequest(request, admitted);
    assert.equal(verified.checkpoint, note.toString('utf8'));
    assert.equal(verified.end, BigInt(item.end));
  } else {
    assert.throws(() => verifySubtreeRequest(request, admitted), { code: item.expected });
  }
});
