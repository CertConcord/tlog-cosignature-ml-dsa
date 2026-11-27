import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseSubtreeRequest, verifySubtreeRequest } from './transport.mjs';
import { mlDsa87KeyID, subtreeInput } from './extension.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/subtree-consistency.json', import.meta.url)));
const existing = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url)));
const key = createPublicKey({ key: Buffer.from(vectors.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const witness = { name: vectors.witness.name, publicKey: key, at: vectors.witness.at };
const checkpoint = Buffer.from(vectors.checkpoint.noteUtf8Hex, 'hex').toString('utf8');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('fixed checkpoint and 4,627-byte witness signature retain their original bytes', () => {
  assert.equal(Buffer.byteLength(checkpoint), vectors.checkpoint.noteBytes);
  assert.equal(sha(Buffer.from(checkpoint)), vectors.checkpoint.noteSha256);
  assert(checkpoint.startsWith(Buffer.from(vectors.checkpoint.bodyUtf8Hex, 'hex').toString('utf8') + '\n'));
  assert.equal(vectors.witness.signatureBytes, 4627);
});

for (const item of vectors.cases) test('subtree consistency: ' + item.id, () => {
  const prefix = Buffer.from(item.requestPrefixUtf8Hex, 'hex').toString('utf8');
  const wire = prefix + checkpoint;
  assert.equal(Buffer.byteLength(wire), item.wireBytes);
  assert.equal(sha(Buffer.from(wire)), item.wireSha256);
  const parsed = parseSubtreeRequest(wire);
  assert.equal(parsed.start, BigInt(item.start));
  assert.equal(parsed.end, BigInt(item.end));
  assert.equal(parsed.root.toString('hex'), item.subtreeHashHex);
  assert.deepEqual(parsed.proof.map(hash => hash.toString('hex')), item.proofHex);
  if (item.expected === 'VALID') {
    const verified = verifySubtreeRequest(wire, witness);
    assert.equal(verified.checkpoint, checkpoint);
    assert.equal(verified.root.toString('hex'), item.subtreeHashHex);
  } else {
    assert.throws(() => verifySubtreeRequest(wire, witness), { code: item.expected });
  }
});

test('the existing full-range request and its signature remain acceptable', () => {
  const wire = existing.cases.find(item => item.id === 'one-witness-request').wire;
  const admitted = {
    name: existing.witness.name,
    publicKey: createPublicKey({ key: Buffer.from(existing.witness.spki, 'hex'), type: 'spki', format: 'der' }),
    at: existing.at,
  };
  assert.equal(verifySubtreeRequest(wire, admitted).checkpoint, parseSubtreeRequest(wire).checkpoint);
});

test('63 proof hashes use BigInt indices and the fixed wire limit', () => {
  const size = 1n << 63n;
  const subtreeRoot = createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from('large-tree-leaf')])).digest();
  const siblings = Array.from({ length: 63 }, (_, index) => Buffer.alloc(32, index));
  let checkpointRoot = subtreeRoot;
  for (const sibling of siblings)
    checkpointRoot = createHash('sha256').update(Buffer.concat([Buffer.from([1]), checkpointRoot, sibling])).digest();
  const { publicKey, privateKey } = generateKeyPairSync('ml-dsa-87');
  const name = 'witness.example/bigint', origin = 'log.example/bigint', timestamp = 1700000000n;
  const hint = mlDsa87KeyID(name, publicKey);
  const time = Buffer.alloc(8);
  time.writeBigUInt64BE(timestamp);
  const signature = sign(null, subtreeInput({ name, origin, end: size, root: checkpointRoot, timestamp }), {
    key: privateKey, context: Buffer.alloc(0),
  });
  const checkpoint = `${origin}\n${size}\n${checkpointRoot.toString('base64')}\n\n— ${name} ${Buffer.concat([hint, time, signature]).toString('base64')}\n`;
  const request = hashes => `subtree 0 1\n${subtreeRoot.toString('base64')}\n${hashes.map(value => value.toString('base64') + '\n').join('')}\n${checkpoint}`;
  const admitted = { name, publicKey, at: Number(timestamp) };
  assert.equal(verifySubtreeRequest(request(siblings), admitted).end, 1n);
  assert.throws(() => verifySubtreeRequest(request(siblings.slice(0, -1)), admitted), { code: 'SUBTREE_PROOF' });
  assert.throws(() => verifySubtreeRequest(request([...siblings, Buffer.alloc(32)]), admitted), { code: 'SUBTREE_REQUEST' });
});
