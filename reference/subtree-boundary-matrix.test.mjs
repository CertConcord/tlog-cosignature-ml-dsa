import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mlDsa87KeyID, subtreeInput } from './extension.mjs';
import { parseSubtreeRequest, verifySubtreeRequest } from './transport.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-boundary-matrix.json', import.meta.url)));
const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const digest = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => digest(bytes).toString('hex');
const key = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const privateKey = createPrivateKey({ key: Buffer.from(source.witness.pkcs8Hex, 'hex'), type: 'pkcs8', format: 'der' });
const admitted = { name: vector.witness.name, publicKey: key, at: vector.witness.at };
const note = Buffer.from(vector.checkpoint.noteUtf8Hex, 'hex').toString('utf8');

test('boundary matrix source key and 257-leaf checkpoint bytes', () => {
  assert.equal(hex(sourceBytes), vector.sourceLiveVectorSha256);
  assert.equal(hex(Buffer.from(source.witness.spkiHex, 'hex')), vector.witness.spkiSha256);
  assert.equal(mlDsa87KeyID(vector.witness.name, key).toString('hex'), vector.witness.keyHintHex);
  assert.equal(Buffer.byteLength(note), vector.checkpoint.noteBytes);
  assert.equal(hex(Buffer.from(note)), vector.checkpoint.noteSha256);
});

for (const item of vector.cases) test('frozen boundary request: ' + item.id, () => {
  const prefix = Buffer.from(item.requestPrefixUtf8Hex, 'hex').toString('utf8');
  const wire = prefix + note;
  assert.equal(Buffer.byteLength(wire), item.wireBytes);
  assert.equal(hex(Buffer.from(wire)), item.wireSha256);
  const parsed = parseSubtreeRequest(wire);
  assert.equal(parsed.start, BigInt(item.start));
  assert.equal(parsed.end, BigInt(item.end));
  assert.equal(parsed.root.toString('hex'), item.subtreeHashHex);
  assert.deepEqual(parsed.proof.map(value => value.toString('hex')), item.proofHex);
  if (item.expected === 'VALID') assert.equal(verifySubtreeRequest(wire, admitted).checkpoint, note);
  else assert.throws(() => verifySubtreeRequest(wire, admitted), { code: item.expected });
});

const joined = (left, right) => digest(Buffer.concat([Buffer.from([1]), left, right]));
function treeHash(leaves) {
  if (leaves.length === 0) return digest(Buffer.alloc(0));
  if (leaves.length === 1) return digest(Buffer.concat([Buffer.from([0]), leaves[0]]));
  const split = 2 ** Math.floor(Math.log2(leaves.length - 1));
  return joined(treeHash(leaves.slice(0, split)), treeHash(leaves.slice(split)));
}
function subtreeProof(start, end, leaves, omit = true) {
  if (start === end) return [];
  if (start === 0 && end === leaves.length) return omit ? [] : [treeHash(leaves)];
  const split = 2 ** Math.floor(Math.log2(leaves.length - 1));
  if (end <= split) return [...subtreeProof(start, end, leaves.slice(0, split), omit), treeHash(leaves.slice(split))];
  if (start >= split) return [...subtreeProof(start - split, end - split, leaves.slice(split), omit), treeHash(leaves.slice(0, split))];
  assert.equal(start, 0);
  return [...subtreeProof(0, end - split, leaves.slice(split), false), treeHash(leaves.slice(0, split))];
}

test('all aligned ranges across empty and power-of-two boundary trees', () => {
  const sizes = [0, 1, 2, 3, 4, 7, 8, 9, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65,
    127, 128, 129, 255, 256, 257];
  let valid = 0, invalid = 0;
  for (const size of sizes) {
    const leaves = Array.from({ length: size }, (_, index) => Buffer.from(`boundary-leaf-${index}`));
    const root = treeHash(leaves);
    const timestamp = BigInt(vector.witness.timestamp);
    const signature = sign(null, subtreeInput({ name: admitted.name, origin: vector.checkpoint.origin,
      start: 0n, end: BigInt(size), root, timestamp }), { key: privateKey, context: Buffer.alloc(0) });
    const time = Buffer.alloc(8);
    time.writeBigUInt64BE(timestamp);
    const checkpoint = `${vector.checkpoint.origin}\n${size}\n${root.toString('base64')}\n\n` +
      `\u2014 ${admitted.name} ${Buffer.concat([mlDsa87KeyID(admitted.name, key), time, signature]).toString('base64')}\n`;
    for (let start = 0; start <= size; start++) for (let end = start; end <= size; end++) {
      const width = end === start ? 1 : 2 ** Math.ceil(Math.log2(end - start));
      if (start % width !== 0) continue;
      const nodeHash = treeHash(leaves.slice(start, end));
      const nodes = subtreeProof(start, end, leaves);
      assert(nodes.length <= 63);
      const wire = (hash, proof) => `subtree ${start} ${end}\n${hash.toString('base64')}\n` +
        proof.map(value => value.toString('base64') + '\n').join('') + `\n${checkpoint}`;
      assert.equal(verifySubtreeRequest(wire(nodeHash, nodes), admitted).end, BigInt(end));
      valid++;
      if (nodes.length) nodes[0][0] ^= 1;
      else nodeHash[0] ^= 1;
      assert.throws(() => verifySubtreeRequest(wire(nodeHash, nodes), admitted), { code: 'SUBTREE_PROOF' });
      invalid++;
    }
  }
  assert.equal(valid, 8465);
  assert.equal(invalid, 8465);
});
