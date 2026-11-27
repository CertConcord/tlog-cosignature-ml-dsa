// Freeze original virtual-tree proofs on both sides of the C2SP 63-line limit.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { mlDsa87KeyID, subtreeInput } from '../reference/extension.mjs';

const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const name = source.witness.name;
const spki = Buffer.from(source.witness.spkiHex, 'hex');
const publicKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
const privateKey = createPrivateKey({ key: Buffer.from(source.witness.pkcs8Hex, 'hex'), type: 'pkcs8', format: 'der' });
const origin = 'log.example/proof-limit';
const leafText = 'certconcord-proof-limit-leaf-v1';
const timestamp = 1700000000n;
const hint = mlDsa87KeyID(name, publicKey);
const stamp = Buffer.alloc(8);
stamp.writeBigUInt64BE(timestamp);
const sha = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => sha(bytes).toString('hex');
const leaf = sha(Buffer.concat([Buffer.from([0]), Buffer.from(leafText, 'ascii')]));
const joined = (left, right) => sha(Buffer.concat([Buffer.from([1]), left, right]));
const memo = new Map([['1', leaf]]);
function root(size) {
  const key = String(size);
  if (memo.has(key)) return memo.get(key);
  const split = 1n << BigInt((size - 1n).toString(2).length - 1);
  const result = joined(root(split), root(size - split));
  memo.set(key, result);
  return result;
}
function proof(start, end, size, includeRoot = false) {
  if (start === 0n && end === size) return includeRoot ? [root(size)] : [];
  const split = 1n << BigInt((size - 1n).toString(2).length - 1);
  if (end <= split) return [...proof(start, end, split, includeRoot), root(size - split)];
  if (start >= split) return [...proof(start - split, end - split, size - split, includeRoot), root(split)];
  throw new Error('unaligned crossing range');
}
const trees = [];
const cases = [];
for (const size of [2n ** 63n, 2n ** 63n + 1n, 2n ** 64n - 1n]) {
  const fullRoot = root(size);
  const hashes = proof(0n, 1n, size);
  const signature = sign(null, subtreeInput({ name, origin, end: size, root: fullRoot, timestamp }),
    { key: privateKey, context: Buffer.alloc(0) });
  if (signature.length !== 4627) throw new Error('unexpected signature length');
  const note = Buffer.from(`${origin}\n${size}\n${fullRoot.toString('base64')}\n\n` +
    `\u2014 ${name} ${Buffer.concat([hint, stamp, signature]).toString('base64')}\n`);
  const treeId = `proof-limit-${size}`;
  trees.push({ id: treeId, size: String(size), rootHex: fullRoot.toString('hex'),
    noteUtf8Hex: note.toString('hex'), noteBytes: note.length, noteSha256: hex(note) });
  const mutations = hashes.length === 63 ? [null, 'bad-proof-byte'] : [null];
  for (const mutation of mutations) {
    const nodes = hashes.map(value => Buffer.from(value));
    if (mutation) nodes[0][0] ^= 1;
    const prefix = Buffer.from(`subtree 0 1\n${leaf.toString('base64')}\n` +
      nodes.map(value => `${value.toString('base64')}\n`).join('') + '\n');
    const wire = Buffer.concat([prefix, note]);
    cases.push({ id: `${treeId}${mutation ? `-${mutation}` : ''}`, tree: treeId,
      start: '0', end: '1', mutation, subtreeHashHex: leaf.toString('hex'),
      proofHex: nodes.map(value => value.toString('hex')),
      requestPrefixUtf8Hex: prefix.toString('hex'), wireBytes: wire.length,
      wireSha256: hex(wire), expected: mutation ? 'SUBTREE_PROOF' :
        hashes.length === 63 ? 'VALID' : 'SUBTREE_REQUEST' });
  }
}
const vector = { schemaVersion: 1, wireProfile: 'C2SP-20261007-MLDSA87-v2',
  selectedProofRule: 'MTC draft-07 Section 4.4.3', maxTransportProofLines: 63,
  virtualLeafAscii: leafText, sourceLiveVectorSha256: hex(sourceBytes),
  witness: { name, spkiSha256: hex(spki), keyHintHex: hint.toString('hex'),
    timestamp: Number(timestamp), at: source.witness.at },
  checkpointOrigin: origin, trees, cases };
writeFileSync(new URL('../vectors/subtree-proof-limit.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log(JSON.stringify({ trees: trees.length, cases: cases.length,
  proofCounts: cases.map(value => value.proofHex.length),
  wireBytes: cases.map(value => value.wireBytes) }));
