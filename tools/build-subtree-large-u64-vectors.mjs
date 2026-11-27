// Build original large-tree request bytes using one repeated test leaf.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { mlDsa87KeyID, subtreeInput } from '../reference/extension.mjs';

const root = new URL('../', import.meta.url);
const sourceBytes = readFileSync(new URL('vectors/subtree-live-sign.json', root));
const source = JSON.parse(sourceBytes);
const name = source.witness.name;
const key = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const privateKey = createPrivateKey({ key: Buffer.from(source.witness.pkcs8Hex, 'hex'), type: 'pkcs8', format: 'der' });
const sha = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => sha(bytes).toString('hex');
const leaf = Buffer.from('certconcord-large-u64-leaf-v1', 'ascii');
const leafHash = sha(Buffer.concat([Buffer.from([0]), leaf]));
const joined = (left, right) => sha(Buffer.concat([Buffer.from([1]), left, right]));
const memo = new Map([['1', leafHash]]);
function treeHash(size) {
  if (size === 0n) return sha(Buffer.alloc(0));
  const cached = memo.get(String(size));
  if (cached) return cached;
  const split = 1n << BigInt((size - 1n).toString(2).length - 1);
  const result = joined(treeHash(split), treeHash(size - split));
  memo.set(String(size), result);
  return result;
}
function proof(start, end, size, includeRoot = false) {
  if (start === end) return [];
  if (start === 0n && end === size) return includeRoot ? [treeHash(size)] : [];
  const split = 1n << BigInt((size - 1n).toString(2).length - 1);
  if (end <= split) return [...proof(start, end, split, includeRoot), treeHash(size - split)];
  if (start >= split) return [...proof(start - split, end - split, size - split, includeRoot), treeHash(split)];
  if (start !== 0n) throw new Error('unaligned crossing range');
  return [...proof(0n, end - split, size - split, true), treeHash(split)];
}
const origin = 'log.example/large-u64';
const timestamp = 1700000000n;
const timestampBytes = Buffer.alloc(8);
timestampBytes.writeBigUInt64BE(timestamp);
const hint = mlDsa87KeyID(name, key);
const trees = [];
const cases = [];
const sizes = [
  [281474959937536n, 4096n],
  [9223372034707324928n, 32768n],
  [18446744069414649856n, 65536n],
];
for (const [size, tailWidth] of sizes) {
  const rootHash = treeHash(size);
  const signature = sign(null, subtreeInput({ name, origin, end: size, root: rootHash, timestamp }),
    { key: privateKey, context: Buffer.alloc(0) });
  if (signature.length !== 4627) throw new Error('unexpected signature length');
  const note = Buffer.from(`${origin}\n${size}\n${rootHash.toString('base64')}\n\n` +
    `\u2014 ${name} ${Buffer.concat([hint, timestampBytes, signature]).toString('base64')}\n`);
  const treeId = `large-u64-${size}`;
  trees.push({ id: treeId, size: String(size), rootHex: rootHash.toString('hex'),
    noteUtf8Hex: note.toString('hex'), noteBytes: note.length, noteSha256: hex(note) });
  const ranges = [
    ['full', 0n, size],
    ['tail', size - tailWidth, size],
    ['last', size - 1n, size],
  ];
  for (const [label, start, end] of ranges) {
    const expectedRoot = treeHash(end - start);
    const expectedProof = proof(start, end, size);
    for (const mutation of [null, ...(label === 'last' ? ['bad-root', 'bad-proof'] : [])]) {
      const subtreeRoot = Buffer.from(expectedRoot);
      const nodes = expectedProof.map(value => Buffer.from(value));
      if (mutation === 'bad-root') subtreeRoot[0] ^= 1;
      if (mutation === 'bad-proof') nodes[0][0] ^= 1;
      const prefix = Buffer.from(`subtree ${start} ${end}\n${subtreeRoot.toString('base64')}\n` +
        nodes.map(value => `${value.toString('base64')}\n`).join('') + '\n');
      const wire = Buffer.concat([prefix, note]);
      cases.push({ id: `${treeId}-${label}${mutation ? `-${mutation}` : ''}`, tree: treeId,
        start: String(start), end: String(end), mutation,
        subtreeHashHex: subtreeRoot.toString('hex'), proofHex: nodes.map(value => value.toString('hex')),
        requestPrefixUtf8Hex: prefix.toString('hex'), wireBytes: wire.length,
        wireSha256: hex(wire), expected: mutation ? 'SUBTREE_PROOF' : 'VALID' });
    }
  }
}
const vector = { schemaVersion: 1, wireProfile: 'C2SP-20261007-MLDSA87-v2',
  upstreamRangeShape: { editorCommit: '44b1c0b8c54669a35e8d9e96f0e55bb3cab67757',
    path: 'demo/large_consistency_proofs.json',
    sha256: '7fcc6d9d0283ecf7d19e221049f477964dfbf048ef43601a640a8c5a62e47d9f' },
  virtualLeafAscii: leaf.toString('ascii'), sourceLiveVectorSha256: hex(sourceBytes),
  witness: { name, spkiSha256: hex(Buffer.from(source.witness.spkiHex, 'hex')),
    keyHintHex: hint.toString('hex'), timestamp: Number(timestamp), at: source.witness.at },
  checkpointOrigin: origin, trees, cases };
writeFileSync(new URL('vectors/subtree-large-u64.json', root), `${JSON.stringify(vector, null, 2)}\n`);
console.log(JSON.stringify({ trees: trees.length, cases: cases.length,
  proofCounts: cases.filter(value => value.mutation === null).map(value => value.proofHex.length),
  largestWire: Math.max(...cases.map(value => value.wireBytes)) }));
