import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = JSON.parse(readFileSync(join(root, 'vectors/transport.json')));
const base = source.cases.find(item => item.id === 'one-witness-request').wire;
const cut = base.indexOf('\n\n');
if (cut < 0) throw new Error('source request has no proof separator');
const hashA = Buffer.alloc(32, 0x5a);
const hashB = Buffer.alloc(32, 0xa5);
const shortHash = Buffer.alloc(16, 0x5a);
const withProof = hashes => base.slice(0, cut) + hashes.map(hash => '\n' + hash.toString('base64')).join('') + base.slice(cut);
const encode = wire => ({ hex: Buffer.from(wire).toString('hex'), sha256: createHash('sha256').update(wire).digest('hex') });
const emptyWire = encode(base);
const oneWire = encode(withProof([hashA]));
const twoWire = encode(withProof([hashA, hashB]));
const shortWire = encode(withProof([shortHash]));
const vectors = {
  schemaVersion: 1,
  profile: source.wireProfile,
  sourceCase: 'vectors/transport.json#one-witness-request',
  hashes: { a: hashA.toString('hex'), b: hashB.toString('hex'), short: shortHash.toString('hex') },
  wires: { empty: emptyWire, one: oneWire, two: twoWire, short: shortWire },
  cases: [
    { id: 'proof-dense-empty', length: 0, entries: [], expected: 'VALID', wire: 'empty' },
    { id: 'proof-dense-one', length: 1, entries: [{ index: 0, hash: 'a' }], expected: 'VALID', wire: 'one' },
    { id: 'proof-sparse-one', length: 1, entries: [], expected: 'SUBTREE_REQUEST', emittedHashes: [], forbiddenWire: 'empty' },
    { id: 'proof-sparse-middle', length: 3, entries: [{ index: 0, hash: 'a' }, { index: 2, hash: 'b' }], expected: 'SUBTREE_REQUEST', emittedHashes: ['a', 'b'], forbiddenWire: 'two' },
    { id: 'proof-accessor-changing', length: 1, entries: [{ index: 0, hash: 'short' }], slotKind: 'accessor-changing', expected: 'SUBTREE_REQUEST', emittedHashes: ['short'], forbiddenWire: 'short' },
    { id: 'proof-proxy-length-flip', length: 1, entries: [{ index: 0, hash: 'a' }], slotKind: 'proxy-length-flip', expected: 'SUBTREE_REQUEST', emittedHashes: [], forbiddenWire: 'empty' },
    { id: 'proof-proxy-transparent', length: 1, entries: [{ index: 0, hash: 'a' }], slotKind: 'proxy-transparent', expected: 'SUBTREE_REQUEST', emittedHashes: ['a'], forbiddenWire: 'one' },
    { id: 'proof-proxy-revoked', length: 1, entries: [{ index: 0, hash: 'a' }], slotKind: 'proxy-revoked', expected: 'SUBTREE_REQUEST', emittedHashes: ['a'], forbiddenWire: 'one' },
  ],
};
writeFileSync(join(root, 'vectors/sparse-proof.json'), JSON.stringify(vectors, null, 2) + '\n');
