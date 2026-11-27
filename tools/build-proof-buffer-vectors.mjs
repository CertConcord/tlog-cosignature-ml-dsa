import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sparse = JSON.parse(readFileSync(join(root, 'vectors/sparse-proof.json')));
const one = sparse.wires.one;
const wire = Buffer.from(one.hex, 'hex');
if (createHash('sha256').update(wire).digest('hex') !== one.sha256) throw new Error('source wire hash');
const hashes = {
  a: sparse.hashes.a,
  short: Buffer.alloc(16, 0x5a).toString('hex'),
  long: Buffer.alloc(48, 0x5a).toString('hex'),
};
const vectors = {
  schemaVersion: 1,
  profile: sparse.profile,
  sourceCase: 'vectors/sparse-proof.json#wires.one',
  hashes,
  wires: { one },
  cases: [
    { id: 'proof-buffer-plain', hash: 'a', decoration: 'none', expected: 'VALID', wire: 'one' },
    { id: 'proof-buffer-shadow-length-16', hash: 'a', decoration: 'length-16', expected: 'VALID', wire: 'one' },
    { id: 'proof-buffer-shadow-length-throws', hash: 'a', decoration: 'length-throws', expected: 'VALID', wire: 'one' },
    { id: 'proof-buffer-shadow-byte-length-throws', hash: 'a', decoration: 'byte-length-throws', expected: 'VALID', wire: 'one' },
    { id: 'proof-buffer-native-short-spoof', hash: 'short', decoration: 'length-32', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'proof-buffer-native-long-spoof', hash: 'long', decoration: 'length-32', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'proof-buffer-proxy', hash: 'a', decoration: 'proxy', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'proof-buffer-revoked-proxy', hash: 'a', decoration: 'revoked-proxy', expected: 'SUBTREE_REQUEST', noWire: true },
  ],
};
writeFileSync(join(root, 'vectors/proof-buffer.json'), JSON.stringify(vectors, null, 2) + '\n');
