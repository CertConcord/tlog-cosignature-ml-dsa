import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sparse = JSON.parse(readFileSync(join(root, 'vectors/sparse-proof.json')));
const one = sparse.wires.one;
const wire = Buffer.from(one.hex, 'hex');
if (createHash('sha256').update(wire).digest('hex') !== one.sha256) throw new Error('source wire hash');
const original = Buffer.from(wire.toString('utf8').split('\n')[1], 'base64');
if (original.length !== 32) throw new Error('source root length');
const roots = {
  original: original.toString('hex'),
  short: Buffer.alloc(16, 0x5a).toString('hex'),
  long: Buffer.alloc(48, 0x5a).toString('hex'),
};
const vectors = {
  schemaVersion: 1,
  profile: sparse.profile,
  sourceCase: 'vectors/sparse-proof.json#wires.one',
  roots,
  wires: { one },
  cases: [
    { id: 'root-buffer-plain', root: 'original', decoration: 'none', expected: 'VALID', wire: 'one' },
    { id: 'root-buffer-shadow-length-16', root: 'original', decoration: 'length-16', expected: 'VALID', wire: 'one' },
    { id: 'root-buffer-shadow-length-throws', root: 'original', decoration: 'length-throws', expected: 'VALID', wire: 'one' },
    { id: 'root-buffer-shadow-byte-length-throws', root: 'original', decoration: 'byte-length-throws', expected: 'VALID', wire: 'one' },
    { id: 'root-buffer-native-short-spoof', root: 'short', decoration: 'length-32', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'root-buffer-native-long-spoof', root: 'long', decoration: 'length-32', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'root-buffer-uint16-buffer-prototype', root: 'original', decoration: 'uint16-buffer-prototype', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'root-buffer-uint32-buffer-prototype', root: 'original', decoration: 'uint32-buffer-prototype', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'root-buffer-proxy', root: 'original', decoration: 'proxy', expected: 'SUBTREE_REQUEST', noWire: true },
    { id: 'root-buffer-revoked-proxy', root: 'original', decoration: 'revoked-proxy', expected: 'SUBTREE_REQUEST', noWire: true },
  ],
};
writeFileSync(join(root, 'vectors/root-buffer.json'), JSON.stringify(vectors, null, 2) + '\n');
