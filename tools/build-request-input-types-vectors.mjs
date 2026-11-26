import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const transport = JSON.parse(readFileSync(join(root, 'vectors/transport.json')));
const wire = transport.cases.find(item => item.id === 'one-witness-request').wire;
const bytes = Buffer.from(wire, 'utf8');
const cases = [
  { id: 'request-type-bigint-start', field: 'start', inputType: 'bigint', value: '0', expected: 'VALID' },
  { id: 'request-type-safe-number-end', field: 'end', inputType: 'number', value: 3, expected: 'VALID' },
  { id: 'request-type-canonical-string-end', field: 'end', inputType: 'string', value: '3', expected: 'VALID' },
  { id: 'request-type-array-start', field: 'start', inputType: 'array', value: [0], expected: 'SUBTREE_RANGE' },
  { id: 'request-type-array-end', field: 'end', inputType: 'array', value: [3], expected: 'SUBTREE_RANGE' },
  { id: 'request-type-object-start', field: 'start', inputType: 'object-stringifier', value: '0', expected: 'SUBTREE_RANGE' },
  { id: 'request-type-object-end', field: 'end', inputType: 'object-stringifier', value: '3', expected: 'SUBTREE_RANGE' },
].map(item => ({ ...item, byteVector: item.expected === 'VALID' ? 'accepted:canonicalWireHex' : 'forbidden:canonicalWireHex' }));
const vectors = {
  schemaVersion: 1,
  profile: 'C2SP-20261007-MLDSA87-v2',
  sourceCase: 'vectors/transport.json#one-witness-request',
  canonicalWireHex: bytes.toString('hex'),
  canonicalWireSha256: createHash('sha256').update(bytes).digest('hex'),
  baseRange: { start: '0', end: '3' },
  cases,
};
writeFileSync(join(root, 'vectors/request-input-types.json'), JSON.stringify(vectors, null, 2) + '\n');
