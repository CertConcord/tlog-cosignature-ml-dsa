import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const u64 = n => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(n));
  return out;
};
const input = ({ start, end, timestamp }) => Buffer.concat([
  Buffer.from('subtree/v1\n\0'), Buffer.from([1]), Buffer.from('w'),
  u64(timestamp), Buffer.from([1]), Buffer.from('o'),
  u64(start), u64(end), Buffer.alloc(32),
]).toString('hex');

const raw = [
  { id: 'input-type-bigint-start', field: 'start', base: { start: '1', end: '2', timestamp: '0' }, inputType: 'bigint', value: '1', expected: 'VALID' },
  { id: 'input-type-safe-number-end', field: 'end', base: { start: '0', end: '2', timestamp: '0' }, inputType: 'number', value: 2, expected: 'VALID' },
  { id: 'input-type-safe-number-timestamp', field: 'timestamp', base: { start: '0', end: '1', timestamp: '1' }, inputType: 'number', value: 1, expected: 'VALID' },
  { id: 'input-type-hex-string-start', field: 'start', base: { start: '1', end: '2', timestamp: '0' }, inputType: 'string', value: '0x1', expected: 'SUBTREE_INTEGER' },
  { id: 'input-type-leading-zero-end', field: 'end', base: { start: '0', end: '2', timestamp: '0' }, inputType: 'string', value: '02', expected: 'SUBTREE_INTEGER' },
  { id: 'input-type-boolean-timestamp', field: 'timestamp', base: { start: '0', end: '1', timestamp: '1' }, inputType: 'boolean', value: true, expected: 'SUBTREE_INTEGER' },
  { id: 'input-type-array-timestamp', field: 'timestamp', base: { start: '0', end: '1', timestamp: '0' }, inputType: 'array', value: [], expected: 'SUBTREE_INTEGER' },
];
const vectors = {
  schemaVersion: 1,
  profile: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  context: { name: 'w', origin: 'o', rootHex: Buffer.alloc(32).toString('hex') },
  cases: raw.map(item => ({
    ...item,
    [item.expected === 'VALID' ? 'inputHex' : 'forbiddenInputHex']: input(item.base),
  })),
};
writeFileSync(join(root, 'vectors/integer-input-types.json'), JSON.stringify(vectors, null, 2) + '\n');
