import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// This generator constructs signed bytes without importing the reference encoder.
const output = fileURLToPath(new URL('../vectors/integer-boundaries.json', import.meta.url));
const name = 'w';
const origin = 'o';
const root = Buffer.alloc(32);
const u64 = value => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
};
const encode = ({ start, end, timestamp }) => Buffer.concat([
  Buffer.from('subtree/v1\n\0'),
  Buffer.from([1]), Buffer.from(name),
  u64(timestamp),
  Buffer.from([1]), Buffer.from(origin),
  u64(start), u64(end), root,
]).toString('hex');

const inputs = [
  { field: 'start', start: '9007199254740993', end: '9007199254740994', timestamp: '0' },
  { field: 'end', start: '0', end: '9007199254740993', timestamp: '0' },
  { field: 'timestamp', start: '0', end: '1', timestamp: '9007199254740993' },
];
const cases = [
  ...inputs.map(input => ({
    id: `integer-${input.field}-exact`,
    ...input,
    numericType: 'bigint',
    expected: 'VALID',
    inputHex: encode(input),
  })),
  {
    id: 'integer-end-safe-number',
    field: 'end',
    start: '0',
    end: '9007199254740991',
    timestamp: '0',
    numericType: 'number',
    expected: 'VALID',
    inputHex: encode({ start: '0', end: '9007199254740991', timestamp: '0' }),
  },
  ...inputs.map(input => {
    const roundedNumber = String(Number(input[input.field]));
    return {
      id: `integer-${input.field}-unsafe-number`,
      ...input,
      numericType: 'number',
      expected: 'SUBTREE_INTEGER',
      roundedNumber,
      forbiddenInputHex: encode({ ...input, [input.field]: roundedNumber }),
    };
  }),
];

writeFileSync(output, JSON.stringify({
  schemaVersion: 1,
  profile: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  context: { name, origin, rootHex: root.toString('hex') },
  cases,
}, null, 2) + '\n');
