import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const transport = JSON.parse(readFileSync(join(root, 'vectors/transport.json'), 'utf8'));
const base = Buffer.from(transport.cases.find(item => item.id === 'one-witness-request').wire, 'utf8');
const separator = base.indexOf(Buffer.from('\n\n'));
const checkpoint = base.subarray(separator + 2);
const checkpointLines = checkpoint.toString('utf8').split('\n');
if (checkpointLines[1] !== '3') throw new Error('Unexpected checkpoint size');

const valueBytes = item => item.repeatByteHex
  ? Buffer.alloc(item.repeat, Number.parseInt(item.repeatByteHex, 16))
  : Buffer.from(item.decimalAsciiHex, 'hex');
function wireBytes(item) {
  if (item.target === 'checkpoint-signature-count') {
    const noteCut = checkpoint.indexOf(Buffer.from('\n\n'));
    const noteHead = checkpoint.subarray(0, noteCut + 2);
    const lines = Array.from({ length: item.signatureCount }, (_, index) => `— ${item.namePrefix}${index} ${item.payloadBase64}\n`).join('');
    return Buffer.concat([base.subarray(0, separator + 2), noteHead, Buffer.from(lines)]);
  }
  if (item.target === 'max-prefix') {
    const first = checkpoint.indexOf(0x0a), second = checkpoint.indexOf(0x0a, first + 1);
    const maxCheckpoint = Buffer.concat([checkpoint.subarray(0, first + 1), Buffer.from('18446744073709551615'), checkpoint.subarray(second)]);
    const rootLine = base.subarray(base.indexOf(0x0a) + 1, separator);
    const proof = Buffer.from(item.proofHashHex, 'hex').toString('base64') + '\n';
    const range = Buffer.from('subtree 18446744073709551614 18446744073709551615\n');
    return Buffer.concat([range, rootLine, Buffer.from('\n' + proof.repeat(63) + '\n'), maxCheckpoint]);
  }
  if (item.target === 'proof-count') {
    const line = Buffer.from(item.proofHashHex, 'hex').toString('base64') + '\n';
    return Buffer.concat([base.subarray(0, separator), Buffer.from('\n' + line.repeat(item.proofCount) + '\n'), checkpoint]);
  }
  const value = valueBytes(item);
  if (item.target === 'checkpoint-size') {
    const first = checkpoint.indexOf(0x0a), second = checkpoint.indexOf(0x0a, first + 1);
    return Buffer.concat([checkpoint.subarray(0, first + 1), value, checkpoint.subarray(second)]);
  }
  if (item.target === 'request-start') {
    const first = base.indexOf(0x0a);
    return Buffer.concat([Buffer.from('subtree '), value, Buffer.from(' 3\n'), base.subarray(first + 1)]);
  }
  if (item.target === 'request-range') return base;
  throw new Error('Unknown target');
}
const cases = [
  { id: 'decimal-checkpoint-max-u64', target: 'checkpoint-size', decimalAsciiHex: Buffer.from('18446744073709551615').toString('hex'), expected: 'VALID' },
  { id: 'decimal-checkpoint-over-u64', target: 'checkpoint-size', decimalAsciiHex: Buffer.from('18446744073709551616').toString('hex'), expected: 'SUBTREE_RANGE' },
  { id: 'decimal-checkpoint-21-digits', target: 'checkpoint-size', decimalAsciiHex: Buffer.from('100000000000000000000').toString('hex'), expected: 'SUBTREE_RANGE', noBigInt: true },
  { id: 'decimal-checkpoint-million-digits', target: 'checkpoint-size', repeatByteHex: '39', repeat: 1000000, expected: 'SUBTREE_RANGE', noBigInt: true },
  { id: 'decimal-request-canonical', target: 'request-range', decimalAsciiHex: Buffer.from('0 3').toString('hex'), expected: 'VALID' },
  { id: 'decimal-request-start-over-u64', target: 'request-start', decimalAsciiHex: Buffer.from('18446744073709551616').toString('hex'), expected: 'SUBTREE_RANGE' },
  { id: 'decimal-request-start-21-digits', target: 'request-start', decimalAsciiHex: Buffer.from('100000000000000000000').toString('hex'), expected: 'SUBTREE_RANGE' },
  { id: 'decimal-request-start-million-digits', target: 'request-start', repeatByteHex: '39', repeat: 1000000, expected: 'SUBTREE_RANGE', noBigInt: true },
  { id: 'proof-count-63', target: 'proof-count', proofHashHex: '00'.repeat(32), proofCount: 63, expected: 'VALID' },
  { id: 'proof-count-64', target: 'proof-count', proofHashHex: '00'.repeat(32), proofCount: 64, expected: 'SUBTREE_REQUEST' },
  { id: 'proof-count-10000', target: 'proof-count', proofHashHex: '00'.repeat(32), proofCount: 10000, expected: 'SUBTREE_REQUEST', noBufferFrom: true },
  { id: 'proof-prefix-max-2929', target: 'max-prefix', proofHashHex: '00'.repeat(32), expected: 'VALID' },
  { id: 'checkpoint-signatures-10000', target: 'checkpoint-signature-count', signatureCount: 10000, namePrefix: 'w', payloadBase64: 'AAAAAAA=', expected: 'SUBTREE_ONE_WITNESS', noBufferFrom: true },
].map(item => {
  const bytes = wireBytes(item);
  return { ...item, wireLength: bytes.length, wireSha256: createHash('sha256').update(bytes).digest('hex') };
});
writeFileSync(join(root, 'vectors/transport-bounds.json'), JSON.stringify({
  schemaVersion: 1,
  profile: 'C2SP-20261007-MLDSA87-v2',
  sourceCase: 'vectors/transport.json#one-witness-request',
  sourceWireSha256: createHash('sha256').update(base).digest('hex'),
  encoding: 'decimalAsciiHex or repeatByteHex plus repeat gives exact replacement bytes',
  cases,
}, null, 2) + '\n');
