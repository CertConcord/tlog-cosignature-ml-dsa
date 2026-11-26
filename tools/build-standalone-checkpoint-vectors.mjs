import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const transport = JSON.parse(readFileSync(join(root, 'vectors/transport.json'), 'utf8'));
const request = Buffer.from(transport.cases.find(item => item.id === 'one-witness-request').wire, 'utf8');
const separator = request.indexOf(Buffer.from('\n\n'));
if (separator < 0) throw new Error('Missing request/checkpoint separator');
const checkpoint = request.subarray(separator + 2);
const hash = value => createHash('sha256').update(value).digest('hex');

function wireBytes(item) {
  const lines = Array.from(
    { length: item.extraCount },
    (_, index) => `— ${item.namePrefix}${index} ${item.payloadBase64}\n`,
  ).join('');
  return Buffer.concat([checkpoint, Buffer.from(lines, 'utf8')]);
}

const cases = [
  { id: 'standalone-one-witness', operation: 'verify', extraCount: 0, namePrefix: 'w', payloadBase64: 'AAAAAAA=', expected: 'VALID', expectedBase64Decodes: 2 },
  { id: 'generic-two-signature-note', operation: 'parse', extraCount: 1, namePrefix: 'w', payloadBase64: 'AAAAAAA=', expected: 'VALID', expectedBase64Decodes: 3 },
  { id: 'standalone-two-signature-note', operation: 'verify', extraCount: 1, namePrefix: 'w', payloadBase64: 'AAAAAAA=', expected: 'SUBTREE_ONE_WITNESS', expectedBase64Decodes: 1 },
  { id: 'standalone-10000-signature-note', operation: 'verify', extraCount: 9999, namePrefix: 'w', payloadBase64: 'AAAAAAA=', expected: 'SUBTREE_ONE_WITNESS', expectedBase64Decodes: 1 },
  { id: 'standalone-malformed-extra-signature', operation: 'verify', extraCount: 1, namePrefix: 'w', payloadBase64: '!', expected: 'SUBTREE_ONE_WITNESS', expectedBase64Decodes: 1 },
].map(item => {
  const bytes = wireBytes(item);
  return { ...item, signatureLineCount: item.extraCount + 1, wireLength: bytes.length, wireSha256: hash(bytes) };
});

writeFileSync(join(root, 'vectors/standalone-checkpoint-bound.json'), JSON.stringify({
  schemaVersion: 1,
  profile: transport.wireProfile,
  sourceCase: 'vectors/transport.json#one-witness-request',
  sourceRequestSha256: hash(request),
  sourceCheckpointSha256: hash(checkpoint),
  encoding: 'UTF8(checkpoint) || repeated UTF8("— " + namePrefix + decimal(index) + " " + payloadBase64 + LF)',
  cases,
}, null, 2) + '\n');
