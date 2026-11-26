import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parseCheckpointEnvelope, verifySubtreeCheckpoint } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/standalone-checkpoint-bound.json', import.meta.url), 'utf8'));
const transport = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url), 'utf8'));
const source = Buffer.from(transport.cases.find(item => item.id === 'one-witness-request').wire, 'utf8');
assert.equal(createHash('sha256').update(source).digest('hex'), vectors.sourceRequestSha256);
const separator = source.indexOf(Buffer.from('\n\n'));
const checkpoint = source.subarray(separator + 2);
assert.equal(createHash('sha256').update(checkpoint).digest('hex'), vectors.sourceCheckpointSha256);
const witness = {
  name: transport.witness.name,
  publicKey: createPublicKey({ key: Buffer.from(transport.witness.spki, 'hex'), format: 'der', type: 'spki' }),
  at: transport.at,
};

function wireBytes(item) {
  const lines = Array.from(
    { length: item.extraCount },
    (_, index) => `— ${item.namePrefix}${index} ${item.payloadBase64}\n`,
  ).join('');
  return Buffer.concat([checkpoint, Buffer.from(lines, 'utf8')]);
}

for (const item of vectors.cases) {
  test('standalone checkpoint signature bound: ' + item.id, () => {
    const bytes = wireBytes(item);
    assert.equal(bytes.length, item.wireLength);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), item.wireSha256);
    const note = bytes.toString('utf8');
    const original = Buffer.from;
    let base64Decodes = 0;
    Buffer.from = function (...args) {
      if (args[1] === 'base64') base64Decodes++;
      return original.apply(Buffer, args);
    };
    try {
      if (item.expected === 'VALID') {
        const parsed = item.operation === 'verify'
          ? verifySubtreeCheckpoint(note, witness)
          : parseCheckpointEnvelope(note);
        assert.equal(parsed.signatures.length, item.signatureLineCount);
      } else {
        assert.throws(() => verifySubtreeCheckpoint(note, witness), { code: item.expected });
      }
    } finally {
      Buffer.from = original;
    }
    assert.equal(base64Decodes, item.expectedBase64Decodes);
  });
}
