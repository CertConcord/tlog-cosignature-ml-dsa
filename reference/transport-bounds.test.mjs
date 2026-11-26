import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parseCheckpointEnvelope, parseSubtreeRequest } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/transport-bounds.json', import.meta.url), 'utf8'));
const transport = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url), 'utf8'));
const base = Buffer.from(transport.cases.find(item => item.id === 'one-witness-request').wire, 'utf8');
assert.equal(createHash('sha256').update(base).digest('hex'), vectors.sourceWireSha256);
const cut = base.indexOf(Buffer.from('\n\n'));
const checkpoint = base.subarray(cut + 2);

function bytesFor(item) {
  if (item.target === 'max-prefix') {
    const first = checkpoint.indexOf(0x0a), second = checkpoint.indexOf(0x0a, first + 1);
    const maxCheckpoint = Buffer.concat([checkpoint.subarray(0, first + 1), Buffer.from('18446744073709551615'), checkpoint.subarray(second)]);
    const rootLine = base.subarray(base.indexOf(0x0a) + 1, cut);
    const proof = Buffer.from(item.proofHashHex, 'hex').toString('base64') + '\n';
    return Buffer.concat([Buffer.from('subtree 18446744073709551614 18446744073709551615\n'), rootLine, Buffer.from('\n' + proof.repeat(63) + '\n'), maxCheckpoint]);
  }
  if (item.target === 'proof-count') {
    const line = Buffer.from(item.proofHashHex, 'hex').toString('base64') + '\n';
    return Buffer.concat([base.subarray(0, cut), Buffer.from('\n' + line.repeat(item.proofCount) + '\n'), checkpoint]);
  }
  const value = item.repeatByteHex
    ? Buffer.alloc(item.repeat, Number.parseInt(item.repeatByteHex, 16))
    : Buffer.from(item.decimalAsciiHex, 'hex');
  if (item.target === 'checkpoint-size') {
    const first = checkpoint.indexOf(0x0a), second = checkpoint.indexOf(0x0a, first + 1);
    return Buffer.concat([checkpoint.subarray(0, first + 1), value, checkpoint.subarray(second)]);
  }
  if (item.target === 'request-start') {
    const first = base.indexOf(0x0a);
    return Buffer.concat([Buffer.from('subtree '), value, Buffer.from(' 3\n'), base.subarray(first + 1)]);
  }
  return base;
}

for (const item of vectors.cases) {
  test(item.id, () => {
    const bytes = bytesFor(item);
    assert.equal(bytes.length, item.wireLength);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), item.wireSha256);
    const parse = () => item.target === 'checkpoint-size'
      ? parseCheckpointEnvelope(bytes.toString('utf8'))
      : parseSubtreeRequest(bytes.toString('utf8'));
    if (item.expected === 'VALID') {
      const parsed = parse();
      if (item.target === 'checkpoint-size') assert.equal(parsed.size, 0xffffffffffffffffn);
      else {
        assert.equal(parsed.start, item.target === 'max-prefix' ? 0xfffffffffffffffen : 0n);
        assert.equal(parsed.end, item.target === 'max-prefix' ? 0xffffffffffffffffn : 3n);
        if (item.target === 'proof-count' || item.target === 'max-prefix') assert.equal(parsed.proof.length, item.proofCount ?? 63);
        if (item.target === 'max-prefix') {
          assert.equal(parsed.checkpoint.split('\n\n', 1)[0].split('\n')[1], '18446744073709551615');
          assert.equal(bytes.toString('utf8').indexOf('\n\n'), 2929);
        }
      }
      return;
    }
    if (item.noBufferFrom) {
      const original = Buffer.from;
      Buffer.from = () => { throw new Error('BUFFER_FROM_INVOKED'); };
      try { assert.throws(parse, { code: item.expected }); }
      finally { Buffer.from = original; }
    } else if (item.noBigInt) {
      const original = globalThis.BigInt;
      globalThis.BigInt = () => { throw new Error('BIGINT_INVOKED'); };
      try { assert.throws(parse, { code: item.expected }); }
      finally { globalThis.BigInt = original; }
    } else assert.throws(parse, { code: item.expected });
  });
}
