import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { encodeSubtreeRequest, parseSubtreeRequest } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/request-input-types.json', import.meta.url)));
const bytes = Buffer.from(vectors.canonicalWireHex, 'hex');
assert.equal(createHash('sha256').update(bytes).digest('hex'), vectors.canonicalWireSha256);
const wire = bytes.toString('utf8');
const base = parseSubtreeRequest(wire);
assert.equal(base.start.toString(), vectors.baseRange.start);
assert.equal(base.end.toString(), vectors.baseRange.end);

function materialize(item) {
  if (item.inputType === 'bigint') return BigInt(item.value);
  if (item.inputType === 'object-stringifier') return { toString: () => item.value };
  return item.value;
}

for (const item of vectors.cases) {
  test(item.id, () => {
    const value = materialize(item);
    const request = { ...base, [item.field]: value };
    if (item.expected === 'VALID') {
      assert.equal(item.byteVector, 'accepted:canonicalWireHex');
      assert.equal(Buffer.from(encodeSubtreeRequest(request)).toString('hex'), vectors.canonicalWireHex);
    } else {
      assert.equal(item.byteVector, 'forbidden:canonicalWireHex');
      assert.equal(String(value), vectors.baseRange[item.field]);
      assert.throws(() => encodeSubtreeRequest(request), { code: item.expected });
    }
  });
}
