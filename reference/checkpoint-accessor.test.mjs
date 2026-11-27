import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { encodeSubtreeRequest, parseSubtreeRequest } from './transport.mjs';

const fixture = JSON.parse(readFileSync(new URL('../vectors/checkpoint-accessor.json', import.meta.url), 'utf8'));
const transport = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url), 'utf8'));
const wire = transport.cases.find(item => item.id === fixture.sourceCase).wire;
const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');
assert.equal(Buffer.byteLength(wire), fixture.sourceWireBytes);
assert.equal(digest(wire), fixture.sourceWireSha256);
const request = parseSubtreeRequest(wire);
const one = request.checkpoint;
assert.equal(Buffer.byteLength(one), fixture.sourceCheckpointBytes);
assert.equal(digest(one), fixture.sourceCheckpointSha256);
const cut = one.indexOf('\n\n');
const many = one.slice(0, cut + 2) + Array.from({ length: fixture.manySignatureCount }, (_, index) => fixture.manySignatureLine.replace('{index}', String(index))).join('');
assert.equal(Buffer.byteLength(many), fixture.manyCheckpointBytes);
assert.equal(digest(many), fixture.manyCheckpointSha256);

for (const item of fixture.cases) {
  test(item.id, () => {
    let reads = 0;
    const input = {
      ...request,
      get checkpoint() {
        reads++;
        return reads === 1 ? (item.first === 'one' ? one : many) : (item.later === 'one' ? one : many);
      },
    };
    if (item.expected === 'VALID') {
      const output = encodeSubtreeRequest(input);
      assert.equal(Buffer.byteLength(output), item.expectedWireBytes);
      assert.equal(digest(output), item.expectedWireSha256);
      assert.equal(output, wire);
    } else {
      const original = Buffer.from;
      let decoded = false;
      Buffer.from = (...args) => { decoded = true; return original(...args); };
      try { assert.throws(() => encodeSubtreeRequest(input), { code: item.expected }); }
      finally { Buffer.from = original; }
      if (item.noBase64Decode) assert.equal(decoded, false);
    }
    assert.equal(reads, item.getterReads);
  });
}
