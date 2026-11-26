import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { subtreeInput } from './extension.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/integer-boundaries.json', import.meta.url)));
const exact = new Map(vectors.cases.filter(item => item.numericType === 'bigint').map(item => [item.field, item]));

for (const item of vectors.cases) {
  test(`exact uint64 input: ${item.id}`, () => {
    const context = {
      name: vectors.context.name,
      origin: vectors.context.origin,
      root: Buffer.from(vectors.context.rootHex, 'hex'),
      start: BigInt(item.start),
      end: BigInt(item.end),
      timestamp: BigInt(item.timestamp),
    };
    if (item.numericType === 'number') {
      context[item.field] = Number(item[item.field]);
      if (item.expected === 'VALID') {
        assert.equal(subtreeInput(context).toString('hex'), item.inputHex);
      } else {
        assert.equal(String(context[item.field]), item.roundedNumber);
        assert.notEqual(item.forbiddenInputHex, exact.get(item.field).inputHex);
        assert.throws(() => subtreeInput(context), { code: item.expected });
      }
    } else {
      assert.equal(subtreeInput(context).toString('hex'), item.inputHex);
    }
  });
}
