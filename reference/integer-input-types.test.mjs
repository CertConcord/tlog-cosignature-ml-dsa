import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { subtreeInput } from './extension.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/integer-input-types.json', import.meta.url)));

for (const item of vectors.cases) {
  test(item.id, () => {
    const context = {
      name: vectors.context.name,
      origin: vectors.context.origin,
      root: Buffer.from(vectors.context.rootHex, 'hex'),
      start: BigInt(item.base.start),
      end: BigInt(item.base.end),
      timestamp: BigInt(item.base.timestamp),
    };
    context[item.field] = item.inputType === 'bigint' ? BigInt(item.value) : item.value;
    if (item.expected === 'VALID') {
      assert.equal(subtreeInput(context).toString('hex'), item.inputHex);
    } else {
      assert.equal(BigInt(item.value), BigInt(item.base[item.field]));
      assert.throws(() => subtreeInput(context), { code: item.expected });
    }
  });
}
