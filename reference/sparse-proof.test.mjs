import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { encodeSubtreeRequest, parseSubtreeRequest } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/sparse-proof.json', import.meta.url)));
const source = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url)));
const sourceWire = source.cases.find(item => item.id === 'one-witness-request').wire;
const base = parseSubtreeRequest(sourceWire);
const digest = wire => createHash('sha256').update(wire).digest('hex');

for (const [name, vector] of Object.entries(vectors.wires)) {
  test('frozen proof wire bytes: ' + name, () => {
    const bytes = Buffer.from(vector.hex, 'hex');
    assert.equal(bytes.toString('hex'), vector.hex);
    assert.equal(digest(bytes), vector.sha256);
    if (name === 'short') assert.throws(() => parseSubtreeRequest(bytes.toString('utf8')), { code: 'SUBTREE_REQUEST' });
    else assert.equal(parseSubtreeRequest(bytes.toString('utf8')).proof.length, name === 'empty' ? 0 : name === 'one' ? 1 : 2);
  });
}

for (const item of vectors.cases) {
  test(item.id, () => {
    const proof = new Array(item.length);
    if (item.slotKind === 'accessor-changing') {
      let reads = 0;
      Object.defineProperty(proof, '0', { enumerable: true, get() {
        return ++reads <= 2 ? Buffer.from(vectors.hashes.a, 'hex') : Buffer.from(vectors.hashes.short, 'hex');
      } });
    } else {
      for (const entry of item.entries) proof[entry.index] = Buffer.from(vectors.hashes[entry.hash], 'hex');
    }
    const request = { ...base, proof };
    if (item.expected === 'VALID') {
      const wire = encodeSubtreeRequest(request);
      assert.equal(Buffer.from(wire).toString('hex'), vectors.wires[item.wire].hex);
      assert.equal(digest(wire), vectors.wires[item.wire].sha256);
    } else {
      assert.equal(item.expected, 'SUBTREE_REQUEST');
      const cut = sourceWire.indexOf('\n\n');
      const discardedHoleWire = sourceWire.slice(0, cut) + item.entries.map(entry => '\n' + Buffer.from(vectors.hashes[entry.hash], 'hex').toString('base64')).join('') + sourceWire.slice(cut);
      assert.equal(Buffer.from(discardedHoleWire).toString('hex'), vectors.wires[item.forbiddenWire].hex);
      assert.throws(() => encodeSubtreeRequest(request), { code: item.expected });
    }
  });
}
