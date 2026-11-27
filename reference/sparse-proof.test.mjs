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
    let proof = new Array(item.length);
    if (item.slotKind === 'accessor-changing') {
      let reads = 0;
      Object.defineProperty(proof, '0', { enumerable: true, get() {
        return ++reads <= 2 ? Buffer.from(vectors.hashes.a, 'hex') : Buffer.from(vectors.hashes.short, 'hex');
      } });
    } else {
      for (const entry of item.entries) proof[entry.index] = Buffer.from(vectors.hashes[entry.hash], 'hex');
    }
    if (item.slotKind === 'proxy-length-flip') {
      let reads = 0;
      proof = new Proxy(proof, { get(target, property, receiver) {
        if (property === 'length') return ++reads === 1 ? item.length : 0;
        return Reflect.get(target, property, receiver);
      } });
    } else if (item.slotKind === 'proxy-transparent') {
      proof = new Proxy(proof, {});
    } else if (item.slotKind === 'proxy-revoked') {
      const wrapped = Proxy.revocable(proof, {});
      wrapped.revoke();
      proof = wrapped.proxy;
    }
    const request = { ...base, proof };
    if (item.expected === 'VALID') {
      const wire = encodeSubtreeRequest(request);
      assert.equal(Buffer.from(wire).toString('hex'), vectors.wires[item.wire].hex);
      assert.equal(digest(wire), vectors.wires[item.wire].sha256);
    } else {
      assert.equal(item.expected, 'SUBTREE_REQUEST');
      const cut = sourceWire.indexOf('\n\n');
      if (item.slotKind === 'proxy-revoked') {
        assert.deepEqual(item.previousOutcome, { kind: 'error', name: 'TypeError', wire: null });
        assert.throws(() => Array.isArray(proof), TypeError);
        const comparisonWire = sourceWire.slice(0, cut) + item.entries.map(entry => '\n' + Buffer.from(vectors.hashes[entry.hash], 'hex').toString('base64')).join('') + sourceWire.slice(cut);
        assert.equal(Buffer.from(comparisonWire).toString('hex'), vectors.wires[item.comparisonWire].hex);
      } else {
        const forbiddenWire = sourceWire.slice(0, cut) + item.emittedHashes.map(hash => '\n' + Buffer.from(vectors.hashes[hash], 'hex').toString('base64')).join('') + sourceWire.slice(cut);
        assert.equal(Buffer.from(forbiddenWire).toString('hex'), vectors.wires[item.forbiddenWire].hex);
      }
      assert.throws(() => encodeSubtreeRequest(request), { code: item.expected });
    }
  });
}
