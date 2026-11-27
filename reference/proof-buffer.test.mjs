import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { types as utilTypes } from 'node:util';
import { encodeSubtreeRequest, parseSubtreeRequest } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/proof-buffer.json', import.meta.url)));
const sparse = JSON.parse(readFileSync(new URL('../vectors/sparse-proof.json', import.meta.url)));
const one = Buffer.from(vectors.wires.one.hex, 'hex');
const base = parseSubtreeRequest(one.toString('utf8'));
const digest = value => createHash('sha256').update(value).digest('hex');

test('proof Buffer comparison wire is exact', () => {
  assert.equal(vectors.wires.one.hex, sparse.wires.one.hex);
  assert.equal(digest(one), vectors.wires.one.sha256);
  assert.equal(base.proof.length, 1);
  assert.equal(base.proof[0].toString('hex'), vectors.hashes.a);
});

for (const item of vectors.cases) {
  test(item.id, () => {
    let hash = Buffer.from(vectors.hashes[item.hash], 'hex');
    switch (item.decoration) {
      case 'none': break;
      case 'length-16': Object.defineProperty(hash, 'length', { get() { return 16; } }); break;
      case 'length-32': Object.defineProperty(hash, 'length', { get() { return 32; } }); break;
      case 'length-throws': Object.defineProperty(hash, 'length', { get() { throw new Error('SHADOW_LENGTH_READ'); } }); break;
      case 'byte-length-throws': Object.defineProperty(hash, 'byteLength', { get() { throw new Error('SHADOW_BYTE_LENGTH_READ'); } }); break;
      case 'uint16-buffer-prototype': hash = new Uint16Array(hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength)); Object.setPrototypeOf(hash, Buffer.prototype); break;
      case 'uint32-buffer-prototype': hash = new Uint32Array(hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength)); Object.setPrototypeOf(hash, Buffer.prototype); break;
      case 'proxy': hash = new Proxy(hash, {}); break;
      case 'revoked-proxy': {
        const wrapped = Proxy.revocable(hash, {});
        wrapped.revoke();
        hash = wrapped.proxy;
        break;
      }
      default: throw new Error(item.decoration);
    }
    if (item.priorElementCopyHex) {
      assert.equal(Buffer.isBuffer(hash), true);
      assert.equal(utilTypes.isUint8Array(hash), false);
      assert.equal(Reflect.apply(Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get, hash, []), 32);
      const priorCopy = Buffer.alloc(32);
      Reflect.apply(Uint8Array.prototype.set, priorCopy, [hash]);
      assert.equal(priorCopy.toString('hex'), item.priorElementCopyHex);
      assert.notEqual(priorCopy.toString('hex'), vectors.hashes[item.hash]);
    }
    const request = { ...base, proof: [hash] };
    if (item.expected === 'VALID') {
      const wire = encodeSubtreeRequest(request);
      assert.equal(Buffer.from(wire).toString('hex'), vectors.wires[item.wire].hex);
      assert.equal(digest(wire), vectors.wires[item.wire].sha256);
    } else {
      assert.equal(item.expected, 'SUBTREE_REQUEST');
      assert.equal(item.noWire, true);
      assert.throws(() => encodeSubtreeRequest(request), { code: item.expected });
    }
  });
}
