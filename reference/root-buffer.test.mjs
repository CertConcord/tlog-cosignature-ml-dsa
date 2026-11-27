import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { types as utilTypes } from 'node:util';
import { encodeSubtreeRequest, parseSubtreeRequest } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/root-buffer.json', import.meta.url)));
const sparse = JSON.parse(readFileSync(new URL('../vectors/sparse-proof.json', import.meta.url)));
const one = Buffer.from(vectors.wires.one.hex, 'hex');
const base = parseSubtreeRequest(one.toString('utf8'));
const digest = value => createHash('sha256').update(value).digest('hex');

test('root Buffer comparison wire is exact', () => {
  assert.equal(vectors.wires.one.hex, sparse.wires.one.hex);
  assert.equal(digest(one), vectors.wires.one.sha256);
  assert.equal(base.root.toString('hex'), vectors.roots.original);
});

for (const item of vectors.cases) {
  test(item.id, () => {
    let root = Buffer.from(vectors.roots[item.root], 'hex');
    switch (item.decoration) {
      case 'none': break;
      case 'length-16': Object.defineProperty(root, 'length', { get() { return 16; } }); break;
      case 'length-32': Object.defineProperty(root, 'length', { get() { return 32; } }); break;
      case 'length-throws': Object.defineProperty(root, 'length', { get() { throw new Error('SHADOW_LENGTH_READ'); } }); break;
      case 'byte-length-throws': Object.defineProperty(root, 'byteLength', { get() { throw new Error('SHADOW_BYTE_LENGTH_READ'); } }); break;
      case 'uint16-buffer-prototype': root = new Uint16Array(root.buffer.slice(root.byteOffset, root.byteOffset + root.byteLength)); Object.setPrototypeOf(root, Buffer.prototype); Object.defineProperty(root, 'length', { value: 32 }); break;
      case 'uint32-buffer-prototype': root = new Uint32Array(root.buffer.slice(root.byteOffset, root.byteOffset + root.byteLength)); Object.setPrototypeOf(root, Buffer.prototype); Object.defineProperty(root, 'length', { value: 32 }); break;
      case 'proxy': root = new Proxy(root, {}); break;
      case 'revoked-proxy': {
        const wrapped = Proxy.revocable(root, {});
        wrapped.revoke();
        root = wrapped.proxy;
        break;
      }
      default: throw new Error(item.decoration);
    }
    if (item.decoration.endsWith('buffer-prototype')) {
      assert.equal(Buffer.isBuffer(root), true);
      assert.equal(utilTypes.isUint8Array(root), false);
      assert.equal(Reflect.apply(Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get, root, []), 32);
    }
    const request = { ...base, root };
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
