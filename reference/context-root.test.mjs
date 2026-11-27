import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { types as utilTypes } from 'node:util';
import { subtreeInput } from './extension.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/context-root.json', import.meta.url)));
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url)));
const digest = value => createHash('sha256').update(value).digest('hex');

test('core context comparison preimage is exact', () => {
  const normal = Buffer.from(vectors.preimages.valid.hex, 'hex');
  assert.equal(normal.toString('hex'), prefix.input);
  assert.equal(normal.subarray(-32).toString('hex'), vectors.roots.original);
  assert.equal(digest(normal), vectors.preimages.valid.sha256);
  const prior = Buffer.from(vectors.preimages.priorShort.hex, 'hex');
  assert.equal(prior.length, normal.length - 16);
  assert.equal(digest(prior), vectors.preimages.priorShort.sha256);
  assert.equal(prior.subarray(0, -16).toString('hex'), normal.subarray(0, -32).toString('hex'));
});

for (const item of vectors.cases) {
  test(item.id, () => {
    let root = Buffer.from(vectors.roots[item.root], 'hex');
    switch (item.decoration) {
      case 'none': break;
      case 'length-16': Object.defineProperty(root, 'length', { get() { return 16; } }); break;
      case 'length-32': Object.defineProperty(root, 'length', { value: 32 }); break;
      case 'length-throws': Object.defineProperty(root, 'length', { get() { throw new Error('SHADOW_LENGTH_READ'); } }); break;
      case 'byte-length-throws': Object.defineProperty(root, 'byteLength', { get() { throw new Error('SHADOW_BYTE_LENGTH_READ'); } }); break;
      case 'uint16-buffer-prototype': root = new Uint16Array(root.buffer.slice(root.byteOffset, root.byteOffset + root.byteLength)); Object.setPrototypeOf(root, Buffer.prototype); Object.defineProperty(root, 'length', { value: 32 }); break;
      case 'proxy': root = new Proxy(root, {}); break;
      case 'revoked-proxy': {
        const wrapped = Proxy.revocable(root, {});
        wrapped.revoke();
        root = wrapped.proxy;
        break;
      }
      default: throw new Error(item.decoration);
    }
    if (item.decoration === 'uint16-buffer-prototype') {
      assert.equal(Buffer.isBuffer(root), true);
      assert.equal(utilTypes.isUint8Array(root), false);
    }
    const context = { ...vectors.context, root };
    if (item.expected === 'VALID') {
      const preimage = subtreeInput(context);
      assert.equal(preimage.toString('hex'), vectors.preimages[item.preimage].hex);
      assert.equal(digest(preimage), vectors.preimages[item.preimage].sha256);
    } else {
      assert.equal(item.expected, 'SUBTREE_CONTEXT');
      assert.equal(item.noPreimage, true);
      assert.throws(() => subtreeInput(context), { code: item.expected });
    }
  });
}
