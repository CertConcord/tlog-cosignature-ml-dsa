import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { types as utilTypes } from 'node:util';
import { selectMlDsa87Key } from './extension.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/key-hint-buffer.json', import.meta.url)));
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url)));
const spki = Buffer.from(vectors.selectedSpkiHex, 'hex');
const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
const candidates = [{ name: vectors.name, publicKey: key }];

test('key hint and selected SPKI bytes are exact', () => {
  assert.equal(vectors.hints.original, prefix.keyHint);
  assert.equal(vectors.selectedSpkiHex, prefix.spki);
  assert.equal(createHash('sha256').update(spki).digest('hex'), vectors.selectedSpkiSha256);
});

for (const item of vectors.cases) {
  test(item.id, () => {
    let hint = Buffer.from(vectors.hints[item.hint], 'hex');
    switch (item.decoration) {
      case 'none': break;
      case 'length-2': Object.defineProperty(hint, 'length', { get() { return 2; } }); break;
      case 'length-4': Object.defineProperty(hint, 'length', { value: 4 }); break;
      case 'length-throws': Object.defineProperty(hint, 'length', { get() { throw new Error('SHADOW_LENGTH_READ'); } }); break;
      case 'byte-length-throws': Object.defineProperty(hint, 'byteLength', { get() { throw new Error('SHADOW_BYTE_LENGTH_READ'); } }); break;
      case 'uint16-buffer-prototype': hint = new Uint16Array(hint.buffer.slice(hint.byteOffset, hint.byteOffset + hint.byteLength)); Object.setPrototypeOf(hint, Buffer.prototype); Object.defineProperty(hint, 'length', { value: 4 }); break;
      case 'proxy': hint = new Proxy(hint, {}); break;
      case 'revoked-proxy': {
        const wrapped = Proxy.revocable(hint, {});
        wrapped.revoke();
        hint = wrapped.proxy;
        break;
      }
      default: throw new Error(item.decoration);
    }
    if (item.decoration === 'uint16-buffer-prototype') {
      assert.equal(Buffer.isBuffer(hint), true);
      assert.equal(utilTypes.isUint8Array(hint), false);
    }
    if (item.expected === 'VALID') {
      const selected = selectMlDsa87Key(vectors.name, hint, candidates);
      assert.equal(selected, key);
      assert.equal(selected.export({ format: 'der', type: 'spki' }).toString('hex'), vectors[item.selectedSpki]);
    } else {
      assert.equal(item.expected, 'NOTE_KEY_ID');
      assert.equal(item.noSelection, true);
      assert.throws(() => selectMlDsa87Key(vectors.name, hint, candidates), { code: item.expected });
    }
  });
}
