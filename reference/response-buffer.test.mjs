import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { types as utilTypes } from 'node:util';
import { encodeSubtreeResponse, parseSubtreeResponse } from './transport.mjs';

const vectors = JSON.parse(readFileSync(new URL('../vectors/response-buffer.json', import.meta.url)));
const transport = JSON.parse(readFileSync(new URL('../vectors/transport.json', import.meta.url)));
const digest = value => createHash('sha256').update(value).digest('hex');

test('response Buffer comparison wire is exact', () => {
  const source = transport.cases.find(item => item.id === 'raw-subtree-response').wire;
  const frozen = vectors.wires.valid;
  assert.equal(Buffer.from(source).toString('hex'), frozen.hex);
  assert.equal(digest(source), frozen.sha256);
  assert.equal(parseSubtreeResponse(source).toString('hex'), vectors.signatures.original);
  for (const name of ['priorShort', 'priorLong']) {
    assert.equal(digest(Buffer.from(vectors.wires[name].hex, 'hex')), vectors.wires[name].sha256);
    assert.throws(() => parseSubtreeResponse(Buffer.from(vectors.wires[name].hex, 'hex').toString()), { code: 'SUBTREE_SIGNATURE_LENGTH' });
  }
});

for (const item of vectors.cases) {
  test(item.id, () => {
    let signature = Buffer.from(vectors.signatures[item.signature], 'hex');
    switch (item.decoration) {
      case 'none': break;
      case 'length-16': Object.defineProperty(signature, 'length', { get() { return 16; } }); break;
      case 'length-4627': Object.defineProperty(signature, 'length', { value: 4627 }); break;
      case 'length-throws': Object.defineProperty(signature, 'length', { get() { throw new Error('SHADOW_LENGTH_READ'); } }); break;
      case 'byte-length-throws': Object.defineProperty(signature, 'byteLength', { get() { throw new Error('SHADOW_BYTE_LENGTH_READ'); } }); break;
      case 'uint16-buffer-prototype': signature = new Uint16Array(signature.buffer.slice(signature.byteOffset, signature.byteOffset + signature.byteLength)); Object.setPrototypeOf(signature, Buffer.prototype); Object.defineProperty(signature, 'length', { value: 4627 }); break;
      case 'proxy': signature = new Proxy(signature, {}); break;
      case 'revoked-proxy': {
        const wrapped = Proxy.revocable(signature, {});
        wrapped.revoke();
        signature = wrapped.proxy;
        break;
      }
      default: throw new Error(item.decoration);
    }
    if (item.decoration === 'uint16-buffer-prototype') {
      assert.equal(Buffer.isBuffer(signature), true);
      assert.equal(utilTypes.isUint8Array(signature), false);
    }
    if (item.priorWire) {
      const prior = signature.toString('base64') + '\n';
      assert.equal(Buffer.from(prior).toString('hex'), vectors.wires[item.priorWire].hex);
      assert.equal(digest(prior), vectors.wires[item.priorWire].sha256);
    }
    if (item.expected === 'VALID') {
      const wire = encodeSubtreeResponse(signature);
      assert.equal(Buffer.from(wire).toString('hex'), vectors.wires[item.wire].hex);
      assert.equal(digest(wire), vectors.wires[item.wire].sha256);
      assert.equal(parseSubtreeResponse(wire).toString('hex'), vectors.signatures.original);
    } else {
      assert.equal(item.expected, 'SUBTREE_SIGNATURE_LENGTH');
      assert.equal(item.noWire, true);
      assert.throws(() => encodeSubtreeResponse(signature), { code: item.expected });
    }
  });
}
