import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { mlDsa87KeyID, selectMlDsa87Key, subtreeInput, verifyCosignature } from './extension.mjs';

const fixture = JSON.parse(readFileSync(new URL('../vectors/revoked-keyobject.json', import.meta.url), 'utf8'));
const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url), 'utf8'));
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url), 'utf8'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const nameBytes = Buffer.from(fixture.sourceNameUtf8Hex, 'hex');
const name = nameBytes.toString('utf8');
const spki = Buffer.from(source.keys.primary, 'hex');
const hint = Buffer.from(fixture.sourceHintHex, 'hex');
const input = Buffer.from(prefix.input, 'hex');
const signature = Buffer.from(prefix.signature, 'hex');
const context = { ...prefix.context, root: Buffer.from(prefix.context.root, 'hex') };
assert.equal(name, source.name);
assert.equal(source.keyHint, fixture.sourceHintHex);
assert.equal(prefix.spki, source.keys.primary);
assert.equal(prefix.keyHint, fixture.sourceHintHex);
assert.equal(spki.length, fixture.sourceSpkiBytes);
assert.equal(digest(spki), fixture.sourceSpkiSha256);
assert.equal(input.length, fixture.sourceInputBytes);
assert.equal(digest(input), fixture.sourceInputSha256);
assert.deepEqual(subtreeInput(context), input);
assert.equal(signature.length, fixture.sourceSignatureBytes);
assert.equal(digest(signature), fixture.sourceSignatureSha256);

for (const item of fixture.cases) {
  test(item.id, () => {
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    let supplied = key;
    if (item.shape === 'revoked-proxy') {
      const wrapper = Proxy.revocable(key, {});
      wrapper.revoke();
      supplied = wrapper.proxy;
    }
    const call = () => {
      if (item.operation === 'hint') return mlDsa87KeyID(name, supplied);
      if (item.operation === 'select') return selectMlDsa87Key(name, hint, [{ name, publicKey: supplied }]);
      return verifyCosignature(context, signature, supplied);
    };
    if (item.expected !== 'VALID') assert.throws(call, { code: item.expected });
    else if (item.operation === 'hint') assert.deepEqual(call(), hint);
    else if (item.operation === 'select') assert.equal(call(), key);
    else assert.equal(call(), true);
  });
}
