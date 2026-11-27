import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { selectMlDsa87Key } from './extension.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/candidate-array.json', import.meta.url)));
const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const spki = Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));
const keys = Object.fromEntries(Object.entries(spki).map(([id, bytes]) => [id, createPublicKey({ key: bytes, format: 'der', type: 'spki' })]));
const names = { requested: Buffer.from(vector.requestedNameUtf8Hex, 'hex').toString('utf8'), other: Buffer.from(vector.otherNameUtf8Hex, 'hex').toString('utf8') };

test('candidate array vector fixes the exact name, hint and SPKI bytes', () => {
  assert.equal(vector.profile, source.profile);
  assert.equal(vector.sourceSpkiVector, 'vectors/key-discovery.json');
  assert.equal(names.requested, source.name);
  assert.equal(vector.keyHintHex, source.keyHint);
  for (const [id, bytes] of Object.entries(spki)) {
    assert.equal(createHash('sha256').update(bytes).digest('hex'), vector.spkiSha256[id]);
    assert.deepEqual(keys[id].export({ type: 'spki', format: 'der' }), bytes);
  }
});

for (const item of vector.cases) test('candidate array: ' + item.id, () => {
  let registry = item.initial.map(entry => ({ name: names[entry.name], publicKey: keys[entry.key] }));
  let mutationReads = 0, appendedReads = 0, slotReads = 0;
  if (item.mutation) {
    Object.defineProperty(registry[0], 'name', { get() {
      mutationReads++;
      if (item.mutation === 'pop-on-first-name') registry.pop();
      else if (item.mutation === 'replace-on-first-name') registry[1] = { name: names.other, publicKey: keys.second };
      else if (item.mutation === 'append-on-first-name') registry.push({ get name() { appendedReads++; return names.requested; }, publicKey: keys.primary });
      return names.requested;
    } });
  }
  if (item.slotKind === 'accessor') {
    const candidate = registry[0];
    Object.defineProperty(registry, 0, { get() { slotReads++; return candidate; }, configurable: true });
  } else if (item.slotKind === 'inherited') {
    const candidate = registry[0];
    const prototype = Object.create(Array.prototype);
    Object.defineProperty(prototype, 0, { value: candidate, configurable: true });
    registry = new Array(1);
    Object.setPrototypeOf(registry, prototype);
  }
  const select = () => selectMlDsa87Key(names.requested, Buffer.from(vector.keyHintHex, 'hex'), registry);
  if (item.expected === 'primary') assert.equal(select(), keys.primary);
  else assert.throws(select, { code: item.expected });
  assert.equal(mutationReads, item.mutation ? 1 : 0);
  assert.equal(appendedReads, 0);
  assert.equal(slotReads, 0);
});
