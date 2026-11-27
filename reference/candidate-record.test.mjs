import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { selectMlDsa87Key } from './extension.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/candidate-record.json', import.meta.url)));
const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const spki = Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));
const keys = Object.fromEntries(Object.entries(spki).map(([id, bytes]) => [id, createPublicKey({ key: bytes, format: 'der', type: 'spki' })]));
const names = { requested: Buffer.from(vector.requestedNameUtf8Hex, 'hex').toString('utf8'), other: Buffer.from(vector.otherNameUtf8Hex, 'hex').toString('utf8') };

test('candidate record vector fixes exact name, hint, ML-DSA-87 and ML-DSA-44 SPKI bytes', () => {
  assert.equal(vector.profile, source.profile);
  assert.equal(vector.sourceSpkiVector, 'vectors/key-discovery.json');
  assert.equal(names.requested, source.name);
  assert.equal(vector.keyHintHex, source.keyHint);
  for (const [id, bytes] of Object.entries(spki)) {
    assert.equal(createHash('sha256').update(bytes).digest('hex'), vector.spkiSha256[id]);
    assert.deepEqual(keys[id].export({ type: 'spki', format: 'der' }), bytes);
  }
});

for (const item of vector.cases) test('candidate record: ' + item.id, () => {
  const registry = item.initial.map(entry => ({ name: names[entry.name], publicKey: keys[entry.key] }));
  const hint = Buffer.from(vector.keyHintHex, 'hex');
  let nameReads = 0, keyReads = 0, nameReceiver = false, keyReceiver = false;
  if (item.mutation) {
    Object.defineProperty(registry[0], 'name', { get() {
      nameReads++;
      if (item.mutation === 'rewrite-second-name') registry[1].name = names.other;
      else if (item.mutation === 'replace-second-key') registry[1].publicKey = keys.second;
      else if (item.mutation === 'zero-hint') hint.fill(0);
      else if (item.mutation === 'replace-own-key-with-legacy44') registry[0].publicKey = keys.legacy44;
      else if (item.mutation === 'replace-own-key-with-primary') registry[0].publicKey = keys.primary;
      return names.requested;
    } });
  }
  if (item.shape === 'single-accessor' || item.shape === 'two-accessors') {
    const limit = item.shape === 'single-accessor' ? 1 : 2;
    for (let i = 0; i < limit; i++) {
      Object.defineProperty(registry[i], 'name', { get() { nameReads++; return names.requested; } });
      Object.defineProperty(registry[i], 'publicKey', { get() { keyReads++; return keys.primary; } });
    }
  } else if (item.shape === 'shadowed-call') {
    function getName() { nameReads++; nameReceiver = this === registry[0]; return names[item.nameGetterResult]; }
    function getKey() { keyReads++; keyReceiver = this === registry[0]; return keys[item.keyGetterResult]; }
    getName.call = () => names[item.shadowedCallNameResult];
    getKey.call = () => keys[item.shadowedCallKeyResult];
    Object.defineProperty(registry[0], 'name', { get: getName });
    Object.defineProperty(registry[0], 'publicKey', { get: getKey });
  } else if (item.shape === 'absent-getter') {
    Object.defineProperty(registry[0], 'name', { get: undefined });
  } else if (item.shape === 'inherited-name') {
    delete registry[0].name;
    Object.setPrototypeOf(registry[0], { name: names.requested });
  } else if (item.shape === 'proxy') {
    registry[0] = new Proxy(registry[0], {});
  }
  const select = () => selectMlDsa87Key(names.requested, hint, registry);
  if (item.expected === 'primary') assert.equal(select(), keys.primary);
  else assert.throws(select, { code: item.expected });
  if (item.shape === 'two-accessors') assert.equal(nameReads, 0);
  if (item.shape === 'single-accessor') { assert.equal(nameReads, 1); assert.equal(keyReads, 1); }
  if (item.shape === 'shadowed-call') { assert.equal(nameReads, 1); assert.equal(keyReads, 1); assert(nameReceiver); assert(keyReceiver); }
  if (item.mutation) assert.equal(nameReads, 1);
});
