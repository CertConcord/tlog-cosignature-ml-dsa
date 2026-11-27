import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { selectMlDsa87Key } from './extension.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/key-candidate-accessors.json', import.meta.url)));
const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const spki = Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));
const keys = Object.fromEntries(Object.entries(spki).map(([id, bytes]) => [id, createPublicKey({ key: bytes, format: 'der', type: 'spki' })]));
const names = { requested: Buffer.from(vector.requestedNameUtf8Hex, 'hex').toString('utf8'), other: Buffer.from(vector.otherNameUtf8Hex, 'hex').toString('utf8') };

test('candidate accessor vector fixes the exact admission bytes', () => {
  assert.equal(vector.profile, source.profile);
  assert.equal(vector.sourceSpkiVector, 'vectors/key-discovery.json');
  assert.equal(names.requested, source.name);
  assert.equal(vector.keyHintHex, source.keyHint);
  for (const [id, bytes] of Object.entries(spki)) {
    assert.equal(createHash('sha256').update(bytes).digest('hex'), vector.spkiSha256[id]);
    assert.deepEqual(keys[id].export({ format: 'der', type: 'spki' }), bytes);
  }
});

for (const item of vector.cases) test('key candidate accessor: ' + item.id, () => {
  let nameReads = 0, keyReads = 0;
  const candidate = {
    get name() { return names[item.nameReads[Math.min(nameReads++, item.nameReads.length - 1)]]; },
    get publicKey() { return keys[item.keyReads[Math.min(keyReads++, item.keyReads.length - 1)]]; },
  };
  const select = () => selectMlDsa87Key(names.requested, Buffer.from(vector.keyHintHex, 'hex'), [candidate]);
  if (item.expected === 'NOTE_KEY_UNKNOWN') assert.throws(select, { code: item.expected });
  else assert.equal(select(), keys[item.expected]);
  assert.equal(nameReads, 1);
  assert.equal(keyReads, item.nameReads[0] === 'requested' ? 1 : 0);
});
