import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { mlDsa87KeyID, selectMlDsa87Key, verifyCosignature } from './extension.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url)));
const keys = Object.fromEntries(Object.entries(vector.keys).map(([id, hex]) => [id, createPublicKey({ key: Buffer.from(hex, 'hex'), format: 'der', type: 'spki' })]));

test('the exact admitted SPKI derives the published experimental hint', () => {
  assert.equal(vector.profile, 'CERTCONCORD-MLDSA87-SUBTREE-v1');
  assert.equal(vector.name, prefix.context.name);
  assert.equal(vector.keys.primary, prefix.spki);
  assert.equal(vector.keyHint, prefix.keyHint);
  assert.equal(mlDsa87KeyID(vector.name, keys.primary).toString('hex'), vector.keyHint);
  assert.notEqual(mlDsa87KeyID(vector.name, keys.second).toString('hex'), vector.keyHint);
});

for (const item of vector.cases) test('key discovery: ' + item.id, () => {
  const candidates = item.candidates.map(value => ({ name: value.name, publicKey: keys[value.key] }));
  const select = () => selectMlDsa87Key(vector.name, Buffer.from(item.keyHint ?? vector.keyHint, 'hex'), candidates);
  if (item.expected.endsWith('UNKNOWN') || item.expected.endsWith('AMBIGUOUS') || item.expected.endsWith('ID')) {
    assert.throws(select, { code: item.expected });
  } else {
    assert.equal(select(), keys[item.expected]);
    const context = { ...prefix.context, root: Buffer.from(prefix.context.root, 'hex') };
    assert(verifyCosignature(context, Buffer.from(prefix.signature, 'hex'), select()));
  }
});

test('candidate records and capacity are bounded', () => {
  const hint = Buffer.from(vector.keyHint, 'hex');
  assert.throws(() => selectMlDsa87Key(vector.name, hint, [{}]), { code: 'SUBTREE_NAME' });
  assert.throws(() => selectMlDsa87Key(vector.name, hint, [{ name: vector.name, publicKey: { type: 'public', asymmetricKeyType: 'ml-dsa-87' } }]), { code: 'NOTE_KEY_CANDIDATES' });
  assert.throws(() => selectMlDsa87Key(vector.name, hint, Array(65).fill({ name: vector.name, publicKey: keys.primary })), { code: 'NOTE_KEY_CANDIDATES' });
});
