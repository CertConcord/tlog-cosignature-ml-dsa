import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mlDsa87KeyID, selectMlDsa87Key, verifyCosignature } from './extension.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/keyobject-boundary.json', import.meta.url)));
const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url)));
const name = Buffer.from(vector.requestedNameUtf8Hex, 'hex').toString('utf8');
const signature = Buffer.from(prefix.signature, 'hex');
const context = { ...prefix.context, root: Buffer.from(prefix.context.root, 'hex') };
const spki = Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));

test('KeyObject boundary vector fixes exact SPKI, hint and signature bytes', () => {
  assert.equal(vector.profile, source.profile);
  assert.equal(vector.sourceSpkiVector, 'vectors/key-discovery.json');
  assert.equal(vector.sourceSignatureVector, 'vectors/prefix.json');
  assert.equal(name, source.name);
  assert.equal(vector.hintHex.primary, source.keyHint);
  assert.equal(vector.signatureSha256, createHash('sha256').update(signature).digest('hex'));
  for (const [id, bytes] of Object.entries(spki)) {
    assert.equal(vector.spkiSha256[id], createHash('sha256').update(bytes).digest('hex'));
    const hint = createHash('sha256').update(Buffer.concat([
      Buffer.from('certconcord/tlog-ml-dsa-87/v1\n'), Buffer.from(name + '\n'), bytes,
    ])).digest().subarray(0, 4).toString('hex');
    assert.equal(vector.hintHex[id], hint);
  }
});

for (const item of vector.cases) test('KeyObject boundary: ' + item.id, () => {
  let key = createPublicKey({ key: spki[item.actualKey], format: 'der', type: 'spki' });
  if (item.shadowAlgorithm) Object.defineProperty(key, 'asymmetricKeyType', { value: item.shadowAlgorithm });
  if (item.shadowType) Object.defineProperty(key, 'type', { value: item.shadowType });
  if (item.shadowExport) Object.defineProperty(key, 'export', { value: () => spki[item.shadowExport] });
  if (item.prototypeAlgorithm) {
    const altered = Object.create(Object.getPrototypeOf(key));
    Object.defineProperties(altered, {
      asymmetricKeyType: { value: item.prototypeAlgorithm },
      export: { value: () => spki[item.prototypeExport] },
    });
    Object.setPrototypeOf(key, altered);
  }
  if (item.proxy) key = new Proxy(key, {});
  const publicPrototype = Object.getPrototypeOf(key);
  const asymmetricPrototype = Object.getPrototypeOf(publicPrototype);
  const oldExport = item.sharedPrototypeExport && Object.getOwnPropertyDescriptor(publicPrototype, 'export');
  const oldAlgorithm = item.sharedPrototypeAlgorithm && Object.getOwnPropertyDescriptor(asymmetricPrototype, 'asymmetricKeyType');
  if (oldExport) Object.defineProperty(publicPrototype, 'export', { value: () => spki[item.sharedPrototypeExport], configurable: true });
  if (oldAlgorithm) Object.defineProperty(asymmetricPrototype, 'asymmetricKeyType', { get: () => item.sharedPrototypeAlgorithm, configurable: true });
  const call = () => {
    if (item.operation === 'select') return selectMlDsa87Key(name, Buffer.from(vector.hintHex[item.hint], 'hex'), [{ name, publicKey: key }]);
    if (item.operation === 'hint') return mlDsa87KeyID(name, key).toString('hex');
    if (item.operation === 'verify') return verifyCosignature(context, signature, key);
    throw new Error('unknown operation');
  };
  try {
    if (item.expected.startsWith('NOTE_')) assert.throws(call, { code: item.expected });
    else if (item.operation === 'select') assert.equal(call(), key);
    else if (item.operation === 'hint') assert.equal(call(), vector.hintHex[item.expected]);
    else assert.equal(call(), true);
  } finally {
    if (oldExport) Object.defineProperty(publicPrototype, 'export', oldExport);
    if (oldAlgorithm) Object.defineProperty(asymmetricPrototype, 'asymmetricKeyType', oldAlgorithm);
  }
});

test('private ML-DSA-87 KeyObject still derives its actual public SPKI hint', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ml-dsa-87');
  const expected = mlDsa87KeyID(name, publicKey);
  assert.deepEqual(mlDsa87KeyID(name, privateKey), expected);
  Object.defineProperty(privateKey, 'type', { value: 'public' });
  assert.deepEqual(mlDsa87KeyID(name, privateKey), expected);
});
