import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { mlDsa87KeyID } from '../reference/extension.mjs';

// Synthetic public fixtures only. Private keys never leave this process.
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url)));
const primary = createPublicKey({ key: Buffer.from(prefix.spki, 'hex'), format: 'der', type: 'spki' });
const second = generateKeyPairSync('ml-dsa-87').publicKey;
const legacy44 = generateKeyPairSync('ml-dsa-44').publicKey;
const name = prefix.context.name;
const spki = key => key.export({ format: 'der', type: 'spki' }).toString('hex');
const hint = key => mlDsa87KeyID(name, key).toString('hex');
if (hint(primary) === hint(second)) throw new Error('Regenerate the synthetic secondary key');

const vector = {
  schemaVersion: 1,
  profile: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
  name,
  keyHint: prefix.keyHint,
  keys: { primary: spki(primary), second: spki(second), legacy44: spki(legacy44) },
  cases: [
    { id: 'key-discovery-exact', candidates: [{ name, key: 'primary' }], expected: 'primary' },
    { id: 'key-discovery-mixed-registry', candidates: [{ name, key: 'legacy44' }, { name, key: 'second' }, { name, key: 'primary' }], expected: 'primary' },
    { id: 'key-discovery-unknown', candidates: [{ name, key: 'second' }], expected: 'NOTE_KEY_UNKNOWN' },
    { id: 'key-discovery-other-name', candidates: [{ name: 'other.example/witness', key: 'primary' }], expected: 'NOTE_KEY_UNKNOWN' },
    { id: 'key-discovery-altered-hint', keyHint: hint(second), candidates: [{ name, key: 'primary' }], expected: 'NOTE_KEY_UNKNOWN' },
    { id: 'key-discovery-duplicate-hint', candidates: [{ name, key: 'primary' }, { name, key: 'primary' }], expected: 'NOTE_KEY_AMBIGUOUS' },
    { id: 'key-discovery-ml-dsa-44-only', candidates: [{ name, key: 'legacy44' }], expected: 'NOTE_KEY_UNKNOWN' },
    { id: 'key-discovery-short-hint', keyHint: prefix.keyHint.slice(0, 6), candidates: [{ name, key: 'primary' }], expected: 'NOTE_KEY_ID' },
  ],
};
writeFileSync(new URL('../vectors/key-discovery.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
