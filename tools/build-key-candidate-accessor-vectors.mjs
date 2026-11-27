import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const sha256 = hex => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const cases = [
  { id: 'candidate-key-late-ml-dsa-44', nameReads: ['requested'], keyReads: ['primary', 'primary', 'primary', 'primary', 'legacy44'], expected: 'primary', previousResult: 'legacy44' },
  { id: 'candidate-key-early-ml-dsa-44', nameReads: ['requested'], keyReads: ['legacy44', 'primary'], expected: 'NOTE_KEY_UNKNOWN', previousResult: 'primary' },
  { id: 'candidate-key-early-other-87', nameReads: ['requested'], keyReads: ['second', 'primary'], expected: 'NOTE_KEY_UNKNOWN', previousResult: 'primary' },
  { id: 'candidate-name-late-other', nameReads: ['requested', 'other'], keyReads: ['primary'], expected: 'primary', previousResult: 'NOTE_KEY_UNKNOWN' },
  { id: 'candidate-name-early-other', nameReads: ['other', 'requested'], keyReads: ['primary'], expected: 'NOTE_KEY_UNKNOWN', previousResult: 'primary' },
];
const vector = {
  schemaVersion: 1,
  profile: source.profile,
  sourceSpkiVector: 'vectors/key-discovery.json',
  requestedNameUtf8Hex: Buffer.from(source.name, 'utf8').toString('hex'),
  otherNameUtf8Hex: Buffer.from('other.example/witness', 'utf8').toString('hex'),
  keyHintHex: source.keyHint,
  spkiSha256: Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, sha256(hex)])),
  cases,
};
writeFileSync(new URL('../vectors/key-candidate-accessors.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
