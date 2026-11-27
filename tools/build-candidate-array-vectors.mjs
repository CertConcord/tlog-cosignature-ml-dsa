import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const primary = { name: 'requested', key: 'primary' };
const unrelated = { name: 'other', key: 'second' };
const cases = [
  { id: 'candidate-array-dense', initial: [primary], slotKind: 'data', expected: 'primary', previousResult: 'primary' },
  { id: 'candidate-array-remove-duplicate', initial: [primary, primary], slotKind: 'data', mutation: 'pop-on-first-name', expected: 'NOTE_KEY_AMBIGUOUS', previousResult: 'primary' },
  { id: 'candidate-array-replace-duplicate', initial: [primary, primary], slotKind: 'data', mutation: 'replace-on-first-name', expected: 'NOTE_KEY_AMBIGUOUS', previousResult: 'primary' },
  { id: 'candidate-array-append-at-cap', initial: [primary, ...Array(63).fill(unrelated)], slotKind: 'data', mutation: 'append-on-first-name', expected: 'primary', previousResult: 'NOTE_KEY_AMBIGUOUS' },
  { id: 'candidate-array-accessor-slot', initial: [primary], slotKind: 'accessor', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'primary' },
  { id: 'candidate-array-inherited-slot', initial: [primary], slotKind: 'inherited', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'primary' },
];
const vector = {
  schemaVersion: 1,
  profile: source.profile,
  sourceSpkiVector: 'vectors/key-discovery.json',
  requestedNameUtf8Hex: Buffer.from(source.name, 'utf8').toString('hex'),
  otherNameUtf8Hex: Buffer.from('unrelated.example', 'utf8').toString('hex'),
  keyHintHex: source.keyHint,
  spkiSha256: Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex')])),
  cases,
};
writeFileSync(new URL('../vectors/candidate-array.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
