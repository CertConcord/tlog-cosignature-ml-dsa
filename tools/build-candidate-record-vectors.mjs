import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const primary = { name: 'requested', key: 'primary' };
const cases = [
  { id: 'candidate-record-data-unique', initial: [primary, { name: 'other', key: 'legacy44' }], shape: 'data', expected: 'primary', previousResult: 'primary' },
  { id: 'candidate-record-data-duplicate', initial: [primary, primary], shape: 'data', expected: 'NOTE_KEY_AMBIGUOUS', previousResult: 'NOTE_KEY_AMBIGUOUS' },
  { id: 'candidate-record-name-cross-mutation', initial: [primary, primary], shape: 'data', mutation: 'rewrite-second-name', expected: 'NOTE_KEY_AMBIGUOUS', previousResult: 'primary' },
  { id: 'candidate-record-key-cross-mutation', initial: [primary, primary], shape: 'data', mutation: 'replace-second-key', expected: 'NOTE_KEY_AMBIGUOUS', previousResult: 'primary' },
  { id: 'candidate-record-hint-mutation', initial: [primary], shape: 'data', mutation: 'zero-hint', expected: 'primary', previousResult: 'NOTE_KEY_UNKNOWN' },
  { id: 'candidate-record-singleton-accessor', initial: [primary], shape: 'single-accessor', expected: 'primary', previousResult: 'primary' },
  { id: 'candidate-record-own-key-to-ml-dsa-44', initial: [primary], shape: 'data', mutation: 'replace-own-key-with-legacy44', expected: 'NOTE_KEY_UNKNOWN', previousResult: 'NOTE_KEY_UNKNOWN' },
  { id: 'candidate-record-own-key-to-primary', initial: [{ name: 'requested', key: 'second' }], shape: 'data', mutation: 'replace-own-key-with-primary', expected: 'primary', previousResult: 'primary' },
  { id: 'candidate-record-shadowed-getter-call', initial: [primary], shape: 'shadowed-call', nameGetterResult: 'requested', keyGetterResult: 'primary', shadowedCallNameResult: 'other', shadowedCallKeyResult: 'second', expected: 'primary', previousResult: 'NOTE_KEY_UNKNOWN' },
  { id: 'candidate-record-absent-getter', initial: [primary], shape: 'absent-getter', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'NOTE_KEY_CANDIDATES' },
  { id: 'candidate-record-two-accessors', initial: [primary, primary], shape: 'two-accessors', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'NOTE_KEY_AMBIGUOUS' },
  { id: 'candidate-record-inherited-name', initial: [primary], shape: 'inherited-name', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'primary' },
  { id: 'candidate-record-proxy', initial: [primary], shape: 'proxy', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'primary' },
];
const sha256 = hex => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const vector = {
  schemaVersion: 1,
  profile: source.profile,
  sourceSpkiVector: 'vectors/key-discovery.json',
  requestedNameUtf8Hex: Buffer.from(source.name, 'utf8').toString('hex'),
  otherNameUtf8Hex: Buffer.from('unrelated.example', 'utf8').toString('hex'),
  keyHintHex: source.keyHint,
  spkiSha256: Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, sha256(hex)])),
  cases,
};
writeFileSync(new URL('../vectors/candidate-record.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
