import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const source = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const prefix = JSON.parse(readFileSync(new URL('../vectors/prefix.json', import.meta.url)));
const sha256 = hex => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const hint = (name, hex) => createHash('sha256').update(Buffer.concat([
  Buffer.from('certconcord/tlog-ml-dsa-87/v1\n'), Buffer.from(name + '\n'), Buffer.from(hex, 'hex'),
])).digest().subarray(0, 4).toString('hex');
const cases = [
  { id: 'keyobject-normal-87', operation: 'select', actualKey: 'primary', hint: 'primary', expected: 'primary', previousResult: 'primary' },
  { id: 'keyobject-shadowed-algorithm-44', operation: 'select', actualKey: 'legacy44', shadowAlgorithm: 'ml-dsa-87', hint: 'legacy44', expected: 'NOTE_KEY_UNKNOWN', previousResult: 'legacy44' },
  { id: 'keyobject-shadowed-export-44', operation: 'select', actualKey: 'legacy44', shadowAlgorithm: 'ml-dsa-87', shadowExport: 'primary', hint: 'primary', expected: 'NOTE_KEY_UNKNOWN', previousResult: 'legacy44' },
  { id: 'keyobject-shadowed-type-87', operation: 'select', actualKey: 'primary', shadowType: 'private', hint: 'primary', expected: 'primary', previousResult: 'NOTE_KEY_CANDIDATES' },
  { id: 'keyobject-shadowed-algorithm-87', operation: 'select', actualKey: 'primary', shadowAlgorithm: 'ml-dsa-44', hint: 'primary', expected: 'primary', previousResult: 'NOTE_KEY_UNKNOWN' },
  { id: 'keyobject-shadowed-export-87', operation: 'select', actualKey: 'primary', shadowExport: 'second', hint: 'primary', expected: 'primary', previousResult: 'NOTE_KEY_UNKNOWN' },
  { id: 'keyobject-prototype-44', operation: 'select', actualKey: 'legacy44', prototypeAlgorithm: 'ml-dsa-87', prototypeExport: 'primary', hint: 'primary', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'legacy44' },
  { id: 'keyobject-shared-prototype-shadow-44', operation: 'select', actualKey: 'legacy44', sharedPrototypeAlgorithm: 'ml-dsa-87', sharedPrototypeExport: 'primary', hint: 'primary', expected: 'NOTE_KEY_UNKNOWN', previousResult: 'legacy44' },
  { id: 'keyobject-proxy-87', operation: 'select', actualKey: 'primary', proxy: true, hint: 'primary', expected: 'NOTE_KEY_CANDIDATES', previousResult: 'primary' },
  { id: 'keyobject-hint-shadowed-44', operation: 'hint', actualKey: 'legacy44', shadowAlgorithm: 'ml-dsa-87', expected: 'NOTE_KEY_SCHEME', previousResult: 'legacy44' },
  { id: 'keyobject-hint-shadowed-export-87', operation: 'hint', actualKey: 'primary', shadowExport: 'second', expected: 'primary', previousResult: 'second' },
  { id: 'keyobject-verify-shadowed-44', operation: 'verify', actualKey: 'legacy44', shadowAlgorithm: 'ml-dsa-87', expected: 'NOTE_KEY_SCHEME', previousResult: 'false' },
  { id: 'keyobject-verify-shadowed-87', operation: 'verify', actualKey: 'primary', shadowAlgorithm: 'ml-dsa-44', expected: 'primary', previousResult: 'NOTE_KEY_SCHEME' },
];
const vector = {
  schemaVersion: 1,
  profile: source.profile,
  sourceSpkiVector: 'vectors/key-discovery.json',
  sourceSignatureVector: 'vectors/prefix.json',
  requestedNameUtf8Hex: Buffer.from(source.name, 'utf8').toString('hex'),
  hintHex: Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, hint(source.name, hex)])),
  spkiSha256: Object.fromEntries(Object.entries(source.keys).map(([id, hex]) => [id, sha256(hex)])),
  signatureSha256: sha256(prefix.signature),
  cases,
};
writeFileSync(new URL('../vectors/keyobject-boundary.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
