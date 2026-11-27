import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const prefix = JSON.parse(readFileSync(join(root, 'vectors/prefix.json')));
const spki = Buffer.from(prefix.spki, 'hex');
const original = Buffer.from(prefix.keyHint, 'hex');
const derived = createHash('sha256').update(Buffer.concat([
  Buffer.from('certconcord/tlog-ml-dsa-87/v1\n'),
  Buffer.from(prefix.context.name + '\n'),
  spki,
])).digest().subarray(0, 4);
if (original.length !== 4 || !original.equals(derived)) throw new Error('source hint');
const vectors = {
  schemaVersion: 1,
  profile: prefix.profile,
  sourceCase: 'vectors/prefix.json#keyHint',
  name: prefix.context.name,
  selectedSpkiHex: prefix.spki,
  selectedSpkiSha256: createHash('sha256').update(spki).digest('hex'),
  hints: {
    original: original.toString('hex'),
    short: original.subarray(0, 2).toString('hex'),
    long: Buffer.concat([original, Buffer.from([0x5a, 0x5a])]).toString('hex'),
  },
  cases: [
    { id: 'key-hint-buffer-plain', hint: 'original', decoration: 'none', expected: 'VALID', selectedSpki: 'selectedSpkiHex' },
    { id: 'key-hint-buffer-shadow-length-2', hint: 'original', decoration: 'length-2', expected: 'VALID', selectedSpki: 'selectedSpkiHex' },
    { id: 'key-hint-buffer-shadow-length-throws', hint: 'original', decoration: 'length-throws', expected: 'VALID', selectedSpki: 'selectedSpkiHex' },
    { id: 'key-hint-buffer-shadow-byte-length-throws', hint: 'original', decoration: 'byte-length-throws', expected: 'VALID', selectedSpki: 'selectedSpkiHex' },
    { id: 'key-hint-buffer-native-short-spoof', hint: 'short', decoration: 'length-4', expected: 'NOTE_KEY_ID', noSelection: true },
    { id: 'key-hint-buffer-native-long-spoof', hint: 'long', decoration: 'length-4', expected: 'NOTE_KEY_ID', noSelection: true },
    { id: 'key-hint-buffer-uint16-buffer-prototype', hint: 'original', decoration: 'uint16-buffer-prototype', expected: 'NOTE_KEY_ID', noSelection: true },
    { id: 'key-hint-buffer-proxy', hint: 'original', decoration: 'proxy', expected: 'NOTE_KEY_ID', noSelection: true },
    { id: 'key-hint-buffer-revoked-proxy', hint: 'original', decoration: 'revoked-proxy', expected: 'NOTE_KEY_ID', noSelection: true },
  ],
};
writeFileSync(join(root, 'vectors/key-hint-buffer.json'), JSON.stringify(vectors, null, 2) + '\n');
