import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const prefix = JSON.parse(readFileSync(join(root, 'vectors/prefix.json')));
const normal = Buffer.from(prefix.input, 'hex');
const native = Buffer.from(prefix.context.root, 'hex');
if (native.length !== 32 || !normal.subarray(-32).equals(native)) throw new Error('source preimage root');
const short = Buffer.alloc(16, 0x5a);
const priorShort = Buffer.concat([normal.subarray(0, -32), short]);
const frozen = bytes => ({ hex: bytes.toString('hex'), sha256: createHash('sha256').update(bytes).digest('hex') });
const vectors = {
  schemaVersion: 1,
  profile: prefix.profile,
  sourceCase: 'vectors/prefix.json#input',
  context: { name: prefix.context.name, origin: prefix.context.origin, start: prefix.context.start,
    end: prefix.context.end, timestamp: prefix.context.timestamp },
  roots: {
    original: native.toString('hex'),
    short: short.toString('hex'),
    long: Buffer.alloc(48, 0x5a).toString('hex'),
  },
  preimages: { valid: frozen(normal), priorShort: frozen(priorShort) },
  cases: [
    { id: 'context-root-plain', root: 'original', decoration: 'none', expected: 'VALID', preimage: 'valid' },
    { id: 'context-root-shadow-length-16', root: 'original', decoration: 'length-16', expected: 'VALID', preimage: 'valid' },
    { id: 'context-root-shadow-length-throws', root: 'original', decoration: 'length-throws', expected: 'VALID', preimage: 'valid' },
    { id: 'context-root-shadow-byte-length-throws', root: 'original', decoration: 'byte-length-throws', expected: 'VALID', preimage: 'valid' },
    { id: 'context-root-native-short-spoof', root: 'short', decoration: 'length-32', expected: 'SUBTREE_CONTEXT', noPreimage: true, priorPreimage: 'priorShort' },
    { id: 'context-root-native-long-spoof', root: 'long', decoration: 'length-32', expected: 'SUBTREE_CONTEXT', noPreimage: true },
    { id: 'context-root-uint16-buffer-prototype', root: 'original', decoration: 'uint16-buffer-prototype', expected: 'SUBTREE_CONTEXT', noPreimage: true },
    { id: 'context-root-proxy', root: 'original', decoration: 'proxy', expected: 'SUBTREE_CONTEXT', noPreimage: true },
    { id: 'context-root-revoked-proxy', root: 'original', decoration: 'revoked-proxy', expected: 'SUBTREE_CONTEXT', noPreimage: true },
  ],
};
writeFileSync(join(root, 'vectors/context-root.json'), JSON.stringify(vectors, null, 2) + '\n');
