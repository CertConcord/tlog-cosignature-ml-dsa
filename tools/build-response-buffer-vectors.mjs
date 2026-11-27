import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const transport = JSON.parse(readFileSync(join(root, 'vectors/transport.json')));
const validText = transport.cases.find(item => item.id === 'raw-subtree-response').wire;
if (!validText.endsWith('\n')) throw new Error('source response LF');
const native = Buffer.from(validText.slice(0, -1), 'base64');
if (native.length !== 4627 || native.toString('base64') + '\n' !== validText) throw new Error('source signature');
const priorShort = Buffer.alloc(16, 0x5a).toString('base64') + '\n';
const priorLong = Buffer.alloc(4630, 0x5a).toString('base64') + '\n';
const frozen = text => ({ hex: Buffer.from(text).toString('hex'), sha256: createHash('sha256').update(text).digest('hex') });
const vectors = {
  schemaVersion: 1,
  profile: transport.wireProfile,
  sourceCase: 'vectors/transport.json#raw-subtree-response',
  signatures: {
    original: native.toString('hex'),
    short: Buffer.alloc(16, 0x5a).toString('hex'),
    long: Buffer.alloc(4630, 0x5a).toString('hex'),
    typed16: Buffer.alloc(4628, 0x5a).toString('hex'),
  },
  wires: { valid: frozen(validText), priorShort: frozen(priorShort), priorLong: frozen(priorLong) },
  cases: [
    { id: 'response-buffer-plain', signature: 'original', decoration: 'none', expected: 'VALID', wire: 'valid' },
    { id: 'response-buffer-shadow-length-16', signature: 'original', decoration: 'length-16', expected: 'VALID', wire: 'valid' },
    { id: 'response-buffer-shadow-length-throws', signature: 'original', decoration: 'length-throws', expected: 'VALID', wire: 'valid' },
    { id: 'response-buffer-shadow-byte-length-throws', signature: 'original', decoration: 'byte-length-throws', expected: 'VALID', wire: 'valid' },
    { id: 'response-buffer-native-short-spoof', signature: 'short', decoration: 'length-4627', expected: 'SUBTREE_SIGNATURE_LENGTH', noWire: true, priorWire: 'priorShort' },
    { id: 'response-buffer-native-long-spoof', signature: 'long', decoration: 'length-4627', expected: 'SUBTREE_SIGNATURE_LENGTH', noWire: true, priorWire: 'priorLong' },
    { id: 'response-buffer-uint16-buffer-prototype', signature: 'typed16', decoration: 'uint16-buffer-prototype', expected: 'SUBTREE_SIGNATURE_LENGTH', noWire: true },
    { id: 'response-buffer-proxy', signature: 'original', decoration: 'proxy', expected: 'SUBTREE_SIGNATURE_LENGTH', noWire: true },
    { id: 'response-buffer-revoked-proxy', signature: 'original', decoration: 'revoked-proxy', expected: 'SUBTREE_SIGNATURE_LENGTH', noWire: true },
  ],
};
writeFileSync(join(root, 'vectors/response-buffer.json'), JSON.stringify(vectors, null, 2) + '\n');
