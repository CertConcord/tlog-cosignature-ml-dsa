import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { postSignSubtree } from '../reference/client.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-python-http-interop.json', import.meta.url)));
const source = JSON.parse(readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url)));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const bytes = item => {
  const result = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(result.length, item.bytes);
  assert.equal(sha(result), item.sha256);
  return result;
};

const [port, mode] = process.argv.slice(2);
assert.match(port ?? '', /^[0-9]+$/);
const selected = vector.cases.find(item => item.mode === mode);
assert(selected && !mode.startsWith('raw-'));
const spki = Buffer.from(source.witness.spkiHex, 'hex');
assert.equal(sha(spki), vector.spkiSha256);
const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
const admitted = { name: source.witness.name, publicKey, at: source.witness.at };
const request = bytes(mode === 'bad-proof-local' ? vector.badProofRequest : vector.request).toString('utf8');
const prefix = `http://127.0.0.1:${port}/witness`;
let outcome;
try {
  const signature = await postSignSubtree(prefix, request, admitted);
  assert.equal(selected.expected, 'VALID');
  assert.equal(signature.length, vector.liveSignatureBytes);
  assert.equal(verify(null, Buffer.from(vector.signerInputHex, 'hex'),
    { key: publicKey, context: Buffer.alloc(0) }, signature), true);
  if (mode === 'frozen')
    assert.deepEqual(signature, Buffer.from(bytes(vector.bodies.frozen).toString('ascii').trimEnd(), 'base64'));
  outcome = { result: 'VALID', signatureBytes: signature.length };
} catch (error) {
  if (selected.expected === 'VALID') throw error;
  assert.equal(error.code, selected.expected);
  if (selected.status !== undefined) assert.equal(error.status, selected.status);
  outcome = { result: error.code, ...(error.status === undefined ? {} : { status: error.status }) };
}
process.stdout.write(JSON.stringify(outcome) + '\n');
