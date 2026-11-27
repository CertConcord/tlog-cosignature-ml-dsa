import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { postSignSubtree } from '../reference/client.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-large-u64-http.json', import.meta.url)));
const largeBytes = readFileSync(new URL('../vectors/subtree-large-u64.json', import.meta.url));
const large = JSON.parse(largeBytes);
const source = JSON.parse(readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url)));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(largeBytes), vector.sourceLargeVectorSha256);
const tree = large.trees.find(item => item.size === '18446744069414649856');
const normal = large.cases.find(item => item.id === vector.requestSourceCase);
const badProof = large.cases.find(item => item.id === vector.badProofSourceCase);
assert(tree && normal && badProof);
const requestBytes = item => Buffer.concat([Buffer.from(item.requestPrefixUtf8Hex, 'hex'),
  Buffer.from(tree.noteUtf8Hex, 'hex')]);
const normalBytes = requestBytes(normal);
const badBytes = requestBytes(badProof);
assert.equal(normalBytes.length, vector.requestBytes);
assert.equal(sha(normalBytes), vector.requestSha256);
assert.equal(sha(badBytes), vector.badProofRequestSha256);
const key = createPublicKey({ key: Buffer.from(source.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const witness = { name: large.witness.name, publicKey: key, at: large.witness.at };
const [port, caseId] = process.argv.slice(2);
assert.match(port ?? '', /^[0-9]+$/);
const selected = vector.cases.find(item => item.id === caseId);
assert(selected && selected.mode !== 'raw-bad-proof');
const prefix = `http://127.0.0.1:${port}/witness`;
const message = Buffer.from(vector.signerInputHex, 'hex');
let result;
if (selected.mode === 'bad-proof-local') {
  await assert.rejects(postSignSubtree(prefix, badBytes.toString('utf8'), witness),
    { code: selected.expected });
  result = { outcome: selected.expected };
} else if (selected.expected === 'VALID') {
  const signature = await postSignSubtree(prefix, normalBytes.toString('utf8'), witness);
  assert.equal(signature.length, 4627);
  assert(verify(null, message, { key, context: Buffer.alloc(0) }, signature));
  if (selected.mode === 'frozen') {
    const body = Buffer.from(vector.responses.valid.utf8Hex, 'hex');
    assert.equal(body.length, vector.responses.valid.bytes);
    assert.equal(sha(body), vector.responses.valid.sha256);
    assert.deepEqual(signature, Buffer.from(body.subarray(0, -1).toString('ascii'), 'base64'));
  }
  result = { outcome: 'VALID', signatureBytes: signature.length };
} else {
  await assert.rejects(postSignSubtree(prefix, normalBytes.toString('utf8'), witness),
    { code: selected.expected });
  result = { outcome: selected.expected };
}
process.stdout.write(JSON.stringify(result) + '\n');
