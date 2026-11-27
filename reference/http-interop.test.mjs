import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { postSignSubtree } from './client.mjs';
import { processSignSubtree } from './http.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-http-interop.json', import.meta.url)));
const source = [
  ['subtree-http.json', vector.sourceServerVectorSha256],
  ['subtree-http-client.json', vector.sourceClientVectorSha256],
  ['subtree-response-auth.json', vector.sourceResponseAuthVectorSha256],
];
for (const [name, expected] of source)
  assert.equal(createHash('sha256').update(readFileSync(new URL(`../vectors/${name}`, import.meta.url))).digest('hex'), expected);
const publicKey = createPublicKey({ key: Buffer.from(vector.witness.spkiHex, 'hex'), format: 'der', type: 'spki' });
const otherKey = createPublicKey({ key: Buffer.from(vector.witness.otherSpkiHex, 'hex'), format: 'der', type: 'spki' });
const admitted = { name: vector.witness.name, publicKey, at: vector.witness.at };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const wire = item => {
  const bytes = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const expectedSignature = Buffer.from(wire(vector.bodies.success).toString('ascii').trimEnd(), 'base64');

for (const item of vector.cases) {
  test(item.id, async () => {
    const seen = [];
    const requestBytes = wire(vector.requests[item.request]);
    let serverError = null;
    const server = createServer(async (request, response) => {
      try {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = Buffer.concat(chunks);
        const record = { method: request.method, path: request.url, body,
          result: null, origin: null, signedInput: null };
        seen.push(record);
        const result = processSignSubtree(body.toString('utf8'), {
          name: vector.witness.name,
          publicKey: item.serverKey === 'other' ? otherKey : publicKey,
          at: vector.witness.at,
          originKnown(origin) { record.origin = origin; return item.originKnown; },
          sign(input) { record.signedInput = Buffer.from(input); return expectedSignature; },
        });
        record.result = result;
        response.writeHead(result.status);
        response.end(result.body);
      } catch (error) {
        serverError = error;
        response.writeHead(500);
        response.end();
      }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const prefix = `http://127.0.0.1:${server.address().port}/witness`;
      if (item.expected === 'VALID') {
        assert.deepEqual(await postSignSubtree(prefix, requestBytes.toString('utf8'), admitted), expectedSignature);
      } else {
        await assert.rejects(postSignSubtree(prefix, requestBytes.toString('utf8'), admitted), error =>
          error.code === item.expected && (item.expected !== 'SUBTREE_HTTP_STATUS' || error.status === item.serverStatus));
      }
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
    assert.equal(serverError, null);
    assert.equal(seen.length, item.sent ? 1 : 0);
    if (!item.sent) return;
    const record = seen[0];
    assert.equal(record.method, vector.endpoint.method);
    assert.equal(record.path, vector.endpoint.path);
    assert.deepEqual(record.body, requestBytes);
    assert.equal(record.result.status, item.serverStatus);
    assert.deepEqual(Buffer.from(record.result.body, 'ascii'), wire(vector.bodies[item.body]));
    assert.equal(record.origin, item.serverStatus === 200 || item.serverStatus === 404 ? vector.expectedOrigin : null);
    assert.equal(record.signedInput?.toString('hex') ?? null, item.serverStatus === 200 ? vector.signerInputHex : null);
  });
}
