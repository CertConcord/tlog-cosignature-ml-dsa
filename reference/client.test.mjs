import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { postSignSubtree } from './client.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-http-client.json', import.meta.url)));
const source = readFileSync(new URL('../vectors/subtree-response-auth.json', import.meta.url));
assert.equal(createHash('sha256').update(source).digest('hex'), vector.sourceResponseVectorSha256);
const publicKey = createPublicKey({ key: Buffer.from(vector.witness.spkiHex, 'hex'), type: 'spki', format: 'der' });
const witness = { name: vector.witness.name, publicKey, at: vector.witness.at };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const from = item => {
  const bytes = Buffer.from(item.utf8Hex, 'hex');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const validSignature = Buffer.from(from(vector.responses.valid).toString('ascii').trimEnd(), 'base64');

async function peer(status, body, action) {
  const seen = [];
  const server = createServer(async (request, response) => {
    const parts = [];
    for await (const part of request) parts.push(part);
    seen.push({ method: request.method, path: request.url, body: Buffer.concat(parts) });
    response.writeHead(status);
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await action(`http://127.0.0.1:${server.address().port}/witness`, seen); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

for (const item of vector.cases) {
  test(item.id, async () => {
    const body = from(vector.responses[item.response]);
    const request = from(vector.requests[item.request]);
    await peer(item.httpStatus, body, async (localPrefix, seen) => {
      const prefix = item.prefix ?? localPrefix;
      if (item.expected === 'VALID') {
        const signature = await postSignSubtree(prefix, request.toString('utf8'), witness);
        assert.deepEqual(signature, validSignature);
      } else {
        await assert.rejects(postSignSubtree(prefix, request.toString('utf8'), witness), error =>
          error.code === item.expected && (item.expected !== 'SUBTREE_HTTP_STATUS' || error.status === item.httpStatus));
      }
      assert.equal(seen.length, item.sent ? 1 : 0);
      if (item.sent) {
        assert.equal(seen[0].method, vector.request.method);
        assert.equal(seen[0].path, vector.request.path);
        assert.deepEqual(seen[0].body, request);
      }
    });
  });
}

test('trailing slash in submission prefix preserves the exact endpoint', async () => {
  await peer(200, from(vector.responses.valid), async (prefix, seen) => {
    const signature = await postSignSubtree(prefix + '/', from(vector.requests.valid).toString('utf8'), witness);
    assert.deepEqual(signature, validSignature);
    assert.equal(seen[0].path, '/witness/sign-subtree');
  });
});
