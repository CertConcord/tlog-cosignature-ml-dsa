import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { postSignSubtree } from './client.mjs';
import { mlDsa87KeyID } from './extension.mjs';
import { processSignSubtree } from './http.mjs';
import { encodeSubtreeRequest, parseSubtreeRequest, parseSubtreeResponse,
  verifySubtreeCheckpoint, verifySubtreeRequest, verifySubtreeResponse } from './transport.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/subtree-max-carriage.json', import.meta.url)));
const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const spki = Buffer.from(source.witness.spkiHex, 'hex');
const publicKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
const witness = { name: vector.witness.name, publicKey, at: vector.witness.at };
const raw = item => {
  const bytes = Buffer.from(item.wireUtf8Hex, 'hex');
  assert.equal(bytes.length, item.wireBytes);
  assert.equal(sha(bytes), item.wireSha256);
  return bytes;
};
const [valid, badProof, leadingZero, extraProof] = vector.cases;
const validBytes = raw(valid);
const validText = validBytes.toString('utf8');
const responseBytes = raw(vector.response);
const responseSignature = parseSubtreeResponse(responseBytes.toString('ascii'));

test('maximum selected carriage binds the admitted key, prefix and checkpoint bytes', () => {
  assert.equal(vector.wireProfile, 'C2SP-20261007-MLDSA87-v2');
  assert.equal(vector.selectedProofRule, 'MTC draft-07 Section 4.4.3');
  assert.equal(sha(sourceBytes), vector.sourceLiveVectorSha256);
  assert.equal(sha(spki), vector.witness.spkiSha256);
  assert.equal(mlDsa87KeyID(witness.name, publicKey).toString('hex'), vector.witness.keyHintHex);
  assert.equal(Buffer.byteLength(vector.witness.name), 255);
  assert.equal(Buffer.byteLength(vector.origin), 255);
  assert.equal(vector.proofHex.length, 63);
  assert.equal(`subtree ${vector.start} ${vector.end}`.length, 49);
  assert.equal(vector.preCheckpointCut, 2929);
  assert.equal(vector.prefixBytes, 2931);
  assert.equal(validBytes.length, 9703);
  const prefix = Buffer.from(vector.requestPrefixUtf8Hex, 'hex');
  const note = Buffer.from(vector.noteUtf8Hex, 'hex');
  assert.equal(prefix.length, vector.prefixBytes);
  assert.equal(prefix.indexOf('\n\n'), vector.preCheckpointCut);
  assert.equal(note.length, vector.noteBytes);
  assert.equal(sha(note), vector.noteSha256);
  assert.deepEqual(validBytes, Buffer.concat([prefix, note]));
  const checkpoint = verifySubtreeCheckpoint(note.toString('utf8'), witness);
  assert.equal(checkpoint.size, BigInt(vector.size));
  assert.equal(checkpoint.root.toString('hex'), vector.checkpointRootHex);
  const request = verifySubtreeRequest(validText, witness);
  assert.equal(request.start, BigInt(vector.start));
  assert.equal(request.end, BigInt(vector.end));
  assert.equal(request.root.toString('hex'), vector.subtreeRootHex);
  assert.deepEqual(request.proof.map(value => value.toString('hex')), vector.proofHex);
  assert.equal(encodeSubtreeRequest({ start: request.start, end: request.end,
    root: request.root, proof: request.proof, checkpoint: note.toString('utf8') }), validText);
});

for (const item of vector.cases.slice(1)) test(`complete max-carriage rejection: ${item.id}`, () => {
  const request = raw(item).toString('utf8');
  assert.throws(() => verifySubtreeRequest(request, witness), { code: item.expected });
  if (item.expected === 'SUBTREE_PROOF') {
    const parsed = parseSubtreeRequest(request);
    assert.equal(parsed.proof.length, 63);
    assert.equal(encodeSubtreeRequest(parsed), request);
  } else {
    assert.throws(() => parseSubtreeRequest(request), { code: item.expected });
  }
});

test('frozen maximum-carriage response authenticates only its own request', () => {
  assert.equal(vector.response.signingInputBytes, 580);
  const signed = Buffer.from(vector.response.signingInputHex, 'hex');
  assert.equal(signed.length, vector.response.signingInputBytes);
  assert.equal(sha(signed), vector.response.signingInputSha256);
  assert.equal(responseBytes.length, 6173);
  assert.equal(verify(null, signed, { key: publicKey, context: Buffer.alloc(0) }, responseSignature), true);
  assert.deepEqual(verifySubtreeResponse(validText, responseBytes.toString('ascii'), witness), responseSignature);
  const otherBytes = raw(vector.wrongMessageResponse);
  const otherSignature = parseSubtreeResponse(otherBytes.toString('ascii'));
  const otherInput = Buffer.from(vector.wrongMessageResponse.signingInputHex, 'hex');
  assert.equal(sha(otherInput), vector.wrongMessageResponse.signingInputSha256);
  assert.equal(verify(null, otherInput, { key: publicKey, context: Buffer.alloc(0) }, otherSignature), true);
  assert.equal(verify(null, signed, { key: publicKey, context: Buffer.alloc(0) }, otherSignature), false);
  assert.throws(() => verifySubtreeResponse(validText, otherBytes.toString('ascii'), witness),
    { code: 'SUBTREE_SIGNATURE' });
});

test('loopback client and witness preserve 9703 request bytes at the selected bounds', async () => {
  const seen = [];
  const errors = [];
  let wrongResponse = false;
  const server = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      seen.push({ method: request.method, path: request.url, body });
      if (wrongResponse) {
        response.writeHead(200);
        response.end(raw(vector.wrongMessageResponse));
        return;
      }
      const result = processSignSubtree(body.toString('utf8'), {
        ...witness,
        originKnown(origin) { return origin === vector.origin; },
        sign(input) {
          assert.equal(input.toString('hex'), vector.response.signingInputHex);
          return responseSignature;
        },
      });
      response.writeHead(result.status);
      response.end(result.body);
    } catch (error) {
      errors.push(error);
      response.writeHead(500);
      response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const prefix = `http://127.0.0.1:${server.address().port}/witness`;
    assert.deepEqual(await postSignSubtree(prefix, validText, witness), responseSignature);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].method, 'POST');
    assert.equal(seen[0].path, '/witness/sign-subtree');
    assert.deepEqual(seen[0].body, validBytes);
    for (const item of [badProof, leadingZero, extraProof]) {
      await assert.rejects(postSignSubtree(prefix, raw(item).toString('utf8'), witness),
        { code: item.expected });
      assert.equal(seen.length, 1);
    }
    for (const [item, status] of [[badProof, 422], [leadingZero, 400], [extraProof, 400]]) {
      const result = await fetch(`${prefix}/sign-subtree`, { method: 'POST', body: raw(item), redirect: 'manual' });
      assert.equal(result.status, status);
      assert.equal(await result.text(), '');
    }
    assert.equal(seen.length, 4);
    wrongResponse = true;
    await assert.rejects(postSignSubtree(prefix, validText, witness), { code: 'SUBTREE_SIGNATURE' });
    assert.equal(seen.length, 5);
    assert.deepEqual(seen[4].body, validBytes);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
  assert.deepEqual(errors, []);
});
