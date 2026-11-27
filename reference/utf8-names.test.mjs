import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { c2spNameBytes } from './name.mjs';
import { mlDsa87KeyID, selectMlDsa87Key, subtreeInput } from './extension.mjs';
import { encodeSubtreeRequest, parseSubtreeRequest, verifySubtreeRequest,
  verifySubtreeResponse } from './transport.mjs';
import { processSignSubtree } from './http.mjs';
import { postSignSubtree } from './client.mjs';

const bytes = readFileSync(new URL('../vectors/utf8-names.json', import.meta.url));
const vector = JSON.parse(bytes);
const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const discovery = JSON.parse(readFileSync(new URL('../vectors/key-discovery.json', import.meta.url)));
const publicKey = createPublicKey({ key: Buffer.from(vector.publicSpkiHex, 'hex'),
  type: 'spki', format: 'der' });
const privateKey = createPrivateKey({ key: Buffer.from(source.witness.pkcs8Hex, 'hex'),
  type: 'pkcs8', format: 'der' });
const sha = data => createHash('sha256').update(data).digest('hex');
const admitted = { name: vector.primary.name, publicKey, at: vector.at };

test('UTF-8 names retain exact bytes, experimental hint and ML-DSA-44 boundary', () => {
  assert.equal(sha(sourceBytes), vector.sources.sourceLiveVectorSha256);
  assert.equal(sha(Buffer.from(vector.publicSpkiHex, 'hex')), vector.publicSpkiSha256);
  assert.equal(mlDsa87KeyID(vector.primary.name, publicKey).toString('hex'),
    vector.primary.keyHintHex);
  assert.equal(mlDsa87KeyID(vector.asciiBaseline.name, publicKey).toString('hex'),
    vector.asciiBaseline.keyHintHex);
  assert.equal(c2spNameBytes(vector.primary.name).toString('hex'), vector.primary.nameUtf8Hex);
  assert.equal(c2spNameBytes(vector.primary.origin).toString('hex'), vector.primary.originUtf8Hex);
  const legacy = createPublicKey({ key: Buffer.from(discovery.keys.legacy44, 'hex'),
    type: 'spki', format: 'der' });
  assert.equal(selectMlDsa87Key(vector.primary.name, Buffer.from(vector.primary.keyHintHex, 'hex'),
    [{ name: vector.primary.name, publicKey: legacy },
      { name: vector.primary.name, publicKey }]), publicKey);
  assert.throws(() => mlDsa87KeyID(vector.primary.name, legacy), { code: 'NOTE_KEY_SCHEME' });
  const decomposed = vector.primary.name.normalize('NFD');
  assert.notEqual(decomposed, vector.primary.name);
  assert.notEqual(mlDsa87KeyID(decomposed, publicKey).toString('hex'), vector.primary.keyHintHex);
});

test('Unicode 18 White_Space and byte length are enforced without normalization', () => {
  assert.equal(vector.whiteSpaceCodePoints.length, 25);
  for (const item of vector.nameSamples) {
    const codeUnits = (item.utf16CodeUnitsHex.match(/.{4}/g) ?? [])
      .map(value => parseInt(value, 16));
    const name = String.fromCharCode(...codeUnits);
    assert.equal(Buffer.from(name).toString('hex'), item.utf8Hex, item.id);
    assert.equal(c2spNameBytes(name) === null ? 'SUBTREE_NAME' : 'VALID', item.expected, item.id);
  }
  assert.equal(c2spNameBytes(String.fromCharCode(0x61, 0xd800, 0x62)), null);
  assert.equal(vector.unpairedSurrogate.utf16CodeUnitsHex, '0061d8000062');
});

test('UTF-8 name byte bound precedes allocation', () => {
  const nativeFrom = Buffer.from;
  let calls = 0;
  Buffer.from = function(...args) {
    calls++;
    return Reflect.apply(nativeFrom, Buffer, args);
  };
  try {
    assert.equal(c2spNameBytes(vector.boundary.name).toString('hex'),
      vector.boundary.nameUtf8Hex);
    assert.equal(calls, 1);
    calls = 0;
    assert.equal(c2spNameBytes('é'.repeat(128)), null);
    assert.equal(c2spNameBytes('a'.repeat(256)), null);
    assert.equal(calls, 0);
  } finally {
    Buffer.from = nativeFrom;
  }
});

for (const profile of ['primary', 'boundary']) test(`signed UTF-8 checkpoint: ${profile}`, () => {
  const item = vector[profile];
  const request = Buffer.from(item.requestUtf8Hex, 'hex').toString('utf8');
  const note = Buffer.from(item.noteUtf8Hex, 'hex').toString('utf8');
  assert.equal(Buffer.from(request).toString('hex'), item.requestUtf8Hex);
  assert.equal(sha(Buffer.from(request)), item.requestSha256);
  assert.equal(Buffer.from(item.name).toString('hex'), item.nameUtf8Hex);
  assert.equal(Buffer.from(item.origin).toString('hex'), item.originUtf8Hex);
  assert.equal(subtreeInput({ name: item.name, origin: item.origin,
    start: 0n, end: 1n, root: Buffer.from(vector.rootHex, 'hex'), timestamp: BigInt(vector.timestamp) })
    .toString('hex'), item.checkpointInputHex);
  assert.equal(parseSubtreeRequest(request).checkpoint, note);
  assert.equal(encodeSubtreeRequest({ start: 0n, end: 1n, root: Buffer.from(vector.rootHex, 'hex'),
    proof: [], checkpoint: note }), request);
  assert.equal(verifySubtreeRequest(request, { name: item.name, publicKey, at: vector.at }).origin,
    item.origin);
});

for (const item of vector.cases) test(`complete UTF-8 wire: ${item.id}`, () => {
  const wire = Buffer.from(item.wireUtf8Hex, 'hex');
  assert.equal(wire.length, item.wireBytes);
  assert.equal(sha(wire), item.wireSha256);
  const text = wire.toString('utf8');
  assert.equal(Buffer.from(text).toString('hex'), item.wireUtf8Hex);
  const selected = item.id.includes('boundary') || item.id.includes('overlong') ?
    vector.boundary.name : vector.primary.name;
  if (item.expected === 'VALID') {
    assert.equal(verifySubtreeRequest(text, { name: selected, publicKey, at: vector.at }).origin,
      item.id.includes('boundary') ? vector.boundary.origin : vector.primary.origin);
  } else {
    assert.throws(() => verifySubtreeRequest(text, { name: selected, publicKey, at: vector.at }),
      { code: item.expected });
  }
});

test('frozen response binds the exact UTF-8 origin and witness name', () => {
  const request = Buffer.from(vector.primary.requestUtf8Hex, 'hex').toString('utf8');
  const response = Buffer.from(vector.response.wireUtf8Hex, 'hex').toString('ascii');
  const wrong = Buffer.from(vector.wrongResponse.wireUtf8Hex, 'hex').toString('ascii');
  assert.equal(sha(Buffer.from(response)), vector.response.wireSha256);
  assert.equal(sha(Buffer.from(wrong)), vector.wrongResponse.wireSha256);
  assert.equal(subtreeInput({ name: vector.primary.name, origin: vector.primary.origin,
    start: 0n, end: 1n, root: Buffer.from(vector.rootHex, 'hex'), timestamp: 0n })
    .toString('hex'), vector.response.signingInputHex);
  assert.equal(verifySubtreeResponse(request, response, admitted).toString('hex'),
    vector.response.signatureHex);
  assert.throws(() => verifySubtreeResponse(request, wrong, admitted),
    { code: 'SUBTREE_SIGNATURE' });
});

test('real HTTP loopback carries UTF-8 bytes and rejects a local invalid name before sending', async () => {
  const request = Buffer.from(vector.primary.requestUtf8Hex, 'hex').toString('utf8');
  const invalid = Buffer.from(vector.cases.find(item => item.id === 'utf8-name-space').wireUtf8Hex,
    'hex').toString('utf8');
  const seen = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    seen.push({ url: req.url, method: req.method, hex: body.toString('hex') });
    const result = processSignSubtree(body.toString('utf8'), { ...admitted,
      originKnown: value => value === vector.primary.origin,
      sign: input => sign(null, input, { key: privateKey, context: Buffer.alloc(0) }) });
    res.writeHead(result.status, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(result.body);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const prefix = `http://127.0.0.1:${server.address().port}/`;
    const signature = await postSignSubtree(prefix, request, admitted);
    assert.equal(signature.length, 4627);
    assert.deepEqual(seen, [{ url: '/sign-subtree', method: 'POST',
      hex: vector.primary.requestUtf8Hex }]);
    await assert.rejects(postSignSubtree(prefix, invalid, admitted),
      { code: 'CHECKPOINT_SIGNATURE' });
    assert.equal(seen.length, 1);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
