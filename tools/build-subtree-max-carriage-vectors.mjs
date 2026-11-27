// Freeze a signed request that reaches the selected range and proof prefix bounds.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { mlDsa87KeyID, subtreeInput } from '../reference/extension.mjs';
import { encodeSubtreeResponse } from '../reference/transport.mjs';

const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const spki = Buffer.from(source.witness.spkiHex, 'hex');
const publicKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
const privateKey = createPrivateKey({ key: Buffer.from(source.witness.pkcs8Hex, 'hex'), type: 'pkcs8', format: 'der' });
const namePrefix = 'witness.example/';
const originPrefix = 'log.example/';
const name = namePrefix + 'w'.repeat(255 - namePrefix.length);
const origin = originPrefix + 'o'.repeat(255 - originPrefix.length);
const size = 2n ** 64n - 1n;
const start = size - 3n;
const end = size - 1n;
const timestamp = 1700000000n;
const leafAscii = 'certconcord-max-carriage-leaf-v1';
const sha = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => sha(bytes).toString('hex');
const joined = (left, right) => sha(Buffer.concat([Buffer.from([1]), left, right]));
const leaf = sha(Buffer.concat([Buffer.from([0]), Buffer.from(leafAscii, 'ascii')]));
const memo = new Map([['1', leaf]]);
function treeHash(n) {
  const key = String(n);
  if (memo.has(key)) return memo.get(key);
  const split = 1n << BigInt((n - 1n).toString(2).length - 1);
  const result = joined(treeHash(split), treeHash(n - split));
  memo.set(key, result);
  return result;
}
function proof(a, b, n, includeRoot = false) {
  if (a === 0n && b === n) return includeRoot ? [treeHash(n)] : [];
  const split = 1n << BigInt((n - 1n).toString(2).length - 1);
  if (b <= split) return [...proof(a, b, split, includeRoot), treeHash(n - split)];
  if (a >= split) return [...proof(a - split, b - split, n - split, includeRoot), treeHash(split)];
  if (a !== 0n) throw new Error('unaligned crossing range');
  return [...proof(0n, b - split, n - split, true), treeHash(split)];
}
const checkpointRoot = treeHash(size);
const subtreeRoot = treeHash(end - start);
const hashes = proof(start, end, size);
if (Buffer.byteLength(name) !== 255 || Buffer.byteLength(origin) !== 255 || hashes.length !== 63)
  throw new Error('unexpected selected boundary');
const hint = mlDsa87KeyID(name, publicKey);
const stamp = Buffer.alloc(8);
stamp.writeBigUInt64BE(timestamp);
const checkpointSignature = sign(null, subtreeInput({ name, origin, end: size, root: checkpointRoot, timestamp }),
  { key: privateKey, context: Buffer.alloc(0) });
if (checkpointSignature.length !== 4627) throw new Error('unexpected signature length');
const note = Buffer.from(`${origin}\n${size}\n${checkpointRoot.toString('base64')}\n\n` +
  `\u2014 ${name} ${Buffer.concat([hint, stamp, checkpointSignature]).toString('base64')}\n`);
const prefix = (range, nodes) => Buffer.from(`${range}\n${subtreeRoot.toString('base64')}\n` +
  nodes.map(value => `${value.toString('base64')}\n`).join('') + '\n');
const range = `subtree ${start} ${end}`;
const requestPrefix = prefix(range, hashes);
const request = Buffer.concat([requestPrefix, note]);
if (range.length !== 49 || requestPrefix.indexOf('\n\n') !== 2929 || request.length !== 9703)
  throw new Error('unexpected request length');
const changed = hashes.map(value => Buffer.from(value));
changed[0][0] ^= 1;
const variants = [
  { id: 'max-carriage-valid', mutation: null, wire: request, expected: 'VALID' },
  { id: 'max-carriage-bad-proof', mutation: 'first-proof-byte',
    wire: Buffer.concat([prefix(range, changed), note]), expected: 'SUBTREE_PROOF' },
  { id: 'max-carriage-leading-zero', mutation: 'range-leading-zero',
    wire: Buffer.concat([prefix(`subtree 0${start} ${end}`, hashes), note]), expected: 'SUBTREE_RANGE' },
  { id: 'max-carriage-extra-proof', mutation: 'extra-proof-line',
    wire: Buffer.concat([prefix(range, [...hashes, hashes[0]]), note]), expected: 'SUBTREE_REQUEST' },
];
const responseInput = subtreeInput({ name, origin, start, end, root: subtreeRoot, timestamp: 0n });
const responseSignature = sign(null, responseInput, { key: privateKey, context: Buffer.alloc(0) });
const response = Buffer.from(encodeSubtreeResponse(responseSignature));
const otherRoot = Buffer.from(subtreeRoot);
otherRoot[0] ^= 1;
const wrongMessageInput = subtreeInput({ name, origin, start, end, root: otherRoot, timestamp: 0n });
const wrongMessageSignature = sign(null, wrongMessageInput, { key: privateKey, context: Buffer.alloc(0) });
const wrongMessageResponse = Buffer.from(encodeSubtreeResponse(wrongMessageSignature));
const vector = {
  schemaVersion: 1, wireProfile: 'C2SP-20261007-MLDSA87-v2',
  selectedProofRule: 'MTC draft-07 Section 4.4.3', sourceLiveVectorSha256: hex(sourceBytes),
  leafAscii, witness: { name, spkiSha256: hex(spki), keyHintHex: hint.toString('hex'),
    timestamp: Number(timestamp), at: source.witness.at },
  origin, size: String(size), start: String(start), end: String(end),
  checkpointRootHex: checkpointRoot.toString('hex'), subtreeRootHex: subtreeRoot.toString('hex'),
  proofHex: hashes.map(value => value.toString('hex')),
  noteUtf8Hex: note.toString('hex'), noteBytes: note.length, noteSha256: hex(note),
  requestPrefixUtf8Hex: requestPrefix.toString('hex'), prefixBytes: requestPrefix.length,
  preCheckpointCut: requestPrefix.indexOf('\n\n'),
  cases: variants.map(item => ({ id: item.id, mutation: item.mutation, expected: item.expected,
    wireUtf8Hex: item.wire.toString('hex'), wireBytes: item.wire.length, wireSha256: hex(item.wire) })),
  response: { signingInputHex: responseInput.toString('hex'), signingInputBytes: responseInput.length,
    signingInputSha256: hex(responseInput), wireUtf8Hex: response.toString('hex'),
    wireBytes: response.length, wireSha256: hex(response) },
  wrongMessageResponse: { signingInputHex: wrongMessageInput.toString('hex'),
    signingInputSha256: hex(wrongMessageInput), wireUtf8Hex: wrongMessageResponse.toString('hex'),
    wireBytes: wrongMessageResponse.length, wireSha256: hex(wrongMessageResponse),
    expected: 'SUBTREE_SIGNATURE' },
};
writeFileSync(new URL('../vectors/subtree-max-carriage.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log(JSON.stringify({ noteBytes: note.length, requestBytes: request.length,
  prefixBytes: requestPrefix.length, cut: requestPrefix.indexOf('\n\n'),
  responseBytes: response.length, cases: variants.map(value => [value.id, value.wire.length]) }));
