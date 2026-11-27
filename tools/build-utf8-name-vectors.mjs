// Freeze test-only signatures for C2SP UTF-8 names in the experimental profile.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { c2spNameBytes } from '../reference/name.mjs';
import { mlDsa87KeyID, selectMlDsa87Key, subtreeInput } from '../reference/extension.mjs';
import { encodeSubtreeRequest, encodeSubtreeResponse, verifySubtreeRequest,
  verifySubtreeResponse } from '../reference/transport.mjs';

const sourceBytes = readFileSync(new URL('../vectors/subtree-live-sign.json', import.meta.url));
const source = JSON.parse(sourceBytes);
const spki = Buffer.from(source.witness.spkiHex, 'hex');
const publicKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
const privateKey = createPrivateKey({ key: Buffer.from(source.witness.pkcs8Hex, 'hex'),
  type: 'pkcs8', format: 'der' });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const leaf = Buffer.from('certconcord-utf8-name-leaf-v1', 'ascii');
const root = createHash('sha256').update(Buffer.concat([Buffer.from([0]), leaf])).digest();
const timestamp = 1700000000n;
const stamp = Buffer.alloc(8);
stamp.writeBigUInt64BE(timestamp);
const name = 'témoin.example/é';
const origin = 'café.example/árbol';
const boundaryName = 'é'.repeat(127) + 'a';
const boundaryOrigin = 'ö'.repeat(127) + 'b';
if (c2spNameBytes(boundaryName)?.length !== 255 || c2spNameBytes(boundaryOrigin)?.length !== 255)
  throw new Error('incorrect UTF-8 byte boundary');

function signedRequest(witnessName, logOrigin) {
  const hint = mlDsa87KeyID(witnessName, publicKey);
  const checkpointInput = subtreeInput({ name: witnessName, origin: logOrigin,
    start: 0n, end: 1n, root, timestamp });
  const signature = sign(null, checkpointInput, { key: privateKey, context: Buffer.alloc(0) });
  if (signature.length !== 4627) throw new Error('unexpected ML-DSA-87 signature length');
  const payload = Buffer.concat([hint, stamp, signature]);
  const note = `${logOrigin}\n1\n${root.toString('base64')}\n\n` +
    `\u2014 ${witnessName} ${payload.toString('base64')}\n`;
  const request = encodeSubtreeRequest({ start: 0n, end: 1n, root, proof: [], checkpoint: note });
  verifySubtreeRequest(request, { name: witnessName, publicKey, at: source.witness.at });
  return { name: witnessName, origin: logOrigin, hint, checkpointInput, signature,
    payload, note, request };
}
const primary = signedRequest(name, origin);
const boundary = signedRequest(boundaryName, boundaryOrigin);
if (selectMlDsa87Key(name, primary.hint, [{ name, publicKey }]) !== publicKey)
  throw new Error('UTF-8 key discovery failed');
if (mlDsa87KeyID(source.witness.name, publicKey).toString('hex') !== source.witness.keyIDHex)
  throw new Error('ASCII key hint changed');

const replaceOnce = (text, before, after) => {
  if (text.split(before).length !== 2) throw new Error('ambiguous replacement');
  return text.replace(before, after);
};
const changedHint = Buffer.from(primary.payload);
changedHint[0] ^= 1;
const variants = [
  { id: 'utf8-name-valid', mutation: null, wire: primary.request, expected: 'VALID' },
  { id: 'utf8-name-boundary-valid', mutation: null, wire: boundary.request, expected: 'VALID' },
  { id: 'utf8-name-wrong-origin', mutation: 'origin-code-point',
    wire: replaceOnce(primary.request, origin, 'cafè.example/árbol'), expected: 'CHECKPOINT_SIGNATURE' },
  { id: 'utf8-name-nfd', mutation: 'witness-name-decomposition',
    wire: replaceOnce(primary.request, name, name.normalize('NFD')), expected: 'SUBTREE_WITNESS_KEY' },
  { id: 'utf8-name-space', mutation: 'witness-name-no-break-space',
    wire: replaceOnce(primary.request, name, name.replace('é', '\u00a0')), expected: 'CHECKPOINT_SIGNATURE' },
  { id: 'utf8-name-plus', mutation: 'witness-name-plus',
    wire: replaceOnce(primary.request, name, name.replace('é', '+')), expected: 'CHECKPOINT_SIGNATURE' },
  { id: 'utf8-name-wrong-hint', mutation: 'experimental-key-hint-byte',
    wire: replaceOnce(primary.request, primary.payload.toString('base64'), changedHint.toString('base64')),
    expected: 'SUBTREE_WITNESS_KEY' },
  { id: 'utf8-name-overlong', mutation: '256-byte-witness-name',
    wire: replaceOnce(boundary.request, boundaryName, 'é'.repeat(128)),
    expected: 'CHECKPOINT_SIGNATURE' },
];
for (const item of variants) {
  try {
    const selected = item.id.includes('boundary') || item.id.includes('overlong') ? boundaryName : name;
    verifySubtreeRequest(item.wire, { name: selected, publicKey, at: source.witness.at });
    if (item.expected !== 'VALID') throw new Error(`${item.id}: unexpected acceptance`);
  } catch (error) {
    if (error.code !== item.expected) throw error;
  }
}
const responseInput = subtreeInput({ name, origin, start: 0n, end: 1n, root, timestamp: 0n });
const responseSignature = sign(null, responseInput, { key: privateKey, context: Buffer.alloc(0) });
const response = encodeSubtreeResponse(responseSignature);
verifySubtreeResponse(primary.request, response, { name, publicKey, at: source.witness.at });
const wrongInput = subtreeInput({ name, origin: 'cafè.example/árbol',
  start: 0n, end: 1n, root, timestamp: 0n });
const wrongSignature = sign(null, wrongInput, { key: privateKey, context: Buffer.alloc(0) });
const wrongResponse = encodeSubtreeResponse(wrongSignature);
try {
  verifySubtreeResponse(primary.request, wrongResponse, { name, publicKey, at: source.witness.at });
  throw new Error('wrong response accepted');
} catch (error) {
  if (error.code !== 'SUBTREE_SIGNATURE') throw error;
}

const whiteSpace = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000];
const nameSamples = [
  { id: 'ascii', value: 'witness.example', expected: 'VALID' },
  { id: 'latin', value: name, expected: 'VALID' },
  { id: 'astral', value: 'witness.example/😀', expected: 'VALID' },
  { id: 'del', value: 'witness.example/\u007f', expected: 'VALID' },
  { id: 'boundary-255', value: boundaryName, expected: 'VALID' },
  { id: 'overlong-256', value: 'é'.repeat(128), expected: 'SUBTREE_NAME' },
  { id: 'plus', value: 'a+b', expected: 'SUBTREE_NAME' },
  { id: 'control', value: 'a\u001fb', expected: 'SUBTREE_NAME' },
  { id: 'empty', value: '', expected: 'SUBTREE_NAME' },
  ...whiteSpace.map(code => ({ id: `white-space-${code.toString(16)}`,
    value: `a${String.fromCodePoint(code)}b`, expected: 'SUBTREE_NAME' })),
];
for (const item of nameSamples) {
  const actual = c2spNameBytes(item.value) === null ? 'SUBTREE_NAME' : 'VALID';
  if (actual !== item.expected) throw new Error(`${item.id}: ${actual}`);
}
if (c2spNameBytes('a\ud800b') !== null) throw new Error('lone surrogate accepted');
const freeze = value => ({ name: value.name, origin: value.origin,
  nameUtf8Hex: Buffer.from(value.name).toString('hex'),
  originUtf8Hex: Buffer.from(value.origin).toString('hex'),
  keyHintHex: value.hint.toString('hex'), checkpointInputHex: value.checkpointInput.toString('hex'),
  checkpointSignatureHex: value.signature.toString('hex'),
  noteUtf8Hex: Buffer.from(value.note).toString('hex'),
  requestUtf8Hex: Buffer.from(value.request).toString('hex'),
  requestSha256: hash(Buffer.from(value.request)) });
const vector = {
  schemaVersion: 1, wireProfile: 'C2SP-20261007-MLDSA87-v2',
  sources: { c2spCosignature: 'a29318317776ae8a0e65ff45cfe450fd935a1aca',
    unicodeWhiteSpaceSha256: 'f438f532e8737bb8a2702126cdf9c4af5e357c58c7acf9d9eb2fc7c1a1d955d6',
    sourceLiveVectorSha256: hash(sourceBytes) },
  publicSpkiHex: spki.toString('hex'), publicSpkiSha256: hash(spki),
  asciiBaseline: { name: source.witness.name, keyHintHex: source.witness.keyIDHex },
  leafAscii: leaf.toString('ascii'), rootHex: root.toString('hex'),
  timestamp: Number(timestamp), at: source.witness.at,
  primary: freeze(primary), boundary: freeze(boundary),
  cases: variants.map(item => ({ id: item.id, mutation: item.mutation,
    expected: item.expected, wireUtf8Hex: Buffer.from(item.wire).toString('hex'),
    wireBytes: Buffer.byteLength(item.wire), wireSha256: hash(Buffer.from(item.wire)) })),
  response: { signingInputHex: responseInput.toString('hex'), signatureHex: responseSignature.toString('hex'),
    wireUtf8Hex: Buffer.from(response).toString('hex'), wireBytes: Buffer.byteLength(response),
    wireSha256: hash(Buffer.from(response)), expected: 'VALID' },
  wrongResponse: { signingInputHex: wrongInput.toString('hex'), signatureHex: wrongSignature.toString('hex'),
    wireUtf8Hex: Buffer.from(wrongResponse).toString('hex'), wireBytes: Buffer.byteLength(wrongResponse),
    wireSha256: hash(Buffer.from(wrongResponse)), expected: 'SUBTREE_SIGNATURE' },
  whiteSpaceCodePoints: whiteSpace.map(code => code.toString(16).padStart(4, '0')),
  nameSamples: nameSamples.map(item => ({ id: item.id, expected: item.expected,
    utf8Hex: Buffer.from(item.value).toString('hex'),
    utf16CodeUnitsHex: Array.from({ length: item.value.length }, (_, i) =>
      item.value.charCodeAt(i).toString(16).padStart(4, '0')).join('') })),
  unpairedSurrogate: { utf16CodeUnitsHex: '0061d8000062', expected: 'SUBTREE_NAME' },
};
writeFileSync(new URL('../vectors/utf8-names.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log(JSON.stringify({ primaryBytes: Buffer.byteLength(primary.request),
  boundaryBytes: Buffer.byteLength(boundary.request), cases: variants.length,
  nameSamples: nameSamples.length, responseBytes: Buffer.byteLength(response) }));
