import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { mlDsa87KeyID, subtreeInput } from '../reference/extension.mjs';
import { encodeSubtreeRequest, encodeSubtreeResponse } from '../reference/transport.mjs';

// Synthetic public fixtures only. Private keys never leave this process.
const witness = generateKeyPairSync('ml-dsa-87'), log = generateKeyPairSync('ed25519');
const name = 'witness.example/independent', origin = 'log.example/documents';
const root = createHash('sha256').update('synthetic three-entry Merkle root').digest();
const body = `${origin}\n3\n${root.toString('base64')}\n`;
const timestamp = Buffer.alloc(8); timestamp.writeBigUInt64BE(1700000000n);
const checkpointSignature = sign(null, subtreeInput({ name, origin, end: 3, root, timestamp: 1700000000 }), witness.privateKey);
const witnessLine = `— ${name} ${Buffer.concat([mlDsa87KeyID(name, witness.publicKey), timestamp, checkpointSignature]).toString('base64')}\n`;
const logRaw = log.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const logHint = createHash('sha256').update(Buffer.concat([Buffer.from(origin + '\n'), Buffer.from([1]), logRaw])).digest().subarray(0, 4);
const logLine = `— ${origin} ${Buffer.concat([logHint, sign(null, Buffer.from(body), log.privateKey)]).toString('base64')}\n`;
const checkpoint = body + '\n' + witnessLine;
const request = encodeSubtreeRequest({ start: 0, end: 3, root, proof: [], checkpoint });
const signature = sign(null, subtreeInput({ name, origin, end: 3, root, timestamp: 0 }), witness.privateKey);
const response = encodeSubtreeResponse(signature);
const oldLine = `— ${name} ${Buffer.concat([mlDsa87KeyID(name, witness.publicKey), Buffer.alloc(8), signature]).toString('base64')}\n`;
const cases = [
  { id: 'raw-subtree-response', operation: 'response', wire: response, expected: 'VALID' },
  { id: 'legacy-note-response', operation: 'response', wire: oldLine, expected: 'SUBTREE_RESPONSE_ENCODING' },
  { id: 'legacy-timestamp-prefix', operation: 'response', wire: Buffer.concat([Buffer.alloc(8), signature]).toString('base64') + '\n', expected: 'SUBTREE_SIGNATURE_LENGTH' },
  { id: 'legacy-key-hint-prefix', operation: 'response', wire: Buffer.concat([mlDsa87KeyID(name, witness.publicKey), signature]).toString('base64') + '\n', expected: 'SUBTREE_SIGNATURE_LENGTH' },
  { id: 'missing-response-lf', operation: 'response', wire: response.slice(0, -1), expected: 'SUBTREE_RESPONSE_ENCODING' },
  { id: 'response-crlf', operation: 'response', wire: response.replace(/\n/g, '\r\n'), expected: 'SUBTREE_RESPONSE_ENCODING' },
  { id: 'response-no-padding', operation: 'response', wire: response.replace(/=+\n$/, '\n'), expected: 'SUBTREE_BASE64' },
  { id: 'extra-response-line', operation: 'response', wire: response + '\n', expected: 'SUBTREE_RESPONSE_ENCODING' },
  { id: 'one-witness-request', operation: 'request', wire: request, expected: 'VALID' },
  { id: 'legacy-mixed-checkpoint', operation: 'request', wire: request + logLine, expected: 'SUBTREE_ONE_WITNESS' },
  { id: 'duplicate-witness', operation: 'request', wire: request + witnessLine, expected: 'CHECKPOINT_DUPLICATE_SIGNATURE' },
  { id: 'log-instead-of-witness', operation: 'request', wire: request.replace(witnessLine, logLine), expected: 'SUBTREE_WITNESS_KEY' },
  { id: 'subtree-outside-checkpoint', operation: 'request', wire: request.replace('subtree 0 3\n', 'subtree 0 4\n'), expected: 'SUBTREE_CHECKPOINT_RANGE' },
  { id: 'request-leading-zero', operation: 'request', wire: request.replace('subtree 0 3\n', 'subtree 00 3\n'), expected: 'SUBTREE_RANGE' },
  { id: 'request-crlf', operation: 'request', wire: request.replace(/\n/g, '\r\n'), expected: 'SUBTREE_REQUEST' },
  { id: 'log-checkpoint', operation: 'log', wire: body + '\n' + logLine + witnessLine, expected: 'VALID' },
  { id: 'witness-only-log-checkpoint', operation: 'log', wire: checkpoint, expected: 'CHECKPOINT_LOG_SIGNATURE_REQUIRED' },
];
const vector = { schemaVersion: 1, wireProfile: 'C2SP-20261007-MLDSA87-v2', witness: { name, spki: witness.publicKey.export({ format: 'der', type: 'spki' }).toString('hex') }, log: { name: origin, keyHint: logHint.toString('hex'), spki: log.publicKey.export({ format: 'der', type: 'spki' }).toString('hex') }, at: 1700000000, root: root.toString('hex'), cases };
writeFileSync(new URL('../vectors/transport.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
