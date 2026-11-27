import { subtreeInput, verifyCosignature } from './extension.mjs';
import { encodeSubtreeResponse, parseSubtreeRequest, parseSubtreeResponse, verifySubtreeRequest } from './transport.mjs';

const failure = code => Object.assign(new Error(code), { code });
const empty = status => ({ status, body: '' });

// A synchronous, stateless /sign-subtree exchange. The caller owns origin
// admission, witness key custody, durable state and the actual HTTP server.
export function processSignSubtree(requestText, settings) {
  const { name, publicKey, at, maxFutureSkew, originKnown, sign } = settings;
  if (typeof originKnown !== 'function' || typeof sign !== 'function') throw failure('SUBTREE_POLICY');

  try {
    parseSubtreeRequest(requestText);
  } catch (error) {
    if (typeof error?.code === 'string') return empty(400);
    throw error;
  }

  let request;
  try {
    request = verifySubtreeRequest(requestText, { name, publicKey, at, maxFutureSkew });
  } catch (error) {
    if (error?.code === 'SUBTREE_PROOF') return empty(422);
    if (['SUBTREE_WITNESS_KEY', 'CHECKPOINT_SIGNATURE', 'CHECKPOINT_FUTURE'].includes(error?.code)) return empty(403);
    throw error;
  }

  const known = originKnown(request.origin);
  if (typeof known !== 'boolean') throw failure('SUBTREE_POLICY');
  if (!known) return empty(404);

  const context = { name, origin: request.origin, start: request.start, end: request.end,
    root: request.root, timestamp: 0n };
  const body = encodeSubtreeResponse(sign(subtreeInput(context)));
  const emittedSignature = parseSubtreeResponse(body);
  if (!verifyCosignature(context, emittedSignature, publicKey)) throw failure('SUBTREE_SIGNER_SIGNATURE');
  return { status: 200, body };
}
