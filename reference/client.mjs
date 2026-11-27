import { verifySubtreeRequest, verifySubtreeResponse } from './transport.mjs';

const failure = (code, status) => Object.assign(new Error(code), { code, ...(status === undefined ? {} : { status }) });

function endpoint(prefix) {
  if (typeof prefix !== 'string') throw failure('SUBTREE_HTTP_URL');
  let url;
  try { url = new URL(prefix); } catch { throw failure('SUBTREE_HTTP_URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash)
    throw failure('SUBTREE_HTTP_URL');
  return url.href + (url.href.endsWith('/') ? '' : '/') + 'sign-subtree';
}

async function boundedBody(response) {
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > 8192) {
      try { await reader.cancel(); } catch { /* retain the size error */ }
      throw failure('SUBTREE_HTTP_BODY_LIMIT');
    }
    chunks.push(Buffer.from(value));
  }
  const bytes = Buffer.concat(chunks, total);
  if (bytes.some(value => value > 0x7f)) throw failure('SUBTREE_RESPONSE_ENCODING');
  return bytes.toString('ascii');
}

// Sends one canonical request and returns only a cryptographically verified
// ML-DSA-87 signature. The caller supplies the admitted witness and URL policy.
export async function postSignSubtree(prefix, requestText, witness, { signal } = {}) {
  const target = endpoint(prefix);
  const { name, publicKey, at, maxFutureSkew } = witness;
  const admitted = { name, publicKey, at, maxFutureSkew };
  verifySubtreeRequest(requestText, admitted);
  const response = await fetch(target, { method: 'POST', body: Buffer.from(requestText, 'utf8'),
    redirect: 'error', signal });
  if (response.status !== 200) {
    try { await response.body?.cancel(); } catch { /* retain the status error */ }
    throw failure('SUBTREE_HTTP_STATUS', response.status);
  }
  return verifySubtreeResponse(requestText, await boundedBody(response), admitted);
}
