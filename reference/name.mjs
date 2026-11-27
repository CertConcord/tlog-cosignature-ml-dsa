// C2SP cosigner names and log origins are UTF-8 scalar strings of 1..255
// bytes. White_Space is the 25-code-point Unicode 18.0 property; controls
// below U+0020 and U+002B are excluded separately.
const whiteSpace = code => code === 0x20 || code === 0x85 || code === 0xa0 ||
  code === 0x1680 || (code >= 0x2000 && code <= 0x200a) ||
  code === 0x2028 || code === 0x2029 || code === 0x202f ||
  code === 0x205f || code === 0x3000;

export function c2spNameBytes(value) {
  // Every Unicode scalar occupies at least one UTF-16 code unit. This bound
  // makes the following scan constant-size even for an attacker-sized string.
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) return null;
  let byteLength = 0;
  for (const scalar of value) {
    const code = scalar.codePointAt(0);
    if (code < 0x20 || code === 0x2b || (code >= 0xd800 && code <= 0xdfff) ||
        whiteSpace(code)) return null;
    byteLength += code <= 0x7f ? 1 : code <= 0x7ff ? 2 : code <= 0xffff ? 3 : 4;
    if (byteLength > 255) return null;
  }
  return Buffer.from(value, 'utf8');
}
