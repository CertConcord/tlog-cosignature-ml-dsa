// C2SP cosigner names and log origins are UTF-8 scalar strings of 1..255
// bytes. White_Space is the 25-code-point Unicode 18.0 property; controls
// below U+0020 and U+002B are excluded separately.
const whiteSpace = code => code === 0x20 || code === 0x85 || code === 0xa0 ||
  code === 0x1680 || (code >= 0x2000 && code <= 0x200a) ||
  code === 0x2028 || code === 0x2029 || code === 0x202f ||
  code === 0x205f || code === 0x3000;

export function c2spNameBytes(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  for (const scalar of value) {
    const code = scalar.codePointAt(0);
    if (code < 0x20 || code === 0x2b || (code >= 0xd800 && code <= 0xdfff) ||
        whiteSpace(code)) return null;
  }
  const bytes = Buffer.from(value, 'utf8');
  return bytes.length <= 255 ? bytes : null;
}
