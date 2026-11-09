// Punycode label decoding (RFC 3492), so look-alike checks can see the letters an "xn--" name shows.

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;

function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
}

function digitOf(code) {
  if (code >= 0x30 && code <= 0x39) return code - 22; // 0-9 -> 26-35
  if (code >= 0x41 && code <= 0x5a) return code - 0x41; // A-Z -> 0-25
  if (code >= 0x61 && code <= 0x7a) return code - 0x61; // a-z -> 0-25
  return BASE;
}

/** Decodes the part after "xn--" of one label. Returns null for malformed input. */
export function decodeLabel(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 63) return null;
  const output = [];
  const basicEnd = Math.max(input.lastIndexOf('-'), 0);
  for (let j = 0; j < basicEnd; j++) {
    const code = input.charCodeAt(j);
    if (code >= 0x80) return null;
    output.push(code);
  }

  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;
  for (let index = basicEnd > 0 ? basicEnd + 1 : 0; index < input.length; ) {
    const oldI = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) return null;
      const digit = digitOf(input.charCodeAt(index++));
      if (digit >= BASE || digit > Math.floor((MAX_INT - i) / w)) return null;
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return null;
      w *= BASE - t;
    }
    const length = output.length + 1;
    bias = adapt(i - oldI, length, oldI === 0);
    if (Math.floor(i / length) > MAX_INT - n) return null;
    n += Math.floor(i / length);
    i %= length;
    if (n > 0x10ffff) return null;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** The Unicode form of a host name; labels that fail to decode are kept as they are. */
export function hostToUnicode(host) {
  return host
    .split('.')
    .map((label) => (label.startsWith('xn--') ? decodeLabel(label.slice(4)) ?? label : label))
    .join('.');
}
