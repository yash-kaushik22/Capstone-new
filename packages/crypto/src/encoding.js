// Byte and text helpers shared by every module. No dependencies, browser and Node.

export const utf8 = {
  encode: (s) => new TextEncoder().encode(s),
  decode: (b) => new TextDecoder('utf-8', { fatal: true }).decode(b),
};

export function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function toB64u(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64u(str) {
  if (typeof str !== 'string' || !B64U_RE.test(str)) throw new TypeError('invalid base64url');
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** Deterministic JSON: object keys sorted recursively. Used for anything that gets signed or hashed. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

/** Human-comparable fingerprint: first 10 bytes of SHA-256 as five 4-hex groups. */
export async function fingerprintOf(bytes) {
  const hex = toHex((await sha256(bytes)).subarray(0, 10));
  return hex.match(/.{4}/g).join(' ');
}
