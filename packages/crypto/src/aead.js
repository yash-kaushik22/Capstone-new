// Thin wrappers over Web Crypto: HKDF-SHA-256 and AES-256-GCM.
import { concat, randomBytes, utf8 } from './encoding.js';
import { DecryptionError } from './errors.js';

const subtle = () => globalThis.crypto.subtle;
const toBytes = (x) => (typeof x === 'string' ? utf8.encode(x) : x);

/** Derive an AES-256-GCM key from input keying material. */
export async function hkdfAesKey(ikm, { salt = new Uint8Array(0), info, usages = ['encrypt', 'decrypt'] }) {
  const base = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: toBytes(salt), info: toBytes(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

/** Derive raw bytes (e.g. an authentication token). */
export async function hkdfBytes(ikm, { salt = new Uint8Array(0), info, length = 32 }) {
  const base = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: toBytes(salt), info: toBytes(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** AES-256-GCM with a random 96-bit IV. Output = iv || ciphertext || tag. */
export async function seal(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: toBytes(aad), tagLength: 128 }, key, plaintext);
  return concat(iv, new Uint8Array(ct));
}

export async function open(key, sealed, aad) {
  if (!(sealed instanceof Uint8Array) || sealed.length < 28) throw new DecryptionError();
  try {
    const pt = await subtle().decrypt(
      { name: 'AES-GCM', iv: sealed.subarray(0, 12), additionalData: toBytes(aad), tagLength: 128 },
      key,
      sealed.subarray(12),
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptionError();
  }
}
