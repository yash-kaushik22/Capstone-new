/**
 * Zero-knowledge password handling (same idea as Bitwarden / 1Password):
 *
 *   master   = PBKDF2-SHA-256(NFKC(password), salt = "secureshare/v2|" username "|" randomSalt, >= 600k iterations)
 *   authKey  = HKDF(master, info "secureshare/v2/auth")   -> sent to the server, which stores Argon2id(authKey)
 *   vaultKey = HKDF(master, info "secureshare/v2/vault")  -> never leaves the device
 *
 * The server never sees the password or the vault key, so it cannot open the
 * user's private-key vault even though it stores it (enables multi-device login).
 */
import { hkdfAesKey, hkdfBytes, seal, open } from './aead.js';
import { concat, fromB64u, randomBytes, toB64u, utf8 } from './encoding.js';
import { exportPrivatePkcs8, importEncPrivate, importSigPrivate } from './identity.js';

export const KDF_ALG = 'pbkdf2-sha256';
export const MIN_ITERATIONS = 600_000; // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256

export function newKdfParams(iterations = MIN_ITERATIONS) {
  return { alg: KDF_ALG, iterations, salt: toB64u(randomBytes(16)) };
}

export async function deriveLoginKeys(password, username, params, { minIterations = MIN_ITERATIONS } = {}) {
  if (params?.alg !== KDF_ALG) throw new Error('Unsupported key-derivation parameters');
  // A malicious or misconfigured server must not be able to downgrade the work factor.
  if (!Number.isInteger(params.iterations) || params.iterations < minIterations) {
    throw new Error(`Refusing weak key derivation (${params.iterations} iterations)`);
  }
  const subtle = globalThis.crypto.subtle;
  const pw = await subtle.importKey('raw', utf8.encode(String(password).normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const salt = concat(utf8.encode(`secureshare/v2|${username}|`), fromB64u(params.salt));
  const master = new Uint8Array(
    await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: params.iterations }, pw, 256),
  );
  const [auth, vaultKey] = await Promise.all([
    hkdfBytes(master, { info: 'secureshare/v2/auth' }),
    hkdfAesKey(master, { info: 'secureshare/v2/vault' }),
  ]);
  master.fill(0);
  return { authKey: toB64u(auth), vaultKey };
}

const vaultAad = (username) => `secureshare/v2/vault|${username}`;

/** Encrypt the identity private keys for storage on the server. */
export async function createVault(vaultKey, username, identity) {
  const payload = {
    enc: toB64u(await exportPrivatePkcs8(identity.enc.privateKey)),
    sig: toB64u(await exportPrivatePkcs8(identity.sig.privateKey)),
  };
  return toB64u(await seal(vaultKey, utf8.encode(JSON.stringify(payload)), vaultAad(username)));
}

/** @returns {{encPrivate: CryptoKey, sigPrivate: CryptoKey}} non-extractable keys */
export async function openVault(vaultKey, username, vault) {
  const { enc, sig } = JSON.parse(utf8.decode(await open(vaultKey, fromB64u(vault), vaultAad(username))));
  const [encPrivate, sigPrivate] = await Promise.all([importEncPrivate(fromB64u(enc)), importSigPrivate(fromB64u(sig))]);
  return { encPrivate, sigPrivate };
}
