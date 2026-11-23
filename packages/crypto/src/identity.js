/**
 * Per-user identity keys, generated on the user's device:
 *   - encryption key: ECDH P-256 (receives the owner copy of file secrets and the
 *     user's CP-ABE secret key from the attribute authority)
 *   - signing key:    ECDSA P-256 / SHA-256 (signs file manifests)
 *
 * ECIES "seal to public key": ephemeral ECDH + HKDF-SHA-256 + AES-256-GCM, with
 * caller-supplied AAD binding the ciphertext to its purpose.
 */
import { hkdfAesKey, seal, open } from './aead.js';
import { concat, fromB64u, toB64u, utf8, fingerprintOf, canonicalJson } from './encoding.js';
import { DecryptionError, SignatureError } from './errors.js';

const subtle = () => globalThis.crypto.subtle;
export const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
export const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG_ALG = { name: 'ECDSA', hash: 'SHA-256' };

const pickJwk = ({ kty, crv, x, y }) => ({ kty, crv, x, y });

/** Generate both key pairs. Private keys are extractable only so they can be wrapped into the vault. */
export async function generateIdentity() {
  const [enc, sig] = await Promise.all([
    subtle().generateKey(ECDH, true, ['deriveBits']),
    subtle().generateKey(ECDSA, true, ['sign', 'verify']),
  ]);
  return { enc, sig };
}

export const exportPublicJwk = async (publicKey) => pickJwk(await subtle().exportKey('jwk', publicKey));

export function importEncPublic(jwk) {
  return subtle().importKey('jwk', pickJwk(jwk), ECDH, true, []);
}
export function importSigPublic(jwk) {
  return subtle().importKey('jwk', pickJwk(jwk), ECDSA, true, ['verify']);
}

export const exportPrivatePkcs8 = async (key) => new Uint8Array(await subtle().exportKey('pkcs8', key));
/** Re-imported private keys are non-extractable: script can use them but not read them out. */
export const importEncPrivate = (pkcs8) => subtle().importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']);
export const importSigPrivate = (pkcs8) => subtle().importKey('pkcs8', pkcs8, ECDSA, false, ['sign']);

/** SHA-256 fingerprint of a public JWK, formatted for out-of-band comparison. */
export const jwkFingerprint = (jwk) => fingerprintOf(utf8.encode(canonicalJson(pickJwk(jwk))));

// ---------- ECIES ----------

async function eciesKey(sharedBits, epkRaw, recipientRaw) {
  return hkdfAesKey(new Uint8Array(sharedBits), { salt: concat(epkRaw, recipientRaw), info: 'secureshare/v2/ecies' });
}

/** Encrypt bytes to a recipient's ECDH public JWK. @returns compact string "epk.ct" */
export async function sealTo(recipientJwk, plaintext, aad) {
  const recipient = await importEncPublic(recipientJwk);
  const recipientRaw = new Uint8Array(await subtle().exportKey('raw', recipient));
  const eph = await subtle().generateKey(ECDH, true, ['deriveBits']);
  const epkRaw = new Uint8Array(await subtle().exportKey('raw', eph.publicKey));
  const bits = await subtle().deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256);
  const ct = await seal(await eciesKey(bits, epkRaw, recipientRaw), plaintext, aad);
  return `${toB64u(epkRaw)}.${toB64u(ct)}`;
}

export async function openSealed(privateKey, ownPublicJwk, sealed, aad) {
  try {
    const [epkPart, ctPart] = String(sealed).split('.');
    const epkRaw = fromB64u(epkPart);
    const recipientRaw = new Uint8Array(await subtle().exportKey('raw', await importEncPublic(ownPublicJwk)));
    const epk = await subtle().importKey('raw', epkRaw, ECDH, false, []);
    const bits = await subtle().deriveBits({ name: 'ECDH', public: epk }, privateKey, 256);
    return await open(await eciesKey(bits, epkRaw, recipientRaw), fromB64u(ctPart), aad);
  } catch {
    throw new DecryptionError('Could not open sealed data (wrong key or tampered)');
  }
}

// ---------- signatures over canonical JSON ----------

export async function signObject(privateKey, obj) {
  const sig = await subtle().sign(SIG_ALG, privateKey, utf8.encode(canonicalJson(obj)));
  return toB64u(new Uint8Array(sig));
}

export async function verifyObject(publicJwk, obj, signature) {
  let ok;
  try {
    ok = await subtle().verify(SIG_ALG, await importSigPublic(publicJwk), fromB64u(signature), utf8.encode(canonicalJson(obj)));
  } catch {
    ok = false;
  }
  if (!ok) throw new SignatureError();
  return true;
}
