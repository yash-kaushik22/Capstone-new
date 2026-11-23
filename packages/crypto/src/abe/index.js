/**
 * CP-ABE key wrapping: protects a file's 32-byte secret under an access policy.
 *
 *   (header, K) = FAME.encapsulate(pk, policy)
 *   kek         = HKDF-SHA-256(K, salt = SHA-256(header), info = "secureshare/v2/abe-kem")
 *   wrapped     = AES-256-GCM(kek, fileSecret, AAD = "secureshare/v2/abe|" fileId "|" canonicalPolicy)
 *
 * The AAD binds the envelope to one file and one policy, so the server cannot move
 * an envelope to another file or relabel its policy without detection.
 */
import * as fame from './fame.js';
import { parsePolicy, formatPolicy } from './policy.js';
import { hkdfAesKey, seal, open } from '../aead.js';
import { canonicalJson, fromB64u, toB64u, utf8, sha256, fingerprintOf } from '../encoding.js';
import { DecryptionError } from '../errors.js';

export { fame };
export const SCHEME = fame.SCHEME;

async function kek(keyBytes, header) {
  const salt = await sha256(utf8.encode(canonicalJson(header)));
  return hkdfAesKey(keyBytes, { salt, info: 'secureshare/v2/abe-kem' });
}

const aadFor = (fileId, policy) => `secureshare/v2/abe|${fileId}|${policy}`;

/** @returns envelope object (JSON-serialisable) */
export async function wrapSecret({ publicKey, policy, secret, fileId }) {
  const ast = parsePolicy(policy);
  const canonical = formatPolicy(ast);
  const { header, key } = fame.encapsulate(publicKey, ast);
  const ct = await seal(await kek(key, header), secret, aadFor(fileId, canonical));
  return { v: 1, scheme: SCHEME, policy: canonical, header, ct: toB64u(ct) };
}

/** @throws PolicyNotSatisfiedError | DecryptionError */
export async function unwrapSecret({ secretKey, envelope, fileId }) {
  if (envelope?.v !== 1 || envelope.scheme !== SCHEME) throw new DecryptionError('Unsupported ABE envelope');
  const ast = parsePolicy(envelope.policy);
  if (formatPolicy(ast) !== envelope.policy) throw new DecryptionError('Policy is not in canonical form');
  const key = fame.decapsulate(secretKey, ast, envelope.header);
  return open(await kek(key, envelope.header), fromB64u(envelope.ct), aadFor(fileId, envelope.policy));
}

export const publicKeyFingerprint = (pk) => fingerprintOf(fame.publicKeyBytes(pk));
