/**
 * High-level file flows used by the web client and the end-to-end smoke test.
 *
 * Upload: random fileId + 32-byte file secret -> SSE2 ciphertext + encrypted metadata,
 *         secret wrapped (a) under the CP-ABE policy and (b) to the owner's ECDH key,
 *         everything summarised in a manifest signed with the owner's ECDSA key.
 * Download: verify signature + ciphertext hash, unwrap secret (ABE or owner copy), decrypt.
 */
import * as abe from './abe/index.js';
import { canonicalPolicy } from './abe/policy.js';
import { seal, open } from './aead.js';
import { canonicalJson, fromB64u, randomBytes, sha256, toB64u, toHex, utf8 } from './encoding.js';
import { deriveFileKeys, encryptBlob, decryptBlob } from './fileCipher.js';
import { sealTo, openSealed, signObject, verifyObject } from './identity.js';
import { DecryptionError, SignatureError } from './errors.js';

export const FILE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const newFileId = () => toB64u(randomBytes(16));

const metaAad = (fileId) => `secureshare/v2/meta|${fileId}`;
const ownerAad = (fileId, ownerId) => `secureshare/v2/owner|${fileId}|${ownerId}`;
const hashHex = async (str) => toHex(await sha256(utf8.encode(str)));
const blobSha256 = async (blob) => toHex(await sha256(new Uint8Array(await blob.arrayBuffer())));

export async function buildManifest({ fileId, ownerId, abeEnvelope, encMeta, ownerEnvelope, ciphertext, createdAt }) {
  return {
    v: 1,
    fileId,
    ownerId,
    policy: abeEnvelope.policy,
    ciphertext: { sha256: await blobSha256(ciphertext), size: ciphertext.size },
    encMetaSha256: await hashHex(encMeta),
    abeEnvelopeSha256: await hashHex(canonicalJson(abeEnvelope)),
    ownerEnvelopeSha256: await hashHex(ownerEnvelope),
    createdAt,
  };
}

/**
 * @param {object} args
 * @param {Blob} args.file plaintext
 * @param {{name:string,type:string}} args.meta
 * @param {string} args.policy  e.g. "dept:cse AND role:faculty"
 * @param {object} args.abePublicKey authority public parameters
 * @param {{id:string, encPublicJwk:object, sigPrivate:CryptoKey}} args.owner
 */
export async function encryptForUpload({ file, meta, policy, abePublicKey, owner, onProgress }) {
  const fileId = newFileId();
  const secret = randomBytes(32);
  const { dataKey, metaKey } = await deriveFileKeys(secret, fileId);
  const ciphertext = await encryptBlob(file, dataKey, fileId, { onProgress });
  const metaJson = JSON.stringify({ name: meta.name, type: meta.type || 'application/octet-stream', size: file.size });
  const encMeta = toB64u(await seal(metaKey, utf8.encode(metaJson), metaAad(fileId)));
  const abeEnvelope = await abe.wrapSecret({ publicKey: abePublicKey, policy: canonicalPolicy(policy), secret, fileId });
  const ownerEnvelope = await sealTo(owner.encPublicJwk, secret, ownerAad(fileId, owner.id));
  secret.fill(0);
  const manifest = await buildManifest({
    fileId,
    ownerId: owner.id,
    abeEnvelope,
    encMeta,
    ownerEnvelope,
    ciphertext,
    createdAt: new Date().toISOString(),
  });
  const signature = await signObject(owner.sigPrivate, manifest);
  return { fileId, ciphertext, encMeta, abeEnvelope, ownerEnvelope, manifest, signature };
}

/** Check that a server record matches its signed manifest. Throws SignatureError. */
export async function verifyRecord(record, ownerSigJwk) {
  const { manifest, signature } = record;
  await verifyObject(ownerSigJwk, manifest, signature);
  const checks = [
    manifest.fileId === record.id,
    manifest.ownerId === record.ownerId,
    manifest.policy === record.abeEnvelope.policy,
    manifest.encMetaSha256 === (await hashHex(record.encMeta)),
    manifest.abeEnvelopeSha256 === (await hashHex(canonicalJson(record.abeEnvelope))),
    manifest.ownerEnvelopeSha256 === (await hashHex(record.ownerEnvelope)),
  ];
  if (checks.includes(false)) throw new SignatureError('File record does not match the owner\'s signed manifest');
  return manifest;
}

/** Recover the file secret: owner copy if we own it, otherwise CP-ABE. */
export async function recoverSecret(record, me) {
  if (record.ownerId === me.id) {
    return openSealed(me.encPrivate, me.encPublicJwk, record.ownerEnvelope, ownerAad(record.id, me.id));
  }
  if (!me.abeSecretKey) throw new DecryptionError('You have no attribute key yet');
  return abe.unwrapSecret({ secretKey: me.abeSecretKey, envelope: record.abeEnvelope, fileId: record.id });
}

export async function decryptMeta(record, secret) {
  const { metaKey } = await deriveFileKeys(secret, record.id);
  return JSON.parse(utf8.decode(await open(metaKey, fromB64u(record.encMeta), metaAad(record.id))));
}

/**
 * Full download path. `record` is the server's file record, `ciphertext` the downloaded Blob.
 * @returns {{ blob: Blob, meta: {name,type,size}, manifest }}
 */
export async function decryptDownload({ record, ciphertext, ownerSigJwk, me, onProgress }) {
  const manifest = await verifyRecord(record, ownerSigJwk);
  if (ciphertext.size !== manifest.ciphertext.size || (await blobSha256(ciphertext)) !== manifest.ciphertext.sha256) {
    throw new SignatureError('Downloaded ciphertext does not match the signed manifest');
  }
  const secret = await recoverSecret(record, me);
  const { dataKey } = await deriveFileKeys(secret, record.id);
  const meta = await decryptMeta(record, secret);
  const blob = await decryptBlob(ciphertext, dataKey, record.id, { onProgress });
  secret.fill(0);
  return { blob: new Blob([blob], { type: meta.type }), meta, manifest };
}

/**
 * Owner changes the access policy: re-wrap the same file secret under the new policy
 * and re-sign. Users who already downloaded and decrypted the file keep that copy.
 */
export async function rewrapPolicy({ record, newPolicy, abePublicKey, owner }) {
  if (record.ownerId !== owner.id) throw new Error('Only the owner can change the policy');
  const secret = await recoverSecret(record, { ...owner, abeSecretKey: null });
  const abeEnvelope = await abe.wrapSecret({ publicKey: abePublicKey, policy: canonicalPolicy(newPolicy), secret, fileId: record.id });
  secret.fill(0);
  const manifest = {
    ...record.manifest,
    policy: abeEnvelope.policy,
    abeEnvelopeSha256: await hashHex(canonicalJson(abeEnvelope)),
    updatedAt: new Date().toISOString(),
  };
  const signature = await signObject(owner.sigPrivate, manifest);
  return { abeEnvelope, manifest, signature };
}
