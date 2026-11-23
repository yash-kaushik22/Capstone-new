/**
 * Chunked AES-256-GCM file format "SSE2" (STREAM-style online AEAD).
 *
 *   header (16 B) = "SSE2" | chunkSize u32 BE | noncePrefix (8 random bytes)
 *   chunk_i       = AES-GCM(dataKey, IV = noncePrefix || i u32, AAD = header || i u32 || isLast u8 || fileId)
 *
 * Every file has its own random secret, so keys are never reused across files.
 * Flipped bits, reordered/duplicated/dropped chunks, truncation, header edits and
 * moving the ciphertext to another fileId all fail authentication.
 */
import { hkdfAesKey } from './aead.js';
import { concat, utf8 } from './encoding.js';
import { DecryptionError } from './errors.js';

const subtle = () => globalThis.crypto.subtle;
const MAGIC = [0x53, 0x53, 0x45, 0x32]; // "SSE2"
export const HEADER_BYTES = 16;
export const TAG_BYTES = 16;
export const DEFAULT_CHUNK_BYTES = 1024 * 1024;
const MAX_CHUNK_BYTES = 16 * 1024 * 1024;

/** Two independent AES keys from the per-file secret. */
export async function deriveFileKeys(fileSecret, fileId) {
  if (!(fileSecret instanceof Uint8Array) || fileSecret.length !== 32) throw new TypeError('file secret must be 32 bytes');
  const salt = utf8.encode(`secureshare/v2/file|${fileId}`);
  const [dataKey, metaKey] = await Promise.all([
    hkdfAesKey(fileSecret, { salt, info: 'secureshare/v2/data' }),
    hkdfAesKey(fileSecret, { salt, info: 'secureshare/v2/meta' }),
  ]);
  return { dataKey, metaKey };
}

function chunkIv(header, i) {
  const iv = new Uint8Array(12);
  iv.set(header.subarray(8, 16));
  new DataView(iv.buffer).setUint32(8, i);
  return iv;
}

function chunkAad(header, i, isLast, fileIdBytes) {
  const pos = new Uint8Array(5);
  new DataView(pos.buffer).setUint32(0, i);
  pos[4] = isLast ? 1 : 0;
  return concat(header, pos, fileIdBytes);
}

/** @param {Blob} blob plaintext  @returns {Promise<Blob>} ciphertext */
export async function encryptBlob(blob, dataKey, fileId, { chunkSize = DEFAULT_CHUNK_BYTES, onProgress } = {}) {
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_BYTES) throw new RangeError('bad chunkSize');
  const header = new Uint8Array(HEADER_BYTES);
  header.set(MAGIC);
  new DataView(header.buffer).setUint32(4, chunkSize);
  globalThis.crypto.getRandomValues(header.subarray(8, 16));
  const fid = utf8.encode(fileId);
  const count = Math.max(1, Math.ceil(blob.size / chunkSize));
  const parts = [header];
  for (let i = 0; i < count; i++) {
    const plain = new Uint8Array(await blob.slice(i * chunkSize, Math.min(blob.size, (i + 1) * chunkSize)).arrayBuffer());
    const ct = await subtle().encrypt(
      { name: 'AES-GCM', iv: chunkIv(header, i), additionalData: chunkAad(header, i, i === count - 1, fid), tagLength: 128 },
      dataKey,
      plain,
    );
    parts.push(new Uint8Array(ct));
    onProgress?.((i + 1) / count);
  }
  return new Blob(parts, { type: 'application/octet-stream' });
}

/** @returns {Promise<Blob>} plaintext. Throws DecryptionError on any authentication failure. */
export async function decryptBlob(blob, dataKey, fileId, { onProgress } = {}) {
  if (blob.size < HEADER_BYTES + TAG_BYTES) throw new DecryptionError('Ciphertext too short');
  const header = new Uint8Array(await blob.slice(0, HEADER_BYTES).arrayBuffer());
  if (!MAGIC.every((b, i) => header[i] === b)) throw new DecryptionError('Not a SecureShare v2 ciphertext');
  const chunkSize = new DataView(header.buffer).getUint32(4);
  if (chunkSize < 1 || chunkSize > MAX_CHUNK_BYTES) throw new DecryptionError('Invalid chunk size');
  const fid = utf8.encode(fileId);
  const enc = chunkSize + TAG_BYTES;
  const count = Math.max(1, Math.ceil((blob.size - HEADER_BYTES) / enc));
  const parts = [];
  try {
    for (let i = 0; i < count; i++) {
      const start = HEADER_BYTES + i * enc;
      const c = new Uint8Array(await blob.slice(start, Math.min(blob.size, start + enc)).arrayBuffer());
      const pt = await subtle().decrypt(
        { name: 'AES-GCM', iv: chunkIv(header, i), additionalData: chunkAad(header, i, i === count - 1, fid), tagLength: 128 },
        dataKey,
        c,
      );
      parts.push(new Uint8Array(pt));
      onProgress?.((i + 1) / count);
    }
  } catch {
    throw new DecryptionError();
  }
  return new Blob(parts);
}
