import {
  encryptForUpload, decryptDownload, rewrapPolicy, recoverSecret, decryptMeta, verifyRecord,
} from '@secureshare/crypto';
import { api } from '../api.js';
import { authorityParams } from './account.js';

const me = (session, abeKey) => ({
  id: session.user.id,
  encPrivate: session.keys.encPrivate,
  encPublicJwk: session.keys.encPublicJwk,
  sigPrivate: session.keys.sigPrivate,
  abeSecretKey: abeKey?.secretKey ?? null,
});

export async function uploadFile(session, file, policy, onProgress) {
  const { publicKey } = await authorityParams();
  const up = await encryptForUpload({
    file,
    meta: { name: file.name, type: file.type },
    policy,
    abePublicKey: publicKey,
    owner: { id: session.user.id, encPublicJwk: session.keys.encPublicJwk, sigPrivate: session.keys.sigPrivate },
    onProgress: (p) => onProgress?.({ stage: 'Encrypting', value: p }),
  });
  await api.post('/api/files', {
    fileId: up.fileId,
    encMeta: up.encMeta,
    abeEnvelope: up.abeEnvelope,
    ownerEnvelope: up.ownerEnvelope,
    manifest: up.manifest,
    signature: up.signature,
  });
  onProgress?.({ stage: 'Uploading ciphertext', value: null });
  try {
    await api.putBinary(`/api/files/${up.fileId}/blob`, up.ciphertext);
  } catch (err) {
    await api.del(`/api/files/${up.fileId}`).catch(() => {});
    throw err;
  }
  return up.fileId;
}

export const listFiles = (scope) => api.get(`/api/files?scope=${scope}`).then((r) => r.files);
export const getRecord = (id) => api.get(`/api/files/${id}`);

/** Decrypt just the file name/type (verifies the owner's signature first). */
export async function describe(session, abeKey, id) {
  const record = await getRecord(id);
  await verifyRecord(record, record.ownerSigPublicKey);
  const secret = await recoverSecret(record, me(session, abeKey));
  const meta = await decryptMeta(record, secret);
  secret.fill(0);
  return meta;
}

export async function download(session, abeKey, id, onProgress) {
  const record = await getRecord(id);
  onProgress?.({ stage: 'Downloading ciphertext', value: null });
  const ciphertext = await api.getBlob(`/api/files/${id}/blob`);
  const out = await decryptDownload({
    record,
    ciphertext,
    ownerSigJwk: record.ownerSigPublicKey,
    me: me(session, abeKey),
    onProgress: (p) => onProgress?.({ stage: 'Decrypting', value: p }),
  });
  saveBlob(out.blob, out.meta.name);
  return out.meta;
}

export async function changePolicy(session, id, newPolicy) {
  const record = await getRecord(id);
  const { publicKey } = await authorityParams();
  const body = await rewrapPolicy({ record, newPolicy, abePublicKey: publicKey, owner: me(session, null) });
  return api.put(`/api/files/${id}/policy`, body);
}

export const deleteFile = (id) => api.del(`/api/files/${id}`);

export function safeFilename(name) {
  const cleaned = String(name || 'download')
    // eslint-disable-next-line no-control-regex -- stripping control characters is the point
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f]/g, '_')
    .replace(/^\.+/, '_')
    .slice(0, 200);
  return cleaned || 'download';
}

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeFilename(name);
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
