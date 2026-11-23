// Account flows. All key material is created and opened here, in the browser.
import {
  newKdfParams, deriveLoginKeys, createVault, openVault, generateIdentity, exportPublicJwk,
  openSealed, utf8, jwkFingerprint, abe,
} from '@secureshare/crypto';
import { api } from '../api.js';

async function unlockWith(user, vault, vaultKey) {
  const { encPrivate, sigPrivate } = await openVault(vaultKey, user.username, vault);
  return { user, keys: { encPrivate, sigPrivate, encPublicJwk: user.encPublicKey, sigPublicJwk: user.sigPublicKey } };
}

export async function register(username, password) {
  username = username.trim().toLowerCase();
  const kdf = newKdfParams();
  const { authKey, vaultKey } = await deriveLoginKeys(password, username, kdf);
  const identity = await generateIdentity();
  const body = {
    username,
    kdf,
    authKey,
    encPublicKey: await exportPublicJwk(identity.enc.publicKey),
    sigPublicKey: await exportPublicJwk(identity.sig.publicKey),
    vault: await createVault(vaultKey, username, identity),
  };
  const { user, vault } = await api.post('/api/auth/register', body);
  return unlockWith(user, vault, vaultKey);
}

export async function login(username, password) {
  username = username.trim().toLowerCase();
  const params = await api.get(`/api/auth/params?username=${encodeURIComponent(username)}`);
  const { authKey, vaultKey } = await deriveLoginKeys(password, username, params);
  const { user, vault } = await api.post('/api/auth/login', { username, authKey });
  return unlockWith(user, vault, vaultKey);
}

/** Session cookie still valid after a reload, but keys live only in memory: re-derive from the password. */
export async function unlock(me, password) {
  const { vaultKey } = await deriveLoginKeys(password, me.user.username, me.kdf);
  try {
    return await unlockWith(me.user, me.vault, vaultKey);
  } catch {
    throw new Error('Wrong password');
  }
}

export const currentSession = () => api.get('/api/auth/me');
export const logout = () => api.post('/api/auth/logout');

/** Authority public parameters (cached for the page lifetime). */
let paramsPromise;
export function authorityParams() {
  paramsPromise ??= api.get('/authority/params').catch((e) => {
    paramsPromise = undefined;
    throw e;
  });
  return paramsPromise;
}

/** Fetch this user's CP-ABE key from the authority and open it with the device key. */
export async function fetchAbeKey(session) {
  const res = await api.get('/authority/keys/me');
  const aad = `secureshare/v2/abe-key|${session.user.id}|${res.version}`;
  const sk = JSON.parse(utf8.decode(await openSealed(session.keys.encPrivate, session.keys.encPublicJwk, res.sealedKey, aad)));
  if (sk.scheme !== abe.SCHEME) throw new Error('Unexpected key scheme from authority');
  return { secretKey: sk, attributes: res.attributes, version: res.version, issuedAt: res.issuedAt };
}

export async function fingerprints(session) {
  const [enc, sig] = await Promise.all([jwkFingerprint(session.keys.encPublicJwk), jwkFingerprint(session.keys.sigPublicJwk)]);
  return { enc, sig };
}
