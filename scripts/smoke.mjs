#!/usr/bin/env node
/**
 * End-to-end smoke test over real HTTP against running services. Uses the same
 * crypto code as the browser. Run against a fresh database (it creates users).
 *
 *   BASE_URL=https://localhost npm run smoke                  # behind Caddy
 *   API_URL=http://127.0.0.1:4000 AUTHORITY_URL=http://127.0.0.1:7000 npm run smoke
 *
 * Admin: logs in as SMOKE_ADMIN (default "admin", must equal BOOTSTRAP_ADMIN) with
 * SMOKE_ADMIN_PASSWORD, registering it first if it does not exist yet.
 */
import {
  newKdfParams, deriveLoginKeys, createVault, openVault, generateIdentity, exportPublicJwk, openSealed,
  utf8, encryptForUpload, decryptDownload, rewrapPolicy, recoverSecret, randomBytes, toHex, PolicyNotSatisfiedError,
} from '@secureshare/crypto';

const base = process.env.BASE_URL?.replace(/\/$/, '');
const API = process.env.API_URL ?? base ?? 'http://127.0.0.1:4000';
const AUTH = process.env.AUTHORITY_URL ?? base ?? 'http://127.0.0.1:7000';
const ADMIN = process.env.SMOKE_ADMIN ?? 'admin';
const ADMIN_PW = process.env.SMOKE_ADMIN_PASSWORD ?? 'smoke-admin-password-1';
const suffix = toHex(randomBytes(3));
let passed = 0;

function check(cond, label) {
  if (!cond) throw new Error(`FAILED: ${label}`);
  passed++;
  console.log(`  ✓ ${label}`);
}

class Client {
  constructor(name) {
    this.name = name;
    this.cookie = '';
  }
  async req(method, url, { json, body, type } = {}) {
    const headers = { 'X-SecureShare-CSRF': '1' };
    if (this.cookie) headers.Cookie = this.cookie;
    if (json !== undefined) headers['Content-Type'] = 'application/json';
    if (type) headers['Content-Type'] = type;
    const res = await fetch(url, { method, headers, body: json !== undefined ? JSON.stringify(json) : body });
    const set = res.headers.getSetCookie?.() ?? [];
    for (const c of set) {
      const pair = c.split(';')[0];
      if (/=$/.test(pair) || /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c)) this.cookie = '';
      else this.cookie = pair;
    }
    return res;
  }
  async json(method, url, opts) {
    const res = await this.req(method, url, opts);
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    return { status: res.status, data, headers: res.headers };
  }
}

async function register(client, username, password) {
  const kdf = newKdfParams();
  const { authKey, vaultKey } = await deriveLoginKeys(password, username, kdf);
  const id = await generateIdentity();
  const r = await client.json('POST', `${API}/api/auth/register`, {
    json: {
      username, kdf, authKey,
      encPublicKey: await exportPublicJwk(id.enc.publicKey),
      sigPublicKey: await exportPublicJwk(id.sig.publicKey),
      vault: await createVault(vaultKey, username, id),
    },
  });
  if (r.status !== 201) throw new Error(`register ${username}: ${r.status} ${JSON.stringify(r.data)}`);
  return unlock(client, r.data, vaultKey);
}

async function login(client, username, password) {
  const params = (await client.json('GET', `${API}/api/auth/params?username=${username}`)).data;
  const { authKey, vaultKey } = await deriveLoginKeys(password, username, params);
  const r = await client.json('POST', `${API}/api/auth/login`, { json: { username, authKey } });
  if (r.status !== 200) return null;
  return unlock(client, r.data, vaultKey);
}

async function unlock(client, { user, vault }, vaultKey) {
  const { encPrivate, sigPrivate } = await openVault(vaultKey, user.username, vault);
  Object.assign(client, { user, encPrivate, sigPrivate, encPublicJwk: user.encPublicKey });
  return client;
}

async function fetchKey(client) {
  const r = await client.json('GET', `${AUTH}/authority/keys/me`);
  if (r.status !== 200) throw new Error(`keys/me ${r.status}`);
  const aad = `secureshare/v2/abe-key|${client.user.id}|${r.data.version}`;
  client.abeSecretKey = JSON.parse(utf8.decode(await openSealed(client.encPrivate, client.encPublicJwk, r.data.sealedKey, aad)));
  return r.data;
}

async function upload(owner, content, policy, pk) {
  const up = await encryptForUpload({
    file: new Blob([content]), meta: { name: `smoke-${suffix}.txt`, type: 'text/plain' }, policy, abePublicKey: pk,
    owner: { id: owner.user.id, encPublicJwk: owner.encPublicJwk, sigPrivate: owner.sigPrivate },
  });
  const r1 = await owner.json('POST', `${API}/api/files`, {
    json: { fileId: up.fileId, encMeta: up.encMeta, abeEnvelope: up.abeEnvelope, ownerEnvelope: up.ownerEnvelope, manifest: up.manifest, signature: up.signature },
  });
  if (r1.status !== 201) throw new Error(`create ${r1.status} ${JSON.stringify(r1.data)}`);
  const r2 = await owner.req('PUT', `${API}/api/files/${up.fileId}/blob`, { body: up.ciphertext, type: 'application/octet-stream' });
  if (r2.status !== 204) throw new Error(`blob ${r2.status} ${await r2.text()}`);
  return up.fileId;
}

async function fetchAndDecrypt(client, id) {
  const rec = await client.json('GET', `${API}/api/files/${id}`);
  if (rec.status !== 200) return { status: rec.status };
  const blob = await (await client.req('GET', `${API}/api/files/${id}/blob`)).blob();
  const out = await decryptDownload({
    record: rec.data, ciphertext: blob, ownerSigJwk: rec.data.ownerSigPublicKey,
    me: { id: client.user.id, encPrivate: client.encPrivate, encPublicJwk: client.encPublicJwk, abeSecretKey: client.abeSecretKey },
  });
  return { status: 200, text: await out.blob.text(), meta: out.meta, record: rec.data };
}

async function main() {
  console.log(`SecureShare smoke test  api=${API}  authority=${AUTH}`);

  console.log('Services');
  check((await fetch(`${API}/api/health`)).status === 200, 'API health');
  check((await fetch(`${AUTH}/authority/health`)).status === 200, 'authority health');
  const params = await (await fetch(`${AUTH}/authority/params`)).json();
  check(params.publicKey?.scheme === 'fame-bls12381-v1', `authority publishes FAME public key (${params.fingerprint})`);
  const h = (await fetch(`${API}/api/health`)).headers;
  check(h.get('x-powered-by') === null && h.get('strict-transport-security') !== null, 'security headers present');
  check((await new Client('x').json('POST', `${API}/api/auth/login`, { json: {} })).status === 400, 'invalid input rejected');
  const noCsrf = await fetch(`${API}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  check(noCsrf.status === 403, 'state-changing request without CSRF header rejected');

  console.log('Accounts (password never sent; keys generated client-side)');
  const admin = new Client('admin');
  if (!(await login(admin, ADMIN, ADMIN_PW))) await register(admin, ADMIN, ADMIN_PW);
  check(admin.user.role === 'admin', `admin "${ADMIN}" signed in`);
  const [carol, alice, bob, eve] = await Promise.all(
    ['carol', 'alice', 'bob', 'eve'].map((n) => register(new Client(n), `${n}_${suffix}`, `pw-${n}-${suffix}-long`)),
  );
  check(Boolean(carol.user && alice.user && bob.user && eve.user), 'registered carol, alice, bob, eve');
  const wrong = await new Client('w').json('POST', `${API}/api/auth/login`, { json: { username: alice.user.username, authKey: 'A'.repeat(43) } });
  check(wrong.status === 401, 'wrong credentials rejected');

  console.log('Attribute authority');
  const assign = async (c, attributes) => {
    const r = await admin.json('PUT', `${AUTH}/authority/admin/users/${c.user.id}/attributes`, { json: { username: c.user.username, attributes } });
    if (r.status !== 200) throw new Error(`assign ${r.status} ${JSON.stringify(r.data)}`);
  };
  await assign(carol, ['dept:hr']);
  await assign(alice, ['dept:cse', 'role:faculty']);
  await assign(bob, ['dept:cse', 'role:student']);
  check((await alice.json('PUT', `${AUTH}/authority/admin/users/${alice.user.id}/attributes`, { json: { username: alice.user.username, attributes: ['role:admin'] } })).status === 403, 'non-admin cannot assign attributes');
  for (const c of [carol, alice, bob, eve]) await fetchKey(c);
  check(alice.abeSecretKey.attributes.join() === `dept:cse,role:faculty,user:${alice.user.username}`, 'alice key has dept:cse, role:faculty, user:alice');

  console.log('Encrypted sharing by policy');
  const content = `exam paper ${suffix} ${'x'.repeat(5000)}`;
  const id = await upload(carol, content, 'dept:cse AND role:faculty', params.publicKey);
  check(Boolean(id), 'carol encrypted and uploaded with policy "dept:cse AND role:faculty"');
  const listed = await alice.json('GET', `${API}/api/files?scope=shared`);
  check(listed.data.files.some((f) => f.id === id), 'file appears in alice\'s "shared with me"');
  const a = await fetchAndDecrypt(alice, id);
  check(a.text === content && a.meta.name === `smoke-${suffix}.txt`, 'alice verified signature and decrypted the file');
  check((await fetchAndDecrypt(carol, id)).text === content, 'owner decrypts own file');
  check((await fetchAndDecrypt(bob, id)).status === 404, 'bob (student) is refused by the server gate');
  check((await fetchAndDecrypt(eve, id)).status === 404, 'eve (no attributes) is refused by the server gate');
  let cryptoDenied = false;
  try {
    await recoverSecret(a.record, { id: bob.user.id, abeSecretKey: bob.abeSecretKey });
  } catch (err) {
    cryptoDenied = err instanceof PolicyNotSatisfiedError;
  }
  check(cryptoDenied, 'bob\'s CP-ABE key cannot unwrap the file key even with the record in hand');

  console.log('Revocation and policy change');
  await assign(alice, ['dept:cse']);
  await new Promise((r) => setTimeout(r, 5500)); // API caches attributes for 5 s
  check((await fetchAndDecrypt(alice, id)).status === 404, 'removing role:faculty blocks alice immediately');
  const rec = (await carol.json('GET', `${API}/api/files/${id}`)).data;
  const rw = await rewrapPolicy({ record: rec, newPolicy: `role:student OR user:${eve.user.username}`, abePublicKey: params.publicKey, owner: { id: carol.user.id, encPrivate: carol.encPrivate, encPublicJwk: carol.encPublicJwk, sigPrivate: carol.sigPrivate } });
  check((await carol.json('PUT', `${API}/api/files/${id}/policy`, { json: rw })).status === 200, 'carol re-wrapped the key under a new policy');
  check((await fetchAndDecrypt(bob, id)).text === content, 'bob (student) can now decrypt');
  check((await fetchAndDecrypt(eve, id)).text === content, 'eve (named via user:) can now decrypt');

  console.log('Sessions and audit');
  const stolen = carol.cookie;
  check((await carol.json('POST', `${API}/api/auth/logout`)).status === 204, 'logout');
  const replay = new Client('replay');
  replay.cookie = stolen;
  check((await replay.json('GET', `${API}/api/files`)).status === 401, 'old session token is revoked server-side after logout');
  const audit = await admin.json('GET', `${API}/api/admin/audit?limit=200`);
  check(audit.data.events.some((e) => e.action === 'file.access' && e.outcome === 'denied'), 'denied access attempts are audited');

  console.log(`\nAll ${passed} checks passed.`);
}

main().catch((err) => {
  console.error(`\n${err.stack || err.message}\n${passed} checks passed before the failure.`);
  process.exit(1);
});
