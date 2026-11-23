import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { generateKeyPair, exportSPKI, SignJWT } from 'jose';
import {
  generateIdentity, exportPublicJwk, openSealed, utf8, abe, randomBytes, toB64u,
} from '@secureshare/crypto';
import { createLogger, JWT_ISSUER, JWT_AUDIENCE } from '@secureshare/server-common';
import { createModels } from '../src/models.js';
import { createApps, loadOrCreateKeys, keySealAad } from '../src/app.js';
import { loadConfig } from '../src/config.js';

let mongod;
let conn;
let models;
let apps;
let keys;
let signer;
let config;
const logger = createLogger({ name: 'test', level: 'silent' });
const kek = randomBytes(32);
const INTERNAL = 'x'.repeat(40);

async function token({ sub, usr, role = 'user', ek }) {
  return new SignJWT({ usr, role, ek })
    .setProtectedHeader({ alg: 'ES256' })
    .setSubject(sub)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signer);
}

async function makeUser(username, role = 'user') {
  const id = new mongoose.Types.ObjectId().toString();
  const ident = await generateIdentity();
  const ek = await exportPublicJwk(ident.enc.publicKey);
  const jwt = await token({ sub: id, usr: username, role, ek });
  return { id, username, ek, priv: ident.enc.privateKey, cookie: `${config.cookieName}=${jwt}` };
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  conn = await mongoose.createConnection(mongod.getUri('authority_test')).asPromise();
  models = createModels(conn);
  const pair = await generateKeyPair('ES256');
  signer = pair.privateKey;
  config = loadConfig({
    AUTHORITY_KEK: toB64u(kek),
    INTERNAL_TOKEN: INTERNAL,
    JWT_PUBLIC_KEY: await exportSPKI(pair.publicKey),
    PUBLIC_ORIGIN: 'https://secureshare.test',
    COOKIE_SECURE: 'false',
  });
  keys = await loadOrCreateKeys(models, kek, logger);
  apps = await createApps({ config, models, keys, logger });
}, 120_000);

afterAll(async () => {
  await conn?.close();
  await mongod?.stop();
});

beforeEach(async () => {
  await models.Attributes.deleteMany({});
  await models.IssuedKey.deleteMany({});
});

const put = (path, cookie) => request(apps.app).put(path).set('Cookie', cookie).set('X-SecureShare-CSRF', '1');

describe('master key', () => {
  it('is stored sealed and reloads to the same public key', async () => {
    const state = await models.State.findById('fame').lean();
    expect(state.mskSealed).not.toContain(keys.msk.a1);
    const again = await loadOrCreateKeys(models, kek, logger);
    expect(again.fingerprint).toBe(keys.fingerprint);
    expect(again.msk).toEqual(keys.msk);
  });

  it('refuses to start with the wrong KEK', async () => {
    await expect(loadOrCreateKeys(models, randomBytes(32), logger)).rejects.toThrow(/AUTHORITY_KEK/);
  });

  it('publishes only the public key', async () => {
    const res = await request(apps.app).get('/authority/params').expect(200);
    expect(res.body.fingerprint).toBe(keys.fingerprint);
    expect(JSON.stringify(res.body)).not.toMatch(/"a1"|"b1"|gd1/);
  });
});

describe('key issuance', () => {
  it('requires a session', async () => {
    await request(apps.app).get('/authority/keys/me').expect(401);
  });

  it('issues a key sealed to the device key containing assigned + user: attributes', async () => {
    const admin = await makeUser('admin', 'admin');
    const alice = await makeUser('alice');
    await put(`/authority/admin/users/${alice.id}/attributes`, admin.cookie)
      .send({ username: 'alice', attributes: ['Dept:CSE', 'role:faculty', 'dept:cse'] })
      .expect(200);

    const res = await request(apps.app).get('/authority/keys/me').set('Cookie', alice.cookie).expect(200);
    expect(res.body.attributes).toEqual(['dept:cse', 'role:faculty', 'user:alice']);
    const sk = JSON.parse(utf8.decode(await openSealed(alice.priv, alice.ek, res.body.sealedKey, keySealAad(alice.id, res.body.version))));
    expect(sk.attributes).toEqual(['dept:cse', 'role:faculty', 'user:alice']);

    // The key actually decrypts a matching policy.
    const secret = randomBytes(32);
    const env = await abe.wrapSecret({ publicKey: keys.publicKey, policy: 'dept:cse AND role:faculty', secret, fileId: 'f' });
    expect(await abe.unwrapSecret({ secretKey: sk, envelope: env, fileId: 'f' })).toEqual(secret);

    // Cached on the second call; re-issued after an attribute change.
    const again = await request(apps.app).get('/authority/keys/me').set('Cookie', alice.cookie).expect(200);
    expect(again.body.sealedKey).toBe(res.body.sealedKey);
    await put(`/authority/admin/users/${alice.id}/attributes`, admin.cookie).send({ username: 'alice', attributes: ['role:student'] }).expect(200);
    const changed = await request(apps.app).get('/authority/keys/me').set('Cookie', alice.cookie).expect(200);
    expect(changed.body.version).toBe(res.body.version + 1);
    expect(changed.body.attributes).toEqual(['role:student', 'user:alice']);
  });

  it('a sealed key cannot be opened by another device', async () => {
    const bob = await makeUser('bob');
    const eve = await makeUser('eve');
    const res = await request(apps.app).get('/authority/keys/me').set('Cookie', bob.cookie).expect(200);
    await expect(openSealed(eve.priv, eve.ek, res.body.sealedKey, keySealAad(bob.id, 0))).rejects.toThrow();
  });

  it('rejects forged or expired-looking tokens', async () => {
    const other = await generateKeyPair('ES256');
    const forged = await new SignJWT({ usr: 'x', role: 'admin' }).setProtectedHeader({ alg: 'ES256' }).setSubject('a'.repeat(24))
      .setIssuer(JWT_ISSUER).setAudience(JWT_AUDIENCE).setExpirationTime('5m').sign(other.privateKey);
    await request(apps.app).get('/authority/admin/users').set('Cookie', `${config.cookieName}=${forged}`).expect(401);
  });
});

describe('administration', () => {
  it('is restricted to admins and validates attributes', async () => {
    const admin = await makeUser('root', 'admin');
    const user = await makeUser('carol');
    await put(`/authority/admin/users/${user.id}/attributes`, user.cookie).send({ username: 'carol', attributes: ['x:y'] }).expect(403);
    await put(`/authority/admin/users/${user.id}/attributes`, admin.cookie).send({ username: 'carol', attributes: ['user:root'] }).expect(400);
    await put(`/authority/admin/users/${user.id}/attributes`, admin.cookie).send({ username: 'carol', attributes: ['no-colon'] }).expect(400);
    await put(`/authority/admin/users/${user.id}/attributes`, admin.cookie).send({ username: 'carol', attributes: [], extra: 1 }).expect(400);
    await put('/authority/admin/users/not-an-id/attributes', admin.cookie).send({ username: 'carol', attributes: [] }).expect(400);
    const list = await request(apps.app).get('/authority/admin/users').set('Cookie', admin.cookie).expect(200);
    expect(list.body.users).toEqual([]);
    const audit = await request(apps.app).get('/authority/admin/audit').set('Cookie', admin.cookie).expect(200);
    expect(Array.isArray(audit.body.events)).toBe(true);
    await put(`/authority/admin/users/${user.id}/attributes`, admin.cookie).send({ username: 'carol', attributes: ['dept:law', 'year:2026'] }).expect(200);
    const catalog = await request(apps.app).get('/authority/catalog').set('Cookie', user.cookie).expect(200);
    expect(catalog.body.attributes).toEqual(['dept:law', 'year:2026']);
  });

  it('requires the CSRF header and same origin for writes', async () => {
    const admin = await makeUser('root2', 'admin');
    await request(apps.app).put(`/authority/admin/users/${admin.id}/attributes`).set('Cookie', admin.cookie)
      .send({ username: 'root2', attributes: [] }).expect(403);
    await put(`/authority/admin/users/${admin.id}/attributes`, admin.cookie).set('Origin', 'https://evil.example')
      .send({ username: 'root2', attributes: [] }).expect(403);
  });
});

describe('internal API', () => {
  it('requires the service token', async () => {
    const id = new mongoose.Types.ObjectId().toString();
    await request(apps.internal).get(`/internal/users/${id}/attributes`).expect(401);
    await request(apps.internal).get(`/internal/users/${id}/attributes`).set('Authorization', 'Bearer wrong').expect(401);
    const res = await request(apps.internal).get(`/internal/users/${id}/attributes`).set('Authorization', `Bearer ${INTERNAL}`).expect(200);
    expect(res.body).toEqual({ attributes: [], version: 0 });
  });

  it('is not reachable through the public app', async () => {
    const id = new mongoose.Types.ObjectId().toString();
    await request(apps.app).get(`/internal/users/${id}/attributes`).set('Authorization', `Bearer ${INTERNAL}`).expect(404);
  });
});
