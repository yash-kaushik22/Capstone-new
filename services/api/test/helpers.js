import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import mongoose from 'mongoose';
import request from 'supertest';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import {
  abe, generateIdentity, exportPublicJwk, newKdfParams, randomBytes, toB64u, encryptForUpload,
} from '@secureshare/crypto';
import { AppError, createLogger } from '@secureshare/server-common';
import { createModels } from '../src/models.js';
import { createStorage } from '../src/storage.js';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

export async function startTestEnv(overrides = {}) {
  const mongod = await MongoMemoryServer.create();
  const conn = await mongoose.createConnection(mongod.getUri('api_test')).asPromise();
  const models = createModels(conn);
  await Promise.all(Object.values(models).map((m) => m.init()));
  const dir = await mkdtemp(path.join(tmpdir(), 'ss-blobs-'));
  const storage = await createStorage(dir);
  const pair = await generateKeyPair('ES256', { extractable: true });
  const config = loadConfig({
    SERVER_SECRET: 's'.repeat(40),
    INTERNAL_TOKEN: 'i'.repeat(40),
    JWT_PRIVATE_KEY: await exportPKCS8(pair.privateKey),
    JWT_PUBLIC_KEY: await exportSPKI(pair.publicKey),
    COOKIE_SECURE: 'false',
    PUBLIC_ORIGIN: 'https://secureshare.test',
    BOOTSTRAP_ADMIN: 'admin',
    MAX_UPLOAD_BYTES: String(64 * 1024),
    AUTH_RATE_LIMIT: '1000',
    ...overrides,
  });

  // In-process stand-in for the attribute authority's internal endpoint.
  const attributes = new Map();
  const authority = {
    down: false,
    async attributesOf(userId) {
      if (this.down) throw new AppError(503, 'Attribute authority unavailable');
      return attributes.get(userId) ?? [];
    },
  };
  const logger = createLogger({ name: 'test', level: 'silent' });
  const app = await createApp({ config, models, storage, authority, logger });
  const { pk, msk } = abe.fame.setup();

  return {
    app, config, models, storage, dir, authority, attributes, abePk: pk, abeMsk: msk,
    async stop() {
      await conn.close();
      await mongod.stop();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/** Register a user the way the client does (keys generated locally; authKey is random here). */
export async function registerUser(env, username) {
  const ident = await generateIdentity();
  const body = {
    username,
    kdf: newKdfParams(),
    authKey: toB64u(randomBytes(32)),
    encPublicKey: await exportPublicJwk(ident.enc.publicKey),
    sigPublicKey: await exportPublicJwk(ident.sig.publicKey),
    vault: toB64u(randomBytes(300)),
  };
  const res = await request(env.app).post('/api/auth/register').set('X-SecureShare-CSRF', '1').send(body);
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  const cookie = res.headers['set-cookie'][0].split(';')[0];
  return {
    ...res.body.user,
    authKey: body.authKey,
    cookie,
    encPublicJwk: body.encPublicKey,
    sigPublicJwk: body.sigPublicKey,
    encPrivate: ident.enc.privateKey,
    sigPrivate: ident.sig.privateKey,
  };
}

export const csrf = (req, cookie) => req.set('X-SecureShare-CSRF', '1').set('Cookie', cookie);

/** Encrypt + register + upload. Returns the upload bundle. */
export async function uploadFile(env, owner, { content = 'top secret', name = 'secret.txt', policy = 'dept:cse' } = {}) {
  const up = await encryptForUpload({
    file: new Blob([content]),
    meta: { name, type: 'text/plain' },
    policy,
    abePublicKey: env.abePk,
    owner: { id: owner.id, encPublicJwk: owner.encPublicJwk, sigPrivate: owner.sigPrivate },
  });
  const meta = {
    fileId: up.fileId, encMeta: up.encMeta, abeEnvelope: up.abeEnvelope, ownerEnvelope: up.ownerEnvelope,
    manifest: up.manifest, signature: up.signature,
  };
  const r1 = await csrf(request(env.app).post('/api/files'), owner.cookie).send(meta);
  if (r1.status !== 201) throw new Error(`create failed ${r1.status} ${JSON.stringify(r1.body)}`);
  const bytes = Buffer.from(await up.ciphertext.arrayBuffer());
  const r2 = await csrf(request(env.app).put(`/api/files/${up.fileId}/blob`), owner.cookie)
    .set('Content-Type', 'application/octet-stream').send(bytes);
  if (r2.status !== 204) throw new Error(`blob failed ${r2.status} ${JSON.stringify(r2.body)}`);
  return { ...up, meta, bytes };
}
