import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import request from 'supertest';
import {
  abe, decryptDownload, rewrapPolicy, signObject, encryptForUpload, PolicyNotSatisfiedError,
} from '@secureshare/crypto';
import { startTestEnv, registerUser, csrf, uploadFile } from './helpers.js';

let env;
let owner;
let faculty;
let student;
let outsider;

beforeAll(async () => {
  env = await startTestEnv();
  owner = await registerUser(env, 'owner');
  faculty = await registerUser(env, 'faculty1');
  student = await registerUser(env, 'student1');
  outsider = await registerUser(env, 'outsider');
  env.attributes.set(faculty.id, ['dept:cse', 'role:faculty']);
  env.attributes.set(student.id, ['dept:cse', 'role:student']);
  env.attributes.set(outsider.id, ['dept:ece']);
}, 120_000);
afterAll(() => env?.stop());

const get = (url, user) => request(env.app).get(url).set('Cookie', user.cookie);
const keyFor = (user) => abe.fame.keygen(env.abeMsk, [...env.attributes.get(user.id), `user:${user.username}`]);

async function download(user, id) {
  const rec = (await get(`/api/files/${id}`, user).expect(200)).body;
  const blob = await get(`/api/files/${id}/blob`, user).buffer(true).parse((res, cb) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => cb(null, Buffer.concat(chunks)));
  }).expect(200);
  const me = { id: user.id, encPrivate: user.encPrivate, encPublicJwk: user.encPublicJwk, abeSecretKey: rec.ownerId === user.id ? null : keyFor(user) };
  return decryptDownload({ record: rec, ciphertext: new Blob([blob.body]), ownerSigJwk: rec.ownerSigPublicKey, me });
}

describe('upload and policy-gated download', () => {
  it('owner and policy-satisfying users get the file; others see nothing', async () => {
    const up = await uploadFile(env, owner, { content: 'exam answers', name: 'answers.txt', policy: 'dept:cse AND role:faculty' });

    for (const who of [owner, faculty]) {
      const out = await download(who, up.fileId);
      expect(await out.blob.text()).toBe('exam answers');
      expect(out.meta.name).toBe('answers.txt');
    }
    const shared = await get('/api/files?scope=shared', faculty).expect(200);
    expect(shared.body.files.map((f) => f.id)).toContain(up.fileId);
    const owned = await get('/api/files', owner).expect(200);
    expect(owned.body.files.map((f) => f.id)).toContain(up.fileId);

    for (const who of [student, outsider]) {
      expect((await get('/api/files?scope=shared', who).expect(200)).body.files.map((f) => f.id)).not.toContain(up.fileId);
      await get(`/api/files/${up.fileId}`, who).expect(404);
      await get(`/api/files/${up.fileId}/blob`, who).expect(404);
    }
  });

  it('even if the server gate were bypassed, the wrong attributes cannot decrypt', async () => {
    const up = await uploadFile(env, owner, { policy: 'role:faculty' });
    const rec = (await get(`/api/files/${up.fileId}`, owner).expect(200)).body;
    await expect(decryptDownload({
      record: rec, ciphertext: up.ciphertext, ownerSigJwk: rec.ownerSigPublicKey,
      me: { id: student.id, abeSecretKey: keyFor(student) },
    })).rejects.toThrow(PolicyNotSatisfiedError);
  });

  it('revoking an attribute at the authority blocks downloads immediately', async () => {
    const up = await uploadFile(env, owner, { policy: 'role:faculty' });
    await get(`/api/files/${up.fileId}/blob`, faculty).expect(200);
    env.attributes.set(faculty.id, ['dept:cse']);
    await get(`/api/files/${up.fileId}/blob`, faculty).expect(404);
    env.attributes.set(faculty.id, ['dept:cse', 'role:faculty']);
  });

  it('fails closed when the authority is down (owner still has access)', async () => {
    const up = await uploadFile(env, owner, { policy: 'role:faculty' });
    env.authority.down = true;
    try {
      await get(`/api/files/${up.fileId}`, faculty).expect(503);
      await get('/api/files?scope=shared', faculty).expect(503);
      await get(`/api/files/${up.fileId}`, owner).expect(200);
    } finally {
      env.authority.down = false;
    }
  });

  it('targets a single user with user:<name>', async () => {
    const up = await uploadFile(env, owner, { policy: 'user:student1' });
    expect(await (await download(student, up.fileId)).blob.text()).toBe('top secret');
    await get(`/api/files/${up.fileId}`, faculty).expect(404);
  });

  it('stores only ciphertext: no plaintext or file name on disk or in the database', async () => {
    const marker = 'PLAINTEXT-MARKER-91c2';
    const up = await uploadFile(env, owner, { content: marker.repeat(20), name: 'marker-name-77.txt', policy: 'role:faculty' });
    const files = (await readdir(env.dir)).filter((f) => /^[a-f0-9]{48}$/.test(f));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const buf = await readFile(path.join(env.dir, f));
      expect(buf.includes(Buffer.from(marker))).toBe(false);
    }
    const dump = JSON.stringify(await env.models.File.findById(up.fileId).lean());
    expect(dump).not.toContain(marker);
    expect(dump).not.toContain('marker-name-77');
  });
});

describe('upload validation', () => {
  async function prepared(overrides = {}) {
    const up = await encryptForUpload({
      file: new Blob(['x'.repeat(100)]), meta: { name: 'a.txt' }, policy: 'dept:cse', abePublicKey: env.abePk,
      owner: { id: owner.id, encPublicJwk: owner.encPublicJwk, sigPrivate: owner.sigPrivate },
    });
    return {
      up,
      body: { fileId: up.fileId, encMeta: up.encMeta, abeEnvelope: up.abeEnvelope, ownerEnvelope: up.ownerEnvelope, manifest: up.manifest, signature: up.signature, ...overrides },
    };
  }
  const create = (body, user = owner) => csrf(request(env.app).post('/api/files'), user.cookie).send(body);

  it('rejects a manifest signed by someone else', async () => {
    const { up, body } = await prepared();
    const forged = await signObject(student.sigPrivate, up.manifest);
    await create({ ...body, signature: forged }).expect(400);
    await create(body, student).expect(400); // student submitting owner's manifest
  });

  it('rejects mismatched metadata, non-canonical policy and malformed envelopes', async () => {
    const { up, body } = await prepared();
    await create({ ...body, encMeta: `${up.encMeta}AA` }).expect(400);
    await create({ ...body, abeEnvelope: { ...up.abeEnvelope, policy: 'DEPT:CSE' } }).expect(400);
    await create({ ...body, abeEnvelope: { ...up.abeEnvelope, header: { ...up.abeEnvelope.header, rows: [] } } }).expect(400);
    await create({ ...body, abeEnvelope: { ...up.abeEnvelope, extra: 1 } }).expect(400);
    await create({ ...body, fileId: '../../etc/passwd' }).expect(400);
  });

  it('accepts ciphertext only if it matches the signed size and hash, exactly once', async () => {
    const { up, body } = await prepared();
    await create(body).expect(201);
    await create(body).expect(409);
    const bytes = Buffer.from(await up.ciphertext.arrayBuffer());
    const put = () => csrf(request(env.app).put(`/api/files/${up.fileId}/blob`), owner.cookie).set('Content-Type', 'application/octet-stream');
    const tampered = Buffer.from(bytes);
    tampered[40] ^= 1;
    await put().send(tampered).expect(400);
    await put().send(bytes.subarray(0, bytes.length - 1)).expect(400);
    await get(`/api/files/${up.fileId}`, owner).expect(404); // still pending
    await put().set('Content-Type', 'text/plain').send(bytes.toString('latin1')).expect(415);
    await put().send(bytes).expect(204);
    await put().send(bytes).expect(409);
    // Only the owner can upload the blob.
    const other = await prepared();
    await create(other.body).expect(201);
    await csrf(request(env.app).put(`/api/files/${other.up.fileId}/blob`), faculty.cookie)
      .set('Content-Type', 'application/octet-stream').send(Buffer.from(await other.up.ciphertext.arrayBuffer())).expect(404);
  });

  it('enforces the upload size limit', async () => {
    const up = await encryptForUpload({
      file: new Blob([new Uint8Array(70 * 1024)]), meta: { name: 'big' }, policy: 'dept:cse', abePublicKey: env.abePk,
      owner: { id: owner.id, encPublicJwk: owner.encPublicJwk, sigPrivate: owner.sigPrivate },
    });
    await create({ fileId: up.fileId, encMeta: up.encMeta, abeEnvelope: up.abeEnvelope, ownerEnvelope: up.ownerEnvelope, manifest: up.manifest, signature: up.signature }).expect(413);
  });

  it('requires a session', async () => {
    await request(env.app).get('/api/files').expect(401);
    await request(env.app).get('/api/files/AAAAAAAAAAAAAAAAAAAAAA/blob').expect(401);
  });
});

describe('policy change and deletion', () => {
  it('owner re-wraps under a new policy; access follows the new policy', async () => {
    const up = await uploadFile(env, owner, { content: 'moving target', policy: 'role:faculty' });
    const rec = (await get(`/api/files/${up.fileId}`, owner).expect(200)).body;
    const rw = await rewrapPolicy({
      record: rec, newPolicy: 'role:student', abePublicKey: env.abePk,
      owner: { id: owner.id, encPrivate: owner.encPrivate, encPublicJwk: owner.encPublicJwk, sigPrivate: owner.sigPrivate },
    });
    await csrf(request(env.app).put(`/api/files/${up.fileId}/policy`), faculty.cookie).send(rw).expect(404);
    await csrf(request(env.app).put(`/api/files/${up.fileId}/policy`), owner.cookie)
      .send({ ...rw, manifest: { ...rw.manifest, encMetaSha256: '0'.repeat(64) } }).expect(400);
    await csrf(request(env.app).put(`/api/files/${up.fileId}/policy`), owner.cookie).send(rw).expect(200);
    expect(await (await download(student, up.fileId)).blob.text()).toBe('moving target');
    await get(`/api/files/${up.fileId}`, faculty).expect(404);
  });

  it('only the owner can delete; the blob is removed', async () => {
    const up = await uploadFile(env, owner, { policy: 'role:faculty' });
    const { blobName } = await env.models.File.findById(up.fileId).lean();
    await csrf(request(env.app).delete(`/api/files/${up.fileId}`), faculty.cookie).expect(404);
    await csrf(request(env.app).delete(`/api/files/${up.fileId}`), owner.cookie).expect(204);
    expect((await readdir(env.dir)).includes(blobName)).toBe(false);
    await get(`/api/files/${up.fileId}`, owner).expect(404);
  });

  it('records downloads and denials in the audit log', async () => {
    const events = await env.models.Audit.find().lean();
    expect(events.some((e) => e.action === 'file.download' && e.username === 'faculty1')).toBe(true);
    expect(events.some((e) => e.action === 'file.access' && e.outcome === 'denied')).toBe(true);
  });
});
