import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { newKdfParams, generateIdentity, exportPublicJwk, toB64u, randomBytes } from '@secureshare/crypto';
import { startTestEnv, registerUser, csrf } from './helpers.js';

let env;
beforeAll(async () => {
  env = await startTestEnv({ MAX_FAILED_LOGINS: '3' });
}, 120_000);
afterAll(() => env?.stop());

const login = (username, authKey) =>
  request(env.app).post('/api/auth/login').set('X-SecureShare-CSRF', '1').send({ username, authKey });

describe('registration', () => {
  it('creates the account, sets a hardened session cookie and stores only public data + vault', async () => {
    const u = await registerUser(env, 'alice');
    expect(u.role).toBe('user');
    const doc = await env.models.User.findOne({ username: 'alice' }).lean();
    expect(doc.authHash).toMatch(/^\$argon2id\$/);
    expect(JSON.stringify(doc)).not.toContain(u.authKey);
    const res = await login('alice', u.authKey).expect(200);
    const cookie = res.headers['set-cookie'][0];
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Strict/);
  });

  it('makes the bootstrap admin an admin', async () => {
    expect((await registerUser(env, 'admin')).role).toBe('admin');
  });

  it('rejects duplicates, weak KDF settings, unknown fields and missing CSRF header', async () => {
    await registerUser(env, 'bob');
    await expect(registerUser(env, 'bob')).rejects.toThrow(/409/);
    const ident = await generateIdentity();
    const base = {
      username: 'carol', kdf: newKdfParams(), authKey: toB64u(randomBytes(32)),
      encPublicKey: await exportPublicJwk(ident.enc.publicKey), sigPublicKey: await exportPublicJwk(ident.sig.publicKey),
      vault: toB64u(randomBytes(300)),
    };
    const post = (b) => request(env.app).post('/api/auth/register').set('X-SecureShare-CSRF', '1').send(b);
    await post({ ...base, kdf: { ...base.kdf, iterations: 1000 } }).expect(400);
    await post({ ...base, role: 'admin' }).expect(400);
    await post({ ...base, username: 'x' }).expect(400);
    await post({ ...base, username: { $gt: '' } }).expect(400);
    await request(env.app).post('/api/auth/register').send(base).expect(403);
    await request(env.app).post('/api/auth/register').set('X-SecureShare-CSRF', '1').set('Origin', 'https://evil.example').send(base).expect(403);
    await request(env.app).post('/api/auth/register').set('X-SecureShare-CSRF', '1').set('Sec-Fetch-Site', 'cross-site').send(base).expect(403);
  });
});

describe('login', () => {
  it('returns KDF params for known users and stable fake params for unknown ones', async () => {
    await registerUser(env, 'dave');
    const known = await request(env.app).get('/api/auth/params?username=dave').expect(200);
    const doc = await env.models.User.findOne({ username: 'dave' }).lean();
    expect(known.body.salt).toBe(doc.kdf.salt);
    const a = await request(env.app).get('/api/auth/params?username=nobody_here').expect(200);
    const b = await request(env.app).get('/api/auth/params?username=nobody_here').expect(200);
    expect(a.body).toEqual(b.body);
    expect(Object.keys(a.body).sort()).toEqual(Object.keys(known.body).sort());
  });

  it('gives the same error for wrong key and unknown user', async () => {
    await registerUser(env, 'erin');
    const wrong = await login('erin', toB64u(randomBytes(32))).expect(401);
    const unknown = await login('nobody_here', toB64u(randomBytes(32))).expect(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  it('locks the account after repeated failures; admin can unlock', async () => {
    const u = await registerUser(env, 'frank');
    for (let i = 0; i < 3; i++) await login('frank', toB64u(randomBytes(32))).expect(401);
    await login('frank', u.authKey).expect(429);
    const adm = await registerUser(env, 'root_admin');
    await env.models.User.updateOne({ username: 'root_admin' }, { role: 'admin' });
    const fresh = await login('root_admin', adm.authKey).expect(200);
    const admCookie = fresh.headers['set-cookie'][0].split(';')[0];
    await csrf(request(env.app).post(`/api/admin/users/${u.id}/unlock`), admCookie).expect(204);
    await login('frank', u.authKey).expect(200);
  });

  it('logout revokes the session token', async () => {
    const u = await registerUser(env, 'gina');
    await request(env.app).get('/api/auth/me').set('Cookie', u.cookie).expect(200);
    await csrf(request(env.app).post('/api/auth/logout'), u.cookie).expect(204);
    await request(env.app).get('/api/auth/me').set('Cookie', u.cookie).expect(401);
  });

  it('rejects tampered tokens', async () => {
    const u = await registerUser(env, 'hank');
    const [name, value] = u.cookie.split('=');
    const parts = value.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
    payload.role = 'admin';
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    await request(env.app).get('/api/admin/users').set('Cookie', `${name}=${parts.join('.')}`).expect(401);
  });
});

describe('admin', () => {
  it('is admin-only', async () => {
    const u = await registerUser(env, 'ivan');
    await request(env.app).get('/api/admin/users').set('Cookie', u.cookie).expect(403);
    await request(env.app).get('/api/admin/audit').set('Cookie', u.cookie).expect(403);
  });

  it('lists users and the audit log without secrets', async () => {
    const adm = await registerUser(env, 'auditor');
    await env.models.User.updateOne({ username: 'auditor' }, { role: 'admin' });
    const res = await login('auditor', adm.authKey).expect(200);
    const cookie = res.headers['set-cookie'][0].split(';')[0];
    const users = await request(env.app).get('/api/admin/users').set('Cookie', cookie).expect(200);
    expect(users.body.users.find((x) => x.username === 'alice')).toBeTruthy();
    expect(JSON.stringify(users.body)).not.toMatch(/authHash|vault/);
    const audit = await request(env.app).get('/api/admin/audit').set('Cookie', cookie).expect(200);
    expect(audit.body.events.some((e) => e.action === 'user.login' && e.outcome === 'denied')).toBe(true);
  });
});

describe('transport hardening', () => {
  it('sets security headers and hides the framework', async () => {
    const res = await request(env.app).get('/api/health').expect(200);
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['strict-transport-security']).toBeTruthy();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('rejects oversized and malformed JSON', async () => {
    await request(env.app).post('/api/auth/login').set('X-SecureShare-CSRF', '1').set('Content-Type', 'application/json').send('{bad').expect(400);
    await request(env.app).post('/api/auth/login').set('X-SecureShare-CSRF', '1').send({ username: 'a'.repeat(200 * 1024) }).expect(413);
  });
});
