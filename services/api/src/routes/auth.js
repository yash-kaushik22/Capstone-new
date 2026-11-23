import { createHmac, randomBytes } from 'node:crypto';
import express from 'express';
import argon2 from 'argon2';
import { SignJWT, importPKCS8 } from 'jose';
import { z } from 'zod';
import { KDF_ALG } from '@secureshare/crypto';
import { AppError, JWT_AUDIENCE, JWT_ISSUER, limiter } from '@secureshare/server-common';

// OWASP Argon2id baseline (19 MiB, t=2, p=1).
const ARGON = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };
const usernameSchema = z.string().trim().toLowerCase().regex(/^[a-z0-9_]{3,32}$/, 'username: 3-32 chars, a-z 0-9 _');
const b64u = (n) => z.string().regex(new RegExp(`^[A-Za-z0-9_-]{${n}}$`));
const jwk = z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: b64u(43), y: b64u(43) });

export function publicUser(u) {
  return {
    id: String(u._id),
    username: u.username,
    role: u.role,
    encPublicKey: { kty: u.encPublicKey.kty, crv: u.encPublicKey.crv, x: u.encPublicKey.x, y: u.encPublicKey.y },
    sigPublicKey: { kty: u.sigPublicKey.kty, crv: u.sigPublicKey.crv, x: u.sigPublicKey.x, y: u.sigPublicKey.y },
  };
}

export async function authRouter({ config, models, audit, session }) {
  const { User, RevokedToken } = models;
  const router = express.Router();
  const signingKey = await importPKCS8(config.jwtPrivateKeyPem, 'ES256');
  const dummyHash = await argon2.hash(randomBytes(32), ARGON); // equalises timing for unknown users

  const authLimiter = limiter({ windowMs: 15 * 60_000, limit: config.authRateLimit, message: 'Too many attempts, try again later' });
  const paramsLimiter = limiter({ windowMs: 15 * 60_000, limit: config.authRateLimit * 3 });

  const registerBody = z.strictObject({
    username: usernameSchema,
    kdf: z.strictObject({ alg: z.literal(KDF_ALG), iterations: z.number().int().min(config.kdfIterations).max(10_000_000), salt: b64u(22) }),
    authKey: b64u(43),
    encPublicKey: jwk,
    sigPublicKey: jwk,
    vault: z.string().regex(/^[A-Za-z0-9_-]{100,4096}$/),
  });
  const loginBody = z.strictObject({ username: usernameSchema, authKey: b64u(43) });

  async function startSession(res, user) {
    const jwt = await new SignJWT({ usr: user.username, role: user.role, ek: publicUser(user).encPublicKey })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .setSubject(String(user._id))
      .setIssuer(JWT_ISSUER)
      .setAudience(JWT_AUDIENCE)
      .setJti(randomBytes(16).toString('base64url'))
      .setIssuedAt()
      .setExpirationTime(`${config.jwtTtlSeconds}s`)
      .sign(signingKey);
    res.cookie(config.cookieName, jwt, {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'strict',
      path: '/',
      maxAge: config.jwtTtlSeconds * 1000,
    });
  }

  // Public KDF parameters. Unknown usernames get stable fake parameters (no account enumeration).
  router.get('/params', paramsLimiter, async (req, res) => {
    const username = usernameSchema.parse(req.query.username);
    const user = await User.findOne({ username }).select('kdf').lean();
    if (user) return res.json(user.kdf);
    const salt = createHmac('sha256', config.serverSecret).update(`kdf-salt|${username}`).digest().subarray(0, 16).toString('base64url');
    return res.json({ alg: KDF_ALG, iterations: config.kdfIterations, salt });
  });

  router.post('/register', authLimiter, async (req, res) => {
    if (!config.registrationOpen) throw new AppError(403, 'Registration is closed');
    const body = registerBody.parse(req.body);
    if (await User.exists({ username: body.username })) throw new AppError(409, 'Username is taken');
    const user = await User.create({
      username: body.username,
      role: config.bootstrapAdmin && body.username === config.bootstrapAdmin ? 'admin' : 'user',
      kdf: body.kdf,
      authHash: await argon2.hash(body.authKey, ARGON),
      encPublicKey: body.encPublicKey,
      sigPublicKey: body.sigPublicKey,
      vault: body.vault,
    });
    await startSession(res, user);
    audit(req, 'user.register', { target: user.username, user });
    res.status(201).json({ user: publicUser(user), vault: user.vault });
  });

  router.post('/login', authLimiter, async (req, res) => {
    const { username, authKey } = loginBody.parse(req.body);
    const user = await User.findOne({ username });
    if (user?.lockedUntil && user.lockedUntil > new Date()) {
      audit(req, 'user.login', { target: username, outcome: 'denied', details: { reason: 'locked' } });
      throw new AppError(429, 'Too many failed attempts. Try again later.');
    }
    const ok = await argon2.verify(user?.authHash ?? dummyHash, authKey);
    if (!user || !ok) {
      if (user) {
        user.failedLogins += 1;
        if (user.failedLogins >= config.maxFailedLogins) {
          user.lockedUntil = new Date(Date.now() + config.lockoutMinutes * 60_000);
          user.failedLogins = 0;
        }
        await user.save();
      }
      audit(req, 'user.login', { target: username, outcome: 'denied' });
      throw new AppError(401, 'Invalid username or password');
    }
    if (user.failedLogins || user.lockedUntil) {
      user.failedLogins = 0;
      user.lockedUntil = null;
      await user.save();
    }
    await startSession(res, user);
    audit(req, 'user.login', { target: username, user });
    res.json({ user: publicUser(user), vault: user.vault });
  });

  router.post('/logout', session.requireUser, async (req, res) => {
    await RevokedToken.updateOne(
      { _id: req.session.jti },
      { $set: { expiresAt: new Date(req.session.exp * 1000) } },
      { upsert: true },
    );
    res.clearCookie(config.cookieName, { httpOnly: true, secure: config.cookieSecure, sameSite: 'strict', path: '/' });
    audit(req, 'user.logout', {});
    res.status(204).end();
  });

  router.get('/me', session.requireUser, async (req, res) => {
    const user = await User.findById(req.user.id);
    if (!user) throw new AppError(401, 'Not signed in');
    res.json({ user: publicUser(user), vault: user.vault, kdf: user.kdf });
  });

  return router;
}
