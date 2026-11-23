import express from 'express';
import { z } from 'zod';
import {
  abe, aead, canonicalJson, sealTo, sha256, toHex, utf8, policy as policyLib, fromB64u,
} from '@secureshare/crypto';
import {
  AppError, applyBaseSecurity, csrfGuard, errorHandler, httpLogger, limiter, notFound,
  requireInternalToken, sessionVerifier,
} from '@secureshare/server-common';

const KEK_INFO = 'secureshare/v2/authority-kek';
const MSK_AAD = 'secureshare/v2/authority-msk';
const userIdSchema = z.string().regex(/^[a-f0-9]{24}$/);
const ekSchema = z.object({
  kty: z.literal('EC'),
  crv: z.literal('P-256'),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  y: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});
const attributesBody = z.strictObject({
  username: z.string().regex(/^[a-z0-9_]{3,32}$/),
  attributes: z.array(z.string().max(100)).max(64),
});

/** Load the FAME keys, creating and sealing them on first start. */
export async function loadOrCreateKeys({ State }, kekBytes, logger) {
  const kek = await aead.hkdfAesKey(kekBytes, { info: KEK_INFO });
  let state = await State.findById('fame').lean();
  if (!state) {
    const { pk, msk } = abe.fame.setup();
    const mskSealed = canonicalJson({ v: 1, ct: Buffer.from(await aead.seal(kek, utf8.encode(JSON.stringify(msk)), MSK_AAD)).toString('base64url') });
    try {
      await State.create({ _id: 'fame', publicKey: pk, mskSealed });
      logger?.info('generated new CP-ABE master key pair');
    } catch (err) {
      if (err?.code !== 11000) throw err; // another replica won the race
    }
    state = await State.findById('fame').lean();
  }
  let msk;
  try {
    const { ct } = JSON.parse(state.mskSealed);
    msk = JSON.parse(utf8.decode(await aead.open(kek, fromB64u(ct), MSK_AAD)));
  } catch {
    throw new Error('Cannot unseal the CP-ABE master key: wrong AUTHORITY_KEK?');
  }
  return { publicKey: state.publicKey, msk, fingerprint: await abe.publicKeyFingerprint(state.publicKey) };
}

export const userAttribute = (username) => `user:${username}`;

function normalizeAssigned(list) {
  const out = new Set();
  for (const raw of list) {
    const attr = policyLib.normalizeAttribute(raw);
    if (attr.startsWith('user:')) throw new AppError(400, 'The user: attribute is assigned automatically');
    out.add(attr);
  }
  return [...out].sort();
}

const thumbprint = async (jwk) => toHex(await sha256(utf8.encode(canonicalJson({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }))));

export async function createApps({ config, models, keys, logger }) {
  const { Attributes, IssuedKey, Audit } = models;
  const session = await sessionVerifier({ publicKeyPem: config.jwtPublicKeyPem, cookieName: config.cookieName });
  const audit = (req, action, target, details) =>
    Audit.create({ actor: req.user?.username, action, target, details }).catch((err) => logger.error({ err }, 'audit write failed'));

  // ------------------------------------------------------------ public app (behind the reverse proxy at /authority)
  const app = express();
  applyBaseSecurity(app, { trustProxy: config.trustProxy });
  app.use(httpLogger(logger));
  app.use(limiter({ windowMs: 60_000, limit: 300 }));
  app.use(express.json({ limit: '32kb' }));
  app.use(csrfGuard({ publicOrigin: config.publicOrigin }));

  const r = express.Router();
  r.get('/health', (_req, res) => res.json({ status: 'ok' }));

  r.get('/params', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300');
    res.json({ scheme: abe.SCHEME, publicKey: keys.publicKey, fingerprint: keys.fingerprint });
  });

  r.get('/me', session.requireUser, async (req, res) => {
    const rec = await Attributes.findOne({ userId: req.user.id }).lean();
    res.json({ attributes: [...(rec?.attributes ?? []), userAttribute(req.user.username)], version: rec?.version ?? 0 });
  });

  // Attribute names in use (no user mapping), to help owners write policies.
  r.get('/catalog', session.requireUser, async (_req, res) => {
    const attributes = (await Attributes.distinct('attributes')).sort();
    res.json({ attributes });
  });

  // Issue (or return the cached) CP-ABE secret key, sealed to the caller's device encryption key.
  r.get('/keys/me', session.requireUser, limiter({ windowMs: 60_000, limit: 30, keyGenerator: (req) => req.user.id }), async (req, res) => {
    const ek = ekSchema.safeParse(req.session.ek);
    if (!ek.success) throw new AppError(400, 'Session has no device key');
    const rec = await Attributes.findOne({ userId: req.user.id }).lean();
    const version = rec?.version ?? 0;
    const ekThumbprint = await thumbprint(ek.data);
    let issued = await IssuedKey.findOne({ userId: req.user.id }).lean();
    if (!issued || issued.version !== version || issued.ekThumbprint !== ekThumbprint || issued.username !== req.user.username) {
      const attributes = [...(rec?.attributes ?? []), userAttribute(req.user.username)].sort();
      const sk = abe.fame.keygen(keys.msk, attributes);
      const sealedKey = await sealTo(ek.data, utf8.encode(JSON.stringify(sk)), keySealAad(req.user.id, version));
      issued = await IssuedKey.findOneAndUpdate(
        { userId: req.user.id },
        { $set: { version, username: req.user.username, ekThumbprint, attributes, sealedKey, issuedAt: new Date() } },
        { upsert: true, new: true, lean: true },
      );
      audit(req, 'key.issue', req.user.id, { version, attributes });
    }
    res.json({ version: issued.version, attributes: issued.attributes, sealedKey: issued.sealedKey, issuedAt: issued.issuedAt });
  });

  // ---- administration
  const admin = express.Router();
  admin.use(session.requireUser, session.requireAdmin);
  admin.get('/users', async (_req, res) => {
    const list = await Attributes.find().sort({ username: 1 }).limit(1000).lean();
    res.json({ users: list.map(({ userId, username, attributes, version, updatedAt, updatedBy }) => ({ userId, username, attributes, version, updatedAt, updatedBy })) });
  });
  admin.put('/users/:userId/attributes', async (req, res) => {
    const userId = userIdSchema.parse(req.params.userId);
    const body = attributesBody.parse(req.body);
    const attributes = normalizeAssigned(body.attributes);
    const prev = await Attributes.findOne({ userId }).lean();
    const rec = await Attributes.findOneAndUpdate(
      { userId },
      { $set: { username: body.username, attributes, updatedBy: req.user.username }, $inc: { version: 1 } },
      { upsert: true, new: true, lean: true },
    );
    await IssuedKey.deleteOne({ userId }); // force re-issue with the new attribute set
    audit(req, 'attributes.set', userId, { username: body.username, before: prev?.attributes ?? [], after: attributes, version: rec.version });
    res.json({ userId, username: rec.username, attributes: rec.attributes, version: rec.version });
  });
  admin.get('/audit', async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    res.json({ events: await Audit.find().sort({ at: -1 }).limit(limit).lean() });
  });
  r.use('/admin', admin);

  app.use('/authority', r);
  app.use(notFound);
  app.use(errorHandler(logger));

  // ------------------------------------------------------------ internal app (private network only)
  const internal = express();
  internal.disable('x-powered-by');
  internal.use(requireInternalToken(config.internalToken));
  internal.get('/internal/users/:userId/attributes', async (req, res) => {
    const userId = userIdSchema.parse(req.params.userId);
    const rec = await Attributes.findOne({ userId }).lean();
    res.json({ attributes: rec?.attributes ?? [], version: rec?.version ?? 0 });
  });
  internal.use(notFound);
  internal.use(errorHandler(logger));

  return { app, internal };
}

export const keySealAad = (userId, version) => `secureshare/v2/abe-key|${userId}|${version}`;
