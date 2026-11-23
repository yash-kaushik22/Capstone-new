import { readFileSync } from 'node:fs';
import { timingSafeEqual, createHash } from 'node:crypto';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { importSPKI, jwtVerify } from 'jose';
import { pino } from 'pino';
import { pinoHttp } from 'pino-http';
import { ZodError } from 'zod';

// ---------------------------------------------------------------- config

/**
 * Read a secret from NAME or from the file named by NAME_FILE (Docker secrets).
 * Trailing newlines from files are stripped.
 */
export function readSecret(env, name, { required = true } = {}) {
  const file = env[`${name}_FILE`];
  const value = file ? readFileSync(file, 'utf8').replace(/\r?\n$/, '') : env[name];
  if (required && !value) throw new Error(`${name} (or ${name}_FILE) must be set`);
  return value;
}

/** Insert a password (e.g. from a Docker secret file) into a MongoDB connection string. */
export function mongoUri(uri, password) {
  if (!password) return uri;
  const u = new URL(uri);
  u.password = encodeURIComponent(password);
  return u.toString();
}

export function intFromEnv(env, name, def, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer in [${min}, ${max}]`);
  return n;
}

export const boolFromEnv = (env, name, def) => (env[name] === undefined || env[name] === '' ? def : env[name] === 'true');

export function sessionCookieName(secure) {
  // The __Host- prefix makes browsers refuse the cookie unless it is Secure, host-only and Path=/.
  return secure ? '__Host-ss_session' : 'ss_session';
}

// ---------------------------------------------------------------- logging

export function createLogger({ level = 'info', name }) {
  return pino({
    name,
    level,
    redact: {
      paths: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]', '*.authKey', '*.password', '*.vault'],
      censor: '[redacted]',
    },
  });
}

export const httpLogger = (logger) =>
  pinoHttp({
    logger,
    customLogLevel: (_req, res, err) => (err || res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info'),
    autoLogging: { ignore: (req) => req.url.endsWith('/health') },
    serializers: {
      req: (req) => ({ method: req.method, url: req.url.split('?')[0], ip: req.remoteAddress }),
    },
  });

// ---------------------------------------------------------------- errors

export class AppError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function notFound(_req, _res, next) {
  next(new AppError(404, 'Not found'));
}

export const errorHandler = (logger) => (err, req, res, _next) => {
  if (res.headersSent) return res.destroy();
  if (err instanceof ZodError) {
    return res.status(400).json({ error: 'Invalid request', details: err.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`) });
  }
  if (err instanceof AppError) return res.status(err.status).json({ error: err.message, ...(err.code && { code: err.code }) });
  if (err?.name === 'PolicyError') return res.status(400).json({ error: err.message });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
  if (err?.code === 11000) return res.status(409).json({ error: 'Already exists' });
  (req.log ?? logger).error({ err }, 'unhandled error');
  return res.status(500).json({ error: 'Internal server error' });
};

// ---------------------------------------------------------------- security middleware

/** Baseline hardening for a JSON API behind a reverse proxy. */
export function applyBaseSecurity(app, { trustProxy }) {
  app.disable('x-powered-by');
  app.set('trust proxy', trustProxy);
  app.set('query parser', 'simple'); // no nested objects from query strings
  app.use(
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true },
    }),
  );
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  app.use(cookieParser());
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
export const CSRF_HEADER = 'x-secureshare-csrf';

/**
 * CSRF defence in depth (on top of SameSite=Strict cookies):
 *  - state-changing requests must carry a custom header, which cross-site forms cannot set
 *    and cross-origin fetch cannot send without a CORS pre-flight that we never approve;
 *  - if the browser sends Origin / Sec-Fetch-Site, they must say same-origin.
 */
export function csrfGuard({ publicOrigin }) {
  return (req, _res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();
    if (req.get(CSRF_HEADER) !== '1') return next(new AppError(403, 'Missing CSRF header'));
    const origin = req.get('origin');
    if (origin && publicOrigin && origin !== publicOrigin) return next(new AppError(403, 'Cross-origin request rejected'));
    const site = req.get('sec-fetch-site');
    if (site && site !== 'same-origin' && site !== 'none') return next(new AppError(403, 'Cross-site request rejected'));
    return next();
  };
}

export function limiter({ windowMs, limit, keyGenerator, message = 'Too many requests, slow down' }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    ...(keyGenerator && { keyGenerator }),
    handler: (_req, res) => res.status(429).json({ error: message }),
  });
}

export function safeEqual(a, b) {
  const ha = createHash('sha256').update(String(a)).digest();
  const hb = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(ha, hb);
}

/** Service-to-service bearer token check (constant time). */
export function requireInternalToken(token) {
  return (req, _res, next) => {
    const header = req.get('authorization') ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!presented || !safeEqual(presented, token)) return next(new AppError(401, 'Unauthorized'));
    return next();
  };
}

// ---------------------------------------------------------------- sessions

export const JWT_ISSUER = 'secureshare-api';
export const JWT_AUDIENCE = 'secureshare';

/**
 * Verifies the ES256 session JWT issued by the API. `isRevoked(payload)` lets the
 * API consult its logout deny-list; the authority relies on the short token TTL.
 */
export async function sessionVerifier({ publicKeyPem, cookieName, isRevoked }) {
  const key = await importSPKI(publicKeyPem, 'ES256');
  async function verify(req) {
    const token = req.cookies?.[cookieName];
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, key, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE, algorithms: ['ES256'] });
      if (isRevoked && (await isRevoked(payload))) return null;
      return payload;
    } catch {
      return null;
    }
  }
  const requireUser = async (req, _res, next) => {
    const payload = await verify(req);
    if (!payload) return next(new AppError(401, 'Not signed in'));
    req.session = payload;
    req.user = { id: payload.sub, username: payload.usr, role: payload.role };
    return next();
  };
  const requireAdmin = (req, _res, next) =>
    req.user?.role === 'admin' ? next() : next(new AppError(403, 'Administrator role required'));
  return { verify, requireUser, requireAdmin };
}
