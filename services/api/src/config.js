import path from 'node:path';
import { readSecret, intFromEnv, boolFromEnv, sessionCookieName, mongoUri } from '@secureshare/server-common';
import { MIN_ITERATIONS } from '@secureshare/crypto';

export function loadConfig(env = process.env) {
  const serverSecret = readSecret(env, 'SERVER_SECRET');
  if (serverSecret.length < 32) throw new Error('SERVER_SECRET must be at least 32 characters');
  const internalToken = readSecret(env, 'INTERNAL_TOKEN');
  if (internalToken.length < 32) throw new Error('INTERNAL_TOKEN must be at least 32 characters');
  const cookieSecure = boolFromEnv(env, 'COOKIE_SECURE', true);
  return {
    port: intFromEnv(env, 'PORT', 4000, { min: 1, max: 65535 }),
    host: env.HOST || '0.0.0.0',
    mongoUri: mongoUri(env.MONGODB_URI || 'mongodb://127.0.0.1:27017/secureshare', readSecret(env, 'MONGODB_PASSWORD', { required: false })),
    storageDir: path.resolve(env.STORAGE_DIR || './data/blobs'),
    maxUploadBytes: intFromEnv(env, 'MAX_UPLOAD_BYTES', 100 * 1024 * 1024, { min: 1024 }),
    jwtPrivateKeyPem: readSecret(env, 'JWT_PRIVATE_KEY'),
    jwtPublicKeyPem: readSecret(env, 'JWT_PUBLIC_KEY'),
    jwtTtlSeconds: intFromEnv(env, 'JWT_TTL_SECONDS', 1800, { min: 60, max: 86400 }),
    cookieSecure,
    cookieName: sessionCookieName(cookieSecure),
    publicOrigin: env.PUBLIC_ORIGIN || '',
    authorityInternalUrl: (env.AUTHORITY_INTERNAL_URL || 'http://127.0.0.1:7001').replace(/\/$/, ''),
    internalToken,
    serverSecret,
    kdfIterations: intFromEnv(env, 'KDF_ITERATIONS', MIN_ITERATIONS, { min: MIN_ITERATIONS }),
    bootstrapAdmin: (env.BOOTSTRAP_ADMIN || '').toLowerCase(),
    authRateLimit: intFromEnv(env, 'AUTH_RATE_LIMIT', 20, { min: 1 }),
    maxFailedLogins: intFromEnv(env, 'MAX_FAILED_LOGINS', 5, { min: 1 }),
    lockoutMinutes: intFromEnv(env, 'LOCKOUT_MINUTES', 15, { min: 1 }),
    registrationOpen: boolFromEnv(env, 'REGISTRATION_OPEN', true),
    trustProxy: intFromEnv(env, 'TRUST_PROXY_HOPS', 1, { min: 0, max: 10 }),
    logLevel: env.LOG_LEVEL || 'info',
  };
}
