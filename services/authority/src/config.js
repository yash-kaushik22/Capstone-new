import { readSecret, intFromEnv, boolFromEnv, sessionCookieName, mongoUri } from '@secureshare/server-common';
import { fromB64u } from '@secureshare/crypto';

export function loadConfig(env = process.env) {
  const kek = fromB64u(readSecret(env, 'AUTHORITY_KEK'));
  if (kek.length !== 32) throw new Error('AUTHORITY_KEK must be 32 bytes, base64url-encoded');
  const internalToken = readSecret(env, 'INTERNAL_TOKEN');
  if (internalToken.length < 32) throw new Error('INTERNAL_TOKEN must be at least 32 characters');
  const cookieSecure = boolFromEnv(env, 'COOKIE_SECURE', true);
  return {
    port: intFromEnv(env, 'AUTHORITY_PORT', 7000, { min: 1, max: 65535 }),
    internalPort: intFromEnv(env, 'AUTHORITY_INTERNAL_PORT', 7001, { min: 1, max: 65535 }),
    host: env.HOST || '0.0.0.0',
    mongoUri: mongoUri(
      env.AUTHORITY_MONGODB_URI || 'mongodb://127.0.0.1:27017/secureshare_authority',
      readSecret(env, 'AUTHORITY_MONGODB_PASSWORD', { required: false }),
    ),
    kek,
    internalToken,
    jwtPublicKeyPem: readSecret(env, 'JWT_PUBLIC_KEY'),
    cookieName: sessionCookieName(cookieSecure),
    publicOrigin: env.PUBLIC_ORIGIN || '',
    trustProxy: intFromEnv(env, 'TRUST_PROXY_HOPS', 1, { min: 0, max: 10 }),
    logLevel: env.LOG_LEVEL || 'info',
  };
}
