#!/usr/bin/env node
// Generates every secret SecureShare needs into ./secrets (directory mode 0700) and a local
// .env for development. Existing files are kept unless --force is given.
//   node scripts/gen-secrets.mjs [--force]
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.join(root, 'secrets');
const force = process.argv.includes('--force');
mkdirSync(dir, { recursive: true, mode: 0o700 });
chmodSync(dir, 0o700);

const token = (n = 32) => randomBytes(n).toString('base64url');
const created = [];

function write(name, content) {
  const file = path.join(dir, name);
  if (existsSync(file) && !force) return;
  // 0644 inside a 0700 directory: unreadable to other host users, but readable by the
  // non-root users inside the containers that Compose bind-mounts each secret into.
  writeFileSync(file, content, { mode: 0o644 });
  chmodSync(file, 0o644);
  created.push(name);
}

if (force || !existsSync(path.join(dir, 'jwt_private.pem'))) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  write('jwt_private.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }));
  write('jwt_public.pem', publicKey.export({ type: 'spki', format: 'pem' }));
}
write('authority_kek', token(32));
write('internal_token', token(32));
write('server_secret', token(48));
write('mongo_root_password', token(24));
write('mongo_api_password', token(24));
write('mongo_authority_password', token(24));

// Local development .env (plain processes, no Docker).
const envFile = path.join(root, '.env');
if (!existsSync(envFile) || force) {
  const tpl = readFileSync(path.join(root, '.env.example'), 'utf8');
  writeFileSync(envFile, tpl, { mode: 0o600 });
  created.push('.env');
}

console.log(created.length ? `Created: ${created.join(', ')}` : 'All secrets already exist (use --force to rotate).');
console.log(`Secrets directory: ${dir}`);
console.log('Back up secrets/authority_kek: without it the CP-ABE master key cannot be unsealed.');
