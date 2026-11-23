# Architecture

```
                       Internet (HTTPS only)
                              │
                     ┌────────▼─────────┐
                     │  web (Caddy)     │  TLS, security headers, static React app
                     │  :80 :443        │  /api/* -> api, /authority/* -> authority
                     └───┬──────────┬───┘
            frontend net │          │
             ┌───────────▼──┐   ┌───▼──────────────┐
             │ api :4000    │   │ authority :7000  │ public: params, keys/me, admin
             │ accounts,    ├──►│ :7001 internal   │ internal: current attributes
             │ files, gate, │   │ FAME master key  │
             │ audit        │   │ (sealed by KEK)  │
             └──────┬───────┘   └──────┬───────────┘
        backend net │ (internal: no    │
                    │  outside access) │
             ┌──────▼──────────────────▼──┐
             │ mongo :27017                │  db secureshare (api user)
             │ auth on, one user per DB    │  db secureshare_authority (authority user)
             └─────────────────────────────┘
   blobs volume (ciphertext only) mounted into api
```

## Repository layout

```
packages/crypto         All cryptography (FAME CP-ABE, policy/LSSS, SSE2 file format, ECIES,
                        signatures, password KDF + vault, high-level upload/download flows).
                        Used by the browser, both services and the smoke test.
packages/server-common  Config/secrets loading, logging, error handling, helmet, CSRF guard,
                        rate limiting, JWT session verification.
services/api            Express 5 + Mongoose. Auth, files, policy gate, admin, audit.
services/authority      Express 5 + Mongoose. Master key, attribute admin, key issuance.
client                  React 19 + Vite.
deploy/                 Dockerfiles, Caddyfile, MongoDB init script, compose env template.
scripts/                gen-secrets, smoke test, remote deploy script.
.github/                CI, release, deploy, CodeQL, Dependabot.
docs/                   This folder.
```

## Main flows

**Register.** Browser picks a KDF salt, derives `authKey` and `vaultKey` from the password, generates ECDH + ECDSA key pairs, encrypts the private keys into a vault with `vaultKey`, and posts username, KDF params, `authKey`, public keys and vault. The API stores Argon2id(authKey) and sets an ES256 session cookie whose claims include the user's ECDH public key.

**Get an attribute key.** Browser calls `GET /authority/keys/me`. The authority verifies the JWT, runs FAME KeyGen for the user's attributes + `user:<name>`, seals the result to the ECDH key in the JWT and returns it. The browser opens it with its private key.

**Upload.** Browser generates `fileId` and a file secret, encrypts the file (SSE2) and its name, wraps the secret under the CP-ABE policy and to the owner's own key, signs a manifest, then:
1. `POST /api/files` with envelopes + signed manifest (API verifies signature and hashes).
2. `PUT /api/files/:id/blob` with the ciphertext (API checks size and SHA-256 against the manifest while streaming).

**Download.** `GET /api/files/:id` and `/blob` pass only if the caller owns the file or their *current* attributes (fetched from the authority) satisfy the policy. The browser verifies the manifest signature and ciphertext hash, unwraps the secret with its CP-ABE key and decrypts.

**Revoke / change policy.** An admin edits attributes (authority bumps the key version; the API gate reflects it within 5 seconds). An owner re-wraps the file secret under a new policy and re-signs the manifest (`PUT /api/files/:id/policy`).

## API summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health`, `/api/meta` | none | liveness; upload limit |
| GET | `/api/auth/params?username=` | none | KDF parameters (fake for unknown users) |
| POST | `/api/auth/register`, `/api/auth/login` | none | create account / sign in |
| POST | `/api/auth/logout` | user | revoke session |
| GET | `/api/auth/me` | user | profile + vault (for unlock) |
| POST | `/api/files` | user | register a file (signed manifest) |
| PUT | `/api/files/:id/blob` | owner | upload ciphertext once |
| GET | `/api/files?scope=owned\|shared` | user | list |
| GET | `/api/files/:id`, `/api/files/:id/blob` | owner or policy | record / ciphertext |
| PUT | `/api/files/:id/policy` | owner | re-wrapped envelope + new signature |
| DELETE | `/api/files/:id` | owner | delete |
| GET | `/api/admin/users`, `/api/admin/audit`; POST `/api/admin/users/:id/unlock` | admin | administration |
| GET | `/authority/health`, `/authority/params` | none | liveness; FAME public key + fingerprint |
| GET | `/authority/me`, `/authority/catalog`, `/authority/keys/me` | user | own attributes; attribute names in use; sealed key |
| GET/PUT | `/authority/admin/users[/:userId/attributes]`, GET `/authority/admin/audit` | admin | attribute management |
| GET | `/internal/users/:id/attributes` (port 7001) | service token | used by the API gate |

All state-changing requests need the `X-SecureShare-CSRF: 1` header.
