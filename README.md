# SecureShare

Secure file sharing with **ciphertext-policy attribute-based encryption (CP-ABE)** and **end-to-end encryption**.

An owner encrypts a file in the browser and attaches an access policy such as

```
(dept:cse AND role:faculty) OR user:alice
```

Anyone whose attributes satisfy the policy can decrypt it. Nobody else can, including the server operator. Attributes are assigned by an administrator through a separate attribute authority.

## What it does

- **CP-ABE:** FAME (Agrawal-Chase, CCS 2017) on the BLS12-381 pairing curve, with AND/OR policies, collusion resistance, and a `user:<name>` attribute for sharing with specific people.
- **End-to-end encryption:** AES-256-GCM chunked file encryption, encrypted file names, owner-signed manifests (ECDSA P-256) checked by the recipient before decryption. The server only ever stores ciphertext.
- **Zero-knowledge accounts:** the password never leaves the browser. It derives a login key (Argon2id-hashed on the server) and a vault key that encrypts the user's private keys.
- **Two layers of access control:** cryptography plus a server-side policy gate that checks live attributes, so revoking an attribute takes effect immediately.
- **Hardening:** TLS with HSTS, strict CSP, SameSite=Strict httpOnly cookies + CSRF header and Origin checks, rate limiting and account lockout, strict input validation, audit log, non-root read-only containers, isolated internal network, per-service database users.
- **Automation:** GitHub Actions for lint, tests, end-to-end test, image build, Trivy and CodeQL scans, secret scanning, signed image releases to GHCR, and SSH deployment with health checks and automatic rollback.

## Quick start (development)

Needs Node 22.12+ and MongoDB 7 or 8 on `localhost:27017`.

```bash
npm ci
npm run setup     # creates ./secrets and .env
npm run dev       # authority :7000, API :4000, web app http://localhost:5173
```

Register a user called `admin` first (the `BOOTSTRAP_ADMIN`); it gets the Administration tab. Then:

1. Register two more users in separate browser profiles, e.g. `farid` and `sana`.
2. As `admin`, open **Administration** and give `farid` the attributes `dept:cse, role:faculty` and `sana` the attributes `dept:cse, role:student`.
3. As a third user, upload a file with policy `dept:cse AND role:faculty`.
4. `farid` sees it under **Shared with me** and can download it. `sana` cannot see it at all.
5. Change the policy to `role:student`, or remove `farid`'s `role:faculty`, and watch access change.

## Production

```bash
npm run setup
cp deploy/.env.example deploy/.env       # set DOMAIN and ACME_EMAIL
docker compose --env-file deploy/.env up -d --build
```

Caddy gets a Let's Encrypt certificate for `DOMAIN`. For CI/CD (GHCR images, signed releases, SSH deploys with rollback) see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Tests

```bash
npm run lint
npm test          # crypto, authority, API (real mongod via mongodb-memory-server), client
npm run build
npm run smoke     # end-to-end over HTTP against running services (25 checks)
```

| Suite | Tests | Covers |
|---|---|---|
| `packages/crypto` | 63 | policy parser and LSSS (exhaustive over attribute subsets), FAME correctness, unauthorized keys, collusion, wrong authority, envelope binding, tamper detection on every layer, ECIES, signatures, password vault, full upload/download/re-policy flow |
| `services/authority` | 11 | master key sealing and reload, wrong KEK, key issuance sealed to the device, re-issue after attribute change, admin-only and CSRF, forged tokens, internal endpoint isolation |
| `services/api` | 26 | registration/login/lockout/logout revocation, enumeration resistance, tampered JWTs, signature and manifest checks, ciphertext hash enforcement, policy gate, revocation, fail-closed, size limits, no plaintext in storage or DB, audit |
| `client` | 5 | helpers (file name sanitising, policy validation) |
| `scripts/smoke.mjs` | 25 checks | the whole system over real HTTP |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, flows, API reference
- [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md): every key, every construction, and the known limitations
- [docs/SECURITY.md](docs/SECURITY.md): threat model and the control for each threat
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): CI/CD pipeline, server setup, operations

## Limitations worth knowing

The attribute authority can derive any user's key (inherent to single-authority ABE), so it runs as a separate service with its own secrets. Revocation cannot take back a file someone already decrypted. The FAME implementation follows the paper and is thoroughly tested but has not been externally audited. Details in [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md#8-known-limitations).
