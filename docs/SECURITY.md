# Security model and controls

## Assets

File contents and names; users' passwords and private keys; the CP-ABE master key; attribute assignments; the audit trail.

## Trust boundaries

| Component | Trusted for | Not trusted with |
|---|---|---|
| User's browser | everything for that user | other users' keys |
| API (file server) | storing data, enforcing the access gate, issuing sessions | plaintext files, file names, passwords, private keys, the master key |
| Attribute authority | knowing who has which attributes, issuing keys | plaintext files (never sees ciphertext), passwords |
| MongoDB, disk, backups | durability | anything readable: stored data is ciphertext, hashes or sealed blobs |
| Network | delivery | confidentiality or integrity (TLS + end-to-end encryption) |

## Threats and what stops them

| Threat | Control | Where |
|---|---|---|
| Eavesdropping / MITM on the network | TLS 1.2+/1.3 via Caddy with HSTS; files are already end-to-end encrypted before upload | `deploy/caddy/Caddyfile` |
| Database or storage leak | Only ciphertext, encrypted names, Argon2id hashes, password-encrypted vaults and sealed keys are stored; master key sealed under a KEK held outside the DB | `docs/CRYPTOGRAPHY.md` |
| Malicious or compromised file server reading files | It never has file secrets or attribute keys | crypto design |
| Server swapping ciphertext, policy or envelopes | Owner-signed manifest verified in the recipient's browser before decryption | `packages/crypto/src/files.js` |
| User downloading a file outside their policy | Server gate (404) **and** CP-ABE (cannot decrypt) | `services/api/src/routes/files.js` |
| Colluding users pooling attributes | FAME collusion resistance (tested) | `packages/crypto/test/abe.test.js` |
| Revoked user keeps access | Gate checks live attributes on every request; key re-issued on change | authority + API |
| Password guessing online | 20 auth requests / 15 min per IP; account lock after 5 failures (15 min); same error for wrong user/password; timing-equalised verify | `routes/auth.js` |
| Password cracking after a leak | Server stores Argon2id(HKDF(PBKDF2-600k(password))) | `routes/auth.js`, `password.js` |
| Account enumeration | Fake KDF params for unknown users; identical login errors | `routes/auth.js` |
| Session theft via XSS | Cookie is httpOnly; strict CSP with no inline script or eval; React escaping; keys non-extractable | Caddyfile, `client/` |
| CSRF | SameSite=Strict cookie + required custom header + Origin and Sec-Fetch-Site checks | `server-common` |
| Session replay after logout | JWT `jti` deny-list with TTL; 30-minute token lifetime | `routes/auth.js` |
| Forged sessions / privilege escalation | ES256 JWT, issuer/audience/algorithm pinned; admin routes check role; tampered tokens rejected (tested) | `server-common` |
| NoSQL injection | zod strict schemas on every body; `sanitizeFilter`; simple query parser | models, routes |
| Path traversal | File ids are validated base64url; blobs use random hex names; download names sanitised client-side | `storage.js`, `files.js` (client) |
| Upload abuse / DoS | Size declared in signed manifest and enforced while streaming; 100 MiB cap; per-user upload rate; per-IP rate limit; body limits at proxy and app | API, Caddyfile |
| Clickjacking, MIME sniffing, referrer leaks | `frame-ancestors 'none'`, X-Frame-Options, nosniff, `Referrer-Policy: no-referrer` | Caddyfile, helmet |
| Internal endpoint exposure | Authority's internal API listens on a separate port, only on the internal Docker network, behind a bearer token | `docker-compose.yml` |
| Container breakout impact | Non-root users, read-only root FS, all capabilities dropped, no-new-privileges, memory/PID limits; MongoDB unreachable from outside | `docker-compose.yml` |
| Database credential misuse | Separate MongoDB users per service, each limited to its own database; root password only used at init | `deploy/mongo/init-users.js` |
| Secrets in git | `./secrets` is git-ignored; Docker secrets mounted as files; gitleaks in CI | `.gitignore`, CI |
| Vulnerable dependencies / images | `npm audit` (prod, high), Dependabot, CodeQL, Trivy on every image, dependency review on PRs | `.github/` |
| Tampered images in deployment | Images signed with cosign (keyless) in CI; deploy verifies signatures before pulling | `release.yml`, `deploy.yml` |
| Bad deploy | Health-checked rollout with automatic rollback to the previous tag | `scripts/remote-deploy.sh` |
| Repudiation | Audit log of logins (incl. failures), uploads, downloads, denials, policy changes, attribute changes and key issuance | API + authority |

## Out of scope / residual risk

- A compromised user device, or malicious JavaScript served by a compromised web server, can read what that user can read. Web apps cannot fully defend against the server that delivers their code.
- The attribute authority can decrypt anything it gets ciphertext for (inherent to single-authority ABE).
- Rate limits are per process (in memory). Use a shared store such as Redis if you run several API replicas.
- Forgotten passwords cannot be recovered: that is the cost of the server not knowing them.

## Reporting

Please report vulnerabilities privately to the maintainers rather than in a public issue.
