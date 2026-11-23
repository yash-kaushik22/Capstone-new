# Cryptography

All primitives come from two places: the browser/Node **Web Crypto API** (AES-GCM, HKDF, PBKDF2, ECDH, ECDSA, SHA-256) and **@noble/curves** (BLS12-381 pairing, hash-to-curve). No primitive is hand-written. The CP-ABE *scheme* on top of the pairing is implemented in this repository (`packages/crypto/src/abe/fame.js`) and has not been independently audited.

The same package runs in the browser, in the Node services (signature checks, key issuance) and in the smoke test, so every path is exercised by the test suite.

## 1. Keys at a glance

| Key | Created where | Stored where | Who can use it |
|---|---|---|---|
| Password | user's head | nowhere | user |
| `authKey` = HKDF(PBKDF2(password)) | browser | server stores Argon2id(authKey) | proves knowledge of the password |
| `vaultKey` = HKDF(PBKDF2(password)) | browser | never stored | opens the user's vault |
| Identity keys: ECDH P-256 (encryption) + ECDSA P-256 (signing) | browser, at registration | private halves in the *vault* (AES-GCM under `vaultKey`) on the server; public halves in plain | user's browser only |
| CP-ABE master key (FAME `msk`) | attribute authority, on first start | authority DB, sealed with AES-256-GCM under `AUTHORITY_KEK` | authority only |
| CP-ABE public key (FAME `pk`) | authority | public (`GET /authority/params`) | everyone |
| User CP-ABE secret key (attributes) | authority, on request | authority DB, *sealed to the user's ECDH key* | user's browser only |
| File secret (32 random bytes) | browser, per file | never stored in plain; wrapped twice (below) | owner + policy-satisfying users |
| Session JWT (ES256) | API | httpOnly cookie | API + authority verify it |

## 2. Password handling (zero knowledge)

```
master   = PBKDF2-SHA-256(NFKC(password), salt = "secureshare/v2|" username "|" randomSalt, iterations >= 600 000)
authKey  = HKDF-SHA-256(master, info "secureshare/v2/auth")    -> sent to the server
vaultKey = HKDF-SHA-256(master, info "secureshare/v2/vault")   -> stays in the browser
```

The server Argon2id-hashes `authKey` (19 MiB, t=2, p=1) and never sees the password or `vaultKey`, so it cannot open the vault it stores. The client refuses parameters below 600 000 iterations, so a malicious server cannot downgrade the work factor. `GET /api/auth/params` returns HMAC-derived fake parameters for unknown usernames, so it cannot be used to enumerate accounts.

Because the vault is stored server-side, a user can sign in from any browser. After a page reload the keys are gone from memory and the user re-enters the password to unlock them; nothing secret is written to `localStorage` or IndexedDB. Private keys are re-imported as **non-extractable** `CryptoKey` objects.

## 3. CP-ABE: FAME on BLS12-381

Scheme: Agrawal and Chase, *FAME: Fast Attribute-based Message Encryption*, ACM CCS 2017 (the scheme the Rust `rabe` library calls AC17). Properties: ciphertext-policy, arbitrary monotone AND/OR policies, unbounded attribute names, attributes may repeat inside a policy, fully secure under the decisional linear assumption in the random-oracle model, and constant-cost decryption (6 pairings computed as one multi-pairing).

Instantiation:
- Type-III pairing on BLS12-381, G = G1, H = G2, using `@noble/curves`.
- Hash H: RFC 9380 hash-to-curve into G1 with domain tag `SECURESHARE-V2-FAME_BLS12381G1_XMD:SHA-256_SSWU_RO_`. Attribute hashes and LSSS column hashes use different prefixes (`A|attr|l|t` vs `C|j|l|t`) so they cannot collide.
- Scalars: 64 random bytes reduced mod r (bias below 2^-256).
- Points are decoded with on-curve and subgroup checks.

It is used as a **KEM**:
```
(header, K)  = FAME.Encaps(pk, policy)             K = T1^s1 * T2^s2 in GT
kek          = HKDF-SHA-256(K, salt = SHA-256(header), info "secureshare/v2/abe-kem")
abeEnvelope  = AES-256-GCM(kek, fileSecret, AAD = "secureshare/v2/abe|" fileId "|" canonicalPolicy)
```
The AAD ties the envelope to one file and one policy text. Swapping the policy string for another one of the same shape, or moving the envelope to another file, makes decryption fail (tested).

### Policy language

```
dept:cse AND role:faculty
(dept:cse AND role:faculty) OR user:alice
dept:ece AND (year:3 OR year:4) AND role:student
```
Attributes are `key:value`, case-insensitive. `AND`/`&&` binds tighter than `OR`/`||`; parentheses group. Limits: 32 attributes, depth 16, 2048 characters. The policy is converted to an LSSS matrix with the Lewko-Waters algorithm; for a minimal satisfying set the reconstruction coefficients are all 1, which the decryptor checks before pairing. There are no comparison operators: express ranges as separate attributes (`year:3 OR year:4`).

### Attributes and the `user:` attribute

The authority adds `user:<username>` to every key automatically and refuses to let admins assign any `user:` attribute. Owners can therefore share with named people (`user:alice`) through the same CP-ABE mechanism, and mix that with attribute clauses.

### Collusion resistance

Each user key is randomised (r1, r2, sigma values). Combining components from two users' keys does not produce a valid key; `abe.test.js` splices two keys together and checks that the recovered K is wrong.

## 4. File encryption (format SSE2)

```
fileId                = 16 random bytes, base64url (chosen by the client, bound into every AAD)
dataKey, metaKey      = HKDF-SHA-256(fileSecret, salt "secureshare/v2/file|" fileId, info ".../data" | ".../meta")
header (16 B)         = "SSE2" | chunkSize u32 | noncePrefix (8 random bytes)
chunk i               = AES-256-GCM(dataKey, IV = noncePrefix || i, AAD = header || i || isLast || fileId)
encMeta               = AES-256-GCM(metaKey, {name, type, size}, AAD "secureshare/v2/meta|" fileId)
ownerEnvelope         = ECIES(owner's ECDH key, fileSecret, AAD "secureshare/v2/owner|" fileId "|" ownerId)
```
1 MiB chunks. Bit flips, reordering, duplication, truncation, header edits and moving the ciphertext to another file all fail authentication (tested). The file name is encrypted, so the server stores only an opaque size and a random blob name.

ECIES = ephemeral ECDH P-256, HKDF-SHA-256 (salt = ephemeral || recipient public key), AES-256-GCM.

## 5. Signed manifests (sender authentication)

The owner signs, with ECDSA P-256/SHA-256 over canonical JSON:
```
{ v, fileId, ownerId, policy, ciphertext: {sha256, size}, encMetaSha256, abeEnvelopeSha256, ownerEnvelopeSha256, createdAt, [updatedAt] }
```
- The API verifies the signature with the owner's registered key at upload and on policy change, and only accepts ciphertext whose size and SHA-256 match it.
- The recipient's browser verifies the signature, every hash, and the downloaded ciphertext hash **before** decrypting. A server that swaps the ciphertext, edits the policy text or substitutes another envelope is detected (tested).

## 6. Key issuance by the authority

`GET /authority/keys/me` reads the caller's identity from the session JWT, including the user's ECDH public key (`ek` claim, put there by the API). The authority runs FAME KeyGen for the user's current attributes plus `user:<name>`, seals the key with ECIES to `ek` (AAD `"secureshare/v2/abe-key|" userId "|" version`) and caches the sealed copy. Changing a user's attributes increments `version` and discards the cached key. Neither the API nor anyone on the network path can open the sealed key.

## 7. Two layers of access control

1. **Cryptographic:** without a satisfying attribute key the file secret cannot be recovered.
2. **Server gate:** the API asks the authority (internal port, bearer token) for the user's *current* attributes and releases records and ciphertext only if they satisfy the policy, otherwise it answers 404. It fails closed if the authority is unreachable.

The gate is what makes revocation immediate. CP-ABE alone cannot revoke a key that was already issued, but a revoked user can no longer download any ciphertext to use it on.

## 8. Known limitations

- **Key escrow:** the attribute authority can derive any user's key, so it can decrypt any file whose ciphertext it obtains. It is a separate service with its own database and secrets for this reason. Multi-authority ABE would remove this; it is not implemented.
- **Already-downloaded data:** revoking access or changing a policy cannot take back a file someone already decrypted, or a file secret they already recovered. For that, upload a new version.
- **Trust in the API for identity:** the authority trusts the API's signed JWT for "who is this and what is their device key". A fully compromised API could request keys for other users. Fingerprints on the *Keys & attributes* page let users detect key substitution out of band.
- **Policies are public:** the policy text is visible to the server and to anyone with the record (FAME is not policy-hiding).
- **In-memory processing:** files are encrypted as Blobs in memory, so the default limit is 100 MiB.
- **Not audited:** the FAME implementation follows the paper and passes correctness, negative, tamper and collusion tests, but it has not had an external review.
