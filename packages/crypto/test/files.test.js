import { describe, it, expect, beforeAll } from 'vitest';
import {
  abe, encryptBlob, decryptBlob, deriveFileKeys, generateIdentity, exportPublicJwk, sealTo, openSealed,
  signObject, verifyObject, jwkFingerprint, newKdfParams, deriveLoginKeys, createVault, openVault,
  encryptForUpload, decryptDownload, rewrapPolicy, randomBytes, DecryptionError, SignatureError,
  PolicyNotSatisfiedError, MIN_ITERATIONS,
} from '../src/index.js';

const text = (blob) => blob.text();
let pk;
let msk;

beforeAll(() => {
  ({ pk, msk } = abe.fame.setup());
});

describe('SSE2 file cipher', () => {
  const fileId = 'AAAAAAAAAAAAAAAAAAAAAA';
  let dataKey;
  beforeAll(async () => {
    ({ dataKey } = await deriveFileKeys(randomBytes(32), fileId));
  });

  it.each([0, 1, 15, 16, 17, 64, 1000])('round-trips %d bytes with 16-byte chunks', async (n) => {
    const plain = randomBytes(n);
    const ct = await encryptBlob(new Blob([plain]), dataKey, fileId, { chunkSize: 16 });
    const out = new Uint8Array(await (await decryptBlob(ct, dataKey, fileId)).arrayBuffer());
    expect(out).toEqual(plain);
  });

  it('round-trips 8 MiB with the default chunk size', async () => {
    const plain = new Uint8Array(8 * 1024 * 1024).map((_, i) => i & 0xff);
    const ct = await encryptBlob(new Blob([plain]), dataKey, fileId);
    const out = new Uint8Array(await (await decryptBlob(ct, dataKey, fileId)).arrayBuffer());
    expect(out.length).toBe(plain.length);
    expect(out[123457]).toBe(plain[123457]);
  });

  async function mutate(fn) {
    const ct = new Uint8Array(await (await encryptBlob(new Blob([randomBytes(64)]), dataKey, fileId, { chunkSize: 16 })).arrayBuffer());
    return new Blob([fn(ct)]);
  }
  const CH = 32; // 16 data + 16 tag

  it.each([
    ['bit flip in body', (c) => { c[20] ^= 1; return c; }],
    ['bit flip in header nonce', (c) => { c[10] ^= 1; return c; }],
    ['truncated last chunk', (c) => c.subarray(0, 16 + 3 * CH)],
    ['chunks swapped', (c) => { const x = c.slice(); x.set(c.subarray(16 + CH, 16 + 2 * CH), 16); x.set(c.subarray(16, 16 + CH), 16 + CH); return x; }],
    ['chunk duplicated', (c) => { const x = new Uint8Array(c.length + CH); x.set(c); x.set(c.subarray(16, 16 + CH), c.length); return x; }],
  ])('detects %s', async (_, fn) => {
    await expect(decryptBlob(await mutate(fn), dataKey, fileId)).rejects.toThrow(DecryptionError);
  });

  it('is bound to the file id', async () => {
    const ct = await encryptBlob(new Blob(['hi']), dataKey, fileId);
    await expect(decryptBlob(ct, dataKey, 'BBBBBBBBBBBBBBBBBBBBBB')).rejects.toThrow(DecryptionError);
  });
});

describe('identity keys', () => {
  it('ECIES seals to a public key and binds the AAD', async () => {
    const id = await generateIdentity();
    const jwk = await exportPublicJwk(id.enc.publicKey);
    const sealed = await sealTo(jwk, new Uint8Array([1, 2, 3]), 'ctx');
    expect(await openSealed(id.enc.privateKey, jwk, sealed, 'ctx')).toEqual(new Uint8Array([1, 2, 3]));
    await expect(openSealed(id.enc.privateKey, jwk, sealed, 'other')).rejects.toThrow(DecryptionError);
    const other = await generateIdentity();
    await expect(openSealed(other.enc.privateKey, await exportPublicJwk(other.enc.publicKey), sealed, 'ctx')).rejects.toThrow(DecryptionError);
  });

  it('signs canonical JSON regardless of key order', async () => {
    const id = await generateIdentity();
    const jwk = await exportPublicJwk(id.sig.publicKey);
    const sig = await signObject(id.sig.privateKey, { b: 1, a: [1, { y: 2, x: 1 }] });
    await expect(verifyObject(jwk, { a: [1, { x: 1, y: 2 }], b: 1 }, sig)).resolves.toBe(true);
    await expect(verifyObject(jwk, { a: [1, { x: 1, y: 3 }], b: 1 }, sig)).rejects.toThrow(SignatureError);
    expect(await jwkFingerprint(jwk)).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
  });
});

describe('password-derived vault', () => {
  it('derives a stable auth key, opens the vault, and refuses weak parameters', async () => {
    const params = newKdfParams(MIN_ITERATIONS);
    const a = await deriveLoginKeys('correct horse', 'alice', params);
    const b = await deriveLoginKeys('correct horse', 'alice', params);
    const c = await deriveLoginKeys('wrong horse', 'alice', params);
    const d = await deriveLoginKeys('correct horse', 'bob', params);
    expect(a.authKey).toBe(b.authKey);
    expect(a.authKey).not.toBe(c.authKey);
    expect(a.authKey).not.toBe(d.authKey);

    const id = await generateIdentity();
    const vault = await createVault(a.vaultKey, 'alice', id);
    const keys = await openVault(b.vaultKey, 'alice', vault);
    expect(keys.encPrivate.extractable).toBe(false);
    await expect(openVault(c.vaultKey, 'alice', vault)).rejects.toThrow(DecryptionError);
    await expect(openVault(a.vaultKey, 'mallory', vault)).rejects.toThrow(DecryptionError);
    await expect(deriveLoginKeys('x', 'alice', { ...params, iterations: 1000 })).rejects.toThrow(/weak/);
  });
});

describe('end-to-end file flow', () => {
  async function makeUser(id, attrs) {
    const ident = await generateIdentity();
    return {
      id,
      encPublicJwk: await exportPublicJwk(ident.enc.publicKey),
      sigPublicJwk: await exportPublicJwk(ident.sig.publicKey),
      encPrivate: ident.enc.privateKey,
      sigPrivate: ident.sig.privateKey,
      abeSecretKey: attrs ? abe.fame.keygen(msk, [...attrs, `user:${id}`]) : null,
    };
  }

  it('owner and authorised recipients decrypt; others cannot; tampering is detected', async () => {
    const owner = await makeUser('owner', ['dept:hr']);
    const faculty = await makeUser('fac', ['dept:cse', 'role:faculty']);
    const student = await makeUser('stu', ['dept:cse', 'role:student']);

    const up = await encryptForUpload({
      file: new Blob(['exam paper']),
      meta: { name: 'exam.txt', type: 'text/plain' },
      policy: 'dept:cse AND role:faculty',
      abePublicKey: pk,
      owner,
    });
    const record = {
      id: up.fileId, ownerId: owner.id, encMeta: up.encMeta, abeEnvelope: up.abeEnvelope,
      ownerEnvelope: up.ownerEnvelope, manifest: up.manifest, signature: up.signature,
    };

    for (const who of [owner, faculty]) {
      const out = await decryptDownload({ record, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: who });
      expect(await text(out.blob)).toBe('exam paper');
      expect(out.meta).toMatchObject({ name: 'exam.txt', type: 'text/plain', size: 10 });
    }
    await expect(decryptDownload({ record, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: student }))
      .rejects.toThrow(PolicyNotSatisfiedError);

    // Server swaps the ciphertext, edits the policy text, or forges the owner key.
    const swapped = await encryptForUpload({ file: new Blob(['fake']), meta: { name: 'x' }, policy: 'dept:cse', abePublicKey: pk, owner });
    await expect(decryptDownload({ record, ciphertext: swapped.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: faculty })).rejects.toThrow(SignatureError);
    await expect(decryptDownload({ record: { ...record, abeEnvelope: { ...record.abeEnvelope, policy: 'dept:cse' } }, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: faculty })).rejects.toThrow(SignatureError);
    await expect(decryptDownload({ record, ciphertext: up.ciphertext, ownerSigJwk: student.sigPublicJwk, me: faculty })).rejects.toThrow(SignatureError);

    // Policy change: student gains access, faculty loses it (for new downloads).
    const rw = await rewrapPolicy({ record, newPolicy: 'role:student', abePublicKey: pk, owner });
    const record2 = { ...record, ...rw };
    const out = await decryptDownload({ record: record2, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: student });
    expect(await text(out.blob)).toBe('exam paper');
    await expect(decryptDownload({ record: record2, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: faculty }))
      .rejects.toThrow(PolicyNotSatisfiedError);
  });

  it('targets one specific user with the user: attribute', async () => {
    const owner = await makeUser('own2', []);
    const bob = await makeUser('bob', ['dept:cse']);
    const eve = await makeUser('eve', ['dept:cse']);
    const up = await encryptForUpload({ file: new Blob(['for bob']), meta: { name: 'b' }, policy: 'user:bob', abePublicKey: pk, owner });
    const record = { id: up.fileId, ownerId: owner.id, ...up };
    expect(await text((await decryptDownload({ record, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: bob })).blob)).toBe('for bob');
    await expect(decryptDownload({ record, ciphertext: up.ciphertext, ownerSigJwk: owner.sigPublicJwk, me: eve })).rejects.toThrow(PolicyNotSatisfiedError);
  });
});
