import { describe, it, expect, beforeAll } from 'vitest';
import { fame, wrapSecret, unwrapSecret, publicKeyFingerprint } from '../src/abe/index.js';
import { parsePolicy } from '../src/abe/policy.js';
import { randomBytes } from '../src/encoding.js';
import { DecryptionError, PolicyNotSatisfiedError } from '../src/errors.js';

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
let pk;
let msk;

beforeAll(() => {
  ({ pk, msk } = fame.setup());
});

describe('FAME CP-ABE', () => {
  const policy = '(dept:cse AND role:faculty) OR user:alice OR (dept:ece AND year:4 AND role:student)';

  it.each([
    [['dept:cse', 'role:faculty'], true],
    [['dept:cse', 'role:faculty', 'year:4'], true],
    [['user:alice'], true],
    [['dept:ece', 'year:4', 'role:student'], true],
    [['dept:cse', 'role:student'], false],
    [['dept:ece', 'year:4'], false],
    [['user:bob'], false],
    [[], false],
  ])('attributes %j -> authorised=%s', (attrs, ok) => {
    const ast = parsePolicy(policy);
    const { header, key } = fame.encapsulate(pk, ast);
    const sk = fame.keygen(msk, attrs);
    if (ok) expect(eq(fame.decapsulate(sk, ast, header), key)).toBe(true);
    else expect(() => fame.decapsulate(sk, ast, header)).toThrow(PolicyNotSatisfiedError);
  });

  it('supports an attribute used several times in one policy', () => {
    const ast = parsePolicy('(a:1 AND b:2) OR (a:1 AND c:3)');
    const { header, key } = fame.encapsulate(pk, ast);
    expect(eq(fame.decapsulate(fame.keygen(msk, ['a:1', 'c:3']), ast, header), key)).toBe(true);
  });

  it('resists collusion: two users cannot combine partial keys', () => {
    const ast = parsePolicy('dept:cse AND role:faculty');
    const { header, key } = fame.encapsulate(pk, ast);
    const alice = fame.keygen(msk, ['dept:cse', 'role:student']);
    const bob = fame.keygen(msk, ['dept:ece', 'role:faculty']);
    // Try both ways of splicing their key material together.
    for (const [base, other] of [[alice, bob], [bob, alice]]) {
      const merged = { ...base, attributes: ['dept:cse', 'role:faculty'], k: { ...base.k, ...alice.k, 'role:faculty': bob.k['role:faculty'] } };
      expect(eq(fame.decapsulate(merged, ast, header), key)).toBe(false);
      void other;
    }
  });

  it('a key from a different authority does not decrypt', () => {
    const other = fame.setup();
    const ast = parsePolicy('a:1');
    const { header, key } = fame.encapsulate(pk, ast);
    expect(eq(fame.decapsulate(fame.keygen(other.msk, ['a:1']), ast, header), key)).toBe(false);
  });

  it('two encapsulations of the same policy give unrelated keys', () => {
    const ast = parsePolicy('a:1');
    expect(eq(fame.encapsulate(pk, ast).key, fame.encapsulate(pk, ast).key)).toBe(false);
  });

  it('rejects malformed public keys and headers', () => {
    expect(() => fame.encapsulate({ ...pk, scheme: 'x' }, parsePolicy('a:1'))).toThrow();
    const ast = parsePolicy('a:1');
    const { header } = fame.encapsulate(pk, ast);
    const sk = fame.keygen(msk, ['a:1']);
    expect(() => fame.decapsulate(sk, ast, { ...header, rows: [] })).toThrow(DecryptionError);
    expect(() => fame.decapsulate(sk, ast, { ...header, c0: ['AAAA', 'AAAA', 'AAAA'] })).toThrow(DecryptionError);
  });
});

describe('ABE key wrapping', () => {
  const secret = randomBytes(32);

  it('round-trips for an authorised user and canonicalises the policy', async () => {
    const env = await wrapSecret({ publicKey: pk, policy: 'Dept:CSE and role:faculty', secret, fileId: 'f1' });
    expect(env.policy).toBe('dept:cse AND role:faculty');
    const sk = fame.keygen(msk, ['dept:cse', 'role:faculty']);
    expect(eq(await unwrapSecret({ secretKey: sk, envelope: env, fileId: 'f1' }), secret)).toBe(true);
  });

  it('fails for an unauthorised user', async () => {
    const env = await wrapSecret({ publicKey: pk, policy: 'dept:cse AND role:faculty', secret, fileId: 'f1' });
    const sk = fame.keygen(msk, ['dept:cse']);
    await expect(unwrapSecret({ secretKey: sk, envelope: env, fileId: 'f1' })).rejects.toThrow(PolicyNotSatisfiedError);
  });

  it('is bound to the file id and the policy', async () => {
    const env = await wrapSecret({ publicKey: pk, policy: 'a:1 OR b:2', secret, fileId: 'f1' });
    const sk = fame.keygen(msk, ['a:1', 'b:2']);
    await expect(unwrapSecret({ secretKey: sk, envelope: env, fileId: 'f2' })).rejects.toThrow(DecryptionError);
    // Relabelling the policy (same LSSS shape, different attribute) must fail.
    await expect(unwrapSecret({ secretKey: sk, envelope: { ...env, policy: 'b:2 OR a:1' }, fileId: 'f1' })).rejects.toThrow(DecryptionError);
  });

  it('detects tampering with the wrapped secret', async () => {
    const env = await wrapSecret({ publicKey: pk, policy: 'a:1', secret, fileId: 'f1' });
    const sk = fame.keygen(msk, ['a:1']);
    const ct = env.ct.slice(0, -2) + (env.ct.endsWith('AA') ? 'BB' : 'AA');
    await expect(unwrapSecret({ secretKey: sk, envelope: { ...env, ct }, fileId: 'f1' })).rejects.toThrow(DecryptionError);
  });

  it('produces a stable fingerprint of the public key', async () => {
    expect(await publicKeyFingerprint(pk)).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
    expect(await publicKeyFingerprint(pk)).toBe(await publicKeyFingerprint(JSON.parse(JSON.stringify(pk))));
  });
});
