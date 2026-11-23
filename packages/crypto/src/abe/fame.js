/**
 * FAME ciphertext-policy ABE (Agrawal & Chase, "FAME: Fast Attribute-based Message
 * Encryption", ACM CCS 2017), used as a key-encapsulation mechanism (KEM).
 *
 * - Type-III pairing on BLS12-381 from @noble/curves (audited). G = G1, H = G2.
 * - Hash H: RFC 9380 hash-to-curve into G1 with a SecureShare-specific DST.
 * - Arbitrary monotone AND/OR policies via an LSSS matrix (see ./policy.js),
 *   attributes may repeat inside a policy, unbounded attribute universe.
 * - Security in the paper: fully (adaptively) secure under the decisional linear
 *   assumption in the random-oracle model. This file only implements the scheme;
 *   it has not been independently audited.
 *
 * Notation follows the paper. Indices l in {1,2,3}, t in {1,2}.
 *   Setup:  pk = (h, H1=h^a1, H2=h^a2, T1=e(g,h)^(d1 a1 + d3), T2=e(g,h)^(d2 a2 + d3))
 *           msk = (a1, a2, b1, b2, g^d1, g^d2, g^d3)
 *   KeyGen: sk0 = (h^(b1 r1), h^(b2 r2), h^(r1+r2))
 *           sk_{y,t} = H(y1t)^(b1 r1/at) H(y2t)^(b2 r2/at) H(y3t)^((r1+r2)/at) g^(sigma_y/at),  sk_{y,3} = g^(-sigma_y)
 *           sk'_t    = g^dt H(011t)^(b1 r1/at) H(012t)^(b2 r2/at) H(013t)^((r1+r2)/at) g^(sigma'/at), sk'_3 = g^d3 g^(-sigma')
 *   Encaps: ct0 = (H1^s1, H2^s2, h^(s1+s2))
 *           ct_{i,l} = H(pi(i) l 1)^s1 H(pi(i) l 2)^s2 prod_j [H(0 j l 1)^s1 H(0 j l 2)^s2]^(M_ij)
 *           K = T1^s1 T2^s2
 *   Decaps: K = prod_t e(sk'_t prod_i sk_{pi(i),t}, ct0_t) / prod_l e(prod_i ct_{i,l}, sk0_l)
 *           (reconstruction coefficients are all 1 for Lewko-Waters matrices)
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { utf8, toB64u, fromB64u, randomBytes } from '../encoding.js';
import { PolicyNotSatisfiedError, DecryptionError } from '../errors.js';
import { toLsss, satisfyingRows } from './policy.js';

export const SCHEME = 'fame-bls12381-v1';
const { G1, G2, fields } = bls;
const { Fr, Fp12 } = fields;
const g = G1.Point.BASE;
const h = G2.Point.BASE;
const DST = 'SECURESHARE-V2-FAME_BLS12381G1_XMD:SHA-256_SSWU_RO_';

// ---------- scalar and group helpers ----------

export function randomScalar() {
  for (;;) {
    const k = Fr.create(bytesToNumberBE(randomBytes(64))); // 512 bits mod r: negligible bias
    if (k !== 0n) return k;
  }
}

const add = (...xs) => xs.reduce((a, b) => Fr.add(a, b));
const mul = (...xs) => xs.reduce((a, b) => Fr.mul(a, b));

function smul(P, k) {
  const s = Fr.create(k);
  return s === 0n ? P.constructor.ZERO : P.multiply(s);
}

const sum = (points, Zero) => points.reduce((a, b) => a.add(b), Zero);

const hashCache = new Map();
function hashG1(label) {
  let P = hashCache.get(label);
  if (!P) {
    P = G1.hashToCurve(utf8.encode(label), { DST });
    if (hashCache.size > 4096) hashCache.clear();
    hashCache.set(label, P);
  }
  return P;
}
// Attribute and column hashes use different prefixes; attributes cannot contain "|".
const hAttr = (attr, l, t) => hashG1(`A|${attr}|${l}|${t}`);
const hCol = (j, l, t) => hashG1(`C|${j}|${l}|${t}`);

// ---------- serialisation ----------

const encG1 = (P) => toB64u(P.toBytes(true));
const encG2 = (P) => toB64u(P.toBytes(true));
const encGT = (x) => toB64u(Fp12.toBytes(x));
const encFr = (k) => k.toString(16);

function decG1(s) {
  const P = G1.Point.fromBytes(fromB64u(s)); // checks on-curve and subgroup membership
  return P;
}
function decG2(s) {
  return G2.Point.fromBytes(fromB64u(s));
}
const decGT = (s) => Fp12.fromBytes(fromB64u(s));
function decFr(s) {
  if (!/^[0-9a-f]{1,64}$/.test(s)) throw new TypeError('bad scalar');
  const k = BigInt(`0x${s}`);
  if (k <= 0n || k >= Fr.ORDER) throw new TypeError('scalar out of range');
  return k;
}

const triple = (arr, dec) => {
  if (!Array.isArray(arr) || arr.length !== 3) throw new TypeError('expected 3 group elements');
  return arr.map(dec);
};

// ---------- Setup ----------

export function setup() {
  const [a1, a2, b1, b2, d1, d2, d3] = Array.from({ length: 7 }, randomScalar);
  const egh = bls.pairing(g, h);
  const pk = {
    v: 1,
    scheme: SCHEME,
    H1: encG2(smul(h, a1)),
    H2: encG2(smul(h, a2)),
    T1: encGT(Fp12.pow(egh, add(mul(d1, a1), d3))),
    T2: encGT(Fp12.pow(egh, add(mul(d2, a2), d3))),
  };
  const msk = {
    v: 1,
    scheme: SCHEME,
    a1: encFr(a1),
    a2: encFr(a2),
    b1: encFr(b1),
    b2: encFr(b2),
    gd1: encG1(smul(g, d1)),
    gd2: encG1(smul(g, d2)),
    gd3: encG1(smul(g, d3)),
  };
  return { pk, msk };
}

function loadPk(pk) {
  if (pk?.scheme !== SCHEME || pk.v !== 1) throw new TypeError('unsupported ABE public key');
  return { H1: decG2(pk.H1), H2: decG2(pk.H2), T1: decGT(pk.T1), T2: decGT(pk.T2) };
}

// ---------- KeyGen ----------

/** @param msk master secret key  @param attributes normalised attribute strings */
export function keygen(msk, attributes) {
  if (msk?.scheme !== SCHEME) throw new TypeError('unsupported master key');
  const a = [decFr(msk.a1), decFr(msk.a2)];
  const b1 = decFr(msk.b1);
  const b2 = decFr(msk.b2);
  const gd = [decG1(msk.gd1), decG1(msk.gd2), decG1(msk.gd3)];
  const r1 = randomScalar();
  const r2 = randomScalar();
  const ainv = a.map((x) => Fr.inv(x));
  const k0 = [smul(h, mul(b1, r1)), smul(h, mul(b2, r2)), smul(h, add(r1, r2))];

  // exponents e_l / a_t shared by every attribute component
  const ex = ainv.map((ai) => [mul(b1, r1, ai), mul(b2, r2, ai), mul(add(r1, r2), ai)]);

  const k = {};
  for (const y of [...new Set(attributes)].sort()) {
    const sigma = randomScalar();
    const parts = [0, 1].map((t) =>
      sum(
        [
          smul(hAttr(y, 1, t + 1), ex[t][0]),
          smul(hAttr(y, 2, t + 1), ex[t][1]),
          smul(hAttr(y, 3, t + 1), ex[t][2]),
          smul(g, mul(sigma, ainv[t])),
        ],
        G1.Point.ZERO,
      ),
    );
    parts.push(smul(g, Fr.neg(sigma)));
    k[y] = parts.map(encG1);
  }

  const sigmaP = randomScalar();
  const kp = [0, 1].map((t) =>
    sum(
      [
        gd[t],
        smul(hCol(1, 1, t + 1), ex[t][0]),
        smul(hCol(1, 2, t + 1), ex[t][1]),
        smul(hCol(1, 3, t + 1), ex[t][2]),
        smul(g, mul(sigmaP, ainv[t])),
      ],
      G1.Point.ZERO,
    ),
  );
  kp.push(gd[2].add(smul(g, Fr.neg(sigmaP))));

  return {
    v: 1,
    scheme: SCHEME,
    attributes: Object.keys(k),
    k0: k0.map(encG2),
    kp: kp.map(encG1),
    k,
  };
}

// ---------- Encapsulate / Decapsulate ----------

/**
 * @param pk public key  @param ast parsed policy
 * @returns {{ header: {c0:string[], rows:string[][]}, key: Uint8Array }} key = encoded GT element
 */
export function encapsulate(pk, ast) {
  const P = loadPk(pk);
  const { rows, cols } = toLsss(ast);
  const s1 = randomScalar();
  const s2 = randomScalar();
  const c0 = [smul(P.H1, s1), smul(P.H2, s2), smul(h, add(s1, s2))];

  // colTerm[j][l] = H(0 j l 1)^s1 * H(0 j l 2)^s2
  const colTerm = [];
  for (let j = 1; j <= cols; j++) {
    colTerm.push([1, 2, 3].map((l) => smul(hCol(j, l, 1), s1).add(smul(hCol(j, l, 2), s2))));
  }
  const attrTerm = new Map();
  const ct = rows.map(({ attr, vec }) => {
    if (!attrTerm.has(attr)) {
      attrTerm.set(attr, [1, 2, 3].map((l) => smul(hAttr(attr, l, 1), s1).add(smul(hAttr(attr, l, 2), s2))));
    }
    return [0, 1, 2].map((li) => {
      let acc = attrTerm.get(attr)[li];
      vec.forEach((m, j) => {
        if (m === 1) acc = acc.add(colTerm[j][li]);
        else if (m === -1) acc = acc.subtract(colTerm[j][li]);
        else if (m !== 0) acc = acc.add(smul(colTerm[j][li], BigInt(m)));
      });
      return acc;
    });
  });

  const K = Fp12.mul(Fp12.pow(P.T1, s1), Fp12.pow(P.T2, s2));
  return {
    header: { c0: c0.map(encG2), rows: ct.map((r) => r.map(encG1)) },
    key: Fp12.toBytes(K),
  };
}

/**
 * @param sk user secret key  @param ast parsed policy (must be the one used to encapsulate)
 * @param header {c0, rows}
 * @returns encoded GT element (same bytes as encapsulate().key when authorised)
 */
export function decapsulate(sk, ast, header) {
  if (sk?.scheme !== SCHEME) throw new TypeError('unsupported ABE secret key');
  const { rows, cols } = toLsss(ast);
  if (!Array.isArray(header?.rows) || header.rows.length !== rows.length) throw new DecryptionError('ABE header does not match policy');
  const chosen = satisfyingRows(ast, new Set(sk.attributes));
  if (!chosen) throw new PolicyNotSatisfiedError();

  // Sanity check: the chosen rows must reconstruct the target vector (1,0,...,0).
  const target = new Array(cols).fill(0);
  for (const i of chosen) rows[i].vec.forEach((m, j) => (target[j] += m));
  if (target[0] !== 1 || target.slice(1).some((x) => x !== 0)) throw new Error('LSSS reconstruction failed');

  let c0;
  let A;
  try {
    c0 = triple(header.c0, decG2);
    A = [0, 1, 2].map((l) => sum(chosen.map((i) => decG1(header.rows[i][l])), G1.Point.ZERO));
  } catch {
    throw new DecryptionError('Malformed ABE header');
  }
  if (c0.some((P) => P.equals(G2.Point.ZERO))) throw new DecryptionError('Malformed ABE header');
  const k0 = triple(sk.k0, decG2);
  const kp = triple(sk.kp, decG1);
  const B = [0, 1, 2].map((t) =>
    chosen.reduce((acc, i) => acc.add(decG1(sk.k[rows[i].attr][t])), kp[t]),
  );

  const K = bls.pairingBatch([
    { g1: B[0], g2: c0[0] },
    { g1: B[1], g2: c0[1] },
    { g1: B[2], g2: c0[2] },
    { g1: A[0].negate(), g2: k0[0] },
    { g1: A[1].negate(), g2: k0[1] },
    { g1: A[2].negate(), g2: k0[2] },
  ]);
  return Fp12.toBytes(K);
}

/** Bytes that identify a public key (for fingerprints). */
export function publicKeyBytes(pk) {
  return utf8.encode(`${pk.scheme}|${pk.H1}|${pk.H2}|${pk.T1}|${pk.T2}`);
}
