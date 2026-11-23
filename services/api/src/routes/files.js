import express from 'express';
import mongoose from 'mongoose';
import { z } from 'zod';
import {
  abe, canonicalJson, policy as policyLib, sha256, toHex, utf8, verifyObject, FILE_ID_RE,
} from '@secureshare/crypto';
import { AppError, limiter } from '@secureshare/server-common';
import { PayloadTooLargeError } from '../storage.js';

const b64u = (min, max) => z.string().min(min).max(max).regex(/^[A-Za-z0-9_-]+$/);
const hex64 = z.string().regex(/^[a-f0-9]{64}$/);
const fileIdSchema = z.string().regex(FILE_ID_RE);
const G1 = z.string().regex(/^[A-Za-z0-9_-]{64}$/); // 48-byte compressed point
const G2 = z.string().regex(/^[A-Za-z0-9_-]{128}$/); // 96-byte compressed point

const abeEnvelopeSchema = z.strictObject({
  v: z.literal(1),
  scheme: z.literal(abe.SCHEME),
  policy: z.string().min(3).max(2048),
  header: z.strictObject({ c0: z.array(G2).length(3), rows: z.array(z.array(G1).length(3)).min(1).max(policyLib.LIMITS.maxLeaves) }),
  ct: b64u(40, 200),
});

const manifestSchema = z.strictObject({
  v: z.literal(1),
  fileId: fileIdSchema,
  ownerId: z.string().regex(/^[a-f0-9]{24}$/),
  policy: z.string().max(2048),
  ciphertext: z.strictObject({ sha256: hex64, size: z.number().int().min(32) }),
  encMetaSha256: hex64,
  abeEnvelopeSha256: hex64,
  ownerEnvelopeSha256: hex64,
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime().optional(),
});

const createBody = z.strictObject({
  fileId: fileIdSchema,
  encMeta: b64u(40, 4096),
  abeEnvelope: abeEnvelopeSchema,
  ownerEnvelope: z.string().regex(/^[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{40,200}$/),
  manifest: manifestSchema,
  signature: b64u(80, 100),
});

const policyBody = z.strictObject({ abeEnvelope: abeEnvelopeSchema, manifest: manifestSchema, signature: b64u(80, 100) });

const hashHex = async (s) => toHex(await sha256(utf8.encode(s)));

/** Structural checks: the policy is canonical and the ABE header has one row per policy leaf. */
function checkEnvelope(env) {
  let ast;
  try {
    ast = policyLib.parsePolicy(env.policy);
  } catch (err) {
    throw new AppError(400, `Invalid policy: ${err.message}`);
  }
  if (policyLib.formatPolicy(ast) !== env.policy) throw new AppError(400, 'Policy is not in canonical form');
  if (env.header.rows.length !== policyLib.leaves(ast).length) throw new AppError(400, 'ABE header does not match the policy');
  return ast;
}

export function filesRouter({ config, models, storage, authority, audit, session }) {
  const { File, User } = models;
  const router = express.Router();
  router.use(session.requireUser);
  const uploadLimiter = limiter({ windowMs: 60 * 60_000, limit: 120, keyGenerator: (req) => req.user.id, message: 'Upload limit reached, try later' });

  async function effectiveAttributes(user) {
    return new Set([...(await authority.attributesOf(user.id)), `user:${user.username}`]);
  }

  /** Owner, or a user whose current attributes satisfy the file's policy. Same 404 for all denials. */
  async function accessibleFile(req, { requireReady = true } = {}) {
    const parsed = fileIdSchema.safeParse(req.params.id);
    if (!parsed.success) throw new AppError(404, 'File not found');
    const file = await File.findById(parsed.data);
    if (!file || (requireReady && file.status !== 'ready')) throw new AppError(404, 'File not found');
    if (String(file.ownerId) === req.user.id) return { file, isOwner: true };
    const attrs = await effectiveAttributes(req.user);
    if (!policyLib.satisfies(policyLib.parsePolicy(file.policy), attrs)) {
      audit(req, 'file.access', { target: file.id, outcome: 'denied' });
      throw new AppError(404, 'File not found');
    }
    return { file, isOwner: false };
  }

  async function ownedFile(req, { requireReady = true } = {}) {
    const parsed = fileIdSchema.safeParse(req.params.id);
    if (!parsed.success) throw new AppError(404, 'File not found');
    const file = await File.findOne({ _id: parsed.data, ownerId: req.user.id });
    if (!file || (requireReady && file.status !== 'ready')) throw new AppError(404, 'File not found');
    return file;
  }

  async function verifySigned(req, { manifest, signature, abeEnvelope }) {
    const owner = await User.findById(req.user.id).select('sigPublicKey').lean();
    try {
      await verifyObject(owner.sigPublicKey, manifest, signature);
    } catch {
      throw new AppError(400, 'Manifest signature is invalid');
    }
    if (manifest.ownerId !== req.user.id) throw new AppError(400, 'Manifest owner mismatch');
    if (manifest.policy !== abeEnvelope.policy) throw new AppError(400, 'Manifest policy mismatch');
    if (manifest.abeEnvelopeSha256 !== (await hashHex(canonicalJson(abeEnvelope)))) throw new AppError(400, 'Manifest does not match ABE envelope');
  }

  const listItem = (f, ownerName) => ({
    id: f.id,
    ownerId: String(f.ownerId),
    ownerUsername: ownerName,
    policy: f.policy,
    size: f.size,
    createdAt: f.createdAt,
    updatedAt: f.updatedAt,
  });

  // 1) Register a file: metadata, envelopes and signed manifest. Ciphertext follows in step 2.
  router.post('/', uploadLimiter, async (req, res) => {
    const body = createBody.parse(req.body);
    checkEnvelope(body.abeEnvelope);
    const { manifest } = body;
    if (manifest.fileId !== body.fileId) throw new AppError(400, 'Manifest file id mismatch');
    if (manifest.ciphertext.size > config.maxUploadBytes) throw new AppError(413, `File exceeds the ${config.maxUploadBytes}-byte limit`);
    await verifySigned(req, body);
    if (manifest.encMetaSha256 !== (await hashHex(body.encMeta))) throw new AppError(400, 'Manifest does not match metadata');
    if (manifest.ownerEnvelopeSha256 !== (await hashHex(body.ownerEnvelope))) throw new AppError(400, 'Manifest does not match owner envelope');
    await File.create({
      _id: body.fileId,
      ownerId: req.user.id,
      policy: body.abeEnvelope.policy,
      encMeta: body.encMeta,
      abeEnvelope: body.abeEnvelope,
      ownerEnvelope: body.ownerEnvelope,
      manifest,
      signature: body.signature,
    });
    audit(req, 'file.create', { target: body.fileId, details: { policy: body.abeEnvelope.policy } });
    res.status(201).json({ id: body.fileId });
  });

  // 2) Upload ciphertext. Size and SHA-256 must match the signed manifest.
  router.put('/:id/blob', async (req, res) => {
    const file = await ownedFile(req, { requireReady: false });
    if (file.status !== 'pending') throw new AppError(409, 'Ciphertext already uploaded');
    if (!req.is('application/octet-stream')) throw new AppError(415, 'Content-Type must be application/octet-stream');
    const expected = file.manifest.ciphertext;
    const declared = Number(req.get('content-length'));
    if (Number.isFinite(declared) && declared !== expected.size) throw new AppError(400, 'Content-Length does not match manifest');
    let stored;
    try {
      stored = await storage.put(req, Math.min(config.maxUploadBytes, expected.size));
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        res.set('Connection', 'close');
        throw new AppError(413, 'Ciphertext larger than declared');
      }
      throw err;
    }
    if (stored.size !== expected.size || stored.sha256 !== expected.sha256) {
      await storage.remove(stored.name);
      throw new AppError(400, 'Ciphertext does not match the signed manifest');
    }
    const updated = await File.updateOne({ _id: file.id, status: 'pending' }, { $set: { status: 'ready', blobName: stored.name, size: stored.size } });
    if (!updated.modifiedCount) {
      await storage.remove(stored.name);
      throw new AppError(409, 'Ciphertext already uploaded');
    }
    audit(req, 'file.upload', { target: file.id, details: { size: stored.size } });
    res.status(204).end();
  });

  // List files I own, or files whose policy my current attributes satisfy.
  router.get('/', async (req, res) => {
    const scope = req.query.scope === 'shared' ? 'shared' : 'owned';
    let files;
    if (scope === 'owned') {
      files = await File.find({ ownerId: req.user.id, status: 'ready' }).sort({ createdAt: -1 }).limit(1000);
    } else {
      const attrs = await effectiveAttributes(req.user);
      const candidates = await File.find({ status: 'ready', ownerId: mongoose.trusted({ $ne: req.user.id }) }).sort({ createdAt: -1 }).limit(5000);
      files = candidates.filter((f) => policyLib.satisfies(policyLib.parsePolicy(f.policy), attrs)).slice(0, 1000);
    }
    const owners = await User.find({ _id: mongoose.trusted({ $in: [...new Set(files.map((f) => String(f.ownerId)))] }) }).select('username').lean();
    const names = new Map(owners.map((o) => [String(o._id), o.username]));
    res.json({ files: files.map((f) => listItem(f, names.get(String(f.ownerId)))) });
  });

  // Full record (envelopes, signed manifest, owner's signing key) for decryption.
  router.get('/:id', async (req, res) => {
    const { file } = await accessibleFile(req);
    const owner = await User.findById(file.ownerId).select('username sigPublicKey').lean();
    res.json({
      ...listItem(file, owner?.username),
      encMeta: file.encMeta,
      abeEnvelope: file.abeEnvelope,
      ownerEnvelope: file.ownerEnvelope,
      manifest: file.manifest,
      signature: file.signature,
      ownerSigPublicKey: owner && { kty: owner.sigPublicKey.kty, crv: owner.sigPublicKey.crv, x: owner.sigPublicKey.x, y: owner.sigPublicKey.y },
    });
  });

  router.get('/:id/blob', async (req, res) => {
    const { file } = await accessibleFile(req);
    audit(req, 'file.download', { target: file.id });
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(file.size),
      'Content-Disposition': 'attachment; filename="ciphertext.bin"',
      'X-Content-Type-Options': 'nosniff',
    });
    const stream = storage.open(file.blobName);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });

  // Owner re-wraps the file secret under a new policy (signed).
  router.put('/:id/policy', async (req, res) => {
    const file = await ownedFile(req);
    const body = policyBody.parse(req.body);
    checkEnvelope(body.abeEnvelope);
    await verifySigned(req, body);
    const old = file.manifest;
    const m = body.manifest;
    const unchanged = ['fileId', 'ownerId', 'encMetaSha256', 'ownerEnvelopeSha256', 'createdAt'].every((k) => m[k] === old[k])
      && m.ciphertext.sha256 === old.ciphertext.sha256 && m.ciphertext.size === old.ciphertext.size;
    if (!unchanged) throw new AppError(400, 'Only the policy may change');
    const before = file.policy;
    file.policy = body.abeEnvelope.policy;
    file.abeEnvelope = body.abeEnvelope;
    file.manifest = m;
    file.signature = body.signature;
    file.markModified('abeEnvelope');
    file.markModified('manifest');
    await file.save();
    audit(req, 'file.policy', { target: file.id, details: { before, after: file.policy } });
    res.json(listItem(file, req.user.username));
  });

  router.delete('/:id', async (req, res) => {
    const file = await ownedFile(req, { requireReady: false });
    if (file.blobName) await storage.remove(file.blobName);
    await File.deleteOne({ _id: file.id });
    audit(req, 'file.delete', { target: file.id });
    res.status(204).end();
  });

  return router;
}
