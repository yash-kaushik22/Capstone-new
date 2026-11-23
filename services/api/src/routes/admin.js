import express from 'express';
import mongoose from 'mongoose';
import { AppError } from '@secureshare/server-common';

export function adminRouter({ models, audit, session }) {
  const { User, Audit } = models;
  const router = express.Router();
  router.use(session.requireUser, session.requireAdmin);

  router.get('/users', async (_req, res) => {
    const users = await User.find().sort({ username: 1 }).limit(2000).select('username role createdAt lockedUntil').lean();
    res.json({
      users: users.map((u) => ({
        id: String(u._id),
        username: u.username,
        role: u.role,
        createdAt: u.createdAt,
        locked: Boolean(u.lockedUntil && u.lockedUntil > new Date()),
      })),
    });
  });

  router.post('/users/:id/unlock', async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new AppError(404, 'User not found');
    const r = await User.updateOne({ _id: req.params.id }, { $set: { failedLogins: 0, lockedUntil: null } });
    if (!r.matchedCount) throw new AppError(404, 'User not found');
    audit(req, 'admin.unlock', { target: req.params.id });
    res.status(204).end();
  });

  router.get('/audit', async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    const events = await Audit.find().sort({ at: -1 }).limit(limit).lean();
    res.json({ events: events.map(({ _id, ...e }) => ({ id: String(_id), ...e })) });
  });

  return router;
}
