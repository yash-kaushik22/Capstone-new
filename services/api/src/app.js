import express from 'express';
import {
  applyBaseSecurity, csrfGuard, errorHandler, httpLogger, limiter, notFound, sessionVerifier,
} from '@secureshare/server-common';
import { authRouter } from './routes/auth.js';
import { filesRouter } from './routes/files.js';
import { adminRouter } from './routes/admin.js';

export async function createApp({ config, models, storage, authority, logger, isDbReady = () => true }) {
  const session = await sessionVerifier({
    publicKeyPem: config.jwtPublicKeyPem,
    cookieName: config.cookieName,
    isRevoked: async (p) => Boolean(p.jti && (await models.RevokedToken.exists({ _id: p.jti }))),
  });

  const audit = (req, action, { target, outcome = 'ok', details, user } = {}) => {
    models.Audit.create({
      userId: user ? String(user._id) : req.user?.id,
      username: user ? user.username : req.user?.username,
      action,
      target,
      outcome,
      ip: req.ip,
      details,
    }).catch((err) => logger.error({ err }, 'audit write failed'));
  };

  const app = express();
  applyBaseSecurity(app, { trustProxy: config.trustProxy });
  app.use(httpLogger(logger));
  app.use(limiter({ windowMs: 60_000, limit: 600 }));
  app.use(csrfGuard({ publicOrigin: config.publicOrigin }));

  const api = express.Router();
  api.get('/health', (_req, res) => {
    const ready = isDbReady();
    res.status(ready ? 200 : 503).json({ status: ready ? 'ok' : 'degraded' });
  });
  api.get('/meta', (_req, res) => {
    res.json({ maxUploadBytes: config.maxUploadBytes, registrationOpen: config.registrationOpen, minKdfIterations: config.kdfIterations });
  });
  // JSON parsing everywhere except the raw ciphertext upload route.
  const json = express.json({ limit: '128kb' });
  api.use((req, res, next) => (req.path.endsWith('/blob') ? next() : json(req, res, next)));
  api.use('/auth', await authRouter({ config, models, audit, session }));
  api.use('/files', filesRouter({ config, models, storage, authority, audit, session }));
  api.use('/admin', adminRouter({ models, audit, session }));

  app.use('/api', api);
  app.use(notFound);
  app.use(errorHandler(logger));
  return app;
}
