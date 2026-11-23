import mongoose from 'mongoose';
import { createLogger } from '@secureshare/server-common';
import { loadConfig } from './config.js';
import { createModels } from './models.js';
import { createStorage } from './storage.js';
import { createAuthorityClient } from './authorityClient.js';
import { createApp } from './app.js';

const config = loadConfig();
const logger = createLogger({ name: 'api', level: config.logLevel });

const conn = await mongoose.createConnection(config.mongoUri, { serverSelectionTimeoutMS: 10_000 }).asPromise();
const models = createModels(conn);
await Promise.all(Object.values(models).map((m) => m.init()));
const storage = await createStorage(config.storageDir);
const authority = createAuthorityClient({ baseUrl: config.authorityInternalUrl, token: config.internalToken });

const app = await createApp({ config, models, storage, authority, logger, isDbReady: () => conn.readyState === 1 });
const server = app.listen(config.port, config.host, () => logger.info(`API listening on :${config.port}`));
server.requestTimeout = 10 * 60_000; // large uploads on slow links

// Remove registrations whose ciphertext never arrived.
const sweep = setInterval(async () => {
  try {
    const stale = await models.File.find({ status: 'pending', createdAt: mongoose.trusted({ $lt: new Date(Date.now() - 60 * 60_000) }) }).select('_id blobName');
    for (const f of stale) {
      if (f.blobName) await storage.remove(f.blobName);
      await models.File.deleteOne({ _id: f._id, status: 'pending' });
    }
    if (stale.length) logger.info({ count: stale.length }, 'removed stale pending uploads');
  } catch (err) {
    logger.error({ err }, 'pending sweep failed');
  }
}, 10 * 60_000);
sweep.unref();

function shutdown(signal) {
  logger.info({ signal }, 'shutting down');
  server.close(() => conn.close().finally(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
