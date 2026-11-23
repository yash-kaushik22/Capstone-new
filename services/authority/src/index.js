import mongoose from 'mongoose';
import { createLogger } from '@secureshare/server-common';
import { loadConfig } from './config.js';
import { createModels } from './models.js';
import { createApps, loadOrCreateKeys } from './app.js';

const config = loadConfig();
const logger = createLogger({ name: 'authority', level: config.logLevel });

const conn = await mongoose.createConnection(config.mongoUri, { serverSelectionTimeoutMS: 10_000 }).asPromise();
const models = createModels(conn);
await Promise.all(Object.values(models).map((m) => m.init()));
const keys = await loadOrCreateKeys(models, config.kek, logger);
logger.info({ fingerprint: keys.fingerprint }, 'CP-ABE public key loaded');

const { app, internal } = await createApps({ config, models, keys, logger });
const servers = [
  app.listen(config.port, config.host, () => logger.info(`public API on :${config.port}`)),
  internal.listen(config.internalPort, config.host, () => logger.info(`internal API on :${config.internalPort}`)),
];

function shutdown(signal) {
  logger.info({ signal }, 'shutting down');
  Promise.all(servers.map((s) => new Promise((r) => s.close(r))))
    .then(() => conn.close())
    .finally(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
