// Ciphertext blob storage on local disk. Names are random and reveal nothing.
// Swap this module for an S3/GCS implementation with the same interface if needed.
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export class PayloadTooLargeError extends Error {}

const NAME_RE = /^[a-f0-9]{48}$/;

export async function createStorage(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmpDir = path.join(dir, '.tmp');
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  const resolve = (name) => {
    if (!NAME_RE.test(name)) throw new Error('invalid blob name');
    return path.join(dir, name);
  };

  return {
    dir,
    /** Stream `source` to disk, hashing as it goes. Rejects with PayloadTooLargeError past maxBytes. */
    async put(source, maxBytes) {
      const name = randomBytes(24).toString('hex');
      const tmp = path.join(tmpDir, name);
      const hash = createHash('sha256');
      let size = 0;
      const meter = new Transform({
        transform(chunk, _enc, cb) {
          size += chunk.length;
          if (size > maxBytes) return cb(new PayloadTooLargeError());
          hash.update(chunk);
          return cb(null, chunk);
        },
      });
      try {
        await pipeline(source, meter, createWriteStream(tmp, { flags: 'wx', mode: 0o600 }));
        await rename(tmp, resolve(name));
      } catch (err) {
        await rm(tmp, { force: true });
        throw err;
      }
      return { name, size, sha256: hash.digest('hex') };
    },
    open: (name) => createReadStream(resolve(name)),
    size: async (name) => (await stat(resolve(name))).size,
    remove: (name) => rm(resolve(name), { force: true }),
  };
}
