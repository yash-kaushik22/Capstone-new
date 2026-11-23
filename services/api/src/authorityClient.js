// Fetches a user's current attributes from the authority's internal endpoint.
// Results are cached for a few seconds; on any failure we fail closed.
import { AppError } from '@secureshare/server-common';

export function createAuthorityClient({ baseUrl, token, ttlMs = 5000, fetchImpl = globalThis.fetch }) {
  const cache = new Map();
  return {
    async attributesOf(userId) {
      const hit = cache.get(userId);
      if (hit && hit.until > Date.now()) return hit.attributes;
      let res;
      try {
        res = await fetchImpl(`${baseUrl}/internal/users/${encodeURIComponent(userId)}/attributes`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(3000),
        });
      } catch {
        throw new AppError(503, 'Attribute authority unavailable');
      }
      if (!res.ok) throw new AppError(503, 'Attribute authority unavailable');
      const { attributes } = await res.json();
      if (!Array.isArray(attributes)) throw new AppError(503, 'Attribute authority returned bad data');
      if (cache.size > 10_000) cache.clear();
      cache.set(userId, { attributes, until: Date.now() + ttlMs });
      return attributes;
    },
    invalidate: (userId) => cache.delete(userId),
  };
}
