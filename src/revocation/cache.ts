// Defines asynchronous cache storage and provides a bounded in-memory cache with expiration.
export interface CacheStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs: number): Promise<void>;
  delete(key: string): Promise<void>;
}

export function createMemoryCache({
  maxEntries = 256,
  now = Date.now
}: {
  maxEntries?: number;
  now?: () => number;
} = {}): CacheStore {
  if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
    throw new TypeError("maxEntries must be a positive integer");
  }
  const entries = new Map<string, { value: string; expiresAt: number }>();

  return {
    async get(key) {
      const entry = entries.get(key);
      if (!entry) return null;
      if (entry.expiresAt <= now()) {
        entries.delete(key);
        return null;
      }
      return entry.value;
    },
    async set(key, value, ttlMs) {
      if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
        throw new TypeError("ttlMs must be positive and finite");
      }
      entries.delete(key);
      if (entries.size >= maxEntries) {
        entries.delete(entries.keys().next().value!);
      }
      entries.set(key, { value, expiresAt: now() + ttlMs });
    },
    async delete(key) {
      entries.delete(key);
    }
  };
}
