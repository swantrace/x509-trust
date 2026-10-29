import type { RevocationReport } from "./diagnostics.ts";

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

export function createRevocationCache({
  cache,
  now,
  maxCacheAgeMs
}: {
  cache: CacheStore;
  now: () => number;
  maxCacheAgeMs: number;
}) {
  async function discard(key: string, notify: RevocationReport): Promise<void> {
    try {
      await cache.delete(key);
    } catch {
      notify({
        event: "cache_error",
        message: "Unable to delete cached evidence"
      });
    }
  }

  async function read(
    key: string,
    notify: RevocationReport
  ): Promise<Uint8Array | null> {
    try {
      const stored = await cache.get(key);
      if (stored === null) return null;
      const entry: unknown = JSON.parse(stored);
      if (
        entry !== null &&
        typeof entry === "object" &&
        "der" in entry &&
        typeof entry.der === "string" &&
        "expiresAt" in entry &&
        typeof entry.expiresAt === "number" &&
        Number.isFinite(entry.expiresAt) &&
        entry.expiresAt > now() &&
        "cachedAt" in entry &&
        typeof entry.cachedAt === "number" &&
        Number.isFinite(entry.cachedAt) &&
        entry.cachedAt <= now() &&
        entry.cachedAt + maxCacheAgeMs > now()
      ) {
        return Buffer.from(entry.der, "base64");
      }
    } catch {
      notify({
        event: "cache_error",
        message: "Unable to read or parse cached evidence"
      });
    }
    notify({
      event: "cache_discarded",
      message: "Cached evidence is expired or unusable"
    });
    await discard(key, notify);
    return null;
  }

  async function write(
    key: string,
    data: Uint8Array,
    nextUpdate: Date,
    notify: RevocationReport
  ): Promise<void> {
    const cachedAt = now();
    const expiresAt = Math.min(nextUpdate.getTime(), cachedAt + maxCacheAgeMs);
    const ttlMs = Math.floor(expiresAt - now());
    if (ttlMs > 0) {
      try {
        await cache.set(
          key,
          JSON.stringify({
            der: Buffer.from(data).toString("base64"),
            expiresAt,
            cachedAt
          }),
          ttlMs
        );
      } catch {
        notify({
          event: "cache_error",
          message: "Unable to cache validated evidence"
        });
      }
    }
  }

  return { read, write, discard };
}
