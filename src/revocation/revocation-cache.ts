// Builds revocation cache keys and reads, expires, and stores response bytes.
import { createHash } from "node:crypto";
import { z } from "zod";
import type { SourceDiagnosticReporter } from "../diagnostics.ts";
import type { CacheStore } from "./cache.ts";
import type { SourceCheckOptions } from "./revocation.ts";
export interface RevocationCache {
  cacheKey(kind: "crl" | "ocsp", options: SourceCheckOptions): string;
  read(
    key: string,
    notify: SourceDiagnosticReporter
  ): Promise<Uint8Array | null>;
  discard(key: string, notify: SourceDiagnosticReporter): Promise<void>;
  write(
    key: string,
    data: Uint8Array,
    nextUpdate: Date,
    notify: SourceDiagnosticReporter
  ): Promise<void>;
}

const cachedRevocationSchema = z.object({
  der: z.string(),
  expiresAt: z.number(),
  cachedAt: z.number()
});

function digestBytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function createRevocationCache({
  cache,
  now,
  maxCacheAgeMs,
  cacheKeyPrefix
}: {
  cache: CacheStore;
  now: () => number;
  maxCacheAgeMs: number;
  cacheKeyPrefix: string;
}): RevocationCache {
  function cacheKey(kind: "crl" | "ocsp", options: SourceCheckOptions): string {
    const components = [
      options.source,
      digestBytes(options.issuerDer),
      ...(kind === "ocsp"
        ? [
            digestBytes(options.certificateDer),
            options.ocspRequestDer ? digestBytes(options.ocspRequestDer) : ""
          ]
        : [])
    ];
    const digest = createHash("sha256")
      .update(JSON.stringify(components))
      .digest("base64url");
    return `${cacheKeyPrefix}:${kind}:${digest}`;
  }

  async function discard(
    key: string,
    notify: SourceDiagnosticReporter
  ): Promise<void> {
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
    notify: SourceDiagnosticReporter
  ): Promise<Uint8Array | null> {
    try {
      const stored = await cache.get(key);
      if (stored === null) return null;
      const parsed = cachedRevocationSchema.safeParse(JSON.parse(stored));
      if (parsed.success) {
        const { der, expiresAt, cachedAt } = parsed.data;
        const currentTime = now();
        if (
          expiresAt > currentTime &&
          cachedAt <= currentTime &&
          cachedAt + maxCacheAgeMs > currentTime
        ) {
          return Uint8Array.from(Buffer.from(der, "base64"));
        }
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

  function write(
    key: string,
    data: Uint8Array,
    nextUpdate: Date,
    notify: SourceDiagnosticReporter
  ): Promise<void> {
    const cachedAt = now();
    const expiresAt = Math.min(nextUpdate.getTime(), cachedAt + maxCacheAgeMs);
    const ttlMs = Math.floor(expiresAt - now());
    if (ttlMs > 0) {
      const persist = async () => {
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
      };
      return persist();
    }
    return Promise.resolve();
  }
  return { cacheKey, read, discard, write };
}
