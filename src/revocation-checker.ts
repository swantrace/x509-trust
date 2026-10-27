import { createHash } from "node:crypto";
import type { Certificate } from "pkijs";
import { type CacheStore, createMemoryCache } from "./cache.ts";
import { type CrlValidationResult, validateCrl } from "./crl.ts";
import { type OcspValidationResult, validateOcsp } from "./ocsp.ts";

const DEFAULT_MAX_CACHE_AGE_MS = 60 * 60 * 1000;

interface RevocationCheckOptions {
  certificate: Certificate;
  issuerCertificate: Certificate;
  source: string;
  load: () => Promise<Uint8Array>;
  checkDate?: Date;
}

type RevocationResult =
  | { status: "good" | "revoked"; nextUpdate: Date }
  | { status: "unknown" };

function certificateDer(certificate: Certificate): string {
  return Buffer.from(certificate.toSchema(true).toBER(false)).toString(
    "base64"
  );
}

export function createRevocationChecker({
  now = Date.now,
  cache = createMemoryCache({ now }),
  maxCacheAgeMs = DEFAULT_MAX_CACHE_AGE_MS,
  cacheKeyPrefix = "x509-trust:revocation:v1"
}: {
  now?: () => number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
} = {}) {
  if (!Number.isFinite(maxCacheAgeMs) || maxCacheAgeMs <= 0) {
    throw new TypeError("maxCacheAgeMs must be positive and finite");
  }

  function cacheKey(
    kind: "crl" | "ocsp",
    options: RevocationCheckOptions
  ): string {
    const components = [
      options.source,
      certificateDer(options.issuerCertificate)
    ];
    if (kind === "ocsp") components.push(certificateDer(options.certificate));
    const digest = createHash("sha256")
      .update(JSON.stringify(components))
      .digest("base64url");
    return `${cacheKeyPrefix}:${kind}:${digest}`;
  }

  async function discard(key: string): Promise<void> {
    try {
      await cache.delete(key);
    } catch {
      // A cache outage must not prevent fresh validation.
    }
  }

  async function read(key: string): Promise<Uint8Array | null> {
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
      // Treat unavailable or malformed cache entries as misses.
    }
    await discard(key);
    return null;
  }

  async function check<T extends RevocationResult>(
    key: string,
    load: () => Promise<Uint8Array>,
    validate: (data: Uint8Array) => Promise<T>
  ): Promise<T> {
    const cached = await read(key);
    if (cached !== null) {
      const result = await validate(cached);
      if (result.status !== "unknown") return result;
      await discard(key);
    }

    const data = Uint8Array.from(await load());
    const result = await validate(data);
    if (result.status !== "unknown") {
      const cachedAt = now();
      const expiresAt = Math.min(
        result.nextUpdate.getTime(),
        cachedAt + maxCacheAgeMs
      );
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
          // The validated result remains usable if the cache cannot be written.
        }
      }
    }
    return result;
  }

  return {
    async checkCrl(
      options: RevocationCheckOptions
    ): Promise<CrlValidationResult> {
      const checkDate = options.checkDate;
      if (checkDate && Number.isNaN(checkDate.getTime()))
        throw new TypeError("checkDate must be a valid date");
      return check(cacheKey("crl", options), options.load, (crl) =>
        validateCrl({
          certificate: options.certificate,
          issuerCertificate: options.issuerCertificate,
          crl,
          checkDate: checkDate ?? new Date(now())
        })
      );
    },
    async checkOcsp(
      options: RevocationCheckOptions
    ): Promise<OcspValidationResult> {
      const checkDate = options.checkDate;
      if (checkDate && Number.isNaN(checkDate.getTime()))
        throw new TypeError("checkDate must be a valid date");
      return check(cacheKey("ocsp", options), options.load, (response) =>
        validateOcsp({
          certificate: options.certificate,
          issuerCertificate: options.issuerCertificate,
          response,
          checkDate: checkDate ?? new Date(now())
        })
      );
    }
  };
}
