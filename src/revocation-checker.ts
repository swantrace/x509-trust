import { createHash } from "node:crypto";
import { type CacheStore, createMemoryCache } from "./cache.ts";
import { type CrlValidationResult, validateCrl } from "./crl.ts";
import {
  createDiagnosticReporter,
  type DiagnosticCallback,
  type DiagnosticEvent
} from "./diagnostics.ts";
import { type OcspValidationResult, validateOcsp } from "./ocsp.ts";

const DEFAULT_MAX_CACHE_AGE_MS = 60 * 60 * 1000;

interface RevocationCheckOptions {
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  source: string;
  load: () => Promise<Uint8Array>;
  checkDate?: Date;
  certificateIndex?: number;
}

type RevocationResult =
  | { status: "good" | "revoked"; nextUpdate: Date }
  | { status: "unknown"; code: string; message: string };

function snapshot(options: RevocationCheckOptions): RevocationCheckOptions {
  return {
    ...options,
    certificate: Uint8Array.from(options.certificate),
    issuerCertificate: Uint8Array.from(options.issuerCertificate)
  };
}

export function createRevocationChecker({
  now = Date.now,
  cache = createMemoryCache({ now }),
  maxCacheAgeMs = DEFAULT_MAX_CACHE_AGE_MS,
  cacheKeyPrefix = "x509-trust:revocation:v1",
  onDiagnostic
}: {
  now?: () => number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  onDiagnostic?: DiagnosticCallback;
} = {}) {
  if (!Number.isFinite(maxCacheAgeMs) || maxCacheAgeMs <= 0) {
    throw new TypeError("maxCacheAgeMs must be positive and finite");
  }
  const report = createDiagnosticReporter(onDiagnostic);

  type Report = (
    event: Pick<DiagnosticEvent, "event" | "message" | "code" | "status">
  ) => void;

  function cacheKey(
    kind: "crl" | "ocsp",
    options: RevocationCheckOptions
  ): string {
    const components = [
      options.source,
      Buffer.from(options.issuerCertificate).toString("base64")
    ];
    if (kind === "ocsp")
      components.push(Buffer.from(options.certificate).toString("base64"));
    const digest = createHash("sha256")
      .update(JSON.stringify(components))
      .digest("base64url");
    return `${cacheKeyPrefix}:${kind}:${digest}`;
  }

  async function discard(key: string, notify: Report): Promise<void> {
    try {
      await cache.delete(key);
    } catch {
      notify({
        event: "cache_error",
        message: "Unable to delete cached evidence"
      });
    }
  }

  async function read(key: string, notify: Report): Promise<Uint8Array | null> {
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

  async function check<T extends RevocationResult>(
    key: string,
    load: () => Promise<Uint8Array>,
    validate: (data: Uint8Array) => Promise<T>,
    notify: Report
  ): Promise<T> {
    const cached = await read(key, notify);
    if (cached !== null) {
      notify({ event: "cache_hit", message: "Revalidating cached evidence" });
      const result = await validate(cached);
      if (result.status !== "unknown") {
        notify({
          event: "revocation_result",
          status: result.status,
          message: "Cached evidence established revocation status"
        });
        return result;
      }
      notify({
        event: "revocation_result",
        status: result.status,
        code: result.code,
        message: result.message
      });
      notify({
        event: "cache_discarded",
        message: "Cached evidence did not establish revocation status"
      });
      await discard(key, notify);
    } else {
      notify({ event: "cache_miss", message: "No usable cached evidence" });
    }

    let result: T;
    let data: Uint8Array;
    try {
      data = Uint8Array.from(await load());
      result = await validate(data);
    } catch (error) {
      notify({
        event: "revocation_error",
        message: "Unable to load or validate revocation evidence"
      });
      throw error;
    }
    notify({
      event: "revocation_result",
      status: result.status,
      ...(result.status === "unknown"
        ? { code: result.code, message: result.message }
        : { message: "Loaded evidence established revocation status" })
    });
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
          notify({
            event: "cache_error",
            message: "Unable to cache validated evidence"
          });
        }
      }
    }
    return result;
  }

  return {
    async checkCrl(
      options: RevocationCheckOptions
    ): Promise<CrlValidationResult> {
      options = snapshot(options);
      const checkDate = options.checkDate;
      if (checkDate && Number.isNaN(checkDate.getTime()))
        throw new TypeError("checkDate must be a valid date");
      return check(
        cacheKey("crl", options),
        options.load,
        (crl) =>
          validateCrl({
            certificate: options.certificate,
            issuerCertificate: options.issuerCertificate,
            crl,
            checkDate: checkDate ?? new Date(now())
          }),
        (event) =>
          report({
            ...event,
            mechanism: "crl",
            certificateIndex: options.certificateIndex
          })
      );
    },
    async checkOcsp(
      options: RevocationCheckOptions
    ): Promise<OcspValidationResult> {
      options = snapshot(options);
      const checkDate = options.checkDate;
      if (checkDate && Number.isNaN(checkDate.getTime()))
        throw new TypeError("checkDate must be a valid date");
      return check(
        cacheKey("ocsp", options),
        options.load,
        (response) =>
          validateOcsp({
            certificate: options.certificate,
            issuerCertificate: options.issuerCertificate,
            response,
            checkDate: checkDate ?? new Date(now())
          }),
        (event) =>
          report({
            ...event,
            mechanism: "ocsp",
            certificateIndex: options.certificateIndex
          })
      );
    }
  };
}
