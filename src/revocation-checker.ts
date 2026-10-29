import { createHash } from "node:crypto";
import type { RevocationStatus } from "../native/index.js";
import {
  type CacheStore,
  createMemoryCache,
  createRevocationCache
} from "./cache.ts";
import {
  createDiagnosticReporter,
  type DiagnosticCallback,
  type RevocationReport
} from "./diagnostics.ts";
import {
  type CrlValidationResult,
  type OcspValidationResult,
  validateCrl,
  validateOcsp
} from "./revocation-validation.ts";

const DEFAULT_MAX_CACHE_AGE_MS = 60 * 60 * 1000;

interface RevocationCheckOptions<
  T extends RevocationResult = CrlValidationResult | OcspValidationResult
> {
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  source: string;
  load: () => Promise<Uint8Array>;
  checkDate?: Date;
  certificateIndex?: number;
  validate?: (data: Uint8Array) => Promise<T>;
  shouldStop?: () => boolean;
}

type RevocationResult =
  | { status: Exclude<`${RevocationStatus}`, "unknown">; nextUpdate: Date }
  | { status: "unknown"; code: string; message: string };

function snapshot<T extends RevocationResult>(
  options: RevocationCheckOptions<T>
): RevocationCheckOptions<T> {
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
  const evidenceCache = createRevocationCache({ cache, now, maxCacheAgeMs });

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

  async function check<T extends RevocationResult>(
    key: string,
    load: () => Promise<Uint8Array>,
    validate: (data: Uint8Array) => Promise<T>,
    notify: RevocationReport,
    shouldStop: () => boolean = () => false
  ): Promise<T> {
    const cached = await evidenceCache.read(key, notify);
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
      await evidenceCache.discard(key, notify);
      if (shouldStop()) return result;
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
      await evidenceCache.write(key, data, result.nextUpdate, notify);
    }
    return result;
  }

  return {
    async checkCrl(
      options: RevocationCheckOptions<CrlValidationResult>
    ): Promise<CrlValidationResult> {
      options = snapshot(options);
      const checkDate = options.checkDate;
      if (checkDate && Number.isNaN(checkDate.getTime()))
        throw new TypeError("checkDate must be a valid date");
      return check(
        cacheKey("crl", options),
        options.load,
        options.validate ??
          ((crl) =>
            validateCrl({
              certificate: options.certificate,
              issuerCertificate: options.issuerCertificate,
              crl,
              checkDate: checkDate ?? new Date(now())
            })),
        (event) =>
          report({
            ...event,
            mechanism: "crl",
            certificateIndex: options.certificateIndex
          }),
        options.shouldStop
      );
    },
    async checkOcsp(
      options: RevocationCheckOptions<OcspValidationResult>
    ): Promise<OcspValidationResult> {
      options = snapshot(options);
      const checkDate = options.checkDate;
      if (checkDate && Number.isNaN(checkDate.getTime()))
        throw new TypeError("checkDate must be a valid date");
      return check(
        cacheKey("ocsp", options),
        options.load,
        options.validate ??
          ((response) =>
            validateOcsp({
              certificate: options.certificate,
              issuerCertificate: options.issuerCertificate,
              response,
              checkDate: checkDate ?? new Date(now())
            })),
        (event) =>
          report({
            ...event,
            mechanism: "ocsp",
            certificateIndex: options.certificateIndex
          }),
        options.shouldStop
      );
    }
  };
}
