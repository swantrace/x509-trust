import { createHash } from "node:crypto";
import {
  createDiagnosticReporter,
  type DiagnosticCallback,
  type DiagnosticEvent
} from "../diagnostics.ts";
import type { CrlValidationResult } from "../engine/crl.ts";
import type { OcspValidationResult } from "../engine/ocsp.ts";
import {
  inlinePkiEngine,
  type PkiEngine,
  type PreparedCertificate
} from "../engine/pki-engine.ts";
import { ResourceLimitError, revocationErrorCode } from "../errors.ts";
import type { CompiledValidationProfile } from "../profile/profile.ts";
import { type CacheStore, createMemoryCache } from "./cache.ts";
import {
  type CertificateFindings,
  type CertificateRevocation,
  decideRevocation,
  type RevocationAttempt,
  type RevocationFinding,
  type RevocationSummary
} from "./revocation.ts";
import type { RevocationProvider } from "./revocation-provider.ts";

const DEFAULT_MAX_CACHE_AGE_MS = 60 * 60 * 1000;

interface CertificateCheckOptions {
  prepared: PreparedCertificate;
  certificateIndex: number;
  checkDateMs?: number;
  signal?: AbortSignal;
  onProgress?: (findings: CertificateFindings) => void;
}

interface SourceCheckOptions {
  mechanism: "crl" | "ocsp";
  certificateDer: Uint8Array;
  issuerDer: Uint8Array;
  source: string;
  signal?: AbortSignal;
  checkDateMs?: number;
  certificateIndex?: number;
  ocspRequestDer?: Uint8Array;
}

type RevocationResult = CrlValidationResult | OcspValidationResult;

function digestBytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

function recordResult(
  attempt: RevocationAttempt,
  result: CrlValidationResult | OcspValidationResult
): RevocationSummary | undefined {
  attempt.status = result.status;
  attempt.code = result.status === "unknown" ? result.code : undefined;
  if (result.status === "unknown") {
    attempt.message = result.message;
    return undefined;
  }
  const summary: RevocationSummary = {
    certificateIndex: attempt.certificateIndex,
    mechanism: attempt.mechanism,
    status: result.status,
    authenticated: true,
    fresh: true,
    thisUpdateMs: result.thisUpdate.getTime(),
    nextUpdateMs: result.nextUpdate.getTime(),
    checkedAtMs: result.checkedAt.getTime()
  };
  attempt.evidence = summary;
  attempt.message =
    result.status === "revoked"
      ? "Authenticated evidence reports revocation"
      : "Authenticated evidence reports good status";
  return summary;
}

function findingFor(attempt: RevocationAttempt): RevocationFinding {
  return {
    certificateIndex: attempt.certificateIndex,
    mechanism: attempt.mechanism,
    status: attempt.status,
    authenticated:
      attempt.status !== "unknown" && attempt.evidence?.authenticated === true,
    fresh: attempt.status !== "unknown" && attempt.evidence?.fresh === true,
    ...(attempt.code === undefined ? {} : { code: attempt.code }),
    message: attempt.message,
    source: attempt.source,
    durationMs: attempt.durationMs,
    ...(attempt.evidence
      ? {
          thisUpdateMs: attempt.evidence.thisUpdateMs,
          nextUpdateMs: attempt.evidence.nextUpdateMs,
          checkedAtMs: attempt.evidence.checkedAtMs
        }
      : {})
  };
}

function findingsFor(
  certificateIndex: number,
  attempts: RevocationAttempt[]
): CertificateFindings {
  const findings = attempts.map(findingFor);
  return {
    certificateIndex,
    pathValid: true,
    revocation: {
      crl: findings.filter((finding) => finding.mechanism === "crl"),
      ocsp: findings.filter((finding) => finding.mechanism === "ocsp")
    }
  };
}

export function createRevocationChecker({
  profile,
  provider,
  engine = inlinePkiEngine,
  now = Date.now,
  cache = createMemoryCache({ now }),
  maxCacheAgeMs = DEFAULT_MAX_CACHE_AGE_MS,
  cacheKeyPrefix = "x509-trust:revocation:v1",
  onDiagnostic
}: {
  profile: CompiledValidationProfile;
  provider: RevocationProvider;
  engine?: PkiEngine;
  now?: () => number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  onDiagnostic?: DiagnosticCallback;
}) {
  if (!Number.isFinite(maxCacheAgeMs) || maxCacheAgeMs <= 0) {
    throw new TypeError("maxCacheAgeMs must be positive and finite");
  }
  const report = createDiagnosticReporter(onDiagnostic);

  type Report = (
    event: Pick<DiagnosticEvent, "event" | "message" | "code" | "status">
  ) => void;

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
        return Uint8Array.from(Buffer.from(entry.der, "base64"));
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

  async function checkSource(
    options: SourceCheckOptions
  ): Promise<RevocationResult> {
    const { mechanism, checkDateMs, signal } = options;
    if (checkDateMs !== undefined && !Number.isFinite(checkDateMs)) {
      throw new TypeError("checkDate must be a valid date");
    }
    const key = cacheKey(mechanism, options);
    const notify: Report = (event) =>
      report({
        ...event,
        mechanism,
        certificateIndex: options.certificateIndex
      });

    function validate(data: Uint8Array): Promise<RevocationResult> {
      const input = {
        certificateDer: options.certificateDer,
        issuerDer: options.issuerDer,
        checkDateMs: checkDateMs ?? now(),
        signal
      };
      return mechanism === "crl"
        ? engine.validateCrl({ ...input, crl: data })
        : engine.validateOcsp({ ...input, response: data });
    }

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

    let result: RevocationResult;
    let data: Uint8Array;
    try {
      const request = {
        url: options.source,
        issuerCertificate: options.issuerDer,
        signal
      };
      const downloaded =
        mechanism === "crl"
          ? await provider.loadCrl!(request)
          : await provider.loadOcsp!({
              ...request,
              certificate: Uint8Array.from(options.certificateDer),
              issuerCertificate: Uint8Array.from(options.issuerDer),
              requestDer: options.ocspRequestDer!
            });
      data = Uint8Array.from(downloaded);
      result = await validate(data);
    } catch (error) {
      notify({
        event: "revocation_error",
        code: revocationErrorCode(error),
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
        const write = async () => {
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
        // A revoked result must not wait for a slow cache backend. The write is
        // observed via its own catch; good results keep the previous behavior.
        if (result.status === "revoked") void write();
        else await write();
      }
    }
    return result;
  }

  async function checkCertificate({
    prepared,
    certificateIndex,
    checkDateMs,
    signal,
    onProgress
  }: CertificateCheckOptions): Promise<CertificateRevocation> {
    const attempts: RevocationAttempt[] = [];
    const reportProgress = () =>
      onProgress?.(findingsFor(certificateIndex, attempts));
    reportProgress();
    let message =
      "No usable CRL or OCSP source is configured for this certificate";

    for (const mechanism of profile.revocation.sourceOrder) {
      signal?.throwIfAborted();
      const urls = mechanism === "crl" ? prepared.crlUrls : prepared.ocspUrls;
      const loader = mechanism === "crl" ? provider.loadCrl : provider.loadOcsp;
      if (!loader) continue;
      if (urls.length === 0) {
        message = `No ${mechanism.toUpperCase()} source is advertised for this certificate`;
        continue;
      }

      for (const url of urls) {
        signal?.throwIfAborted();
        const startedAt = performance.now();
        const attempt: RevocationAttempt = {
          certificateIndex,
          mechanism,
          source: url,
          status: "unknown",
          code: "EVIDENCE_PENDING",
          message: "Waiting for revocation evidence"
        };
        attempts.push(attempt);
        reportProgress();
        try {
          const result = await checkSource({
            mechanism,
            certificateDer: prepared.der,
            issuerDer: prepared.issuerDer!,
            source: url,
            certificateIndex,
            checkDateMs,
            signal,
            ocspRequestDer: prepared.ocspRequestDer
          });
          attempt.durationMs = Math.round(performance.now() - startedAt);
          const summary = recordResult(attempt, result);
          if (!summary) {
            message = attempt.message;
            continue;
          }
          const decision = decideRevocation(
            profile.revocation.requiredEvidence,
            attempts
          );
          if (decision.status !== "unknown") {
            return {
              ...decision,
              findings: findingsFor(certificateIndex, attempts)
            };
          }
          // This mechanism is satisfied; continue with the next required one.
          break;
        } catch (error) {
          attempt.durationMs = Math.round(performance.now() - startedAt);
          attempt.code = signal?.aborted
            ? "EVIDENCE_ABORTED"
            : revocationErrorCode(error);
          attempt.message =
            "Unable to load or validate certificate revocation data";
          if (signal?.aborted || error instanceof ResourceLimitError)
            throw error;
          message = "Unable to load or validate certificate revocation data";
        } finally {
          reportProgress();
        }
      }
    }

    const decision = decideRevocation(
      profile.revocation.requiredEvidence,
      attempts
    );
    const findings = findingsFor(certificateIndex, attempts);
    if (decision.status !== "unknown") {
      return { ...decision, findings };
    }
    return {
      status: "unknown",
      message: decision.message || message,
      findings
    };
  }

  return checkCertificate;
}
