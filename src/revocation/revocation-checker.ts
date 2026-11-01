// Checks certificate revocation sources in profile order and reports per-source attempts.
import {
  createDiagnosticReporter,
  type DiagnosticCallback
} from "../diagnostics.ts";
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
  type RevocationAttempt
} from "./revocation.ts";
import { createRevocationCache } from "./revocation-cache.ts";
import { findingsFor, recordResult } from "./revocation-findings.ts";
import type { RevocationProvider } from "./revocation-provider.ts";
import { createRevocationSourceChecker } from "./revocation-source.ts";

const DEFAULT_MAX_CACHE_AGE_MS = 60 * 60 * 1000;
export interface CertificateCheckOptions {
  prepared: PreparedCertificate;
  certificateIndex: number;
  checkDateMs?: number;
  signal?: AbortSignal;
  onProgress?: (findings: CertificateFindings) => void;
}

export type CertificateRevocationChecker = (
  options: CertificateCheckOptions
) => Promise<CertificateRevocation>;

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
}): CertificateRevocationChecker {
  if (!Number.isFinite(maxCacheAgeMs) || maxCacheAgeMs <= 0) {
    throw new TypeError("maxCacheAgeMs must be positive and finite");
  }
  const checkSource = createRevocationSourceChecker({
    provider,
    engine,
    now,
    report: createDiagnosticReporter(onDiagnostic),
    cache: createRevocationCache({ cache, now, maxCacheAgeMs, cacheKeyPrefix })
  });
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
    let unavailableSourceMessage =
      "No usable CRL or OCSP source is configured for this certificate";

    for (const mechanism of profile.revocation.sourceOrder) {
      signal?.throwIfAborted();
      const urls = mechanism === "crl" ? prepared.crlUrls : prepared.ocspUrls;
      const loader = mechanism === "crl" ? provider.loadCrl : provider.loadOcsp;
      if (!loader) continue;
      if (urls.length === 0) {
        unavailableSourceMessage = `No ${mechanism.toUpperCase()} source is advertised for this certificate`;
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
          if (!summary) continue;
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
        } finally {
          reportProgress();
        }
      }
    }

    const decision = decideRevocation(
      profile.revocation.requiredEvidence,
      attempts,
      unavailableSourceMessage
    );
    const findings = findingsFor(certificateIndex, attempts);
    return { ...decision, findings };
  }

  return checkCertificate;
}
