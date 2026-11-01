import { X509Certificate } from "node:crypto";
import type { DiagnosticCallback } from "./diagnostics.ts";
import type { CertificateInput } from "./engine/certificate-path.ts";
import type { ValidatedLeafCertificate } from "./engine/leaf-certificate.ts";
import { inlinePkiEngine, type PkiEngine } from "./engine/pki-engine.ts";
import { invalidProfile, ResourceLimitError } from "./errors.ts";
import {
  compileValidationProfile,
  DEFAULT_VALIDATION_PROFILE,
  type ProfileVersion,
  type ValidationProfileInput
} from "./profile/profile.ts";
import {
  applyTrustRules,
  normalizeRuleRegistrations,
  type TrustRuleRegistration
} from "./profile/rules.ts";
import type { CacheStore } from "./revocation/cache.ts";
import type { HttpOptions } from "./revocation/http-loaders.ts";
import {
  type CertificateFindings,
  type RevocationFinding,
  type RevocationSummary,
  requiredMechanisms
} from "./revocation/revocation.ts";
import { createRevocationChecker } from "./revocation/revocation-checker.ts";
import {
  createRevocationProvider,
  type RevocationLoaderOptions,
  type RevocationProvider
} from "./revocation/revocation-provider.ts";

export interface TrustValidatorOptions extends RevocationLoaderOptions {
  trustAnchors: readonly CertificateInput[];
  profile?: ValidationProfileInput;
  rules?: readonly TrustRuleRegistration[];
  provider?: RevocationProvider;
  engine?: PkiEngine;
  http?: HttpOptions;
  deadlineMs?: number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
}

export interface VerifyOptions {
  certificateChain: readonly CertificateInput[];
  checkDate?: Date;
  signal?: AbortSignal;
}

export type ValidationFailureCode =
  | "INVALID_CERTIFICATE"
  | "INVALID_CERTIFICATE_PATH"
  | "CERTIFICATE_REVOKED"
  | "REVOCATION_STATUS_UNKNOWN"
  | "PROFILE_REJECTED"
  | "UNKNOWN_PROFILE"
  | "UNKNOWN_PROFILE_VERSION"
  | "RESOURCE_LIMIT_EXCEEDED";

export type ValidationResult =
  | {
      valid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      leafCertificate: ValidatedLeafCertificate;
      evidence: RevocationSummary[];
      findings: CertificateFindings[];
      profileId: string;
      profileVersion: ProfileVersion;
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
      evidence?: RevocationSummary[];
      findings?: CertificateFindings[];
      profileId?: string;
      profileVersion?: ProfileVersion;
    };

export interface TrustValidator {
  verify(options: VerifyOptions): Promise<ValidationResult>;
}

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

export function createTrustValidator({
  trustAnchors,
  profile: profileInput,
  rules: ruleInput,
  crlLoader: providedCrlLoader,
  ocspLoader: providedOcspLoader,
  provider,
  engine: providedEngine,
  http,
  deadlineMs = 60_000,
  cache,
  maxCacheAgeMs,
  cacheKeyPrefix,
  now = Date.now,
  onDiagnostic
}: TrustValidatorOptions): TrustValidator {
  if (trustAnchors.length === 0) {
    throw new TypeError("trustAnchors must contain at least one certificate");
  }
  const rules = normalizeRuleRegistrations(ruleInput);
  const profile = compileValidationProfile(
    profileInput ?? DEFAULT_VALIDATION_PROFILE,
    { registeredRuleNames: rules.map((rule) => rule.name) }
  );
  const profileMetadata = {
    profileId: profile.id,
    profileVersion: profile.version
  };
  const anchors = trustAnchors.map((input) =>
    Uint8Array.from(new X509Certificate(input).raw)
  );
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) {
    throw new TypeError("deadlineMs must be a positive integer");
  }
  if (
    provider &&
    (providedCrlLoader !== undefined || providedOcspLoader !== undefined)
  ) {
    throw invalidProfile(
      "provider cannot be combined with crlLoader or ocspLoader"
    );
  }
  const revocationProvider =
    provider ??
    createRevocationProvider({
      crlLoader: providedCrlLoader,
      ocspLoader: providedOcspLoader,
      http
    });
  const engine = providedEngine ?? inlinePkiEngine;
  const mandatory =
    profile.revocation.requiredEvidence === "any"
      ? []
      : requiredMechanisms(profile.revocation.requiredEvidence);
  if (mandatory.includes("crl") && !revocationProvider.loadCrl) {
    throw invalidProfile(
      "The profile requires CRL evidence but the CRL loader is disabled"
    );
  }
  if (mandatory.includes("ocsp") && !revocationProvider.loadOcsp) {
    throw invalidProfile(
      "The profile requires OCSP evidence but the OCSP loader is disabled"
    );
  }
  const checkRevocation = createRevocationChecker({
    profile,
    provider: revocationProvider,
    engine,
    cache,
    maxCacheAgeMs,
    cacheKeyPrefix,
    now,
    onDiagnostic
  });

  return {
    async verify({
      certificateChain,
      checkDate,
      signal
    }: VerifyOptions): Promise<ValidationResult> {
      if (signal?.aborted) throw abortError();
      const explicitCheckDateMs = checkDate?.getTime();
      if (
        explicitCheckDateMs !== undefined &&
        Number.isNaN(explicitCheckDateMs)
      ) {
        throw new TypeError("checkDate must be a valid date");
      }
      const path = await engine.preparePath({
        certificateChain,
        trustAnchors: anchors,
        checkDateMs: explicitCheckDateMs ?? now(),
        signal
      });
      if (!path.pathValid) {
        return {
          valid: false,
          code: path.code,
          message: path.message,
          ...profileMetadata
        };
      }

      if (signal?.aborted) throw abortError();
      // The last path entry is the configured trust anchor. All non-anchor
      // pipelines start together; within a certificate the profile order holds.
      const controller = new AbortController();
      const progress = new Map<number, CertificateFindings>();
      let collecting = true;
      let removeAbortListener = () => {};
      const aborted = new Promise<"aborted">((resolve) => {
        if (!signal) return;
        const onAbort = () => {
          controller.abort();
          resolve("aborted");
        };
        signal.addEventListener("abort", onAbort, { once: true });
        removeAbortListener = () =>
          signal.removeEventListener("abort", onAbort);
      });

      let resolveRevoked!: (value: {
        certificateIndex: number;
        evidence: RevocationSummary;
        findings: CertificateFindings;
      }) => void;
      const revokedSignal = new Promise<{
        certificateIndex: number;
        evidence: RevocationSummary;
        findings: CertificateFindings;
      }>((resolve) => {
        resolveRevoked = resolve;
      });
      let deadlineTimer: NodeJS.Timeout | undefined;
      const deadline = new Promise<"deadline">((resolve) => {
        deadlineTimer = setTimeout(() => {
          controller.abort();
          resolve("deadline");
        }, deadlineMs);
        deadlineTimer.unref();
      });

      type PipelineResult =
        | {
            index: number;
            result: Awaited<ReturnType<typeof checkRevocation>>;
          }
        | { index: number; error: unknown };
      const allCompleted = Promise.all(
        path.certificates.slice(0, -1).map(async (prepared, index) => {
          try {
            const result = await checkRevocation({
              prepared,
              certificateIndex: index,
              checkDateMs: explicitCheckDateMs,
              signal: controller.signal,
              onProgress(findings) {
                if (collecting) progress.set(index, findings);
              }
            });
            if (result.status === "revoked") {
              resolveRevoked({
                certificateIndex: index,
                evidence: result.evidence,
                findings: result.findings
              });
            }
            return { index, result } satisfies PipelineResult;
          } catch (error) {
            return { index, error } satisfies PipelineResult;
          }
        })
      );

      const outcome = await Promise.race([
        allCompleted.then((results) => ({
          kind: "completed" as const,
          results
        })),
        revokedSignal.then((value) => ({ kind: "revoked" as const, value })),
        aborted.then(() => ({ kind: "aborted" as const })),
        deadline.then(() => ({ kind: "deadline" as const }))
      ]);
      collecting = false;
      const partialFindings = [...progress.values()].sort(
        (a, b) => a.certificateIndex - b.certificateIndex
      );
      removeAbortListener();
      if (deadlineTimer) clearTimeout(deadlineTimer);
      if (outcome.kind === "aborted") {
        controller.abort();
        throw abortError();
      }
      if (outcome.kind === "deadline") {
        controller.abort();
        const interrupted = (finding: RevocationFinding) =>
          finding.code === "EVIDENCE_PENDING" ||
          finding.code === "EVIDENCE_ABORTED"
            ? {
                ...finding,
                code: "EVIDENCE_DEADLINE_EXCEEDED",
                message:
                  "The evidence deadline expired before this attempt completed"
              }
            : finding;
        return {
          valid: false,
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "The verification deadline was exceeded",
          findings: partialFindings.map((entry) => ({
            ...entry,
            revocation: {
              crl: entry.revocation.crl.map(interrupted),
              ocsp: entry.revocation.ocsp.map(interrupted)
            }
          })),
          ...profileMetadata
        };
      }
      if (outcome.kind === "revoked") {
        controller.abort();
        return {
          valid: false,
          code: "CERTIFICATE_REVOKED",
          message: "Certificate has been revoked",
          certificateIndex: outcome.value.certificateIndex,
          evidence: [outcome.value.evidence],
          findings: [outcome.value.findings],
          ...profileMetadata
        };
      }
      if (signal?.aborted) throw abortError();

      const revokedEntry = outcome.results.find(
        (entry) => !("error" in entry) && entry.result.status === "revoked"
      );
      if (
        revokedEntry &&
        !("error" in revokedEntry) &&
        revokedEntry.result.status === "revoked"
      ) {
        return {
          valid: false,
          code: "CERTIFICATE_REVOKED",
          message: "Certificate has been revoked",
          certificateIndex: revokedEntry.index,
          evidence: [revokedEntry.result.evidence],
          findings: [revokedEntry.result.findings],
          ...profileMetadata
        };
      }
      const evidence: RevocationSummary[] = [];
      const findings: CertificateFindings[] = [];
      for (const entry of outcome.results) {
        if ("error" in entry) {
          const resourceLimited = entry.error instanceof ResourceLimitError;
          return {
            valid: false,
            code: resourceLimited
              ? "RESOURCE_LIMIT_EXCEEDED"
              : "REVOCATION_STATUS_UNKNOWN",
            message: resourceLimited
              ? (entry.error as ResourceLimitError).message
              : "Revocation validation failed",
            certificateIndex: entry.index,
            findings: partialFindings,
            ...profileMetadata
          };
        }
        if (entry.result.status === "unknown") {
          return {
            valid: false,
            code: "REVOCATION_STATUS_UNKNOWN",
            message: entry.result.message,
            certificateIndex: entry.index,
            findings: partialFindings,
            ...profileMetadata
          };
        }
        if (entry.result.status !== "good") continue;
        evidence.push(...entry.result.evidence);
        findings.push(entry.result.findings);
      }

      const ruleFailure = await applyTrustRules({
        profile,
        leaf: path.leafCertificate,
        certificatePath: path.certificates.map((entry) => entry.facts),
        profileId: profile.id,
        rules
      });
      if (ruleFailure) {
        return {
          valid: false,
          code: "PROFILE_REJECTED",
          message: ruleFailure,
          evidence,
          findings,
          ...profileMetadata
        };
      }

      return {
        valid: true,
        certificatePath: path.certificatePath,
        trustAnchorFingerprint256: path.trustAnchorFingerprint256,
        leafCertificate: path.leafCertificate,
        evidence,
        findings,
        ...profileMetadata
      };
    }
  };
}
