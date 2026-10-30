import { X509Certificate } from "node:crypto";
import type { CacheStore } from "./cache.ts";
import type { CertificateInput } from "./certificate-path.ts";
import type { DiagnosticCallback } from "./diagnostics.ts";
import { invalidPolicy, ResourceLimitError } from "./errors.ts";
import { type EvidenceSummary, requiredMechanisms } from "./evidence.ts";
import { collectCertificateEvidence } from "./evidence-collector.ts";
import {
  createEvidenceProvider,
  type EvidenceProvider
} from "./evidence-provider.ts";
import {
  type CrlLoadOptions,
  type HttpOptions,
  type OcspLoadOptions
} from "./http-loaders.ts";
import type { ValidatedLeafCertificate } from "./leaf-certificate.ts";
import { createInlinePkiEngine } from "./pki-engine.ts";
import {
  compileTrustPolicy,
  DEFAULT_TRUST_POLICY,
  type TrustPolicyInput
} from "./policy.ts";
import { createRevocationChecker } from "./revocation-checker.ts";
import {
  applyTrustRules,
  normalizeRuleRegistrations,
  type TrustRuleRegistration
} from "./rules.ts";

export interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
  policy?: TrustPolicyInput;
  rules?: readonly TrustRuleRegistration[];
  communityId?: string;
  loadCrl?:
    | ((url: string, options?: CrlLoadOptions) => Promise<Uint8Array>)
    | false;
  loadOcsp?: ((options: OcspLoadOptions) => Promise<Uint8Array>) | false;
  provider?: EvidenceProvider;
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
  | "POLICY_REJECTED"
  | "UNKNOWN_COMMUNITY"
  | "UNKNOWN_POLICY_VERSION"
  | "RESOURCE_LIMIT_EXCEEDED";

export type ValidationResult =
  | {
      valid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      leafCertificate: ValidatedLeafCertificate;
      evidence: EvidenceSummary[];
      policyId: string;
      policyVersion: number;
      communityId?: string;
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
      evidence?: EvidenceSummary[];
      policyId?: string;
      policyVersion?: number;
      communityId?: string;
    };

export interface TrustValidator {
  verify(options: VerifyOptions): Promise<ValidationResult>;
}

type CrlLoader = (url: string, options?: CrlLoadOptions) => Promise<Uint8Array>;
type OcspLoader = (options: OcspLoadOptions) => Promise<Uint8Array>;

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

export function createTrustValidator({
  trustAnchors,
  policy: policyInput,
  rules: ruleInput,
  communityId,
  loadCrl,
  loadOcsp,
  provider,
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
  if (
    communityId !== undefined &&
    (typeof communityId !== "string" || communityId.trim() === "")
  ) {
    throw invalidPolicy("communityId must be a non-empty string");
  }
  const rules = normalizeRuleRegistrations(ruleInput);
  const policy = compileTrustPolicy(policyInput ?? DEFAULT_TRUST_POLICY, {
    registeredRuleNames: rules.map((rule) => rule.name)
  });
  const anchors = trustAnchors.map((input) =>
    Uint8Array.from(new X509Certificate(input).raw)
  );
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) {
    throw new TypeError("deadlineMs must be a positive integer");
  }
  if (provider && (loadCrl !== undefined || loadOcsp !== undefined)) {
    throw invalidPolicy("provider cannot be combined with loadCrl or loadOcsp");
  }
  const evidenceProvider =
    provider ?? createEvidenceProvider({ loadCrl, loadOcsp, http });
  const crlLoader: CrlLoader | false = evidenceProvider.supportsCrl
    ? (url, options) => evidenceProvider.loadCrl(url, options)
    : false;
  const ocspLoader: OcspLoader | false = evidenceProvider.supportsOcsp
    ? (options) => evidenceProvider.loadOcsp(options)
    : false;
  const engine = createInlinePkiEngine();
  const mandatory =
    policy.revocation.requiredEvidence === "any"
      ? []
      : requiredMechanisms(policy.revocation.requiredEvidence);
  if (mandatory.includes("crl") && !crlLoader) {
    throw invalidPolicy(
      "The policy requires CRL evidence but the CRL loader is disabled"
    );
  }
  if (mandatory.includes("ocsp") && !ocspLoader) {
    throw invalidPolicy(
      "The policy requires OCSP evidence but the OCSP loader is disabled"
    );
  }
  const checker = createRevocationChecker({
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
        checkDateMs: explicitCheckDateMs ?? now()
      });
      if (!path.pathValid) {
        return {
          valid: false,
          code: path.code,
          message: path.message,
          policyId: policy.id,
          policyVersion: policy.version,
          ...(communityId ? { communityId } : {})
        };
      }

      if (signal?.aborted) throw abortError();
      // The last path entry is the configured trust anchor. All non-anchor
      // pipelines start together; within a certificate the policy order holds.
      const controller = new AbortController();
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
        evidence: EvidenceSummary;
      }) => void;
      const revokedSignal = new Promise<{
        certificateIndex: number;
        evidence: EvidenceSummary;
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
            result: Awaited<ReturnType<typeof collectCertificateEvidence>>;
          }
        | { index: number; error: unknown };
      const allCompleted = Promise.all(
        path.certificates.slice(0, -1).map(async (prepared, index) => {
          try {
            const result = await collectCertificateEvidence({
              policy,
              checker,
              prepared,
              certificateIndex: index,
              checkDateMs: explicitCheckDateMs,
              signal: controller.signal,
              crlLoader: crlLoader || undefined,
              ocspLoader: ocspLoader || undefined
            });
            if (result.status === "revoked") {
              resolveRevoked({
                certificateIndex: index,
                evidence: result.evidence
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
      removeAbortListener();
      if (deadlineTimer) clearTimeout(deadlineTimer);
      if (outcome.kind === "aborted") {
        controller.abort();
        throw abortError();
      }
      if (outcome.kind === "deadline") {
        controller.abort();
        return {
          valid: false,
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "The verification deadline was exceeded",
          policyId: policy.id,
          policyVersion: policy.version,
          ...(communityId ? { communityId } : {})
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
          policyId: policy.id,
          policyVersion: policy.version,
          ...(communityId ? { communityId } : {})
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
          policyId: policy.id,
          policyVersion: policy.version,
          ...(communityId ? { communityId } : {})
        };
      }
      const evidence: EvidenceSummary[] = [];
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
            policyId: policy.id,
            policyVersion: policy.version,
            ...(communityId ? { communityId } : {})
          };
        }
        if (entry.result.status === "unknown") {
          return {
            valid: false,
            code: "REVOCATION_STATUS_UNKNOWN",
            message: entry.result.message,
            certificateIndex: entry.index,
            policyId: policy.id,
            policyVersion: policy.version,
            ...(communityId ? { communityId } : {})
          };
        }
        if (entry.result.status !== "good") continue;
        evidence.push(...entry.result.evidence);
      }

      const ruleFailure = await applyTrustRules({
        policy,
        leaf: path.leafCertificate,
        certificatePath: path.certificates.map((entry) => entry.facts),
        communityId,
        rules
      });
      if (ruleFailure) {
        return {
          valid: false,
          code: "POLICY_REJECTED",
          message: ruleFailure,
          evidence,
          policyId: policy.id,
          policyVersion: policy.version,
          ...(communityId ? { communityId } : {})
        };
      }

      return {
        valid: true,
        certificatePath: path.certificatePath,
        trustAnchorFingerprint256: path.trustAnchorFingerprint256,
        leafCertificate: path.leafCertificate,
        evidence,
        policyId: policy.id,
        policyVersion: policy.version,
        ...(communityId ? { communityId } : {})
      };
    }
  };
}
