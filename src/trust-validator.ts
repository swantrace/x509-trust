import { X509Certificate } from "node:crypto";
import type { CacheStore } from "./cache.ts";
import type { CertificateInput } from "./certificate-path.ts";
import type { DiagnosticCallback } from "./diagnostics.ts";
import { invalidPolicy } from "./errors.ts";
import { type EvidenceSummary, requiredMechanisms } from "./evidence.ts";
import { collectCertificateEvidence } from "./evidence-collector.ts";
import {
  createHttpLoaders,
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

export interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
  policy?: TrustPolicyInput;
  loadCrl?: ((url: string) => Promise<Uint8Array>) | false;
  loadOcsp?: ((options: OcspLoadOptions) => Promise<Uint8Array>) | false;
  http?: HttpOptions;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
}

export interface VerifyOptions {
  certificateChain: readonly CertificateInput[];
  checkDate?: Date;
}

export type ValidationFailureCode =
  | "INVALID_CERTIFICATE"
  | "INVALID_CERTIFICATE_PATH"
  | "CERTIFICATE_REVOKED"
  | "REVOCATION_STATUS_UNKNOWN";

export type ValidationResult =
  | {
      valid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      leafCertificate: ValidatedLeafCertificate;
      evidence: EvidenceSummary[];
      policyId: string;
      policyVersion: number;
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
      evidence?: EvidenceSummary[];
      policyId?: string;
      policyVersion?: number;
    };

export interface TrustValidator {
  verify(options: VerifyOptions): Promise<ValidationResult>;
}

export function createTrustValidator({
  trustAnchors,
  policy: policyInput,
  loadCrl,
  loadOcsp,
  http,
  cache,
  maxCacheAgeMs,
  cacheKeyPrefix,
  now = Date.now,
  onDiagnostic
}: TrustValidatorOptions): TrustValidator {
  if (trustAnchors.length === 0) {
    throw new TypeError("trustAnchors must contain at least one certificate");
  }
  const policy = compileTrustPolicy(policyInput ?? DEFAULT_TRUST_POLICY);
  const anchors = trustAnchors.map((input) =>
    Uint8Array.from(new X509Certificate(input).raw)
  );
  const engine = createInlinePkiEngine();
  const defaults = createHttpLoaders(http);
  const crlLoader = loadCrl ?? defaults.loadCrl;
  const ocspLoader = loadOcsp ?? defaults.loadOcsp;
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
      checkDate
    }: VerifyOptions): Promise<ValidationResult> {
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
          policyVersion: policy.version
        };
      }

      // The last path entry is the configured trust anchor.
      const evidence: EvidenceSummary[] = [];
      for (let index = 0; index < path.certificates.length - 1; index++) {
        const revocation = await collectCertificateEvidence({
          policy,
          checker,
          prepared: path.certificates[index],
          certificateIndex: index,
          checkDateMs: explicitCheckDateMs,
          crlLoader: crlLoader || undefined,
          ocspLoader: ocspLoader || undefined
        });
        if (revocation.status === "revoked") {
          return {
            valid: false,
            code: "CERTIFICATE_REVOKED",
            message: "Certificate has been revoked",
            certificateIndex: index,
            evidence: [revocation.evidence],
            policyId: policy.id,
            policyVersion: policy.version
          };
        }
        if (revocation.status === "unknown") {
          return {
            valid: false,
            code: "REVOCATION_STATUS_UNKNOWN",
            message: revocation.message,
            certificateIndex: index,
            policyId: policy.id,
            policyVersion: policy.version
          };
        }
        evidence.push(...revocation.evidence);
      }

      return {
        valid: true,
        certificatePath: path.certificatePath,
        trustAnchorFingerprint256: path.trustAnchorFingerprint256,
        leafCertificate: path.leafCertificate,
        evidence,
        policyId: policy.id,
        policyVersion: policy.version
      };
    }
  };
}
