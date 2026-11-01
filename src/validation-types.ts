// Defines public validator options, results, and failure codes.
import type { DiagnosticCallback } from "./diagnostics.ts";
import type { CertificateInput } from "./engine/certificate-path.ts";
import type { ValidatedLeafCertificate } from "./engine/leaf-certificate.ts";
import type { PkiEngine } from "./engine/pki-engine.ts";
import type {
  ProfileVersion,
  ValidationProfileInput
} from "./profile/profile.ts";
import type { TrustRuleRegistration } from "./profile/rules.ts";
import type { CacheStore } from "./revocation/cache.ts";
import type { HttpOptions } from "./revocation/http-loaders.ts";
import type {
  CertificateFindings,
  RevocationSummary
} from "./revocation/revocation.ts";
import type {
  RevocationLoaderOptions,
  RevocationProvider
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
