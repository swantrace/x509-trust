import type { CacheStore } from "./cache.ts";
import type { CertificateInput } from "./certificates.ts";
import type { DiagnosticCallback } from "./diagnostics.ts";
import type {
  CrlLoadOptions,
  HttpOptions,
  OcspLoadOptions
} from "./http-loaders.ts";

export interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
  loadCrl?:
    | ((url: string, options?: CrlLoadOptions) => Promise<Uint8Array>)
    | false;
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
      leafUriSubjectAlternativeNames: string[];
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
    };

export interface TrustValidator {
  verify(options: VerifyOptions): Promise<ValidationResult>;
}
