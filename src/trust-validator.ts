import type { RevocationStatus } from "../native/index.js";
import type { CacheStore } from "./cache.ts";
import { certificateDer } from "./certificate-input.ts";
import { getUriSubjectAlternativeNames } from "./certificate-names.ts";
import {
  type CertificateInput,
  validateCertificatePath
} from "./certificate-path.ts";
import type { CrlValidationResult } from "./crl.ts";
import type { DiagnosticCallback } from "./diagnostics.ts";
import {
  createHttpLoaders,
  type HttpOptions,
  type OcspLoadOptions
} from "./http-loaders.ts";
import type { OcspValidationResult } from "./ocsp.ts";
import { createRevocationChecker } from "./revocation-checker.ts";
import { getRevocationEndpoints } from "./revocation-endpoints.ts";

export interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
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

type CertificateRevocation =
  | { status: Exclude<`${RevocationStatus}`, "unknown"> }
  | { status: "unknown"; message: string };

export function createTrustValidator({
  trustAnchors,
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
  const anchors = trustAnchors.map(certificateDer);
  const defaults = createHttpLoaders(http);
  const crlLoader = loadCrl ?? defaults.loadCrl;
  const ocspLoader = loadOcsp ?? defaults.loadOcsp;
  const checker = createRevocationChecker({
    cache,
    maxCacheAgeMs,
    cacheKeyPrefix,
    now,
    onDiagnostic
  });

  async function checkCertificateRevocation(
    certificateDer: Uint8Array,
    issuerDer: Uint8Array,
    certificateIndex: number,
    checkDate?: Date
  ): Promise<CertificateRevocation> {
    let endpoints: ReturnType<typeof getRevocationEndpoints>;
    try {
      endpoints = getRevocationEndpoints(certificateDer);
    } catch {
      return {
        status: "unknown",
        message: "Unable to parse certificate revocation endpoints"
      };
    }

    const attempts: Array<
      () => Promise<CrlValidationResult | OcspValidationResult>
    > = [];
    if (ocspLoader) {
      for (const url of endpoints.ocspUrls) {
        attempts.push(() =>
          checker.checkOcsp({
            certificate: certificateDer,
            issuerCertificate: issuerDer,
            source: url,
            certificateIndex,
            checkDate,
            load: () =>
              ocspLoader({
                url,
                certificate: Uint8Array.from(certificateDer),
                issuerCertificate: Uint8Array.from(issuerDer)
              })
          })
        );
      }
    }
    if (crlLoader) {
      for (const url of endpoints.crlUrls) {
        attempts.push(() =>
          checker.checkCrl({
            certificate: certificateDer,
            issuerCertificate: issuerDer,
            source: url,
            certificateIndex,
            checkDate,
            load: () => crlLoader(url)
          })
        );
      }
    }

    let message =
      "No usable CRL or OCSP source is configured for this certificate";
    for (const attempt of attempts) {
      try {
        const result = await attempt();
        if (result.status !== "unknown") return result;
        message = result.message;
      } catch {
        message = "Unable to load or validate certificate revocation data";
      }
    }
    return { status: "unknown", message };
  }

  return {
    async verify({
      certificateChain,
      checkDate
    }: VerifyOptions): Promise<ValidationResult> {
      const path = await validateCertificatePath({
        certificateChain,
        trustAnchors: anchors,
        checkDate: checkDate ?? new Date(now())
      });
      if (!path.pathValid) {
        return { valid: false, code: path.code, message: path.message };
      }

      let leafUriSubjectAlternativeNames: string[];
      try {
        leafUriSubjectAlternativeNames = getUriSubjectAlternativeNames(
          path.certificatePath[0]
        );
      } catch {
        return {
          valid: false,
          code: "INVALID_CERTIFICATE",
          message: "Invalid leaf subject alternative name extension"
        };
      }
      for (let index = 0; index < path.certificatePath.length - 1; index++) {
        const revocation = await checkCertificateRevocation(
          path.certificatePath[index],
          path.certificatePath[index + 1],
          index,
          checkDate
        );
        if (revocation.status === "revoked") {
          return {
            valid: false,
            code: "CERTIFICATE_REVOKED",
            message: "Certificate has been revoked",
            certificateIndex: index
          };
        }
        if (revocation.status === "unknown") {
          return {
            valid: false,
            code: "REVOCATION_STATUS_UNKNOWN",
            message: revocation.message,
            certificateIndex: index
          };
        }
      }

      return {
        valid: true,
        certificatePath: path.certificatePath,
        trustAnchorFingerprint256: path.trustAnchorFingerprint256,
        leafUriSubjectAlternativeNames
      };
    }
  };
}
