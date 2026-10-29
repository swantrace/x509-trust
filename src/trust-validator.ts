import { createCertificateRevocationChecker } from "./certificate-revocation.ts";
import {
  certificateDer,
  getUriSubjectAlternativeNames,
  validateCertificatePath
} from "./certificates.ts";
import { createHttpLoaders } from "./http-loaders.ts";
import { createRevocationChecker } from "./revocation-checker.ts";
import type {
  TrustValidator,
  TrustValidatorOptions,
  ValidationResult,
  VerifyOptions
} from "./validation-types.ts";

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

  const checkCertificateRevocation = createCertificateRevocationChecker({
    loadCrl: crlLoader,
    loadOcsp: ocspLoader,
    checker
  });

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
