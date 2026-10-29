import { createCertificateRevocationChecker } from "./certificate-revocation.ts";
import { certificateBytes, validateCertificatePath } from "./certificates.ts";
import { createHttpLoaders } from "./http-loaders.ts";
import { createRevocationBatch } from "./revocation-batch.ts";
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
  // Snapshot configuration in JS; certificate parsing belongs to the path worker.
  const anchors = trustAnchors.map((input) =>
    Uint8Array.from(certificateBytes(input))
  );
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

      const batch = createRevocationBatch(
        path.certificatePath,
        path.revocationTargets.map((target) => target.certificateIndex),
        now
      );
      const checkCertificateRevocation = createCertificateRevocationChecker({
        loadCrl: crlLoader,
        loadOcsp: ocspLoader,
        checker,
        batch
      });
      const results = await Promise.all(
        path.revocationTargets.map(async (target) => {
          try {
            return await checkCertificateRevocation(
              target,
              path.certificatePath,
              checkDate
            );
          } finally {
            batch.complete(target.certificateIndex);
          }
        })
      );
      const revokedIndex = results.findIndex(
        (result) => result.status === "revoked"
      );
      if (revokedIndex !== -1) {
        return {
          valid: false,
          code: "CERTIFICATE_REVOKED",
          message: "Certificate has been revoked",
          certificateIndex: revokedIndex
        };
      }
      for (let index = 0; index < results.length; index++) {
        const revocation = results[index];
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
        leafUriSubjectAlternativeNames: path.leafUriSubjectAlternativeNames
      };
    }
  };
}
