import { createCertificateRevocationChecker } from "./certificate-revocation.ts";
import { certificateBytes, validateCertificatePath } from "./certificates.ts";
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

      const controller = new AbortController();
      let revoked = false;
      let reportRevoked!: (certificateIndex: number) => void;
      const revokedSignal = new Promise<number>((resolve) => {
        reportRevoked = resolve;
      });
      const checkCertificateRevocation = createCertificateRevocationChecker({
        loadCrl: crlLoader,
        loadOcsp: ocspLoader,
        checker,
        shouldStop: () => revoked,
        signal: controller.signal
      });
      const allResults = Promise.all(
        path.revocationTargets.map(async (target) => {
          const result = await checkCertificateRevocation(
            target,
            path.certificatePath,
            checkDate
          );
          if (result.status === "revoked" && !revoked) {
            revoked = true;
            reportRevoked(target.certificateIndex);
            controller.abort();
          }
          return { certificateIndex: target.certificateIndex, result };
        })
      );
      const outcome = await Promise.race([
        allResults.then((results) => ({ results })),
        revokedSignal.then((certificateIndex) => ({ certificateIndex }))
      ]);
      if ("certificateIndex" in outcome) {
        return {
          valid: false,
          code: "CERTIFICATE_REVOKED",
          message: "Certificate has been revoked",
          certificateIndex: outcome.certificateIndex
        };
      }
      const revokedResult = outcome.results.find(
        ({ result }) => result.status === "revoked"
      );
      if (revokedResult) {
        return {
          valid: false,
          code: "CERTIFICATE_REVOKED",
          message: "Certificate has been revoked",
          certificateIndex: revokedResult.certificateIndex
        };
      }
      for (const { certificateIndex, result: revocation } of outcome.results) {
        if (revocation.status === "unknown") {
          return {
            valid: false,
            code: "REVOCATION_STATUS_UNKNOWN",
            message: revocation.message,
            certificateIndex
          };
        }
      }

      return {
        valid: true,
        certificatePath: path.certificatePath,
        trustAnchorFingerprint256: path.trustAnchorFingerprint256,
        leafCertificate: path.leafCertificate
      };
    }
  };
}
