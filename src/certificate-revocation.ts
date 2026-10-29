import type {
  NativeRevocationTarget,
  RevocationStatus
} from "../native/index.js";
import type { createRevocationChecker } from "./revocation-checker.ts";
import type {
  CrlValidationResult,
  OcspValidationResult
} from "./revocation-validation.ts";
import type { TrustValidatorOptions } from "./validation-types.ts";

type CertificateRevocation =
  | { status: Exclude<`${RevocationStatus}`, "unknown"> }
  | { status: "unknown"; message: string };

export function createCertificateRevocationChecker({
  loadCrl: crlLoader,
  loadOcsp: ocspLoader,
  checker,
  shouldStop,
  signal
}: {
  loadCrl: TrustValidatorOptions["loadCrl"];
  loadOcsp: TrustValidatorOptions["loadOcsp"];
  checker: ReturnType<typeof createRevocationChecker>;
  shouldStop: () => boolean;
  signal: AbortSignal;
}) {
  return async function checkCertificateRevocation(
    target: NativeRevocationTarget,
    path: Uint8Array[],
    checkDate?: Date
  ): Promise<CertificateRevocation> {
    const certificateIndex = target.certificateIndex;
    const certificateDer = path[certificateIndex];
    const issuerDer = path[certificateIndex + 1];

    const attempts: Array<
      () => Promise<CrlValidationResult | OcspValidationResult>
    > = [];
    if (ocspLoader) {
      for (const url of target.ocspUrls) {
        attempts.push(() =>
          checker.checkOcsp({
            certificate: certificateDer,
            issuerCertificate: issuerDer,
            source: url,
            certificateIndex,
            checkDate,
            shouldStop,
            load: () =>
              ocspLoader({
                url,
                certificate: Uint8Array.from(certificateDer),
                issuerCertificate: Uint8Array.from(issuerDer),
                request:
                  target.ocspRequest && Uint8Array.from(target.ocspRequest),
                signal
              })
          })
        );
      }
    }
    if (crlLoader) {
      for (const url of target.crlUrls) {
        attempts.push(() =>
          checker.checkCrl({
            certificate: certificateDer,
            issuerCertificate: issuerDer,
            source: url,
            certificateIndex,
            checkDate,
            shouldStop,
            load: () => crlLoader(url, { signal })
          })
        );
      }
    }

    let message =
      "No usable CRL or OCSP source is configured for this certificate";
    for (const attempt of attempts) {
      if (shouldStop()) break;
      try {
        const result = await attempt();
        if (result.status !== "unknown") return result;
        message = result.message;
      } catch {
        message = "Unable to load or validate certificate revocation data";
      }
    }
    return { status: "unknown", message };
  };
}
