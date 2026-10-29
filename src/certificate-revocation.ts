import type { RevocationStatus } from "../native/index.js";
import { nativeRevocationEndpoints } from "./native.ts";
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
  checker
}: {
  loadCrl: TrustValidatorOptions["loadCrl"];
  loadOcsp: TrustValidatorOptions["loadOcsp"];
  checker: ReturnType<typeof createRevocationChecker>;
}) {
  return async function checkCertificateRevocation(
    certificateDer: Uint8Array,
    issuerDer: Uint8Array,
    certificateIndex: number,
    checkDate?: Date
  ): Promise<CertificateRevocation> {
    let endpoints: ReturnType<typeof nativeRevocationEndpoints>;
    try {
      endpoints = nativeRevocationEndpoints(certificateDer);
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
  };
}
