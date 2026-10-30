import { X509Certificate } from "node:crypto";
import type { CacheStore } from "./cache.ts";
import type { CertificateInput } from "./certificate-path.ts";
import type { CrlValidationResult } from "./crl.ts";
import type { DiagnosticCallback } from "./diagnostics.ts";
import {
  createHttpLoaders,
  type HttpOptions,
  type OcspLoadOptions
} from "./http-loaders.ts";
import type { OcspValidationResult } from "./ocsp.ts";
import {
  createInlinePkiEngine,
  type PreparedCertificate
} from "./pki-engine.ts";
import { createRevocationChecker } from "./revocation-checker.ts";

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
  | { status: "good" | "revoked" }
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
  const anchors = trustAnchors.map((input) =>
    Uint8Array.from(new X509Certificate(input).raw)
  );
  const engine = createInlinePkiEngine();
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
    prepared: PreparedCertificate,
    certificateIndex: number,
    checkDateMs?: number
  ): Promise<CertificateRevocation> {
    const attempts: Array<
      () => Promise<CrlValidationResult | OcspValidationResult>
    > = [];
    if (ocspLoader) {
      for (const url of prepared.ocspUrls) {
        attempts.push(() =>
          checker.checkOcsp({
            certificateDer: prepared.der,
            issuerDer: prepared.issuerDer!,
            source: url,
            certificateIndex,
            checkDateMs,
            ocspRequestDer: prepared.ocspRequestDer!,
            load: () =>
              ocspLoader({
                url,
                certificate: Uint8Array.from(prepared.der),
                issuerCertificate: Uint8Array.from(prepared.issuerDer!)
              })
          })
        );
      }
    }
    if (crlLoader) {
      for (const url of prepared.crlUrls) {
        attempts.push(() =>
          checker.checkCrl({
            certificateDer: prepared.der,
            issuerDer: prepared.issuerDer!,
            source: url,
            certificateIndex,
            checkDateMs,
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
        return { valid: false, code: path.code, message: path.message };
      }

      // The last path entry is the configured trust anchor.
      for (let index = 0; index < path.certificates.length - 1; index++) {
        const revocation = await checkCertificateRevocation(
          path.certificates[index],
          index,
          explicitCheckDateMs
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
        leafUriSubjectAlternativeNames: path.leafUriSubjectAlternativeNames
      };
    }
  };
}
