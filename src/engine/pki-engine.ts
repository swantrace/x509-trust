import { X509Certificate } from "node:crypto";
import { BitString } from "asn1js";
import {
  BasicConstraints,
  Certificate,
  id_BasicConstraints,
  id_KeyUsage,
  OCSPRequest
} from "pkijs";
import {
  type CertificateInput,
  validateCertificatePath
} from "./certificate-path.ts";
import { validateCrl } from "./crl.ts";
import { parseDer } from "./der.ts";
import {
  type CertificateFacts,
  extractCertificateFacts,
  extractLeafCertificate,
  type ValidatedLeafCertificate
} from "./leaf-certificate.ts";
import { validateOcsp } from "./ocsp.ts";
import { getRevocationEndpoints } from "./revocation-endpoints.ts";

const MAX_CERTIFICATE_CHAIN_LENGTH = 16;
const MAX_TRUST_ANCHORS = 32;
const KEY_CERT_SIGN = 0x04;
const OCSP_CERT_ID_HASH = "SHA-1";

const SUPPORTED_CRITICAL_EXTENSIONS = new Set([
  "2.5.29.15", // keyUsage
  "2.5.29.17", // subjectAltName
  "2.5.29.19", // basicConstraints
  "2.5.29.30", // nameConstraints
  "2.5.29.31", // cRLDistributionPoints
  "2.5.29.32", // certificatePolicies
  "2.5.29.33", // policyMappings
  "2.5.29.35", // authorityKeyIdentifier
  "2.5.29.36", // policyConstraints
  "2.5.29.37", // extKeyUsage
  "2.5.29.54", // inhibitAnyPolicy
  "1.3.6.1.5.5.7.1.1" // authorityInfoAccess
]);

export interface PreparedCertificate {
  index: number;
  der: Uint8Array;
  issuerDer?: Uint8Array;
  crlUrls: string[];
  ocspUrls: string[];
  ocspRequestDer?: Uint8Array;
  facts: CertificateFacts;
}

export type PreparedPathResult =
  | {
      pathValid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      certificates: PreparedCertificate[];
      leafCertificate: ValidatedLeafCertificate;
    }
  | {
      pathValid: false;
      code: "INVALID_CERTIFICATE" | "INVALID_CERTIFICATE_PATH";
      message: string;
    };

export interface PkiEngine {
  preparePath(options: {
    certificateChain: readonly CertificateInput[];
    trustAnchors: readonly Uint8Array[];
    checkDateMs: number;
    signal?: AbortSignal;
  }): Promise<PreparedPathResult>;
  validateCrl: typeof validateCrl;
  validateOcsp: typeof validateOcsp;
}

function normalizeCertificate(
  input: CertificateInput,
  label: string
): Uint8Array<ArrayBuffer> {
  if (typeof input === "string") {
    return parseDer(new X509Certificate(input).raw, label).bytes;
  }
  const bytes = Uint8Array.from(input);
  const header = new TextDecoder("ascii").decode(bytes.subarray(0, 11));
  return header === "-----BEGIN "
    ? parseDer(new X509Certificate(input).raw, label).bytes
    : parseDer(bytes, label).bytes;
}

function extensionValue<T>(
  certificate: Certificate,
  oid: string
): T | undefined {
  const extensions = (certificate.extensions ?? []).filter(
    (extension) => extension.extnID === oid
  );
  if (extensions.length > 1) {
    throw new TypeError(`Duplicate certificate extension: ${oid}`);
  }
  return extensions[0]?.parsedValue as T | undefined;
}

function keyUsageAllowsKeyCertSign(
  certificate: Certificate
): boolean | undefined {
  const usage = extensionValue<BitString>(certificate, id_KeyUsage);
  if (!usage) return undefined;
  if (!(usage instanceof BitString)) return false;
  return (usage.valueBlock.valueHexView[0] & KEY_CERT_SIGN) !== 0;
}

function pathLength(certificate: Certificate): number | undefined {
  const constraints = extensionValue<BasicConstraints>(
    certificate,
    id_BasicConstraints
  );
  if (!(constraints instanceof BasicConstraints)) return undefined;
  const value = constraints.pathLenConstraint;
  return typeof value === "number" ? value : value?.valueBlock.valueDec;
}

function assertCertificateStructure(
  certificate: Certificate,
  label: string
): void {
  const seen = new Set<string>();
  for (const extension of certificate.extensions ?? []) {
    if (seen.has(extension.extnID)) {
      throw new TypeError(
        `${label} has a duplicate extension ${extension.extnID}`
      );
    }
    seen.add(extension.extnID);
    if (
      extension.critical &&
      !SUPPORTED_CRITICAL_EXTENSIONS.has(extension.extnID)
    ) {
      throw new TypeError(
        `${label} has an unsupported critical extension ${extension.extnID}`
      );
    }
    if (extension.critical && !extension.parsedValue) {
      throw new TypeError(
        `${label} has an unparseable critical extension ${extension.extnID}`
      );
    }
  }
}

function assertTrustAnchor(
  anchor: Certificate,
  checkDate: Date
): string | undefined {
  if (anchor.notBefore.value > checkDate || anchor.notAfter.value < checkDate) {
    return "The trust anchor is not valid at the validation date";
  }
  const constraints = extensionValue<BasicConstraints>(
    anchor,
    id_BasicConstraints
  );
  if (!(constraints instanceof BasicConstraints) || constraints.cA !== true) {
    return "The trust anchor is not a CA certificate";
  }
  if (keyUsageAllowsKeyCertSign(anchor) === false) {
    return "The trust anchor's key usage does not permit certificate signing";
  }
  return undefined;
}

function assertPathLengthConstraints(
  certificates: Certificate[]
): string | undefined {
  // Index 0 is the leaf; every higher index is a CA certificate.
  for (let index = 1; index < certificates.length; index++) {
    const limit = pathLength(certificates[index]);
    if (limit === undefined) continue;
    let intermediatesBelow = 0;
    for (let below = 1; below < index; below++) {
      if (!certificates[below].subject.isEqual(certificates[below].issuer)) {
        intermediatesBelow++;
      }
    }
    if (intermediatesBelow > limit) {
      return "A certificate pathLenConstraint was exceeded";
    }
  }
  return undefined;
}

async function createOcspRequest(
  certificate: Certificate,
  issuerCertificate: Certificate
): Promise<Uint8Array> {
  const request = new OCSPRequest();
  await request.createForCertificate(certificate, {
    issuerCertificate,
    hashAlgorithm: OCSP_CERT_ID_HASH
  });
  return new Uint8Array(request.toSchema(true).toBER(false));
}

export function createInlinePkiEngine(): PkiEngine {
  return {
    async preparePath({ certificateChain, trustAnchors, checkDateMs, signal }) {
      signal?.throwIfAborted();
      if (!Number.isFinite(checkDateMs)) {
        throw new TypeError("checkDate must be a valid date");
      }
      if (trustAnchors.length === 0) {
        throw new TypeError(
          "trustAnchors must contain at least one certificate"
        );
      }
      if (trustAnchors.length > MAX_TRUST_ANCHORS) {
        throw new TypeError("trustAnchors exceeds the supported limit");
      }
      if (certificateChain.length === 0) {
        return {
          pathValid: false,
          code: "INVALID_CERTIFICATE_PATH",
          message: "certificateChain must contain at least one certificate"
        };
      }
      if (certificateChain.length > MAX_CERTIFICATE_CHAIN_LENGTH) {
        return {
          pathValid: false,
          code: "INVALID_CERTIFICATE_PATH",
          message: "certificateChain exceeds the supported limit"
        };
      }

      let normalizedChain: Uint8Array[];
      let normalizedAnchors: Uint8Array[];
      try {
        normalizedChain = certificateChain.map((input, index) =>
          normalizeCertificate(input, `certificateChain[${index}]`)
        );
        normalizedAnchors = trustAnchors.map(
          (anchor, index) => parseDer(anchor, `trustAnchors[${index}]`).bytes
        );
      } catch {
        return {
          pathValid: false,
          code: "INVALID_CERTIFICATE",
          message:
            "The supplied certificate input is not a single valid DER value"
        };
      }

      const checkDate = new Date(checkDateMs);
      const path = await validateCertificatePath({
        certificateChain: normalizedChain,
        trustAnchors: normalizedAnchors,
        checkDate
      });
      if (!path.pathValid) return path;

      try {
        const certificates = path.certificatePath.map((der) =>
          Certificate.fromBER(Uint8Array.from(der))
        );
        for (const [index, certificate] of certificates.entries()) {
          assertCertificateStructure(
            certificate,
            index === 0 ? "Leaf certificate" : `Certificate ${index}`
          );
        }
        const anchorError = assertTrustAnchor(
          certificates[certificates.length - 1],
          checkDate
        );
        if (anchorError) {
          return {
            pathValid: false,
            code: "INVALID_CERTIFICATE_PATH",
            message: anchorError
          };
        }
        const lengthError = assertPathLengthConstraints(certificates);
        if (lengthError) {
          return {
            pathValid: false,
            code: "INVALID_CERTIFICATE_PATH",
            message: lengthError
          };
        }

        const prepared: PreparedCertificate[] = [];
        for (let index = 0; index < certificates.length; index++) {
          const certificate = certificates[index];
          const endpoints = getRevocationEndpoints(certificate);
          const issuer = certificates[index + 1];
          prepared.push({
            index,
            der: Uint8Array.from(path.certificatePath[index]),
            issuerDer: issuer
              ? Uint8Array.from(path.certificatePath[index + 1])
              : undefined,
            crlUrls: endpoints.crlUrls,
            ocspUrls: endpoints.ocspUrls,
            ocspRequestDer: issuer
              ? await createOcspRequest(certificate, issuer)
              : undefined,
            facts: extractCertificateFacts(
              certificate,
              path.certificatePath[index]
            )
          });
        }

        let leafCertificate: ValidatedLeafCertificate;
        try {
          leafCertificate = extractLeafCertificate(
            certificates[0],
            path.certificatePath[0]
          );
        } catch {
          return {
            pathValid: false,
            code: "INVALID_CERTIFICATE",
            message: "Invalid leaf certificate metadata"
          };
        }

        return {
          pathValid: true,
          certificatePath: path.certificatePath.map((der) =>
            Uint8Array.from(der)
          ),
          trustAnchorFingerprint256: path.trustAnchorFingerprint256,
          certificates: prepared,
          leafCertificate
        };
      } catch {
        return {
          pathValid: false,
          code: "INVALID_CERTIFICATE_PATH",
          message: "The validated certificate path contains invalid metadata"
        };
      }
    },

    validateCrl,
    validateOcsp
  };
}
