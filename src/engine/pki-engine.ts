// Prepares validated certificate paths and exposes inline CRL and OCSP verification.
import { Certificate } from "pkijs";
import {
  assertCertificateStructure,
  getPathLengthError,
  getTrustAnchorError,
  normalizeCertificate
} from "./certificate-constraints.ts";
import { validateCertificatePath } from "./certificate-path.ts";
import { validateCrl } from "./crl.ts";
import { parseDer } from "./der.ts";
import {
  extractCertificateFacts,
  extractLeafCertificate,
  type ValidatedLeafCertificate
} from "./leaf-certificate.ts";
import { validateOcsp } from "./ocsp.ts";
import { createOcspRequest } from "./ocsp-request.ts";
import type { PkiEngine, PreparedCertificate } from "./pki-types.ts";
import { getRevocationEndpoints } from "./revocation-endpoints.ts";

export type {
  PkiEngine,
  PreparedCertificate,
  PreparedPathResult
} from "./pki-types.ts";

const MAX_CERTIFICATE_CHAIN_LENGTH = 16;
const MAX_TRUST_ANCHORS = 32;
export const inlinePkiEngine: PkiEngine = {
  async preparePath({ certificateChain, trustAnchors, checkDateMs, signal }) {
    signal?.throwIfAborted();
    if (!Number.isFinite(checkDateMs)) {
      throw new TypeError("checkDate must be a valid date");
    }
    if (trustAnchors.length === 0) {
      throw new TypeError("trustAnchors must contain at least one certificate");
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
      const anchorError = getTrustAnchorError(
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
      const lengthError = getPathLengthError(certificates);
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
          path.certificatePath[0],
          prepared[0].facts
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
