// Builds and validates certificate paths against configured trust anchors using PKI.js.
import { X509Certificate } from "node:crypto";
import { Certificate, CertificateChainValidationEngine } from "pkijs";

export type CertificateInput = string | Uint8Array;

interface CertificatePathOptions {
  // Leaf first; the root certificate may be omitted.
  certificateChain: readonly CertificateInput[];
  trustAnchors: readonly CertificateInput[];
  checkDate?: Date;
}

type CertificatePathResult =
  | {
      pathValid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
    }
  | {
      pathValid: false;
      code: "INVALID_CERTIFICATE" | "INVALID_CERTIFICATE_PATH";
      message: string;
    };

function parseCertificate(input: CertificateInput): Certificate {
  return Certificate.fromBER(new X509Certificate(input).raw);
}

export async function validateCertificatePath({
  certificateChain,
  trustAnchors,
  checkDate = new Date()
}: CertificatePathOptions): Promise<CertificatePathResult> {
  if (Number.isNaN(checkDate.getTime())) {
    throw new TypeError("checkDate must be a valid date");
  }
  if (trustAnchors.length === 0) {
    throw new TypeError("trustAnchors must contain at least one certificate");
  }
  const trustedCerts = trustAnchors.map(parseCertificate);

  if (certificateChain.length === 0) {
    return {
      pathValid: false,
      code: "INVALID_CERTIFICATE_PATH",
      message: "certificateChain must contain at least one certificate"
    };
  }

  let certificates: Certificate[];
  try {
    certificates = certificateChain.map(parseCertificate);
  } catch {
    return {
      pathValid: false,
      code: "INVALID_CERTIFICATE",
      message: "certificateChain contains an invalid certificate"
    };
  }

  const engine = new CertificateChainValidationEngine({
    // PKI.js selects the last certificate as the leaf.
    certs: certificates.reverse(),
    trustedCerts,
    checkDate
  });

  // Path validation only; revocation is handled separately.
  const result = await engine.verify();
  if (!result.result) {
    return {
      pathValid: false,
      code: "INVALID_CERTIFICATE_PATH",
      message: result.resultMessage
    };
  }

  const certificatePath = engine.certs.map(
    (certificate) => new Uint8Array(certificate.toSchema().toBER(false))
  );
  const trustAnchor = new X509Certificate(
    certificatePath[certificatePath.length - 1]
  );

  return {
    pathValid: true,
    certificatePath,
    trustAnchorFingerprint256: trustAnchor.fingerprint256
  };
}
