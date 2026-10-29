import {
  nativeCertificateDer,
  nativeUriSubjectAlternativeNames,
  nativeValidateCertificatePath
} from "./native.ts";

export type CertificateInput = string | Uint8Array;

export function certificateDer(input: CertificateInput): Uint8Array {
  return nativeCertificateDer(
    typeof input === "string" ? Buffer.from(input) : input
  );
}

export function getUriSubjectAlternativeNames(
  certificate: CertificateInput
): string[] {
  return nativeUriSubjectAlternativeNames(certificateDer(certificate));
}

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
  const trustedCerts = trustAnchors.map(certificateDer);

  if (certificateChain.length === 0) {
    return {
      pathValid: false,
      code: "INVALID_CERTIFICATE_PATH",
      message: "certificateChain must contain at least one certificate"
    };
  }

  let certificates: Uint8Array[];
  try {
    certificates = certificateChain.map(certificateDer);
  } catch {
    return {
      pathValid: false,
      code: "INVALID_CERTIFICATE",
      message: "certificateChain contains an invalid certificate"
    };
  }

  try {
    // Path validation only; revocation is handled separately.
    const result = await nativeValidateCertificatePath(
      certificates,
      trustedCerts,
      checkDate.getTime()
    );
    return {
      pathValid: true,
      certificatePath: result.certificatePath,
      trustAnchorFingerprint256: result.trustAnchorFingerprint256
    };
  } catch (error) {
    return {
      pathValid: false,
      code:
        error instanceof Error && "code" in error && error.code === "InvalidArg"
          ? "INVALID_CERTIFICATE"
          : "INVALID_CERTIFICATE_PATH",
      message:
        error instanceof Error
          ? error.message
          : "Unable to validate certificate path"
    };
  }
}
