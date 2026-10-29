import type { NativeValidatedPath } from "../native/index.js";
import {
  nativeCertificateDer,
  nativeUriSubjectAlternativeNames,
  nativeValidateCertificatePath
} from "./native.ts";

export type CertificateInput = string | Uint8Array;

export function certificateBytes(input: CertificateInput): Uint8Array {
  return typeof input === "string" ? Buffer.from(input) : input;
}

export function certificateDer(input: CertificateInput): Uint8Array {
  return nativeCertificateDer(certificateBytes(input));
}

export function getUriSubjectAlternativeNames(
  certificate: CertificateInput
): string[] {
  return nativeUriSubjectAlternativeNames(certificateBytes(certificate));
}

interface CertificatePathOptions {
  // Leaf first; the root certificate may be omitted.
  certificateChain: readonly CertificateInput[];
  trustAnchors: readonly CertificateInput[];
  checkDate?: Date;
}

type CertificatePathResult =
  | ({ pathValid: true } & NativeValidatedPath)
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

  if (certificateChain.length === 0) {
    return {
      pathValid: false,
      code: "INVALID_CERTIFICATE_PATH",
      message: "certificateChain must contain at least one certificate"
    };
  }

  let certificates: Uint8Array[];
  try {
    certificates = certificateChain.map(certificateBytes);
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
      trustAnchors.map(certificateBytes),
      checkDate.getTime()
    );
    return {
      pathValid: true,
      ...result
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
