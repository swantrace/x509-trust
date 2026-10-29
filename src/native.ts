import { createRequire } from "node:module";
import type { RevocationEndpoints } from "../native/index.js";

const binding: typeof import("../native/index.js") = createRequire(
  import.meta.url
)("../native/index.node");

// Keep native signatures and result types sourced from the generated declarations.
export const nativeValidateCertificatePath = binding.validateCertificatePath;
export const nativeValidateCrl = binding.validateCrl;
export const nativeCreateOcspRequest = binding.createOcspRequest;
export const nativeValidateOcsp = binding.validateOcsp;
export const nativeValidateEvidence = binding.validateEvidence;

export function nativeCertificateDer(input: Uint8Array): Uint8Array {
  try {
    return binding.certificateDer(input);
  } catch (cause) {
    throw new TypeError(
      cause instanceof Error ? cause.message : "Invalid certificate",
      { cause }
    );
  }
}

export function nativeUriSubjectAlternativeNames(der: Uint8Array): string[] {
  try {
    return binding.getUriSubjectAlternativeNames(der);
  } catch (cause) {
    throw new TypeError(
      cause instanceof Error ? cause.message : "Invalid certificate",
      { cause }
    );
  }
}

export function nativeRevocationEndpoints(
  der: Uint8Array
): RevocationEndpoints {
  try {
    return binding.getRevocationEndpoints(der);
  } catch (cause) {
    throw new TypeError(
      cause instanceof Error ? cause.message : "Invalid certificate",
      { cause }
    );
  }
}
