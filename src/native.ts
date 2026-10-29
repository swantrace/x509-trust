import { createRequire } from "node:module";

const binding: typeof import("../native/index.js") = createRequire(
  import.meta.url
)("../native/index.node");

export function nativeValidateCertificatePath(
  chain: Uint8Array[],
  anchors: Uint8Array[],
  checkDateMs: number
) {
  return binding.validateCertificatePath(chain, anchors, checkDateMs);
}

export function nativeValidateCrl(
  certificate: Uint8Array,
  issuerCertificate: Uint8Array,
  crl: Uint8Array,
  checkDateMs: number
) {
  return binding.validateCrl(certificate, issuerCertificate, crl, checkDateMs);
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

export function nativeRevocationEndpoints(der: Uint8Array): {
  crlUrls: string[];
  ocspUrls: string[];
} {
  try {
    return binding.getRevocationEndpoints(der);
  } catch (cause) {
    throw new TypeError(
      cause instanceof Error ? cause.message : "Invalid certificate",
      { cause }
    );
  }
}
