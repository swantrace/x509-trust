import { nativeCertificateDer } from "./native.ts";

export type CertificateInput = string | Uint8Array;

export function certificateDer(input: CertificateInput): Uint8Array {
  return nativeCertificateDer(
    typeof input === "string" ? Buffer.from(input) : input
  );
}
