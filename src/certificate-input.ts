import { X509Certificate } from "node:crypto";

export type CertificateInput = string | Uint8Array;

export function certificateDer(input: CertificateInput): Uint8Array {
  // DER certificates start with a SEQUENCE. Preserve their full input so Rust
  // can reject trailing data; normalize PEM strings and byte buffers with Node.
  return typeof input === "string" || input[0] !== 0x30
    ? new X509Certificate(input).raw
    : input;
}
