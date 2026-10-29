import { X509Certificate } from "node:crypto";
import type { CertificateInput } from "./certificate-path.ts";
import { nativeUriSubjectAlternativeNames } from "./native.ts";

export function getUriSubjectAlternativeNames(
  certificate: CertificateInput
): string[] {
  return nativeUriSubjectAlternativeNames(
    typeof certificate === "string"
      ? new X509Certificate(certificate).raw
      : certificate
  );
}
