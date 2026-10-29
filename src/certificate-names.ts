import { type CertificateInput, certificateDer } from "./certificate-input.ts";
import { nativeUriSubjectAlternativeNames } from "./native.ts";

export function getUriSubjectAlternativeNames(
  certificate: CertificateInput
): string[] {
  return nativeUriSubjectAlternativeNames(certificateDer(certificate));
}
