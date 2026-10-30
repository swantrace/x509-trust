import { X509Certificate } from "node:crypto";
import { AltName, Certificate, id_SubjectAltName } from "pkijs";
import type { CertificateInput } from "./certificate-path.ts";

const URI_GENERAL_NAME = 6;

export function uriSubjectAlternativeNames(certificate: Certificate): string[] {
  const matches = (certificate.extensions ?? []).filter(
    (entry) => entry.extnID === id_SubjectAltName
  );
  if (matches.length > 1) {
    throw new TypeError("Duplicate subject alternative name extension");
  }
  const extension = matches[0];
  if (!extension) return [];

  const names = extension.parsedValue;
  if (!(names instanceof AltName) || "parsingError" in names) {
    throw new TypeError("Invalid subject alternative name extension");
  }

  return names.altNames
    .filter(
      (name) => name.type === URI_GENERAL_NAME && typeof name.value === "string"
    )
    .map((name) => name.value as string);
}

export function getUriSubjectAlternativeNames(
  certificate: CertificateInput
): string[] {
  return uriSubjectAlternativeNames(
    Certificate.fromBER(new X509Certificate(certificate).raw)
  );
}
