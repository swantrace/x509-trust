// Extracts certificate identity, URI subject alternative names, and leaf public-key metadata.
import { X509Certificate } from "node:crypto";
import {
  AltName,
  BasicConstraints,
  Certificate,
  id_BasicConstraints,
  id_SubjectAltName
} from "pkijs";
import {
  certificatePolicyOids,
  extendedKeyUsageOids,
  type KeyUsageName,
  keyUsageNames,
  singleExtension
} from "./certificate-extensions.ts";
import type { CertificateInput } from "./certificate-path.ts";

export type { KeyUsageName } from "./certificate-extensions.ts";
export { keyUsageNames } from "./certificate-extensions.ts";

const URI_GENERAL_NAME = 6;
export interface CertificateFacts {
  fingerprint256: string;
  subject: string;
  issuer: string;
  isCa: boolean;
  keyUsages?: KeyUsageName[];
  extendedKeyUsageOids?: string[];
  certificatePolicyOids?: string[];
}

export interface ValidatedLeafCertificate {
  publicKeySpkiDer: Uint8Array;
  uriSubjectAlternativeNames: string[];
  fingerprint256: string;
  serialNumber: string;
  notBeforeMs: number;
  notAfterMs: number;
  subject: string;
  issuer: string;
  keyUsages?: KeyUsageName[];
  extendedKeyUsageOids?: string[];
  certificatePolicyOids?: string[];
  der: Uint8Array;
}

export function getUriSubjectAlternativeNames(
  input: CertificateInput | Certificate
): string[] {
  const certificate =
    input instanceof Certificate
      ? input
      : Certificate.fromBER(new X509Certificate(input).raw);
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

function normalizeSerialNumber(serialNumber: string): string {
  let normalized = serialNumber.toUpperCase();
  if (normalized.length % 2 !== 0) normalized = `0${normalized}`;
  while (normalized.length > 2 && normalized.startsWith("00")) {
    normalized = normalized.slice(2);
  }
  return normalized;
}

export function extractCertificateFacts(
  certificate: Certificate,
  der: Uint8Array
): CertificateFacts {
  const nodeCertificate = new X509Certificate(der);
  const constraints = singleExtension<BasicConstraints>(
    certificate,
    id_BasicConstraints
  );
  if (constraints !== undefined && !(constraints instanceof BasicConstraints)) {
    throw new TypeError("Invalid basic constraints extension");
  }
  return {
    fingerprint256: nodeCertificate.fingerprint256,
    subject: nodeCertificate.subject,
    issuer: nodeCertificate.issuer,
    isCa: constraints?.cA === true,
    keyUsages: keyUsageNames(certificate),
    extendedKeyUsageOids: extendedKeyUsageOids(certificate),
    certificatePolicyOids: certificatePolicyOids(certificate)
  };
}

export function extractLeafCertificate(
  certificate: Certificate,
  der: Uint8Array,
  facts = extractCertificateFacts(certificate, der)
): ValidatedLeafCertificate {
  const nodeCertificate = new X509Certificate(der);
  return {
    publicKeySpkiDer: new Uint8Array(
      certificate.subjectPublicKeyInfo.toSchema().toBER(false)
    ),
    uriSubjectAlternativeNames: getUriSubjectAlternativeNames(certificate),
    fingerprint256: facts.fingerprint256,
    serialNumber: normalizeSerialNumber(nodeCertificate.serialNumber),
    notBeforeMs: certificate.notBefore.value.getTime(),
    notAfterMs: certificate.notAfter.value.getTime(),
    subject: facts.subject,
    issuer: facts.issuer,
    keyUsages: facts.keyUsages?.slice(),
    extendedKeyUsageOids: facts.extendedKeyUsageOids?.slice(),
    certificatePolicyOids: facts.certificatePolicyOids?.slice(),
    der: Uint8Array.from(der)
  };
}
