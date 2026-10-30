import { X509Certificate } from "node:crypto";
import { BitString } from "asn1js";
import {
  BasicConstraints,
  type Certificate,
  CertificatePolicies,
  ExtKeyUsage,
  id_BasicConstraints,
  id_CertificatePolicies,
  id_ExtKeyUsage,
  id_KeyUsage
} from "pkijs";
import { uriSubjectAlternativeNames } from "./certificate-names.ts";

export type KeyUsageName =
  | "digitalSignature"
  | "nonRepudiation"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";

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

const KEY_USAGE_BITS: ReadonlyArray<[KeyUsageName, number, number]> = [
  ["digitalSignature", 0, 0x80],
  ["nonRepudiation", 0, 0x40],
  ["keyEncipherment", 0, 0x20],
  ["dataEncipherment", 0, 0x10],
  ["keyAgreement", 0, 0x08],
  ["keyCertSign", 0, 0x04],
  ["cRLSign", 0, 0x02],
  ["encipherOnly", 0, 0x01],
  ["decipherOnly", 1, 0x80]
];

function singleExtension<T>(
  certificate: Certificate,
  oid: string
): T | undefined {
  const matches = (certificate.extensions ?? []).filter(
    (extension) => extension.extnID === oid
  );
  if (matches.length > 1) {
    throw new TypeError(`Duplicate certificate extension: ${oid}`);
  }
  const value = matches[0]?.parsedValue;
  return value === undefined ? undefined : (value as T);
}

export function keyUsageNames(
  certificate: Certificate
): KeyUsageName[] | undefined {
  const usage = singleExtension<BitString>(certificate, id_KeyUsage);
  if (usage === undefined) return undefined;
  if (!(usage instanceof BitString)) {
    throw new TypeError("Invalid key usage extension");
  }
  const bytes = usage.valueBlock.valueHexView;
  return KEY_USAGE_BITS.filter(
    ([, byte, mask]) => byte < bytes.byteLength && (bytes[byte] & mask) !== 0
  ).map(([name]) => name);
}

export function extendedKeyUsageOids(
  certificate: Certificate
): string[] | undefined {
  const usage = singleExtension<ExtKeyUsage>(certificate, id_ExtKeyUsage);
  if (usage === undefined) return undefined;
  if (!(usage instanceof ExtKeyUsage)) {
    throw new TypeError("Invalid extended key usage extension");
  }
  return Array.from(usage.keyPurposes);
}

export function certificatePolicyOids(
  certificate: Certificate
): string[] | undefined {
  const policies = singleExtension<CertificatePolicies>(
    certificate,
    id_CertificatePolicies
  );
  if (policies === undefined) return undefined;
  if (!(policies instanceof CertificatePolicies)) {
    throw new TypeError("Invalid certificate policies extension");
  }
  return policies.certificatePolicies.map((policy) => policy.policyIdentifier);
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
  der: Uint8Array
): ValidatedLeafCertificate {
  const nodeCertificate = new X509Certificate(der);
  const facts = extractCertificateFacts(certificate, der);
  return {
    publicKeySpkiDer: new Uint8Array(
      certificate.subjectPublicKeyInfo.toSchema().toBER(false)
    ),
    uriSubjectAlternativeNames: uriSubjectAlternativeNames(certificate),
    fingerprint256: facts.fingerprint256,
    serialNumber: normalizeSerialNumber(nodeCertificate.serialNumber),
    notBeforeMs: certificate.notBefore.value.getTime(),
    notAfterMs: certificate.notAfter.value.getTime(),
    subject: facts.subject,
    issuer: facts.issuer,
    keyUsages: facts.keyUsages,
    extendedKeyUsageOids: facts.extendedKeyUsageOids,
    certificatePolicyOids: facts.certificatePolicyOids,
    der: Uint8Array.from(der)
  };
}
