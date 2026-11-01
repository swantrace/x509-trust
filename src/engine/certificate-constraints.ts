// Normalizes certificate input and checks extension, trust-anchor, and path-length constraints.
import { X509Certificate } from "node:crypto";
import { BitString } from "asn1js";
import {
  BasicConstraints,
  Certificate,
  id_BasicConstraints,
  id_KeyUsage
} from "pkijs";
import type { CertificateInput } from "./certificate-path.ts";
import { parseDer } from "./der.ts";

const KEY_CERT_SIGN = 0x04;

const SUPPORTED_CRITICAL_EXTENSIONS = new Set([
  "2.5.29.15", // keyUsage
  "2.5.29.17", // subjectAltName
  "2.5.29.19", // basicConstraints
  "2.5.29.30", // nameConstraints
  "2.5.29.31", // cRLDistributionPoints
  "2.5.29.32", // certificatePolicies
  "2.5.29.33", // policyMappings
  "2.5.29.35", // authorityKeyIdentifier
  "2.5.29.36", // policyConstraints
  "2.5.29.37", // extKeyUsage
  "2.5.29.54", // inhibitAnyPolicy
  "1.3.6.1.5.5.7.1.1" // authorityInfoAccess
]);

export function normalizeCertificate(
  input: CertificateInput,
  label: string
): Uint8Array<ArrayBuffer> {
  if (typeof input === "string") {
    return parseDer(new X509Certificate(input).raw, label).bytes;
  }
  const bytes = Uint8Array.from(input);
  const header = new TextDecoder("ascii").decode(bytes.subarray(0, 11));
  return header === "-----BEGIN "
    ? parseDer(new X509Certificate(input).raw, label).bytes
    : parseDer(bytes, label).bytes;
}

function extensionValue<T>(
  certificate: Certificate,
  oid: string
): T | undefined {
  const extensions = (certificate.extensions ?? []).filter(
    (extension) => extension.extnID === oid
  );
  if (extensions.length > 1) {
    throw new TypeError(`Duplicate certificate extension: ${oid}`);
  }
  return extensions[0]?.parsedValue as T | undefined;
}

function keyUsageAllowsKeyCertSign(
  certificate: Certificate
): boolean | undefined {
  const usage = extensionValue<BitString>(certificate, id_KeyUsage);
  if (!usage) return undefined;
  if (!(usage instanceof BitString)) return false;
  return (usage.valueBlock.valueHexView[0] & KEY_CERT_SIGN) !== 0;
}

function pathLength(certificate: Certificate): number | undefined {
  const constraints = extensionValue<BasicConstraints>(
    certificate,
    id_BasicConstraints
  );
  if (!(constraints instanceof BasicConstraints)) return undefined;
  const value = constraints.pathLenConstraint;
  return typeof value === "number" ? value : value?.valueBlock.valueDec;
}

export function assertCertificateStructure(
  certificate: Certificate,
  label: string
): void {
  const seen = new Set<string>();
  for (const extension of certificate.extensions ?? []) {
    if (seen.has(extension.extnID)) {
      throw new TypeError(
        `${label} has a duplicate extension ${extension.extnID}`
      );
    }
    seen.add(extension.extnID);
    if (
      extension.critical &&
      !SUPPORTED_CRITICAL_EXTENSIONS.has(extension.extnID)
    ) {
      throw new TypeError(
        `${label} has an unsupported critical extension ${extension.extnID}`
      );
    }
    if (extension.critical && !extension.parsedValue) {
      throw new TypeError(
        `${label} has an unparseable critical extension ${extension.extnID}`
      );
    }
  }
}

export function getTrustAnchorError(
  anchor: Certificate,
  checkDate: Date
): string | undefined {
  if (anchor.notBefore.value > checkDate || anchor.notAfter.value < checkDate) {
    return "The trust anchor is not valid at the validation date";
  }
  const constraints = extensionValue<BasicConstraints>(
    anchor,
    id_BasicConstraints
  );
  if (!(constraints instanceof BasicConstraints) || constraints.cA !== true) {
    return "The trust anchor is not a CA certificate";
  }
  if (keyUsageAllowsKeyCertSign(anchor) === false) {
    return "The trust anchor's key usage does not permit certificate signing";
  }
  return undefined;
}

export function getPathLengthError(
  certificates: Certificate[]
): string | undefined {
  // Index 0 is the leaf; every higher index is a CA certificate.
  for (let index = 1; index < certificates.length; index++) {
    const limit = pathLength(certificates[index]);
    if (limit === undefined) continue;
    let intermediatesBelow = 0;
    for (let below = 1; below < index; below++) {
      if (!certificates[below].subject.isEqual(certificates[below].issuer)) {
        intermediatesBelow++;
      }
    }
    if (intermediatesBelow > limit) {
      return "A certificate pathLenConstraint was exceeded";
    }
  }
  return undefined;
}
