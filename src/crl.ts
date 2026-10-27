import { BitString } from "asn1js";
import {
  type Certificate,
  CertificateRevocationList,
  checkCA,
  id_AuthorityKeyIdentifier,
  id_BaseCRLNumber,
  id_CertificateIssuer,
  id_CRLNumber,
  id_IssuingDistributionPoint,
  id_KeyUsage
} from "pkijs";

const CRL_SIGN_KEY_USAGE = 0x02;
const SUPPORTED_CRITICAL_EXTENSIONS = new Set([
  id_AuthorityKeyIdentifier,
  id_CRLNumber
]);

type CrlFailureCode =
  | "INVALID_CRL"
  | "CRL_ISSUER_MISMATCH"
  | "CRL_ISSUER_NOT_AUTHORIZED"
  | "INVALID_CRL_SIGNATURE"
  | "CRL_NOT_YET_VALID"
  | "CRL_EXPIRED"
  | "CRL_MISSING_NEXT_UPDATE"
  | "UNSUPPORTED_CRL";

export type CrlValidationResult =
  | { status: "good" | "revoked"; thisUpdate: Date; nextUpdate: Date }
  | { status: "unknown"; code: CrlFailureCode; message: string };

function unknownCrlStatus(
  code: CrlFailureCode,
  message: string
): CrlValidationResult {
  return { status: "unknown", code, message };
}

function issuerCanSignCrl(issuer: Certificate): boolean {
  if (!checkCA(issuer)) return false;
  const keyUsage = issuer.extensions?.find(
    (extension) => extension.extnID === id_KeyUsage
  );
  if (!keyUsage) return true;
  const usage = keyUsage.parsedValue;
  return (
    usage instanceof BitString &&
    (usage.valueBlock.valueHexView[0] & CRL_SIGN_KEY_USAGE) !== 0
  );
}

function hasUnsupportedExtensions(crl: CertificateRevocationList): boolean {
  return (
    (crl.crlExtensions?.extensions ?? []).some(
      (extension) =>
        extension.extnID === id_BaseCRLNumber ||
        extension.extnID === id_IssuingDistributionPoint ||
        (extension.critical &&
          !SUPPORTED_CRITICAL_EXTENSIONS.has(extension.extnID))
    ) ||
    (crl.revokedCertificates ?? []).some((entry) =>
      (entry.crlEntryExtensions?.extensions ?? []).some(
        (extension) =>
          extension.extnID === id_CertificateIssuer || extension.critical
      )
    )
  );
}

// Certificate and issuer must belong to a previously validated certificate path.
export async function validateCrl({
  certificate,
  issuerCertificate,
  crl: crlDer,
  checkDate = new Date()
}: {
  certificate: Certificate;
  issuerCertificate: Certificate;
  crl: Uint8Array;
  checkDate?: Date;
}): Promise<CrlValidationResult> {
  if (Number.isNaN(checkDate.getTime())) {
    throw new TypeError("checkDate must be a valid date");
  }

  let crl: CertificateRevocationList;
  try {
    crl = CertificateRevocationList.fromBER(Uint8Array.from(crlDer));
  } catch {
    return unknownCrlStatus("INVALID_CRL", "Unable to parse the DER CRL");
  }

  if (
    !certificate.issuer.isEqual(issuerCertificate.subject) ||
    !crl.issuer.isEqual(issuerCertificate.subject)
  ) {
    return unknownCrlStatus(
      "CRL_ISSUER_MISMATCH",
      "Certificate and CRL must have the supplied issuer"
    );
  }
  if (!issuerCanSignCrl(issuerCertificate)) {
    return unknownCrlStatus(
      "CRL_ISSUER_NOT_AUTHORIZED",
      "The issuer must be a CA permitted to sign CRLs"
    );
  }
  if (hasUnsupportedExtensions(crl)) {
    return unknownCrlStatus(
      "UNSUPPORTED_CRL",
      "Only direct, complete CRLs without scope restrictions are supported"
    );
  }

  const thisUpdate = crl.thisUpdate.value;
  const nextUpdate = crl.nextUpdate?.value;
  if (!nextUpdate) {
    return unknownCrlStatus(
      "CRL_MISSING_NEXT_UPDATE",
      "CRL nextUpdate is required"
    );
  }
  if (
    Number.isNaN(thisUpdate.getTime()) ||
    Number.isNaN(nextUpdate.getTime()) ||
    nextUpdate <= thisUpdate
  ) {
    return unknownCrlStatus("INVALID_CRL", "Invalid CRL validity interval");
  }
  if (thisUpdate > checkDate) {
    return unknownCrlStatus(
      "CRL_NOT_YET_VALID",
      "CRL thisUpdate is in the future"
    );
  }
  if (nextUpdate <= checkDate) {
    return unknownCrlStatus("CRL_EXPIRED", "CRL nextUpdate has been reached");
  }

  if (
    !Buffer.from(crl.signature.toSchema().toBER(false)).equals(
      Buffer.from(crl.signatureAlgorithm.toSchema().toBER(false))
    )
  ) {
    return unknownCrlStatus(
      "INVALID_CRL_SIGNATURE",
      "CRL signature algorithm identifiers do not match"
    );
  }
  try {
    if (!(await crl.verify({ issuerCertificate }))) {
      return unknownCrlStatus(
        "INVALID_CRL_SIGNATURE",
        "CRL signature is invalid"
      );
    }
  } catch {
    return unknownCrlStatus(
      "INVALID_CRL_SIGNATURE",
      "Unable to verify CRL signature"
    );
  }

  return {
    status: crl.isCertificateRevoked(certificate) ? "revoked" : "good",
    thisUpdate,
    nextUpdate
  };
}
