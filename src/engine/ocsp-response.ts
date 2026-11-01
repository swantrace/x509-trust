// Defines OCSP result types and matches response entries to certificate and issuer identities.
import {
  type BasicOCSPResponse,
  CertID,
  type Certificate,
  getAlgorithmByOID,
  type SingleResponse
} from "pkijs";
export type OcspFailureCode =
  | "INVALID_OCSP_RESPONSE"
  | "OCSP_RESPONDER_ERROR"
  | "UNSUPPORTED_OCSP_RESPONSE"
  | "OCSP_ISSUER_MISMATCH"
  | "OCSP_CERTIFICATE_MISMATCH"
  | "INVALID_OCSP_SIGNATURE"
  | "OCSP_RESPONDER_VERIFICATION_FAILED"
  | "OCSP_NOT_YET_VALID"
  | "OCSP_EXPIRED"
  | "OCSP_MISSING_NEXT_UPDATE"
  | "OCSP_STATUS_UNKNOWN";

export type OcspValidationResult =
  | {
      status: "good" | "revoked";
      thisUpdate: Date;
      nextUpdate: Date;
      checkedAt: Date;
    }
  | { status: "unknown"; code: OcspFailureCode; message: string };

export function unknownOcspStatus(
  code: OcspFailureCode,
  message: string
): OcspValidationResult {
  return { status: "unknown", code, message };
}

export async function matchingResponses(
  response: BasicOCSPResponse,
  certificate: Certificate,
  issuerCertificate: Certificate
): Promise<SingleResponse[]> {
  const matches: SingleResponse[] = [];
  for (const single of response.tbsResponseData.responses) {
    const algorithm = getAlgorithmByOID(
      single.certID.hashAlgorithm.algorithmId,
      true
    );
    const expected = await CertID.create(certificate, {
      issuerCertificate,
      hashAlgorithm: algorithm.name
    });
    if (single.certID.isEqual(expected)) matches.push(single);
  }
  return matches;
}
