import { nativeValidateOcsp } from "./native.ts";

type OcspFailureCode =
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
  | { status: "good" | "revoked"; thisUpdate: Date; nextUpdate: Date }
  | { status: "unknown"; code: OcspFailureCode; message: string };

// Certificate and issuer must belong to a previously validated certificate path.
export async function validateOcsp({
  certificate,
  issuerCertificate,
  response,
  checkDate = new Date()
}: {
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  response: Uint8Array;
  checkDate?: Date;
}): Promise<OcspValidationResult> {
  if (Number.isNaN(checkDate.getTime())) {
    throw new TypeError("checkDate must be a valid date");
  }
  const result = await nativeValidateOcsp(
    certificate,
    issuerCertificate,
    response,
    checkDate.getTime()
  );
  if (result.status === "unknown") {
    if (!result.code || !result.message)
      throw new Error("Incomplete native OCSP failure result");
    return { status: "unknown", code: result.code, message: result.message };
  }
  if (result.thisUpdateMs === undefined || result.nextUpdateMs === undefined) {
    throw new Error("Incomplete native OCSP validity interval");
  }
  return {
    status: result.status,
    thisUpdate: new Date(result.thisUpdateMs),
    nextUpdate: new Date(result.nextUpdateMs)
  };
}
