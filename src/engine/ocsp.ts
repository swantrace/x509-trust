// Authenticates direct-issuer OCSP responses and checks certificate status and freshness.
import {
  BasicOCSPResponse,
  Certificate,
  id_PKIX_OCSP_Basic,
  OCSPResponse,
  type SingleResponse
} from "pkijs";
import { parseDer } from "./der.ts";
import {
  matchingResponses,
  type OcspValidationResult,
  unknownOcspStatus
} from "./ocsp-response.ts";

export type { OcspValidationResult } from "./ocsp-response.ts";

const OCSP_RESPONSE_SUCCESSFUL = 0;
const OCSP_STATUS_GOOD = 0;
const OCSP_STATUS_REVOKED = 1;
// Certificate and issuer must belong to a previously validated certificate path.
export async function validateOcsp({
  certificateDer,
  issuerDer,
  response: responseDer,
  checkDateMs = Date.now()
}: {
  certificateDer: Uint8Array;
  issuerDer: Uint8Array;
  response: Uint8Array;
  checkDateMs?: number;
  signal?: AbortSignal;
}): Promise<OcspValidationResult> {
  try {
    const certificate = new Certificate({
      schema: parseDer(certificateDer, "certificate").schema
    });
    const issuerCertificate = new Certificate({
      schema: parseDer(issuerDer, "issuer certificate").schema
    });
    const responseSchema = parseDer(responseDer, "OCSP response").schema;
    const checkDate = new Date(checkDateMs);
    if (Number.isNaN(checkDate.getTime())) {
      throw new TypeError("checkDate must be a valid date");
    }
    if (!certificate.issuer.isEqual(issuerCertificate.subject)) {
      return unknownOcspStatus(
        "OCSP_ISSUER_MISMATCH",
        "Certificate does not have the supplied issuer"
      );
    }

    let outer: OCSPResponse;
    try {
      outer = new OCSPResponse({ schema: responseSchema });
    } catch {
      return unknownOcspStatus(
        "INVALID_OCSP_RESPONSE",
        "Unable to parse the DER OCSP response"
      );
    }
    if (outer.responseStatus.valueBlock.valueDec !== OCSP_RESPONSE_SUCCESSFUL) {
      return unknownOcspStatus(
        "OCSP_RESPONDER_ERROR",
        "OCSP responder did not return a successful response"
      );
    }
    if (!outer.responseBytes) {
      return unknownOcspStatus(
        "INVALID_OCSP_RESPONSE",
        "OCSP response has no response bytes"
      );
    }
    if (outer.responseBytes.responseType !== id_PKIX_OCSP_Basic) {
      return unknownOcspStatus(
        "UNSUPPORTED_OCSP_RESPONSE",
        "Only BasicOCSPResponse is supported"
      );
    }

    let basic: BasicOCSPResponse;
    let matches: SingleResponse[];
    try {
      basic = BasicOCSPResponse.fromBER(
        Uint8Array.from(outer.responseBytes.response.valueBlock.valueHexView)
      );
      matches = await matchingResponses(basic, certificate, issuerCertificate);
    } catch {
      return unknownOcspStatus(
        "INVALID_OCSP_RESPONSE",
        "Unable to parse or match the BasicOCSPResponse"
      );
    }
    if (matches.length !== 1) {
      return unknownOcspStatus(
        "OCSP_CERTIFICATE_MISMATCH",
        "OCSP response must contain exactly one matching certificate status"
      );
    }
    const single = matches[0];
    if (
      (basic.tbsResponseData.version ?? 0) !== 0 ||
      basic.tbsResponseData.responseExtensions?.some(
        (extension) => extension.critical
      ) ||
      single.singleExtensions?.some((extension) => extension.critical)
    ) {
      return unknownOcspStatus(
        "UNSUPPORTED_OCSP_RESPONSE",
        "Unsupported OCSP version or critical extension"
      );
    }

    const producedAt = basic.tbsResponseData.producedAt;
    const { thisUpdate, nextUpdate } = single;
    if (!nextUpdate) {
      return unknownOcspStatus(
        "OCSP_MISSING_NEXT_UPDATE",
        "This verifier requires nextUpdate to bound response freshness"
      );
    }
    if (
      [producedAt, thisUpdate, nextUpdate].some((date) =>
        Number.isNaN(date.getTime())
      ) ||
      nextUpdate <= thisUpdate
    ) {
      return unknownOcspStatus(
        "INVALID_OCSP_RESPONSE",
        "Invalid OCSP response time interval"
      );
    }
    if (producedAt > checkDate || thisUpdate > checkDate) {
      return unknownOcspStatus(
        "OCSP_NOT_YET_VALID",
        "OCSP response was produced or updated in the future"
      );
    }
    if (nextUpdate <= checkDate) {
      return unknownOcspStatus(
        "OCSP_EXPIRED",
        "OCSP nextUpdate has been reached"
      );
    }

    // Pin only the already-validated issuer; embedded certificates grant no trust.
    basic.certs = [issuerCertificate];
    try {
      if (
        !(await basic.verify({
          issuerCerts: [issuerCertificate],
          trustedResponders: [issuerCertificate]
        }))
      ) {
        return unknownOcspStatus(
          "INVALID_OCSP_SIGNATURE",
          "OCSP signature does not verify with the issuer"
        );
      }
    } catch {
      return unknownOcspStatus(
        "OCSP_RESPONDER_VERIFICATION_FAILED",
        "Unable to authenticate a direct-issuer OCSP response"
      );
    }

    if (single.certStatus.idBlock.tagNumber === OCSP_STATUS_GOOD) {
      return { status: "good", thisUpdate, nextUpdate, checkedAt: checkDate };
    }
    if (single.certStatus.idBlock.tagNumber === OCSP_STATUS_REVOKED) {
      return {
        status: "revoked",
        thisUpdate,
        nextUpdate,
        checkedAt: checkDate
      };
    }
    return unknownOcspStatus(
      "OCSP_STATUS_UNKNOWN",
      "OCSP responder reports unknown certificate status"
    );
  } catch {
    return unknownOcspStatus(
      "INVALID_OCSP_RESPONSE",
      "Unable to parse the supplied revocation inputs"
    );
  }
}
