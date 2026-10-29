import type { CrlFailureCode, RevocationStatus } from "../native/index.js";
import { nativeValidateCrl } from "./native.ts";

export type CrlValidationResult =
  | {
      status: Exclude<`${RevocationStatus}`, "unknown">;
      thisUpdate: Date;
      nextUpdate: Date;
    }
  | { status: "unknown"; code: `${CrlFailureCode}`; message: string };

// Certificate and issuer must belong to a previously validated certificate path.
export async function validateCrl({
  certificate,
  issuerCertificate,
  crl,
  checkDate = new Date()
}: {
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  crl: Uint8Array;
  checkDate?: Date;
}): Promise<CrlValidationResult> {
  if (Number.isNaN(checkDate.getTime())) {
    throw new TypeError("checkDate must be a valid date");
  }
  const result = await nativeValidateCrl(
    certificate,
    issuerCertificate,
    crl,
    checkDate.getTime()
  );
  if (result.status === "unknown") {
    if (!result.code || !result.message)
      throw new Error("Incomplete native CRL failure result");
    return { status: "unknown", code: result.code, message: result.message };
  }
  if (result.thisUpdateMs === undefined || result.nextUpdateMs === undefined) {
    throw new Error("Incomplete native CRL validity interval");
  }
  return {
    status: result.status,
    thisUpdate: new Date(result.thisUpdateMs),
    nextUpdate: new Date(result.nextUpdateMs)
  };
}
