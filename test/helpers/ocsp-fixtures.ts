import { OctetString } from "asn1js";
import { BasicOCSPResponse, OCSPResponse } from "pkijs";
import { fixtureTime, readCertificateDer, readOcsp } from "./fixtures.ts";

export function modifiedResponse(
  change: (basic: BasicOCSPResponse) => void
): Uint8Array {
  const outer = OCSPResponse.fromBER(readOcsp("good"));
  const basic = BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  );
  change(basic);
  basic.tbsResponseData.tbsView = new Uint8Array(
    basic.tbsResponseData.toSchema(true).toBER(false)
  );
  outer.responseBytes!.response = new OctetString({
    valueHex: basic.toSchema().toBER(false)
  });
  return new Uint8Array(outer.toSchema().toBER(false));
}

export const certificateDer = readCertificateDer("leaf");
export const issuerDer = readCertificateDer("intermediate");
export const checkDateMs = fixtureTime;
