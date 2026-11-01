import assert from "node:assert/strict";
import { test } from "node:test";
import { BasicOCSPResponse, OCSPResponse } from "pkijs";
import { validateOcsp } from "../src/engine/ocsp.ts";
import { readOcsp } from "./helpers/fixtures.ts";
import {
  certificateDer,
  checkDateMs,
  issuerDer,
  modifiedResponse
} from "./helpers/ocsp-fixtures.ts";

test("reports unknown for an expired OCSP response", async () => {
  const outer = OCSPResponse.fromBER(readOcsp("good"));
  const basic = BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  );
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readOcsp("good"),
    checkDateMs: basic.tbsResponseData.responses[0].nextUpdate!.getTime()
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_EXPIRED");
});

test("reports unknown before the response's thisUpdate", async () => {
  const outer = OCSPResponse.fromBER(readOcsp("good"));
  const basic = BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  );
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readOcsp("good"),
    checkDateMs: basic.tbsResponseData.responses[0].thisUpdate.getTime() - 1000
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_NOT_YET_VALID");
});

test("reports unknown when nextUpdate is absent", async () => {
  const response = modifiedResponse((basic) => {
    delete basic.tbsResponseData.responses[0].nextUpdate;
  });
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response,
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_MISSING_NEXT_UPDATE");
});

test("reports unknown for an invalid validation timestamp", async () => {
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readOcsp("good"),
    checkDateMs: NaN
  });
  assert.equal(result.status, "unknown");
  assert.equal(
    result.status === "unknown" && result.code,
    "INVALID_OCSP_RESPONSE"
  );
});
