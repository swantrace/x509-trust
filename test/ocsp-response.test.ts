import assert from "node:assert/strict";
import { test } from "node:test";
import { Enumerated } from "asn1js";
import { Extension, OCSPResponse } from "pkijs";
import { validateOcsp } from "../src/engine/ocsp.ts";
import {
  certificateDer,
  checkDateMs,
  issuerDer,
  modifiedResponse
} from "./helpers/ocsp-fixtures.ts";

test("rejects malformed OCSP data and unsuccessful responder status", async () => {
  const failed = new OCSPResponse({
    responseStatus: new Enumerated({ value: 3 })
  });
  for (const [response, code] of [
    [Buffer.from("not an OCSP response"), "INVALID_OCSP_RESPONSE"],
    [new Uint8Array(failed.toSchema().toBER(false)), "OCSP_RESPONDER_ERROR"]
  ] as const) {
    const result = await validateOcsp({
      certificateDer,
      issuerDer,
      response,
      checkDateMs
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, code);
  }
});

test("rejects duplicate certificate status entries", async () => {
  const response = modifiedResponse((basic) => {
    basic.tbsResponseData.responses.push(basic.tbsResponseData.responses[0]);
  });
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response,
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_CERTIFICATE_MISMATCH");
});

test("rejects unsupported critical response extensions", async () => {
  const response = modifiedResponse((basic) => {
    basic.tbsResponseData.responseExtensions = [
      new Extension({
        extnID: "1.2.3.4.5",
        critical: true,
        extnValue: new Uint8Array([0x05, 0x00]).buffer
      })
    ];
  });
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response,
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "UNSUPPORTED_OCSP_RESPONSE");
});
