import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Enumerated, OctetString } from "asn1js";
import { BasicOCSPResponse, Certificate, Extension, OCSPResponse } from "pkijs";
import { validateOcsp } from "../src/engine/ocsp.ts";

function readDer(name: string): Uint8Array<ArrayBuffer> {
  const pem = readFileSync(new URL(`./fixtures/${name}.pem`, import.meta.url));
  return Uint8Array.from(new X509Certificate(pem).raw);
}

function readResponse(name: string) {
  return readFileSync(new URL(`./fixtures/ocsp/${name}.der`, import.meta.url));
}

function modifiedResponse(
  change: (basic: BasicOCSPResponse) => void
): Uint8Array {
  const outer = OCSPResponse.fromBER(readResponse("good"));
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

const certificateDer = readDer("leaf");
const issuerDer = readDer("intermediate");
const checkDateMs = Date.parse(
  readFileSync(
    new URL("./fixtures/validation-time.txt", import.meta.url),
    "utf8"
  ).trim()
);

for (const [name, subject, status] of [
  ["good", "leaf", "good"],
  ["revoked", "revoked-leaf", "revoked"],
  ["unknown", "leaf", "unknown"]
]) {
  test(`authenticates the signed ${name} OCSP fixture and returns ${status}`, async () => {
    const result = await validateOcsp({
      certificateDer: readDer(subject),
      issuerDer,
      response: readResponse(name),
      checkDateMs
    });
    assert.equal(result.status, status);
    if (result.status === "unknown")
      assert.equal(result.code, "OCSP_STATUS_UNKNOWN");
  });
}

test("checks the intermediate using a response signed by its root issuer", async () => {
  const result = await validateOcsp({
    certificateDer: issuerDer,
    issuerDer: readDer("root"),
    response: readResponse("intermediate-good"),
    checkDateMs
  });
  assert.equal(result.status, "good");
});

test("matches issuer hashes as well as serial number", async () => {
  assert.ok(
    Certificate.fromBER(certificateDer).serialNumber.isEqual(
      Certificate.fromBER(issuerDer).serialNumber
    )
  );
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readResponse("intermediate-good"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_CERTIFICATE_MISMATCH");
});

test("rejects a response for a different client certificate", async () => {
  const result = await validateOcsp({
    certificateDer: readDer("revoked-leaf"),
    issuerDer,
    response: readResponse("good"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_CERTIFICATE_MISMATCH");
});

test("reports unknown for an expired OCSP response", async () => {
  const outer = OCSPResponse.fromBER(readResponse("good"));
  const basic = BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  );
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readResponse("good"),
    checkDateMs: basic.tbsResponseData.responses[0].nextUpdate!.getTime()
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_EXPIRED");
});

test("reports unknown before the response's thisUpdate", async () => {
  const outer = OCSPResponse.fromBER(readResponse("good"));
  const basic = BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  );
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readResponse("good"),
    checkDateMs: basic.tbsResponseData.responses[0].thisUpdate.getTime() - 1000
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_NOT_YET_VALID");
});

test("rejects a modified OCSP signature", async () => {
  const response = modifiedResponse((basic) => {
    const signature = basic.signature.valueBlock.valueHexView;
    signature[signature.length - 1] ^= 1;
  });
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response,
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "INVALID_OCSP_SIGNATURE");
});

test("can authenticate a direct-issuer response without embedded certificates", async () => {
  const response = modifiedResponse((basic) => {
    delete basic.certs;
  });
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response,
    checkDateMs
  });
  assert.equal(result.status, "good");
});

test("does not trust an embedded certificate with the issuer's name and a different key", async () => {
  const impostor = Certificate.fromBER(readDer("untrusted-root"));
  impostor.subject = Certificate.fromBER(issuerDer).subject;
  const response = modifiedResponse((basic) => {
    basic.certs = [impostor];
  });
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response,
    checkDateMs
  });
  assert.equal(result.status, "good");
});

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

test("reports unknown for an invalid validation timestamp", async () => {
  const result = await validateOcsp({
    certificateDer,
    issuerDer,
    response: readResponse("good"),
    checkDateMs: NaN
  });
  assert.equal(result.status, "unknown");
  assert.equal(
    result.status === "unknown" && result.code,
    "INVALID_OCSP_RESPONSE"
  );
});
