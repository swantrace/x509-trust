import assert from "node:assert/strict";
import { test } from "node:test";
import { Certificate } from "pkijs";
import { validateOcsp } from "../src/engine/ocsp.ts";
import { readCertificateDer, readOcsp } from "./helpers/fixtures.ts";
import {
  certificateDer,
  checkDateMs,
  issuerDer,
  modifiedResponse
} from "./helpers/ocsp-fixtures.ts";

for (const [name, subject, status] of [
  ["good", "leaf", "good"],
  ["revoked", "revoked-leaf", "revoked"],
  ["unknown", "leaf", "unknown"]
]) {
  test(`authenticates the signed ${name} OCSP fixture and returns ${status}`, async () => {
    const result = await validateOcsp({
      certificateDer: readCertificateDer(subject),
      issuerDer,
      response: readOcsp(name),
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
    issuerDer: readCertificateDer("root"),
    response: readOcsp("intermediate-good"),
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
    response: readOcsp("intermediate-good"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_CERTIFICATE_MISMATCH");
});

test("rejects a response for a different client certificate", async () => {
  const result = await validateOcsp({
    certificateDer: readCertificateDer("revoked-leaf"),
    issuerDer,
    response: readOcsp("good"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_CERTIFICATE_MISMATCH");
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
  const impostor = Certificate.fromBER(readCertificateDer("untrusted-root"));
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
