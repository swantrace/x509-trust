import assert from "node:assert/strict";
import { test } from "node:test";
import { BitString, OctetString } from "asn1js";
import {
  Certificate,
  CertificateRevocationList,
  Extension,
  Extensions,
  id_BaseCRLNumber,
  id_IssuingDistributionPoint,
  id_KeyUsage
} from "pkijs";
import { validateCrl } from "../src/engine/crl.ts";
import {
  fixtureTime,
  readCertificateDer,
  readCrl
} from "./helpers/fixtures.ts";

const certificateDer = readCertificateDer("leaf");
const issuerDer = readCertificateDer("intermediate");
const checkDateMs = fixtureTime;
const crl = readCrl("intermediate-revoked");

test("reports good when a valid CRL revokes a different certificate", async () => {
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl,
    checkDateMs
  });
  assert.equal(result.status, "good");
  assert.ok(result.thisUpdate.getTime() <= checkDateMs);
  assert.ok(result.nextUpdate.getTime() > checkDateMs);
});

test("reports revoked for the certificate listed in a valid signed CRL", async () => {
  const result = await validateCrl({
    certificateDer: readCertificateDer("revoked-leaf"),
    issuerDer,
    crl,
    checkDateMs
  });
  assert.equal(result.status, "revoked");
});

test("uses the earlier clean CRL as its own snapshot of revocation status", async () => {
  const result = await validateCrl({
    certificateDer: readCertificateDer("revoked-leaf"),
    issuerDer,
    crl: readCrl("intermediate-clean"),
    checkDateMs
  });
  assert.equal(result.status, "good");
});

test("checks intermediate certificate status using its root issuer's CRL", async () => {
  const result = await validateCrl({
    certificateDer: issuerDer,
    issuerDer: readCertificateDer("root"),
    crl: readCrl("root"),
    checkDateMs
  });
  assert.equal(result.status, "good");
});

test("reports unknown for an expired CRL", async () => {
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl: readCrl("intermediate-expired"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "CRL_EXPIRED");
});

test("reports unknown before thisUpdate and at the nextUpdate boundary", async () => {
  const parsed = CertificateRevocationList.fromBER(crl);
  for (const [date, code] of [
    [new Date(parsed.thisUpdate.value.getTime() - 1000), "CRL_NOT_YET_VALID"],
    [parsed.nextUpdate!.value, "CRL_EXPIRED"]
  ] as const) {
    const result = await validateCrl({
      certificateDer,
      issuerDer,
      crl,
      checkDateMs: date.getTime()
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, code);
  }
});

test("rejects a CRL issued by a different CA", async () => {
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl: readCrl("root"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "CRL_ISSUER_MISMATCH");
});

test("rejects an issuer whose key usage does not permit CRL signing", async () => {
  const issuer = Certificate.fromBER(readCertificateDer("intermediate"));
  const keyUsage = issuer.extensions!.find(
    (extension) => extension.extnID === id_KeyUsage
  )!;
  keyUsage.parsedValue = new BitString({
    valueHex: new Uint8Array([0x04]).buffer
  });
  keyUsage.extnValue = new OctetString({
    valueHex: keyUsage.parsedValue.toBER(false)
  });
  const result = await validateCrl({
    certificateDer,
    issuerDer: new Uint8Array(issuer.toSchema(true).toBER(false)),
    crl,
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "CRL_ISSUER_NOT_AUTHORIZED");
});

test("rejects a modified CRL signature", async () => {
  const modified = Buffer.from(crl);
  modified[modified.length - 1] ^= 1;
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl: modified,
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "INVALID_CRL_SIGNATURE");
});

test("reports unknown for malformed CRL data", async () => {
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl: Buffer.from("not a CRL"),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "INVALID_CRL");
});

test("requires nextUpdate instead of accepting a CRL indefinitely", async () => {
  const parsed = CertificateRevocationList.fromBER(crl);
  delete parsed.nextUpdate;
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl: new Uint8Array(parsed.toSchema(true).toBER(false)),
    checkDateMs
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "CRL_MISSING_NEXT_UPDATE");
});

for (const extnID of [
  id_BaseCRLNumber,
  id_IssuingDistributionPoint,
  "1.2.3.4.5"
]) {
  test(`reports unknown for unsupported CRL extension ${extnID}`, async () => {
    const parsed = CertificateRevocationList.fromBER(crl);
    parsed.crlExtensions ??= new Extensions();
    parsed.crlExtensions.extensions.push(
      new Extension({
        extnID,
        critical: true,
        extnValue: new Uint8Array([0x05, 0x00]).buffer
      })
    );
    const result = await validateCrl({
      certificateDer,
      issuerDer,
      crl: new Uint8Array(parsed.toSchema(true).toBER(false)),
      checkDateMs
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, "UNSUPPORTED_CRL");
  });
}

test("reports unknown for an invalid validation timestamp", async () => {
  const result = await validateCrl({
    certificateDer,
    issuerDer,
    crl,
    checkDateMs: NaN
  });
  assert.equal(result.status, "unknown");
  assert.equal(result.status === "unknown" && result.code, "INVALID_CRL");
});
