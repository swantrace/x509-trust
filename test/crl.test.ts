import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BitString } from "asn1js";
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

function readFixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
}

function readCertificate(name: string): Certificate {
  return Certificate.fromBER(
    new X509Certificate(readFixture(`${name}.pem`)).raw
  );
}

function readCrl(name: string) {
  return Buffer.from(
    readFixture(`crl/${name}.crl.pem`).replace(/-----[^\n]+-----/g, ""),
    "base64"
  );
}

const certificate = readCertificate("leaf");
const issuerCertificate = readCertificate("intermediate");
const checkDate = new Date(readFixture("validation-time.txt").trim());
const crl = readCrl("intermediate-revoked");

test("reports good when a valid CRL revokes a different certificate", async () => {
  const result = await validateCrl({
    certificate,
    issuerCertificate,
    crl,
    checkDate
  });
  assert.equal(result.status, "good");
  assert.ok(result.thisUpdate <= checkDate);
  assert.ok(result.nextUpdate > checkDate);
});

test("reports revoked for the certificate listed in a valid signed CRL", async () => {
  const result = await validateCrl({
    certificate: readCertificate("revoked-leaf"),
    issuerCertificate,
    crl,
    checkDate
  });
  assert.equal(result.status, "revoked");
});

test("uses the earlier clean CRL as its own snapshot of revocation status", async () => {
  const result = await validateCrl({
    certificate: readCertificate("revoked-leaf"),
    issuerCertificate,
    crl: readCrl("intermediate-clean"),
    checkDate
  });
  assert.equal(result.status, "good");
});

test("checks intermediate certificate status using its root issuer's CRL", async () => {
  const result = await validateCrl({
    certificate: issuerCertificate,
    issuerCertificate: readCertificate("root"),
    crl: readCrl("root"),
    checkDate
  });
  assert.equal(result.status, "good");
});

test("reports unknown for an expired CRL", async () => {
  const result = await validateCrl({
    certificate,
    issuerCertificate,
    crl: readCrl("intermediate-expired"),
    checkDate
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
      certificate,
      issuerCertificate,
      crl,
      checkDate: date
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, code);
  }
});

test("rejects a CRL issued by a different CA", async () => {
  const result = await validateCrl({
    certificate,
    issuerCertificate,
    crl: readCrl("root"),
    checkDate
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "CRL_ISSUER_MISMATCH");
});

test("rejects an issuer whose key usage does not permit CRL signing", async () => {
  const issuer = readCertificate("intermediate");
  const keyUsage = issuer.extensions!.find(
    (extension) => extension.extnID === id_KeyUsage
  )!;
  keyUsage.parsedValue = new BitString({
    valueHex: new Uint8Array([0x04]).buffer
  });
  const result = await validateCrl({
    certificate,
    issuerCertificate: issuer,
    crl,
    checkDate
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "CRL_ISSUER_NOT_AUTHORIZED");
});

test("rejects a modified CRL signature", async () => {
  const modified = Buffer.from(crl);
  modified[modified.length - 1] ^= 1;
  const result = await validateCrl({
    certificate,
    issuerCertificate,
    crl: modified,
    checkDate
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "INVALID_CRL_SIGNATURE");
});

test("reports unknown for malformed CRL data", async () => {
  const result = await validateCrl({
    certificate,
    issuerCertificate,
    crl: Buffer.from("not a CRL"),
    checkDate
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "INVALID_CRL");
});

test("requires nextUpdate instead of accepting a CRL indefinitely", async () => {
  const parsed = CertificateRevocationList.fromBER(crl);
  delete parsed.nextUpdate;
  const result = await validateCrl({
    certificate,
    issuerCertificate,
    crl: new Uint8Array(parsed.toSchema(true).toBER(false)),
    checkDate
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
      certificate,
      issuerCertificate,
      crl: new Uint8Array(parsed.toSchema(true).toBER(false)),
      checkDate
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, "UNSUPPORTED_CRL");
  });
}

test("rejects an invalid check date", async () => {
  await assert.rejects(
    validateCrl({
      certificate,
      issuerCertificate,
      crl,
      checkDate: new Date(NaN)
    }),
    TypeError
  );
});
