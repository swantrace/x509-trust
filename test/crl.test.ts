import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BitString, OctetString } from "asn1js";
import {
  Certificate,
  CertificateRevocationList,
  Extension,
  Extensions,
  id_BaseCRLNumber,
  id_CertificateIssuer,
  id_CRLNumber,
  id_IssuingDistributionPoint,
  id_KeyUsage
} from "pkijs";
import { nativeValidateCrl } from "../src/native.ts";
import { validateCrl } from "../src/revocation-validation.ts";

function readFixture(name: string): string {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
}

function readCertificate(name: string): Uint8Array {
  return new X509Certificate(readFixture(`${name}.pem`)).raw;
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
  const issuer = Certificate.fromBER(
    Uint8Array.from(readCertificate("intermediate"))
  );
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
    certificate,
    issuerCertificate: new Uint8Array(issuer.toSchema(true).toBER(false)),
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

test("rejects a same-name issuer with a different public key", async () => {
  const impostor = Certificate.fromBER(
    Uint8Array.from(readCertificate("untrusted-root"))
  );
  impostor.subject = Certificate.fromBER(
    Uint8Array.from(issuerCertificate)
  ).subject;
  const result = await validateCrl({
    certificate,
    issuerCertificate: new Uint8Array(impostor.toSchema(true).toBER(false)),
    crl,
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

test("checks CRL time boundaries at millisecond precision", async () => {
  const parsed = CertificateRevocationList.fromBER(crl);
  const start = parsed.thisUpdate.value.getTime();
  const end = parsed.nextUpdate!.value.getTime();
  for (const [time, expected] of [
    [start - 1, "CRL_NOT_YET_VALID"],
    [start, "good"],
    [end - 1, "good"],
    [end, "CRL_EXPIRED"]
  ] as const) {
    const result = await validateCrl({
      certificate,
      issuerCertificate,
      crl,
      checkDate: new Date(time)
    });
    assert.equal(
      result.status === "unknown" ? result.code : result.status,
      expected
    );
  }
});

test("rejects malformed certificates, truncated CRLs and trailing DER", async () => {
  for (const input of [
    new Uint8Array(),
    crl.subarray(0, crl.length - 1),
    Buffer.concat([crl, Buffer.from([0x00])])
  ]) {
    const result = await validateCrl({
      certificate,
      issuerCertificate,
      crl: input,
      checkDate
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, "INVALID_CRL");
  }
  const badCertificate = await validateCrl({
    certificate: Uint8Array.of(0x05, 0x00),
    issuerCertificate,
    crl,
    checkDate
  });
  assert.ok(badCertificate.status === "unknown");
  assert.equal(badCertificate.code, "INVALID_CRL");
  const badIssuer = await validateCrl({
    certificate,
    issuerCertificate: Uint8Array.of(0x05, 0x00),
    crl,
    checkDate
  });
  assert.ok(badIssuer.status === "unknown");
  assert.equal(badIssuer.code, "CRL_ISSUER_NOT_AUTHORIZED");
});

test("rejects mismatched signature algorithm identifiers and non-byte-aligned signatures", async () => {
  for (const mutate of [
    (parsed: CertificateRevocationList) => {
      parsed.signatureAlgorithm.algorithmId = "1.2.840.113549.1.1.12";
    },
    (parsed: CertificateRevocationList) => {
      parsed.signatureValue.valueBlock.unusedBits = 1;
    }
  ]) {
    const parsed = CertificateRevocationList.fromBER(crl);
    mutate(parsed);
    const result = await validateCrl({
      certificate,
      issuerCertificate,
      crl: new Uint8Array(parsed.toSchema().toBER(false)),
      checkDate
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, "INVALID_CRL_SIGNATURE");
  }
});

for (const extnID of [id_BaseCRLNumber, id_IssuingDistributionPoint]) {
  test(`rejects unsupported noncritical CRL extension ${extnID}`, async () => {
    const parsed = CertificateRevocationList.fromBER(crl);
    parsed.crlExtensions!.extensions.push(
      new Extension({ extnID, extnValue: Uint8Array.of(0x05, 0x00).buffer })
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

test("rejects indirect and unsupported critical entry extensions", async () => {
  for (const [extnID, critical] of [
    [id_CertificateIssuer, false],
    ["1.2.3.4.5", true]
  ] as const) {
    const parsed = CertificateRevocationList.fromBER(crl);
    parsed.revokedCertificates![0].crlEntryExtensions = new Extensions({
      extensions: [
        new Extension({
          extnID,
          critical,
          extnValue: Uint8Array.of(0x05, 0x00).buffer
        })
      ]
    });
    const result = await validateCrl({
      certificate,
      issuerCertificate,
      crl: new Uint8Array(parsed.toSchema(true).toBER(false)),
      checkDate
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, "UNSUPPORTED_CRL");
  }
});

test("rejects duplicate or malformed supported CRL extensions", async () => {
  for (const duplicate of [true, false]) {
    const parsed = CertificateRevocationList.fromBER(crl);
    if (duplicate) {
      parsed.crlExtensions!.extensions.push(
        parsed.crlExtensions!.extensions.find(
          (entry) => entry.extnID === id_CRLNumber
        )!
      );
    } else {
      parsed.crlExtensions!.extensions.find(
        (entry) => entry.extnID === id_CRLNumber
      )!.extnValue = new OctetString({
        valueHex: Uint8Array.of(0x05, 0x00).buffer
      });
    }
    const result = await validateCrl({
      certificate,
      issuerCertificate,
      crl: new Uint8Array(parsed.toSchema(true).toBER(false)),
      checkDate
    });
    assert.ok(result.status === "unknown");
    assert.equal(result.code, "INVALID_CRL");
  }
});

test("snapshots certificate, issuer and CRL bytes before worker execution", async () => {
  const inputCertificate = Uint8Array.from(certificate);
  const inputIssuer = Uint8Array.from(issuerCertificate);
  const inputCrl = Uint8Array.from(crl);
  const pending = nativeValidateCrl(
    inputCertificate,
    inputIssuer,
    inputCrl,
    checkDate.getTime()
  );
  inputCertificate.fill(0);
  inputIssuer.fill(0);
  inputCrl.fill(0);
  const result = await pending;
  assert.equal(result.status, "good");
  assert.equal(
    result.thisUpdateMs,
    CertificateRevocationList.fromBER(crl).thisUpdate.value.getTime()
  );
});
