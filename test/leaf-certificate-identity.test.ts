import assert from "node:assert/strict";
import { createPublicKey, sign, verify, X509Certificate } from "node:crypto";
import { test } from "node:test";
import { Certificate } from "pkijs";
import { extractLeafCertificate } from "../src/engine/leaf-certificate.ts";
import { getUriSubjectAlternativeNames } from "../src/index.ts";
import { readCertificate, readCertificateDer } from "./helpers/fixtures.ts";
import { syntheticCertificate } from "./helpers/leaf-certificate-fixtures.ts";

test("reads URI SANs from PEM, DER and parsed certificates through the public API", () => {
  const pem = readCertificate("leaf");
  const der = readCertificateDer("leaf");
  for (const input of [pem, der, Certificate.fromBER(der)]) {
    assert.deepEqual(getUriSubjectAlternativeNames(input), [
      "https://client.example.org/app"
    ]);
  }
});

test("extracts identity, validity and fingerprint metadata matching Node", () => {
  const der = readCertificateDer("leaf");
  const nodeCertificate = new X509Certificate(der);
  const leaf = extractLeafCertificate(Certificate.fromBER(der), der);

  assert.equal(leaf.fingerprint256, nodeCertificate.fingerprint256);
  assert.equal(leaf.serialNumber, "1000");
  assert.equal(leaf.notBeforeMs, Date.parse(nodeCertificate.validFrom));
  assert.equal(leaf.notAfterMs, Date.parse(nodeCertificate.validTo));
  assert.equal(leaf.subject, nodeCertificate.subject);
  assert.equal(leaf.issuer, nodeCertificate.issuer);
  assert.deepEqual(leaf.uriSubjectAlternativeNames, [
    "https://client.example.org/app"
  ]);
  assert.deepEqual(leaf.keyUsages, ["digitalSignature"]);
  assert.equal(leaf.extendedKeyUsageOids, undefined);
  assert.equal(leaf.certificatePolicyOids, undefined);
  assert.deepEqual(leaf.der, der);
});

test("extracts a sign-padded serial number without its padding byte", async () => {
  const { der } = await syntheticCertificate({ serialHex: [0x00, 0xab] });
  const leaf = extractLeafCertificate(Certificate.fromBER(der), der);
  assert.equal(leaf.serialNumber, "AB");
});

for (const algorithm of ["rsa", "ec"] as const) {
  test(`extracts an importable ${algorithm.toUpperCase()} SPKI that verifies a signature`, async () => {
    const { der, privateKey } = await syntheticCertificate({ algorithm });
    const leaf = extractLeafCertificate(Certificate.fromBER(der), der);
    const publicKey = createPublicKey({
      key: Buffer.from(leaf.publicKeySpkiDer),
      format: "der",
      type: "spki"
    });
    const data = Buffer.from("independent payload");
    const signature = sign("sha256", data, privateKey as never);
    assert.equal(verify("sha256", data, publicKey, signature), true);
  });
}
