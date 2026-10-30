import assert from "node:assert/strict";
import { createPublicKey, sign, verify, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BitString, Integer, Utf8String } from "asn1js";
import {
  AttributeTypeAndValue,
  Certificate,
  CertificatePolicies,
  Extension,
  ExtKeyUsage,
  id_CertificatePolicies,
  id_ExtKeyUsage,
  id_SubjectAltName,
  PolicyInformation,
  RelativeDistinguishedNames,
  Time
} from "pkijs";
import {
  extractLeafCertificate,
  keyUsageNames
} from "../src/leaf-certificate.ts";

function readDer(name: string): Uint8Array<ArrayBuffer> {
  const pem = readFileSync(new URL(`./fixtures/${name}.pem`, import.meta.url));
  return Uint8Array.from(new X509Certificate(pem).raw);
}

function extension(oid: string, value: { toSchema(): unknown }): Extension {
  return new Extension({
    extnID: oid,
    critical: false,
    extnValue: (
      value.toSchema() as { toBER(flag?: boolean): ArrayBuffer }
    ).toBER(false),
    parsedValue: value as never
  });
}

async function syntheticCertificate({
  algorithm = "rsa",
  serialHex = [0x01],
  extensions = []
}: {
  algorithm?: "rsa" | "ec";
  serialHex?: number[];
  extensions?: Extension[];
} = {}): Promise<{ der: Uint8Array<ArrayBuffer>; privateKey: unknown }> {
  const keys =
    algorithm === "rsa"
      ? await globalThis.crypto.subtle.generateKey(
          {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
          },
          true,
          ["sign", "verify"]
        )
      : await globalThis.crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"]
        );
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new Integer({
    valueHex: new Uint8Array(serialHex).buffer
  });
  const name = new RelativeDistinguishedNames({
    typesAndValues: [
      new AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new Utf8String({ value: "Synthetic Subject" })
      })
    ]
  });
  certificate.issuer = name;
  certificate.subject = name;
  certificate.notBefore = new Time({
    type: 0,
    value: new Date("2026-01-01T00:00:00Z")
  });
  certificate.notAfter = new Time({
    type: 0,
    value: new Date("2027-01-01T00:00:00Z")
  });
  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
  certificate.extensions = extensions;
  await certificate.sign(keys.privateKey, "SHA-256");
  return {
    der: new Uint8Array(certificate.toSchema(true).toBER(false)),
    privateKey: keys.privateKey
  };
}

test("extracts identity, validity and fingerprint metadata matching Node", () => {
  const der = readDer("leaf");
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

test("returns undefined for absent KU, EKU and policy extensions", async () => {
  const { der } = await syntheticCertificate();
  const leaf = extractLeafCertificate(Certificate.fromBER(der), der);
  assert.equal(leaf.keyUsages, undefined);
  assert.equal(leaf.extendedKeyUsageOids, undefined);
  assert.equal(leaf.certificatePolicyOids, undefined);
  assert.deepEqual(leaf.uriSubjectAlternativeNames, []);
});

test("preserves multi-valued EKU and certificate policy OIDs", async () => {
  const { der } = await syntheticCertificate({
    extensions: [
      extension(
        id_ExtKeyUsage,
        new ExtKeyUsage({
          keyPurposes: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.9"]
        })
      ),
      extension(
        id_CertificatePolicies,
        new CertificatePolicies({
          certificatePolicies: [
            new PolicyInformation({ policyIdentifier: "1.2.3.4" }),
            new PolicyInformation({ policyIdentifier: "1.2.3.5" })
          ]
        })
      )
    ]
  });
  const leaf = extractLeafCertificate(Certificate.fromBER(der), der);
  assert.deepEqual(leaf.extendedKeyUsageOids, [
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.5.5.7.3.9"
  ]);
  assert.deepEqual(leaf.certificatePolicyOids, ["1.2.3.4", "1.2.3.5"]);
});

test("rejects malformed or duplicate leaf extensions instead of hiding them", () => {
  const der = readDer("leaf");
  const certificate = Certificate.fromBER(der);
  const san = certificate.extensions!.find(
    (entry) => entry.extnID === id_SubjectAltName
  )!;
  certificate.extensions!.push(san);
  assert.throws(
    () => extractLeafCertificate(certificate, der),
    /Duplicate subject alternative name/
  );

  const malformed = Certificate.fromBER(der);
  malformed.extensions!.find(
    (entry) => entry.extnID === id_SubjectAltName
  )!.parsedValue = new BitString({ valueHex: new Uint8Array([0]).buffer });
  assert.throws(
    () => extractLeafCertificate(malformed, der),
    /Invalid subject alternative name/
  );
});

test("reads key usage as named bits rather than OIDs", () => {
  const der = readDer("leaf");
  assert.deepEqual(keyUsageNames(Certificate.fromBER(der)), [
    "digitalSignature"
  ]);
});
