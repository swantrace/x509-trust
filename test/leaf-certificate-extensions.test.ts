import assert from "node:assert/strict";
import { test } from "node:test";
import { BitString } from "asn1js";
import {
  Certificate,
  CertificatePolicies,
  ExtKeyUsage,
  id_CertificatePolicies,
  id_ExtKeyUsage,
  id_SubjectAltName,
  PolicyInformation
} from "pkijs";
import {
  extractLeafCertificate,
  keyUsageNames
} from "../src/engine/leaf-certificate.ts";
import { readCertificateDer } from "./helpers/fixtures.ts";
import {
  extension,
  syntheticCertificate
} from "./helpers/leaf-certificate-fixtures.ts";

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
  const der = readCertificateDer("leaf");
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
  const der = readCertificateDer("leaf");
  assert.deepEqual(keyUsageNames(Certificate.fromBER(der)), [
    "digitalSignature"
  ]);
});
