import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { BitString, OctetString } from "asn1js";
import {
  BasicConstraints,
  Extension,
  id_BasicConstraints,
  id_KeyUsage
} from "pkijs";
import { readCertificateDer } from "./helpers/fixtures.ts";
import {
  checkDateMs,
  intermediateDer,
  leafDer,
  mutate,
  prepare,
  rootDer
} from "./helpers/pki-engine-fixtures.ts";

test("prepares a validated path with DER snapshots and revocation targets", async () => {
  const result = await prepare([leafDer, intermediateDer]);
  assert.ok(result.pathValid);
  assert.deepEqual(
    result.certificatePath.map(
      (der) => new X509Certificate(der).fingerprint256
    ),
    [leafDer, intermediateDer, rootDer].map(
      (der) => new X509Certificate(der).fingerprint256
    )
  );
  assert.equal(result.certificates.length, 3);
  assert.deepEqual(result.certificates[0].crlUrls, [
    "http://crl.example.test/intermediate.crl"
  ]);
  assert.deepEqual(result.certificates[1].ocspUrls, [
    "http://ocsp.example.test/root"
  ]);
  assert.ok(result.certificates[0].ocspRequestDer);
  assert.equal(result.certificates[2].issuerDer, undefined);
  assert.deepEqual(result.leafCertificate.uriSubjectAlternativeNames, [
    "https://client.example.org/app"
  ]);
  const facts = result.certificates[0].facts;
  assert.equal(result.leafCertificate.fingerprint256, facts.fingerprint256);
  assert.deepEqual(result.leafCertificate.keyUsages, facts.keyUsages);
  assert.notEqual(result.leafCertificate.keyUsages, facts.keyUsages);
  result.leafCertificate.keyUsages?.push("keyCertSign");
  assert.deepEqual(facts.keyUsages, ["digitalSignature"]);
  const snapshot = result.certificatePath[0];
  const callerBytes = Uint8Array.from(leafDer);
  callerBytes.fill(0);
  assert.notDeepEqual(snapshot, callerBytes);
});

test("accepts a typed-array subview without reading neighbouring bytes", async () => {
  const padded = Buffer.concat([
    Buffer.from([0xde, 0xad]),
    Buffer.from(leafDer),
    Buffer.from([0xbe, 0xef])
  ]);
  const view = padded.subarray(2, 2 + leafDer.byteLength);
  const result = await prepare([view, intermediateDer]);
  assert.ok(result.pathValid);
});

test("rejects trailing DER bytes and oversized chain inputs", async () => {
  const trailing = Buffer.concat([Buffer.from(leafDer), Buffer.from([0])]);
  const result = await prepare([trailing, intermediateDer]);
  assert.equal(result.pathValid, false);
  assert.equal(result.code, "INVALID_CERTIFICATE");

  const tooLong = await prepare(Array.from({ length: 17 }, () => leafDer));
  assert.equal(tooLong.pathValid, false);
  assert.equal(tooLong.code, "INVALID_CERTIFICATE_PATH");
});

test("rejects a path whose issuer is a different CA", async () => {
  const result = await prepare([leafDer, readCertificateDer("untrusted-root")]);
  assert.equal(result.pathValid, false);
  assert.equal(result.code, "INVALID_CERTIFICATE_PATH");
});

test("rejects a trust anchor outside its validity period", async () => {
  const anchor = mutate("root", (certificate) => {
    certificate.notAfter.value = new Date(checkDateMs - 24 * 60 * 60 * 1000);
  });
  const result = await prepare([leafDer, intermediateDer], [anchor]);
  assert.equal(result.pathValid, false);
  assert.equal(result.code, "INVALID_CERTIFICATE_PATH");
});

test("rejects a trust anchor without CA BasicConstraints", async () => {
  const anchor = mutate("root", (certificate) => {
    const constraints = new BasicConstraints({ cA: false });
    const extension = certificate.extensions!.find(
      (entry) => entry.extnID === id_BasicConstraints
    )!;
    extension.parsedValue = constraints;
    extension.extnValue = new OctetString({
      valueHex: constraints.toSchema().toBER(false)
    });
  });
  const result = await prepare([leafDer, intermediateDer], [anchor]);
  assert.equal(result.pathValid, false);
});

test("rejects a trust anchor whose key usage omits keyCertSign", async () => {
  const anchor = mutate("root", (certificate) => {
    const usage = new BitString({
      valueHex: new Uint8Array([0x00]).buffer
    });
    const extension = certificate.extensions!.find(
      (entry) => entry.extnID === id_KeyUsage
    )!;
    extension.parsedValue = usage;
    extension.extnValue = new OctetString({
      valueHex: usage.toBER(false)
    });
  });
  const result = await prepare([leafDer, intermediateDer], [anchor]);
  assert.equal(result.pathValid, false);
});

test("rejects a path that exceeds a trust anchor's pathLenConstraint", async () => {
  const anchor = mutate("root", (certificate) => {
    const constraints = new BasicConstraints({
      cA: true,
      pathLenConstraint: 0
    });
    const extension = certificate.extensions!.find(
      (entry) => entry.extnID === id_BasicConstraints
    )!;
    extension.parsedValue = constraints;
    extension.extnValue = new OctetString({
      valueHex: constraints.toSchema().toBER(false)
    });
  });
  const result = await prepare([leafDer, intermediateDer], [anchor]);
  assert.equal(result.pathValid, false);
  assert.match(result.pathValid ? "" : result.message, /pathLenConstraint/);
});

test("rejects duplicate and unsupported critical extensions", async () => {
  const duplicate = mutate("root", (certificate) => {
    certificate.extensions!.push(certificate.extensions![0]);
  });
  const duplicateResult = await prepare(
    [leafDer, intermediateDer],
    [duplicate]
  );
  assert.equal(duplicateResult.pathValid, false);

  const unknownCritical = mutate("root", (certificate) => {
    certificate.extensions!.push(
      new Extension({
        extnID: "1.2.3.4.5",
        critical: true,
        extnValue: new Uint8Array([0x05, 0x00]).buffer
      })
    );
  });
  const criticalResult = await prepare(
    [leafDer, intermediateDer],
    [unknownCritical]
  );
  assert.equal(criticalResult.pathValid, false);
});
