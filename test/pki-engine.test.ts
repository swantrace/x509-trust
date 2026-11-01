import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BitString, OctetString } from "asn1js";
import {
  BasicConstraints,
  Certificate,
  Extension,
  id_BasicConstraints,
  id_KeyUsage
} from "pkijs";
import { inlinePkiEngine } from "../src/engine/pki-engine.ts";

function readPem(name: string): string {
  return readFileSync(
    new URL(`./fixtures/${name}.pem`, import.meta.url),
    "utf8"
  );
}

function readDer(name: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(new X509Certificate(readPem(name)).raw);
}

function readCrl(name: string): Uint8Array<ArrayBuffer> {
  const pem = readFileSync(
    new URL(`./fixtures/crl/${name}.crl.pem`, import.meta.url),
    "utf8"
  );
  return Uint8Array.from(
    Buffer.from(pem.replace(/-----[^\n]+-----/g, ""), "base64")
  );
}

function mutate(
  name: string,
  change: (certificate: Certificate) => void
): Uint8Array {
  const certificate = Certificate.fromBER(readDer(name));
  change(certificate);
  return new Uint8Array(certificate.toSchema(true).toBER(false));
}

const rootDer = readDer("root");
const intermediateDer = readDer("intermediate");
const leafDer = readDer("leaf");
const checkDateMs = Date.parse(
  readFileSync(
    new URL("./fixtures/validation-time.txt", import.meta.url),
    "utf8"
  ).trim()
);
const engine = inlinePkiEngine;

async function prepare(
  certificateChain: Uint8Array[],
  trustAnchors: Uint8Array[] = [rootDer]
) {
  return engine.preparePath({ certificateChain, trustAnchors, checkDateMs });
}

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
  const result = await prepare([leafDer, readDer("untrusted-root")]);
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

test("validates CRL and OCSP DER snapshots and rejects trailing bytes", async () => {
  const crl = readCrl("intermediate-revoked");
  const padded = Buffer.concat([Buffer.from([0]), Buffer.from(crl)]);
  const crlView = padded.subarray(1);
  assert.equal(
    (
      await engine.validateCrl({
        certificateDer: leafDer,
        issuerDer: intermediateDer,
        crl: crlView,
        checkDateMs
      })
    ).status,
    "good"
  );
  const trailing = Buffer.concat([Buffer.from(crl), Buffer.from([0])]);
  const trailingCrl = await engine.validateCrl({
    certificateDer: leafDer,
    issuerDer: intermediateDer,
    crl: trailing,
    checkDateMs
  });
  assert.equal(trailingCrl.status, "unknown");
  assert.equal(
    trailingCrl.status === "unknown" && trailingCrl.code,
    "INVALID_CRL"
  );

  const response = readFileSync(
    new URL("./fixtures/ocsp/good.der", import.meta.url)
  );
  assert.equal(
    (
      await engine.validateOcsp({
        certificateDer: leafDer,
        issuerDer: intermediateDer,
        response: Buffer.concat([Buffer.from([1]), response]).subarray(1),
        checkDateMs
      })
    ).status,
    "good"
  );
  const trailingResponse = await engine.validateOcsp({
    certificateDer: leafDer,
    issuerDer: intermediateDer,
    response: Buffer.concat([response, Buffer.from([0])]),
    checkDateMs
  });
  assert.equal(trailingResponse.status, "unknown");
  assert.equal(
    trailingResponse.status === "unknown" && trailingResponse.code,
    "INVALID_OCSP_RESPONSE"
  );
});

test("revocation inputs retain DER size, completeness and timestamp checks", async () => {
  const crl = readCrl("intermediate-revoked");
  const response = readFileSync(
    new URL("./fixtures/ocsp/good.der", import.meta.url)
  );
  for (const overrides of [
    { certificateDer: new Uint8Array() },
    { certificateDer: new Uint8Array(1024 * 1024 + 1) },
    { certificateDer: Buffer.concat([leafDer, Buffer.from([0])]) },
    { issuerDer: Buffer.concat([intermediateDer, Buffer.from([0])]) },
    { checkDateMs: NaN },
    { checkDateMs: Infinity },
    { checkDateMs: Number.MAX_SAFE_INTEGER }
  ]) {
    const input = {
      certificateDer: leafDer,
      issuerDer: intermediateDer,
      checkDateMs,
      ...overrides
    };
    const crlResult = await engine.validateCrl({ ...input, crl });
    const ocspResult = await engine.validateOcsp({ ...input, response });
    assert.equal(crlResult.status, "unknown");
    assert.equal(
      crlResult.status === "unknown" && crlResult.code,
      "INVALID_CRL"
    );
    assert.equal(ocspResult.status, "unknown");
    assert.equal(
      ocspResult.status === "unknown" && ocspResult.code,
      "INVALID_OCSP_RESPONSE"
    );
  }
  const oversized = new Uint8Array(1024 * 1024 + 1);
  const input = {
    certificateDer: leafDer,
    issuerDer: intermediateDer,
    checkDateMs
  };
  assert.equal(
    (await engine.validateCrl({ ...input, crl: oversized })).status,
    "unknown"
  );
  assert.equal(
    (await engine.validateOcsp({ ...input, response: oversized })).status,
    "unknown"
  );
});

test("revocation validation snapshots caller bytes before asynchronous work", async () => {
  const certificateDer = Uint8Array.from(leafDer);
  const issuerDer = Uint8Array.from(intermediateDer);
  const crl = readCrl("intermediate-revoked");
  const response = Uint8Array.from(
    readFileSync(new URL("./fixtures/ocsp/good.der", import.meta.url))
  );
  const input = { certificateDer, issuerDer, checkDateMs };
  const crlResult = engine.validateCrl({ ...input, crl });
  const ocspResult = engine.validateOcsp({ ...input, response });
  for (const bytes of [certificateDer, issuerDer, crl, response]) bytes.fill(0);
  assert.equal((await crlResult).status, "good");
  assert.equal((await ocspResult).status, "good");
});
