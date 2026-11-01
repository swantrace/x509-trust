import assert from "node:assert/strict";
import { test } from "node:test";
import { readCrl, readOcsp } from "./helpers/fixtures.ts";
import {
  checkDateMs,
  engine,
  intermediateDer,
  leafDer
} from "./helpers/pki-engine-fixtures.ts";

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

  const response = readOcsp("good");
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
  const response = readOcsp("good");
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
  const response = Uint8Array.from(readOcsp("good"));
  const input = { certificateDer, issuerDer, checkDateMs };
  const crlResult = engine.validateCrl({ ...input, crl });
  const ocspResult = engine.validateOcsp({ ...input, response });
  for (const bytes of [certificateDer, issuerDer, crl, response]) bytes.fill(0);
  assert.equal((await crlResult).status, "good");
  assert.equal((await ocspResult).status, "good");
});
