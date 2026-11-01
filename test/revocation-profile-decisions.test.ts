import assert from "node:assert/strict";
import { test } from "node:test";
import { type RevocationMechanism } from "../src/index.ts";
import {
  chainInput,
  goodCrls,
  goodOcsps,
  intermediateCrl,
  intermediateOcsp,
  intermediateRevokedOcsp,
  leafCrl,
  leafOcsp,
  leafRevokedOcsp,
  validators
} from "./helpers/revocation-profile-fixtures.ts";

test("requiredEvidence=both requires both mechanisms and reports both summaries", async () => {
  const calls = { crl: [] as string[], ocsp: [] as string[] };
  const validator = validators({
    requiredEvidence: "both",
    sourceOrder: ["ocsp", "crl"],
    crlResponses: goodCrls,
    ocspResponses: goodOcsps,
    calls
  });
  const result = await validator.verify({ certificateChain: chainInput });
  assert.equal(result.valid, true);
  assert.equal(result.findings.length, 2);
  for (const finding of result.findings) {
    assert.deepEqual(
      {
        crl: finding.revocation.crl.map((entry) => entry.status),
        ocsp: finding.revocation.ocsp.map((entry) => entry.status)
      },
      { crl: ["good"], ocsp: ["good"] }
    );
  }
  assert.deepEqual(
    result.evidence.map(({ certificateIndex, mechanism }) => ({
      certificateIndex,
      mechanism
    })),
    [
      { certificateIndex: 0, mechanism: "ocsp" },
      { certificateIndex: 0, mechanism: "crl" },
      { certificateIndex: 1, mechanism: "ocsp" },
      { certificateIndex: 1, mechanism: "crl" }
    ]
  );

  const missingCrl = validators({
    requiredEvidence: "both",
    sourceOrder: ["ocsp", "crl"],
    crlResponses: {
      [leafCrl[0]]: Buffer.from("invalid CRL"),
      [leafCrl[1]]: Buffer.from("invalid CRL"),
      [intermediateCrl]: Buffer.from("invalid CRL")
    },
    ocspResponses: goodOcsps,
    calls: { crl: [], ocsp: [] }
  });
  const missing = await missingCrl.verify({ certificateChain: chainInput });
  assert.equal(missing.valid, false);
  assert.equal(missing.code, "REVOCATION_STATUS_UNKNOWN");
});

test("an authenticated revoked response wins over good evidence from the other mechanism", async () => {
  for (const sourceOrder of [
    ["ocsp", "crl"],
    ["crl", "ocsp"]
  ] as RevocationMechanism[][]) {
    const validator = validators({
      requiredEvidence: "both",
      sourceOrder,
      crlResponses: goodCrls,
      ocspResponses: {
        ...goodOcsps,
        [leafOcsp]: leafRevokedOcsp
      },
      calls: { crl: [], ocsp: [] }
    });
    const result = await validator.verify({ certificateChain: chainInput });
    assert.equal(result.valid, false);
    assert.equal(result.code, "CERTIFICATE_REVOKED");
    assert.equal(result.certificateIndex, 0);
    assert.deepEqual(
      result.evidence?.map(({ mechanism, status }) => ({ mechanism, status })),
      [{ mechanism: "ocsp", status: "revoked" }]
    );
  }
});

test("a good leaf cannot mask a revoked intermediate", async () => {
  const validator = validators({
    requiredEvidence: "any",
    sourceOrder: ["ocsp"],
    crlResponses: goodCrls,
    ocspResponses: {
      ...goodOcsps,
      [intermediateOcsp]: intermediateRevokedOcsp
    },
    calls: { crl: [], ocsp: [] }
  });
  const result = await validator.verify({ certificateChain: chainInput });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(result.certificateIndex, 1);
});
