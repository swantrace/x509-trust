import assert from "node:assert/strict";
import { test } from "node:test";
import {
  chainInput,
  goodCrls,
  goodOcsps,
  intermediateCrl,
  intermediateOcsp,
  leafCrl,
  leafOcsp,
  leafRevokedOcsp,
  validators
} from "./helpers/revocation-profile-fixtures.ts";

test("tries each URL for a required mechanism in order and falls back", async () => {
  const calls = { crl: [] as string[], ocsp: [] as string[] };
  const validator = validators({
    requiredEvidence: "any",
    sourceOrder: ["crl"],
    crlResponses: {
      ...goodCrls,
      [leafCrl[0]]: Buffer.from("invalid CRL")
    },
    ocspResponses: goodOcsps,
    ocspLoader: false,
    calls
  });
  const result = await validator.verify({ certificateChain: chainInput });
  assert.equal(result.valid, true);
  assert.deepEqual(
    calls.crl.filter((url) => url.startsWith("http://leaf.test")),
    [leafCrl[0], leafCrl[1]]
  );
  assert.deepEqual(
    calls.crl.filter((url) => url === intermediateCrl),
    [intermediateCrl]
  );
  assert.equal(calls.ocsp.length, 0);
});

test("sourceOrder controls collection order independently of required evidence", async () => {
  const crlFirst = { crl: [] as string[], ocsp: [] as string[] };
  const crlValidator = validators({
    requiredEvidence: "any",
    sourceOrder: ["crl", "ocsp"],
    crlResponses: goodCrls,
    ocspResponses: goodOcsps,
    calls: crlFirst
  });
  assert.equal(
    (await crlValidator.verify({ certificateChain: chainInput })).valid,
    true
  );
  assert.deepEqual(
    new Set(crlFirst.crl),
    new Set([leafCrl[0], intermediateCrl])
  );
  assert.deepEqual(crlFirst.ocsp, []);

  const ocspFirst = { crl: [] as string[], ocsp: [] as string[] };
  const ocspValidator = validators({
    requiredEvidence: "any",
    sourceOrder: ["ocsp", "crl"],
    crlResponses: goodCrls,
    ocspResponses: goodOcsps,
    calls: ocspFirst
  });
  assert.equal(
    (await ocspValidator.verify({ certificateChain: chainInput })).valid,
    true
  );
  assert.deepEqual(
    new Set(ocspFirst.ocsp),
    new Set([leafOcsp, intermediateOcsp])
  );
  assert.deepEqual(ocspFirst.crl, []);
});

test("the first usable source stops collection without claiming later sources agree", async () => {
  const calls = { crl: [] as string[], ocsp: [] as string[] };
  const validator = validators({
    requiredEvidence: "any",
    sourceOrder: ["crl", "ocsp"],
    crlResponses: goodCrls,
    ocspResponses: {
      ...goodOcsps,
      [leafOcsp]: leafRevokedOcsp
    },
    calls
  });
  const result = await validator.verify({ certificateChain: chainInput });
  assert.equal(result.valid, true);
  assert.equal(calls.ocsp.length, 0);
});
