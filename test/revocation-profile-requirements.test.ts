import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustValidator, ProfileError } from "../src/index.ts";
import {
  chain,
  chainInput,
  goodCrls,
  goodOcsps,
  intermediateCrl,
  intermediateOcsp,
  leafCrl,
  leafOcsp,
  profile,
  validators
} from "./helpers/revocation-profile-fixtures.ts";

test("requiredEvidence=crl needs CRL success even when OCSP is good", async () => {
  const calls = { crl: [] as string[], ocsp: [] as string[] };
  const validator = validators({
    requiredEvidence: "crl",
    sourceOrder: ["ocsp", "crl"],
    crlResponses: goodCrls,
    ocspResponses: goodOcsps,
    calls
  });
  const result = await validator.verify({ certificateChain: chainInput });
  assert.equal(result.valid, true);
  assert.deepEqual(
    result.evidence.map((entry) => entry.mechanism),
    ["crl", "crl"]
  );
  assert.deepEqual(new Set(calls.ocsp), new Set([leafOcsp, intermediateOcsp]));
  assert.deepEqual(new Set(calls.crl), new Set([leafCrl[0], intermediateCrl]));

  const ocspOnlyCalls = { crl: [] as string[], ocsp: [] as string[] };
  const ocspOnly = validators({
    requiredEvidence: "crl",
    sourceOrder: ["ocsp", "crl"],
    crlResponses: {
      [leafCrl[0]]: Buffer.from("invalid CRL"),
      [leafCrl[1]]: Buffer.from("invalid CRL"),
      [intermediateCrl]: Buffer.from("invalid CRL")
    },
    ocspResponses: goodOcsps,
    calls: ocspOnlyCalls
  });
  const ocspOnlyResult = await ocspOnly.verify({
    certificateChain: chainInput
  });
  assert.equal(ocspOnlyResult.valid, false);
  assert.equal(ocspOnlyResult.code, "REVOCATION_STATUS_UNKNOWN");
  assert.equal(ocspOnlyResult.evidence, undefined);
});

test("registered profile rejects a disabled required loader at configuration time", () => {
  assert.throws(
    () =>
      createTrustValidator({
        trustAnchors: [chain.root.der],
        profile: profile("crl", ["ocsp", "crl"]),
        crlLoader: false
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      return true;
    }
  );
  assert.throws(
    () =>
      createTrustValidator({
        trustAnchors: [chain.root.der],
        profile: profile("ocsp", ["ocsp"]),
        ocspLoader: false
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      return true;
    }
  );
});

test("requiredEvidence=ocsp needs OCSP success even when CRLs are good", async () => {
  const calls = { crl: [] as string[], ocsp: [] as string[] };
  const invalidOcsp = validators({
    requiredEvidence: "ocsp",
    sourceOrder: ["crl", "ocsp"],
    crlResponses: goodCrls,
    ocspResponses: {
      [leafOcsp]: Buffer.from("invalid OCSP response"),
      [intermediateOcsp]: Buffer.from("invalid OCSP response")
    },
    calls
  });
  const invalid = await invalidOcsp.verify({ certificateChain: chainInput });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.code, "REVOCATION_STATUS_UNKNOWN");

  const validCalls = { crl: [] as string[], ocsp: [] as string[] };
  const valid = validators({
    requiredEvidence: "ocsp",
    sourceOrder: ["crl", "ocsp"],
    crlResponses: goodCrls,
    ocspResponses: goodOcsps,
    calls: validCalls
  });
  assert.equal(
    (await valid.verify({ certificateChain: chainInput })).valid,
    true
  );
  assert.deepEqual(
    new Set(validCalls.crl),
    new Set([leafCrl[0], intermediateCrl])
  );
  assert.deepEqual(
    new Set(validCalls.ocsp),
    new Set([leafOcsp, intermediateOcsp])
  );
});
