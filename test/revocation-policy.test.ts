import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createTrustValidator,
  PolicyError,
  type RequiredEvidence,
  type RevocationMechanism,
  type TrustPolicyInput
} from "../src/index.ts";
import {
  createCrl,
  createOcspResponse,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

const leafCrl = ["http://leaf.test/one.crl", "http://leaf.test/two.crl"];
const leafOcsp = "http://leaf.test/ocsp";
const intermediateCrl = "http://intermediate.test/root.crl";
const intermediateOcsp = "http://intermediate.test/ocsp";
const checkDate = new Date("2026-10-15T00:00:00Z");
const now = () => checkDate.getTime();

const chain = await createSyntheticChain({
  intermediate: {
    crlUrls: [intermediateCrl],
    ocspUrls: [intermediateOcsp]
  },
  leaf: {
    crlUrls: leafCrl,
    ocspUrls: [leafOcsp]
  }
});
const leafGoodCrl = await createCrl(chain.intermediate, []);
const intermediateGoodCrl = await createCrl(chain.root, []);
const leafGoodOcsp = await createOcspResponse(
  chain.intermediate,
  chain.leaf,
  "good"
);
const intermediateGoodOcsp = await createOcspResponse(
  chain.root,
  chain.intermediate,
  "good"
);
const leafRevokedOcsp = await createOcspResponse(
  chain.intermediate,
  chain.leaf,
  "revoked"
);
const intermediateRevokedOcsp = await createOcspResponse(
  chain.root,
  chain.intermediate,
  "revoked"
);
const chainInput = [chain.leaf.der, chain.intermediate.der];

function policy(
  requiredEvidence: RequiredEvidence,
  sourceOrder: RevocationMechanism[]
): TrustPolicyInput {
  return {
    id: `test:${requiredEvidence}`,
    version: 1,
    source: "synthetic policy",
    anchorSetId: "synthetic:root",
    revocation: { requiredEvidence, sourceOrder }
  };
}

function validators({
  requiredEvidence,
  sourceOrder,
  crlResponses,
  ocspResponses,
  loadCrl = true,
  loadOcsp = true,
  calls
}: {
  requiredEvidence: RequiredEvidence;
  sourceOrder: RevocationMechanism[];
  crlResponses: Record<string, Uint8Array>;
  ocspResponses: Record<string, Uint8Array>;
  loadCrl?: boolean;
  loadOcsp?: boolean;
  calls: { crl: string[]; ocsp: string[] };
}) {
  return createTrustValidator({
    trustAnchors: [chain.root.der],
    policy: policy(requiredEvidence, sourceOrder),
    now,
    loadCrl:
      loadCrl === false
        ? false
        : async (url) => {
            calls.crl.push(url);
            const response = crlResponses[url];
            if (!response) throw new Error(`No CRL for ${url}`);
            return response;
          },
    loadOcsp:
      loadOcsp === false
        ? false
        : async ({ url }) => {
            calls.ocsp.push(url);
            const response = ocspResponses[url];
            if (!response) throw new Error(`No OCSP response for ${url}`);
            return response;
          }
  });
}

const goodCrls = {
  [leafCrl[0]]: leafGoodCrl,
  [leafCrl[1]]: leafGoodCrl,
  [intermediateCrl]: intermediateGoodCrl
};
const goodOcsps = {
  [leafOcsp]: leafGoodOcsp,
  [intermediateOcsp]: intermediateGoodOcsp
};

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
    loadOcsp: false,
    calls
  });
  const result = await validator.verify({ certificateChain: chainInput });
  assert.equal(result.valid, true);
  assert.deepEqual(calls.crl, [leafCrl[0], leafCrl[1], intermediateCrl]);
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
  assert.deepEqual(crlFirst.crl, [leafCrl[0], intermediateCrl]);
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
  assert.deepEqual(ocspFirst.ocsp, [leafOcsp, intermediateOcsp]);
  assert.deepEqual(ocspFirst.crl, []);
});

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
  assert.deepEqual(calls.ocsp, [leafOcsp, intermediateOcsp]);
  assert.deepEqual(calls.crl, [leafCrl[0], intermediateCrl]);

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

test("registered policy rejects a disabled required loader at configuration time", () => {
  assert.throws(
    () =>
      createTrustValidator({
        trustAnchors: [chain.root.der],
        policy: policy("crl", ["ocsp", "crl"]),
        loadCrl: false
      }),
    (error: unknown) => {
      assert.ok(error instanceof PolicyError);
      assert.equal(error.code, "INVALID_POLICY");
      return true;
    }
  );
  assert.throws(
    () =>
      createTrustValidator({
        trustAnchors: [chain.root.der],
        policy: policy("ocsp", ["ocsp"]),
        loadOcsp: false
      }),
    (error: unknown) => {
      assert.ok(error instanceof PolicyError);
      assert.equal(error.code, "INVALID_POLICY");
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
  assert.deepEqual(validCalls.crl, [leafCrl[0], intermediateCrl]);
  assert.deepEqual(validCalls.ocsp, [leafOcsp, intermediateOcsp]);
});

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
