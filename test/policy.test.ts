import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  compileTrustPolicy,
  createTrustValidator,
  DEFAULT_TRUST_POLICY,
  PolicyError,
  type TrustPolicyInput,
  trustPolicyCapabilities
} from "../src/index.ts";

function readCertificate(name: string): string {
  return readFileSync(
    new URL(`./fixtures/${name}.pem`, import.meta.url),
    "utf8"
  );
}

function readCrl(name: string) {
  const pem = readFileSync(
    new URL(`./fixtures/crl/${name}.crl.pem`, import.meta.url),
    "utf8"
  );
  return Buffer.from(pem.replace(/-----[^\n]+-----/g, ""), "base64");
}

const checkDate = new Date(
  readFileSync(
    new URL("./fixtures/validation-time.txt", import.meta.url),
    "utf8"
  ).trim()
);
const now = () => checkDate.getTime();
const root = readCertificate("root");
const intermediate = readCertificate("intermediate");
const leaf = readCertificate("leaf");

function validPolicy(
  overrides: Partial<TrustPolicyInput> = {}
): TrustPolicyInput {
  return {
    id: "test:policy",
    version: 1,
    source: "test policy",
    anchorSetId: "test:anchors",
    revocation: {
      requiredEvidence: "any",
      sourceOrder: ["ocsp", "crl"]
    },
    ...overrides
  };
}

function expectPolicyError(
  fn: () => unknown,
  code: "INVALID_POLICY" | "UNSUPPORTED_POLICY"
) {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof PolicyError);
    assert.equal(error.code, code);
    return true;
  });
}

test("compiles the strict default policy and freezes every level", () => {
  const policy = compileTrustPolicy();
  assert.equal(policy.id, DEFAULT_TRUST_POLICY.id);
  assert.equal(policy.revocation.requiredEvidence, "any");
  assert.deepEqual(policy.revocation.sourceOrder, ["ocsp", "crl"]);
  assert.equal(policy.revocation.onUnknown, "reject");
  assert.equal(policy.revocation.scope, "non-anchor-chain");
  assert.equal(policy.revocation.requireNextUpdate, true);
  assert.equal(policy.revocation.clockSkewMs, 0);
  assert.ok(Object.isFrozen(policy));
  assert.ok(Object.isFrozen(policy.revocation));
  assert.ok(Object.isFrozen(policy.revocation.sourceOrder));
});

test("copies caller data so later mutations cannot change a compiled policy", () => {
  const input = validPolicy({
    rules: {
      leafKeyUsage: ["digitalSignature"],
      requiredLeafPolicyOids: ["1.2.3.4"]
    }
  });
  const policy = compileTrustPolicy(input);
  input.revocation!.sourceOrder = ["crl"];
  (input.rules!.leafKeyUsage as string[]).push("keyCertSign");
  (input.rules!.requiredLeafPolicyOids as string[]).push("1.2.3.5");
  assert.deepEqual(policy.revocation.sourceOrder, ["ocsp", "crl"]);
  assert.deepEqual(policy.rules?.leafKeyUsage, ["digitalSignature"]);
  assert.deepEqual(policy.rules?.requiredLeafPolicyOids, ["1.2.3.4"]);
  assert.throws(() => {
    (policy.revocation.sourceOrder as RevocationMechanism[]).push("crl");
  }, TypeError);
});

type RevocationMechanism = "crl" | "ocsp";

test("rejects unknown fields and malformed policy identity", () => {
  expectPolicyError(
    () => compileTrustPolicy({ ...validPolicy(), unexpected: true } as never),
    "INVALID_POLICY"
  );
  expectPolicyError(
    () =>
      compileTrustPolicy({
        ...validPolicy(),
        revocation: { requiredEvidence: "any", unknown: true }
      } as never),
    "INVALID_POLICY"
  );
  expectPolicyError(
    () =>
      compileTrustPolicy({
        ...validPolicy(),
        rules: { unknownRule: true }
      } as never),
    "INVALID_POLICY"
  );
  for (const overrides of [
    { id: "" },
    { version: 0 },
    { version: 1.5 },
    { source: " " },
    { anchorSetId: "" }
  ]) {
    expectPolicyError(
      () => compileTrustPolicy({ ...validPolicy(), ...overrides }),
      "INVALID_POLICY"
    );
  }
});

test("rejects duplicate or unsupported source orders that miss required evidence", () => {
  for (const sourceOrder of [[], ["ocsp", "ocsp"], ["dns"]]) {
    expectPolicyError(
      () =>
        compileTrustPolicy({
          ...validPolicy(),
          revocation: { requiredEvidence: "any", sourceOrder }
        } as never),
      sourceOrder[0] === "dns" ? "UNSUPPORTED_POLICY" : "INVALID_POLICY"
    );
  }
  expectPolicyError(
    () =>
      compileTrustPolicy({
        ...validPolicy(),
        revocation: { requiredEvidence: "crl", sourceOrder: ["ocsp"] }
      }),
    "INVALID_POLICY"
  );
  expectPolicyError(
    () =>
      compileTrustPolicy({
        ...validPolicy(),
        revocation: { requiredEvidence: "both", sourceOrder: ["crl"] }
      }),
    "INVALID_POLICY"
  );
  const both = compileTrustPolicy({
    ...validPolicy(),
    revocation: { requiredEvidence: "both", sourceOrder: ["ocsp", "crl"] }
  });
  assert.deepEqual(both.revocation.sourceOrder, ["ocsp", "crl"]);
});

test("rejects mandatory capabilities that are not implemented", () => {
  const cases: Array<Partial<TrustPolicyInput["revocation"]>> = [
    { requiredEvidence: "dns" as never },
    { onUnknown: "allow" as never },
    { scope: "leaf-only" as never },
    { requireNextUpdate: false as never },
    { clockSkewMs: 1000 as never }
  ];
  for (const revocation of cases) {
    expectPolicyError(
      () =>
        compileTrustPolicy({
          ...validPolicy(),
          revocation: {
            ...validPolicy().revocation,
            ...revocation
          }
        }),
      "UNSUPPORTED_POLICY"
    );
  }
});

test("validates rule values, OIDs and registered rule names", () => {
  for (const rules of [
    { leafKeyUsage: [] },
    { leafExtendedKeyUsage: [] },
    { requiredLeafPolicyOids: [] },
    { leafKeyUsage: ["notAUsage"] },
    { leafExtendedKeyUsage: ["not-an-oid"] },
    { requiredLeafPolicyOids: ["1.2.3."] },
    { maxPathDepth: 0 },
    { maxPathDepth: 1.5 }
  ]) {
    expectPolicyError(
      () =>
        compileTrustPolicy({
          ...validPolicy(),
          rules: rules as never
        }),
      (rules as { leafKeyUsage?: string[] }).leafKeyUsage?.[0] === "notAUsage"
        ? "UNSUPPORTED_POLICY"
        : "INVALID_POLICY"
    );
  }
  expectPolicyError(
    () =>
      compileTrustPolicy({
        ...validPolicy(),
        rules: { requiredRuleNames: ["unregistered"] }
      }),
    "UNSUPPORTED_POLICY"
  );
  const policy = compileTrustPolicy(
    {
      ...validPolicy(),
      rules: { requiredRuleNames: ["community-check"] }
    },
    { registeredRuleNames: ["community-check"] }
  );
  assert.deepEqual(policy.rules?.requiredRuleNames, ["community-check"]);
});

test("exposes the supported capability catalog without claiming unimplemented semantics", () => {
  assert.deepEqual(trustPolicyCapabilities.requiredEvidence, [
    "any",
    "crl",
    "ocsp",
    "both"
  ]);
  assert.equal(
    trustPolicyCapabilities.unsupported.delegatedOcsp.length > 0,
    true
  );
});

test("rejects invalid policy configuration before any certificate I/O", async () => {
  let loads = 0;
  const loader = async () => {
    loads++;
    return readCrl("intermediate-revoked");
  };
  expectPolicyError(
    () =>
      createTrustValidator({
        trustAnchors: [root],
        policy: { ...validPolicy(), id: "" },
        loadCrl: loader
      }),
    "INVALID_POLICY"
  );
  expectPolicyError(
    () =>
      createTrustValidator({
        trustAnchors: [root],
        policy: validPolicy({
          revocation: { requiredEvidence: "both", sourceOrder: ["ocsp"] }
        }),
        loadCrl: loader
      }),
    "INVALID_POLICY"
  );
  assert.equal(loads, 0);
});

test("a valid strict policy still rejects invalid paths and authenticated revocation", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    policy: validPolicy(),
    now,
    loadOcsp: false,
    async loadCrl(url) {
      return url.endsWith("/root.crl")
        ? readCrl("root")
        : readCrl("intermediate-revoked");
    }
  });
  const untrustedValidator = createTrustValidator({
    trustAnchors: [readCertificate("untrusted-root")],
    policy: validPolicy(),
    now,
    loadOcsp: false,
    loadCrl: async () => readCrl("intermediate-revoked")
  });
  const untrusted = await untrustedValidator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(untrusted.valid, false);
  assert.equal(untrusted.code, "INVALID_CERTIFICATE_PATH");
  assert.equal(untrusted.policyId, "test:policy");

  const revoked = await validator.verify({
    certificateChain: [readCertificate("revoked-leaf"), intermediate]
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
  assert.equal(revoked.policyVersion, 1);
});

test("returns the selected policy identity on success", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    policy: validPolicy({ id: "test:policy:success", version: 7 }),
    now,
    loadOcsp: false,
    async loadCrl(url) {
      return url.endsWith("/root.crl")
        ? readCrl("root")
        : readCrl("intermediate-clean");
    }
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, true);
  assert.equal(result.policyId, "test:policy:success");
  assert.equal(result.policyVersion, 7);
  assert.equal(
    result.leafCertificate.fingerprint256,
    new X509Certificate(leaf).fingerprint256
  );
});
