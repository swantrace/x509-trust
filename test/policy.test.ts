import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  compileValidationProfile,
  createTrustValidator,
  DEFAULT_VALIDATION_PROFILE,
  ProfileError,
  type ValidationProfileInput
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
  overrides: Partial<ValidationProfileInput> = {}
): ValidationProfileInput {
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

function expectProfileError(
  fn: () => unknown,
  code: "INVALID_PROFILE" | "UNSUPPORTED_PROFILE"
) {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof ProfileError);
    assert.equal(error.code, code);
    return true;
  });
}

test("compiles the strict default policy and freezes every level", () => {
  const policy = compileValidationProfile();
  assert.equal(policy.id, DEFAULT_VALIDATION_PROFILE.id);
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
      requiredCertificatePolicyOids: ["1.2.3.4"]
    }
  });
  const policy = compileValidationProfile(input);
  input.revocation!.sourceOrder = ["crl"];
  (input.rules!.leafKeyUsage as string[]).push("keyCertSign");
  (input.rules!.requiredCertificatePolicyOids as string[]).push("1.2.3.5");
  assert.deepEqual(policy.revocation.sourceOrder, ["ocsp", "crl"]);
  assert.deepEqual(policy.rules?.leafKeyUsage, ["digitalSignature"]);
  assert.deepEqual(policy.rules?.requiredCertificatePolicyOids, ["1.2.3.4"]);
  assert.throws(() => {
    (policy.revocation.sourceOrder as RevocationMechanism[]).push("crl");
  }, TypeError);
});

type RevocationMechanism = "crl" | "ocsp";

test("rejects unknown fields and malformed policy identity", () => {
  expectProfileError(
    () =>
      compileValidationProfile({ ...validPolicy(), unexpected: true } as never),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validPolicy(),
        revocation: { requiredEvidence: "any", unknown: true }
      } as never),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validPolicy(),
        rules: { unknownRule: true }
      } as never),
    "INVALID_PROFILE"
  );
  for (const overrides of [
    { id: "" },
    { version: 0 },
    { version: 1.5 },
    { source: " " },
    { anchorSetId: "" }
  ]) {
    expectProfileError(
      () => compileValidationProfile({ ...validPolicy(), ...overrides }),
      "INVALID_PROFILE"
    );
  }
});

test("rejects duplicate or unsupported source orders that miss required evidence", () => {
  for (const sourceOrder of [[], ["ocsp", "ocsp"], ["dns"]]) {
    expectProfileError(
      () =>
        compileValidationProfile({
          ...validPolicy(),
          revocation: { requiredEvidence: "any", sourceOrder }
        } as never),
      sourceOrder[0] === "dns" ? "UNSUPPORTED_PROFILE" : "INVALID_PROFILE"
    );
  }
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validPolicy(),
        revocation: { requiredEvidence: "crl", sourceOrder: ["ocsp"] }
      }),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validPolicy(),
        revocation: { requiredEvidence: "both", sourceOrder: ["crl"] }
      }),
    "INVALID_PROFILE"
  );
  const both = compileValidationProfile({
    ...validPolicy(),
    revocation: { requiredEvidence: "both", sourceOrder: ["ocsp", "crl"] }
  });
  assert.deepEqual(both.revocation.sourceOrder, ["ocsp", "crl"]);
});

test("rejects unsupported revocation configuration", () => {
  const cases: Array<Partial<ValidationProfileInput["revocation"]>> = [
    { requiredEvidence: "dns" as never },
    { onUnknown: "allow" as never },
    { scope: "leaf-only" as never },
    { requireNextUpdate: false as never },
    { clockSkewMs: 1000 as never }
  ];
  for (const revocation of cases) {
    expectProfileError(
      () =>
        compileValidationProfile({
          ...validPolicy(),
          revocation: {
            ...validPolicy().revocation,
            ...revocation
          }
        }),
      "UNSUPPORTED_PROFILE"
    );
  }
});

test("validates rule values, OIDs and registered rule names", () => {
  for (const rules of [
    { leafKeyUsage: [] },
    { leafExtendedKeyUsage: [] },
    { requiredCertificatePolicyOids: [] },
    { leafKeyUsage: ["notAUsage"] },
    { leafExtendedKeyUsage: ["not-an-oid"] },
    { requiredCertificatePolicyOids: ["1.2.3."] },
    { maxPathDepth: 0 },
    { maxPathDepth: 1.5 }
  ]) {
    expectProfileError(
      () =>
        compileValidationProfile({
          ...validPolicy(),
          rules: rules as never
        }),
      (rules as { leafKeyUsage?: string[] }).leafKeyUsage?.[0] === "notAUsage"
        ? "UNSUPPORTED_PROFILE"
        : "INVALID_PROFILE"
    );
  }
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validPolicy(),
        rules: { requiredRuleNames: ["unregistered"] }
      }),
    "UNSUPPORTED_PROFILE"
  );
  const policy = compileValidationProfile(
    {
      ...validPolicy(),
      rules: { requiredRuleNames: ["policy-set-check"] }
    },
    { registeredRuleNames: ["policy-set-check"] }
  );
  assert.deepEqual(policy.rules?.requiredRuleNames, ["policy-set-check"]);
});

test("rejects invalid policy configuration before any certificate I/O", async () => {
  let loads = 0;
  const loader = async () => {
    loads++;
    return readCrl("intermediate-revoked");
  };
  expectProfileError(
    () =>
      createTrustValidator({
        trustAnchors: [root],
        profile: { ...validPolicy(), id: "" },
        loadCrl: loader
      }),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      createTrustValidator({
        trustAnchors: [root],
        profile: validPolicy({
          revocation: { requiredEvidence: "both", sourceOrder: ["ocsp"] }
        }),
        loadCrl: loader
      }),
    "INVALID_PROFILE"
  );
  assert.equal(loads, 0);
});

test("a valid strict policy still rejects invalid paths and authenticated revocation", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    profile: validPolicy(),
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
    profile: validPolicy(),
    now,
    loadOcsp: false,
    loadCrl: async () => readCrl("intermediate-revoked")
  });
  const untrusted = await untrustedValidator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(untrusted.valid, false);
  assert.equal(untrusted.code, "INVALID_CERTIFICATE_PATH");
  assert.equal(untrusted.profileId, "test:policy");

  const revoked = await validator.verify({
    certificateChain: [readCertificate("revoked-leaf"), intermediate]
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
  assert.equal(revoked.profileVersion, 1);
});

test("returns the selected policy identity on success", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    profile: validPolicy({ id: "test:policy:success", version: 7 }),
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
  assert.equal(result.profileId, "test:policy:success");
  assert.equal(result.profileVersion, 7);
  assert.equal(
    result.leafCertificate.fingerprint256,
    new X509Certificate(leaf).fingerprint256
  );
});

test("compiles structured policy sources and ordered string versions", () => {
  const policy = compileValidationProfile({
    ...validPolicy(),
    version: "2026-01",
    versionOrder: 42,
    source: {
      uri: "https://policy-set.example/policy",
      version: "3.2",
      effectiveDate: "2026-01-15"
    }
  });
  assert.equal(policy.version, "2026-01");
  assert.equal(policy.versionOrder, 42);
  assert.deepEqual(policy.source, {
    uri: "https://policy-set.example/policy",
    version: "3.2",
    effectiveDate: "2026-01-15"
  });
  assert.throws(
    () =>
      compileValidationProfile({
        ...validPolicy(),
        version: "2026-01"
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.match(error.message, /versionOrder is required/);
      return true;
    }
  );
  for (const source of [
    { uri: "" },
    { uri: "https://x", unknown: true },
    { uri: "https://x", effectiveDate: "not-a-date" }
  ]) {
    assert.throws(
      () =>
        compileValidationProfile({
          ...validPolicy(),
          source: source as never
        }),
      ProfileError
    );
  }
});
