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

function validProfile(
  overrides: Partial<ValidationProfileInput> = {}
): ValidationProfileInput {
  return {
    id: "test:profile",
    version: 1,
    source: "test profile",
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

test("compiles the strict default profile and freezes every level", () => {
  const profile = compileValidationProfile();
  assert.equal(profile.id, DEFAULT_VALIDATION_PROFILE.id);
  assert.equal(profile.revocation.requiredEvidence, "any");
  assert.deepEqual(profile.revocation.sourceOrder, ["ocsp", "crl"]);
  assert.equal(profile.revocation.onUnknown, "reject");
  assert.equal(profile.revocation.scope, "non-anchor-chain");
  assert.equal(profile.revocation.requireNextUpdate, true);
  assert.equal(profile.revocation.clockSkewMs, 0);
  assert.ok(Object.isFrozen(profile));
  assert.ok(Object.isFrozen(profile.revocation));
  assert.ok(Object.isFrozen(profile.revocation.sourceOrder));
});

test("copies caller data so later mutations cannot change a compiled profile", () => {
  const input = validProfile({
    rules: {
      leafKeyUsage: ["digitalSignature"],
      requiredCertificatePolicyOids: ["1.2.3.4"]
    }
  });
  const profile = compileValidationProfile(input);
  input.revocation!.sourceOrder = ["crl"];
  (input.rules!.leafKeyUsage as string[]).push("keyCertSign");
  (input.rules!.requiredCertificatePolicyOids as string[]).push("1.2.3.5");
  assert.deepEqual(profile.revocation.sourceOrder, ["ocsp", "crl"]);
  assert.deepEqual(profile.rules?.leafKeyUsage, ["digitalSignature"]);
  assert.deepEqual(profile.rules?.requiredCertificatePolicyOids, ["1.2.3.4"]);
  assert.throws(() => {
    (profile.revocation.sourceOrder as RevocationMechanism[]).push("crl");
  }, TypeError);
});

type RevocationMechanism = "crl" | "ocsp";

test("rejects unknown fields and malformed profile identity", () => {
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validProfile(),
        unexpected: true
      } as never),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validProfile(),
        revocation: { requiredEvidence: "any", unknown: true }
      } as never),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validProfile(),
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
      () => compileValidationProfile({ ...validProfile(), ...overrides }),
      "INVALID_PROFILE"
    );
  }
});

test("rejects duplicate or unsupported source orders that miss required evidence", () => {
  for (const sourceOrder of [[], ["ocsp", "ocsp"], ["dns"]]) {
    expectProfileError(
      () =>
        compileValidationProfile({
          ...validProfile(),
          revocation: { requiredEvidence: "any", sourceOrder }
        } as never),
      sourceOrder[0] === "dns" ? "UNSUPPORTED_PROFILE" : "INVALID_PROFILE"
    );
  }
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validProfile(),
        revocation: { requiredEvidence: "crl", sourceOrder: ["ocsp"] }
      }),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile({
        ...validProfile(),
        revocation: { requiredEvidence: "both", sourceOrder: ["crl"] }
      }),
    "INVALID_PROFILE"
  );
  const both = compileValidationProfile({
    ...validProfile(),
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
          ...validProfile(),
          revocation: {
            ...validProfile().revocation,
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
          ...validProfile(),
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
        ...validProfile(),
        rules: { requiredRuleNames: ["unregistered"] }
      }),
    "UNSUPPORTED_PROFILE"
  );
  const profile = compileValidationProfile(
    {
      ...validProfile(),
      rules: { requiredRuleNames: ["profile-check"] }
    },
    { registeredRuleNames: ["profile-check"] }
  );
  assert.deepEqual(profile.rules?.requiredRuleNames, ["profile-check"]);
});

test("rejects invalid profile configuration before any certificate I/O", async () => {
  let loads = 0;
  const loader = async () => {
    loads++;
    return readCrl("intermediate-revoked");
  };
  expectProfileError(
    () =>
      createTrustValidator({
        trustAnchors: [root],
        profile: { ...validProfile(), id: "" },
        crlLoader: loader
      }),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      createTrustValidator({
        trustAnchors: [root],
        profile: validProfile({
          revocation: { requiredEvidence: "both", sourceOrder: ["ocsp"] }
        }),
        crlLoader: loader
      }),
    "INVALID_PROFILE"
  );
  assert.equal(loads, 0);
});

test("a valid strict profile still rejects invalid paths and authenticated revocation", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    profile: validProfile(),
    now,
    ocspLoader: false,
    async crlLoader({ url }) {
      return url.endsWith("/root.crl")
        ? readCrl("root")
        : readCrl("intermediate-revoked");
    }
  });
  const untrustedValidator = createTrustValidator({
    trustAnchors: [readCertificate("untrusted-root")],
    profile: validProfile(),
    now,
    ocspLoader: false,
    crlLoader: async () => readCrl("intermediate-revoked")
  });
  const untrusted = await untrustedValidator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(untrusted.valid, false);
  assert.equal(untrusted.code, "INVALID_CERTIFICATE_PATH");
  assert.equal(untrusted.profileId, "test:profile");

  const revoked = await validator.verify({
    certificateChain: [readCertificate("revoked-leaf"), intermediate]
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
  assert.equal(revoked.profileVersion, 1);
});

test("schema validation preserves strings and treats undefined profile fields as absent", () => {
  const profile = compileValidationProfile({
    ...validProfile(),
    id: " test:profile ",
    unexpected: undefined,
    source: { uri: " test source ", version: undefined, unexpected: undefined },
    revocation: { requiredEvidence: undefined, unexpected: undefined },
    rules: { maxPathDepth: undefined, unexpected: undefined }
  });
  assert.equal(profile.id, " test:profile ");
  assert.deepEqual(profile.source, { uri: " test source " });
  assert.equal(profile.revocation.requiredEvidence, "any");
  assert.deepEqual(profile.revocation.sourceOrder, ["ocsp", "crl"]);
  assert.equal(Object.hasOwn(profile, "rules"), false);
  assert.equal(Object.hasOwn(profile, "unexpected"), false);
});

test("schema failures keep profile error codes and identify the invalid field", () => {
  assert.throws(
    () =>
      compileValidationProfile(
        validProfile({ rules: { maxPathDepth: Infinity } })
      ),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      assert.match(error.message, /rules\.maxPathDepth/);
      return true;
    }
  );
  expectProfileError(
    () =>
      compileValidationProfile(
        validProfile({ version: Number.MAX_SAFE_INTEGER + 1 })
      ),
    "INVALID_PROFILE"
  );
  expectProfileError(
    () =>
      compileValidationProfile(
        validProfile({ revocation: { requiredEvidence: "dns" as never } })
      ),
    "UNSUPPORTED_PROFILE"
  );
});

test("returns the selected profile identity on success", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    profile: validProfile({ id: "test:profile:success", version: 7 }),
    now,
    ocspLoader: false,
    async crlLoader({ url }) {
      return url.endsWith("/root.crl")
        ? readCrl("root")
        : readCrl("intermediate-clean");
    }
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, true);
  assert.equal(result.profileId, "test:profile:success");
  assert.equal(result.profileVersion, 7);
  assert.equal(
    result.leafCertificate.fingerprint256,
    new X509Certificate(leaf).fingerprint256
  );
});

test("compiles structured profile sources and ordered string versions", () => {
  const profile = compileValidationProfile({
    ...validProfile(),
    version: "2026-01",
    versionOrder: 42,
    source: {
      uri: "https://profile.example/profile",
      version: "3.2",
      effectiveDate: "2026-01-15"
    }
  });
  assert.equal(profile.version, "2026-01");
  assert.equal(profile.versionOrder, 42);
  assert.deepEqual(profile.source, {
    uri: "https://profile.example/profile",
    version: "3.2",
    effectiveDate: "2026-01-15"
  });
  assert.throws(
    () =>
      compileValidationProfile({
        ...validProfile(),
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
          ...validProfile(),
          source: source as never
        }),
      ProfileError
    );
  }
});
