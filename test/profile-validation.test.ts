import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import {
  compileValidationProfile,
  createTrustValidator
} from "../src/index.ts";
import { readCertificate, readCrl } from "./helpers/fixtures.ts";
import {
  expectProfileError,
  intermediate,
  leaf,
  now,
  root,
  validProfile
} from "./helpers/profile-fixtures.ts";

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
