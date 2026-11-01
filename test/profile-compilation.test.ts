import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compileValidationProfile,
  DEFAULT_VALIDATION_PROFILE,
  ProfileError
} from "../src/index.ts";
import { validProfile } from "./helpers/profile-fixtures.ts";

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
