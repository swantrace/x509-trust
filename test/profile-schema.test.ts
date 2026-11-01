import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compileValidationProfile,
  ProfileError,
  type ValidationProfileInput
} from "../src/index.ts";
import {
  expectProfileError,
  validProfile
} from "./helpers/profile-fixtures.ts";

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
