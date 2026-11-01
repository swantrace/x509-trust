import assert from "node:assert/strict";
import { ProfileError, type ValidationProfileInput } from "../../src/index.ts";
import { fixtureTime, readCertificate } from "./fixtures.ts";

export const checkDate = new Date(fixtureTime);
export const now = () => checkDate.getTime();
export const root = readCertificate("root");
export const intermediate = readCertificate("intermediate");
export const leaf = readCertificate("leaf");

export function validProfile(
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

export function expectProfileError(
  fn: () => unknown,
  code: "INVALID_PROFILE" | "UNSUPPORTED_PROFILE"
) {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof ProfileError);
    assert.equal(error.code, code);
    return true;
  });
}
