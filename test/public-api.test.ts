import assert from "node:assert/strict";
import { test } from "node:test";
import * as api from "../src/index.ts";

test("public entrypoint exposes profile names without legacy policy/community API", () => {
  assert.equal(typeof api.compileValidationProfile, "function");
  assert.equal(typeof api.createValidationProfileRegistry, "function");
  assert.equal(typeof api.createTrustValidator, "function");
  for (const legacy of [
    "compileTrustPolicy",
    "createTrustRegistry",
    "DEFAULT_TRUST_POLICY",
    "PolicyError",
    "trustPolicyCapabilities",
    "PROFILE_CAPABILITIES",
    "profileCapabilities"
  ]) {
    assert.equal(legacy in api, false, `${legacy} must not be exported`);
  }
});
