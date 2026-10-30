import assert from "node:assert/strict";
import { test } from "node:test";
import * as api from "../src/index.ts";

test("public entrypoint exposes profile names without legacy policy/community API", () => {
  assert.equal(typeof api.compileValidationProfile, "function");
  assert.equal(typeof api.createValidationProfileRegistry, "function");
  assert.equal(typeof api.createTrustValidator, "function");
  assert.ok(api.PROFILE_CAPABILITIES.includes("revocation:crl"));
  for (const legacy of [
    "compileTrustPolicy",
    "createTrustRegistry",
    "DEFAULT_TRUST_POLICY",
    "PolicyError",
    "trustPolicyCapabilities"
  ]) {
    assert.equal(legacy in api, false, `${legacy} must not be exported`);
  }
});
