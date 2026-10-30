import assert from "node:assert/strict";
import { test } from "node:test";
import * as api from "../src/index.ts";

test("public entrypoint exposes profile names without legacy profile/community API", () => {
  assert.equal(typeof api.compileValidationProfile, "function");
  assert.equal(typeof api.createValidationProfileRegistry, "function");
  assert.equal(typeof api.createTrustValidator, "function");
});
