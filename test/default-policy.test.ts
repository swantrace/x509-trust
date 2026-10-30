import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { compileTrustPolicy, DEFAULT_TRUST_POLICY } from "../src/index.ts";

test("the checked-in default policy mirrors the built-in strict default", () => {
  const file = JSON.parse(
    readFileSync(
      new URL("../policies/default/policy.json", import.meta.url),
      "utf8"
    )
  );
  assert.deepEqual(compileTrustPolicy(file), compileTrustPolicy());
  assert.deepEqual(
    compileTrustPolicy(file),
    compileTrustPolicy(DEFAULT_TRUST_POLICY)
  );
});
