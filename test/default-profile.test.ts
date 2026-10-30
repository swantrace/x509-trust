import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  compileValidationProfile,
  DEFAULT_VALIDATION_PROFILE
} from "../src/index.ts";

test("the checked-in default profile mirrors the built-in strict default", () => {
  const file = JSON.parse(
    readFileSync(
      new URL("../profiles/default/profile.json", import.meta.url),
      "utf8"
    )
  );
  assert.deepEqual(compileValidationProfile(file), compileValidationProfile());
  assert.deepEqual(
    compileValidationProfile(file),
    compileValidationProfile(DEFAULT_VALIDATION_PROFILE)
  );
});
