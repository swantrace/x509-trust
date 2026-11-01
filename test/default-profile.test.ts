import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compileValidationProfile,
  DEFAULT_VALIDATION_PROFILE
} from "../src/index.ts";
import { readFixture } from "./helpers/fixtures.ts";

test("the checked-in default profile mirrors the built-in strict default", () => {
  const file = JSON.parse(readFixture("default-profile.json").toString("utf8"));
  assert.deepEqual(compileValidationProfile(file), compileValidationProfile());
  assert.deepEqual(
    compileValidationProfile(file),
    compileValidationProfile(DEFAULT_VALIDATION_PROFILE)
  );
});
