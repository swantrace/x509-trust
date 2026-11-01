import assert from "node:assert/strict";
import { test } from "node:test";
import { ProfileError } from "../src/index.ts";
import {
  base,
  inputFor,
  makeRegistry,
  profileFor
} from "./helpers/profile-registry-fixtures.ts";

test("registry schemas reject malformed inputs before certificate I/O", async () => {
  const { registry, calls } = makeRegistry([
    { profileId: "known", chain: base }
  ]);
  for (const input of [
    null,
    {
      profileId: "known",
      certificateChain: inputFor(base),
      unexpected: undefined
    },
    { profileId: "known", certificateChain: {} },
    { profileId: "known", certificateChain: inputFor(base), profileVersion: 0 },
    {
      profileId: "known",
      certificateChain: inputFor(base),
      checkDate: "2026-10-15"
    }
  ]) {
    await assert.rejects(registry.verify(input), TypeError);
  }
  for (const input of [
    null,
    { trustAnchors: [base.root.der] },
    { profile: profileFor("bad"), trustAnchors: [] },
    {
      profile: profileFor("bad"),
      trustAnchors: [base.root.der],
      unexpected: undefined
    }
  ]) {
    assert.throws(
      () => registry.register(input),
      (error: unknown) => {
        assert.ok(error instanceof ProfileError);
        assert.equal(error.code, "INVALID_PROFILE");
        return true;
      }
    );
  }
  const malformedCertificate = await registry.verify({
    profileId: "known",
    certificateChain: [123]
  });
  assert.equal(malformedCertificate.valid, false);
  assert.equal(malformedCertificate.code, "INVALID_CERTIFICATE");
  const oversizedChain = await registry.verify({
    profileId: "known",
    certificateChain: Array(17).fill(null)
  });
  assert.equal(oversizedChain.valid, false);
  assert.equal(oversizedChain.code, "INVALID_CERTIFICATE_PATH");
  assert.equal(calls.crl.length, 0);
});

test("rejects duplicate profile versions and does not partially register failures", async () => {
  const { registry } = makeRegistry([
    {
      profileId: "versions",
      chain: base,
      profile: profileFor("v1", { version: 1 })
    }
  ]);
  assert.throws(
    () =>
      registry.register({
        trustAnchors: [base.root.der],
        profile: { ...profileFor("v1-again", { version: 1 }), id: "versions" }
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      return true;
    }
  );

  assert.throws(
    () =>
      registry.register({
        trustAnchors: [base.root.der],
        profile: {
          ...profileFor("broken"),
          rules: { requiredRuleNames: ["missing-rule"] }
        }
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "UNSUPPORTED_PROFILE");
      return true;
    }
  );
  const broken = await registry.verify({
    profileId: "broken",
    certificateChain: inputFor(base)
  });
  assert.equal(broken.valid, false);
  assert.equal(broken.code, "UNKNOWN_PROFILE");
});
