import assert from "node:assert/strict";
import { test } from "node:test";
import { ProfileError } from "../src/index.ts";
import { normalizeRuleRegistrations } from "../src/profile/rules.ts";
import {
  base,
  baseLeafCrlUrl,
  inputFor,
  makeRegistry,
  profileFor
} from "./helpers/profile-registry-fixtures.ts";
import { createLeafForChain } from "./helpers/synthetic-pki.ts";

test("rule schemas preserve callbacks and reject invalid registrations", () => {
  const check = () => ({ ok: true as const });
  const input = [{ name: " custom rule ", check }];
  const rules = normalizeRuleRegistrations(input);
  assert.notEqual(rules, input);
  assert.notEqual(rules[0], input[0]);
  assert.equal(rules[0].name, " custom rule ");
  assert.equal(rules[0].check, check);
  assert.deepEqual(normalizeRuleRegistrations(undefined), []);
  for (const invalid of [
    null,
    [{ name: "rule", check: true }],
    [{ name: " ", check }],
    [{ name: "rule", check, unexpected: undefined }],
    [
      { name: "rule", check },
      { name: "rule", check }
    ]
  ]) {
    assert.throws(
      () => normalizeRuleRegistrations(invalid),
      (error: unknown) => {
        assert.ok(error instanceof ProfileError);
        assert.equal(error.code, "INVALID_PROFILE");
        return true;
      }
    );
  }
});

test("built-in leaf KU, EKU, certificate policy OID and path depth rules run after core validation", async () => {
  const { registry } = makeRegistry([
    {
      profileId: "rules",
      chain: base,
      profile: profileFor("rules:profile", {
        rules: {
          leafKeyUsage: ["digitalSignature"],
          leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
          requiredCertificatePolicyOids: ["1.2.3.4"],
          maxPathDepth: 3
        }
      })
    }
  ]);
  const success = await registry.verify({
    profileId: "rules",
    certificateChain: inputFor(base)
  });
  assert.equal(success.valid, true);

  const wrongKeyUsage = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    keyUsageBits: [0x20]
  });
  const wrongUsage = await registry.verify({
    profileId: "rules",
    certificateChain: inputFor(base, wrongKeyUsage)
  });
  assert.equal(wrongUsage.valid, false);
  assert.equal(wrongUsage.code, "PROFILE_REJECTED");

  const noEku = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl]
  });
  const missingEku = await registry.verify({
    profileId: "rules",
    certificateChain: inputFor(base, noEku)
  });
  assert.equal(missingEku.valid, false);
  assert.equal(missingEku.code, "PROFILE_REJECTED");

  const leafWithoutPolicy = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    extendedKeyUsageOids: ["1.3.6.1.5.5.7.3.2"]
  });
  const { registry: profileRegistry } = makeRegistry([
    {
      profileId: "leaf-profile",
      chain: base,
      profile: profileFor("leaf-profile:profile", {
        rules: { requiredCertificatePolicyOids: ["2.9.9.9"] }
      })
    }
  ]);
  const intermediateOnly = await profileRegistry.verify({
    profileId: "leaf-profile",
    certificateChain: inputFor(base, leafWithoutPolicy)
  });
  assert.equal(intermediateOnly.valid, false);
  assert.equal(intermediateOnly.code, "PROFILE_REJECTED");

  const leafWithPolicy = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    certificatePolicyOids: ["2.9.9.9"]
  });
  const leafPolicy = await profileRegistry.verify({
    profileId: "leaf-profile",
    certificateChain: inputFor(base, leafWithPolicy)
  });
  assert.equal(leafPolicy.valid, true);

  const { registry: depthRegistry } = makeRegistry([
    {
      profileId: "depth",
      chain: base,
      profile: profileFor("depth:profile", {
        rules: { maxPathDepth: 2 }
      })
    }
  ]);
  const tooDeep = await depthRegistry.verify({
    profileId: "depth",
    certificateChain: inputFor(base)
  });
  assert.equal(tooDeep.valid, false);
  assert.equal(tooDeep.code, "PROFILE_REJECTED");
});
