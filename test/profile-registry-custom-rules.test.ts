import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import {
  type TrustRuleContext,
  type TrustRuleRegistration
} from "../src/index.ts";
import {
  base,
  baseLeafCrlUrl,
  crlByUrl,
  inputFor,
  makeRegistry,
  profileFor,
  registryWithRule,
  sameSan,
  second
} from "./helpers/profile-registry-fixtures.ts";
import { createCrl, createLeafForChain } from "./helpers/synthetic-pki.ts";

test("registered custom rules receive trusted facts and fail closed", async () => {
  let observed: TrustRuleContext | undefined;
  const capture = await registryWithRule("custom-ok", {
    name: "capture",
    check(context) {
      observed = context;
      return { ok: true };
    }
  });
  const success = await capture.verify({
    profileId: "custom-ok",
    certificateChain: inputFor(base)
  });
  assert.equal(success.valid, true);
  assert.equal(observed?.profileId, "custom-ok");
  assert.equal(observed?.certificatePath.length, 3);
  assert.deepEqual(observed?.leaf.uriSubjectAlternativeNames, [sameSan]);
  assert.equal(
    observed?.leaf.fingerprint256,
    new X509Certificate(base.leaf.der).fingerprint256
  );

  const denied = await registryWithRule("custom-deny", {
    name: "deny",
    check: () => ({ ok: false, message: "denied by registered rule" })
  });
  const deniedResult = await denied.verify({
    profileId: "custom-deny",
    certificateChain: inputFor(base)
  });
  assert.equal(deniedResult.valid, false);
  assert.equal(deniedResult.code, "PROFILE_REJECTED");
  assert.equal(
    deniedResult.valid === false && deniedResult.message,
    "denied by registered rule"
  );

  const unrecognized = await registryWithRule("custom-bad", {
    name: "bad",
    check: (() => ({ valid: true })) as never
  });
  const badResult = await unrecognized.verify({
    profileId: "custom-bad",
    certificateChain: inputFor(base)
  });
  assert.equal(badResult.valid, false);
  assert.equal(badResult.code, "PROFILE_REJECTED");

  const throwing = await registryWithRule("custom-throw", {
    name: "throw",
    check: () => {
      throw new Error("rule failure");
    }
  });
  const throwResult = await throwing.verify({
    profileId: "custom-throw",
    certificateChain: inputFor(base)
  });
  assert.equal(throwResult.valid, false);
  assert.equal(throwResult.code, "PROFILE_REJECTED");
});

test("rules cannot override core path or revocation failures", async () => {
  const rule: TrustRuleRegistration = {
    name: "always-ok",
    check: () => ({ ok: true })
  };
  const { registry } = makeRegistry([
    {
      profileId: "core",
      chain: base,
      profile: {
        ...profileFor("core:profile"),
        rules: { requiredRuleNames: [rule.name] }
      },
      rules: [rule]
    }
  ]);
  const wrongAnchor = await registry.verify({
    profileId: "core",
    certificateChain: inputFor(second)
  });
  assert.equal(wrongAnchor.valid, false);
  assert.equal(wrongAnchor.code, "INVALID_CERTIFICATE_PATH");

  const revokedLeaf = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl]
  });
  const revokedCrl = await createCrl(base.intermediate, [revokedLeaf]);
  const { registry: revokedRegistry } = makeRegistry(
    [
      {
        profileId: "core-revoked",
        chain: base,
        profile: {
          ...profileFor("core-revoked:profile"),
          rules: { requiredRuleNames: [rule.name] }
        },
        rules: [rule]
      }
    ],
    async (url) => {
      if (url === baseLeafCrlUrl) return revokedCrl;
      const response = crlByUrl.get(url);
      if (!response) throw new Error(`No CRL for ${url}`);
      return response;
    }
  );
  const revoked = await revokedRegistry.verify({
    profileId: "core-revoked",
    certificateChain: inputFor(base, revokedLeaf)
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
});
