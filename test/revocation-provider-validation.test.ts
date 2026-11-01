import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createRevocationProvider,
  createTrustValidator,
  type ValidationProfileInput
} from "../src/index.ts";
import { deferred } from "./helpers/revocation-provider-fixtures.ts";
import {
  createCrl,
  createLeafForChain,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

test("verification deadline returns RESOURCE_LIMIT_EXCEEDED", async () => {
  const chain = await createSyntheticChain({
    intermediate: { crlUrls: ["http://deadline.test/intermediate.crl"] },
    leaf: { crlUrls: ["http://deadline.test/leaf.crl"] }
  });
  const release = deferred<Uint8Array>();
  let loads = 0;
  const provider = createRevocationProvider({
    ocspLoader: false,
    maxActiveRequests: 1,
    crlLoader: async () => {
      loads++;
      return release.promise;
    }
  });
  const profile: ValidationProfileInput = {
    id: "deadline:profile",
    version: 1,
    source: "deadline test",
    anchorSetId: "deadline:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
  const validator = createTrustValidator({
    trustAnchors: [chain.root.der],
    profile,
    provider,
    deadlineMs: 25
  });
  const result = await validator.verify({
    certificateChain: [chain.leaf.der, chain.intermediate.der]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "RESOURCE_LIMIT_EXCEEDED");
  assert.equal(loads, 1);
  assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
  release.resolve(new Uint8Array([1]));
});

test("shared CRL bytes still yield per-certificate status", async () => {
  const chain = await createSyntheticChain({
    intermediate: { crlUrls: ["http://status.test/intermediate.crl"] },
    leaf: { crlUrls: ["http://status.test/leaf.crl"] }
  });
  const revokedLeaf = await createLeafForChain(chain, {
    crlUrls: ["http://status.test/leaf.crl"]
  });
  const leafCrl = await createCrl(chain.intermediate, [revokedLeaf]);
  const intermediateCrl = await createCrl(chain.root, []);
  const provider = createRevocationProvider({
    ocspLoader: false,
    crlLoader: async ({ url }) =>
      url.endsWith("/intermediate.crl") ? intermediateCrl : leafCrl
  });
  const profile: ValidationProfileInput = {
    id: "status:profile",
    version: 1,
    source: "status test",
    anchorSetId: "status:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
  const makeValidator = () =>
    createTrustValidator({
      trustAnchors: [chain.root.der],
      profile,
      provider,
      now: () => new Date("2026-10-15T00:00:00Z").getTime()
    });
  const good = await makeValidator().verify({
    certificateChain: [chain.leaf.der, chain.intermediate.der]
  });
  const revoked = await makeValidator().verify({
    certificateChain: [revokedLeaf.der, chain.intermediate.der]
  });
  assert.equal(good.valid, true);
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
});
