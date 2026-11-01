import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createRevocationProvider,
  createTrustValidator,
  type RevocationProvider
} from "../src/index.ts";
import {
  certificate,
  deferred,
  issuer,
  otherIssuer,
  requestDer
} from "./helpers/revocation-provider-fixtures.ts";
import { createCrl, createSyntheticChain } from "./helpers/synthetic-pki.ts";

test("shares one CRL download for the same URL and issuer", async () => {
  let loads = 0;
  const started = deferred();
  const gate = deferred<Uint8Array>();
  const provider = createRevocationProvider({
    ocspLoader: false,
    crlLoader: async () => {
      loads++;
      started.resolve();
      return gate.promise;
    }
  });
  const first = provider.loadCrl!({
    url: "http://single.test/crl",
    issuerCertificate: issuer
  });
  await started.promise;
  const second = provider.loadCrl!({
    url: "http://single.test/crl",
    issuerCertificate: issuer
  });
  assert.equal(loads, 1);
  const differentIssuer = provider.loadCrl!({
    url: "http://single.test/crl",
    issuerCertificate: otherIssuer
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(loads, 2);
  gate.resolve(new Uint8Array([9]));
  assert.deepEqual(await first, new Uint8Array([9]));
  assert.deepEqual(await second, new Uint8Array([9]));
  assert.deepEqual(await differentIssuer, new Uint8Array([9]));
});

test("shares OCSP downloads only when URL, certificate, issuer and request DER match", async () => {
  let loads = 0;
  const started = deferred();
  const gate = deferred<Uint8Array>();
  const provider = createRevocationProvider({
    crlLoader: false,
    ocspLoader: async () => {
      loads++;
      started.resolve();
      return gate.promise;
    }
  });
  const options = {
    url: "http://ocsp.test/status",
    certificate,
    issuerCertificate: issuer,
    requestDer
  };
  const first = provider.loadOcsp!(options);
  await started.promise;
  const second = provider.loadOcsp!(options);
  assert.equal(loads, 1);
  const differentInputs = [
    { ...options, url: "http://other-ocsp.test/status" },
    { ...options, certificate: new Uint8Array([0x99]) },
    { ...options, issuerCertificate: otherIssuer },
    { ...options, requestDer: new Uint8Array([0x99]) }
  ].map((input) => provider.loadOcsp!(input));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(loads, 5);
  gate.resolve(new Uint8Array([7]));
  for (const result of await Promise.all([first, second, ...differentInputs])) {
    assert.deepEqual(result, new Uint8Array([7]));
  }
});

test("validators sharing a provider share download limits and pending downloads", {
  timeout: 5000
}, async (t) => {
  const leafUrl = "http://validators.test/leaf.crl";
  const intermediateUrl = "http://validators.test/intermediate.crl";
  const chain = await createSyntheticChain({
    intermediate: { crlUrls: [intermediateUrl] },
    leaf: { crlUrls: [leafUrl] }
  });
  const leafCrl = await createCrl(chain.intermediate, []);
  const intermediateCrl = await createCrl(chain.root, []);
  const subscribed = deferred();
  const started = deferred();
  const release = deferred();
  t.after(() => release.resolve());
  const loads: string[] = [];
  let active = 0;
  let maxActive = 0;
  const provider = createRevocationProvider({
    ocspLoader: false,
    maxActiveRequests: 1,
    crlLoader: async ({ url }) => {
      loads.push(url);
      active++;
      maxActive = Math.max(maxActive, active);
      started.resolve();
      try {
        await release.promise;
        return url === leafUrl ? leafCrl : intermediateCrl;
      } finally {
        active--;
      }
    }
  });
  let requests = 0;
  const observed: RevocationProvider = {
    ...provider,
    loadCrl(request) {
      const pending = provider.loadCrl!(request);
      if (++requests === 4) subscribed.resolve();
      return pending;
    }
  };
  const makeValidator = () =>
    createTrustValidator({
      trustAnchors: [chain.root.der],
      provider: observed,
      now: () => new Date("2026-10-15T00:00:00Z").getTime()
    });
  const first = makeValidator().verify({
    certificateChain: [chain.leaf.der, chain.intermediate.der]
  });
  const second = makeValidator().verify({
    certificateChain: [chain.leaf.der, chain.intermediate.der]
  });

  // Both validators must subscribe before any download can populate a cache.
  await Promise.all([subscribed.promise, started.promise]);
  assert.deepEqual(provider.stats(), { active: 1, queued: 1 });
  assert.equal(loads.length, 1);
  release.resolve();
  const results = await Promise.all([first, second]);
  assert.ok(results.every((result) => result.valid));
  assert.equal(maxActive, 1);
  assert.equal(loads.length, 2);
  assert.deepEqual(new Set(loads), new Set([leafUrl, intermediateUrl]));
  assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
});
