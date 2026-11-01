import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustValidator } from "../src/index.ts";
import {
  crlChain,
  deferred,
  intermediateCrlUrl,
  intermediateGoodCrl,
  intermediateGoodOcsp,
  leafCrlOne,
  leafCrlTwo,
  leafGoodCrl,
  leafOcspUrl,
  leafRevokedOcsp,
  now,
  ocspChain,
  profile
} from "./helpers/concurrency-fixtures.ts";

test("starts every non-anchor evidence pipeline before any of them completes", {
  timeout: 5000
}, async () => {
  const started = new Set<string>();
  const bothStarted = deferred();
  const releases = new Map<string, () => void>();
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: profile(["crl"]),
    now,
    ocspLoader: false,
    crlLoader: async ({ url }) => {
      started.add(url);
      if (started.size === 2) bothStarted.resolve();
      const gate = deferred<Uint8Array>();
      const response =
        url === intermediateCrlUrl ? intermediateGoodCrl : leafGoodCrl;
      releases.set(url, () => gate.resolve(response));
      return gate.promise;
    }
  });
  const verification = validator.verify({
    certificateChain: [crlChain.leaf.der, crlChain.intermediate.der]
  });
  await bothStarted.promise;
  // Both leaf and intermediate pipelines are blocked, so both must have
  // started before either can complete.
  assert.equal(started.size, 2);
  for (const [url, release] of releases) {
    release();
    assert.ok(url);
  }
  const result = await verification;
  assert.equal(result.valid, true);
  assert.equal(result.evidence.length, 2);
});

test("a stalled other certificate does not delay a confirmed revoked result", {
  timeout: 5000
}, async () => {
  const intermediateStarted = deferred();
  const releaseIntermediate = deferred<Uint8Array>();
  const validator = createTrustValidator({
    trustAnchors: [ocspChain.root.der],
    profile: profile(["ocsp", "crl"]),
    now,
    crlLoader: false,
    ocspLoader: async ({ url, signal }) => {
      if (url === leafOcspUrl) return leafRevokedOcsp;
      intermediateStarted.resolve();
      // Deliberately ignores abort: a stalled custom loader must not block a
      // revoked result confirmed by another pipeline.
      assert.ok(signal);
      return releaseIntermediate.promise;
    }
  });
  const verification = validator.verify({
    certificateChain: [ocspChain.leaf.der, ocspChain.intermediate.der]
  });
  await intermediateStarted.promise;
  const result = await verification;
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(result.certificateIndex, 0);
  assert.deepEqual(
    result.evidence?.map(({ mechanism, status }) => ({ mechanism, status })),
    [{ mechanism: "ocsp", status: "revoked" }]
  );
  releaseIntermediate.resolve(intermediateGoodOcsp);
  // Let the abandoned pipeline settle; the returned failure cannot change.
  await new Promise((resolve) => setImmediate(resolve));
});

test("falls back within one certificate while another certificate is still pending", {
  timeout: 5000
}, async () => {
  const secondLeafStarted = deferred();
  const releaseIntermediate = deferred<Uint8Array>();
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: profile(["crl"]),
    now,
    ocspLoader: false,
    crlLoader: async ({ url }) => {
      if (url === leafCrlOne) return Buffer.from("invalid CRL");
      if (url === leafCrlTwo) {
        secondLeafStarted.resolve();
        return leafGoodCrl;
      }
      return releaseIntermediate.promise;
    }
  });
  const verification = validator.verify({
    certificateChain: [crlChain.leaf.der, crlChain.intermediate.der]
  });
  await secondLeafStarted.promise;
  releaseIntermediate.resolve(intermediateGoodCrl);
  const result = await verification;
  assert.equal(result.valid, true);
});
