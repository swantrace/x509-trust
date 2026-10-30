import assert from "node:assert/strict";
import { test } from "node:test";
import type { CacheStore } from "../src/evidence/cache.ts";
import {
  createTrustValidator,
  type ValidationProfileInput
} from "../src/index.ts";
import {
  createCrl,
  createOcspResponse,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const checkDate = new Date("2026-10-15T00:00:00Z");
const now = () => checkDate.getTime();
const leafCrlOne = "http://crl.test/leaf-one.crl";
const leafCrlTwo = "http://crl.test/leaf-two.crl";
const intermediateCrlUrl = "http://crl.test/intermediate.crl";
const leafOcspUrl = "http://ocsp.test/leaf";
const intermediateOcspUrl = "http://ocsp.test/intermediate";

const crlChain = await createSyntheticChain({
  intermediate: { crlUrls: [intermediateCrlUrl] },
  leaf: { crlUrls: [leafCrlOne, leafCrlTwo] }
});
const ocspChain = await createSyntheticChain({
  intermediate: { ocspUrls: [intermediateOcspUrl] },
  leaf: { ocspUrls: [leafOcspUrl] }
});

const leafGoodCrl = await createCrl(crlChain.intermediate, []);
const intermediateGoodCrl = await createCrl(crlChain.root, []);
const leafRevokedOcsp = await createOcspResponse(
  ocspChain.intermediate,
  ocspChain.leaf,
  "revoked"
);
const intermediateRevokedOcsp = await createOcspResponse(
  ocspChain.root,
  ocspChain.intermediate,
  "revoked"
);
const intermediateGoodOcsp = await createOcspResponse(
  ocspChain.root,
  ocspChain.intermediate,
  "good"
);

function policy(sourceOrder: ("crl" | "ocsp")[]): ValidationProfileInput {
  return {
    id: "concurrency:policy",
    version: 1,
    source: "concurrency test",
    anchorSetId: "concurrency:root",
    revocation: { requiredEvidence: "any", sourceOrder }
  };
}

test("starts every non-anchor evidence pipeline before any of them completes", {
  timeout: 5000
}, async () => {
  const started = new Set<string>();
  const bothStarted = deferred();
  const releases = new Map<string, () => void>();
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: policy(["crl"]),
    now,
    loadOcsp: false,
    loadCrl: async (url) => {
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
    profile: policy(["ocsp", "crl"]),
    now,
    loadCrl: false,
    loadOcsp: async ({ url, signal }) => {
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
    profile: policy(["crl"]),
    now,
    loadOcsp: false,
    loadCrl: async (url) => {
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

test("external abort reaches willing loaders and rejects with AbortError", {
  timeout: 5000
}, async () => {
  const started = deferred();
  const observedAbort = deferred();
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: policy(["crl"]),
    now,
    loadOcsp: false,
    loadCrl: (_url, options) =>
      new Promise<Uint8Array>((_resolve, reject) => {
        started.resolve();
        const signal = options?.signal;
        assert.ok(signal);
        if (signal.aborted) {
          observedAbort.resolve();
          reject(new DOMException("aborted", "AbortError"));
          return;
        }
        signal.addEventListener(
          "abort",
          () => {
            observedAbort.resolve();
            reject(new DOMException("aborted", "AbortError"));
          },
          { once: true }
        );
      })
  });
  const controller = new AbortController();
  const verification = validator.verify({
    certificateChain: [crlChain.leaf.der, crlChain.intermediate.der],
    signal: controller.signal
  });
  await started.promise;
  controller.abort();
  await assert.rejects(verification, (error: unknown) => {
    assert.ok(error instanceof DOMException);
    assert.equal(error.name, "AbortError");
    return true;
  });
  await observedAbort.promise;
});

test("a slow cache write does not delay an authenticated revoked result", {
  timeout: 5000
}, async () => {
  const cache: CacheStore = {
    async get() {
      return null;
    },
    set() {
      // Never resolves: a revoked result must not await cache persistence.
      return new Promise(() => {});
    },
    async delete() {}
  };
  const validator = createTrustValidator({
    trustAnchors: [ocspChain.root.der],
    profile: policy(["ocsp"]),
    now,
    cache,
    loadCrl: false,
    loadOcsp: async ({ url }) =>
      url === leafOcspUrl ? leafRevokedOcsp : intermediateRevokedOcsp
  });
  const result = await validator.verify({
    certificateChain: [ocspChain.leaf.der, ocspChain.intermediate.der]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
});

test("an explicit checkDate is copied before asynchronous validation", async () => {
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: policy(["crl"]),
    now,
    loadOcsp: false,
    loadCrl: async (url) =>
      url === intermediateCrlUrl ? intermediateGoodCrl : leafGoodCrl
  });
  const date = new Date(checkDate);
  const verification = validator.verify({
    certificateChain: [crlChain.leaf.der, crlChain.intermediate.der],
    checkDate: date
  });
  date.setTime(0);
  const result = await verification;
  assert.equal(result.valid, true);
});
