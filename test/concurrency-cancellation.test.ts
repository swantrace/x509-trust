import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustValidator } from "../src/index.ts";
import type { CacheStore } from "../src/revocation/cache.ts";
import {
  checkDate,
  crlChain,
  deferred,
  intermediateCrlUrl,
  intermediateGoodCrl,
  intermediateRevokedOcsp,
  leafGoodCrl,
  leafOcspUrl,
  leafRevokedOcsp,
  now,
  ocspChain,
  profile
} from "./helpers/concurrency-fixtures.ts";

test("external abort reaches willing loaders and rejects with AbortError", {
  timeout: 5000
}, async () => {
  const started = deferred();
  const observedAbort = deferred();
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: profile(["crl"]),
    now,
    ocspLoader: false,
    crlLoader: ({ signal }) =>
      new Promise<Uint8Array>((_resolve, reject) => {
        started.resolve();
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
    profile: profile(["ocsp"]),
    now,
    cache,
    crlLoader: false,
    ocspLoader: async ({ url }) =>
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
    profile: profile(["crl"]),
    now,
    ocspLoader: false,
    crlLoader: async ({ url }) =>
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

test("external cancellation wins when the deadline also expires during startup", {
  timeout: 5000
}, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const controller = new AbortController();
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: profile(["crl"]),
    now,
    deadlineMs: 50,
    ocspLoader: false,
    crlLoader: async () => {
      loads++;
      return leafGoodCrl;
    },
    cache: {
      async get() {
        t.mock.timers.tick(50);
        controller.abort();
        return null;
      },
      async set() {},
      async delete() {}
    }
  });
  await assert.rejects(
    validator.verify({
      certificateChain: [crlChain.leaf.der, crlChain.intermediate.der],
      signal: controller.signal
    }),
    { name: "AbortError" }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(loads, 0);
});
