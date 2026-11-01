import assert from "node:assert/strict";
import { test } from "node:test";
import { createRevocationProvider } from "../src/index.ts";
import { deferred, issuer } from "./helpers/revocation-provider-fixtures.ts";

test("one subscriber's cancel does not abort a download another still needs", async () => {
  const started = deferred();
  const gate = deferred<Uint8Array>();
  let underlyingSignal: AbortSignal | undefined;
  const provider = createRevocationProvider({
    ocspLoader: false,
    crlLoader: async ({ signal }) => {
      underlyingSignal = signal;
      started.resolve();
      return gate.promise;
    }
  });
  const firstController = new AbortController();
  const secondController = new AbortController();
  const first = provider.loadCrl!({
    url: "http://shared.test/crl",
    issuerCertificate: issuer,
    signal: firstController.signal
  });
  await started.promise;
  const second = provider.loadCrl!({
    url: "http://shared.test/crl",
    issuerCertificate: issuer,
    signal: secondController.signal
  });
  firstController.abort();
  await assert.rejects(first, (error: unknown) => {
    assert.ok(error instanceof DOMException);
    assert.equal(error.name, "AbortError");
    return true;
  });
  assert.equal(underlyingSignal?.aborted, false);
  gate.resolve(new Uint8Array([5]));
  assert.deepEqual(await second, new Uint8Array([5]));
});

test("when every subscriber cancels, the underlying request aborts and slots free up", async () => {
  let loads = 0;
  const started = deferred();
  const aborted = deferred();
  const provider = createRevocationProvider({
    ocspLoader: false,
    maxActiveRequests: 1,
    crlLoader: async ({ signal }) => {
      loads++;
      if (loads > 1) return new Uint8Array([6]);
      started.resolve();
      return new Promise<Uint8Array>((_resolve, reject) => {
        assert.ok(signal);
        signal.addEventListener(
          "abort",
          () => {
            aborted.resolve();
            reject(new DOMException("aborted", "AbortError"));
          },
          { once: true }
        );
      });
    }
  });
  const firstController = new AbortController();
  const secondController = new AbortController();
  const first = provider.loadCrl!({
    url: "http://cancel.test/crl",
    issuerCertificate: issuer,
    signal: firstController.signal
  });
  await started.promise;
  const second = provider.loadCrl!({
    url: "http://cancel.test/crl",
    issuerCertificate: issuer,
    signal: secondController.signal
  });
  firstController.abort();
  secondController.abort();
  await assert.rejects(first);
  await assert.rejects(second);
  await aborted.promise;
  assert.deepEqual(
    await provider.loadCrl!({
      url: "http://cancel.test/crl",
      issuerCertificate: issuer
    }),
    new Uint8Array([6])
  );
  assert.equal(loads, 2);
});

test("cancelling all queued subscribers removes the download before a later retry", async () => {
  const started = deferred();
  const gate = deferred<Uint8Array>();
  const loads: string[] = [];
  const provider = createRevocationProvider({
    ocspLoader: false,
    maxActiveRequests: 1,
    crlLoader: async ({ url }) => {
      loads.push(url);
      started.resolve();
      return gate.promise;
    }
  });
  const activeUrl = "http://queued.test/active.crl";
  const queuedUrl = "http://queued.test/queued.crl";
  const active = provider.loadCrl!({
    url: activeUrl,
    issuerCertificate: issuer
  });
  await started.promise;
  const controller = new AbortController();
  const cancelled = provider.loadCrl!({
    url: queuedUrl,
    issuerCertificate: issuer,
    signal: controller.signal
  });
  const secondController = new AbortController();
  const alsoCancelled = provider.loadCrl!({
    url: queuedUrl,
    issuerCertificate: issuer,
    signal: secondController.signal
  });
  assert.deepEqual(provider.stats(), { active: 1, queued: 1 });

  controller.abort();
  await assert.rejects(cancelled, { name: "AbortError" });
  assert.deepEqual(provider.stats(), { active: 1, queued: 1 });
  secondController.abort();
  await assert.rejects(alsoCancelled, { name: "AbortError" });
  assert.deepEqual(provider.stats(), { active: 1, queued: 0 });
  assert.deepEqual(loads, [activeUrl]);

  const retry = provider.loadCrl!({
    url: queuedUrl,
    issuerCertificate: issuer
  });
  assert.deepEqual(provider.stats(), { active: 1, queued: 1 });
  gate.resolve(new Uint8Array([3]));
  await active;
  assert.deepEqual(await retry, new Uint8Array([3]));
  assert.deepEqual(loads, [activeUrl, queuedUrl]);
  assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
});
