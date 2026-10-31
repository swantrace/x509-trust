import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createEvidenceProvider,
  createTrustValidator,
  type EvidenceProvider,
  ResourceLimitError,
  type ValidationProfileInput
} from "../src/index.ts";
import {
  createCrl,
  createLeafForChain,
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

const issuer = new Uint8Array([0x01, 0x02]);
const otherIssuer = new Uint8Array([0x03, 0x04]);
const requestDer = new Uint8Array([0x10, 0x11]);
const certificate = new Uint8Array([0x20, 0x21]);

test("provider methods remain callable without their receiver", async () => {
  const provider = createEvidenceProvider({
    loadCrl: async () => new Uint8Array([1]),
    loadOcsp: async () => new Uint8Array([2])
  });
  const { loadCrl, loadOcsp, stats } = provider;

  assert.equal(Object.getPrototypeOf(provider), Object.prototype);
  assert.equal(provider.supportsCrl, true);
  assert.equal(provider.supportsOcsp, true);
  assert.deepEqual(
    await loadCrl("http://detached.test/crl", { issuerCertificate: issuer }),
    new Uint8Array([1])
  );
  assert.deepEqual(
    await loadOcsp({
      url: "http://detached.test/ocsp",
      certificate,
      issuerCertificate: issuer,
      requestDer
    }),
    new Uint8Array([2])
  );
  assert.deepEqual(stats(), { active: 0, queued: 0 });
});

test("bounds active requests and rejects overload beyond the queue", async () => {
  let active = 0;
  let maxActive = 0;
  const started = deferred();
  const gates = new Map<string, ReturnType<typeof deferred<Uint8Array>>>();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 1,
    maxQueuedRequests: 1,
    maxActivePerOrigin: 1,
    queueTimeoutMs: 1000,
    loadCrl: async (url) => {
      active++;
      maxActive = Math.max(maxActive, active);
      started.resolve();
      const gate = deferred<Uint8Array>();
      gates.set(url, gate);
      try {
        return await gate.promise;
      } finally {
        active--;
      }
    }
  });
  const first = provider.loadCrl("http://limit.test/one", {
    issuerCertificate: issuer
  });
  await started.promise;
  const second = provider.loadCrl("http://limit.test/two", {
    issuerCertificate: issuer
  });
  const third = provider.loadCrl("http://limit.test/three", {
    issuerCertificate: issuer
  });
  await assert.rejects(third, ResourceLimitError);
  assert.deepEqual(provider.stats(), { active: 1, queued: 1 });
  assert.equal(maxActive, 1);
  assert.equal(gates.size, 1);
  gates.get("http://limit.test/one")!.resolve(new Uint8Array([1]));
  await first;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(gates.size, 2);
  gates.get("http://limit.test/two")!.resolve(new Uint8Array([2]));
  await second;
  assert.equal(maxActive, 1);
});

test("enforces a per-origin active limit while allowing other origins", async () => {
  const starts: string[] = [];
  const gates = new Map<string, ReturnType<typeof deferred<Uint8Array>>>();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 2,
    maxQueuedRequests: 4,
    maxActivePerOrigin: 1,
    queueTimeoutMs: 1000,
    loadCrl: async (url) => {
      starts.push(url);
      const gate = deferred<Uint8Array>();
      gates.set(url, gate);
      return gate.promise;
    }
  });
  const firstA = provider.loadCrl("http://a.test/one", {
    issuerCertificate: issuer
  });
  const firstB = provider.loadCrl("http://b.test/one", {
    issuerCertificate: issuer
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(
    new Set(starts),
    new Set(["http://a.test/one", "http://b.test/one"])
  );
  const secondA = provider.loadCrl("http://a.test/two", {
    issuerCertificate: issuer
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(starts.includes("http://a.test/two"), false);
  gates.get("http://a.test/one")!.resolve(new Uint8Array([1]));
  await firstA;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(starts.includes("http://a.test/two"), true);
  gates.get("http://b.test/one")!.resolve(new Uint8Array([2]));
  gates.get("http://a.test/two")!.resolve(new Uint8Array([3]));
  await Promise.all([firstB, secondA]);
});

test("shares one CRL download for the same URL and issuer", async () => {
  let loads = 0;
  const started = deferred();
  const gate = deferred<Uint8Array>();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async () => {
      loads++;
      started.resolve();
      return gate.promise;
    }
  });
  const first = provider.loadCrl("http://single.test/crl", {
    issuerCertificate: issuer
  });
  await started.promise;
  const second = provider.loadCrl("http://single.test/crl", {
    issuerCertificate: issuer
  });
  assert.equal(loads, 1);
  const differentIssuer = provider.loadCrl("http://single.test/crl", {
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
  const provider = createEvidenceProvider({
    loadCrl: false,
    loadOcsp: async () => {
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
  const first = provider.loadOcsp(options);
  await started.promise;
  const second = provider.loadOcsp(options);
  assert.equal(loads, 1);
  const differentInputs = [
    { ...options, url: "http://other-ocsp.test/status" },
    { ...options, certificate: new Uint8Array([0x99]) },
    { ...options, issuerCertificate: otherIssuer },
    { ...options, requestDer: new Uint8Array([0x99]) }
  ].map((input) => provider.loadOcsp(input));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(loads, 5);
  gate.resolve(new Uint8Array([7]));
  for (const result of await Promise.all([first, second, ...differentInputs])) {
    assert.deepEqual(result, new Uint8Array([7]));
  }
});

test("one subscriber's cancel does not abort a download another still needs", async () => {
  const started = deferred();
  const gate = deferred<Uint8Array>();
  let underlyingSignal: AbortSignal | undefined;
  const provider = createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async (_url, options) => {
      underlyingSignal = options?.signal;
      started.resolve();
      return gate.promise;
    }
  });
  const firstController = new AbortController();
  const secondController = new AbortController();
  const first = provider.loadCrl("http://shared.test/crl", {
    issuerCertificate: issuer,
    signal: firstController.signal
  });
  await started.promise;
  const second = provider.loadCrl("http://shared.test/crl", {
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
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 1,
    maxQueuedRequests: 1,
    maxActivePerOrigin: 1,
    loadCrl: async (_url, options) => {
      loads++;
      if (loads > 1) return new Uint8Array([6]);
      started.resolve();
      return new Promise<Uint8Array>((_resolve, reject) => {
        const signal = options?.signal;
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
  const first = provider.loadCrl("http://cancel.test/crl", {
    issuerCertificate: issuer,
    signal: firstController.signal
  });
  await started.promise;
  const second = provider.loadCrl("http://cancel.test/crl", {
    issuerCertificate: issuer,
    signal: secondController.signal
  });
  firstController.abort();
  secondController.abort();
  await assert.rejects(first);
  await assert.rejects(second);
  await aborted.promise;
  assert.deepEqual(
    await provider.loadCrl("http://cancel.test/crl", {
      issuerCertificate: issuer
    }),
    new Uint8Array([6])
  );
  assert.equal(loads, 2);
});

test("a failed shared load is removed so a retry performs a fresh download", async () => {
  let loads = 0;
  const started = deferred();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async () => {
      loads++;
      started.resolve();
      if (loads === 1) throw new Error("transport failed");
      return new Uint8Array([8]);
    }
  });
  const first = provider.loadCrl("http://retry.test/crl", {
    issuerCertificate: issuer
  });
  await started.promise;
  const second = provider.loadCrl("http://retry.test/crl", {
    issuerCertificate: issuer
  });
  await assert.rejects(first, /transport failed/);
  await assert.rejects(second, /transport failed/);
  assert.deepEqual(
    await provider.loadCrl("http://retry.test/crl", {
      issuerCertificate: issuer
    }),
    new Uint8Array([8])
  );
  assert.equal(loads, 2);
});

for (const outcome of ["resolves", "rejects"] as const) {
  test(`an abandoned download that later ${outcome} cannot remove its replacement`, async () => {
    const abandoned = deferred<Uint8Array>();
    const replacement = deferred<Uint8Array>();
    const started = deferred();
    const replacementStarted = deferred();
    let loads = 0;
    const provider = createEvidenceProvider({
      loadOcsp: false,
      loadCrl: async () => {
        loads++;
        if (loads === 1) {
          started.resolve();
          // A custom loader may ignore abort and finish after a retry starts.
          return abandoned.promise;
        }
        replacementStarted.resolve();
        return replacement.promise;
      }
    });
    const controller = new AbortController();
    const url = "http://replacement.test/crl";
    const first = provider.loadCrl(url, {
      issuerCertificate: issuer,
      signal: controller.signal
    });
    await started.promise;
    controller.abort();
    await assert.rejects(first, { name: "AbortError" });

    const retry = provider.loadCrl(url, { issuerCertificate: issuer });
    await replacementStarted.promise;
    if (outcome === "resolves") abandoned.resolve(new Uint8Array([1]));
    else abandoned.reject(new Error("abandoned download failed"));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(provider.stats(), { active: 1, queued: 0 });

    const subscriber = provider.loadCrl(url, { issuerCertificate: issuer });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(loads, 2);
    replacement.resolve(new Uint8Array([2]));
    assert.deepEqual(await retry, new Uint8Array([2]));
    assert.deepEqual(await subscriber, new Uint8Array([2]));
    assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
  });
}

test("cancelling all queued subscribers frees space for a replacement download", async () => {
  const started = deferred();
  const gate = deferred<Uint8Array>();
  const loads: string[] = [];
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 1,
    maxQueuedRequests: 1,
    loadCrl: async (url) => {
      loads.push(url);
      started.resolve();
      return gate.promise;
    }
  });
  const activeUrl = "http://queued.test/active.crl";
  const queuedUrl = "http://queued.test/queued.crl";
  const active = provider.loadCrl(activeUrl, { issuerCertificate: issuer });
  await started.promise;
  const controller = new AbortController();
  const cancelled = provider.loadCrl(queuedUrl, {
    issuerCertificate: issuer,
    signal: controller.signal
  });
  const secondController = new AbortController();
  const alsoCancelled = provider.loadCrl(queuedUrl, {
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

  const retry = provider.loadCrl(queuedUrl, { issuerCertificate: issuer });
  assert.deepEqual(provider.stats(), { active: 1, queued: 1 });
  gate.resolve(new Uint8Array([3]));
  await active;
  assert.deepEqual(await retry, new Uint8Array([3]));
  assert.deepEqual(loads, [activeUrl, queuedUrl]);
  assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
});

test("queue waiters time out with a resource error", async () => {
  const started = deferred();
  const gate = deferred<Uint8Array>();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 1,
    maxQueuedRequests: 1,
    maxActivePerOrigin: 1,
    queueTimeoutMs: 25,
    loadCrl: async () => {
      started.resolve();
      return gate.promise;
    }
  });
  const first = provider.loadCrl("http://timeout.test/one", {
    issuerCertificate: issuer
  });
  await started.promise;
  const second = provider.loadCrl("http://timeout.test/two", {
    issuerCertificate: issuer
  });
  await assert.rejects(second, ResourceLimitError);
  gate.resolve(new Uint8Array([4]));
  await first;
});

test("verification deadline returns RESOURCE_LIMIT_EXCEEDED", async () => {
  const chain = await createSyntheticChain({
    intermediate: { crlUrls: ["http://deadline.test/intermediate.crl"] },
    leaf: { crlUrls: ["http://deadline.test/leaf.crl"] }
  });
  const release = deferred<Uint8Array>();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async () => release.promise
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
  release.resolve(new Uint8Array([1]));
});

test("validator maps a provider queue limit to RESOURCE_LIMIT_EXCEEDED", async () => {
  const chainA = await createSyntheticChain({
    intermediate: { crlUrls: ["http://queue-a.test/intermediate.crl"] },
    leaf: { crlUrls: ["http://queue-a.test/leaf.crl"] }
  });
  const chainB = await createSyntheticChain({
    intermediate: { crlUrls: ["http://queue-b.test/intermediate.crl"] },
    leaf: { crlUrls: ["http://queue-b.test/leaf.crl"] }
  });
  const started = deferred();
  const release = deferred<Uint8Array>();
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 1,
    maxQueuedRequests: 0,
    maxActivePerOrigin: 1,
    loadCrl: async () => {
      started.resolve();
      return release.promise;
    }
  });
  const profile: ValidationProfileInput = {
    id: "queue:profile",
    version: 1,
    source: "queue test",
    anchorSetId: "queue:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
  const makeValidator = (chain: typeof chainA) =>
    createTrustValidator({
      trustAnchors: [chain.root.der],
      profile,
      provider,
      deadlineMs: 5000
    });
  const first = makeValidator(chainA).verify({
    certificateChain: [chainA.leaf.der, chainA.intermediate.der]
  });
  await started.promise;
  const second = await makeValidator(chainB).verify({
    certificateChain: [chainB.leaf.der, chainB.intermediate.der]
  });
  assert.equal(second.valid, false);
  assert.equal(second.code, "RESOURCE_LIMIT_EXCEEDED");
  release.resolve(new Uint8Array([1]));
  await first;
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
  const provider = createEvidenceProvider({
    loadOcsp: false,
    maxActiveRequests: 1,
    maxQueuedRequests: 1,
    loadCrl: async (url) => {
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
  const observed: EvidenceProvider = {
    ...provider,
    loadCrl(url, options) {
      const pending = provider.loadCrl(url, options);
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
  const provider = createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async (url) =>
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
