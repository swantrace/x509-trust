import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createTrustValidator,
  type DiagnosticEvent,
  type ValidationProfileInput
} from "../src/index.ts";
import type { CacheStore } from "../src/revocation/cache.ts";
import {
  createCrl,
  createOcspResponse,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
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

function profile(sourceOrder: ("crl" | "ocsp")[]): ValidationProfileInput {
  return {
    id: "concurrency:profile",
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

test("deadline findings preserve completed attempts and identify interrupted sources", {
  timeout: 5000
}, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const leafCompleted = deferred();
  const intermediateStarted = deferred();
  const releaseIntermediate = deferred<Uint8Array>();
  t.after(() => releaseIntermediate.resolve(intermediateGoodCrl));
  const events: DiagnosticEvent[] = [];
  let intermediateSignal: AbortSignal | undefined;
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: profile(["crl"]),
    now,
    deadlineMs: 50,
    ocspLoader: false,
    crlLoader: async ({ url, signal }) => {
      if (url === leafCrlOne) {
        throw new DOMException("private transport details", "TimeoutError");
      }
      if (url === leafCrlTwo) return leafGoodCrl;
      intermediateSignal = signal;
      intermediateStarted.resolve();
      return releaseIntermediate.promise;
    },
    onDiagnostic(event) {
      events.push(event);
      if (event.certificateIndex === 0 && event.status === "good") {
        leafCompleted.resolve();
      }
    }
  });
  const verification = validator.verify({
    certificateChain: [crlChain.leaf.der, crlChain.intermediate.der]
  });
  await Promise.all([leafCompleted.promise, intermediateStarted.promise]);
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(50);
  const result = await verification;
  assert.equal(result.valid, false);
  assert.equal(result.code, "RESOURCE_LIMIT_EXCEEDED");
  assert.equal(intermediateSignal?.aborted, true);
  assert.deepEqual(
    result.findings?.map(({ certificateIndex, revocation }) => ({
      certificateIndex,
      attempts: revocation.crl.map(({ source, status, code }) => ({
        source,
        status,
        code
      }))
    })),
    [
      {
        certificateIndex: 0,
        attempts: [
          { source: leafCrlOne, status: "unknown", code: "EVIDENCE_TIMEOUT" },
          { source: leafCrlTwo, status: "good", code: undefined }
        ]
      },
      {
        certificateIndex: 1,
        attempts: [
          {
            source: intermediateCrlUrl,
            status: "unknown",
            code: "EVIDENCE_DEADLINE_EXCEEDED"
          }
        ]
      }
    ]
  );
  for (const finding of result.findings![0].revocation.crl) {
    assert.ok(finding.durationMs! >= 0);
  }
  assert.ok(
    events.some(
      (event) =>
        event.event === "revocation_error" && event.code === "EVIDENCE_TIMEOUT"
    )
  );
  assert.equal(
    JSON.stringify(events).includes("private transport details"),
    false
  );

  const snapshot = structuredClone(result);
  releaseIntermediate.resolve(intermediateGoodCrl);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(result, snapshot);
});

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
