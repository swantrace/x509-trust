import assert from "node:assert/strict";
import { test } from "node:test";
import { createRevocationProvider, type OcspRequest } from "../src/index.ts";
import {
  certificate,
  deferred,
  issuer,
  requestDer
} from "./helpers/revocation-provider-fixtures.ts";

test("provider methods remain callable without their receiver", async () => {
  const provider = createRevocationProvider({
    crlLoader: async (request) => {
      assert.equal(request.url, "http://detached.test/crl");
      assert.deepEqual(request.issuerCertificate, issuer);
      assert.ok(request.signal instanceof AbortSignal);
      return new Uint8Array([1]);
    },
    ocspLoader: async (request) => {
      assert.equal(request.url, "http://detached.test/ocsp");
      assert.deepEqual(request.certificate, certificate);
      assert.deepEqual(request.issuerCertificate, issuer);
      assert.deepEqual(request.requestDer, requestDer);
      assert.ok(request.signal instanceof AbortSignal);
      return new Uint8Array([2]);
    }
  });
  const { loadCrl, loadOcsp, stats } = provider;

  assert.equal(Object.getPrototypeOf(provider), Object.prototype);
  assert.ok(loadCrl);
  assert.ok(loadOcsp);
  assert.deepEqual(
    await loadCrl({
      url: "http://detached.test/crl",
      issuerCertificate: issuer
    }),
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

test("loading functions are present only for enabled mechanisms", () => {
  for (const crlEnabled of [true, false]) {
    for (const ocspEnabled of [true, false]) {
      const provider = createRevocationProvider({
        crlLoader: crlEnabled ? undefined : false,
        ocspLoader: ocspEnabled ? undefined : false
      });
      assert.equal(
        typeof provider.loadCrl,
        crlEnabled ? "function" : "undefined"
      );
      assert.equal(
        typeof provider.loadOcsp,
        ocspEnabled ? "function" : "undefined"
      );
      assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
    }
  }
});

test("rejects incomplete provider requests", async () => {
  const provider = createRevocationProvider({
    crlLoader: async () => new Uint8Array(),
    ocspLoader: async () => new Uint8Array()
  });
  await assert.rejects(
    // @ts-expect-error Provider requests require an issuer for shared downloads.
    provider.loadCrl!({ url: "http://missing.test/crl" }),
    /requires issuerCertificate/
  );
  // @ts-expect-error Provider requests require prepared OCSP request bytes.
  const incompleteOcsp: OcspRequest = {
    url: "http://missing.test/ocsp",
    certificate,
    issuerCertificate: issuer
  };
  await assert.rejects(
    provider.loadOcsp!(incompleteOcsp),
    /requires requestDer/
  );
});

test("bounds concurrency while allowing more than 32 pending downloads", async (t) => {
  const gate = deferred();
  const bothStarted = deferred();
  t.after(() => gate.resolve());
  let active = 0;
  let maxActive = 0;
  let loads = 0;
  const provider = createRevocationProvider({
    ocspLoader: false,
    maxActiveRequests: 2,
    crlLoader: async () => {
      loads++;
      active++;
      maxActive = Math.max(maxActive, active);
      if (active === 2) bothStarted.resolve();
      try {
        await gate.promise;
        return new Uint8Array([1]);
      } finally {
        active--;
      }
    }
  });
  const completed = Promise.all(
    Array.from({ length: 42 }, (_, index) =>
      provider.loadCrl!({
        url: `http://same.test/${index}.crl`,
        issuerCertificate: issuer
      })
    )
  );
  await bothStarted.promise;
  assert.deepEqual(provider.stats(), { active: 2, queued: 40 });
  assert.equal(loads, 2);

  gate.resolve();
  assert.equal((await completed).length, 42);
  assert.equal(loads, 42);
  assert.equal(maxActive, 2);
  assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
});
