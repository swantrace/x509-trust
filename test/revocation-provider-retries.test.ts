import assert from "node:assert/strict";
import { test } from "node:test";
import { createRevocationProvider } from "../src/index.ts";
import { deferred, issuer } from "./helpers/revocation-provider-fixtures.ts";

test("a failed shared load is removed so a retry performs a fresh download", async () => {
  let loads = 0;
  const started = deferred();
  const provider = createRevocationProvider({
    ocspLoader: false,
    crlLoader: async () => {
      loads++;
      started.resolve();
      if (loads === 1) throw new Error("transport failed");
      return new Uint8Array([8]);
    }
  });
  const first = provider.loadCrl!({
    url: "http://retry.test/crl",
    issuerCertificate: issuer
  });
  await started.promise;
  const second = provider.loadCrl!({
    url: "http://retry.test/crl",
    issuerCertificate: issuer
  });
  await assert.rejects(first, /transport failed/);
  await assert.rejects(second, /transport failed/);
  assert.deepEqual(
    await provider.loadCrl!({
      url: "http://retry.test/crl",
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
    const provider = createRevocationProvider({
      ocspLoader: false,
      crlLoader: async () => {
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
    const first = provider.loadCrl!({
      url,
      issuerCertificate: issuer,
      signal: controller.signal
    });
    await started.promise;
    controller.abort();
    await assert.rejects(first, { name: "AbortError" });

    const retry = provider.loadCrl!({ url, issuerCertificate: issuer });
    await replacementStarted.promise;
    if (outcome === "resolves") abandoned.resolve(new Uint8Array([1]));
    else abandoned.reject(new Error("abandoned download failed"));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(provider.stats(), { active: 1, queued: 0 });

    const subscriber = provider.loadCrl!({ url, issuerCertificate: issuer });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(loads, 2);
    replacement.resolve(new Uint8Array([2]));
    assert.deepEqual(await retry, new Uint8Array([2]));
    assert.deepEqual(await subscriber, new Uint8Array([2]));
    assert.deepEqual(provider.stats(), { active: 0, queued: 0 });
  });
}
