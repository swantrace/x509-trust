import assert from "node:assert/strict";
import { test } from "node:test";
import { type CacheStore } from "../src/revocation/cache.ts";
import { createRevocationChecker } from "../src/revocation/revocation-checker.ts";
import { createRevocationProvider } from "../src/revocation/revocation-provider.ts";
import { fixtureTime } from "./helpers/fixtures.ts";
import {
  crl,
  crlOptions,
  ocspOptions,
  prepared,
  profile
} from "./helpers/revocation-checker-fixtures.ts";

test("treats cache corruption and cache outages as misses", async () => {
  for (const failure of ["malformed", "offline"]) {
    const cache: CacheStore = {
      async get() {
        if (failure === "offline") throw new Error("cache offline");
        return "invalid JSON";
      },
      async set() {
        throw new Error("cache offline");
      },
      async delete() {
        throw new Error("cache offline");
      }
    };
    const provider = createRevocationProvider({
      crlLoader: async () => crl,
      ocspLoader: false
    });
    const checkCertificate = createRevocationChecker({
      profile,
      provider,
      cache,
      now: () => fixtureTime
    });
    assert.equal((await checkCertificate(crlOptions)).status, "good");
  }
});

test("explains missing sources without hiding a failed query", async () => {
  const noSources = {
    ...crlOptions,
    prepared: { ...prepared, crlUrls: [], ocspUrls: [] }
  };
  const checkMissing = createRevocationChecker({
    profile,
    provider: createRevocationProvider({
      crlLoader: async () => crl,
      ocspLoader: false
    })
  });
  const missing = await checkMissing(noSources);
  assert.equal(missing.status, "unknown");
  assert.equal(
    missing.status === "unknown" && missing.message,
    "No CRL source is advertised for this certificate"
  );

  const checkDisabled = createRevocationChecker({
    profile,
    provider: createRevocationProvider({ crlLoader: false, ocspLoader: false })
  });
  const disabled = await checkDisabled(noSources);
  assert.equal(
    disabled.status === "unknown" && disabled.message,
    "No usable CRL or OCSP source is configured for this certificate"
  );

  const checkFailed = createRevocationChecker({
    profile,
    provider: createRevocationProvider({
      crlLoader: async () => crl,
      ocspLoader: async () => {
        throw new Error("offline");
      }
    })
  });
  const failed = await checkFailed(ocspOptions);
  assert.equal(
    failed.status === "unknown" && failed.message,
    "Unable to load or validate certificate revocation data"
  );
});

test("checks cached structure and freshness while tolerating extra fields", async () => {
  const cached = {
    der: Buffer.from(crl).toString("base64"),
    expiresAt: fixtureTime + 10_000,
    cachedAt: fixtureTime
  };
  for (const entry of [
    null,
    {},
    { ...cached, der: 123 },
    { ...cached, expiresAt: "later" },
    { ...cached, cachedAt: null },
    { ...cached, expiresAt: fixtureTime },
    { ...cached, cachedAt: fixtureTime + 1 },
    { ...cached, cachedAt: fixtureTime - 1000 },
    { ...cached, extra: "allowed" }
  ]) {
    let loads = 0;
    let discarded = false;
    const check = createRevocationChecker({
      profile,
      now: () => fixtureTime,
      maxCacheAgeMs: 1000,
      cache: {
        async get() {
          return JSON.stringify(entry);
        },
        async set() {},
        async delete() {
          discarded = true;
        }
      },
      provider: createRevocationProvider({
        ocspLoader: false,
        crlLoader: async () => {
          loads++;
          return crl;
        }
      })
    });
    assert.equal((await check(crlOptions)).status, "good");
    const valid = entry !== null && "extra" in entry;
    assert.equal(loads, valid ? 0 : 1, JSON.stringify(entry));
    assert.equal(discarded, !valid, JSON.stringify(entry));
  }
});
