import assert from "node:assert/strict";
import { test } from "node:test";
import { CertificateRevocationList } from "pkijs";
import { type CacheStore } from "../src/revocation/cache.ts";
import { createRevocationChecker } from "../src/revocation/revocation-checker.ts";
import { createRevocationProvider } from "../src/revocation/revocation-provider.ts";
import { fixtureTime, readCrl, readOcsp } from "./helpers/fixtures.ts";
import {
  crl,
  crlOptions,
  ocspOptions,
  profile
} from "./helpers/revocation-checker-fixtures.ts";

test("does not cache unusable CRLs or signed unknown OCSP statuses", async () => {
  let loads = 0;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      loads++;
      return readCrl("intermediate-expired");
    },
    ocspLoader: async () => {
      loads++;
      return readOcsp("unknown");
    }
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => fixtureTime
  });
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.equal((await checkCertificate(crlOptions)).status, "unknown");
    assert.equal((await checkCertificate(ocspOptions)).status, "unknown");
  }
  assert.equal(loads, 4);
});

test("accepts an asynchronous external cache shared by checker instances", async () => {
  const entries = new Map<string, string>();
  let ttl = 0;
  const cache: CacheStore = {
    async get(key) {
      return entries.get(key) ?? null;
    },
    async set(key, value, ttlMs) {
      entries.set(key, value);
      ttl = ttlMs;
    },
    async delete(key) {
      entries.delete(key);
    }
  };
  let loads = 0;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      loads++;
      return crl;
    },
    ocspLoader: false
  });
  const configuration = {
    profile,
    provider,
    cache,
    now: () => fixtureTime,
    cacheKeyPrefix: "sahara:test"
  };
  await createRevocationChecker(configuration)(crlOptions);
  assert.equal(
    (await createRevocationChecker(configuration)(crlOptions)).status,
    "good"
  );
  assert.equal(loads, 1);
  assert.equal(ttl, 60 * 60 * 1000);
  assert.ok([...entries.keys()][0].startsWith("sahara:test:crl:"));
  const stored = JSON.parse([...entries.values()][0]);
  assert.equal(stored.der, crl.toString("base64"));
  assert.equal(stored.status, undefined);
});

test("revalidates cached bytes and replaces a corrupted cached signature", async () => {
  const entries = new Map<string, string>();
  const cache: CacheStore = {
    async get(key) {
      return entries.get(key) ?? null;
    },
    async set(key, value) {
      entries.set(key, value);
    },
    async delete(key) {
      entries.delete(key);
    }
  };
  let loads = 0;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      loads++;
      return crl;
    },
    ocspLoader: false
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    cache,
    now: () => fixtureTime
  });
  await checkCertificate(crlOptions);
  const key = [...entries.keys()][0];
  const stored = JSON.parse(entries.get(key)!);
  const modified = Buffer.from(crl);
  modified[modified.length - 1] ^= 1;
  entries.set(
    key,
    JSON.stringify({
      ...stored,
      der: modified.toString("base64"),
      status: "good"
    })
  );
  assert.equal((await checkCertificate(crlOptions)).status, "good");
  assert.equal(loads, 2);
  assert.equal(JSON.parse(entries.get(key)!).der, crl.toString("base64"));
});

test("rechecks cached evidence when an explicit validation date changes", async () => {
  let loads = 0;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      loads++;
      return crl;
    },
    ocspLoader: false
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => fixtureTime
  });
  await checkCertificate(crlOptions);
  const nextUpdate = CertificateRevocationList.fromBER(crl).nextUpdate!.value;
  const result = await checkCertificate({
    ...crlOptions,
    checkDateMs: nextUpdate.getTime()
  });
  assert.equal(result.status, "unknown");
  assert.equal(result.findings.revocation.crl[0].code, "CRL_EXPIRED");
  assert.equal(loads, 2);
});
