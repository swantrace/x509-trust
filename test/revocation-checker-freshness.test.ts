import assert from "node:assert/strict";
import { test } from "node:test";
import { CertificateRevocationList } from "pkijs";
import { createMemoryCache } from "../src/revocation/cache.ts";
import { createRevocationChecker } from "../src/revocation/revocation-checker.ts";
import { createRevocationProvider } from "../src/revocation/revocation-provider.ts";
import { fixtureTime, readOcsp } from "./helpers/fixtures.ts";
import {
  crl,
  crlOptions,
  ocspOptions,
  profile
} from "./helpers/revocation-checker-fixtures.ts";

test("reloads at the configured maximum cache age", async () => {
  let time = fixtureTime;
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
    now: () => time,
    maxCacheAgeMs: 1000
  });
  await checkCertificate(crlOptions);
  time += 1000;
  assert.equal((await checkCertificate(crlOptions)).status, "good");
  assert.equal(loads, 2);
});

test("never serves a CRL after nextUpdate, even when its cache age allows longer", async () => {
  const parsed = CertificateRevocationList.fromBER(crl);
  let time = parsed.nextUpdate!.value.getTime() - 1000;
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
    now: () => time
  });
  assert.equal((await checkCertificate(crlOptions)).status, "good");
  time += 1000;
  const result = await checkCertificate(crlOptions);
  assert.equal(result.status, "unknown");
  assert.equal(result.findings.revocation.crl[0].code, "CRL_EXPIRED");
  assert.equal(loads, 2);
});

test("uses the current time after loading a freshly produced response", async () => {
  let time = fixtureTime - 1000;
  const provider = createRevocationProvider({
    crlLoader: false,
    ocspLoader: async () => {
      time = fixtureTime;
      return readOcsp("good");
    }
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => time
  });
  assert.equal((await checkCertificate(ocspOptions)).status, "good");
});

test("honors a stricter cache age when reusing a shared store", async () => {
  let time = fixtureTime;
  const now = () => time;
  const cache = createMemoryCache({ now });
  let loads = 0;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      loads++;
      return crl;
    },
    ocspLoader: false
  });
  await createRevocationChecker({
    profile,
    provider,
    cache,
    now,
    maxCacheAgeMs: 10000
  })(crlOptions);
  time += 2000;
  await createRevocationChecker({
    profile,
    provider,
    cache,
    now,
    maxCacheAgeMs: 1000
  })(crlOptions);
  assert.equal(loads, 2);
});

test("does not fall back to expired cached data when the loader fails", async () => {
  let time = fixtureTime;
  let offline = false;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      if (offline) throw new Error("source offline");
      return crl;
    },
    ocspLoader: false
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => time,
    maxCacheAgeMs: 1000
  });
  await checkCertificate(crlOptions);
  time += 1000;
  offline = true;
  const result = await checkCertificate(crlOptions);
  assert.equal(result.status, "unknown");
  assert.equal(result.findings.revocation.crl[0].code, "EVIDENCE_CHECK_FAILED");
});
