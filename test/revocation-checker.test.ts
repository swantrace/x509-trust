import assert from "node:assert/strict";
import { test } from "node:test";
import { CertificateRevocationList } from "pkijs";
import { inlinePkiEngine } from "../src/engine/pki-engine.ts";
import { compileValidationProfile } from "../src/profile/profile.ts";
import { type CacheStore, createMemoryCache } from "../src/revocation/cache.ts";
import { createRevocationChecker } from "../src/revocation/revocation-checker.ts";
import { createRevocationProvider } from "../src/revocation/revocation-provider.ts";
import {
  fixtureTime,
  readCertificateDer,
  readCrl,
  readOcsp
} from "./helpers/fixtures.ts";

const certificateDer = readCertificateDer("leaf");
const issuerDer = readCertificateDer("intermediate");

const crl = readCrl("intermediate-revoked");
const profile = compileValidationProfile();
const path = await inlinePkiEngine.preparePath({
  certificateChain: [certificateDer, issuerDer],
  trustAnchors: [readCertificateDer("root")],
  checkDateMs: fixtureTime
});
assert.ok(path.pathValid);
const prepared = path.certificates[0];
const crlOptions = {
  prepared: {
    ...prepared,
    crlUrls: ["http://crl.example.test/intermediate.crl"],
    ocspUrls: []
  },
  certificateIndex: 0
};
const ocspOptions = {
  prepared: {
    ...prepared,
    crlUrls: [],
    ocspUrls: ["http://ocsp.example.test/status"]
  },
  certificateIndex: 0
};

test("reuses a CRL across certificates but checks each certificate's status", async () => {
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
  assert.equal((await checkCertificate(crlOptions)).status, "good");
  assert.equal(
    (
      await checkCertificate({
        ...crlOptions,
        prepared: {
          ...crlOptions.prepared,
          der: readCertificateDer("revoked-leaf")
        }
      })
    ).status,
    "revoked"
  );
  assert.equal(loads, 1);
});

test("isolates OCSP responses by certificate, issuer, source and request bytes", async () => {
  let loads = 0;
  const revoked = readCertificateDer("revoked-leaf");
  const provider = createRevocationProvider({
    crlLoader: false,
    ocspLoader: async ({ certificate }) => {
      loads++;
      if (Buffer.from(certificate).equals(revoked)) return readOcsp("revoked");
      return readOcsp(
        Buffer.from(certificate).equals(issuerDer)
          ? "intermediate-good"
          : "good"
      );
    }
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => fixtureTime
  });
  assert.equal((await checkCertificate(ocspOptions)).status, "good");
  assert.equal((await checkCertificate(ocspOptions)).status, "good");
  assert.equal(loads, 1);
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: { ...ocspOptions.prepared, der: revoked }
      })
    ).status,
    "revoked"
  );
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: {
          ...ocspOptions.prepared,
          ocspUrls: ["http://other.test/status"]
        }
      })
    ).status,
    "good"
  );
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: {
          ...ocspOptions.prepared,
          der: issuerDer,
          issuerDer: readCertificateDer("root")
        }
      })
    ).status,
    "good"
  );
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: {
          ...ocspOptions.prepared,
          ocspRequestDer: new Uint8Array([0x30, 0x01, 0x00])
        }
      })
    ).status,
    "good"
  );
  assert.equal(loads, 5);
});

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
