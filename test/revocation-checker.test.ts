import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CertificateRevocationList } from "pkijs";
import { type CacheStore, createMemoryCache } from "../src/cache.ts";
import { createRevocationChecker } from "../src/revocation-checker.ts";

function readCertificate(name: string): Uint8Array {
  const pem = readFileSync(new URL(`./fixtures/${name}.pem`, import.meta.url));
  return new X509Certificate(pem).raw;
}

function readCrl(name: string) {
  const pem = readFileSync(
    new URL(`./fixtures/crl/${name}.crl.pem`, import.meta.url),
    "utf8"
  );
  return Buffer.from(pem.replace(/-----[^\n]+-----/g, ""), "base64");
}

function readOcsp(name: string) {
  return readFileSync(new URL(`./fixtures/ocsp/${name}.der`, import.meta.url));
}

const certificate = readCertificate("leaf");
const issuerCertificate = readCertificate("intermediate");
const fixtureTime = Date.parse(
  readFileSync(
    new URL("./fixtures/validation-time.txt", import.meta.url),
    "utf8"
  ).trim()
);
const crl = readCrl("intermediate-revoked");
const baseOptions = {
  certificate,
  issuerCertificate,
  source: "http://crl.example.test/intermediate.crl"
};

test("reuses a CRL across certificates but checks each certificate's status", async () => {
  let loads = 0;
  const checker = createRevocationChecker({ now: () => fixtureTime });
  const load = async () => {
    loads++;
    return crl;
  };
  assert.equal(
    (await checker.checkCrl({ ...baseOptions, load })).status,
    "good"
  );
  assert.equal(
    (
      await checker.checkCrl({
        ...baseOptions,
        certificate: readCertificate("revoked-leaf"),
        load
      })
    ).status,
    "revoked"
  );
  assert.equal(loads, 1);
});

test("isolates OCSP responses by certificate, issuer and source", async () => {
  let loads = 0;
  const checker = createRevocationChecker({ now: () => fixtureTime });
  const load = async () => {
    loads++;
    return readOcsp("good");
  };
  const options = {
    ...baseOptions,
    source: "http://ocsp.example.test/status",
    load
  };
  assert.equal((await checker.checkOcsp(options)).status, "good");
  assert.equal((await checker.checkOcsp(options)).status, "good");
  assert.equal(loads, 1);
  assert.equal(
    (
      await checker.checkOcsp({
        ...options,
        certificate: readCertificate("revoked-leaf"),
        load: async () => {
          loads++;
          return readOcsp("revoked");
        }
      })
    ).status,
    "revoked"
  );
  assert.equal(
    (
      await checker.checkOcsp({
        ...options,
        source: "http://other.test/status"
      })
    ).status,
    "good"
  );
  assert.equal(
    (
      await checker.checkOcsp({
        ...options,
        certificate: issuerCertificate,
        issuerCertificate: readCertificate("root"),
        load: async () => {
          loads++;
          return readOcsp("intermediate-good");
        }
      })
    ).status,
    "good"
  );
  assert.equal(loads, 4);
});

test("reloads at the configured maximum cache age", async () => {
  let time = fixtureTime;
  let loads = 0;
  const checker = createRevocationChecker({
    now: () => time,
    maxCacheAgeMs: 1000
  });
  const options = {
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  };
  await checker.checkCrl(options);
  time += 1000;
  assert.equal((await checker.checkCrl(options)).status, "good");
  assert.equal(loads, 2);
});

test("never serves a CRL after nextUpdate, even when its cache age allows longer", async () => {
  const parsed = CertificateRevocationList.fromBER(crl);
  let time = parsed.nextUpdate!.value.getTime() - 1000;
  let loads = 0;
  const checker = createRevocationChecker({ now: () => time });
  const options = {
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  };
  assert.equal((await checker.checkCrl(options)).status, "good");
  time += 1000;
  const result = await checker.checkCrl(options);
  assert.equal(result.status, "unknown");
  assert.equal(result.code, "CRL_EXPIRED");
  assert.equal(loads, 2);
});

test("uses the current time after loading a freshly produced response", async () => {
  let time = fixtureTime - 1000;
  const checker = createRevocationChecker({ now: () => time });
  const result = await checker.checkOcsp({
    ...baseOptions,
    load: async () => {
      time = fixtureTime;
      return readOcsp("good");
    }
  });
  assert.equal(result.status, "good");
});

test("does not cache unusable CRLs or signed unknown OCSP statuses", async () => {
  let loads = 0;
  const checker = createRevocationChecker({ now: () => fixtureTime });
  const loadCrl = async () => {
    loads++;
    return readCrl("intermediate-expired");
  };
  const loadOcsp = async () => {
    loads++;
    return readOcsp("unknown");
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.equal(
      (await checker.checkCrl({ ...baseOptions, load: loadCrl })).status,
      "unknown"
    );
    assert.equal(
      (await checker.checkOcsp({ ...baseOptions, load: loadOcsp })).status,
      "unknown"
    );
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
  const configuration = {
    cache,
    now: () => fixtureTime,
    cacheKeyPrefix: "sahara:test"
  };
  let loads = 0;
  const options = {
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  };
  await createRevocationChecker(configuration).checkCrl(options);
  assert.equal(
    (await createRevocationChecker(configuration).checkCrl(options)).status,
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
  const checker = createRevocationChecker({ cache, now: () => fixtureTime });
  let loads = 0;
  const options = {
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  };
  await checker.checkCrl(options);
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
  assert.equal((await checker.checkCrl(options)).status, "good");
  assert.equal(loads, 2);
  assert.equal(JSON.parse(entries.get(key)!).der, crl.toString("base64"));
});

test("rechecks cached evidence when an explicit validation date changes", async () => {
  const checker = createRevocationChecker({ now: () => fixtureTime });
  let loads = 0;
  const options = {
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  };
  await checker.checkCrl(options);
  const nextUpdate = CertificateRevocationList.fromBER(crl).nextUpdate!.value;
  const result = await checker.checkCrl({ ...options, checkDate: nextUpdate });
  assert.equal(result.status, "unknown");
  assert.equal(result.code, "CRL_EXPIRED");
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
    const checker = createRevocationChecker({ cache, now: () => fixtureTime });
    assert.equal(
      (await checker.checkCrl({ ...baseOptions, load: async () => crl }))
        .status,
      "good"
    );
  }
});

test("honors a stricter cache age when reusing a shared store", async () => {
  let time = fixtureTime;
  const now = () => time;
  const cache = createMemoryCache({ now });
  let loads = 0;
  const options = {
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  };
  await createRevocationChecker({ cache, now, maxCacheAgeMs: 10000 }).checkCrl(
    options
  );
  time += 2000;
  await createRevocationChecker({ cache, now, maxCacheAgeMs: 1000 }).checkCrl(
    options
  );
  assert.equal(loads, 2);
});

test("does not fall back to expired cached data when the loader fails", async () => {
  let time = fixtureTime;
  const checker = createRevocationChecker({
    now: () => time,
    maxCacheAgeMs: 1000
  });
  await checker.checkCrl({ ...baseOptions, load: async () => crl });
  time += 1000;
  await assert.rejects(
    checker.checkCrl({
      ...baseOptions,
      load: async () => {
        throw new Error("source offline");
      }
    }),
    /source offline/
  );
});

test("snapshots DER context across asynchronous cache and loader callbacks", async () => {
  const inputCertificate = Uint8Array.from(certificate);
  const inputIssuer = Uint8Array.from(issuerCertificate);
  const checker = createRevocationChecker({ now: () => fixtureTime });
  let loads = 0;
  const first = await checker.checkCrl({
    ...baseOptions,
    certificate: inputCertificate,
    issuerCertificate: inputIssuer,
    load: async () => {
      loads++;
      inputCertificate.fill(0);
      inputIssuer.fill(0);
      return crl;
    }
  });
  assert.equal(first.status, "good");
  const cached = await checker.checkCrl({
    ...baseOptions,
    load: async () => {
      loads++;
      return crl;
    }
  });
  assert.equal(cached.status, "good");
  assert.equal(loads, 1);
});
