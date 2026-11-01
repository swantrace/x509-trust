import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { inlinePkiEngine } from "../src/engine/pki-engine.ts";
import { createMemoryCache, createTrustValidator } from "../src/index.ts";

function readCertificate(name: string): string {
  return readFileSync(
    new URL(`./fixtures/${name}.pem`, import.meta.url),
    "utf8"
  );
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

async function loadCrl(url: string): Promise<Uint8Array> {
  return url.endsWith("/root.crl")
    ? readCrl("root")
    : readCrl("intermediate-revoked");
}

const root = readCertificate("root");
const intermediate = readCertificate("intermediate");
const leaf = readCertificate("leaf");
const revokedLeaf = readCertificate("revoked-leaf");
const checkDate = new Date(
  readFileSync(
    new URL("./fixtures/validation-time.txt", import.meta.url),
    "utf8"
  ).trim()
);
const now = () => checkDate.getTime();

test("public API validates a full path using CRLs for leaf and intermediate", async (t) => {
  const urls: string[] = [];
  const engine = { ...inlinePkiEngine };
  const validateCrl = t.mock.method(engine, "validateCrl");
  const validator = createTrustValidator({
    trustAnchors: [root],
    engine,
    now,
    ocspLoader: false,
    async crlLoader({ url }) {
      urls.push(url);
      return loadCrl(url);
    }
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, true);
  assert.equal(validateCrl.mock.callCount(), 2);
  assert.equal(
    result.trustAnchorFingerprint256,
    new X509Certificate(root).fingerprint256
  );
  assert.deepEqual(
    result.certificatePath.map(
      (der) => new X509Certificate(der).fingerprint256
    ),
    [leaf, intermediate, root].map(
      (pem) => new X509Certificate(pem).fingerprint256
    )
  );
  assert.deepEqual(urls, [
    "http://crl.example.test/intermediate.crl",
    "http://crl.example.test/root.crl"
  ]);
  assert.ok(result.valid);
  assert.equal(
    result.leafCertificate.fingerprint256,
    new X509Certificate(leaf).fingerprint256
  );
  assert.deepEqual(result.leafCertificate.uriSubjectAlternativeNames, [
    "https://client.example.org/app"
  ]);
  assert.deepEqual(result.leafCertificate.keyUsages, ["digitalSignature"]);
  assert.deepEqual(
    result.evidence.map(({ certificateIndex, mechanism, status }) => ({
      certificateIndex,
      mechanism,
      status
    })),
    [
      { certificateIndex: 0, mechanism: "crl", status: "good" },
      { certificateIndex: 1, mechanism: "crl", status: "good" }
    ]
  );
  assert.ok(
    result.evidence.every(
      (entry) => entry.authenticated && entry.fresh && entry.checkedAtMs > 0
    )
  );
  assert.equal(result.findings.length, 2);
  assert.deepEqual(
    result.findings.map((entry) => entry.certificateIndex),
    [0, 1]
  );
  for (const finding of result.findings) {
    assert.equal(finding.pathValid, true);
    assert.equal(finding.revocation.crl.length, 1);
    assert.equal(finding.revocation.crl[0].status, "good");
    assert.equal(finding.revocation.crl[0].authenticated, true);
    assert.equal(finding.revocation.crl[0].fresh, true);
    assert.deepEqual(finding.revocation.ocsp, []);
  }

  // Results are independent snapshots: mutating them must not change trust.
  result.leafCertificate.der.fill(0);
  result.leafCertificate.publicKeySpkiDer.fill(0);
  result.certificatePath[0].fill(0);
  const repeated = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(repeated.valid, true);
  assert.equal(validateCrl.mock.callCount(), 4);
  assert.equal(
    repeated.leafCertificate.fingerprint256,
    new X509Certificate(leaf).fingerprint256
  );
});

test("public API supports OCSP request objects with prepared DER and issuer context", async (t) => {
  const urls: string[] = [];
  const engine = { ...inlinePkiEngine };
  const validateOcsp = t.mock.method(engine, "validateOcsp");
  const validator = createTrustValidator({
    trustAnchors: [root],
    engine,
    now,
    crlLoader: false,
    async ocspLoader({
      url,
      certificate,
      issuerCertificate,
      requestDer,
      signal
    }) {
      urls.push(url);
      assert.ok(requestDer.byteLength > 0);
      assert.ok(signal instanceof AbortSignal);
      const client = new X509Certificate(certificate);
      assert.equal(
        client.checkIssued(new X509Certificate(issuerCertificate)),
        true
      );
      return url.endsWith("/root")
        ? readOcsp("intermediate-good")
        : readOcsp("good");
    }
  });
  const result = await validator.verify({
    certificateChain: [new X509Certificate(leaf).raw, intermediate, root]
  });
  assert.equal(result.valid, true);
  assert.equal(validateOcsp.mock.callCount(), 2);
  assert.deepEqual(urls, [
    "http://ocsp.example.test/intermediate",
    "http://ocsp.example.test/root"
  ]);
});

test("reports revoked while other certificate pipelines may still be pending", async () => {
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    ocspLoader: false,
    async crlLoader({ url }) {
      loads++;
      return loadCrl(url);
    }
  });
  const result = await validator.verify({
    certificateChain: [revokedLeaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(result.certificateIndex, 0);
  assert.ok(loads >= 1);
  assert.equal("leafCertificate" in result, false);
  assert.equal(result.evidence?.length, 1);
  assert.deepEqual(
    result.evidence?.map(({ mechanism, status }) => ({ mechanism, status })),
    [{ mechanism: "crl", status: "revoked" }]
  );
  assert.equal(result.findings?.[0].revocation.crl[0].status, "revoked");
  assert.equal(result.findings?.[0].revocation.crl[0].authenticated, true);
});

test("a good leaf status is insufficient when intermediate status cannot be established", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    ocspLoader: false,
    async crlLoader({ url }) {
      if (url.endsWith("/root.crl")) throw new Error("root CRL unavailable");
      return loadCrl(url);
    }
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "REVOCATION_STATUS_UNKNOWN");
  assert.equal(result.certificateIndex, 1);
  assert.equal(result.findings?.[1].revocation.crl[0].status, "unknown");
  assert.equal(result.findings?.[1].revocation.crl[0].authenticated, false);
  assert.equal(result.findings?.[1].revocation.crl[0].fresh, false);
});

test("rejects invalid, untrusted and expired paths before calling loaders", async () => {
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [readCertificate("untrusted-root")],
    now,
    async crlLoader({ url }) {
      loads++;
      return loadCrl(url);
    }
  });
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate, root] }))
      .valid,
    false
  );
  const malformed = await validator.verify({
    certificateChain: ["not a certificate"]
  });
  assert.equal(malformed.valid, false);
  assert.equal(malformed.code, "INVALID_CERTIFICATE");
  const trusted = createTrustValidator({
    trustAnchors: [root],
    now,
    async crlLoader({ url }) {
      loads++;
      return loadCrl(url);
    }
  });
  const expired = await trusted.verify({
    certificateChain: [leaf, intermediate],
    checkDate: new Date(Date.parse(new X509Certificate(leaf).validTo) + 1000)
  });
  assert.equal(expired.valid, false);
  assert.equal(expired.code, "INVALID_CERTIFICATE_PATH");
  assert.equal("leafCertificate" in expired, false);
  assert.equal(loads, 0);
});

test("does not silently skip revocation checks when both loaders are disabled", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    crlLoader: false,
    ocspLoader: false
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "REVOCATION_STATUS_UNKNOWN");
});

test("falls back from unknown OCSP status to valid CRLs", async () => {
  let ocspLoads = 0;
  let crlLoads = 0;
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    async ocspLoader() {
      ocspLoads++;
      return readOcsp("unknown");
    },
    async crlLoader({ url }) {
      crlLoads++;
      return loadCrl(url);
    }
  });
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate] })).valid,
    true
  );
  assert.equal(ocspLoads, 2);
  assert.equal(crlLoads, 2);
});

test("falls back from OCSP transport failures to valid CRLs", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    crlLoader: ({ url }) => loadCrl(url),
    async ocspLoader() {
      throw new Error("OCSP offline");
    }
  });
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate] })).valid,
    true
  );
});

test("never overrides an authenticated revoked response with a good CRL", async () => {
  let crlLoads = 0;
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    async ocspLoader() {
      return readOcsp("revoked");
    },
    async crlLoader() {
      crlLoads++;
      return readCrl("intermediate-clean");
    }
  });
  const result = await validator.verify({
    certificateChain: [revokedLeaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.deepEqual(
    result.evidence?.map(({ mechanism, status }) => ({ mechanism, status })),
    [{ mechanism: "ocsp", status: "revoked" }]
  );
  assert.ok(crlLoads <= 1);
});

test("returns a validation failure when all evidence is unusable", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    ocspLoader: false,
    async crlLoader() {
      return Buffer.from("invalid CRL");
    }
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "REVOCATION_STATUS_UNKNOWN");
});

test("shares injected cache storage but still validates trust for every request", async () => {
  const cache = createMemoryCache({ now });
  let loads = 0;
  const configuration = {
    trustAnchors: [root],
    cache,
    now,
    ocspLoader: false as const,
    async crlLoader({ url }: { url: string }) {
      loads++;
      return loadCrl(url);
    }
  };
  const input = { certificateChain: [leaf, intermediate] };
  assert.equal(
    (await createTrustValidator(configuration).verify(input)).valid,
    true
  );
  assert.equal(
    (await createTrustValidator(configuration).verify(input)).valid,
    true
  );
  assert.equal(loads, 2);
  const untrusted = createTrustValidator({
    ...configuration,
    trustAnchors: [readCertificate("untrusted-root")]
  });
  assert.equal((await untrusted.verify(input)).valid, false);
  assert.equal(loads, 2);
});

test("snapshots configured trust anchors and reports configuration errors early", async () => {
  const anchor = Buffer.from(new X509Certificate(root).raw);
  const validator = createTrustValidator({
    trustAnchors: [anchor],
    crlLoader: ({ url }) => loadCrl(url),
    ocspLoader: false,
    now
  });
  anchor.fill(0);
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate] })).valid,
    true
  );
  assert.throws(() => createTrustValidator({ trustAnchors: [] }), TypeError);
  assert.throws(() =>
    createTrustValidator({ trustAnchors: ["invalid certificate"] })
  );
  await assert.rejects(
    validator.verify({
      certificateChain: [leaf, intermediate],
      checkDate: new Date(NaN)
    }),
    TypeError
  );
});
