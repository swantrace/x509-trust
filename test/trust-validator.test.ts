import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
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

test("public API validates a full path using CRLs for leaf and intermediate", async () => {
  const urls: string[] = [];
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    loadOcsp: false,
    async loadCrl(url) {
      urls.push(url);
      return loadCrl(url);
    }
  });
  const result = await validator.verify({
    certificateChain: [leaf, intermediate]
  });
  assert.equal(result.valid, true);
  const leafCertificate = new X509Certificate(leaf);
  assert.deepEqual(result.leafCertificate, {
    uriSubjectAlternativeNames: ["https://client.example.org/app"],
    publicKeySpkiDer: new Uint8Array(
      leafCertificate.publicKey.export({ format: "der", type: "spki" })
    ),
    fingerprint256: leafCertificate.fingerprint256,
    serialNumber: leafCertificate.serialNumber,
    notBeforeMs: Date.parse(leafCertificate.validFrom),
    notAfterMs: Date.parse(leafCertificate.validTo)
  });
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
});

test("public API supports OCSP callbacks with DER certificate and issuer context", async () => {
  const urls: string[] = [];
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    loadCrl: false,
    async loadOcsp({ url, certificate, issuerCertificate }) {
      urls.push(url);
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
  assert.deepEqual(urls, [
    "http://ocsp.example.test/intermediate",
    "http://ocsp.example.test/root"
  ]);
});

test("returns revoked without waiting for another certificate's request", async () => {
  let loads = 0;
  let aborted = false;
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    loadOcsp: false,
    async loadCrl(url, { signal } = {}) {
      loads++;
      if (url.endsWith("/root.crl")) {
        return new Promise<Uint8Array>((_resolve, reject) => {
          signal?.addEventListener(
            "abort",
            () => {
              aborted = true;
              reject(signal.reason);
            },
            { once: true }
          );
        });
      }
      return loadCrl(url);
    }
  });
  const result = await validator.verify({
    certificateChain: [revokedLeaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(result.certificateIndex, 0);
  assert.equal("leafCertificate" in result, false);
  assert.equal(loads, 2);
  assert.equal(aborted, true);
});

test("reports the index of a revoked intermediate certificate", async () => {
  const { Certificate, CertificateRevocationList, RevokedCertificate, Time } =
    await import("pkijs");
  const decode = (pem: string) =>
    Certificate.fromBER(new X509Certificate(pem).raw);
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const signedRoot = decode(root);
  await signedRoot.subjectPublicKeyInfo.importKey(keys.publicKey);
  await signedRoot.sign(keys.privateKey, "SHA-256");
  const signedIntermediate = decode(intermediate);
  await signedIntermediate.sign(keys.privateKey, "SHA-256");
  const revokedCrl = CertificateRevocationList.fromBER(readCrl("root"));
  revokedCrl.revokedCertificates = [
    new RevokedCertificate({
      userCertificate: signedIntermediate.serialNumber,
      revocationDate: new Time({ type: 1, value: checkDate })
    })
  ];
  await revokedCrl.sign(keys.privateKey, "SHA-256");

  const result = await createTrustValidator({
    trustAnchors: [new Uint8Array(signedRoot.toSchema().toBER(false))],
    now,
    loadOcsp: false,
    loadCrl: async (url) =>
      url.endsWith("/root.crl")
        ? new Uint8Array(revokedCrl.toSchema().toBER(false))
        : Buffer.of(0)
  }).verify({
    certificateChain: [
      leaf,
      new Uint8Array(signedIntermediate.toSchema().toBER(false))
    ]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(result.certificateIndex, 1);
});

test("a good leaf status is insufficient when intermediate status cannot be established", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    loadOcsp: false,
    async loadCrl(url) {
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
});

test("rejects invalid, untrusted and expired paths before calling loaders", async () => {
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [readCertificate("untrusted-root")],
    now,
    async loadCrl(url) {
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
    async loadCrl(url) {
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
  assert.equal(loads, 0);
});

test("does not silently skip revocation checks when both loaders are disabled", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    loadCrl: false,
    loadOcsp: false
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
    async loadOcsp() {
      ocspLoads++;
      return readOcsp("unknown");
    },
    async loadCrl(url) {
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
    loadCrl,
    async loadOcsp() {
      throw new Error("OCSP offline");
    }
  });
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate] })).valid,
    true
  );
});

test("never overrides an authenticated revoked response with a good CRL", async () => {
  const crlUrls: string[] = [];
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    async loadOcsp() {
      return readOcsp("revoked");
    },
    async loadCrl(url) {
      crlUrls.push(url);
      return readCrl("intermediate-clean");
    }
  });
  const result = await validator.verify({
    certificateChain: [revokedLeaf, intermediate]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(
    crlUrls.includes("http://crl.example.test/intermediate.crl"),
    false
  );
});

test("returns a validation failure when all evidence is unusable", async () => {
  const validator = createTrustValidator({
    trustAnchors: [root],
    now,
    loadOcsp: false,
    async loadCrl() {
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
    loadOcsp: false as const,
    async loadCrl(url: string) {
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
    loadCrl,
    loadOcsp: false,
    now
  });
  anchor.fill(0);
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate] })).valid,
    true
  );
  assert.throws(() => createTrustValidator({ trustAnchors: [] }), TypeError);
  const invalid = await createTrustValidator({
    trustAnchors: ["invalid certificate"]
  }).verify({ certificateChain: [leaf, intermediate] });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.code, "INVALID_CERTIFICATE");
  await assert.rejects(
    validator.verify({
      certificateChain: [leaf, intermediate],
      checkDate: new Date(NaN)
    }),
    TypeError
  );
});
