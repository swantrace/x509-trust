import assert from "node:assert/strict";
import { test } from "node:test";
import { CertificateRevocationList } from "pkijs";
import { validateCrl } from "../src/engine/crl.ts";
import {
  type CrlIndex,
  createCrlIndexCache,
  crlDerHash
} from "../src/engine/crl-index-cache.ts";
import { createInlinePkiEngine } from "../src/engine/pki-engine.ts";
import {
  createTrustValidator,
  type ValidationProfileInput
} from "../src/index.ts";
import {
  createCrl,
  createLeafForChain,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

const checkDate = new Date("2026-10-15T00:00:00Z");

function parsedIndex(
  der: Uint8Array<ArrayBuffer>,
  hash: string,
  bytes = der.byteLength
): CrlIndex {
  return {
    derHash: hash,
    crl: CertificateRevocationList.fromBER(der),
    serials: new Set(),
    unsupportedExtensions: false,
    bytes
  };
}

test("bounded CRL index cache evicts least-recently-used entries", async () => {
  const chain = await createSyntheticChain({});
  const der = await createCrl(chain.intermediate, []);
  const cache = createCrlIndexCache({ maxEntries: 2 });
  cache.set(parsedIndex(der, "a"));
  cache.set(parsedIndex(der, "b"));
  assert.equal(cache.get("a")?.derHash, "a");
  cache.set(parsedIndex(der, "c"));
  assert.equal(cache.get("b"), undefined);
  assert.equal(cache.get("a")?.derHash, "a");
  const stats = cache.stats();
  assert.equal(stats.entries, 2);
  assert.equal(stats.evictions, 1);
  assert.ok(stats.bytes > 0);
});

test("CRL index cache enforces its byte budget", async () => {
  const chain = await createSyntheticChain({});
  const der = await createCrl(chain.intermediate, []);
  const cache = createCrlIndexCache({ maxEntries: 4, maxBytes: 100 });
  cache.set(parsedIndex(der, "too-large", 101));
  assert.equal(cache.get("too-large"), undefined);
  assert.equal(cache.stats().entries, 0);
  cache.set(parsedIndex(der, "small", 10));
  assert.equal(cache.get("small")?.derHash, "small");
  assert.equal(cache.stats().entries, 1);
});

test("reuses a parsed CRL while rechecking each certificate, time and issuer", async () => {
  const chain = await createSyntheticChain({});
  const revokedLeaf = await createLeafForChain(chain);
  const crl = await createCrl(chain.intermediate, [revokedLeaf]);
  const cache = createCrlIndexCache({ maxEntries: 4 });
  const good = await validateCrl({
    certificate: chain.leaf.certificate,
    issuerCertificate: chain.intermediate.certificate,
    crl,
    checkDate,
    indexCache: cache
  });
  assert.equal(good.status, "good");
  assert.equal(cache.stats().misses, 1);
  assert.equal(cache.stats().entries, 1);

  const revoked = await validateCrl({
    certificate: revokedLeaf.certificate,
    issuerCertificate: chain.intermediate.certificate,
    crl,
    checkDate,
    indexCache: cache
  });
  assert.equal(revoked.status, "revoked");
  assert.equal(cache.stats().hits, 1);

  const nextUpdate = CertificateRevocationList.fromBER(crl).nextUpdate!.value;
  const expired = await validateCrl({
    certificate: chain.leaf.certificate,
    issuerCertificate: chain.intermediate.certificate,
    crl,
    checkDate: nextUpdate,
    indexCache: cache
  });
  assert.equal(expired.status, "unknown");
  assert.equal(expired.status === "unknown" && expired.code, "CRL_EXPIRED");

  const wrongIssuer = await validateCrl({
    certificate: chain.leaf.certificate,
    issuerCertificate: chain.root.certificate,
    crl,
    checkDate,
    indexCache: cache
  });
  assert.equal(wrongIssuer.status, "unknown");
  assert.equal(
    wrongIssuer.status === "unknown" && wrongIssuer.code,
    "CRL_ISSUER_MISMATCH"
  );
  assert.equal(cache.stats().hits, 3);
});

test("a cached parse never bypasses signature verification", async () => {
  const chain = await createSyntheticChain({});
  const crl = await createCrl(chain.intermediate, []);
  const tampered = Buffer.from(crl);
  tampered[tampered.length - 1] ^= 1;
  const cache = createCrlIndexCache({ maxEntries: 4 });
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await validateCrl({
      certificate: chain.leaf.certificate,
      issuerCertificate: chain.intermediate.certificate,
      crl: tampered,
      checkDate,
      indexCache: cache
    });
    assert.equal(result.status, "unknown");
    assert.equal(
      result.status === "unknown" && result.code,
      "INVALID_CRL_SIGNATURE"
    );
  }
  assert.equal(cache.stats().hits, 1);
  assert.equal(cache.stats().misses, 1);
});

test("matches CRL serials including DER sign padding", async () => {
  const chain = await createSyntheticChain({});
  const paddedLeaf = await createLeafForChain(chain, {
    serial: [0x00, 0xab]
  });
  const crl = await createCrl(chain.intermediate, [paddedLeaf]);
  const result = await validateCrl({
    certificate: paddedLeaf.certificate,
    issuerCertificate: chain.intermediate.certificate,
    crl,
    checkDate,
    indexCache: createCrlIndexCache()
  });
  assert.equal(result.status, "revoked");
});

test("validates CRL index cache options and validator wiring", async () => {
  assert.throws(() => createCrlIndexCache({ maxEntries: 0 }), TypeError);
  assert.throws(() => createCrlIndexCache({ maxBytes: 0 }), TypeError);
  const chain = await createSyntheticChain({});
  const policy: ValidationProfileInput = {
    id: "index:policy",
    version: 1,
    source: "index test",
    anchorSetId: "index:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
  assert.throws(
    () =>
      createTrustValidator({
        trustAnchors: [chain.root.der],
        profile: policy,
        crlIndexCache: { maxEntries: 0 }
      }),
    TypeError
  );
});

test("inline engine reuses the parsed CRL index across validation tasks", async () => {
  const chain = await createSyntheticChain({});
  const crl = await createCrl(chain.intermediate, []);
  const cache = createCrlIndexCache();
  const engine = createInlinePkiEngine({ crlIndexCache: cache });
  const options = {
    certificateDer: chain.leaf.der,
    issuerDer: chain.intermediate.der,
    crl,
    checkDateMs: checkDate.getTime()
  };
  assert.equal((await engine.validateCrl(options)).status, "good");
  assert.equal((await engine.validateCrl(options)).status, "good");
  assert.deepEqual(cache.stats().hits, 1);
  assert.deepEqual(cache.stats().misses, 1);
});

test("CRL DER hashes distinguish different CRLs", async () => {
  const chain = await createSyntheticChain({});
  const clean = await createCrl(chain.intermediate, []);
  const revokedLeaf = await createLeafForChain(chain);
  const revoked = await createCrl(chain.intermediate, [revokedLeaf]);
  assert.notEqual(crlDerHash(clean), crlDerHash(revoked));
});
