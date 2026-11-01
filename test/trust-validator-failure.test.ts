import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { createTrustValidator } from "../src/index.ts";
import { readCertificate } from "./helpers/fixtures.ts";
import {
  intermediate,
  leaf,
  loadCrl,
  now,
  revokedLeaf,
  root
} from "./helpers/trust-validator-fixtures.ts";

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
