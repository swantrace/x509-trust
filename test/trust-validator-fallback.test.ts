import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustValidator } from "../src/index.ts";
import { readCrl, readOcsp } from "./helpers/fixtures.ts";
import {
  intermediate,
  leaf,
  loadCrl,
  now,
  revokedLeaf,
  root
} from "./helpers/trust-validator-fixtures.ts";

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
