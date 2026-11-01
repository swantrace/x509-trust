import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { inlinePkiEngine } from "../src/engine/pki-engine.ts";
import { createTrustValidator } from "../src/index.ts";
import { readOcsp } from "./helpers/fixtures.ts";
import {
  intermediate,
  leaf,
  loadCrl,
  now,
  root
} from "./helpers/trust-validator-fixtures.ts";

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
