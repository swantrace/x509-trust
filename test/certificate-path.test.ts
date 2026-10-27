import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { validateCertificatePath } from "../src/certificate-path.ts";

function readFixture(name: string): string {
  return readFileSync(
    new URL(`./fixtures/${name}.pem`, import.meta.url),
    "utf8"
  );
}

const root = readFixture("root");
const intermediate = readFixture("intermediate");
const leaf = readFixture("leaf");
const untrustedRoot = readFixture("untrusted-root");
const leafCertificate = new X509Certificate(leaf);
const checkDate = new Date(Date.parse(leafCertificate.validFrom) + 1000);

test("validates a leaf-first chain ending at a configured trust anchor", async () => {
  const result = await validateCertificatePath({
    certificateChain: [leaf, intermediate, root],
    trustAnchors: [root],
    checkDate
  });

  assert.ok(result.pathValid);
  assert.equal(
    result.trustAnchorFingerprint256,
    new X509Certificate(root).fingerprint256
  );
  assert.deepEqual(
    result.certificatePath.map(
      (certificate) => new X509Certificate(certificate).fingerprint256
    ),
    [leaf, intermediate, root].map(
      (certificate) => new X509Certificate(certificate).fingerprint256
    )
  );
});

test("accepts DER certificates and adds the configured root to the path", async () => {
  const result = await validateCertificatePath({
    certificateChain: [
      leafCertificate.raw,
      new X509Certificate(intermediate).raw
    ],
    trustAnchors: [new X509Certificate(root).raw],
    checkDate
  });

  assert.ok(result.pathValid);
  assert.equal(result.certificatePath.length, 3);
  assert.equal(
    result.trustAnchorFingerprint256,
    new X509Certificate(root).fingerprint256
  );
});

test("rejects a chain whose root was supplied by the client but is not trusted", async () => {
  const result = await validateCertificatePath({
    certificateChain: [leaf, intermediate, root],
    trustAnchors: [untrustedRoot],
    checkDate
  });

  assert.ok(!result.pathValid);
  assert.equal(result.code, "INVALID_CERTIFICATE_PATH");
});

test("rejects an expired leaf while its root and intermediate remain valid", async () => {
  const result = await validateCertificatePath({
    certificateChain: [leaf, intermediate],
    trustAnchors: [root],
    checkDate: new Date(Date.parse(leafCertificate.validTo) + 1000)
  });

  assert.ok(!result.pathValid);
  assert.equal(result.code, "INVALID_CERTIFICATE_PATH");
});

test("rejects a certificate whose signature has been modified", async () => {
  const modifiedLeaf = Buffer.from(leafCertificate.raw);
  modifiedLeaf[modifiedLeaf.length - 1] ^= 1;
  const result = await validateCertificatePath({
    certificateChain: [modifiedLeaf, intermediate],
    trustAnchors: [root],
    checkDate
  });

  assert.equal(result.pathValid, false);
});

test("rejects malformed certificates", async () => {
  const result = await validateCertificatePath({
    certificateChain: ["not a certificate"],
    trustAnchors: [root],
    checkDate
  });

  assert.ok(!result.pathValid);
  assert.equal(result.code, "INVALID_CERTIFICATE");
});

test("rejects an empty certificate chain", async () => {
  const result = await validateCertificatePath({
    certificateChain: [],
    trustAnchors: [root],
    checkDate
  });

  assert.equal(result.pathValid, false);
});
