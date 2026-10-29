import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { certificateDer } from "../src/certificates.ts";
import { createTrustValidator } from "../src/index.ts";

const pem = readFileSync(
  new URL("./fixtures/leaf.pem", import.meta.url),
  "utf8"
);
const der = new X509Certificate(pem).raw;

test("Rust normalization agrees with Node for PEM labels, CRLF, buffers and first-certificate selection", () => {
  for (const label of [
    "CERTIFICATE",
    "X509 CERTIFICATE",
    "TRUSTED CERTIFICATE"
  ]) {
    const encoded = pem.replaceAll("CERTIFICATE", label);
    for (const input of [
      encoded,
      encoded.replaceAll("\n", "\r\n"),
      Buffer.from(encoded),
      `${encoded}\n${encoded}`
    ]) {
      assert.deepEqual(
        certificateDer(input),
        new Uint8Array(new X509Certificate(input).raw)
      );
    }
  }
});

test("Rust normalization respects DER view boundaries and returns an independent snapshot", () => {
  const padded = Buffer.concat([Buffer.of(0xff), der, Buffer.of(0xff)]);
  const view = padded.subarray(1, padded.length - 1);
  const result = certificateDer(view);
  assert.deepEqual(result, new Uint8Array(der));
  view.fill(0);
  assert.deepEqual(result, new Uint8Array(der));
});

test("rejects malformed PEM envelopes, Base64, DER and decoded trailing bytes", () => {
  const trailing = Buffer.concat([der, Buffer.of(0)]);
  const invalid = [
    "not a certificate",
    pem.replace("-----END CERTIFICATE-----", "-----END PRIVATE KEY-----"),
    pem.replace(
      "-----BEGIN CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----junk"
    ),
    pem.replaceAll("CERTIFICATE", "PRIVATE KEY"),
    pem.replace("-----END CERTIFICATE-----", ""),
    "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----",
    `-----BEGIN CERTIFICATE-----\n${trailing.toString("base64")}\n-----END CERTIFICATE-----`,
    new Uint8Array(),
    der.subarray(0, der.length - 1),
    trailing
  ];
  for (const input of invalid)
    assert.throws(() => certificateDer(input), TypeError);
});

test("rejects malformed trust anchors in the path worker before any loader runs", async () => {
  for (const anchor of [
    Buffer.concat([der, Buffer.of(0)]),
    pem.replace("-----END CERTIFICATE-----", "-----END PRIVATE KEY-----")
  ]) {
    let loads = 0;
    const validator = createTrustValidator({
      trustAnchors: [anchor],
      loadCrl: async () => {
        loads++;
        return der;
      }
    });
    const result = await validator.verify({ certificateChain: [pem] });
    assert.equal(result.valid, false);
    assert.equal(result.code, "INVALID_CERTIFICATE");
    assert.equal(loads, 0);
  }
});
