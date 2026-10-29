import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  AltName,
  Certificate,
  Extension,
  GeneralName,
  id_SubjectAltName
} from "pkijs";
import { getUriSubjectAlternativeNames } from "../src/index.ts";

const leafPem = readFileSync(
  new URL("./fixtures/leaf.pem", import.meta.url),
  "utf8"
);
const leafDer = new X509Certificate(leafPem).raw;

function withExtensions(extensions: Extension[]): Uint8Array {
  const certificate = Certificate.fromBER(leafDer);
  certificate.extensions = extensions;
  return new Uint8Array(certificate.toSchema(true).toBER(false));
}

function san(names: GeneralName[]): Extension {
  return new Extension({
    extnID: id_SubjectAltName,
    extnValue: new AltName({ altNames: names }).toSchema().toBER(false)
  });
}

test("extracts URI SANs from PEM, DER and typed-array views", () => {
  const padded = Buffer.concat([
    Buffer.from([0x00]),
    leafDer,
    Buffer.from([0xff])
  ]);
  for (const input of [
    leafPem,
    leafDer,
    Uint8Array.from(leafDer),
    padded.subarray(1, padded.length - 1)
  ]) {
    assert.deepEqual(getUriSubjectAlternativeNames(input), [
      "https://client.example.org/app"
    ]);
  }
});

test("preserves URI order, duplicate values, commas and original spelling", () => {
  const first = "HTTPS://Client.Example.org/app?a=1,2";
  const second = "urn:example:client";
  const der = withExtensions([
    san([
      new GeneralName({ type: 6, value: first }),
      new GeneralName({ type: 2, value: "client.example.org" }),
      new GeneralName({ type: 6, value: second }),
      new GeneralName({ type: 1, value: "client@example.org" }),
      new GeneralName({ type: 6, value: first })
    ])
  ]);
  assert.deepEqual(getUriSubjectAlternativeNames(der), [first, second, first]);
});

test("returns no URIs when SAN is absent or contains other name types only", () => {
  const root = readFileSync(
    new URL("./fixtures/root.pem", import.meta.url),
    "utf8"
  );
  for (const input of [
    root,
    withExtensions([]),
    withExtensions([
      san([new GeneralName({ type: 2, value: "client.example.org" })])
    ])
  ]) {
    assert.deepEqual(getUriSubjectAlternativeNames(input), []);
  }
});

test("rejects malformed SAN data and invalid URI encodings", () => {
  for (const bytes of [
    [0x05, 0x00],
    [0x30, 0x03, 0x86, 0x01, 0xff]
  ]) {
    const der = withExtensions([
      new Extension({
        extnID: id_SubjectAltName,
        extnValue: Uint8Array.from(bytes).buffer
      })
    ]);
    assert.throws(() => getUriSubjectAlternativeNames(der), TypeError);
  }
});

test("rejects duplicate SAN extensions", () => {
  const extension = san([
    new GeneralName({ type: 6, value: "urn:example:client" })
  ]);
  assert.throws(
    () => getUriSubjectAlternativeNames(withExtensions([extension, extension])),
    TypeError
  );
});

test("rejects invalid PEM, malformed DER, truncation and trailing data", () => {
  for (const input of [
    "not a certificate",
    new Uint8Array(),
    new Uint8Array([0x05, 0x00]),
    leafDer.subarray(0, leafDer.length - 1),
    Buffer.concat([leafDer, Buffer.from([0x00])])
  ]) {
    assert.throws(() => getUriSubjectAlternativeNames(input));
  }
});
