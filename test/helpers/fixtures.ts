import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";

export function readFixture(name: string) {
  return readFileSync(new URL(`../fixtures/${name}`, import.meta.url));
}

export function readCertificate(name: string): string {
  return readFixture(`${name}.pem`).toString("utf8");
}

export function readCertificateDer(name: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(new X509Certificate(readCertificate(name)).raw);
}

export function readCrl(name: string) {
  const pem = readFixture(`crl/${name}.crl.pem`).toString("utf8");
  return Buffer.from(pem.replace(/-----[^\n]+-----/g, ""), "base64");
}

export function readOcsp(name: string) {
  return readFixture(`ocsp/${name}.der`);
}

export const fixtureTime = Date.parse(
  readFixture("validation-time.txt").toString("utf8").trim()
);
