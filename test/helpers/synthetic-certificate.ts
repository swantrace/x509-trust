import { webcrypto } from "node:crypto";
import { Integer, Utf8String } from "asn1js";
import {
  AttributeTypeAndValue,
  Certificate,
  RelativeDistinguishedNames,
  Time
} from "pkijs";
import { createCertificateExtensions } from "./synthetic-certificate-extensions.ts";
export interface SyntheticCertificate {
  certificate: Certificate;
  der: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
  subject: RelativeDistinguishedNames;
}

export interface SyntheticChain {
  root: SyntheticCertificate;
  intermediate: SyntheticCertificate;
  leaf: SyntheticCertificate;
}

export interface CertificateOptions {
  commonName: string;
  ca?: boolean;
  pathLenConstraint?: number;
  keyUsageBits?: number[];
  crlUrls?: string[];
  ocspUrls?: string[];
  uriSubjectAlternativeNames?: string[];
  extendedKeyUsageOids?: string[];
  certificatePolicyOids?: string[];
  notBefore?: Date;
  notAfter?: Date;
  serial?: number[];
}

export interface CreateChainOptions {
  intermediate?: Partial<CertificateOptions>;
  leaf?: Partial<CertificateOptions>;
}

let nextSerial = 1;

function distinguishedName(commonName: string): RelativeDistinguishedNames {
  return new RelativeDistinguishedNames({
    typesAndValues: [
      new AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new Utf8String({ value: commonName })
      })
    ]
  });
}

export async function generateKeys(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
}

export async function createCertificate(
  options: CertificateOptions,
  keys: CryptoKeyPair,
  issuer?: SyntheticCertificate
): Promise<SyntheticCertificate> {
  const subject = distinguishedName(options.commonName);
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new Integer({
    valueHex: new Uint8Array(options.serial ?? [nextSerial++]).buffer
  });
  certificate.issuer = issuer ? issuer.subject : subject;
  certificate.subject = subject;
  certificate.notBefore = new Time({
    type: 0,
    value: options.notBefore ?? new Date("2026-01-01T00:00:00Z")
  });
  certificate.notAfter = new Time({
    type: 0,
    value: options.notAfter ?? new Date("2030-01-01T00:00:00Z")
  });
  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);

  certificate.extensions = createCertificateExtensions(options);
  await certificate.sign(
    issuer ? issuer.privateKey : keys.privateKey,
    "SHA-256"
  );
  return {
    certificate,
    der: new Uint8Array(certificate.toSchema(true).toBER(false)),
    privateKey: keys.privateKey,
    subject
  };
}
