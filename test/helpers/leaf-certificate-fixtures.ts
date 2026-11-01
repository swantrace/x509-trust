import { Integer, Utf8String } from "asn1js";
import {
  AttributeTypeAndValue,
  Certificate,
  Extension,
  RelativeDistinguishedNames,
  Time
} from "pkijs";

export function extension(
  oid: string,
  value: { toSchema(): unknown }
): Extension {
  return new Extension({
    extnID: oid,
    critical: false,
    extnValue: (
      value.toSchema() as { toBER(flag?: boolean): ArrayBuffer }
    ).toBER(false),
    parsedValue: value as never
  });
}

export async function syntheticCertificate({
  algorithm = "rsa",
  serialHex = [0x01],
  extensions = []
}: {
  algorithm?: "rsa" | "ec";
  serialHex?: number[];
  extensions?: Extension[];
} = {}): Promise<{ der: Uint8Array<ArrayBuffer>; privateKey: unknown }> {
  const keys =
    algorithm === "rsa"
      ? await globalThis.crypto.subtle.generateKey(
          {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
          },
          true,
          ["sign", "verify"]
        )
      : await globalThis.crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"]
        );
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new Integer({
    valueHex: new Uint8Array(serialHex).buffer
  });
  const name = new RelativeDistinguishedNames({
    typesAndValues: [
      new AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new Utf8String({ value: "Synthetic Subject" })
      })
    ]
  });
  certificate.issuer = name;
  certificate.subject = name;
  certificate.notBefore = new Time({
    type: 0,
    value: new Date("2026-01-01T00:00:00Z")
  });
  certificate.notAfter = new Time({
    type: 0,
    value: new Date("2027-01-01T00:00:00Z")
  });
  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
  certificate.extensions = extensions;
  await certificate.sign(keys.privateKey, "SHA-256");
  return {
    der: new Uint8Array(certificate.toSchema(true).toBER(false)),
    privateKey: keys.privateKey
  };
}
