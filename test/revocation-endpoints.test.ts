import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { OctetString } from "asn1js";
import {
  AccessDescription,
  Certificate,
  CRLDistributionPoints,
  DistributionPoint,
  Extension,
  GeneralName,
  InfoAccess,
  id_AuthorityInfoAccess,
  id_ad_caIssuers,
  id_ad_ocsp,
  id_CRLDistributionPoints,
  RelativeDistinguishedNames
} from "pkijs";
import { getRevocationEndpoints } from "../src/revocation-endpoints.ts";

function certificateWithExtensions({
  extensions
}: {
  extensions: Extension[];
}) {
  const pem = readFileSync(new URL("./fixtures/leaf.pem", import.meta.url));
  const certificate = Certificate.fromBER(new X509Certificate(pem).raw);
  for (const extension of extensions) {
    if (
      extension.extnValue.valueBlock.valueHexView.length === 0 &&
      extension.parsedValue
    ) {
      extension.extnValue = new OctetString({
        valueHex: extension.parsedValue.toSchema().toBER(false)
      });
    }
  }
  certificate.extensions = extensions;
  return certificate;
}

function der(certificate: Certificate): Uint8Array {
  return new Uint8Array(certificate.toSchema(true).toBER(false));
}

for (const [name, issuer] of [
  ["leaf", "intermediate"],
  ["revoked-leaf", "intermediate"],
  ["intermediate", "root"]
]) {
  test(`extracts the issuing CA's CRL and OCSP addresses from ${name}.pem`, () => {
    const pem = readFileSync(
      new URL(`./fixtures/${name}.pem`, import.meta.url)
    );
    const certificate = Certificate.fromBER(new X509Certificate(pem).raw);

    assert.deepEqual(getRevocationEndpoints(der(certificate)), {
      crlUrls: [`http://crl.example.test/${issuer}.crl`],
      ocspUrls: [`http://ocsp.example.test/${issuer}`]
    });
  });
}

test("returns empty arrays when a root has no revocation extensions", () => {
  const pem = readFileSync(new URL("./fixtures/root.pem", import.meta.url));
  const certificate = Certificate.fromBER(new X509Certificate(pem).raw);

  assert.deepEqual(getRevocationEndpoints(der(certificate)), {
    crlUrls: [],
    ocspUrls: []
  });
});

test("returns empty arrays when a certificate has no extensions", () => {
  const certificate = certificateWithExtensions({ extensions: [] });
  delete certificate.extensions;
  assert.deepEqual(getRevocationEndpoints(der(certificate)), {
    crlUrls: [],
    ocspUrls: []
  });
});

test("keeps multiple addresses in order and excludes issuer locations and non-URI names", () => {
  const certificate = certificateWithExtensions({
    extensions: [
      new Extension({
        extnID: id_CRLDistributionPoints,
        parsedValue: new CRLDistributionPoints({
          distributionPoints: [
            new DistributionPoint({
              distributionPoint: [
                new GeneralName({
                  type: 6,
                  value: "http://primary.test/ca.crl"
                }),
                new GeneralName({ type: 2, value: "crl.example.test" }),
                new GeneralName({ type: 6, value: "http://backup.test/ca.crl" })
              ],
              cRLIssuer: [
                new GeneralName({
                  type: 6,
                  value: "https://issuer.test/identity"
                })
              ]
            }),
            new DistributionPoint({
              distributionPoint: new RelativeDistinguishedNames()
            }),
            new DistributionPoint({
              distributionPoint: [
                new GeneralName({ type: 6, value: "http://other.test/ca.crl" })
              ]
            })
          ]
        })
      }),
      new Extension({
        extnID: id_AuthorityInfoAccess,
        parsedValue: new InfoAccess({
          accessDescriptions: [
            new AccessDescription({
              accessMethod: id_ad_ocsp,
              accessLocation: new GeneralName({
                type: 6,
                value: "http://primary.test/ocsp"
              })
            }),
            new AccessDescription({
              accessMethod: id_ad_caIssuers,
              accessLocation: new GeneralName({
                type: 6,
                value: "http://issuer.test/ca.cer"
              })
            }),
            new AccessDescription({
              accessMethod: id_ad_ocsp,
              accessLocation: new GeneralName({
                type: 2,
                value: "ocsp.example.test"
              })
            }),
            new AccessDescription({
              accessMethod: id_ad_ocsp,
              accessLocation: new GeneralName({
                type: 6,
                value: "http://backup.test/ocsp"
              })
            })
          ]
        })
      })
    ]
  });

  assert.deepEqual(getRevocationEndpoints(der(certificate)), {
    crlUrls: [
      "http://primary.test/ca.crl",
      "http://backup.test/ca.crl",
      "http://other.test/ca.crl"
    ],
    ocspUrls: ["http://primary.test/ocsp", "http://backup.test/ocsp"]
  });
});

for (const extnID of [id_CRLDistributionPoints, id_AuthorityInfoAccess]) {
  test(`rejects a malformed ${extnID} extension instead of treating it as missing`, () => {
    const certificate = certificateWithExtensions({
      extensions: [
        new Extension({
          extnID,
          extnValue: new Uint8Array([0x05, 0x00]).buffer
        })
      ]
    });

    assert.throws(() => getRevocationEndpoints(der(certificate)), TypeError);
  });

  test(`rejects duplicate ${extnID} extensions`, () => {
    const pem = readFileSync(new URL("./fixtures/leaf.pem", import.meta.url));
    const certificate = Certificate.fromBER(new X509Certificate(pem).raw);
    const extension = certificate.extensions!.find(
      (entry) => entry.extnID === extnID
    )!;
    certificate.extensions!.push(extension);
    assert.throws(() => getRevocationEndpoints(der(certificate)), TypeError);
  });
}

test("rejects malformed, truncated and trailing DER bytes", () => {
  const pem = readFileSync(new URL("./fixtures/leaf.pem", import.meta.url));
  const certificate = new X509Certificate(pem).raw;
  for (const input of [
    new Uint8Array(),
    new Uint8Array([0x05, 0x00]),
    certificate.subarray(0, certificate.length - 1),
    Buffer.concat([certificate, Buffer.from([0x00])])
  ]) {
    assert.throws(() => getRevocationEndpoints(input), TypeError);
  }
});
