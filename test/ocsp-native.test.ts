import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BmpString, Integer, Null, OctetString } from "asn1js";
import {
  AlgorithmIdentifier,
  BasicOCSPResponse,
  CertID,
  Certificate,
  Extension,
  OCSPRequest,
  OCSPResponse,
  RSASSAPSSParams
} from "pkijs";
import { nativeCreateOcspRequest } from "../src/native.ts";
import { validateOcsp } from "../src/ocsp.ts";

function readCertificate(name: string) {
  return new X509Certificate(
    readFileSync(new URL(`./fixtures/${name}.pem`, import.meta.url))
  ).raw;
}

const certificate = readCertificate("leaf");
const issuerCertificate = readCertificate("intermediate");
const fixture = readFileSync(
  new URL("./fixtures/ocsp/good.der", import.meta.url)
);
const checkDate = new Date(
  readFileSync(
    new URL("./fixtures/validation-time.txt", import.meta.url),
    "utf8"
  ).trim()
);

function decode(response: Uint8Array = fixture) {
  const outer = OCSPResponse.fromBER(Uint8Array.from(response));
  const basic = BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  );
  return { outer, basic };
}

function encode(outer: OCSPResponse, basic: BasicOCSPResponse) {
  outer.responseBytes!.response = new OctetString({
    valueHex: basic.toSchema().toBER(false)
  });
  return new Uint8Array(outer.toSchema().toBER(false));
}

async function expectUnknown(response: Uint8Array, code: string) {
  const result = await validateOcsp({
    certificate,
    issuerCertificate,
    response,
    checkDate
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, code);
}

test("native requests match PKI.js byte for byte, without signature or nonce", async () => {
  const expected = new OCSPRequest();
  await expected.createForCertificate(Certificate.fromBER(certificate), {
    issuerCertificate: Certificate.fromBER(issuerCertificate),
    hashAlgorithm: "SHA-1"
  });
  const actual = await nativeCreateOcspRequest(certificate, issuerCertificate);
  assert.deepEqual(
    actual,
    new Uint8Array(expected.toSchema(true).toBER(false))
  );
  const parsed = OCSPRequest.fromBER(actual);
  assert.equal(parsed.optionalSignature, undefined);
  assert.equal(parsed.tbsRequest.requestExtensions, undefined);
  assert.equal(parsed.tbsRequest.requestList.length, 1);
});

test("native OCSP workers snapshot all input bytes before returning", async () => {
  const subject = Uint8Array.from(certificate);
  const issuer = Uint8Array.from(issuerCertificate);
  const response = Uint8Array.from(fixture);
  const validation = validateOcsp({
    certificate: subject,
    issuerCertificate: issuer,
    response,
    checkDate
  });
  const request = nativeCreateOcspRequest(subject, issuer);
  subject.fill(0);
  issuer.fill(0);
  response.fill(0);
  assert.equal((await validation).status, "good");
  const parsed = OCSPRequest.fromBER(Uint8Array.from(await request));
  assert.ok(
    parsed.tbsRequest.requestList[0].reqCert.isEqual(
      decode().basic.tbsResponseData.responses[0].certID
    )
  );
});

test("rejects malformed certificate context and a mismatched issuer", async () => {
  const result = await validateOcsp({
    certificate,
    issuerCertificate: readCertificate("root"),
    response: fixture,
    checkDate
  });
  assert.ok(result.status === "unknown");
  assert.equal(result.code, "OCSP_ISSUER_MISMATCH");
  await assert.rejects(
    nativeCreateOcspRequest(certificate, readCertificate("root"))
  );
  await assert.rejects(
    nativeCreateOcspRequest(
      Buffer.concat([certificate, Buffer.of(0)]),
      issuerCertificate
    )
  );
  const invalid = await validateOcsp({
    certificate: Buffer.of(0),
    issuerCertificate,
    response: fixture,
    checkDate
  });
  assert.ok(invalid.status === "unknown");
  assert.equal(invalid.code, "INVALID_OCSP_RESPONSE");
});

test("rejects trailing data in both OCSP envelopes", async () => {
  await expectUnknown(
    Buffer.concat([fixture, Buffer.of(0)]),
    "INVALID_OCSP_RESPONSE"
  );
  const { outer } = decode();
  outer.responseBytes!.response = new OctetString({
    valueHex: Buffer.concat([
      outer.responseBytes!.response.valueBlock.valueHexView,
      Buffer.of(0)
    ])
  });
  await expectUnknown(
    new Uint8Array(outer.toSchema().toBER(false)),
    "INVALID_OCSP_RESPONSE"
  );
});

test("rejects unknown response versions, CertID algorithms and critical single extensions", async () => {
  for (const [change, code] of [
    [
      (basic: BasicOCSPResponse) => {
        basic.tbsResponseData.version = 1;
      },
      "UNSUPPORTED_OCSP_RESPONSE"
    ],
    [
      (basic: BasicOCSPResponse) => {
        basic.tbsResponseData.responses[0].certID.hashAlgorithm.algorithmId =
          "1.2.3.4.5";
      },
      "INVALID_OCSP_RESPONSE"
    ],
    [
      (basic: BasicOCSPResponse) => {
        basic.tbsResponseData.responses[0].singleExtensions = [
          new Extension({
            extnID: "1.2.3.4.5",
            critical: true,
            extnValue: new Null().toBER(false)
          })
        ];
      },
      "UNSUPPORTED_OCSP_RESPONSE"
    ]
  ] as const) {
    const { outer, basic } = decode();
    change(basic);
    basic.tbsResponseData.tbsView = new Uint8Array(
      basic.tbsResponseData.toSchema(true).toBER(false)
    );
    await expectUnknown(encode(outer, basic), code);
  }
});

test("rejects future producedAt, empty validity intervals and signature padding bits", async () => {
  for (const [change, code] of [
    [
      (basic: BasicOCSPResponse) => {
        basic.tbsResponseData.producedAt = new Date(checkDate.getTime() + 1000);
      },
      "OCSP_NOT_YET_VALID"
    ],
    [
      (basic: BasicOCSPResponse) => {
        basic.tbsResponseData.responses[0].nextUpdate =
          basic.tbsResponseData.responses[0].thisUpdate;
      },
      "INVALID_OCSP_RESPONSE"
    ],
    [
      (basic: BasicOCSPResponse) => {
        basic.signature.valueBlock.unusedBits = 1;
        basic.signature.valueBlock.valueHexView[
          basic.signature.valueBlock.valueHexView.length - 1
        ] &= 0xfe;
      },
      "INVALID_OCSP_SIGNATURE"
    ]
  ] as const) {
    const { outer, basic } = decode();
    change(basic);
    basic.tbsResponseData.tbsView = new Uint8Array(
      basic.tbsResponseData.toSchema(true).toBER(false)
    );
    await expectUnknown(encode(outer, basic), code);
  }
});

// Independent JS signing exercises Rust's decoding, hashing and signature dispatch.
async function signingContext(algorithm: "ECDSA" | "RSA-PSS") {
  const keys =
    algorithm === "ECDSA"
      ? await crypto.subtle.generateKey(
          { name: algorithm, namedCurve: "P-256" },
          true,
          ["sign", "verify"]
        )
      : await crypto.subtle.generateKey(
          {
            name: algorithm,
            modulusLength: 2048,
            publicExponent: Uint8Array.of(1, 0, 1),
            hash: "SHA-256"
          },
          true,
          ["sign", "verify"]
        );
  const issuer = Certificate.fromBER(issuerCertificate);
  await issuer.subjectPublicKeyInfo.importKey(keys.publicKey);
  issuer.issuer = issuer.subject;
  await issuer.sign(keys.privateKey, "SHA-256");
  const subject = Certificate.fromBER(certificate);
  // Exercise a full 20-byte unsigned serial which needs a DER sign-padding byte.
  subject.serialNumber = new Integer({
    valueHex: Uint8Array.of(0, 0x80, ...new Uint8Array(19)).buffer
  });
  await subject.sign(keys.privateKey, "SHA-256");
  return {
    issuer,
    subject,
    key: keys.privateKey,
    issuerDer: new Uint8Array(issuer.toSchema().toBER(false)),
    subjectDer: new Uint8Array(subject.toSchema().toBER(false))
  };
}

test("authenticates independently signed responses and pins responder identity", async (t) => {
  for (const algorithm of ["ECDSA", "RSA-PSS"] as const) {
    await t.test(algorithm, async (t) => {
      const context = await signingContext(algorithm);
      async function signedResponse(
        hash = "SHA-1",
        change?: (basic: BasicOCSPResponse) => void
      ) {
        const { outer, basic } = decode();
        basic.certs = [context.issuer];
        basic.tbsResponseData.responderID = context.issuer.subject;
        basic.tbsResponseData.responses[0].certID = await CertID.create(
          context.subject,
          { issuerCertificate: context.issuer, hashAlgorithm: hash }
        );
        change?.(basic);
        await basic.sign(context.key, "SHA-256");
        return encode(outer, basic);
      }
      async function validate(response: Uint8Array) {
        return validateOcsp({
          certificate: context.subjectDer,
          issuerCertificate: context.issuerDer,
          response,
          checkDate
        });
      }
      for (const hash of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]) {
        await t.test(`CertID ${hash}`, async () => {
          const result = await validate(await signedResponse(hash));
          assert.equal(result.status, "good");
        });
      }
      await t.test(
        "native request preserves a sign-padded serial",
        async () => {
          const request = OCSPRequest.fromBER(
            Uint8Array.from(
              await nativeCreateOcspRequest(
                context.subjectDer,
                context.issuerDer
              )
            )
          );
          assert.ok(
            request.tbsRequest.requestList[0].reqCert.serialNumber.isEqual(
              context.subject.serialNumber
            )
          );
        }
      );
      await t.test("byKey uses the hash of public key bits", async () => {
        const result = await validate(
          await signedResponse("SHA-256", (basic) => {
            basic.tbsResponseData.responderID = new OctetString({
              valueHex: createHash("sha1")
                .update(
                  context.issuer.subjectPublicKeyInfo.subjectPublicKey
                    .valueBlock.valueHexView
                )
                .digest()
            });
          })
        );
        assert.equal(result.status, "good");
      });
      await t.test(
        "a signed response with a false responder ID grants no status",
        async () => {
          const result = await validate(
            await signedResponse("SHA-256", (basic) => {
              basic.tbsResponseData.responderID = new OctetString({
                valueHex: new Uint8Array(20).buffer
              });
            })
          );
          assert.ok(result.status === "unknown");
          assert.equal(result.code, "OCSP_RESPONDER_VERIFICATION_FAILED");
        }
      );
      await t.test("byName matches case and string encoding", async () => {
        const result = await validate(
          await signedResponse("SHA-256", (basic) => {
            basic.tbsResponseData.responderID = Certificate.fromBER(
              context.issuerDer
            ).subject;
            basic.tbsResponseData.responderID.valueBeforeDecode =
              new ArrayBuffer(0);
            basic.tbsResponseData.responderID.typesAndValues[0].value =
              new BmpString({ value: "  X509-TRUST   TEST INTERMEDIATE " });
          })
        );
        assert.equal(result.status, "good");
      });
      await t.test(
        "signature is checked against the supplied issuer's key",
        async () => {
          const response = await signedResponse();
          const { outer, basic } = decode(response);
          basic.signature.valueBlock.valueHexView[0] ^= 1;
          const result = await validate(encode(outer, basic));
          assert.ok(result.status === "unknown");
          assert.equal(result.code, "INVALID_OCSP_SIGNATURE");
        }
      );
      await t.test(
        "an embedded certificate with the issuer's name cannot replace its key",
        async () => {
          const impostor = await signingContext("ECDSA");
          const { outer, basic } = decode(await signedResponse());
          basic.certs = [impostor.issuer];
          await basic.sign(impostor.key, "SHA-256");
          const result = await validate(encode(outer, basic));
          assert.ok(result.status === "unknown");
          assert.equal(result.code, "INVALID_OCSP_SIGNATURE");
        }
      );
      if (algorithm === "RSA-PSS") {
        await t.test(
          "checks declared PSS parameters as well as the signature hash",
          async () => {
            const response = await signedResponse();
            for (const change of [
              (params: RSASSAPSSParams) => {
                params.saltLength = 0;
              },
              (params: RSASSAPSSParams) => {
                params.trailerField = 2;
              },
              (params: RSASSAPSSParams) => {
                params.maskGenAlgorithm.algorithmId = "1.2.3.4.5";
              },
              (params: RSASSAPSSParams) => {
                params.maskGenAlgorithm.algorithmParams =
                  new AlgorithmIdentifier({
                    algorithmId: "2.16.840.1.101.3.4.2.2",
                    algorithmParams: new Null()
                  }).toSchema();
              }
            ]) {
              const { outer, basic } = decode(response);
              const params = new RSASSAPSSParams({
                schema: basic.signatureAlgorithm.algorithmParams
              });
              change(params);
              basic.signatureAlgorithm.algorithmParams = params.toSchema();
              const result = await validate(encode(outer, basic));
              assert.ok(result.status === "unknown");
              assert.equal(result.code, "INVALID_OCSP_SIGNATURE");
            }
          }
        );
      }
    });
  }
});
