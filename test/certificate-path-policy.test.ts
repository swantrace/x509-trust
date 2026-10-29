import assert from "node:assert/strict";
import { test } from "node:test";
import { BitString, Integer, Utf8String } from "asn1js";
import {
  AltName,
  AttributeTypeAndValue,
  BasicConstraints,
  Certificate,
  Extension,
  ExtKeyUsage,
  GeneralName,
  GeneralSubtree,
  NameConstraints
} from "pkijs";
import { validateCertificatePath } from "../src/certificate-path.ts";
import { nativeValidateCertificatePath } from "../src/native.ts";

const checkDate = new Date("2030-06-01T00:00:00Z");
let serial = 1;

interface Issued {
  certificate: Certificate;
  key: CryptoKey;
  der: Uint8Array;
}

function extension(
  oid: string,
  value: ArrayBuffer,
  critical = true
): Extension {
  return new Extension({ extnID: oid, critical, extnValue: value });
}

async function issue(
  name: string,
  issuer?: Issued,
  ca = false,
  pathLen = 0
): Promise<Issued> {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new Integer({ value: serial++ });
  certificate.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new Utf8String({ value: name })
    })
  );
  certificate.issuer = issuer?.certificate.subject ?? certificate.subject;
  certificate.notBefore.value = new Date("2030-01-01T00:00:00Z");
  certificate.notAfter.value = new Date("2031-01-01T00:00:00Z");
  certificate.extensions = [
    extension(
      "2.5.29.19",
      new BasicConstraints(ca ? { cA: true, pathLenConstraint: pathLen } : {})
        .toSchema()
        .toBER(false)
    ),
    extension(
      "2.5.29.15",
      new BitString({ valueHex: Uint8Array.of(ca ? 0x06 : 0x80).buffer }).toBER(
        false
      )
    )
  ];
  if (!ca) {
    certificate.extensions.push(
      extension(
        "2.5.29.17",
        new AltName({
          altNames: [
            new GeneralName({ type: 2, value: "client.allowed.test" }),
            new GeneralName({ type: 6, value: "urn:example:client" })
          ]
        })
          .toSchema()
          .toBER(false),
        false
      )
    );
  }
  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
  await certificate.sign(issuer?.key ?? keys.privateKey, "SHA-256");
  return {
    certificate,
    key: keys.privateKey,
    der: new Uint8Array(certificate.toSchema().toBER(false))
  };
}

async function reissue(
  original: Issued,
  issuer: Issued,
  change: (certificate: Certificate) => void
): Promise<Issued> {
  const certificate = Certificate.fromBER(Uint8Array.from(original.der));
  change(certificate);
  await certificate.sign(issuer.key, "SHA-256");
  return {
    ...original,
    certificate,
    der: new Uint8Array(certificate.toSchema().toBER(false))
  };
}

function replaceExtension(
  certificate: Certificate,
  replacement: Extension
): void {
  certificate.extensions = certificate.extensions!.filter(
    (entry) => entry.extnID !== replacement.extnID
  );
  certificate.extensions.push(replacement);
}

test("native certificate path policy with independently signed certificates", async (t) => {
  const root = await issue("Root", undefined, true, 2);
  const intermediate = await issue("Issuer", root, true, 0);
  const leaf = await issue("Client", intermediate);
  const verify = (
    chain: Uint8Array[] = [leaf.der, intermediate.der],
    anchors = [root.der],
    date = checkDate
  ) =>
    validateCertificatePath({
      certificateChain: chain,
      trustAnchors: anchors,
      checkDate: date
    });
  const reject = async (chain: Uint8Array[], anchors = [root.der]) => {
    const result = await verify(chain, anchors);
    assert.ok(!result.pathValid);
    assert.equal(result.code, "INVALID_CERTIFICATE_PATH");
  };

  await t.test(
    "builds an ECDSA path and returns the original leaf-first DER bytes",
    async () => {
      const result = await verify();
      assert.ok(result.pathValid);
      assert.deepEqual(result.certificatePath, [
        leaf.der,
        intermediate.der,
        root.der
      ]);
    }
  );

  await t.test("does not impose TLS EKUs or hostname matching", async () => {
    const codeSigning = await reissue(leaf, intermediate, (cert) => {
      cert.extensions!.push(
        extension(
          "2.5.29.37",
          new ExtKeyUsage({ keyPurposes: ["1.3.6.1.5.5.7.3.3"] })
            .toSchema()
            .toBER(false)
        )
      );
    });
    assert.equal(
      (await verify([codeSigning.der, intermediate.der])).pathValid,
      true
    );
  });

  await t.test(
    "rejects malformed EKU data even though no particular purpose is required",
    async () => {
      const malformed = await reissue(leaf, intermediate, (cert) => {
        cert.extensions!.push(
          extension("2.5.29.37", Uint8Array.of(0x30, 0x02, 0x05, 0x00).buffer)
        );
      });
      await reject([malformed.der, intermediate.der]);
    }
  );

  await t.test("rejects CA certificates without keyCertSign", async () => {
    const unauthorized = await reissue(intermediate, root, (cert) => {
      replaceExtension(
        cert,
        extension(
          "2.5.29.15",
          new BitString({ valueHex: Uint8Array.of(0x80).buffer }).toBER(false)
        )
      );
    });
    await reject([leaf.der, unauthorized.der]);
  });

  await t.test(
    "rejects a non-CA issuer even when signatures are valid",
    async () => {
      const notCa = await reissue(intermediate, root, (cert) => {
        replaceExtension(
          cert,
          extension("2.5.29.19", new BasicConstraints().toSchema().toBER(false))
        );
      });
      await reject([leaf.der, notCa.der]);
    }
  );

  await t.test("checks the trust anchor CA flag and keyCertSign", async () => {
    const notCa = await reissue(root, root, (cert) => {
      replaceExtension(
        cert,
        extension("2.5.29.19", new BasicConstraints().toSchema().toBER(false))
      );
    });
    const badUsage = await reissue(root, root, (cert) => {
      replaceExtension(
        cert,
        extension(
          "2.5.29.15",
          new BitString({ valueHex: Uint8Array.of(0x80).buffer }).toBER(false)
        )
      );
    });
    for (const anchor of [notCa, badUsage])
      await reject([leaf.der, intermediate.der], [anchor.der]);
  });

  await t.test(
    "checks validity boundaries with millisecond precision",
    async () => {
      const start = leaf.certificate.notBefore.value.getTime();
      const end = leaf.certificate.notAfter.value.getTime();
      for (const [date, expected] of [
        [start - 1, false],
        [start, true],
        [end, true],
        [end + 1, false]
      ] as const) {
        assert.equal(
          (await verify(undefined, undefined, new Date(date))).pathValid,
          expected
        );
      }
    }
  );

  await t.test(
    "checks intermediate and anchor validity, including subsecond expiration",
    async () => {
      const expiresAt = checkDate.getTime() - 1000;
      const expiredIssuer = await reissue(intermediate, root, (cert) => {
        cert.notAfter.value = new Date(expiresAt);
      });
      const expiredRoot = await reissue(root, root, (cert) => {
        cert.notAfter.value = new Date(expiresAt);
      });
      await reject([leaf.der, expiredIssuer.der]);
      await reject([leaf.der, intermediate.der], [expiredRoot.der]);
      assert.equal(
        (await verify(undefined, [expiredRoot.der], new Date(expiresAt + 1)))
          .pathValid,
        false
      );
    }
  );

  await t.test(
    "tries another anchor when the first shares a key and subject but is expired",
    async () => {
      const expired = await reissue(root, root, (cert) => {
        cert.notAfter.value = new Date("2030-05-01T00:00:00Z");
      });
      const result = await verify(undefined, [expired.der, root.der]);
      assert.ok(result.pathValid);
      assert.deepEqual(result.certificatePath.at(-1), root.der);
    }
  );

  await t.test("enforces intermediate path-length constraints", async () => {
    const subCa = await issue("Sub CA", intermediate, true);
    const nestedLeaf = await issue("Nested client", subCa);
    await reject([nestedLeaf.der, subCa.der, intermediate.der]);
  });

  await t.test(
    "enforces DNS name constraints without a hostname parameter",
    async () => {
      for (const [name, expected] of [
        ["allowed.test", true],
        ["other.test", false]
      ] as const) {
        const constrained = await reissue(intermediate, root, (cert) => {
          cert.extensions!.push(
            extension(
              "2.5.29.30",
              new NameConstraints({
                permittedSubtrees: [
                  new GeneralSubtree({
                    base: new GeneralName({ type: 2, value: name })
                  })
                ]
              })
                .toSchema()
                .toBER(false)
            )
          );
        });
        assert.equal(
          (await verify([leaf.der, constrained.der])).pathValid,
          expected
        );
      }
    }
  );

  await t.test(
    "rejects unknown critical extensions in the path or anchor",
    async () => {
      const critical = extension("1.2.3.4", Uint8Array.of(0x05, 0x00).buffer);
      const badLeaf = await reissue(leaf, intermediate, (cert) => {
        cert.extensions!.push(critical);
      });
      const badRoot = await reissue(root, root, (cert) => {
        cert.extensions!.push(critical);
      });
      await reject([badLeaf.der, intermediate.der]);
      await reject([leaf.der, intermediate.der], [badRoot.der]);
    }
  );

  await t.test(
    "fails closed on noncritical policy-processing extensions",
    async () => {
      for (const [oid, bytes] of [
        [
          "2.5.29.33",
          [
            0x30, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x06, 0x03,
            0x2a, 0x03, 0x05
          ]
        ],
        ["2.5.29.36", [0x30, 0x03, 0x80, 0x01, 0x00]],
        ["2.5.29.54", [0x02, 0x01, 0x00]]
      ] as const) {
        const constrained = await reissue(intermediate, root, (cert) => {
          cert.extensions!.push(
            extension(oid, Uint8Array.from(bytes).buffer, false)
          );
        });
        await reject([leaf.der, constrained.der]);
      }
    }
  );

  await t.test(
    "rejects missing issuers and malformed unused candidates",
    async () => {
      await reject([leaf.der]);
      for (const input of [
        Uint8Array.of(0x05, 0x00),
        Uint8Array.from([...leaf.der, 0x00])
      ]) {
        const result = await verify([leaf.der, intermediate.der, input]);
        assert.ok(!result.pathValid);
        assert.equal(result.code, "INVALID_CERTIFICATE");
      }
    }
  );

  await t.test(
    "snapshots native inputs before dispatching to the worker",
    async () => {
      const chain = [leaf.der.slice(), intermediate.der.slice()];
      const anchors = [root.der.slice()];
      const pending = nativeValidateCertificatePath(
        chain,
        anchors,
        checkDate.getTime()
      );
      for (const der of [...chain, ...anchors]) der.fill(0);
      const result = await pending;
      assert.deepEqual(result.certificatePath, [
        leaf.der,
        intermediate.der,
        root.der
      ]);
    }
  );
});
