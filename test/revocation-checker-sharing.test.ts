import assert from "node:assert/strict";
import { test } from "node:test";
import { createRevocationChecker } from "../src/revocation/revocation-checker.ts";
import { createRevocationProvider } from "../src/revocation/revocation-provider.ts";
import {
  fixtureTime,
  readCertificateDer,
  readOcsp
} from "./helpers/fixtures.ts";
import {
  crl,
  crlOptions,
  issuerDer,
  ocspOptions,
  profile
} from "./helpers/revocation-checker-fixtures.ts";

test("reuses a CRL across certificates but checks each certificate's status", async () => {
  let loads = 0;
  const provider = createRevocationProvider({
    crlLoader: async () => {
      loads++;
      return crl;
    },
    ocspLoader: false
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => fixtureTime
  });
  assert.equal((await checkCertificate(crlOptions)).status, "good");
  assert.equal(
    (
      await checkCertificate({
        ...crlOptions,
        prepared: {
          ...crlOptions.prepared,
          der: readCertificateDer("revoked-leaf")
        }
      })
    ).status,
    "revoked"
  );
  assert.equal(loads, 1);
});

test("isolates OCSP responses by certificate, issuer, source and request bytes", async () => {
  let loads = 0;
  const revoked = readCertificateDer("revoked-leaf");
  const provider = createRevocationProvider({
    crlLoader: false,
    ocspLoader: async ({ certificate }) => {
      loads++;
      if (Buffer.from(certificate).equals(revoked)) return readOcsp("revoked");
      return readOcsp(
        Buffer.from(certificate).equals(issuerDer)
          ? "intermediate-good"
          : "good"
      );
    }
  });
  const checkCertificate = createRevocationChecker({
    profile,
    provider,
    now: () => fixtureTime
  });
  assert.equal((await checkCertificate(ocspOptions)).status, "good");
  assert.equal((await checkCertificate(ocspOptions)).status, "good");
  assert.equal(loads, 1);
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: { ...ocspOptions.prepared, der: revoked }
      })
    ).status,
    "revoked"
  );
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: {
          ...ocspOptions.prepared,
          ocspUrls: ["http://other.test/status"]
        }
      })
    ).status,
    "good"
  );
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: {
          ...ocspOptions.prepared,
          der: issuerDer,
          issuerDer: readCertificateDer("root")
        }
      })
    ).status,
    "good"
  );
  assert.equal(
    (
      await checkCertificate({
        ...ocspOptions,
        prepared: {
          ...ocspOptions.prepared,
          ocspRequestDer: new Uint8Array([0x30, 0x01, 0x00])
        }
      })
    ).status,
    "good"
  );
  assert.equal(loads, 5);
});
