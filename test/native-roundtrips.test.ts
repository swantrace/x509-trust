import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

// Install counters before importing the bridge, so this counts real addon calls,
// including accidental parsing/request calls hidden behind TypeScript helpers.
const binding = createRequire(import.meta.url)("../native/index.node");
const calls: string[] = [];
for (const name of Object.keys(binding)) {
  if (typeof binding[name] !== "function") continue;
  const original = binding[name];
  binding[name] = (...args: unknown[]) => {
    calls.push(name);
    return original(...args);
  };
}
const { createTrustValidator, getUriSubjectAlternativeNames } = await import(
  "../src/index.ts"
);
const { nativeValidateEvidence } = await import("../src/native.ts");
const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const fixtureTime = Date.parse(
  fixture("validation-time.txt").toString().trim()
);
const input = {
  certificateChain: [fixture("leaf.pem"), fixture("intermediate.pem")]
};

const crl = (name: string) =>
  Buffer.from(
    fixture(`crl/${name}.crl.pem`)
      .toString()
      .replace(/-----[^\n]+-----/g, ""),
    "base64"
  );

test("CRL-only cold and cached verification also use two calls", async () => {
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => fixtureTime,
    loadOcsp: false,
    loadCrl: async (url) => {
      loads++;
      return crl(url.endsWith("/root.crl") ? "root" : "intermediate-clean");
    }
  });
  for (let attempt = 0; attempt < 2; attempt++) {
    calls.length = 0;
    assert.equal((await validator.verify(input)).valid, true);
    assert.deepEqual(calls, ["validateCertificatePath", "validateEvidence"]);
  }
  assert.equal(loads, 2);
});

test("transport failure and mixed OCSP/CRL evidence still fit one validation batch", async () => {
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => fixtureTime,
    loadOcsp: async ({ url }) => {
      if (!url.endsWith("/root")) throw new Error("OCSP offline");
      return fixture("ocsp/intermediate-good.der");
    },
    loadCrl: async () => crl("intermediate-clean")
  });
  calls.length = 0;
  assert.equal((await validator.verify(input)).valid, true);
  assert.deepEqual(calls, ["validateCertificatePath", "validateEvidence"]);
});

test("an authenticated revoked intermediate wins over an unknown leaf in the same batch", async () => {
  const { Certificate, CertificateRevocationList, RevokedCertificate, Time } =
    await import("pkijs");
  const { X509Certificate } = await import("node:crypto");
  const decode = (name: string) =>
    Certificate.fromBER(new X509Certificate(fixture(`${name}.pem`)).raw);
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const root = decode("root");
  await root.subjectPublicKeyInfo.importKey(keys.publicKey);
  await root.sign(keys.privateKey, "SHA-256");
  const intermediate = decode("intermediate");
  await intermediate.sign(keys.privateKey, "SHA-256");
  const revoked = CertificateRevocationList.fromBER(crl("root"));
  revoked.revokedCertificates = [
    new RevokedCertificate({
      userCertificate: intermediate.serialNumber,
      revocationDate: new Time({ type: 1, value: new Date(fixtureTime) })
    })
  ];
  await revoked.sign(keys.privateKey, "SHA-256");
  const validator = createTrustValidator({
    trustAnchors: [new Uint8Array(root.toSchema().toBER(false))],
    now: () => fixtureTime,
    loadOcsp: false,
    loadCrl: async (url) =>
      url.endsWith("/root.crl")
        ? new Uint8Array(revoked.toSchema().toBER(false))
        : Buffer.of(0)
  });
  const result = await validator.verify({
    certificateChain: [
      fixture("leaf.pem"),
      new Uint8Array(intermediate.toSchema().toBER(false))
    ]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(result.certificateIndex, 1);
});

test("cold and cached default HTTP verification each use exactly two Rust calls", async (t) => {
  const requested: string[] = [];
  const server = http.createServer((request, response) => {
    requested.push(request.url!);
    // Different completion turns must still be collected into one batch.
    setTimeout(
      () =>
        response.end(
          fixture(
            `ocsp/${request.url === "/root" ? "intermediate-good" : "good"}.der`
          )
        ),
      request.url === "/root" ? 25 : 1
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      })
  );
  const send = http.request;
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  t.mock.method(http, "request", ((
    url: URL,
    options: http.RequestOptions,
    callback: (response: http.IncomingMessage) => void
  ) =>
    send(
      new URL(url.pathname, origin),
      options,
      callback
    )) as typeof http.request);
  calls.length = 0;
  const validator = createTrustValidator({
    trustAnchors: [fixture("untrusted-root.pem"), fixture("root.pem")],
    now: () => fixtureTime,
    http: { allowPrivateAddresses: true }
  });
  assert.deepEqual(calls, []);
  for (let attempt = 0; attempt < 2; attempt++) {
    calls.length = 0;
    const result = await validator.verify(input);
    assert.equal(result.valid, true);
    assert.deepEqual(calls, ["validateCertificatePath", "validateEvidence"]);
  }
  assert.deepEqual(requested.sort(), ["/intermediate", "/root"]);
});

test("OCSP-to-CRL fallback uses another batch and unknown OCSP remains uncached", async () => {
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => fixtureTime,
    loadOcsp: async ({ url }) => {
      loads++;
      return fixture(
        `ocsp/${url.endsWith("/root") ? "intermediate-good" : "unknown"}.der`
      );
    },
    loadCrl: async () => {
      loads++;
      return Buffer.from(
        fixture("crl/intermediate-clean.crl.pem")
          .toString()
          .replace(/-----[^\n]+-----/g, ""),
        "base64"
      );
    }
  });
  calls.length = 0;
  assert.equal((await validator.verify(input)).valid, true);
  assert.deepEqual(calls, [
    "validateCertificatePath",
    "validateEvidence",
    "validateEvidence"
  ]);
  assert.equal(loads, 3);
  calls.length = 0;
  // Unknown OCSP is deliberately not cached, so it must be tried again.
  assert.equal((await validator.verify(input)).valid, true);
  assert.deepEqual(calls, [
    "validateCertificatePath",
    "validateEvidence",
    "validateEvidence"
  ]);
  assert.equal(loads, 4);
});

test("invalid cached evidence is reauthenticated, discarded and reloaded in another batch", async () => {
  const entries = new Map<string, string>();
  const cache = {
    get: async (key: string) => entries.get(key) ?? null,
    set: async (key: string, value: string) => {
      entries.set(key, value);
    },
    delete: async (key: string) => {
      entries.delete(key);
    }
  };
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    cache,
    now: () => fixtureTime,
    loadCrl: false,
    loadOcsp: async ({ url }) => {
      loads++;
      return fixture(
        `ocsp/${url.endsWith("/root") ? "intermediate-good" : "good"}.der`
      );
    }
  });
  assert.equal((await validator.verify(input)).valid, true);
  for (const [key, value] of entries) {
    const stored = JSON.parse(value);
    stored.der = Buffer.of(0).toString("base64");
    stored.status = "good";
    entries.set(key, JSON.stringify(stored));
  }
  calls.length = 0;
  assert.equal((await validator.verify(input)).valid, true);
  assert.deepEqual(calls, [
    "validateCertificatePath",
    "validateEvidence",
    "validateEvidence"
  ]);
  assert.equal(loads, 4);
});

test("a revoked result stops a different certificate's invalid-cache refresh", async () => {
  const entries = new Map<string, string>();
  const cache = {
    get: async (key: string) => entries.get(key) ?? null,
    set: async (key: string, value: string) => {
      entries.set(key, value);
    },
    delete: async (key: string) => {
      entries.delete(key);
    }
  };
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    cache,
    now: () => fixtureTime,
    loadCrl: false,
    loadOcsp: async ({ url, certificate }) => {
      loads++;
      if (url.endsWith("/root")) return fixture("ocsp/intermediate-good.der");
      const { X509Certificate } = await import("node:crypto");
      return fixture(
        `ocsp/${new X509Certificate(certificate).serialNumber === new X509Certificate(fixture("revoked-leaf.pem")).serialNumber ? "revoked" : "good"}.der`
      );
    }
  });
  assert.equal((await validator.verify(input)).valid, true);
  for (const [key, value] of entries) {
    const stored = JSON.parse(value);
    if (
      stored.der === fixture("ocsp/intermediate-good.der").toString("base64")
    ) {
      stored.der = Buffer.of(0).toString("base64");
      entries.set(key, JSON.stringify(stored));
    }
  }
  calls.length = 0;
  const result = await validator.verify({
    certificateChain: [fixture("revoked-leaf.pem"), fixture("intermediate.pem")]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "CERTIFICATE_REVOKED");
  assert.equal(loads, 3);
  assert.deepEqual(calls, ["validateCertificatePath", "validateEvidence"]);
});

test("batch freshness uses the clock after all asynchronous sources finish", async () => {
  let clock = fixtureTime;
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => clock,
    loadCrl: false,
    loadOcsp: async ({ url }) => {
      if (url.endsWith("/root")) {
        await new Promise((resolve) => setTimeout(resolve, 10));
        clock = fixtureTime + 40 * 24 * 60 * 60 * 1000;
      }
      return fixture(
        `ocsp/${url.endsWith("/root") ? "intermediate-good" : "good"}.der`
      );
    }
  });
  const result = await validator.verify(input);
  assert.equal(result.valid, false);
  assert.equal(result.code, "REVOCATION_STATUS_UNKNOWN");
});

test("batch input snapshots and mixed CRL/OCSP results preserve certificate identity", async () => {
  const { X509Certificate } = await import("node:crypto");
  const path = ["leaf", "intermediate", "root"].map(
    (name) => new Uint8Array(new X509Certificate(fixture(`${name}.pem`)).raw)
  );
  const evidence = [
    {
      certificateIndex: 1,
      mechanism: "ocsp",
      data: Uint8Array.from(fixture("ocsp/intermediate-good.der")),
      checkDateMs: fixtureTime
    },
    {
      certificateIndex: 0,
      mechanism: "crl",
      data: Buffer.from(
        fixture("crl/intermediate-clean.crl.pem")
          .toString()
          .replace(/-----[^\n]+-----/g, ""),
        "base64"
      ),
      checkDateMs: fixtureTime
    }
  ];
  const pending = nativeValidateEvidence(path, evidence);
  for (const bytes of [...path, ...evidence.map((item) => item.data)])
    bytes.fill(0);
  const results = await pending;
  assert.deepEqual(
    results.map((item) => [
      item.certificateIndex,
      item.mechanism,
      item.result.status
    ]),
    [
      [1, "ocsp", "good"],
      [0, "crl", "good"]
    ]
  );
});

test("URI extraction is one native call and invalid paths never start evidence I/O", async () => {
  calls.length = 0;
  assert.deepEqual(getUriSubjectAlternativeNames(fixture("leaf.pem")), [
    "https://client.example.org/app"
  ]);
  assert.deepEqual(calls, ["getUriSubjectAlternativeNames"]);
  let loads = 0;
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => fixtureTime,
    loadOcsp: async () => {
      loads++;
      return fixture("ocsp/good.der");
    }
  });
  calls.length = 0;
  assert.equal(
    (await validator.verify({ certificateChain: [Buffer.of(0)] })).valid,
    false
  );
  assert.equal(loads, 0);
  assert.deepEqual(calls, ["validateCertificatePath"]);
});
