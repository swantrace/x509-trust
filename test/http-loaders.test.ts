import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import http, { type RequestListener } from "node:http";
import type { AddressInfo } from "node:net";
import { type TestContext, test } from "node:test";
import { BasicOCSPResponse, OCSPRequest, OCSPResponse } from "pkijs";
import { createHttpLoaders } from "../src/evidence/http-loaders.ts";
import { createTrustValidator } from "../src/index.ts";

function fixture(name: string) {
  return readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
}

function crlDer(name: string) {
  return Buffer.from(
    fixture(`crl/${name}.crl.pem`)
      .toString()
      .replace(/-----[^\n]+-----/g, ""),
    "base64"
  );
}

function responseCertId(name: string) {
  const outer = OCSPResponse.fromBER(fixture(`ocsp/${name}.der`));
  return BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  ).tbsResponseData.responses[0].certID;
}

async function startServer(
  t: TestContext,
  handler: RequestListener
): Promise<string> {
  const server = http.createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch(() => {
      response.statusCode = 500;
      response.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(
    () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      })
  );
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function routeFixtureUrls(t: TestContext, origin: string): void {
  const request = http.request;
  // Signed fixtures use .test hosts; route only their destination to the local server.
  t.mock.method(http, "request", ((
    url: string | URL,
    options: http.RequestOptions,
    callback?: (response: http.IncomingMessage) => void
  ) => {
    const original = new URL(url);
    return request(
      new URL(original.pathname + original.search, origin),
      options,
      callback
    );
  }) as typeof http.request);
}

const checkDate = new Date(fixture("validation-time.txt").toString().trim());

test("downloads DER and PEM CRLs from an actual local HTTP server", async (t) => {
  const methods: string[] = [];
  const origin = await startServer(t, (request, response) => {
    methods.push(request.method!);
    response.setHeader("Content-Type", "application/pkix-crl");
    response.end(
      request.url === "/ca.crl"
        ? crlDer("intermediate-revoked")
        : fixture("crl/intermediate-revoked.crl.pem")
    );
  });
  const loaders = createHttpLoaders({ allowPrivateAddresses: true });
  for (const path of ["/ca.crl", "/ca.pem"]) {
    assert.deepEqual(
      Buffer.from(await loaders.loadCrl(origin + path)),
      crlDer("intermediate-revoked")
    );
  }
  assert.deepEqual(methods, ["GET", "GET"]);
});

test("POSTs a DER OCSP request identifying the certificate and issuing key", async (t) => {
  let received: OCSPRequest | undefined;
  let contentType: string | undefined;
  let accept: string | undefined;
  let method: string | undefined;
  const origin = await startServer(t, async (request, response) => {
    method = request.method;
    contentType = request.headers["content-type"];
    accept = request.headers.accept;
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    received = OCSPRequest.fromBER(Buffer.concat(chunks));
    response.setHeader("Content-Type", "application/ocsp-response");
    response.end(fixture("ocsp/good.der"));
  });
  const loaders = createHttpLoaders({ allowPrivateAddresses: true });
  const data = await loaders.loadOcsp({
    url: `${origin}/ocsp`,
    certificate: new X509Certificate(fixture("leaf.pem")).raw,
    issuerCertificate: new X509Certificate(fixture("intermediate.pem")).raw
  });
  assert.deepEqual(Buffer.from(data), fixture("ocsp/good.der"));
  assert.equal(method, "POST");
  assert.equal(contentType, "application/ocsp-request");
  assert.equal(accept, "application/ocsp-response");
  assert.ok(received);
  assert.equal(received.tbsRequest.requestList.length, 1);
  assert.ok(
    received.tbsRequest.requestList[0].reqCert.isEqual(responseCertId("good"))
  );
  assert.equal(received.optionalSignature, undefined);
});

test("default public loaders verify both path certificates over HTTP and reuse cached responses", async (t) => {
  const requests: string[] = [];
  const origin = await startServer(t, async (request, response) => {
    requests.push(`${request.method} ${request.url}`);
    assert.equal(request.method, "POST");
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    const incoming = OCSPRequest.fromBER(Buffer.concat(chunks));
    const id = incoming.tbsRequest.requestList[0].reqCert;
    const name =
      request.url === "/root"
        ? "intermediate-good"
        : id.isEqual(responseCertId("revoked"))
          ? "revoked"
          : "good";
    assert.ok(id.isEqual(responseCertId(name)));
    response.setHeader("Content-Type", "application/ocsp-response");
    response.end(fixture(`ocsp/${name}.der`));
  });
  routeFixtureUrls(t, origin);
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => checkDate.getTime(),
    http: { allowPrivateAddresses: true }
  });
  const input = {
    certificateChain: [fixture("leaf.pem"), fixture("intermediate.pem")]
  };
  assert.equal((await validator.verify(input)).valid, true);
  assert.equal((await validator.verify(input)).valid, true);
  assert.deepEqual(requests, ["POST /intermediate", "POST /root"]);
  const revoked = await validator.verify({
    certificateChain: [fixture("revoked-leaf.pem"), fixture("intermediate.pem")]
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
  assert.equal(requests.length, 3);
});

test("default public loaders fall back from unavailable OCSP to downloaded CRLs", async (t) => {
  const requests: string[] = [];
  const origin = await startServer(t, (request, response) => {
    requests.push(`${request.method} ${request.url}`);
    if (request.method === "POST") {
      response.writeHead(503);
      response.end();
    } else {
      const name =
        request.url === "/root.crl" ? "root" : "intermediate-revoked";
      response.end(fixture(`crl/${name}.crl.pem`));
    }
  });
  routeFixtureUrls(t, origin);
  const validator = createTrustValidator({
    trustAnchors: [fixture("root.pem")],
    now: () => checkDate.getTime(),
    http: { allowPrivateAddresses: true }
  });
  assert.equal(
    (
      await validator.verify({
        certificateChain: [fixture("leaf.pem"), fixture("intermediate.pem")]
      })
    ).valid,
    true
  );
  // The two certificate pipelines run concurrently; each must try its OCSP
  // endpoint before falling back to its CRL endpoint.
  assert.equal(requests.length, 4);
  assert.deepEqual(
    new Set(requests),
    new Set([
      "POST /intermediate",
      "GET /intermediate.crl",
      "POST /root",
      "GET /root.crl"
    ])
  );
  assert.ok(
    requests.indexOf("POST /intermediate") <
      requests.indexOf("GET /intermediate.crl")
  );
  assert.ok(requests.indexOf("POST /root") < requests.indexOf("GET /root.crl"));
});

test("rejects redirects and HTTP errors without following their Location", async (t) => {
  let redirected = false;
  const origin = await startServer(t, (request, response) => {
    if (request.url === "/destination") redirected = true;
    response.writeHead(Number(request.url!.slice(1)), {
      Location: "/destination"
    });
    response.end();
  });
  const loaders = createHttpLoaders({ allowPrivateAddresses: true });
  for (const status of [302, 404, 500]) {
    await assert.rejects(
      loaders.loadCrl(`${origin}/${status}`),
      new RegExp(String(status))
    );
  }
  assert.equal(redirected, false);
});

test("enforces size limits on declared and chunked response bodies", async (t) => {
  const origin = await startServer(t, (request, response) => {
    if (request.url === "/declared") response.setHeader("Content-Length", 256);
    response.write(Buffer.alloc(128));
    response.end(Buffer.alloc(128));
  });
  const loaders = createHttpLoaders({
    allowPrivateAddresses: true,
    maxResponseBytes: 128
  });
  for (const path of ["/declared", "/chunked"]) {
    await assert.rejects(
      loaders.loadCrl(origin + path),
      /exceeds maxResponseBytes/
    );
  }
});

test("the deadline includes a stalled response body", async (t) => {
  const origin = await startServer(t, (_request, response) => {
    response.writeHead(200);
    response.flushHeaders();
  });
  const loaders = createHttpLoaders({
    allowPrivateAddresses: true,
    timeoutMs: 50
  });
  await assert.rejects(loaders.loadCrl(origin), /abort/i);
});

test("an external AbortSignal cancels a built-in HTTP request", async (t) => {
  const requestStarted = new Promise<void>((resolve) => {
    t.after(() => resolve());
  });
  const origin = await startServer(t, (_request, response) => {
    response.writeHead(200);
    response.flushHeaders();
    requestStarted.then(() => response.end());
  });
  const loaders = createHttpLoaders({
    allowPrivateAddresses: true,
    timeoutMs: 5000
  });
  const controller = new AbortController();
  const pending = loaders.loadCrl(origin, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, /abort/i);
});

test("rejects non-public literal addresses and unsafe URLs before opening a connection", async (t) => {
  let calls = 0;
  t.mock.method(http, "request", (() => {
    calls++;
    throw new Error("Unexpected request");
  }) as typeof http.request);
  const loaders = createHttpLoaders();
  for (const host of [
    "127.0.0.1",
    "2130706433",
    "10.0.0.1",
    "169.254.169.254",
    "[::1]",
    "[::ffff:127.0.0.1]",
    "[fd00::1]"
  ]) {
    await assert.rejects(
      loaders.loadCrl(`http://${host}/ca.crl`),
      /public addresses/
    );
  }
  for (const url of [
    "file:///tmp/ca.crl",
    "http://user:password@example.org/ca.crl",
    "http://example.org/ca.crl#fragment"
  ]) {
    await assert.rejects(loaders.loadCrl(url), /HTTP\(S\)/);
  }
  assert.equal(calls, 0);
});

test("blocks a hostname that resolves to a private address at connection time", async (t) => {
  let hits = 0;
  const origin = await startServer(t, (_request, response) => {
    hits++;
    response.end();
  });
  t.mock.method(dns, "lookup", ((_host, _options, callback) => {
    const resolved = callback as unknown as (
      error: Error | null,
      addresses: Array<{ address: string; family: number }>
    ) => void;
    resolved(null, [{ address: "127.0.0.1", family: 4 }]);
  }) as typeof dns.lookup);
  const url = new URL(origin);
  url.hostname = "private.example.test";
  await assert.rejects(
    createHttpLoaders().loadCrl(url.toString()),
    /public addresses/
  );
  assert.equal(hits, 0);
});

test("an origin allowlist still applies when private addresses are explicitly enabled", async (t) => {
  const origin = await startServer(t, (_request, response) => response.end());
  const loaders = createHttpLoaders({
    allowPrivateAddresses: true,
    allowedOrigins: ["https://approved.example.org"]
  });
  await assert.rejects(loaders.loadCrl(origin), /origin is not allowed/);
});

test("rejects invalid HTTP settings at configuration time", () => {
  assert.throws(
    () =>
      createHttpLoaders({
        allowPrivateAddresses: "false" as unknown as boolean
      }),
    TypeError
  );
  for (const value of [0, -1, NaN, Infinity, 1.5]) {
    assert.throws(() => createHttpLoaders({ timeoutMs: value }), TypeError);
    assert.throws(
      () => createHttpLoaders({ maxResponseBytes: value }),
      TypeError
    );
  }
  assert.throws(() => createHttpLoaders({ timeoutMs: 2 ** 32 }), TypeError);
});
