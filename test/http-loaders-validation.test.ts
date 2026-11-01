import assert from "node:assert/strict";
import { test } from "node:test";
import { OCSPRequest } from "pkijs";
import { createTrustValidator } from "../src/index.ts";
import { readFixture } from "./helpers/fixtures.ts";
import {
  checkDate,
  responseCertId,
  routeFixtureUrls,
  startServer
} from "./helpers/http-loaders-fixtures.ts";

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
    response.end(readFixture(`ocsp/${name}.der`));
  });
  routeFixtureUrls(t, origin);
  const validator = createTrustValidator({
    trustAnchors: [readFixture("root.pem")],
    now: () => checkDate.getTime(),
    http: { allowPrivateAddresses: true }
  });
  const input = {
    certificateChain: [readFixture("leaf.pem"), readFixture("intermediate.pem")]
  };
  assert.equal((await validator.verify(input)).valid, true);
  assert.equal((await validator.verify(input)).valid, true);
  assert.deepEqual(requests, ["POST /intermediate", "POST /root"]);
  const revoked = await validator.verify({
    certificateChain: [
      readFixture("revoked-leaf.pem"),
      readFixture("intermediate.pem")
    ]
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
      response.end(readFixture(`crl/${name}.crl.pem`));
    }
  });
  routeFixtureUrls(t, origin);
  const validator = createTrustValidator({
    trustAnchors: [readFixture("root.pem")],
    now: () => checkDate.getTime(),
    http: { allowPrivateAddresses: true }
  });
  assert.equal(
    (
      await validator.verify({
        certificateChain: [
          readFixture("leaf.pem"),
          readFixture("intermediate.pem")
        ]
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
