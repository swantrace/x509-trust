import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { OCSPRequest } from "pkijs";
import { inlinePkiEngine } from "../src/engine/pki-engine.ts";
import {
  loadHttpCrl,
  loadHttpOcsp,
  resolveHttpOptions
} from "../src/revocation/http-loaders.ts";
import { readCrl, readFixture } from "./helpers/fixtures.ts";
import {
  checkDate,
  responseCertId,
  startServer
} from "./helpers/http-loaders-fixtures.ts";

test("downloads DER and PEM CRLs from an actual local HTTP server", async (t) => {
  const methods: string[] = [];
  const origin = await startServer(t, (request, response) => {
    methods.push(request.method!);
    response.setHeader("Content-Type", "application/pkix-crl");
    response.end(
      request.url === "/ca.crl"
        ? readCrl("intermediate-revoked")
        : readFixture("crl/intermediate-revoked.crl.pem")
    );
  });
  const httpConfig = resolveHttpOptions({ allowPrivateAddresses: true });
  for (const path of ["/ca.crl", "/ca.pem"]) {
    assert.deepEqual(
      Buffer.from(await loadHttpCrl({ url: origin + path }, httpConfig)),
      readCrl("intermediate-revoked")
    );
  }
  assert.deepEqual(methods, ["GET", "GET"]);
});

test("POSTs prepared OCSP request bytes without changing them", async (t) => {
  const bodies: Buffer[] = [];
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
    const body = Buffer.concat(chunks);
    bodies.push(body);
    received = OCSPRequest.fromBER(body);
    response.setHeader("Content-Type", "application/ocsp-response");
    response.end(readFixture("ocsp/good.der"));
  });
  const httpConfig = resolveHttpOptions({ allowPrivateAddresses: true });
  const path = await inlinePkiEngine.preparePath({
    certificateChain: [
      readFixture("leaf.pem"),
      readFixture("intermediate.pem")
    ],
    trustAnchors: [new X509Certificate(readFixture("root.pem")).raw],
    checkDateMs: checkDate.getTime()
  });
  assert.ok(path.pathValid);
  const requestDer = path.certificates[0].ocspRequestDer;
  assert.ok(requestDer);
  const callerBytes = Uint8Array.from(requestDer);
  const pending = loadHttpOcsp(
    {
      url: `${origin}/ocsp`,
      requestDer: callerBytes
    },
    httpConfig
  );
  callerBytes.fill(0);
  const data = await pending;
  assert.deepEqual(Buffer.from(data), readFixture("ocsp/good.der"));
  assert.deepEqual(bodies, [Buffer.from(requestDer)]);
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
