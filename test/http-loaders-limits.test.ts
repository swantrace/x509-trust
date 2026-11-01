import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustValidator } from "../src/index.ts";
import {
  loadHttpCrl,
  resolveHttpOptions
} from "../src/revocation/http-loaders.ts";
import { readFixture } from "./helpers/fixtures.ts";
import {
  checkDate,
  routeFixtureUrls,
  startServer
} from "./helpers/http-loaders-fixtures.ts";

test("rejects redirects and HTTP errors without following their Location", async (t) => {
  let redirected = false;
  const origin = await startServer(t, (request, response) => {
    if (request.url === "/destination") redirected = true;
    response.writeHead(Number(request.url!.slice(1)), {
      Location: "/destination"
    });
    response.end();
  });
  const httpConfig = resolveHttpOptions({ allowPrivateAddresses: true });
  for (const status of [302, 404, 500]) {
    await assert.rejects(
      loadHttpCrl({ url: `${origin}/${status}` }, httpConfig),
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
  const httpConfig = resolveHttpOptions({
    allowPrivateAddresses: true,
    maxResponseBytes: 128
  });
  for (const path of ["/declared", "/chunked"]) {
    await assert.rejects(
      loadHttpCrl({ url: origin + path }, httpConfig),
      /exceeds maxResponseBytes/
    );
  }
});

test("the deadline includes a stalled response body", async (t) => {
  const origin = await startServer(t, (_request, response) => {
    response.writeHead(200);
    response.flushHeaders();
  });
  const httpConfig = resolveHttpOptions({
    allowPrivateAddresses: true,
    timeoutMs: 50
  });
  await assert.rejects(loadHttpCrl({ url: origin }, httpConfig), /abort/i);
});

test("validation findings identify actual HTTP timeouts before the overall deadline", async (t) => {
  const origin = await startServer(t, (_request, response) => {
    response.writeHead(200);
    response.flushHeaders();
  });
  routeFixtureUrls(t, origin);
  const validator = createTrustValidator({
    trustAnchors: [readFixture("root.pem")],
    now: () => checkDate.getTime(),
    ocspLoader: false,
    http: { allowPrivateAddresses: true, timeoutMs: 50 },
    deadlineMs: 5000
  });
  const result = await validator.verify({
    certificateChain: [readFixture("leaf.pem"), readFixture("intermediate.pem")]
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, "REVOCATION_STATUS_UNKNOWN");
  assert.equal(result.findings?.length, 2);
  for (const certificate of result.findings!) {
    const attempt = certificate.revocation.crl[0];
    assert.equal(attempt.code, "EVIDENCE_TIMEOUT");
    assert.ok(attempt.source?.startsWith("http://crl.example.test/"));
    assert.ok(attempt.durationMs! >= 0);
  }
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
  const httpConfig = resolveHttpOptions({
    allowPrivateAddresses: true,
    timeoutMs: 5000
  });
  const controller = new AbortController();
  const pending = loadHttpCrl(
    { url: origin, signal: controller.signal },
    httpConfig
  );
  controller.abort();
  await assert.rejects(pending, /abort/i);
});
