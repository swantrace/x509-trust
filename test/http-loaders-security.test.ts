import assert from "node:assert/strict";
import dns from "node:dns";
import http from "node:http";
import { test } from "node:test";
import { createRevocationProvider } from "../src/index.ts";
import {
  loadHttpCrl,
  resolveHttpOptions
} from "../src/revocation/http-loaders.ts";
import { startServer } from "./helpers/http-loaders-fixtures.ts";

test("rejects non-public literal addresses and unsafe URLs before opening a connection", async (t) => {
  let calls = 0;
  t.mock.method(http, "request", (() => {
    calls++;
    throw new Error("Unexpected request");
  }) as typeof http.request);
  const httpConfig = resolveHttpOptions();
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
      loadHttpCrl({ url: `http://${host}/ca.crl` }, httpConfig),
      /public addresses/
    );
  }
  for (const url of [
    "file:///tmp/ca.crl",
    "http://user:password@example.org/ca.crl",
    "http://example.org/ca.crl#fragment"
  ]) {
    await assert.rejects(loadHttpCrl({ url }, httpConfig), /HTTP\(S\)/);
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
    loadHttpCrl({ url: url.toString() }, resolveHttpOptions()),
    /public addresses/
  );
  assert.equal(hits, 0);
});

test("an origin allowlist still applies when private addresses are explicitly enabled", async (t) => {
  const origin = await startServer(t, (_request, response) => response.end());
  const httpConfig = resolveHttpOptions({
    allowPrivateAddresses: true,
    allowedOrigins: ["https://approved.example.org"]
  });
  await assert.rejects(
    loadHttpCrl({ url: origin }, httpConfig),
    /origin is not allowed/
  );
});

test("rejects invalid HTTP settings at configuration time", () => {
  assert.throws(
    () =>
      resolveHttpOptions({
        allowPrivateAddresses: "false" as unknown as boolean
      }),
    TypeError
  );
  for (const value of [0, -1, NaN, Infinity, 1.5]) {
    assert.throws(() => resolveHttpOptions({ timeoutMs: value }), TypeError);
    assert.throws(
      () => resolveHttpOptions({ maxResponseBytes: value }),
      TypeError
    );
    assert.throws(
      () => createRevocationProvider({ http: { timeoutMs: value } }),
      TypeError
    );
  }
  assert.throws(() => resolveHttpOptions({ timeoutMs: 2 ** 32 }), TypeError);
});
