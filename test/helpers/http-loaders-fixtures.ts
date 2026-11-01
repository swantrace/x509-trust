import http, { type RequestListener } from "node:http";
import type { AddressInfo } from "node:net";
import { type TestContext } from "node:test";
import { BasicOCSPResponse, OCSPResponse } from "pkijs";
import { fixtureTime, readFixture } from "./fixtures.ts";

export function responseCertId(name: string) {
  const outer = OCSPResponse.fromBER(readFixture(`ocsp/${name}.der`));
  return BasicOCSPResponse.fromBER(
    Uint8Array.from(outer.responseBytes!.response.valueBlock.valueHexView)
  ).tbsResponseData.responses[0].certID;
}

export async function startServer(
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

export function routeFixtureUrls(t: TestContext, origin: string): void {
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

export const checkDate = new Date(fixtureTime);
