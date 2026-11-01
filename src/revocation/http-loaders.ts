// Downloads CRLs with GET and OCSP responses with POST while enforcing HTTP transport limits.
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import {
  type HttpConfig,
  isPublicAddress,
  parseHttpUrl,
  publicLookup
} from "./http-policy.ts";

export { type HttpOptions, resolveHttpOptions } from "./http-policy.ts";

interface HttpLoadOptions {
  url: string;
  signal?: AbortSignal;
}

interface HttpRequest {
  url: string;
  method: "GET" | "POST";
  headers: http.OutgoingHttpHeaders;
  body?: Uint8Array;
  signal?: AbortSignal;
}

function mergeDeadline(
  timeoutMs: number,
  external?: AbortSignal
): {
  signal: AbortSignal;
  dispose(): void;
} {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(
      new DOMException(
        "The operation was aborted due to timeout",
        "TimeoutError"
      )
    );
  }, timeoutMs);
  timer.unref();
  const onAbort = () => {
    clearTimeout(timer);
    controller.abort(external?.reason);
  };
  if (external) {
    if (external.aborted) onAbort();
    else external.addEventListener("abort", onAbort, { once: true });
  }
  return {
    signal: controller.signal,
    dispose() {
      clearTimeout(timer);
      external?.removeEventListener("abort", onAbort);
    }
  };
}

async function request(
  { url: urlString, method, headers, body, signal }: HttpRequest,
  { origins, allowPrivateAddresses, timeoutMs, maxResponseBytes }: HttpConfig
): Promise<Uint8Array> {
  const url = parseHttpUrl(urlString);
  if (origins && !origins.has(url.origin))
    throw new Error("Revocation URL origin is not allowed");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!allowPrivateAddresses && isIP(hostname) && !isPublicAddress(hostname)) {
    throw new Error("HTTP revocation sources must use public addresses");
  }
  const transport = url.protocol === "https:" ? https : http;
  const deadline = mergeDeadline(timeoutMs, signal);
  return new Promise<Uint8Array>((resolve, reject) => {
    const outgoing = transport.request(
      url,
      {
        method,
        headers,
        agent: false,
        lookup: allowPrivateAddresses ? undefined : publicLookup,
        signal: deadline.signal
      },
      (response) => {
        response.on("error", reject);
        if (response.statusCode !== 200) {
          response.destroy();
          reject(
            new Error(`Revocation HTTP request returned ${response.statusCode}`)
          );
          return;
        }
        if (Number(response.headers["content-length"]) > maxResponseBytes) {
          response.destroy();
          reject(new Error("Revocation response exceeds maxResponseBytes"));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.byteLength;
          if (size > maxResponseBytes) {
            response.destroy(
              new Error("Revocation response exceeds maxResponseBytes")
            );
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => resolve(Buffer.concat(chunks, size)));
      }
    );
    outgoing.on("error", reject);
    outgoing.end(body);
  }).finally(deadline.dispose);
}

export async function loadHttpCrl(
  { url, signal }: HttpLoadOptions,
  http: HttpConfig
): Promise<Uint8Array> {
  const data = await request(
    {
      url,
      method: "GET",
      headers: {
        Accept: "application/pkix-crl, application/octet-stream, text/plain"
      },
      signal
    },
    http
  );
  const text = Buffer.from(data).toString("ascii").trim();
  if (!text.startsWith("-----BEGIN")) return data;
  const pem =
    /^-----BEGIN X509 CRL-----\s+([A-Za-z0-9+/=\s]+)-----END X509 CRL-----$/.exec(
      text
    );
  if (!pem) throw new Error("Invalid PEM CRL response");
  return Buffer.from(pem[1], "base64");
}

export async function loadHttpOcsp(
  { url, requestDer, signal }: HttpLoadOptions & { requestDer: Uint8Array },
  http: HttpConfig
): Promise<Uint8Array> {
  const body = Uint8Array.from(requestDer);
  return request(
    {
      url,
      method: "POST",
      headers: {
        "Content-Type": "application/ocsp-request",
        Accept: "application/ocsp-response",
        "Content-Length": body.byteLength
      },
      body,
      signal
    },
    http
  );
}
