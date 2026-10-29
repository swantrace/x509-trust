import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { isPublicAddress, parseHttpUrl, publicLookup } from "./http-policy.ts";

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

export interface OcspLoadOptions {
  url: string;
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  /** Prepared by Rust with the validated path. Custom loaders may ignore it. */
  request?: Uint8Array;
  /** Aborted when another certificate is confirmed revoked. */
  signal?: AbortSignal;
}

export interface CrlLoadOptions {
  /** Aborted when another certificate is confirmed revoked. */
  signal?: AbortSignal;
}

export interface HttpOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowedOrigins?: readonly string[];
  allowPrivateAddresses?: boolean;
}

export function createHttpLoaders({
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  allowedOrigins,
  allowPrivateAddresses = false
}: HttpOptions = {}) {
  if (typeof allowPrivateAddresses !== "boolean") {
    throw new TypeError("allowPrivateAddresses must be a boolean");
  }
  for (const [name, value] of Object.entries({ timeoutMs, maxResponseBytes })) {
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new TypeError(`${name} must be a positive integer`);
  }
  if (timeoutMs > 2 ** 31 - 1)
    throw new TypeError("timeoutMs exceeds the supported timer range");
  const origins =
    allowedOrigins &&
    new Set(allowedOrigins.map((value) => parseHttpUrl(value).origin));

  async function request(
    urlString: string,
    body?: Uint8Array,
    signal?: AbortSignal
  ): Promise<Uint8Array> {
    const url = parseHttpUrl(urlString);
    if (origins && !origins.has(url.origin))
      throw new Error("Revocation URL origin is not allowed");
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    if (
      !allowPrivateAddresses &&
      isIP(hostname) &&
      !isPublicAddress(hostname)
    ) {
      throw new Error("HTTP revocation sources must use public addresses");
    }
    const transport = url.protocol === "https:" ? https : http;
    return new Promise((resolve, reject) => {
      const outgoing = transport.request(
        url,
        {
          method: body ? "POST" : "GET",
          agent: false,
          lookup: allowPrivateAddresses ? undefined : publicLookup,
          signal: signal
            ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
            : AbortSignal.timeout(timeoutMs),
          headers: body
            ? {
                "Content-Type": "application/ocsp-request",
                Accept: "application/ocsp-response",
                "Content-Length": body.byteLength
              }
            : {
                Accept:
                  "application/pkix-crl, application/octet-stream, text/plain"
              }
        },
        (response) => {
          response.on("error", reject);
          if (response.statusCode !== 200) {
            response.destroy();
            reject(
              new Error(
                `Revocation HTTP request returned ${response.statusCode}`
              )
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
      outgoing.end(body && Buffer.from(body));
    });
  }

  return {
    async loadCrl(
      url: string,
      { signal }: CrlLoadOptions = {}
    ): Promise<Uint8Array> {
      const data = await request(url, undefined, signal);
      const text = Buffer.from(data).toString("ascii").trim();
      if (!text.startsWith("-----BEGIN")) return data;
      const pem =
        /^-----BEGIN X509 CRL-----\s+([A-Za-z0-9+/=\s]+)-----END X509 CRL-----$/.exec(
          text
        );
      if (!pem) throw new Error("Invalid PEM CRL response");
      return Buffer.from(pem[1], "base64");
    },
    async loadOcsp({
      url,
      request: body,
      signal
    }: OcspLoadOptions): Promise<Uint8Array> {
      if (!body) throw new Error("OCSP request DER is required");
      return request(url, body, signal);
    }
  };
}
