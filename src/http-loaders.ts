import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { Certificate, OCSPRequest } from "pkijs";

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const OCSP_CERT_ID_HASH = "SHA-1";

const nonPublicAddresses = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
] as const)
  nonPublicAddresses.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20]
] as const)
  nonPublicAddresses.addSubnet(network, prefix, "ipv6");
const globalIpv6 = new BlockList();
globalIpv6.addSubnet("2000::", 3, "ipv6");

export interface CrlLoadOptions {
  signal?: AbortSignal;
}

export interface OcspLoadOptions {
  url: string;
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  signal?: AbortSignal;
}

export interface HttpOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowedOrigins?: readonly string[];
  allowPrivateAddresses?: boolean;
}

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !nonPublicAddresses.check(address, "ipv4");
  return (
    family === 6 &&
    globalIpv6.check(address, "ipv6") &&
    !nonPublicAddresses.check(address, "ipv6")
  );
}

const publicLookup: LookupFunction = (hostname, options, callback) => {
  // Validate the exact addresses supplied to the connection, not a separate lookup.
  dns.lookup(
    hostname,
    { all: true, family: options.family, hints: options.hints },
    (error, addresses) => {
      if (error) return callback(error, "");
      if (
        addresses.length === 0 ||
        addresses.some(({ address }) => !isPublicAddress(address))
      ) {
        return callback(
          new Error("HTTP revocation sources must resolve to public addresses"),
          ""
        );
      }
      if (options.all) callback(null, addresses);
      else callback(null, addresses[0].address, addresses[0].family);
    }
  );
};

function parseHttpUrl(value: string): URL {
  const url = new URL(value);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash
  ) {
    throw new TypeError(
      "Revocation URL must use HTTP(S) without credentials or a fragment"
    );
  }
  return url;
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

  function mergeDeadline(external?: AbortSignal): {
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
    urlString: string,
    body?: Uint8Array,
    externalSignal?: AbortSignal
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
    const deadline = mergeDeadline(externalSignal);
    return new Promise<Uint8Array>((resolve, reject) => {
      const outgoing = transport.request(
        url,
        {
          method: body ? "POST" : "GET",
          agent: false,
          lookup: allowPrivateAddresses ? undefined : publicLookup,
          signal: deadline.signal,
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
    }).finally(deadline.dispose);
  }

  return {
    async loadCrl(url: string, options?: CrlLoadOptions): Promise<Uint8Array> {
      const data = await request(url, undefined, options?.signal);
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
      certificate,
      issuerCertificate,
      signal
    }: OcspLoadOptions): Promise<Uint8Array> {
      const ocsp = new OCSPRequest();
      await ocsp.createForCertificate(
        Certificate.fromBER(Uint8Array.from(certificate)),
        {
          issuerCertificate: Certificate.fromBER(
            Uint8Array.from(issuerCertificate)
          ),
          hashAlgorithm: OCSP_CERT_ID_HASH
        }
      );
      return request(
        url,
        new Uint8Array(ocsp.toSchema(true).toBER(false)),
        signal
      );
    }
  };
}
