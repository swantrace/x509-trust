// Validates HTTP options, URL origins, and public network addresses before connecting.
import dns from "node:dns";
import { BlockList, isIP, type LookupFunction } from "node:net";

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

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

export interface HttpOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowedOrigins?: readonly string[];
  allowPrivateAddresses?: boolean;
}

export interface HttpConfig {
  timeoutMs: number;
  maxResponseBytes: number;
  origins?: ReadonlySet<string>;
  allowPrivateAddresses: boolean;
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !nonPublicAddresses.check(address, "ipv4");
  return (
    family === 6 &&
    globalIpv6.check(address, "ipv6") &&
    !nonPublicAddresses.check(address, "ipv6")
  );
}

export const publicLookup: LookupFunction = (hostname, options, callback) => {
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

export function parseHttpUrl(value: string): URL {
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

export function resolveHttpOptions({
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  allowedOrigins,
  allowPrivateAddresses = false
}: HttpOptions = {}): HttpConfig {
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
  return { timeoutMs, maxResponseBytes, origins, allowPrivateAddresses };
}
