import { createHash } from "node:crypto";
import type { CertificateRevocationList } from "pkijs";

export interface CrlIndexCacheOptions {
  /** Maximum number of parsed CRLs retained. */
  maxEntries?: number;
  /** Approximate maximum bytes retained (DER + serial index overhead). */
  maxBytes?: number;
}

export interface CrlIndex {
  readonly derHash: string;
  readonly crl: CertificateRevocationList;
  readonly serials: ReadonlySet<string>;
  readonly unsupportedExtensions: boolean;
  readonly bytes: number;
}

export interface CrlIndexCacheStats {
  entries: number;
  bytes: number;
  hits: number;
  misses: number;
  evictions: number;
}

export interface CrlIndexCache {
  get(derHash: string): CrlIndex | undefined;
  set(index: CrlIndex): void;
  stats(): CrlIndexCacheStats;
  clear(): void;
}

const DEFAULT_MAX_ENTRIES = 8;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;

export function crlDerHash(der: Uint8Array): string {
  return createHash("sha256").update(der).digest("base64url");
}

export function serialNumberKey(serial: {
  valueBlock: { valueHexView: Uint8Array };
}): string {
  return Buffer.from(serial.valueBlock.valueHexView).toString("hex");
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return value;
}

export function createCrlIndexCache({
  maxEntries = DEFAULT_MAX_ENTRIES,
  maxBytes = DEFAULT_MAX_BYTES
}: CrlIndexCacheOptions = {}): CrlIndexCache {
  positiveInteger(maxEntries, "crlIndexCache.maxEntries");
  positiveInteger(maxBytes, "crlIndexCache.maxBytes");

  const entries = new Map<string, CrlIndex>();
  let bytes = 0;
  let hits = 0;
  let misses = 0;
  let evictions = 0;

  function remove(hash: string): void {
    const entry = entries.get(hash);
    if (!entry) return;
    entries.delete(hash);
    bytes -= entry.bytes;
  }

  return {
    get(derHash) {
      const entry = entries.get(derHash);
      if (!entry) {
        misses++;
        return undefined;
      }
      hits++;
      // Refresh LRU position.
      entries.delete(derHash);
      entries.set(derHash, entry);
      return entry;
    },

    set(index) {
      remove(index.derHash);
      entries.set(index.derHash, index);
      bytes += index.bytes;
      while (
        entries.size > maxEntries ||
        (bytes > maxBytes && entries.size > 1)
      ) {
        const oldest = entries.keys().next().value;
        if (oldest === undefined) break;
        remove(oldest);
        evictions++;
      }
      if (bytes > maxBytes) {
        // A single entry larger than the byte budget is not retained.
        remove(index.derHash);
        evictions++;
      }
    },

    stats() {
      return {
        entries: entries.size,
        bytes,
        hits,
        misses,
        evictions
      };
    },

    clear() {
      entries.clear();
      bytes = 0;
    }
  };
}
