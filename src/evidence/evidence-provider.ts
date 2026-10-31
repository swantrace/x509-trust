import { createHash } from "node:crypto";
import { ResourceLimitError } from "../errors.ts";
import {
  type CrlLoadOptions,
  createHttpLoaders,
  type HttpOptions,
  type OcspLoadOptions
} from "./http-loaders.ts";
import {
  createRequestScheduler,
  type RequestSchedulerOptions,
  type RequestSchedulerStats
} from "./request-scheduler.ts";

export type CrlLoader = (
  url: string,
  options?: CrlLoadOptions
) => Promise<Uint8Array>;
export type OcspLoader = (options: OcspLoadOptions) => Promise<Uint8Array>;

export interface EvidenceProviderOptions extends RequestSchedulerOptions {
  loadCrl?: CrlLoader | false;
  loadOcsp?: OcspLoader | false;
  http?: HttpOptions;
}

export interface EvidenceProvider {
  readonly supportsCrl: boolean;
  readonly supportsOcsp: boolean;
  loadCrl(url: string, options?: CrlLoadOptions): Promise<Uint8Array>;
  loadOcsp(options: OcspLoadOptions): Promise<Uint8Array>;
  stats(): RequestSchedulerStats;
}

export const EVIDENCE_PROVIDER_DEFAULTS = Object.freeze({
  maxActiveRequests: 8,
  maxQueuedRequests: 32,
  maxActivePerOrigin: 4,
  queueTimeoutMs: 30_000
});

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function digest(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

class ShareDownload {
  readonly #controller = new AbortController();
  readonly #promise: Promise<Uint8Array>;
  readonly #onFinish: () => void;
  #waiters = 0;
  #settled = false;

  constructor(
    start: (signal: AbortSignal) => Promise<Uint8Array>,
    onFinish: () => void
  ) {
    this.#onFinish = onFinish;
    this.#promise = start(this.#controller.signal);
    const settled = () => {
      this.#settled = true;
      this.#onFinish();
    };
    this.#promise.then(settled, settled);
  }

  subscribe(signal?: AbortSignal): Promise<Uint8Array> {
    if (signal?.aborted) return Promise.reject(abortError());
    return new Promise<Uint8Array>((resolve, reject) => {
      let done = false;
      const finish = (): boolean => {
        if (done) return false;
        done = true;
        signal?.removeEventListener("abort", onAbort);
        this.#waiters--;
        return true;
      };
      const onAbort = () => {
        if (!finish()) return;
        if (this.#waiters === 0 && !this.#settled) {
          this.#onFinish();
          this.#controller.abort();
        }
        reject(abortError());
      };
      this.#waiters++;
      this.#promise.then(
        (value) => {
          if (finish()) resolve(value);
        },
        (error) => {
          if (finish()) reject(error);
        }
      );
      if (signal) {
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
      }
    });
  }
}

export function createEvidenceProvider({
  loadCrl,
  loadOcsp,
  http,
  ...schedulerOptions
}: EvidenceProviderOptions = {}): EvidenceProvider {
  const defaults =
    loadCrl === undefined || loadOcsp === undefined
      ? createHttpLoaders(http)
      : undefined;
  const crlLoader: CrlLoader | false =
    loadCrl === false ? false : (loadCrl ?? defaults!.loadCrl);
  const ocspLoader: OcspLoader | false =
    loadOcsp === false ? false : (loadOcsp ?? defaults!.loadOcsp);
  const scheduler = createRequestScheduler(schedulerOptions);
  const downloads = new Map<string, ShareDownload>();

  function sharedLoad(
    key: string,
    origin: string,
    signal: AbortSignal | undefined,
    load: (signal: AbortSignal) => Promise<Uint8Array>
  ): Promise<Uint8Array> {
    if (signal?.aborted) return Promise.reject(abortError());
    let download = downloads.get(key);
    if (!download) {
      const created = new ShareDownload(
        (signal) => scheduler.run(origin, signal, () => load(signal)),
        () => {
          if (downloads.get(key) === created) downloads.delete(key);
        }
      );
      download = created;
      downloads.set(key, download);
    }
    return download.subscribe(signal);
  }

  return {
    supportsCrl: crlLoader !== false,
    supportsOcsp: ocspLoader !== false,

    stats() {
      return scheduler.stats();
    },

    loadCrl(url, options = {}) {
      if (crlLoader === false) {
        return Promise.reject(new Error("CRL loading is disabled"));
      }
      if (!options.issuerCertificate) {
        return Promise.reject(
          new TypeError(
            "A CRL request requires issuerCertificate to identify shared downloads"
          )
        );
      }
      const key = `crl\0${url}\0${digest(options.issuerCertificate)}`;
      return sharedLoad(key, originOf(url), options.signal, (signal) =>
        crlLoader(url, {
          signal,
          issuerCertificate: options.issuerCertificate
        })
      );
    },

    loadOcsp(options) {
      if (ocspLoader === false) {
        return Promise.reject(new Error("OCSP loading is disabled"));
      }
      if (!options.requestDer) {
        return Promise.reject(
          new TypeError(
            "An OCSP request requires requestDer to identify shared downloads"
          )
        );
      }
      const key = [
        "ocsp",
        options.url,
        digest(options.certificate),
        digest(options.issuerCertificate),
        digest(options.requestDer)
      ].join("\0");
      return sharedLoad(key, originOf(options.url), options.signal, (signal) =>
        ocspLoader({ ...options, signal })
      );
    }
  };
}

export { ResourceLimitError };
