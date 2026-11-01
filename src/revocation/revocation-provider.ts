import { createHash } from "node:crypto";
import PQueue from "p-queue";
import { createSharedTaskQueue } from "../shared-task-queue.ts";
import {
  type HttpOptions,
  loadHttpCrl,
  loadHttpOcsp,
  resolveHttpOptions
} from "./http-loaders.ts";

export interface CrlRequest {
  url: string;
  issuerCertificate: Uint8Array;
  signal?: AbortSignal;
}

export interface OcspRequest extends CrlRequest {
  certificate: Uint8Array;
  requestDer: Uint8Array;
}

export type CrlRequestLoader = (options: CrlRequest) => Promise<Uint8Array>;
export type OcspRequestLoader = (options: OcspRequest) => Promise<Uint8Array>;

export interface RevocationLoaderOptions {
  crlLoader?: CrlRequestLoader | false;
  ocspLoader?: OcspRequestLoader | false;
}

export interface RevocationProviderOptions extends RevocationLoaderOptions {
  http?: HttpOptions;
  maxActiveRequests?: number;
}

export interface RevocationProviderStats {
  active: number;
  queued: number;
}

export interface RevocationProvider {
  loadCrl?: CrlRequestLoader;
  loadOcsp?: OcspRequestLoader;
  stats(): RevocationProviderStats;
}

export const DEFAULT_MAX_ACTIVE_REQUESTS = 8;

type Download = (signal: AbortSignal) => Promise<Uint8Array>;

function digest(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function createRevocationProvider({
  crlLoader,
  ocspLoader,
  http,
  maxActiveRequests = DEFAULT_MAX_ACTIVE_REQUESTS
}: RevocationProviderOptions = {}): RevocationProvider {
  const httpConfig =
    crlLoader === undefined || ocspLoader === undefined
      ? resolveHttpOptions(http)
      : undefined;
  const scheduler = new PQueue({ concurrency: maxActiveRequests });

  function scheduleDownload(download: Download, signal: AbortSignal) {
    return scheduler.add(() => download(signal), { signal });
  }

  const downloadQueue = createSharedTaskQueue({ execute: scheduleDownload });

  const provider: RevocationProvider = {
    stats(): RevocationProviderStats {
      return { active: scheduler.pending, queued: scheduler.size };
    }
  };

  if (crlLoader !== false) {
    provider.loadCrl = async (options) => {
      const { url, issuerCertificate } = options;
      if (!issuerCertificate) {
        throw new TypeError(
          "A CRL request requires issuerCertificate to identify shared downloads"
        );
      }
      const key = `crl\0${url}\0${digest(issuerCertificate)}`;
      const download: Download = (signal) => {
        const input = { url, issuerCertificate, signal };
        return crlLoader ? crlLoader(input) : loadHttpCrl(input, httpConfig!);
      };
      return downloadQueue.add(key, download, options);
    };
  }

  if (ocspLoader !== false) {
    provider.loadOcsp = async (options) => {
      const { url, certificate, issuerCertificate, requestDer } = options;
      if (!requestDer) {
        throw new TypeError(
          "An OCSP request requires requestDer to identify shared downloads"
        );
      }
      const key = `ocsp\0${url}\0${digest(certificate)}\0${digest(issuerCertificate)}\0${digest(requestDer)}`;
      const download: Download = (signal) => {
        const input = {
          url,
          certificate,
          issuerCertificate,
          requestDer,
          signal
        };
        return ocspLoader
          ? ocspLoader(input)
          : loadHttpOcsp(input, httpConfig!);
      };
      return downloadQueue.add(key, download, options);
    };
  }

  return provider;
}
