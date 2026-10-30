import { X509Certificate } from "node:crypto";
import { availableParallelism } from "node:os";
import { Piscina } from "piscina";
import type { CrlValidationResult } from "../engine/crl.ts";
import type { OcspValidationResult } from "../engine/ocsp.ts";
import type { PkiEngine, PreparedPathResult } from "../engine/pki-engine.ts";
import { ResourceLimitError } from "../errors.ts";
import type { PkiWorkerResult, PkiWorkerTask } from "./pki-worker-protocol.ts";

export interface PkiWorkerEngineOptions {
  filename?: string | URL;
  minThreads?: number;
  maxThreads?: number;
  maxQueue?: number;
  idleTimeout?: number;
  taskTimeoutMs?: number;
}

export interface PkiWorkerStats {
  threads: number;
  idleThreads: number;
  queueSize: number;
  completed: number;
}

export interface PkiWorkerEngine extends PkiEngine {
  readonly filename: string;
  close(options?: { force?: boolean }): Promise<void>;
  destroy(): Promise<void>;
  stats(): PkiWorkerStats;
}

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function defaultFilename(): URL {
  const extension = import.meta.url.endsWith(".ts") ? "ts" : "js";
  return new URL(`./pki-worker.${extension}`, import.meta.url);
}

function positiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
}

export function createWorkerPkiEngine(
  options: PkiWorkerEngineOptions = {}
): PkiWorkerEngine {
  const maxThreads =
    options.maxThreads ?? Math.max(1, Math.min(4, availableParallelism() - 1));
  const minThreads = options.minThreads ?? 0;
  const maxQueue = options.maxQueue ?? maxThreads * 4;
  const idleTimeout = options.idleTimeout ?? 30_000;
  const taskTimeoutMs = options.taskTimeoutMs ?? 10_000;
  positiveInteger(maxThreads, "maxThreads");
  if (!Number.isSafeInteger(minThreads) || minThreads < 0) {
    throw new TypeError("minThreads must be a non-negative integer");
  }
  if (minThreads > maxThreads) {
    throw new TypeError("minThreads must not exceed maxThreads");
  }
  if (!Number.isSafeInteger(maxQueue) || maxQueue < 0) {
    throw new TypeError("maxQueue must be a non-negative integer");
  }
  positiveInteger(idleTimeout, "idleTimeout");
  positiveInteger(taskTimeoutMs, "taskTimeoutMs");

  const filename = (options.filename ?? defaultFilename()).toString();
  const pool = new Piscina<PkiWorkerTask, PkiWorkerResult>({
    filename,
    minThreads,
    maxThreads,
    maxQueue,
    idleTimeout,
    closeTimeout: 5000
  });

  async function runTask<T extends PkiWorkerResult>(
    task: PkiWorkerTask,
    signal?: AbortSignal
  ): Promise<T> {
    if (signal?.aborted) throw abortError();
    const timeout = AbortSignal.timeout(taskTimeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    try {
      return (await pool.run(task, { signal: combined })) as T;
    } catch (error) {
      if (signal?.aborted) throw abortError();
      if (timeout.aborted) {
        throw new ResourceLimitError("PKI worker task timed out");
      }
      if (
        error instanceof Error &&
        (error.message === "Task queue is at limit" ||
          error.message.startsWith("No task queue available"))
      ) {
        throw new ResourceLimitError(error.message);
      }
      throw error;
    }
  }

  return {
    filename,

    async preparePath({ certificateChain, trustAnchors, checkDateMs, signal }) {
      let chain: Uint8Array[];
      try {
        chain = certificateChain.map((input) =>
          typeof input === "string"
            ? new Uint8Array(new X509Certificate(input).raw)
            : Uint8Array.from(input)
        );
      } catch {
        return {
          pathValid: false,
          code: "INVALID_CERTIFICATE",
          message:
            "The supplied certificate input is not a single valid DER value"
        };
      }
      return runTask<PreparedPathResult>(
        {
          op: "preparePath",
          certificateChain: chain,
          trustAnchors: trustAnchors.map((anchor) => Uint8Array.from(anchor)),
          checkDateMs
        },
        signal
      );
    },

    validateCrl({ certificateDer, issuerDer, crl, checkDateMs, signal }) {
      return runTask<CrlValidationResult>(
        {
          op: "validateCrl",
          certificateDer: Uint8Array.from(certificateDer),
          issuerDer: Uint8Array.from(issuerDer),
          crl: Uint8Array.from(crl),
          checkDateMs
        },
        signal
      );
    },

    validateOcsp({ certificateDer, issuerDer, response, checkDateMs, signal }) {
      return runTask<OcspValidationResult>(
        {
          op: "validateOcsp",
          certificateDer: Uint8Array.from(certificateDer),
          issuerDer: Uint8Array.from(issuerDer),
          response: Uint8Array.from(response),
          checkDateMs
        },
        signal
      );
    },

    stats() {
      return {
        threads: pool.threads.length,
        idleThreads: pool.idleThreads,
        queueSize: pool.queueSize,
        completed: pool.completed
      };
    },

    close(closeOptions) {
      return pool.close(closeOptions);
    },

    destroy() {
      return pool.destroy();
    }
  };
}
