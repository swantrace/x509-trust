import type {
  NativeEvidenceInput,
  NativeEvidenceResult
} from "../native/index.js";
import { nativeValidateEvidence } from "./native.ts";
import { crlResult, ocspResult } from "./revocation-validation.ts";

interface Pending {
  input: Omit<NativeEvidenceInput, "checkDateMs">;
  checkDateMs?: number;
  deliver(result: NativeEvidenceResult): void;
  reject(error: unknown): void;
}

// Each certificate may load one source at a time. Flush only when all remaining
// certificates have evidence ready or have finished, independent of I/O timing.
export function createRevocationBatch(
  path: Uint8Array[],
  indices: number[],
  now: () => number
) {
  const active = new Set(indices);
  const pending = new Map<number, Pending>();
  let inFlight = false;
  let revoked = false;

  function flushWhenReady() {
    if (!inFlight && pending.size > 0 && pending.size === active.size)
      void flush();
  }

  async function flush() {
    inFlight = true;
    const items = [...pending.values()];
    pending.clear();
    try {
      // Read the clock after every source in this batch has completed I/O.
      const checkDateMs = items.some((item) => item.checkDateMs === undefined)
        ? now()
        : 0;
      const results = await nativeValidateEvidence(
        path,
        items.map((item) => ({
          ...item.input,
          checkDateMs: item.checkDateMs ?? checkDateMs
        }))
      );
      if (results.length !== items.length)
        throw new Error("Incomplete native evidence batch");
      revoked ||= results.some((result) => result.result.status === "revoked");
      // Successful authentication ends this certificate's participation even
      // when an asynchronous cache write has not finished yet.
      for (const result of results) {
        if (result.result.status !== "unknown")
          active.delete(result.certificateIndex);
      }
      for (let index = 0; index < items.length; index++)
        items[index].deliver(results[index]);
    } catch (error) {
      for (const item of items) item.reject(error);
    } finally {
      inFlight = false;
      flushWhenReady();
    }
  }

  function enqueue<T>(
    certificateIndex: number,
    mechanism: NativeEvidenceResult["mechanism"],
    data: Uint8Array,
    checkDate: Date | undefined,
    convert: (result: NativeEvidenceResult) => T
  ): Promise<T> {
    if (!active.has(certificateIndex) || pending.has(certificateIndex)) {
      return Promise.reject(new Error("Invalid evidence batch state"));
    }
    return new Promise((resolve, reject) => {
      pending.set(certificateIndex, {
        input: { certificateIndex, mechanism, data: Uint8Array.from(data) },
        checkDateMs: checkDate?.getTime(),
        deliver(result) {
          try {
            if (result.certificateIndex !== certificateIndex)
              throw new Error("Native evidence certificate mismatch");
            resolve(convert(result));
          } catch (error) {
            reject(error);
          }
        },
        reject
      });
      flushWhenReady();
    });
  }

  return {
    isRevoked: () => revoked,
    complete(certificateIndex: number) {
      active.delete(certificateIndex);
      flushWhenReady();
    },
    validateCrl(certificateIndex: number, data: Uint8Array, checkDate?: Date) {
      return enqueue(certificateIndex, "crl", data, checkDate, (result) => {
        if (result.mechanism !== "crl")
          throw new Error("Native evidence mechanism mismatch");
        return crlResult(result.result);
      });
    },
    validateOcsp(certificateIndex: number, data: Uint8Array, checkDate?: Date) {
      return enqueue(certificateIndex, "ocsp", data, checkDate, (result) => {
        if (result.mechanism !== "ocsp")
          throw new Error("Native evidence mechanism mismatch");
        return ocspResult(result.result);
      });
    }
  };
}
