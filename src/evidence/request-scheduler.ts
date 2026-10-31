import { ResourceLimitError } from "../errors.ts";

export interface RequestSchedulerOptions {
  maxActiveRequests?: number;
  maxQueuedRequests?: number;
  maxActivePerOrigin?: number;
  queueTimeoutMs?: number;
}

export interface RequestSchedulerStats {
  active: number;
  queued: number;
}

export interface RequestScheduler {
  run<T>(
    origin: string,
    signal: AbortSignal | undefined,
    task: () => Promise<T>
  ): Promise<T>;
  stats(): RequestSchedulerStats;
}

const DEFAULTS = {
  maxActiveRequests: 8,
  maxQueuedRequests: 32,
  maxActivePerOrigin: 4,
  queueTimeoutMs: 30_000
} as const;

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return value;
}

interface QueuedRequest {
  origin: string;
  resolve: (release: () => void) => void;
  reject: (error: unknown) => void;
  signal?: AbortSignal;
  timer: NodeJS.Timeout;
  onAbort: () => void;
}

export function createRequestScheduler({
  maxActiveRequests = DEFAULTS.maxActiveRequests,
  maxQueuedRequests = DEFAULTS.maxQueuedRequests,
  maxActivePerOrigin = DEFAULTS.maxActivePerOrigin,
  queueTimeoutMs = DEFAULTS.queueTimeoutMs
}: RequestSchedulerOptions = {}): RequestScheduler {
  positiveInteger(maxActiveRequests, "maxActiveRequests");
  if (!Number.isSafeInteger(maxQueuedRequests) || maxQueuedRequests < 0) {
    throw new TypeError("maxQueuedRequests must be a non-negative integer");
  }
  positiveInteger(maxActivePerOrigin, "maxActivePerOrigin");
  positiveInteger(queueTimeoutMs, "queueTimeoutMs");

  let active = 0;
  const activePerOrigin = new Map<string, number>();
  const queue = new Set<QueuedRequest>();

  function canStart(origin: string): boolean {
    return (
      active < maxActiveRequests &&
      (activePerOrigin.get(origin) ?? 0) < maxActivePerOrigin
    );
  }

  function release(origin: string): void {
    active--;
    const current = (activePerOrigin.get(origin) ?? 1) - 1;
    if (current <= 0) activePerOrigin.delete(origin);
    else activePerOrigin.set(origin, current);
    pump();
  }

  function start(origin: string): () => void {
    active++;
    activePerOrigin.set(origin, (activePerOrigin.get(origin) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      release(origin);
    };
  }

  function removeQueued(job: QueuedRequest): boolean {
    if (!queue.delete(job)) return false;
    clearTimeout(job.timer);
    job.signal?.removeEventListener("abort", job.onAbort);
    return true;
  }

  function rejectQueued(job: QueuedRequest, error: Error): void {
    if (removeQueued(job)) job.reject(error);
  }

  function pump(): void {
    for (const job of queue) {
      if (active >= maxActiveRequests) break;
      if (!canStart(job.origin)) continue;
      removeQueued(job);
      if (job.signal?.aborted) {
        job.reject(abortError());
        continue;
      }
      job.resolve(start(job.origin));
    }
  }

  function enqueue(origin: string, signal?: AbortSignal): Promise<() => void> {
    return new Promise((resolve, reject) => {
      if (queue.size >= maxQueuedRequests) {
        reject(new ResourceLimitError("The evidence request queue is full"));
        return;
      }
      const job: QueuedRequest = {
        origin,
        resolve,
        reject,
        signal,
        timer: setTimeout(() => {
          rejectQueued(
            job,
            new ResourceLimitError(
              "Timed out waiting for an evidence request slot"
            )
          );
        }, queueTimeoutMs),
        onAbort: () => rejectQueued(job, abortError())
      };
      job.timer.unref();
      signal?.addEventListener("abort", job.onAbort, { once: true });
      queue.add(job);
    });
  }

  return {
    stats() {
      return { active, queued: queue.size };
    },

    run<T>(
      origin: string,
      signal: AbortSignal | undefined,
      task: () => Promise<T>
    ): Promise<T> {
      if (signal?.aborted) return Promise.reject(abortError());
      // Waiters for a saturated origin must not block other eligible origins.
      const slot = canStart(origin)
        ? Promise.resolve(start(origin))
        : enqueue(origin, signal);
      return slot.then(async (release) => {
        try {
          // A cancellation can arrive after reservation but before this callback.
          if (signal?.aborted) throw abortError();
          return await task();
        } finally {
          release();
        }
      });
    }
  };
}
