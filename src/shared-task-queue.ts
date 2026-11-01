// Shares pending tasks by key while allowing each subscriber to cancel independently.
import { abortError } from "./errors.ts";

export interface SharedTaskQueue<Input, T> {
  /** Submit or join a task; execution is delegated to the configured executor. */
  add(
    key: string,
    input: Input,
    options?: { signal?: AbortSignal }
  ): Promise<T>;
}

class SharedTask<T> {
  readonly key: string;
  readonly start: () => void;
  readonly #controller = new AbortController();
  readonly #promise: Promise<T>;
  readonly #onFinish: (task: SharedTask<T>) => void;
  #waiters = 0;
  #finished = false;

  constructor(
    key: string,
    execute: (signal: AbortSignal) => Promise<T>,
    onFinish: (task: SharedTask<T>) => void
  ) {
    this.key = key;
    this.#onFinish = onFinish;
    const signal = this.#controller.signal;
    let start!: () => void;
    this.#promise = new Promise<T>((resolve, reject) => {
      start = () => {
        try {
          if (signal.aborted) throw abortError();
          resolve(execute(signal));
        } catch (error) {
          reject(error);
        }
      };
    });
    this.start = start;
    this.#promise.then(this.#finish, this.#finish);
  }

  readonly #finish = () => {
    if (this.#finished) return;
    this.#finished = true;
    this.#onFinish(this);
  };

  subscribe(signal?: AbortSignal): Promise<T> {
    if (signal?.aborted || this.#controller.signal.aborted) {
      return Promise.reject(abortError());
    }
    return new Promise<T>((resolve, reject) => {
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
        if (this.#waiters === 0 && !this.#finished) {
          this.#finish();
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

/** Accepts tasks continuously, sharing pending work by key until it finishes. */
export function createSharedTaskQueue<Input, T>({
  execute
}: {
  execute: (input: Input, signal: AbortSignal) => Promise<T>;
}): SharedTaskQueue<Input, T> {
  const tasks = new Map<string, SharedTask<T>>();

  function onFinish(task: SharedTask<T>): void {
    // An abandoned task may settle after another task has reused its key.
    if (tasks.get(task.key) === task) tasks.delete(task.key);
  }

  return {
    add(key, input, { signal } = {}) {
      if (signal?.aborted) return Promise.reject(abortError());
      const existing = tasks.get(key);
      if (existing) return existing.subscribe(signal);
      const shared = new SharedTask(
        key,
        (signal) => execute(input, signal),
        onFinish
      );
      tasks.set(key, shared);
      const result = shared.subscribe(signal);
      shared.start();
      return result;
    }
  };
}
