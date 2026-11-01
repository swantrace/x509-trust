import assert from "node:assert/strict";
import { test } from "node:test";
import PQueue from "p-queue";
import { createSharedTaskQueue } from "../src/shared-task-queue.ts";

type Task<T> = (signal: AbortSignal) => Promise<T>;

function immediateQueue<T>() {
  return createSharedTaskQueue({
    execute: (task: Task<T>, signal) => task(signal)
  });
}

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test("accepts arbitrary input and shares a pending result by key", async (t) => {
  const value = { answer: 42 };
  const execute = t.mock.fn(async (input: { answer: number }) => input);
  const queue = createSharedTaskQueue({ execute });
  const [first, second] = await Promise.all([
    queue.add("same", value),
    queue.add("same", { answer: 43 })
  ]);

  assert.equal(first.answer, 42);
  assert.equal(first, value);
  assert.equal(second, value);
  assert.equal(execute.mock.callCount(), 1);
  assert.equal((await queue.add("same", { answer: 43 })).answer, 43);
  assert.equal(execute.mock.callCount(), 2);
});

test("adapts p-queue and accepts tasks while running and after idle", async (t) => {
  const scheduler = new PQueue({ concurrency: 1 });
  const queue = createSharedTaskQueue({
    execute: (task: Task<number>, signal) =>
      scheduler.add(() => task(signal), { signal })
  });
  const gate = deferred<number>();
  const started = deferred();
  t.after(() => gate.resolve(1));
  const first = queue.add("first", () => {
    started.resolve();
    return gate.promise;
  });
  await started.promise;
  const task = t.mock.fn(async () => 42);
  const second = queue.add("second", task);
  const duplicate = queue.add("second", task);
  assert.equal(task.mock.callCount(), 0);
  assert.equal(scheduler.pending, 1);
  assert.equal(scheduler.size, 1);

  gate.resolve(1);
  assert.deepEqual(await Promise.all([first, second, duplicate]), [1, 42, 42]);
  assert.equal(task.mock.callCount(), 1);
  assert.equal(await queue.add("later", async () => 3), 3);
  assert.equal(scheduler.pending, 0);
  assert.equal(scheduler.size, 0);
});

test("subscribers cancel independently and the last cancel allows a fresh task", async (t) => {
  const queue = immediateQueue<number>();
  const gate = deferred<number>();
  t.after(() => gate.resolve(1));
  let taskSignal: AbortSignal | undefined;
  const task = t.mock.fn((signal: AbortSignal) => {
    taskSignal = signal;
    return gate.promise;
  });
  const firstController = new AbortController();
  const secondController = new AbortController();
  const first = queue.add("same", task, { signal: firstController.signal });
  const second = queue.add("same", task, { signal: secondController.signal });
  firstController.abort();
  await assert.rejects(first, { name: "AbortError" });
  assert.equal(taskSignal?.aborted, false);
  secondController.abort();
  await assert.rejects(second, { name: "AbortError" });
  assert.equal(taskSignal?.aborted, true);
  assert.equal(task.mock.callCount(), 1);
  assert.equal(await queue.add("same", async () => 42), 42);
});

test("already aborted submissions do not execute or reserve the key", async (t) => {
  const queue = immediateQueue<number>();
  const task = t.mock.fn(async () => 42);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(queue.add("same", task, { signal: controller.signal }), {
    name: "AbortError"
  });
  assert.equal(task.mock.callCount(), 0);
  assert.equal(await queue.add("same", task), 42);
  assert.equal(task.mock.callCount(), 1);
});

test("a synchronous executor failure rejects subscribers and clears the key", async (t) => {
  const failure = new Error("startup failed");
  const execute = t.mock.fn(() => {
    throw failure;
  });
  const queue = createSharedTaskQueue({ execute });

  await Promise.all([
    assert.rejects(queue.add("same", 1), (error) => error === failure),
    assert.rejects(queue.add("same", 1), (error) => error === failure)
  ]);
  assert.equal(execute.mock.callCount(), 1);
  await assert.rejects(queue.add("same", 1), (error) => error === failure);
  assert.equal(execute.mock.callCount(), 2);
});

for (const outcome of ["resolves", "rejects"] as const) {
  test(
    "an abandoned task that later " +
      outcome +
      " cannot remove its replacement",
    async (t) => {
      const queue = immediateQueue<number>();
      const abandoned = deferred<number>();
      const replacement = deferred<number>();
      t.after(() => {
        abandoned.resolve(1);
        replacement.resolve(2);
      });
      const controller = new AbortController();
      const first = queue.add("same", () => abandoned.promise, {
        signal: controller.signal
      });
      controller.abort();
      await assert.rejects(first, { name: "AbortError" });

      const retry = queue.add("same", () => replacement.promise);
      if (outcome === "resolves") abandoned.resolve(1);
      else abandoned.reject(new Error("abandoned task failed"));
      await new Promise((resolve) => setImmediate(resolve));

      const unexpected = t.mock.fn(async () => 3);
      const joined = queue.add("same", unexpected);
      replacement.resolve(2);
      assert.deepEqual(await Promise.all([retry, joined]), [2, 2]);
      assert.equal(unexpected.mock.callCount(), 0);
    }
  );
}

test("registers the shared task before the executor can submit the same key again", async (t) => {
  const queue = immediateQueue<number>();
  let joined: Promise<number> | undefined;
  const unexpected = t.mock.fn(async () => 99);
  const first = queue.add("same", async () => {
    joined = queue.add("same", unexpected);
    return 42;
  });
  assert.equal(await first, 42);
  assert.equal(await joined, 42);
  assert.equal(unexpected.mock.callCount(), 0);
});

test("queue instances keep keys isolated and add works detached", async () => {
  const { add } = immediateQueue<number>();
  const other = immediateQueue<number>();
  assert.deepEqual(
    await Promise.all([
      add("same", async () => 1),
      other.add("same", async () => 2)
    ]),
    [1, 2]
  );
});
