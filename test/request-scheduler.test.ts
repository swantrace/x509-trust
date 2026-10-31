import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { test } from "node:test";
import { createRequestScheduler, ResourceLimitError } from "../src/index.ts";

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

test("scheduler methods work detached and instances keep independent state", async () => {
  const scheduler = createRequestScheduler({ maxActiveRequests: 1 });
  const { run, stats } = scheduler;
  const other = createRequestScheduler({ maxActiveRequests: 1 });
  const gate = deferred<number>();
  const pending = run("http://a.test", undefined, () => gate.promise);

  assert.equal(Object.getPrototypeOf(scheduler), Object.prototype);
  assert.deepEqual(stats(), { active: 1, queued: 0 });
  assert.equal(await other.run("http://a.test", undefined, async () => 2), 2);
  assert.deepEqual(other.stats(), { active: 0, queued: 0 });

  gate.resolve(1);
  assert.equal(await pending, 1);
  assert.deepEqual(stats(), { active: 0, queued: 0 });
});

test("cancelling a queued request frees capacity without running its task", async () => {
  const scheduler = createRequestScheduler({
    maxActiveRequests: 1,
    maxQueuedRequests: 1
  });
  const gate = deferred<number>();
  const first = scheduler.run("http://a.test", undefined, () => gate.promise);
  const controller = new AbortController();
  let cancelledTaskRan = false;
  const cancelled = scheduler.run(
    "http://a.test",
    controller.signal,
    async () => {
      cancelledTaskRan = true;
    }
  );

  assert.deepEqual(scheduler.stats(), { active: 1, queued: 1 });
  assert.equal(getEventListeners(controller.signal, "abort").length, 1);
  controller.abort();
  await assert.rejects(cancelled, { name: "AbortError" });
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 0 });
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);

  const replacement = scheduler.run("http://a.test", undefined, async () => 2);
  gate.resolve(1);
  assert.equal(await first, 1);
  assert.equal(await replacement, 2);
  assert.equal(cancelledTaskRan, false);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});

test("an eligible origin starts even when another origin fills the queue", async (t) => {
  const scheduler = createRequestScheduler({
    maxActiveRequests: 2,
    maxActivePerOrigin: 1,
    maxQueuedRequests: 1
  });
  const gate = deferred<number>();
  t.after(() => gate.resolve(1));
  const first = scheduler.run("http://a.test", undefined, () => gate.promise);
  const queued = scheduler.run("http://a.test", undefined, async () => 2);
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 1 });

  assert.equal(
    await scheduler.run("http://b.test", undefined, async () => 3),
    3
  );
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 1 });

  gate.resolve(1);
  assert.deepEqual(await Promise.all([first, queued]), [1, 2]);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});

test("abort before the task callback starts releases its reserved slot", async (t) => {
  const scheduler = createRequestScheduler({ maxActiveRequests: 1 });
  const controller = new AbortController();
  const task = t.mock.fn(async () => 1);
  const cancelled = scheduler.run("http://a.test", controller.signal, task);
  controller.abort();

  await assert.rejects(cancelled, { name: "AbortError" });
  assert.equal(task.mock.callCount(), 0);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
  assert.equal(
    await scheduler.run("http://a.test", undefined, async () => 2),
    2
  );
});

test("abort while the previous task completes prevents a queued callback from starting", async (t) => {
  const scheduler = createRequestScheduler({ maxActiveRequests: 1 });
  const gate = deferred();
  const started = deferred();
  t.after(() => gate.resolve());
  const first = scheduler.run("http://a.test", undefined, () => {
    started.resolve();
    return gate.promise;
  });
  await started.promise;
  const controller = new AbortController();
  const task = t.mock.fn(async () => 2);
  const cancelled = scheduler.run("http://a.test", controller.signal, task);
  const rejected = assert.rejects(cancelled, { name: "AbortError" });

  // Abort as the previous task settles, before the queued callback executes.
  gate.promise.then(() => controller.abort());
  gate.resolve();
  await Promise.all([first, rejected]);
  assert.equal(task.mock.callCount(), 0);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});

test("a started waiter stops its queue timeout and holds its slot when abort is ignored", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const scheduler = createRequestScheduler({
    maxActiveRequests: 1,
    queueTimeoutMs: 10
  });
  const firstGate = deferred();
  const secondGate = deferred<number>();
  const started = deferred();
  t.after(() => {
    firstGate.resolve();
    secondGate.resolve(2);
  });
  const first = scheduler.run(
    "http://a.test",
    undefined,
    () => firstGate.promise
  );
  const controller = new AbortController();
  const second = scheduler.run("http://a.test", controller.signal, () => {
    started.resolve();
    return secondGate.promise;
  });
  firstGate.resolve();
  await started.promise;
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);

  t.mock.timers.tick(20);
  controller.abort();
  const nextTask = t.mock.fn(async () => 3);
  const third = scheduler.run("http://b.test", undefined, nextTask);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(nextTask.mock.callCount(), 0);
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 1 });

  secondGate.resolve(2);
  assert.deepEqual(await Promise.all([first, second, third]), [
    undefined,
    2,
    3
  ]);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});

test("queue timeout removes its abort listener and frees space for a replacement", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const scheduler = createRequestScheduler({
    maxActiveRequests: 1,
    maxQueuedRequests: 1,
    queueTimeoutMs: 10
  });
  const gate = deferred<number>();
  t.after(() => gate.resolve(1));
  const first = scheduler.run("http://a.test", undefined, () => gate.promise);
  const controller = new AbortController();
  const task = t.mock.fn(async () => 2);
  const timedOut = scheduler.run("http://b.test", controller.signal, task);
  const rejected = assert.rejects(timedOut, ResourceLimitError);

  t.mock.timers.tick(10);
  await rejected;
  assert.equal(task.mock.callCount(), 0);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 0 });

  const replacement = scheduler.run("http://c.test", undefined, async () => 3);
  controller.abort();
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 1 });
  gate.resolve(1);
  assert.deepEqual(await Promise.all([first, replacement]), [1, 3]);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});

test("synchronous throws and rejected tasks release slots for queued work", async () => {
  const scheduler = createRequestScheduler({ maxActiveRequests: 1 });
  const failure = new Error("task failed");
  const first = scheduler.run("http://a.test", undefined, () => {
    throw failure;
  });
  const second = scheduler.run("http://a.test", undefined, () =>
    Promise.reject(failure)
  );
  const third = scheduler.run("http://a.test", undefined, async () => 3);

  await Promise.all([
    assert.rejects(first, (error) => error === failure),
    assert.rejects(second, (error) => error === failure)
  ]);
  assert.equal(await third, 3);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});

test("dispatch skips an origin at its limit to start eligible queued work", async () => {
  const scheduler = createRequestScheduler({
    maxActiveRequests: 2,
    maxActivePerOrigin: 1
  });
  const firstGate = deferred();
  const secondGate = deferred();
  const starts: string[] = [];
  const first = scheduler.run(
    "http://a.test",
    undefined,
    () => firstGate.promise
  );
  const second = scheduler.run(
    "http://b.test",
    undefined,
    () => secondGate.promise
  );
  const blocked = scheduler.run("http://a.test", undefined, async () => {
    starts.push("a");
  });
  const eligible = scheduler.run("http://c.test", undefined, async () => {
    starts.push("c");
  });

  secondGate.resolve();
  await second;
  await eligible;
  assert.deepEqual(starts, ["c"]);
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 1 });

  firstGate.resolve();
  await Promise.all([first, blocked]);
  assert.deepEqual(starts, ["c", "a"]);
  assert.deepEqual(scheduler.stats(), { active: 0, queued: 0 });
});
