import assert from "node:assert/strict";
import { test } from "node:test";
import { createRequestScheduler } from "../src/index.ts";

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
  controller.abort();
  await assert.rejects(cancelled, { name: "AbortError" });
  assert.deepEqual(scheduler.stats(), { active: 1, queued: 0 });

  const replacement = scheduler.run("http://a.test", undefined, async () => 2);
  gate.resolve(1);
  assert.equal(await first, 1);
  assert.equal(await replacement, 2);
  assert.equal(cancelledTaskRan, false);
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
