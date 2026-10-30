import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryCache } from "../src/evidence/cache.ts";

test("memory entries expire at their TTL boundary", async () => {
  let time = 1000;
  const cache = createMemoryCache({ now: () => time });
  await cache.set("key", "value", 100);
  assert.equal(await cache.get("key"), "value");
  time += 100;
  assert.equal(await cache.get("key"), null);
});

test("memory cache bounds its size and can delete entries", async () => {
  const cache = createMemoryCache({ maxEntries: 2 });
  await cache.set("first", "one", 10000);
  await cache.set("second", "two", 10000);
  await cache.set("third", "three", 10000);
  assert.equal(await cache.get("first"), null);
  assert.equal(await cache.get("second"), "two");
  await cache.delete("second");
  assert.equal(await cache.get("second"), null);
});

test("updating an entry does not evict another entry unnecessarily", async () => {
  const cache = createMemoryCache({ maxEntries: 2 });
  await cache.set("first", "one", 10000);
  await cache.set("second", "two", 10000);
  await cache.set("first", "updated", 10000);
  assert.equal(await cache.get("second"), "two");
  assert.equal(await cache.get("first"), "updated");
});

test("rejects invalid memory capacity and expiration settings", async () => {
  for (const maxEntries of [0, -1, 1.5, Infinity]) {
    assert.throws(() => createMemoryCache({ maxEntries }), TypeError);
  }
  for (const ttlMs of [0, -1, NaN, Infinity]) {
    await assert.rejects(
      createMemoryCache().set("key", "value", ttlMs),
      TypeError
    );
  }
});
