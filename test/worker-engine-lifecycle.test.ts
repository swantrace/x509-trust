import assert from "node:assert/strict";
import { test } from "node:test";
import { ResourceLimitError } from "../src/index.ts";
import { createWorkerPkiEngine } from "../src/worker.ts";
import {
  chain,
  checkDateMs,
  largeCrl,
  leafCrl
} from "./helpers/worker-engine-fixtures.ts";

test("aborting a running task terminates its worker and the pool recovers", {
  timeout: 15_000
}, async () => {
  const engine = createWorkerPkiEngine({
    maxThreads: 1,
    maxQueue: 1,
    taskTimeoutMs: 10_000
  });
  try {
    const controller = new AbortController();
    const running = engine.validateCrl({
      certificateDer: chain.leaf.der,
      issuerDer: chain.intermediate.der,
      crl: largeCrl,
      checkDateMs,
      signal: controller.signal
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    controller.abort();
    await assert.rejects(running, (error: unknown) => {
      assert.ok(error instanceof DOMException);
      assert.equal(error.name, "AbortError");
      return true;
    });
    assert.equal(
      (
        await engine.validateCrl({
          certificateDer: chain.leaf.der,
          issuerDer: chain.intermediate.der,
          crl: leafCrl,
          checkDateMs
        })
      ).status,
      "good"
    );
  } finally {
    await engine.close({ force: true });
  }
});

test("worker task timeout becomes a resource limit error", {
  timeout: 15_000
}, async () => {
  const engine = createWorkerPkiEngine({
    maxThreads: 1,
    maxQueue: 0,
    taskTimeoutMs: 1
  });
  try {
    await assert.rejects(
      engine.validateCrl({
        certificateDer: chain.leaf.der,
        issuerDer: chain.intermediate.der,
        crl: largeCrl,
        checkDateMs
      }),
      ResourceLimitError
    );
  } finally {
    await engine.close({ force: true });
  }
});

test("closing the worker pool releases its threads", async () => {
  const engine = createWorkerPkiEngine({
    maxThreads: 1,
    maxQueue: 1,
    taskTimeoutMs: 5000
  });
  assert.equal(
    (
      await engine.validateCrl({
        certificateDer: chain.leaf.der,
        issuerDer: chain.intermediate.der,
        crl: leafCrl,
        checkDateMs
      })
    ).status,
    "good"
  );
  assert.ok(engine.stats().threads >= 0);
  await engine.close({ force: true });
  assert.equal(engine.stats().threads, 0);
  assert.equal(engine.stats().queueSize, 0);
});
