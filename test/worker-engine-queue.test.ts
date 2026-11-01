import assert from "node:assert/strict";
import { test } from "node:test";
import { ResourceLimitError } from "../src/index.ts";
import { createWorkerPkiEngine } from "../src/worker.ts";
import {
  chain,
  checkDateMs,
  largeCrl,
  leafCrl,
  waitForIdle
} from "./helpers/worker-engine-fixtures.ts";

test("bounded worker queue rejects excess work and recovers", {
  timeout: 15_000
}, async () => {
  const engine = createWorkerPkiEngine({
    maxThreads: 1,
    maxQueue: 0,
    taskTimeoutMs: 10_000
  });
  try {
    // Warm the worker so the following task is distributed immediately.
    await engine.validateCrl({
      certificateDer: chain.leaf.der,
      issuerDer: chain.intermediate.der,
      crl: leafCrl,
      checkDateMs
    });
    const first = engine.validateCrl({
      certificateDer: chain.leaf.der,
      issuerDer: chain.intermediate.der,
      crl: largeCrl,
      checkDateMs
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    await assert.rejects(
      engine.validateCrl({
        certificateDer: chain.leaf.der,
        issuerDer: chain.intermediate.der,
        crl: leafCrl,
        checkDateMs
      }),
      ResourceLimitError
    );
    assert.equal((await first).status, "good");
    await waitForIdle(engine);
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

test("aborting a queued task rejects it without killing the running task", {
  timeout: 15_000
}, async () => {
  const engine = createWorkerPkiEngine({
    maxThreads: 1,
    maxQueue: 1,
    taskTimeoutMs: 10_000
  });
  try {
    const first = engine.validateCrl({
      certificateDer: chain.leaf.der,
      issuerDer: chain.intermediate.der,
      crl: largeCrl,
      checkDateMs
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    const controller = new AbortController();
    const queued = engine.validateCrl({
      certificateDer: chain.leaf.der,
      issuerDer: chain.intermediate.der,
      crl: leafCrl,
      checkDateMs,
      signal: controller.signal
    });
    controller.abort();
    await assert.rejects(queued, (error: unknown) => {
      assert.ok(error instanceof DOMException);
      assert.equal(error.name, "AbortError");
      return true;
    });
    assert.equal((await first).status, "good");
    await waitForIdle(engine);
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
