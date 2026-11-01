import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustValidator, type DiagnosticEvent } from "../src/index.ts";
import {
  crlChain,
  deferred,
  intermediateCrlUrl,
  intermediateGoodCrl,
  leafCrlOne,
  leafCrlTwo,
  leafGoodCrl,
  now,
  profile
} from "./helpers/concurrency-fixtures.ts";

test("deadline findings preserve completed attempts and identify interrupted sources", {
  timeout: 5000
}, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const leafCompleted = deferred();
  const intermediateStarted = deferred();
  const releaseIntermediate = deferred<Uint8Array>();
  t.after(() => releaseIntermediate.resolve(intermediateGoodCrl));
  const events: DiagnosticEvent[] = [];
  let intermediateSignal: AbortSignal | undefined;
  const validator = createTrustValidator({
    trustAnchors: [crlChain.root.der],
    profile: profile(["crl"]),
    now,
    deadlineMs: 50,
    ocspLoader: false,
    crlLoader: async ({ url, signal }) => {
      if (url === leafCrlOne) {
        throw new DOMException("private transport details", "TimeoutError");
      }
      if (url === leafCrlTwo) return leafGoodCrl;
      intermediateSignal = signal;
      intermediateStarted.resolve();
      return releaseIntermediate.promise;
    },
    onDiagnostic(event) {
      events.push(event);
      if (event.certificateIndex === 0 && event.status === "good") {
        leafCompleted.resolve();
      }
    }
  });
  const verification = validator.verify({
    certificateChain: [crlChain.leaf.der, crlChain.intermediate.der]
  });
  await Promise.all([leafCompleted.promise, intermediateStarted.promise]);
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(50);
  const result = await verification;
  assert.equal(result.valid, false);
  assert.equal(result.code, "RESOURCE_LIMIT_EXCEEDED");
  assert.equal(intermediateSignal?.aborted, true);
  assert.deepEqual(
    result.findings?.map(({ certificateIndex, revocation }) => ({
      certificateIndex,
      attempts: revocation.crl.map(({ source, status, code }) => ({
        source,
        status,
        code
      }))
    })),
    [
      {
        certificateIndex: 0,
        attempts: [
          { source: leafCrlOne, status: "unknown", code: "EVIDENCE_TIMEOUT" },
          { source: leafCrlTwo, status: "good", code: undefined }
        ]
      },
      {
        certificateIndex: 1,
        attempts: [
          {
            source: intermediateCrlUrl,
            status: "unknown",
            code: "EVIDENCE_DEADLINE_EXCEEDED"
          }
        ]
      }
    ]
  );
  for (const finding of result.findings![0].revocation.crl) {
    assert.ok(finding.durationMs! >= 0);
  }
  assert.ok(
    events.some(
      (event) =>
        event.event === "revocation_error" && event.code === "EVIDENCE_TIMEOUT"
    )
  );
  assert.equal(
    JSON.stringify(events).includes("private transport details"),
    false
  );

  const snapshot = structuredClone(result);
  releaseIntermediate.resolve(intermediateGoodCrl);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(result, snapshot);
});
