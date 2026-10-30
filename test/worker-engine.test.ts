import assert from "node:assert/strict";
import { after, test } from "node:test";
import { createInlinePkiEngine } from "../src/engine/pki-engine.ts";
import * as mainEntry from "../src/index.ts";
import {
  createEvidenceProvider,
  createTrustValidator,
  ResourceLimitError,
  type ValidationProfileInput
} from "../src/index.ts";
import { createWorkerPkiEngine } from "../src/worker.ts";
import {
  createCrl,
  createCrlWithSerials,
  createLeafForChain,
  createOcspResponse,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

const checkDateMs = new Date("2026-10-15T00:00:00Z").getTime();
const chain = await createSyntheticChain({
  intermediate: {
    crlUrls: ["http://worker.test/intermediate.crl"],
    ocspUrls: ["http://worker.test/intermediate-ocsp"]
  },
  leaf: {
    crlUrls: ["http://worker.test/leaf.crl"],
    ocspUrls: ["http://worker.test/leaf-ocsp"]
  }
});
const leafCrl = await createCrl(chain.intermediate, []);
const intermediateCrl = await createCrl(chain.root, []);
const leafOcsp = await createOcspResponse(
  chain.intermediate,
  chain.leaf,
  "good"
);
const intermediateOcsp = await createOcspResponse(
  chain.root,
  chain.intermediate,
  "good"
);
const largeCrl = await createCrlWithSerials(
  chain.intermediate,
  Array.from({ length: 3000 }, (_, index) => 200_000 + index)
);
const chainInput = [chain.leaf.der, chain.intermediate.der];

const worker = createWorkerPkiEngine({
  maxThreads: 2,
  maxQueue: 8,
  taskTimeoutMs: 10_000
});
after(async () => {
  await worker.close({ force: true });
});

function policy(): ValidationProfileInput {
  return {
    id: "worker:policy",
    version: 1,
    source: "worker parity test",
    anchorSetId: "worker:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
}

async function waitForIdle(engine: {
  stats(): { idleThreads: number };
}): Promise<void> {
  const deadline = Date.now() + 2000;
  while (engine.stats().idleThreads === 0) {
    if (Date.now() > deadline)
      throw new Error("Worker pool did not become idle");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function provider() {
  return createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async (url) =>
      url.endsWith("/intermediate.crl") ? intermediateCrl : leafCrl
  });
}

test("worker APIs live only on the worker entrypoint", () => {
  assert.equal("createWorkerPkiEngine" in mainEntry, false);
  assert.equal(typeof createWorkerPkiEngine, "function");
});

test("worker path preparation matches the inline engine", async () => {
  const inline = createInlinePkiEngine();
  const options = {
    certificateChain: chainInput,
    trustAnchors: [chain.root.der],
    checkDateMs
  };
  const expected = await inline.preparePath(options);
  const actual = await worker.preparePath(options);
  assert.deepEqual(actual, expected);

  const trailing = Buffer.concat([
    Buffer.from(chain.leaf.der),
    Buffer.from([0])
  ]);
  const expectedInvalid = await inline.preparePath({
    ...options,
    certificateChain: [trailing, chain.intermediate.der]
  });
  const actualInvalid = await worker.preparePath({
    ...options,
    certificateChain: [trailing, chain.intermediate.der]
  });
  assert.deepEqual(actualInvalid, expectedInvalid);
});

test("worker CRL and OCSP validation match the inline engine", async () => {
  const inline = createInlinePkiEngine();
  const crlOptions = {
    certificateDer: chain.leaf.der,
    issuerDer: chain.intermediate.der,
    crl: leafCrl,
    checkDateMs
  };
  assert.deepEqual(
    await worker.validateCrl(crlOptions),
    await inline.validateCrl(crlOptions)
  );

  const ocspOptions = {
    certificateDer: chain.leaf.der,
    issuerDer: chain.intermediate.der,
    response: leafOcsp,
    checkDateMs
  };
  assert.deepEqual(
    await worker.validateOcsp(ocspOptions),
    await inline.validateOcsp(ocspOptions)
  );
  assert.deepEqual(
    await worker.validateOcsp({
      ...ocspOptions,
      certificateDer: chain.intermediate.der,
      issuerDer: chain.root.der,
      response: intermediateOcsp
    }),
    await inline.validateOcsp({
      ...ocspOptions,
      certificateDer: chain.intermediate.der,
      issuerDer: chain.root.der,
      response: intermediateOcsp
    })
  );
});

test("worker-backed validation matches inline success and failure outcomes", async () => {
  const inlineValidator = createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: policy(),
    provider: provider(),
    now: () => checkDateMs
  });
  const workerValidator = createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: policy(),
    provider: provider(),
    engine: worker,
    now: () => checkDateMs
  });
  const inlineGood = await inlineValidator.verify({
    certificateChain: chainInput
  });
  const workerGood = await workerValidator.verify({
    certificateChain: chainInput
  });
  assert.equal(workerGood.valid, inlineGood.valid);
  assert.equal(
    workerGood.valid && workerGood.leafCertificate.fingerprint256,
    inlineGood.valid && inlineGood.leafCertificate.fingerprint256
  );
  assert.deepEqual(
    workerGood.valid &&
      workerGood.evidence.map(({ mechanism, status }) => ({
        mechanism,
        status
      })),
    inlineGood.valid &&
      inlineGood.evidence.map(({ mechanism, status }) => ({
        mechanism,
        status
      }))
  );

  const revokedLeaf = await createLeafForChain(chain, {
    crlUrls: ["http://worker.test/leaf.crl"]
  });
  const revokedCrl = await createCrl(chain.intermediate, [revokedLeaf]);
  const inlineRevoked = await createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: policy(),
    provider: createEvidenceProvider({
      loadOcsp: false,
      loadCrl: async (url) =>
        url.endsWith("/intermediate.crl") ? intermediateCrl : revokedCrl
    }),
    now: () => checkDateMs
  }).verify({ certificateChain: [revokedLeaf.der, chain.intermediate.der] });
  const workerRevoked = await createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: policy(),
    provider: createEvidenceProvider({
      loadOcsp: false,
      loadCrl: async (url) =>
        url.endsWith("/intermediate.crl") ? intermediateCrl : revokedCrl
    }),
    engine: worker,
    now: () => checkDateMs
  }).verify({ certificateChain: [revokedLeaf.der, chain.intermediate.der] });
  assert.equal(workerRevoked.valid, false);
  assert.equal(inlineRevoked.valid, false);
  if (!workerRevoked.valid && !inlineRevoked.valid) {
    assert.equal(workerRevoked.code, inlineRevoked.code);
    assert.equal(
      workerRevoked.certificateIndex,
      inlineRevoked.certificateIndex
    );
  }
});

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
