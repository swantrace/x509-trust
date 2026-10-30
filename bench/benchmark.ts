import { writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { cpus, platform, release, totalmem } from "node:os";
import { monitorEventLoopDelay, performance } from "node:perf_hooks";
import {
  createEvidenceProvider,
  createTrustValidator,
  createWorkerPkiEngine,
  type EvidenceProvider,
  type TrustPolicyInput,
  type ValidationResult
} from "../src/index.ts";
import { createInlinePkiEngine } from "../src/pki-engine.ts";
import {
  createCrl,
  createCrlWithSerials,
  createIntermediateForChain,
  createLeafForChain,
  createOcspResponse,
  createSyntheticChain
} from "../test/helpers/synthetic-pki.ts";

const now = () => new Date("2026-10-15T00:00:00Z").getTime();
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface ServerState {
  leafCrl: Uint8Array;
  intermediateCrl: Uint8Array;
  leafOcsp: Uint8Array;
  intermediateOcsp: Uint8Array;
  leafCrlDelayMs: number;
  intermediateCrlDelayMs: number;
  leafOcspDelayMs: number;
  intermediateOcspDelayMs: number;
  ocspFailure: boolean;
}

interface ServerStats {
  requests: number;
  byPath: Map<string, number>;
  active: number;
  maxInFlight: number;
}

function emptyState(): ServerState {
  return {
    leafCrl: new Uint8Array(),
    intermediateCrl: new Uint8Array(),
    leafOcsp: new Uint8Array(),
    intermediateOcsp: new Uint8Array(),
    leafCrlDelayMs: 0,
    intermediateCrlDelayMs: 0,
    leafOcspDelayMs: 0,
    intermediateOcspDelayMs: 0,
    ocspFailure: false
  };
}

async function startServer(): Promise<{
  origin: string;
  state: ServerState;
  stats: ServerStats;
  resetStats(): void;
  close(): Promise<void>;
}> {
  const state = emptyState();
  const stats: ServerStats = {
    requests: 0,
    byPath: new Map(),
    active: 0,
    maxInFlight: 0
  };

  const server = http.createServer((request, response) => {
    const path = request.url ?? "/";
    stats.requests++;
    stats.byPath.set(path, (stats.byPath.get(path) ?? 0) + 1);
    stats.active++;
    stats.maxInFlight = Math.max(stats.maxInFlight, stats.active);
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      stats.active--;
    };
    response.on("finish", finish);
    response.on("close", finish);
    request.resume();

    void (async () => {
      if (path === "/leaf.crl") {
        if (state.leafCrlDelayMs) await wait(state.leafCrlDelayMs);
        if (!response.destroyed) response.end(state.leafCrl);
      } else if (path === "/intermediate.crl") {
        if (state.intermediateCrlDelayMs)
          await wait(state.intermediateCrlDelayMs);
        if (!response.destroyed) response.end(state.intermediateCrl);
      } else if (path === "/leaf-ocsp") {
        if (state.ocspFailure) {
          response.writeHead(503);
          response.end();
          return;
        }
        if (state.leafOcspDelayMs) await wait(state.leafOcspDelayMs);
        if (!response.destroyed) {
          response.setHeader("Content-Type", "application/ocsp-response");
          response.end(state.leafOcsp);
        }
      } else if (path === "/intermediate-ocsp") {
        if (state.ocspFailure) {
          response.writeHead(503);
          response.end();
          return;
        }
        if (state.intermediateOcspDelayMs)
          await wait(state.intermediateOcspDelayMs);
        if (!response.destroyed) {
          response.setHeader("Content-Type", "application/ocsp-response");
          response.end(state.intermediateOcsp);
        }
      } else {
        response.writeHead(404);
        response.end();
      }
    })().catch(() => {
      if (!response.destroyed) {
        response.writeHead(500);
        response.end();
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${address.port}`,
    state,
    stats,
    resetStats() {
      stats.requests = 0;
      stats.byPath = new Map();
      stats.maxInFlight = stats.active;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
}

interface ScenarioConfig {
  name: string;
  description: string;
  iterations: number;
  warmup: number;
  concurrency?: number;
  run: (iteration: number) => Promise<unknown>;
  expect?: (value: unknown) => void;
  provider?: EvidenceProvider;
}

interface ScenarioResult {
  name: string;
  description: string;
  iterations: number;
  warmup: number;
  concurrency: number;
  samples: number[];
  requests: number;
  requestsByPath: Array<[string, number]>;
  maxInFlight: number;
  maxQueued: number;
  eventLoopP99Ms: number;
  eventLoopMaxMs: number;
  rssDeltaMb: number;
  throughput: number;
}

function percentile(samples: number[], fraction: number): number {
  if (samples.length === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil(fraction * sorted.length) - 1)
  );
  return sorted[index];
}

const server = await startServer();

const mainChain = await createSyntheticChain({
  intermediate: {
    crlUrls: [`${server.origin}/intermediate.crl`],
    ocspUrls: [`${server.origin}/intermediate-ocsp`],
    pathLenConstraint: 5
  },
  leaf: {
    crlUrls: [`${server.origin}/leaf.crl`],
    ocspUrls: [`${server.origin}/leaf-ocsp`]
  }
});
const firstIntermediate = await createIntermediateForChain(
  mainChain.intermediate,
  { commonName: "Synthetic Intermediate A", pathLenConstraint: 5 }
);
const secondIntermediate = await createIntermediateForChain(firstIntermediate, {
  commonName: "Synthetic Intermediate B",
  pathLenConstraint: 5
});
const deepLeaf = await createLeafForChain({
  root: mainChain.root,
  intermediate: secondIntermediate
});

const leafGoodCrl = await createCrl(mainChain.intermediate, []);
const intermediateGoodCrl = await createCrl(mainChain.root, []);
const largeLeafCrl = await createCrlWithSerials(
  mainChain.intermediate,
  Array.from({ length: 3000 }, (_, index) => 100_000 + index)
);
const leafGoodOcsp = await createOcspResponse(
  mainChain.intermediate,
  mainChain.leaf,
  "good"
);
const leafRevokedOcsp = await createOcspResponse(
  mainChain.intermediate,
  mainChain.leaf,
  "revoked"
);
const intermediateGoodOcsp = await createOcspResponse(
  mainChain.root,
  mainChain.intermediate,
  "good"
);

async function resetServer(): Promise<void> {
  const state = emptyState();
  Object.assign(server.state, state);
  server.state.leafCrl = leafGoodCrl;
  server.state.intermediateCrl = intermediateGoodCrl;
  server.state.leafOcsp = leafGoodOcsp;
  server.state.intermediateOcsp = intermediateGoodOcsp;
  server.resetStats();
  await wait(10);
}

function ocspPolicy(): TrustPolicyInput {
  return {
    id: "benchmark:ocsp-first",
    version: 1,
    source: "local benchmark",
    anchorSetId: "benchmark:root",
    revocation: { requiredEvidence: "any", sourceOrder: ["ocsp", "crl"] }
  };
}

function crlPolicy(): TrustPolicyInput {
  return {
    id: "benchmark:crl",
    version: 1,
    source: "local benchmark",
    anchorSetId: "benchmark:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
}

function expectValid(result: unknown): void {
  const value = result as ValidationResult;
  if (!value.valid) {
    throw new Error(
      `Expected valid result, got ${value.code}: ${value.message}`
    );
  }
}

function expectRevoked(result: unknown): void {
  const value = result as ValidationResult;
  if (value.valid || value.code !== "CERTIFICATE_REVOKED") {
    throw new Error(
      `Expected revoked result, got ${value.valid ? "valid" : value.code}`
    );
  }
}

const provider = createEvidenceProvider({
  http: { allowPrivateAddresses: true, timeoutMs: 5000 },
  maxActiveRequests: 16,
  maxQueuedRequests: 64,
  maxActivePerOrigin: 16,
  queueTimeoutMs: 5000
});

function makeValidator(policy: TrustPolicyInput) {
  return createTrustValidator({
    trustAnchors: [mainChain.root.der],
    policy,
    provider,
    now,
    deadlineMs: 10_000
  });
}

const chainInput = [mainChain.leaf.der, mainChain.intermediate.der];

async function runScenario(config: ScenarioConfig): Promise<ScenarioResult> {
  const concurrency = config.concurrency ?? 1;
  const providerForStats = config.provider;
  for (let warm = 0; warm < config.warmup; warm++) {
    const result = await config.run(warm);
    config.expect?.(result);
  }
  server.resetStats();
  const samples: number[] = [];
  let failure: unknown;
  let maxQueued = 0;
  const delayMonitor = monitorEventLoopDelay({ resolution: 1 });
  delayMonitor.enable();
  const queueSampler = setInterval(() => {
    if (!providerForStats) return;
    maxQueued = Math.max(maxQueued, providerForStats.stats().queued);
  }, 1);
  const rssBefore = process.memoryUsage().rss;
  const started = performance.now();

  for (
    let batchStart = 0;
    batchStart < config.iterations;
    batchStart += concurrency
  ) {
    const batchSize = Math.min(concurrency, config.iterations - batchStart);
    await Promise.all(
      Array.from({ length: batchSize }, async (_, offset) => {
        const iteration = batchStart + offset;
        const sampleStart = performance.now();
        try {
          const result = await config.run(iteration);
          config.expect?.(result);
        } catch (error) {
          failure ??= error;
        }
        samples.push(performance.now() - sampleStart);
      })
    );
  }

  const elapsedMs = performance.now() - started;
  clearInterval(queueSampler);
  delayMonitor.disable();
  const rssAfter = process.memoryUsage().rss;
  if (failure) throw failure;

  return {
    name: config.name,
    description: config.description,
    iterations: config.iterations,
    warmup: config.warmup,
    concurrency,
    samples,
    requests: server.stats.requests,
    requestsByPath: [...server.stats.byPath.entries()].sort(),
    maxInFlight: server.stats.maxInFlight,
    maxQueued,
    eventLoopP99Ms: delayMonitor.percentile(99) / 1e6,
    eventLoopMaxMs: delayMonitor.max / 1e6,
    rssDeltaMb: (rssAfter - rssBefore) / (1024 * 1024),
    throughput: config.iterations / (elapsedMs / 1000)
  };
}

const results: ScenarioResult[] = [];

await resetServer();
results.push(
  await runScenario({
    name: "cold-crl",
    description:
      "New validator per request; two CRL downloads over local HTTP.",
    iterations: 15,
    warmup: 0,
    provider,
    run: () =>
      makeValidator(crlPolicy()).verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

await resetServer();
results.push(
  await runScenario({
    name: "cold-ocsp",
    description: "New validator per request; OCSP-first with local HTTP.",
    iterations: 15,
    warmup: 0,
    provider,
    run: () =>
      makeValidator(ocspPolicy()).verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

await resetServer();
const warmValidator = makeValidator(ocspPolicy());
results.push(
  await runScenario({
    name: "warm-cache",
    description:
      "Reused validator and cache; cached evidence revalidated, no network.",
    iterations: 60,
    warmup: 5,
    provider,
    run: () => warmValidator.verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

await resetServer();
server.state.intermediateCrlDelayMs = 20;
results.push(
  await runScenario({
    name: "slow-source",
    description: "Cold CRL path with a 20 ms delay on the intermediate CRL.",
    iterations: 10,
    warmup: 0,
    provider,
    run: () =>
      makeValidator(crlPolicy()).verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);
await wait(30);

await resetServer();
server.state.leafOcsp = leafRevokedOcsp;
server.state.intermediateOcspDelayMs = 100;
results.push(
  await runScenario({
    name: "fast-revoked",
    description:
      "Leaf OCSP revoked while the intermediate response is delayed 100 ms.",
    iterations: 10,
    warmup: 0,
    provider,
    run: () =>
      makeValidator(ocspPolicy()).verify({ certificateChain: chainInput }),
    expect: expectRevoked
  })
);
await wait(120);

await resetServer();
server.state.ocspFailure = true;
results.push(
  await runScenario({
    name: "ocsp-to-crl",
    description:
      "OCSP endpoints return 503; both certificates fall back to CRLs.",
    iterations: 10,
    warmup: 0,
    provider,
    run: () =>
      makeValidator(ocspPolicy()).verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

await resetServer();
const burstValidator = makeValidator(crlPolicy());
results.push(
  await runScenario({
    name: "crl-burst-40",
    description: "40 concurrent requests share two in-flight CRL downloads.",
    iterations: 40,
    warmup: 0,
    concurrency: 40,
    provider,
    run: () => burstValidator.verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

await resetServer();
server.state.leafCrl = largeLeafCrl;
const largeValidator = makeValidator(crlPolicy());
results.push(
  await runScenario({
    name: "large-crl-warm",
    description:
      "Cached CRL with 3000 revoked entries revalidated per request.",
    iterations: 25,
    warmup: 2,
    provider,
    run: () => largeValidator.verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

await resetServer();
server.state.leafCrl = largeLeafCrl;
const workerEngine = createWorkerPkiEngine({
  maxThreads: 2,
  maxQueue: 16,
  taskTimeoutMs: 5000
});
const workerLargeValidator = createTrustValidator({
  trustAnchors: [mainChain.root.der],
  policy: crlPolicy(),
  provider,
  engine: workerEngine,
  now,
  deadlineMs: 10_000
});
results.push(
  await runScenario({
    name: "large-crl-warm-worker",
    description:
      "Same cached 3000-entry CRL revalidation executed in a bounded worker pool.",
    iterations: 25,
    warmup: 2,
    provider,
    run: () => workerLargeValidator.verify({ certificateChain: chainInput }),
    expect: expectValid
  })
);

const cpuEngine = createInlinePkiEngine();
const deepInput = [
  deepLeaf.der,
  secondIntermediate.der,
  firstIntermediate.der,
  mainChain.intermediate.der
];
results.push(
  await runScenario({
    name: "cpu-path-5-cert",
    description:
      "Inline PKI path preparation for a five-certificate chain; no network.",
    iterations: 150,
    warmup: 10,
    run: async () => {
      const result = await cpuEngine.preparePath({
        certificateChain: deepInput,
        trustAnchors: [mainChain.root.der],
        checkDateMs: now()
      });
      if (!result.pathValid) throw new Error(result.message);
      return result;
    }
  })
);

results.push(
  await runScenario({
    name: "cpu-path-5-cert-worker",
    description:
      "Same five-certificate path preparation dispatched through the worker pool.",
    iterations: 150,
    warmup: 10,
    run: async () => {
      const result = await workerEngine.preparePath({
        certificateChain: deepInput,
        trustAnchors: [mainChain.root.der],
        checkDateMs: now()
      });
      if (!result.pathValid) throw new Error(result.message);
      return result;
    }
  })
);

await workerEngine.close({ force: true });
await server.close();

function format(value: number, digits = 2): string {
  return value.toFixed(digits);
}

const cpu = cpus()[0];
const markdown = `# Benchmark results

Generated by \`npm run benchmark\` on ${new Date().toISOString()}.

## Environment

- Node.js: ${process.version}
- Platform: ${platform()} ${release()}
- CPU: ${cpu?.model ?? "unknown"} (${cpus().length} logical cores)
- Memory: ${(totalmem() / (1024 * 1024 * 1024)).toFixed(1)} GiB
- Execution: inline PKI.js and optional bounded Piscina worker scenarios (see table)
- Fixtures: generated synthetic RSA chains and signed CRL/OCSP responses served by a local HTTP server
- Warmup and sample counts are listed per scenario; latency values are wall-clock milliseconds including local loopback and crypto
- Event-loop delay is measured with \`perf_hooks.monitorEventLoopDelay\` at 1 ms resolution
- Provider limits: maxActiveRequests=16, maxQueuedRequests=64, maxActivePerOrigin=16, queueTimeoutMs=5000
- Worker pool (where used): Piscina maxThreads=2, maxQueue=16, taskTimeoutMs=5000

| Scenario | Samples | Warmup | Concurrency | p50 ms | p95 ms | p99 ms | Throughput/s | Requests | Max in-flight | Max queued | EL p99 ms | EL max ms | RSS delta MB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
${results
  .map(
    (result) =>
      `| ${result.name} | ${result.iterations} | ${result.warmup} | ${result.concurrency} | ${format(percentile(result.samples, 0.5))} | ${format(percentile(result.samples, 0.95))} | ${format(percentile(result.samples, 0.99))} | ${format(result.throughput, 1)} | ${result.requests} | ${result.maxInFlight} | ${result.maxQueued} | ${format(result.eventLoopP99Ms)} | ${format(result.eventLoopMaxMs)} | ${format(result.rssDeltaMb, 1)} |`
  )
  .join("\n")}

## Scenario notes

${results.map((result) => `- **${result.name}**: ${result.description} Requests by path: ${result.requestsByPath.map(([path, count]) => `${path}=${count}`).join(", ") || "none"}.`).join("\n")}

## Interpretation and Step 9 input

- Network scenarios are dominated by local HTTP round trips and evidence parsing; the \`warm-cache\` and \`large-crl-warm\` scenarios isolate evidence revalidation without downloads.
- \`cpu-path-5-cert\` isolates path-building CPU without any network or revocation evidence.
- The \`large-crl-warm-worker\` and \`cpu-path-5-cert-worker\` scenarios run the same CPU work through the optional Piscina pool. Compare their latency and event-loop delay with the inline scenarios; the worker pool is optional and remains off unless the host creates and shares one.
- The inline large-CRL and CPU-path event-loop p99 values above are the evidence for keeping the worker mode available. The measurement is a baseline, not a pass/fail gate; rerunning on the target deployment is still required before defaulting worker execution.
- Network concurrency, bounded queues, single-flight, and cancellation remain on the main thread; workers receive only DER/DTO. The pool is owned by the caller and must be closed.
`;

writeFileSync(new URL("../docs/benchmark.md", import.meta.url), markdown);
process.stdout.write(markdown);
