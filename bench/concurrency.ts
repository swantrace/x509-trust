import { writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { cpus, platform, release, totalmem } from "node:os";
import { monitorEventLoopDelay, performance } from "node:perf_hooks";
import { Certificate } from "pkijs";
import { validateCrl } from "../src/crl.ts";
import { createCrlIndexCache } from "../src/crl-index-cache.ts";
import {
  createEvidenceProvider,
  createTrustValidator,
  createWorkerPkiEngine,
  type TrustPolicyInput,
  type ValidationResult
} from "../src/index.ts";
import {
  createCrl,
  createCrlWithSerials,
  createSyntheticChain
} from "../test/helpers/synthetic-pki.ts";

const checkDate = new Date("2026-10-15T00:00:00Z");
const now = () => checkDate.getTime();
const leafCrlUrl = "http://load.test/leaf.crl";
const intermediateCrlUrl = "http://load.test/intermediate.crl";

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function percentile(values: number[], fraction: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[
    Math.min(
      sorted.length - 1,
      Math.max(0, Math.ceil(fraction * sorted.length) - 1)
    )
  ];
}

function p50(values: number[]): number {
  return percentile(values, 0.5);
}

function p99(values: number[]): number {
  return percentile(values, 0.99);
}

async function startHealthServer(): Promise<{
  origin: string;
  close(): Promise<void>;
}> {
  const server = http.createServer((_request, response) => {
    response.statusCode = 200;
    response.end("ok");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
}

interface HealthClient {
  latencies: number[];
  started: Promise<void>;
  stop(): Promise<void>;
}

function startHealthClient(origin: string): HealthClient {
  const latencies: number[] = [];
  const started = deferred();
  let running = true;
  const agent = new http.Agent({ keepAlive: true });
  const loop = (async () => {
    while (running) {
      const begin = performance.now();
      await new Promise<void>((resolve, reject) => {
        const request = http.get(`${origin}/health`, { agent }, (response) => {
          response.resume();
          response.on("end", resolve);
          response.on("error", reject);
        });
        request.on("error", reject);
        request.on("socket", () => started.resolve());
      });
      latencies.push(performance.now() - begin);
    }
  })().catch(() => {});
  return {
    latencies,
    started: started.promise,
    async stop() {
      running = false;
      await loop;
      agent.destroy();
    }
  };
}

interface Scenario {
  name: string;
  description: string;
  concurrency: number;
  durationMs: number;
  warmup: number;
  run: () => Promise<unknown>;
  provider?: { stats(): { queueSize: number } };
  worker?: { stats(): { queueSize: number } };
  close?: () => Promise<void>;
}

interface ScenarioResult {
  name: string;
  description: string;
  concurrency: number;
  durationMs: number;
  completed: number;
  validationThroughput: number;
  validationP50: number;
  validationP99: number;
  healthP50: number;
  healthP99: number;
  eventLoopP99: number;
  eventLoopMax: number;
  cpuPercent: number;
  rssDeltaMb: number;
  maxQueue: number;
}

async function runScenario(
  scenario: Scenario,
  healthOrigin: string
): Promise<ScenarioResult> {
  for (let index = 0; index < scenario.warmup; index++) {
    await scenario.run();
  }
  const monitor = monitorEventLoopDelay({ resolution: 1 });
  const health = startHealthClient(healthOrigin);
  await health.started;
  await new Promise((resolve) => setImmediate(resolve));
  monitor.enable();
  const rssBefore = process.memoryUsage().rss;
  const cpuBefore = process.cpuUsage();
  const validationLatencies: number[] = [];
  let completed = 0;
  let maxQueue = 0;
  const queueSampler = setInterval(() => {
    const queue =
      scenario.worker?.stats().queueSize ??
      scenario.provider?.stats().queueSize ??
      0;
    maxQueue = Math.max(maxQueue, queue);
  }, 2);
  const startedAt = performance.now();
  const deadline = startedAt + scenario.durationMs;
  await Promise.all(
    Array.from({ length: scenario.concurrency }, async () => {
      while (performance.now() < deadline) {
        const begin = performance.now();
        try {
          await scenario.run();
          validationLatencies.push(performance.now() - begin);
          completed++;
        } catch {
          // A failed validation still consumes capacity; count it as completed
          // work but keep latency samples only for successful calls.
          completed++;
        }
      }
    })
  );
  const elapsed = performance.now() - startedAt;
  clearInterval(queueSampler);
  monitor.disable();
  await health.stop();
  const cpu = process.cpuUsage(cpuBefore);
  const rssAfter = process.memoryUsage().rss;
  await scenario.close?.();
  return {
    name: scenario.name,
    description: scenario.description,
    concurrency: scenario.concurrency,
    durationMs: scenario.durationMs,
    completed,
    validationThroughput: completed / (elapsed / 1000),
    validationP50: p50(validationLatencies),
    validationP99: p99(validationLatencies),
    healthP50: p50(health.latencies),
    healthP99: p99(health.latencies),
    eventLoopP99: monitor.percentile(99) / 1e6,
    eventLoopMax: monitor.max / 1e6,
    cpuPercent: ((cpu.user + cpu.system) / 1000 / elapsed) * 100,
    rssDeltaMb: (rssAfter - rssBefore) / (1024 * 1024),
    maxQueue
  };
}

const healthServer = await startHealthServer();
const chain = await createSyntheticChain({
  intermediate: {
    crlUrls: [intermediateCrlUrl]
  },
  leaf: {
    crlUrls: [leafCrlUrl]
  }
});
const largeLeafCrl = await createCrlWithSerials(
  chain.intermediate,
  Array.from({ length: 3000 }, (_, index) => 200_000 + index)
);
const intermediateCrl = await createCrl(chain.root, []);
const directCertificate = Certificate.fromBER(chain.leaf.der);
const directIssuer = Certificate.fromBER(chain.intermediate.der);
const chainInput = [chain.leaf.der, chain.intermediate.der];

function crlPolicy(): TrustPolicyInput {
  return {
    id: "load:crl",
    version: 1,
    source: "concurrency load benchmark",
    anchorSetId: "load:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
}

function provider() {
  return createEvidenceProvider({
    loadOcsp: false,
    loadCrl: async (url) =>
      url.endsWith("/leaf.crl") ? largeLeafCrl : intermediateCrl
  });
}

const inlineIndexCache = createCrlIndexCache({
  maxEntries: 8,
  maxBytes: 64 * 1024 * 1024
});
const directWorkerIndexEngine = createWorkerPkiEngine({
  minThreads: 4,
  maxThreads: 4,
  maxQueue: 64,
  taskTimeoutMs: 5000,
  crlIndexCache: { maxEntries: 8, maxBytes: 64 * 1024 * 1024 }
});
const directWorkerNoIndexEngine = createWorkerPkiEngine({
  minThreads: 4,
  maxThreads: 4,
  maxQueue: 64,
  taskTimeoutMs: 5000,
  crlIndexCache: false
});
const inlineIndexValidator = createTrustValidator({
  trustAnchors: [chain.root.der],
  policy: crlPolicy(),
  provider: provider(),
  crlIndexCache: { maxEntries: 8, maxBytes: 64 * 1024 * 1024 },
  now
});
const workerIndexEngine = createWorkerPkiEngine({
  minThreads: 4,
  maxThreads: 4,
  maxQueue: 64,
  taskTimeoutMs: 5000,
  crlIndexCache: { maxEntries: 8, maxBytes: 64 * 1024 * 1024 }
});
const workerIndexValidator = createTrustValidator({
  trustAnchors: [chain.root.der],
  policy: crlPolicy(),
  provider: provider(),
  engine: workerIndexEngine,
  now
});

const scenarios: Scenario[] = [
  {
    name: "crl-inline-index",
    description:
      "Direct validateCrl, inline, parsed CRL index cache, 32 concurrent callers.",
    concurrency: 32,
    durationMs: 3000,
    warmup: 4,
    run: () =>
      validateCrl({
        certificate: directCertificate,
        issuerCertificate: directIssuer,
        crl: largeLeafCrl,
        checkDate,
        indexCache: inlineIndexCache
      })
  },
  {
    name: "crl-worker-index",
    description:
      "Direct validateCrl, 4 worker threads, worker-local parsed CRL index cache.",
    concurrency: 32,
    durationMs: 3000,
    warmup: 8,
    run: () =>
      directWorkerIndexEngine.validateCrl({
        certificateDer: chain.leaf.der,
        issuerDer: chain.intermediate.der,
        crl: largeLeafCrl,
        checkDateMs: now()
      }),
    worker: directWorkerIndexEngine,
    close: () => directWorkerIndexEngine.close({ force: true })
  },
  {
    name: "crl-inline-no-index",
    description:
      "Direct validateCrl, inline, no parsed CRL cache, 8 concurrent callers.",
    concurrency: 8,
    durationMs: 4000,
    warmup: 1,
    run: () =>
      validateCrl({
        certificate: directCertificate,
        issuerCertificate: directIssuer,
        crl: largeLeafCrl,
        checkDate
      })
  },
  {
    name: "crl-worker-no-index",
    description: "Direct validateCrl, 4 worker threads, no parsed CRL cache.",
    concurrency: 8,
    durationMs: 4000,
    warmup: 4,
    run: () =>
      directWorkerNoIndexEngine.validateCrl({
        certificateDer: chain.leaf.der,
        issuerDer: chain.intermediate.der,
        crl: largeLeafCrl,
        checkDateMs: now()
      }),
    worker: directWorkerNoIndexEngine,
    close: () => directWorkerNoIndexEngine.close({ force: true })
  },
  {
    name: "verify-inline-index",
    description:
      "Full verify, inline, raw CRL cache plus parsed index; includes path validation.",
    concurrency: 32,
    durationMs: 3000,
    warmup: 2,
    run: () => inlineIndexValidator.verify({ certificateChain: chainInput })
  },
  {
    name: "verify-worker-index",
    description:
      "Full verify, 4 worker threads, parsed index; path and CRL work off main.",
    concurrency: 32,
    durationMs: 3000,
    warmup: 4,
    run: () => workerIndexValidator.verify({ certificateChain: chainInput }),
    worker: workerIndexEngine,
    close: () => workerIndexEngine.close({ force: true })
  }
];

const results: ScenarioResult[] = [];
for (const scenario of scenarios) {
  results.push(await runScenario(scenario, healthServer.origin));
}
await healthServer.close();

function format(value: number, digits = 1): string {
  return value.toFixed(digits);
}

const markdown = `# Concurrency load benchmark

Generated by \`npm run benchmark:concurrency\` on ${new Date().toISOString()}.

## Environment

- Node.js: ${process.version}
- Platform: ${platform()} ${release()}
- CPU: ${cpus()[0]?.model ?? "unknown"} (${cpus().length} logical cores)
- Memory: ${(totalmem() / (1024 * 1024 * 1024)).toFixed(1)} GiB
- Validation workload: synthetic 3,000-entry CRL (about 66 KB), local same-process health endpoint
- Closed-loop concurrency: each worker loop repeats validations until its duration ends
- Health endpoint: separate HTTP request loop in the same process; latency shows main-thread starvation
- CPU is process-wide and includes worker threads
- Direct \`validateCrl\` rows exclude certificate path validation; \`verify-*\` rows include it

| Scenario | Concurrency | Duration s | Completed | Validations/s | Val p50 ms | Val p99 ms | Health p50 ms | Health p99 ms | EL p99 ms | EL max ms | CPU % | RSS Δ MB | Max queue |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
${results
  .map(
    (result) =>
      `| ${result.name} | ${result.concurrency} | ${format(result.durationMs / 1000, 1)} | ${result.completed} | ${format(result.validationThroughput)} | ${format(result.validationP50)} | ${format(result.validationP99)} | ${format(result.healthP50)} | ${format(result.healthP99)} | ${format(result.eventLoopP99)} | ${format(result.eventLoopMax)} | ${format(result.cpuPercent)} | ${format(result.rssDeltaMb)} | ${result.maxQueue} |`
  )
  .join("\n")}

## Interpretation

- Compare \`crl-inline-index\` and \`crl-worker-index\` for the hot CRL path, and \`verify-inline-index\` versus \`verify-worker-index\` for full application-level validation.
- A low \`Health p99\` means the main thread kept accepting and completing unrelated requests while validation load was running.
- High \`Validations/s\` with high \`Health p99\` is a throughput/latency tradeoff: the process completes work but stalls other traffic.
- Worker rows include task dispatch and DER structured-copy overhead. For small indexed CRL work, inline may still have higher throughput; for CPU-heavy work, worker rows should show lower health latency.
- Results are local closed-loop measurements, not a production SLA. Re-run with your certificate mix, cache hit ratio, HTTP sources, and worker count.
`;

writeFileSync(
  new URL("../docs/concurrency-benchmark.md", import.meta.url),
  markdown
);
process.stdout.write(markdown);
