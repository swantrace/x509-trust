import { after } from "node:test";
import {
  createRevocationProvider,
  type ValidationProfileInput
} from "../../src/index.ts";
import { createWorkerPkiEngine } from "../../src/worker.ts";
import {
  createCrl,
  createCrlWithSerials,
  createOcspResponse,
  createSyntheticChain
} from "./synthetic-pki.ts";

export const checkDateMs = new Date("2026-10-15T00:00:00Z").getTime();
export const chain = await createSyntheticChain({
  intermediate: {
    crlUrls: ["http://worker.test/intermediate.crl"],
    ocspUrls: ["http://worker.test/intermediate-ocsp"]
  },
  leaf: {
    crlUrls: ["http://worker.test/leaf.crl"],
    ocspUrls: ["http://worker.test/leaf-ocsp"]
  }
});
export const leafCrl = await createCrl(chain.intermediate, []);
export const intermediateCrl = await createCrl(chain.root, []);
export const leafOcsp = await createOcspResponse(
  chain.intermediate,
  chain.leaf,
  "good"
);
export const intermediateOcsp = await createOcspResponse(
  chain.root,
  chain.intermediate,
  "good"
);
export const largeCrl = await createCrlWithSerials(
  chain.intermediate,
  Array.from({ length: 3000 }, (_, index) => 200_000 + index)
);
export const chainInput = [chain.leaf.der, chain.intermediate.der];

export const worker = createWorkerPkiEngine({
  maxThreads: 2,
  maxQueue: 8,
  taskTimeoutMs: 10_000
});
after(async () => {
  await worker.close({ force: true });
});

export function profile(): ValidationProfileInput {
  return {
    id: "worker:profile",
    version: 1,
    source: "worker parity test",
    anchorSetId: "worker:root",
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] }
  };
}

export async function waitForIdle(engine: {
  stats(): { idleThreads: number };
}): Promise<void> {
  const deadline = Date.now() + 2000;
  while (engine.stats().idleThreads === 0) {
    if (Date.now() > deadline)
      throw new Error("Worker pool did not become idle");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

export function provider() {
  return createRevocationProvider({
    ocspLoader: false,
    crlLoader: async ({ url }) =>
      url.endsWith("/intermediate.crl") ? intermediateCrl : leafCrl
  });
}
