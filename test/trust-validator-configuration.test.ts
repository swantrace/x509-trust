import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { createMemoryCache, createTrustValidator } from "../src/index.ts";
import { readCertificate } from "./helpers/fixtures.ts";
import {
  intermediate,
  leaf,
  loadCrl,
  now,
  root
} from "./helpers/trust-validator-fixtures.ts";

test("shares injected cache storage but still validates trust for every request", async () => {
  const cache = createMemoryCache({ now });
  let loads = 0;
  const configuration = {
    trustAnchors: [root],
    cache,
    now,
    ocspLoader: false as const,
    async crlLoader({ url }: { url: string }) {
      loads++;
      return loadCrl(url);
    }
  };
  const input = { certificateChain: [leaf, intermediate] };
  assert.equal(
    (await createTrustValidator(configuration).verify(input)).valid,
    true
  );
  assert.equal(
    (await createTrustValidator(configuration).verify(input)).valid,
    true
  );
  assert.equal(loads, 2);
  const untrusted = createTrustValidator({
    ...configuration,
    trustAnchors: [readCertificate("untrusted-root")]
  });
  assert.equal((await untrusted.verify(input)).valid, false);
  assert.equal(loads, 2);
});

test("snapshots configured trust anchors and reports configuration errors early", async () => {
  const anchor = Buffer.from(new X509Certificate(root).raw);
  const validator = createTrustValidator({
    trustAnchors: [anchor],
    crlLoader: ({ url }) => loadCrl(url),
    ocspLoader: false,
    now
  });
  anchor.fill(0);
  assert.equal(
    (await validator.verify({ certificateChain: [leaf, intermediate] })).valid,
    true
  );
  assert.throws(() => createTrustValidator({ trustAnchors: [] }), TypeError);
  assert.throws(() =>
    createTrustValidator({ trustAnchors: ["invalid certificate"] })
  );
  await assert.rejects(
    validator.verify({
      certificateChain: [leaf, intermediate],
      checkDate: new Date(NaN)
    }),
    TypeError
  );
});
