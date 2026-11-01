import assert from "node:assert/strict";
import { test } from "node:test";
import { inlinePkiEngine } from "../src/engine/pki-engine.ts";
import * as mainEntry from "../src/index.ts";
import {
  createRevocationProvider,
  createTrustValidator
} from "../src/index.ts";
import { createWorkerPkiEngine } from "../src/worker.ts";
import { createCrl, createLeafForChain } from "./helpers/synthetic-pki.ts";
import {
  chain,
  chainInput,
  checkDateMs,
  intermediateCrl,
  intermediateOcsp,
  leafCrl,
  leafOcsp,
  profile,
  provider,
  worker
} from "./helpers/worker-engine-fixtures.ts";

test("worker APIs live only on the worker entrypoint", () => {
  assert.equal("createWorkerPkiEngine" in mainEntry, false);
  assert.equal(typeof createWorkerPkiEngine, "function");
});

test("worker path preparation matches the inline engine", async () => {
  const inline = inlinePkiEngine;
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
  const inline = inlinePkiEngine;
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
    profile: profile(),
    provider: provider(),
    now: () => checkDateMs
  });
  const workerValidator = createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: profile(),
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
    profile: profile(),
    provider: createRevocationProvider({
      ocspLoader: false,
      crlLoader: async ({ url }) =>
        url.endsWith("/intermediate.crl") ? intermediateCrl : revokedCrl
    }),
    now: () => checkDateMs
  }).verify({ certificateChain: [revokedLeaf.der, chain.intermediate.der] });
  const workerRevoked = await createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: profile(),
    provider: createRevocationProvider({
      ocspLoader: false,
      crlLoader: async ({ url }) =>
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
