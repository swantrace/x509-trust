import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import {
  createTrustRegistry,
  PolicyError,
  type RequiredEvidence,
  type TrustPolicyInput,
  type TrustRuleContext,
  type TrustRuleRegistration
} from "../src/index.ts";
import type { SyntheticCertificate } from "./helpers/synthetic-pki.ts";
import {
  createCrl,
  createLeafForChain,
  createSyntheticChain
} from "./helpers/synthetic-pki.ts";

const baseLeafCrlUrl = "http://base.test/leaf.crl";
const baseIntermediateCrlUrl = "http://base.test/intermediate.crl";
const secondLeafCrlUrl = "http://second.test/leaf.crl";
const secondIntermediateCrlUrl = "http://second.test/intermediate.crl";
const sameSan = "https://same.example.test/service";
const checkDate = new Date("2026-10-15T00:00:00Z");

const base = await createSyntheticChain({
  intermediate: {
    crlUrls: [baseIntermediateCrlUrl],
    certificatePolicyOids: ["2.9.9.9"]
  },
  leaf: {
    crlUrls: [baseLeafCrlUrl],
    uriSubjectAlternativeNames: [sameSan],
    extendedKeyUsageOids: ["1.3.6.1.5.5.7.3.2"],
    certificatePolicyOids: ["1.2.3.4"]
  }
});
const second = await createSyntheticChain({
  intermediate: { crlUrls: [secondIntermediateCrlUrl] },
  leaf: {
    crlUrls: [secondLeafCrlUrl],
    uriSubjectAlternativeNames: [sameSan]
  }
});
const baseLeafCrl = await createCrl(base.intermediate, []);
const baseIntermediateCrl = await createCrl(base.root, []);
const secondLeafCrl = await createCrl(second.intermediate, []);
const secondIntermediateCrl = await createCrl(second.root, []);
const crlByUrl = new Map<string, Uint8Array>([
  [baseLeafCrlUrl, baseLeafCrl],
  [baseIntermediateCrlUrl, baseIntermediateCrl],
  [secondLeafCrlUrl, secondLeafCrl],
  [secondIntermediateCrlUrl, secondIntermediateCrl]
]);

function policyFor(
  id: string,
  {
    version = 1,
    rules,
    requiredEvidence = "crl"
  }: {
    version?: number;
    rules?: TrustPolicyInput["rules"];
    requiredEvidence?: RequiredEvidence;
  } = {}
): TrustPolicyInput {
  return {
    id,
    version,
    source: "synthetic registry policy",
    anchorSetId: "synthetic:root",
    revocation: {
      requiredEvidence,
      sourceOrder: requiredEvidence === "ocsp" ? ["ocsp"] : ["crl"]
    },
    ...(rules ? { rules } : {})
  };
}

function makeRegistry(
  registrations: Array<{
    communityId: string;
    chain: typeof base;
    policy?: TrustPolicyInput;
    rules?: readonly TrustRuleRegistration[];
  }>,
  loadCrl?: (url: string) => Promise<Uint8Array>
) {
  const calls = { crl: [] as string[] };
  const registry = createTrustRegistry({
    now: () => checkDate.getTime(),
    loadOcsp: false,
    loadCrl:
      loadCrl ??
      (async (url) => {
        calls.crl.push(url);
        const response = crlByUrl.get(url);
        if (!response) throw new Error(`No CRL for ${url}`);
        return response;
      })
  });
  for (const registration of registrations) {
    registry.register({
      communityId: registration.communityId,
      trustAnchors: [registration.chain.root.der],
      policy:
        registration.policy ?? policyFor(`${registration.communityId}:policy`),
      rules: registration.rules
    });
  }
  return { registry, calls };
}

function inputFor(chain: typeof base, leaf: SyntheticCertificate = chain.leaf) {
  return [leaf.der, chain.intermediate.der];
}

async function ruleCommunity(
  communityId: string,
  rule: TrustRuleRegistration,
  policyOverrides: Partial<TrustPolicyInput> = {}
) {
  const { registry } = makeRegistry([
    {
      communityId,
      chain: base,
      policy: {
        ...policyFor(`${communityId}:policy`),
        ...policyOverrides,
        rules: {
          ...policyOverrides.rules,
          requiredRuleNames: [rule.name]
        }
      },
      rules: [rule]
    }
  ]);
  return registry;
}

test("selects anchors per community even when leaves share a SAN", async () => {
  const { registry } = makeRegistry([
    { communityId: "community-a", chain: base },
    { communityId: "community-b", chain: second }
  ]);
  const first = await registry.verify({
    communityId: "community-a",
    certificateChain: inputFor(base)
  });
  const other = await registry.verify({
    communityId: "community-b",
    certificateChain: inputFor(second)
  });
  assert.equal(first.valid, true);
  assert.equal(other.valid, true);
  assert.equal(first.valid && first.communityId, "community-a");
  assert.equal(other.valid && other.communityId, "community-b");
  assert.deepEqual(
    first.valid && first.leafCertificate.uriSubjectAlternativeNames,
    [sameSan]
  );
  assert.deepEqual(
    other.valid && other.leafCertificate.uriSubjectAlternativeNames,
    [sameSan]
  );

  const cross = await registry.verify({
    communityId: "community-a",
    certificateChain: inputFor(second)
  });
  assert.equal(cross.valid, false);
  assert.equal(cross.code, "INVALID_CERTIFICATE_PATH");
});

test("unknown communities and versions fail without any evidence I/O", async () => {
  const { registry, calls } = makeRegistry([
    { communityId: "known", chain: base }
  ]);
  const unknown = await registry.verify({
    communityId: "unknown",
    certificateChain: inputFor(base)
  });
  assert.equal(unknown.valid, false);
  assert.equal(unknown.code, "UNKNOWN_COMMUNITY");
  assert.equal(calls.crl.length, 0);

  const unknownVersion = await registry.verify({
    communityId: "known",
    policyVersion: 99,
    certificateChain: inputFor(base)
  });
  assert.equal(unknownVersion.valid, false);
  assert.equal(unknownVersion.code, "UNKNOWN_POLICY_VERSION");
  assert.equal(calls.crl.length, 0);
});

test("rejects duplicate policy versions and does not partially register failures", async () => {
  const { registry } = makeRegistry([
    {
      communityId: "versions",
      chain: base,
      policy: policyFor("v1", { version: 1 })
    }
  ]);
  assert.throws(
    () =>
      registry.register({
        communityId: "versions",
        trustAnchors: [base.root.der],
        policy: policyFor("v1-again", { version: 1 })
      }),
    (error: unknown) => {
      assert.ok(error instanceof PolicyError);
      assert.equal(error.code, "INVALID_POLICY");
      return true;
    }
  );

  assert.throws(
    () =>
      registry.register({
        communityId: "broken",
        trustAnchors: [base.root.der],
        policy: {
          ...policyFor("broken"),
          rules: { requiredRuleNames: ["missing-rule"] }
        }
      }),
    (error: unknown) => {
      assert.ok(error instanceof PolicyError);
      assert.equal(error.code, "UNSUPPORTED_POLICY");
      return true;
    }
  );
  const broken = await registry.verify({
    communityId: "broken",
    certificateChain: inputFor(base)
  });
  assert.equal(broken.valid, false);
  assert.equal(broken.code, "UNKNOWN_COMMUNITY");
});

test("selects the latest policy version unless an exact version is requested", async () => {
  const { registry } = makeRegistry([
    {
      communityId: "versioned",
      chain: base,
      policy: policyFor("versioned:v1", { version: 1 })
    },
    {
      communityId: "versioned",
      chain: base,
      policy: policyFor("versioned:v2", {
        version: 2,
        rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
      })
    }
  ]);
  const latest = await registry.verify({
    communityId: "versioned",
    certificateChain: inputFor(base)
  });
  assert.equal(latest.valid, false);
  assert.equal(latest.code, "POLICY_REJECTED");
  assert.equal(latest.policyVersion, 2);

  const pinned = await registry.verify({
    communityId: "versioned",
    policyVersion: 1,
    certificateChain: inputFor(base)
  });
  assert.equal(pinned.valid, true);
  assert.equal(pinned.valid && pinned.policyVersion, 1);
});

test("a version registered during an in-flight request does not affect that request", async () => {
  let release!: () => void;
  let started!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const startedSignal = new Promise<void>((resolve) => {
    started = resolve;
  });
  const { registry } = makeRegistry(
    [
      {
        communityId: "in-flight",
        chain: base,
        policy: policyFor("in-flight:v1", { version: 1 })
      }
    ],
    async (url) => {
      if (url === baseLeafCrlUrl) {
        started();
        await gate;
      }
      const response = crlByUrl.get(url);
      if (!response) throw new Error(`No CRL for ${url}`);
      return response;
    }
  );
  const pending = registry.verify({
    communityId: "in-flight",
    certificateChain: inputFor(base)
  });
  await startedSignal;
  registry.register({
    communityId: "in-flight",
    trustAnchors: [base.root.der],
    policy: policyFor("in-flight:v2", {
      version: 2,
      rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
    })
  });
  release();
  const result = await pending;
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.policyVersion, 1);
});

test("registration snapshots resist later caller mutation", async () => {
  const anchor = Uint8Array.from(base.root.der);
  const policy = policyFor("mutable");
  const { registry } = makeRegistry([]);
  registry.register({
    communityId: "mutable",
    trustAnchors: [anchor],
    policy
  });
  anchor.fill(0);
  (policy.revocation as { sourceOrder: string[] }).sourceOrder = ["ocsp"];
  policy.id = "changed";
  const result = await registry.verify({
    communityId: "mutable",
    certificateChain: inputFor(base)
  });
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.policyId, "mutable");
});

test("built-in leaf KU, EKU, policy OID and path depth rules run after core validation", async () => {
  const { registry } = makeRegistry([
    {
      communityId: "rules",
      chain: base,
      policy: policyFor("rules:policy", {
        rules: {
          leafKeyUsage: ["digitalSignature"],
          leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
          requiredLeafPolicyOids: ["1.2.3.4"],
          maxPathDepth: 3
        }
      })
    }
  ]);
  const success = await registry.verify({
    communityId: "rules",
    certificateChain: inputFor(base)
  });
  assert.equal(success.valid, true);

  const wrongKeyUsage = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    keyUsageBits: [0x20]
  });
  const wrongUsage = await registry.verify({
    communityId: "rules",
    certificateChain: inputFor(base, wrongKeyUsage)
  });
  assert.equal(wrongUsage.valid, false);
  assert.equal(wrongUsage.code, "POLICY_REJECTED");

  const noEku = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl]
  });
  const missingEku = await registry.verify({
    communityId: "rules",
    certificateChain: inputFor(base, noEku)
  });
  assert.equal(missingEku.valid, false);
  assert.equal(missingEku.code, "POLICY_REJECTED");

  const leafWithoutPolicy = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    extendedKeyUsageOids: ["1.3.6.1.5.5.7.3.2"]
  });
  const { registry: policyRegistry } = makeRegistry([
    {
      communityId: "leaf-policy",
      chain: base,
      policy: policyFor("leaf-policy:policy", {
        rules: { requiredLeafPolicyOids: ["2.9.9.9"] }
      })
    }
  ]);
  const intermediateOnly = await policyRegistry.verify({
    communityId: "leaf-policy",
    certificateChain: inputFor(base, leafWithoutPolicy)
  });
  assert.equal(intermediateOnly.valid, false);
  assert.equal(intermediateOnly.code, "POLICY_REJECTED");

  const leafWithPolicy = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    certificatePolicyOids: ["2.9.9.9"]
  });
  const leafPolicy = await policyRegistry.verify({
    communityId: "leaf-policy",
    certificateChain: inputFor(base, leafWithPolicy)
  });
  assert.equal(leafPolicy.valid, true);

  const { registry: depthRegistry } = makeRegistry([
    {
      communityId: "depth",
      chain: base,
      policy: policyFor("depth:policy", {
        rules: { maxPathDepth: 2 }
      })
    }
  ]);
  const tooDeep = await depthRegistry.verify({
    communityId: "depth",
    certificateChain: inputFor(base)
  });
  assert.equal(tooDeep.valid, false);
  assert.equal(tooDeep.code, "POLICY_REJECTED");
});

test("registered custom rules receive trusted facts and fail closed", async () => {
  let observed: TrustRuleContext | undefined;
  const capture = await ruleCommunity("custom-ok", {
    name: "capture",
    check(context) {
      observed = context;
      return { ok: true };
    }
  });
  const success = await capture.verify({
    communityId: "custom-ok",
    certificateChain: inputFor(base)
  });
  assert.equal(success.valid, true);
  assert.equal(observed?.communityId, "custom-ok");
  assert.equal(observed?.certificatePath.length, 3);
  assert.deepEqual(observed?.leaf.uriSubjectAlternativeNames, [sameSan]);
  assert.equal(
    observed?.leaf.fingerprint256,
    new X509Certificate(base.leaf.der).fingerprint256
  );

  const denied = await ruleCommunity("custom-deny", {
    name: "deny",
    check: () => ({ ok: false, message: "denied by registered rule" })
  });
  const deniedResult = await denied.verify({
    communityId: "custom-deny",
    certificateChain: inputFor(base)
  });
  assert.equal(deniedResult.valid, false);
  assert.equal(deniedResult.code, "POLICY_REJECTED");
  assert.equal(
    deniedResult.valid === false && deniedResult.message,
    "denied by registered rule"
  );

  const unrecognized = await ruleCommunity("custom-bad", {
    name: "bad",
    check: (() => ({ valid: true })) as never
  });
  const badResult = await unrecognized.verify({
    communityId: "custom-bad",
    certificateChain: inputFor(base)
  });
  assert.equal(badResult.valid, false);
  assert.equal(badResult.code, "POLICY_REJECTED");

  const throwing = await ruleCommunity("custom-throw", {
    name: "throw",
    check: () => {
      throw new Error("rule failure");
    }
  });
  const throwResult = await throwing.verify({
    communityId: "custom-throw",
    certificateChain: inputFor(base)
  });
  assert.equal(throwResult.valid, false);
  assert.equal(throwResult.code, "POLICY_REJECTED");
});

test("rules cannot override core path or revocation failures", async () => {
  const rule: TrustRuleRegistration = {
    name: "always-ok",
    check: () => ({ ok: true })
  };
  const { registry } = makeRegistry([
    {
      communityId: "core",
      chain: base,
      policy: {
        ...policyFor("core:policy"),
        rules: { requiredRuleNames: [rule.name] }
      },
      rules: [rule]
    }
  ]);
  const wrongAnchor = await registry.verify({
    communityId: "core",
    certificateChain: inputFor(second)
  });
  assert.equal(wrongAnchor.valid, false);
  assert.equal(wrongAnchor.code, "INVALID_CERTIFICATE_PATH");

  const revokedLeaf = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl]
  });
  const revokedCrl = await createCrl(base.intermediate, [revokedLeaf]);
  const { registry: revokedRegistry } = makeRegistry(
    [
      {
        communityId: "core-revoked",
        chain: base,
        policy: {
          ...policyFor("core-revoked:policy"),
          rules: { requiredRuleNames: [rule.name] }
        },
        rules: [rule]
      }
    ],
    async (url) => {
      if (url === baseLeafCrlUrl) return revokedCrl;
      const response = crlByUrl.get(url);
      if (!response) throw new Error(`No CRL for ${url}`);
      return response;
    }
  );
  const revoked = await revokedRegistry.verify({
    communityId: "core-revoked",
    certificateChain: inputFor(base, revokedLeaf)
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
});
