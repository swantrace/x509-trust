import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import {
  createValidationProfileRegistry,
  ProfileError,
  type RequiredEvidence,
  type TrustRuleContext,
  type TrustRuleRegistration,
  type ValidationProfileInput
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

function profileFor(
  id: string,
  {
    version = 1,
    rules,
    requiredEvidence = "crl"
  }: {
    version?: number;
    rules?: ValidationProfileInput["rules"];
    requiredEvidence?: RequiredEvidence;
  } = {}
): ValidationProfileInput {
  return {
    id,
    version,
    source: "synthetic registry profile",
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
    profileId?: string;
    chain: typeof base;
    profile?: ValidationProfileInput;
    rules?: readonly TrustRuleRegistration[];
  }>,
  loadCrl?: (url: string) => Promise<Uint8Array>
) {
  const calls = { crl: [] as string[] };
  const registry = createValidationProfileRegistry({
    now: () => checkDate.getTime(),
    ocspLoader: false,
    crlLoader: async ({ url }) => {
      if (loadCrl) return loadCrl(url);
      calls.crl.push(url);
      const response = crlByUrl.get(url);
      if (!response) throw new Error(`No CRL for ${url}`);
      return response;
    }
  });
  for (const registration of registrations) {
    const profile =
      registration.profile ??
      profileFor(`${registration.profileId ?? "default"}:profile`);
    registry.register({
      profile:
        registration.profileId === undefined
          ? profile
          : { ...profile, id: registration.profileId },
      trustAnchors: [registration.chain.root.der],
      rules: registration.rules
    });
  }
  return { registry, calls };
}

function inputFor(chain: typeof base, leaf: SyntheticCertificate = chain.leaf) {
  return [leaf.der, chain.intermediate.der];
}

async function registryWithRule(
  profileId: string,
  rule: TrustRuleRegistration,
  profileOverrides: Partial<ValidationProfileInput> = {}
) {
  const { registry } = makeRegistry([
    {
      profileId,
      chain: base,
      profile: {
        ...profileFor(`${profileId}:profile`),
        ...profileOverrides,
        rules: {
          ...profileOverrides.rules,
          requiredRuleNames: [rule.name]
        }
      },
      rules: [rule]
    }
  ]);
  return registry;
}

test("selects anchors per profile even when leaves share a SAN", async () => {
  const { registry } = makeRegistry([
    { profileId: "profile-a", chain: base },
    { profileId: "profile-b", chain: second }
  ]);
  const first = await registry.verify({
    profileId: "profile-a",
    certificateChain: inputFor(base)
  });
  const other = await registry.verify({
    profileId: "profile-b",
    certificateChain: inputFor(second)
  });
  assert.equal(first.valid, true);
  assert.equal(other.valid, true);
  assert.equal(first.valid && first.profileId, "profile-a");
  assert.equal(other.valid && other.profileId, "profile-b");
  assert.deepEqual(
    first.valid && first.leafCertificate.uriSubjectAlternativeNames,
    [sameSan]
  );
  assert.deepEqual(
    other.valid && other.leafCertificate.uriSubjectAlternativeNames,
    [sameSan]
  );

  const cross = await registry.verify({
    profileId: "profile-a",
    certificateChain: inputFor(second)
  });
  assert.equal(cross.valid, false);
  assert.equal(cross.code, "INVALID_CERTIFICATE_PATH");
});

test("unknown profiles and versions fail without any evidence I/O", async () => {
  const { registry, calls } = makeRegistry([
    { profileId: "known", chain: base }
  ]);
  const unknown = await registry.verify({
    profileId: "unknown",
    certificateChain: inputFor(base)
  });
  assert.equal(unknown.valid, false);
  assert.equal(unknown.code, "UNKNOWN_PROFILE");
  assert.equal(calls.crl.length, 0);

  const unknownVersion = await registry.verify({
    profileId: "known",
    profileVersion: 99,
    certificateChain: inputFor(base)
  });
  assert.equal(unknownVersion.valid, false);
  assert.equal(unknownVersion.code, "UNKNOWN_PROFILE_VERSION");
  assert.equal(calls.crl.length, 0);
});

test("rejects duplicate profile versions and does not partially register failures", async () => {
  const { registry } = makeRegistry([
    {
      profileId: "versions",
      chain: base,
      profile: profileFor("v1", { version: 1 })
    }
  ]);
  assert.throws(
    () =>
      registry.register({
        trustAnchors: [base.root.der],
        profile: { ...profileFor("v1-again", { version: 1 }), id: "versions" }
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      return true;
    }
  );

  assert.throws(
    () =>
      registry.register({
        trustAnchors: [base.root.der],
        profile: {
          ...profileFor("broken"),
          rules: { requiredRuleNames: ["missing-rule"] }
        }
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "UNSUPPORTED_PROFILE");
      return true;
    }
  );
  const broken = await registry.verify({
    profileId: "broken",
    certificateChain: inputFor(base)
  });
  assert.equal(broken.valid, false);
  assert.equal(broken.code, "UNKNOWN_PROFILE");
});

test("selects the latest profile version unless an exact version is requested", async () => {
  const { registry } = makeRegistry([
    {
      profileId: "versioned",
      chain: base,
      profile: profileFor("versioned:v1", { version: 1 })
    },
    {
      profileId: "versioned",
      chain: base,
      profile: profileFor("versioned:v2", {
        version: 2,
        rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
      })
    }
  ]);
  const latest = await registry.verify({
    profileId: "versioned",
    certificateChain: inputFor(base)
  });
  assert.equal(latest.valid, false);
  assert.equal(latest.code, "PROFILE_REJECTED");
  assert.equal(latest.profileVersion, 2);

  const pinned = await registry.verify({
    profileId: "versioned",
    profileVersion: 1,
    certificateChain: inputFor(base)
  });
  assert.equal(pinned.valid, true);
  assert.equal(pinned.valid && pinned.profileVersion, 1);
});

test("a version registered during a pending request does not affect that request", async () => {
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
        profileId: "pending",
        chain: base,
        profile: profileFor("pending:v1", { version: 1 })
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
    profileId: "pending",
    certificateChain: inputFor(base)
  });
  await startedSignal;
  registry.register({
    trustAnchors: [base.root.der],
    profile: {
      ...profileFor("pending:v2", {
        version: 2,
        rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
      }),
      id: "pending"
    }
  });
  release();
  const result = await pending;
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.profileVersion, 1);
});

test("registration snapshots resist later caller mutation", async () => {
  const anchor = Uint8Array.from(base.root.der);
  const profile = profileFor("mutable");
  const { registry } = makeRegistry([]);
  registry.register({
    trustAnchors: [anchor],
    profile: { ...profile, id: "mutable" }
  });
  anchor.fill(0);
  (profile.revocation as { sourceOrder: string[] }).sourceOrder = ["ocsp"];
  profile.id = "changed";
  const result = await registry.verify({
    profileId: "mutable",
    certificateChain: inputFor(base)
  });
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.profileId, "mutable");
});

test("built-in leaf KU, EKU, certificate policy OID and path depth rules run after core validation", async () => {
  const { registry } = makeRegistry([
    {
      profileId: "rules",
      chain: base,
      profile: profileFor("rules:profile", {
        rules: {
          leafKeyUsage: ["digitalSignature"],
          leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
          requiredCertificatePolicyOids: ["1.2.3.4"],
          maxPathDepth: 3
        }
      })
    }
  ]);
  const success = await registry.verify({
    profileId: "rules",
    certificateChain: inputFor(base)
  });
  assert.equal(success.valid, true);

  const wrongKeyUsage = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    keyUsageBits: [0x20]
  });
  const wrongUsage = await registry.verify({
    profileId: "rules",
    certificateChain: inputFor(base, wrongKeyUsage)
  });
  assert.equal(wrongUsage.valid, false);
  assert.equal(wrongUsage.code, "PROFILE_REJECTED");

  const noEku = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl]
  });
  const missingEku = await registry.verify({
    profileId: "rules",
    certificateChain: inputFor(base, noEku)
  });
  assert.equal(missingEku.valid, false);
  assert.equal(missingEku.code, "PROFILE_REJECTED");

  const leafWithoutPolicy = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    extendedKeyUsageOids: ["1.3.6.1.5.5.7.3.2"]
  });
  const { registry: profileRegistry } = makeRegistry([
    {
      profileId: "leaf-profile",
      chain: base,
      profile: profileFor("leaf-profile:profile", {
        rules: { requiredCertificatePolicyOids: ["2.9.9.9"] }
      })
    }
  ]);
  const intermediateOnly = await profileRegistry.verify({
    profileId: "leaf-profile",
    certificateChain: inputFor(base, leafWithoutPolicy)
  });
  assert.equal(intermediateOnly.valid, false);
  assert.equal(intermediateOnly.code, "PROFILE_REJECTED");

  const leafWithPolicy = await createLeafForChain(base, {
    crlUrls: [baseLeafCrlUrl],
    certificatePolicyOids: ["2.9.9.9"]
  });
  const leafPolicy = await profileRegistry.verify({
    profileId: "leaf-profile",
    certificateChain: inputFor(base, leafWithPolicy)
  });
  assert.equal(leafPolicy.valid, true);

  const { registry: depthRegistry } = makeRegistry([
    {
      profileId: "depth",
      chain: base,
      profile: profileFor("depth:profile", {
        rules: { maxPathDepth: 2 }
      })
    }
  ]);
  const tooDeep = await depthRegistry.verify({
    profileId: "depth",
    certificateChain: inputFor(base)
  });
  assert.equal(tooDeep.valid, false);
  assert.equal(tooDeep.code, "PROFILE_REJECTED");
});

test("registered custom rules receive trusted facts and fail closed", async () => {
  let observed: TrustRuleContext | undefined;
  const capture = await registryWithRule("custom-ok", {
    name: "capture",
    check(context) {
      observed = context;
      return { ok: true };
    }
  });
  const success = await capture.verify({
    profileId: "custom-ok",
    certificateChain: inputFor(base)
  });
  assert.equal(success.valid, true);
  assert.equal(observed?.profileId, "custom-ok");
  assert.equal(observed?.certificatePath.length, 3);
  assert.deepEqual(observed?.leaf.uriSubjectAlternativeNames, [sameSan]);
  assert.equal(
    observed?.leaf.fingerprint256,
    new X509Certificate(base.leaf.der).fingerprint256
  );

  const denied = await registryWithRule("custom-deny", {
    name: "deny",
    check: () => ({ ok: false, message: "denied by registered rule" })
  });
  const deniedResult = await denied.verify({
    profileId: "custom-deny",
    certificateChain: inputFor(base)
  });
  assert.equal(deniedResult.valid, false);
  assert.equal(deniedResult.code, "PROFILE_REJECTED");
  assert.equal(
    deniedResult.valid === false && deniedResult.message,
    "denied by registered rule"
  );

  const unrecognized = await registryWithRule("custom-bad", {
    name: "bad",
    check: (() => ({ valid: true })) as never
  });
  const badResult = await unrecognized.verify({
    profileId: "custom-bad",
    certificateChain: inputFor(base)
  });
  assert.equal(badResult.valid, false);
  assert.equal(badResult.code, "PROFILE_REJECTED");

  const throwing = await registryWithRule("custom-throw", {
    name: "throw",
    check: () => {
      throw new Error("rule failure");
    }
  });
  const throwResult = await throwing.verify({
    profileId: "custom-throw",
    certificateChain: inputFor(base)
  });
  assert.equal(throwResult.valid, false);
  assert.equal(throwResult.code, "PROFILE_REJECTED");
});

test("rules cannot override core path or revocation failures", async () => {
  const rule: TrustRuleRegistration = {
    name: "always-ok",
    check: () => ({ ok: true })
  };
  const { registry } = makeRegistry([
    {
      profileId: "core",
      chain: base,
      profile: {
        ...profileFor("core:profile"),
        rules: { requiredRuleNames: [rule.name] }
      },
      rules: [rule]
    }
  ]);
  const wrongAnchor = await registry.verify({
    profileId: "core",
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
        profileId: "core-revoked",
        chain: base,
        profile: {
          ...profileFor("core-revoked:profile"),
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
    profileId: "core-revoked",
    certificateChain: inputFor(base, revokedLeaf)
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.code, "CERTIFICATE_REVOKED");
});

test("selects string profile versions using explicit versionOrder", async () => {
  const v1 = {
    id: "versions:string:v1",
    version: "2025-01",
    versionOrder: 10,
    source: { uri: "https://profile.example/profile/2025-01" },
    anchorSetId: "synthetic:root",
    revocation: {
      requiredEvidence: "crl" as const,
      sourceOrder: ["crl"] as const
    }
  };
  const v2 = {
    id: "versions:string:v2",
    version: "2026-01",
    versionOrder: 20,
    source: { uri: "https://profile.example/profile/2026-01" },
    anchorSetId: "synthetic:root",
    revocation: {
      requiredEvidence: "crl" as const,
      sourceOrder: ["crl"] as const
    },
    rules: { leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.9"] }
  };
  const { registry } = makeRegistry([
    { profileId: "string-versions", chain: base, profile: v1 },
    { profileId: "string-versions", chain: base, profile: v2 }
  ]);
  const latest = await registry.verify({
    profileId: "string-versions",
    certificateChain: inputFor(base)
  });
  assert.equal(latest.valid, false);
  assert.equal(latest.code, "PROFILE_REJECTED");
  assert.equal(latest.profileVersion, "2026-01");

  const pinned = await registry.verify({
    profileId: "string-versions",
    profileVersion: "2025-01",
    certificateChain: inputFor(base)
  });
  assert.equal(pinned.valid, true);
  assert.equal(pinned.valid && pinned.profileVersion, "2025-01");

  assert.throws(
    () =>
      registry.register({
        profileId: "string-versions",
        trustAnchors: [base.root.der],
        profile: { ...v1, version: "2025-02", versionOrder: 10 }
      }),
    (error: unknown) => {
      assert.ok(error instanceof ProfileError);
      assert.equal(error.code, "INVALID_PROFILE");
      return true;
    }
  );
  const missing = await registry.verify({
    profileId: "string-versions",
    profileVersion: "2024-01",
    certificateChain: inputFor(base)
  });
  assert.equal(missing.valid, false);
  assert.equal(missing.code, "UNKNOWN_PROFILE_VERSION");
});
