import {
  createValidationProfileRegistry,
  type RequiredEvidence,
  type TrustRuleRegistration,
  type ValidationProfileInput
} from "../../src/index.ts";
import type { SyntheticCertificate } from "./synthetic-pki.ts";
import { createCrl, createSyntheticChain } from "./synthetic-pki.ts";

export const baseLeafCrlUrl = "http://base.test/leaf.crl";
export const baseIntermediateCrlUrl = "http://base.test/intermediate.crl";
export const secondLeafCrlUrl = "http://second.test/leaf.crl";
export const secondIntermediateCrlUrl = "http://second.test/intermediate.crl";
export const sameSan = "https://same.example.test/service";
export const checkDate = new Date("2026-10-15T00:00:00Z");

export const base = await createSyntheticChain({
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
export const second = await createSyntheticChain({
  intermediate: { crlUrls: [secondIntermediateCrlUrl] },
  leaf: {
    crlUrls: [secondLeafCrlUrl],
    uriSubjectAlternativeNames: [sameSan]
  }
});
export const baseLeafCrl = await createCrl(base.intermediate, []);
export const baseIntermediateCrl = await createCrl(base.root, []);
export const secondLeafCrl = await createCrl(second.intermediate, []);
export const secondIntermediateCrl = await createCrl(second.root, []);
export const crlByUrl = new Map<string, Uint8Array>([
  [baseLeafCrlUrl, baseLeafCrl],
  [baseIntermediateCrlUrl, baseIntermediateCrl],
  [secondLeafCrlUrl, secondLeafCrl],
  [secondIntermediateCrlUrl, secondIntermediateCrl]
]);

export function profileFor(
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

export function makeRegistry(
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

export function inputFor(
  chain: typeof base,
  leaf: SyntheticCertificate = chain.leaf
) {
  return [leaf.der, chain.intermediate.der];
}

export async function registryWithRule(
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
