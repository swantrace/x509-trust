import {
  createTrustValidator,
  type RequiredEvidence,
  type RevocationMechanism,
  type ValidationProfileInput
} from "../../src/index.ts";
import {
  createCrl,
  createOcspResponse,
  createSyntheticChain
} from "./synthetic-pki.ts";

export const leafCrl = ["http://leaf.test/one.crl", "http://leaf.test/two.crl"];
export const leafOcsp = "http://leaf.test/ocsp";
export const intermediateCrl = "http://intermediate.test/root.crl";
export const intermediateOcsp = "http://intermediate.test/ocsp";
export const checkDate = new Date("2026-10-15T00:00:00Z");
export const now = () => checkDate.getTime();

export const chain = await createSyntheticChain({
  intermediate: {
    crlUrls: [intermediateCrl],
    ocspUrls: [intermediateOcsp]
  },
  leaf: {
    crlUrls: leafCrl,
    ocspUrls: [leafOcsp]
  }
});
export const leafGoodCrl = await createCrl(chain.intermediate, []);
export const intermediateGoodCrl = await createCrl(chain.root, []);
export const leafGoodOcsp = await createOcspResponse(
  chain.intermediate,
  chain.leaf,
  "good"
);
export const intermediateGoodOcsp = await createOcspResponse(
  chain.root,
  chain.intermediate,
  "good"
);
export const leafRevokedOcsp = await createOcspResponse(
  chain.intermediate,
  chain.leaf,
  "revoked"
);
export const intermediateRevokedOcsp = await createOcspResponse(
  chain.root,
  chain.intermediate,
  "revoked"
);
export const chainInput = [chain.leaf.der, chain.intermediate.der];

export function profile(
  requiredEvidence: RequiredEvidence,
  sourceOrder: RevocationMechanism[]
): ValidationProfileInput {
  return {
    id: `test:${requiredEvidence}`,
    version: 1,
    source: "synthetic profile",
    anchorSetId: "synthetic:root",
    revocation: { requiredEvidence, sourceOrder }
  };
}

export function validators({
  requiredEvidence,
  sourceOrder,
  crlResponses,
  ocspResponses,
  crlLoader = true,
  ocspLoader = true,
  calls
}: {
  requiredEvidence: RequiredEvidence;
  sourceOrder: RevocationMechanism[];
  crlResponses: Record<string, Uint8Array>;
  ocspResponses: Record<string, Uint8Array>;
  crlLoader?: boolean;
  ocspLoader?: boolean;
  calls: { crl: string[]; ocsp: string[] };
}) {
  return createTrustValidator({
    trustAnchors: [chain.root.der],
    profile: profile(requiredEvidence, sourceOrder),
    now,
    crlLoader:
      crlLoader === false
        ? false
        : async ({ url }) => {
            calls.crl.push(url);
            const response = crlResponses[url];
            if (!response) throw new Error(`No CRL for ${url}`);
            return response;
          },
    ocspLoader:
      ocspLoader === false
        ? false
        : async ({ url }) => {
            calls.ocsp.push(url);
            const response = ocspResponses[url];
            if (!response) throw new Error(`No OCSP response for ${url}`);
            return response;
          }
  });
}

export const goodCrls = {
  [leafCrl[0]]: leafGoodCrl,
  [leafCrl[1]]: leafGoodCrl,
  [intermediateCrl]: intermediateGoodCrl
};
export const goodOcsps = {
  [leafOcsp]: leafGoodOcsp,
  [intermediateOcsp]: intermediateGoodOcsp
};
