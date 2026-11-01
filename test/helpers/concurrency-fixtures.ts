import { type ValidationProfileInput } from "../../src/index.ts";
import {
  createCrl,
  createOcspResponse,
  createSyntheticChain
} from "./synthetic-pki.ts";

export function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

export const checkDate = new Date("2026-10-15T00:00:00Z");
export const now = () => checkDate.getTime();
export const leafCrlOne = "http://crl.test/leaf-one.crl";
export const leafCrlTwo = "http://crl.test/leaf-two.crl";
export const intermediateCrlUrl = "http://crl.test/intermediate.crl";
export const leafOcspUrl = "http://ocsp.test/leaf";
export const intermediateOcspUrl = "http://ocsp.test/intermediate";

export const crlChain = await createSyntheticChain({
  intermediate: { crlUrls: [intermediateCrlUrl] },
  leaf: { crlUrls: [leafCrlOne, leafCrlTwo] }
});
export const ocspChain = await createSyntheticChain({
  intermediate: { ocspUrls: [intermediateOcspUrl] },
  leaf: { ocspUrls: [leafOcspUrl] }
});

export const leafGoodCrl = await createCrl(crlChain.intermediate, []);
export const intermediateGoodCrl = await createCrl(crlChain.root, []);
export const leafRevokedOcsp = await createOcspResponse(
  ocspChain.intermediate,
  ocspChain.leaf,
  "revoked"
);
export const intermediateRevokedOcsp = await createOcspResponse(
  ocspChain.root,
  ocspChain.intermediate,
  "revoked"
);
export const intermediateGoodOcsp = await createOcspResponse(
  ocspChain.root,
  ocspChain.intermediate,
  "good"
);

export function profile(
  sourceOrder: ("crl" | "ocsp")[]
): ValidationProfileInput {
  return {
    id: "concurrency:profile",
    version: 1,
    source: "concurrency test",
    anchorSetId: "concurrency:root",
    revocation: { requiredEvidence: "any", sourceOrder }
  };
}
