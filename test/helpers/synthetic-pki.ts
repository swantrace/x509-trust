import {
  type CertificateOptions,
  type CreateChainOptions,
  createCertificate,
  generateKeys,
  type SyntheticCertificate,
  type SyntheticChain
} from "./synthetic-certificate.ts";

export type {
  CertificateOptions,
  CreateChainOptions,
  SyntheticCertificate,
  SyntheticChain
} from "./synthetic-certificate.ts";
export {
  createCrl,
  createCrlWithSerials,
  createOcspResponse
} from "./synthetic-revocation.ts";
export async function createSyntheticChain({
  intermediate: intermediateOptions = {},
  leaf: leafOptions = {}
}: CreateChainOptions = {}): Promise<SyntheticChain> {
  const rootKeys = await generateKeys();
  const root = await createCertificate(
    { commonName: "Synthetic Root", ca: true },
    rootKeys
  );
  const intermediateKeys = await generateKeys();
  const intermediate = await createCertificate(
    {
      commonName: "Synthetic Intermediate",
      ca: true,
      pathLenConstraint: 0,
      ...intermediateOptions
    },
    intermediateKeys,
    root
  );
  const leafKeys = await generateKeys();
  const leafCertificate = await createCertificate(
    {
      commonName: "Synthetic Leaf",
      ...leafOptions
    },
    leafKeys,
    intermediate
  );
  return { root, intermediate, leaf: leafCertificate };
}

export async function createIntermediateForChain(
  parent: SyntheticCertificate,
  options: Partial<CertificateOptions> = {}
): Promise<SyntheticCertificate> {
  const keys = await generateKeys();
  return createCertificate(
    {
      commonName: "Synthetic Intermediate",
      ca: true,
      pathLenConstraint: 0,
      ...options
    },
    keys,
    parent
  );
}

export async function createLeafForChain(
  chain: Pick<SyntheticChain, "root" | "intermediate">,
  options: Partial<CertificateOptions> = {}
): Promise<SyntheticCertificate> {
  const keys = await generateKeys();
  return createCertificate(
    { commonName: "Synthetic Leaf", ...options },
    keys,
    chain.intermediate
  );
}
