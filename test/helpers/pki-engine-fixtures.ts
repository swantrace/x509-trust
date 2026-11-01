import { Certificate } from "pkijs";
import { inlinePkiEngine } from "../../src/engine/pki-engine.ts";
import { fixtureTime, readCertificateDer } from "./fixtures.ts";

export function mutate(
  name: string,
  change: (certificate: Certificate) => void
): Uint8Array {
  const certificate = Certificate.fromBER(readCertificateDer(name));
  change(certificate);
  return new Uint8Array(certificate.toSchema(true).toBER(false));
}

export const rootDer = readCertificateDer("root");
export const intermediateDer = readCertificateDer("intermediate");
export const leafDer = readCertificateDer("leaf");
export const checkDateMs = fixtureTime;
export const engine = inlinePkiEngine;

export async function prepare(
  certificateChain: Uint8Array[],
  trustAnchors: Uint8Array[] = [rootDer]
) {
  return engine.preparePath({ certificateChain, trustAnchors, checkDateMs });
}
