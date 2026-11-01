import { fixtureTime, readCertificate, readCrl } from "./fixtures.ts";

export async function loadCrl(url: string): Promise<Uint8Array> {
  return url.endsWith("/root.crl")
    ? readCrl("root")
    : readCrl("intermediate-revoked");
}

export const root = readCertificate("root");
export const intermediate = readCertificate("intermediate");
export const leaf = readCertificate("leaf");
export const revokedLeaf = readCertificate("revoked-leaf");
export const checkDate = new Date(fixtureTime);
export const now = () => checkDate.getTime();
