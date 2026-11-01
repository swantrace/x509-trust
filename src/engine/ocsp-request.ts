// Encodes an OCSP request for a certificate and its validated issuer.
import { type Certificate, OCSPRequest } from "pkijs";

const OCSP_CERT_ID_HASH = "SHA-1";
export async function createOcspRequest(
  certificate: Certificate,
  issuerCertificate: Certificate
): Promise<Uint8Array> {
  const request = new OCSPRequest();
  await request.createForCertificate(certificate, {
    issuerCertificate,
    hashAlgorithm: OCSP_CERT_ID_HASH
  });
  return new Uint8Array(request.toSchema(true).toBER(false));
}
