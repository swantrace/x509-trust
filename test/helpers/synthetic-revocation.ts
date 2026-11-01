import {
  Constructed,
  Enumerated,
  GeneralizedTime,
  Integer,
  OctetString,
  Primitive
} from "asn1js";
import {
  BasicOCSPResponse,
  CertID,
  CertificateRevocationList,
  id_PKIX_OCSP_Basic,
  OCSPResponse,
  ResponseBytes,
  ResponseData,
  RevokedCertificate,
  SingleResponse,
  Time
} from "pkijs";
import type { SyntheticCertificate } from "./synthetic-certificate.ts";
export async function createCrl(
  issuer: SyntheticCertificate,
  revoked: readonly SyntheticCertificate[],
  {
    thisUpdate = new Date("2026-10-01T00:00:00Z"),
    nextUpdate = new Date("2026-11-01T00:00:00Z")
  }: { thisUpdate?: Date; nextUpdate?: Date } = {}
): Promise<Uint8Array<ArrayBuffer>> {
  const crl = new CertificateRevocationList();
  crl.version = 1;
  crl.issuer = issuer.subject;
  crl.thisUpdate = new Time({ type: 0, value: thisUpdate });
  crl.nextUpdate = new Time({ type: 0, value: nextUpdate });
  crl.revokedCertificates = revoked.map(
    (entry) =>
      new RevokedCertificate({
        userCertificate: entry.certificate.serialNumber,
        revocationDate: new Time({ type: 0, value: thisUpdate })
      })
  );
  await crl.sign(issuer.privateKey, "SHA-256");
  return new Uint8Array(crl.toSchema(true).toBER(false));
}

export async function createCrlWithSerials(
  issuer: SyntheticCertificate,
  serials: readonly number[],
  {
    thisUpdate = new Date("2026-10-01T00:00:00Z"),
    nextUpdate = new Date("2026-11-01T00:00:00Z")
  }: { thisUpdate?: Date; nextUpdate?: Date } = {}
): Promise<Uint8Array<ArrayBuffer>> {
  const crl = new CertificateRevocationList();
  crl.version = 1;
  crl.issuer = issuer.subject;
  crl.thisUpdate = new Time({ type: 0, value: thisUpdate });
  crl.nextUpdate = new Time({ type: 0, value: nextUpdate });
  crl.revokedCertificates = serials.map(
    (serial) =>
      new RevokedCertificate({
        userCertificate: new Integer({ value: serial }),
        revocationDate: new Time({ type: 0, value: thisUpdate })
      })
  );
  await crl.sign(issuer.privateKey, "SHA-256");
  return new Uint8Array(crl.toSchema(true).toBER(false));
}

export async function createOcspResponse(
  issuer: SyntheticCertificate,
  subject: SyntheticCertificate,
  status: "good" | "revoked" | "unknown",
  {
    thisUpdate = new Date("2026-10-01T00:00:00Z"),
    nextUpdate = new Date("2026-11-01T00:00:00Z"),
    revokedAt = thisUpdate
  }: {
    thisUpdate?: Date;
    nextUpdate?: Date;
    revokedAt?: Date;
  } = {}
): Promise<Uint8Array<ArrayBuffer>> {
  const certId = await CertID.create(subject.certificate, {
    issuerCertificate: issuer.certificate,
    hashAlgorithm: "SHA-1"
  });
  const certStatus =
    status === "good"
      ? new Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } })
      : status === "revoked"
        ? new Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value: [new GeneralizedTime({ valueDate: revokedAt })]
          })
        : new Primitive({
            idBlock: { tagClass: 3, tagNumber: 2 },
            lenBlock: { length: 1 }
          });
  const responseData = new ResponseData({
    responderID: issuer.subject,
    producedAt: thisUpdate,
    responses: [
      new SingleResponse({
        certID: certId,
        certStatus,
        thisUpdate,
        nextUpdate
      })
    ]
  });
  const basic = new BasicOCSPResponse({ tbsResponseData: responseData });
  await basic.sign(issuer.privateKey, "SHA-256");
  const outer = new OCSPResponse({
    responseStatus: new Enumerated({ value: 0 }),
    responseBytes: new ResponseBytes({
      responseType: id_PKIX_OCSP_Basic,
      response: new OctetString({ valueHex: basic.toSchema().toBER(false) })
    })
  });
  return new Uint8Array(outer.toSchema().toBER(false));
}
