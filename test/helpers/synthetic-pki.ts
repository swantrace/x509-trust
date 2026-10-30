import { webcrypto } from "node:crypto";
import {
  BitString,
  Constructed,
  Enumerated,
  GeneralizedTime,
  Integer,
  OctetString,
  Primitive,
  Utf8String
} from "asn1js";
import {
  AccessDescription,
  AltName,
  AttributeTypeAndValue,
  BasicConstraints,
  BasicOCSPResponse,
  CertID,
  Certificate,
  CertificatePolicies,
  CertificateRevocationList,
  CRLDistributionPoints,
  DistributionPoint,
  Extension,
  ExtKeyUsage,
  GeneralName,
  InfoAccess,
  id_ad_ocsp,
  id_BasicConstraints,
  id_CertificatePolicies,
  id_CRLDistributionPoints,
  id_ExtKeyUsage,
  id_KeyUsage,
  id_PKIX_OCSP_Basic,
  id_SubjectAltName,
  OCSPResponse,
  PolicyInformation,
  RelativeDistinguishedNames,
  ResponseBytes,
  ResponseData,
  RevokedCertificate,
  SingleResponse,
  Time
} from "pkijs";

export interface SyntheticCertificate {
  certificate: Certificate;
  der: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
  subject: RelativeDistinguishedNames;
}

export interface SyntheticChain {
  root: SyntheticCertificate;
  intermediate: SyntheticCertificate;
  leaf: SyntheticCertificate;
}

export interface CertificateOptions {
  commonName: string;
  ca?: boolean;
  pathLenConstraint?: number;
  keyUsageBits?: number[];
  crlUrls?: string[];
  ocspUrls?: string[];
  uriSubjectAlternativeNames?: string[];
  extendedKeyUsageOids?: string[];
  certificatePolicyOids?: string[];
  notBefore?: Date;
  notAfter?: Date;
  serial?: number[];
}

export interface CreateChainOptions {
  intermediate?: Partial<CertificateOptions>;
  leaf?: Partial<CertificateOptions>;
}

let nextSerial = 1;

function distinguishedName(commonName: string): RelativeDistinguishedNames {
  return new RelativeDistinguishedNames({
    typesAndValues: [
      new AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new Utf8String({ value: commonName })
      })
    ]
  });
}

function extension(
  oid: string,
  value: { toSchema(): { toBER(flag?: boolean): ArrayBuffer } },
  critical = false
): Extension {
  return new Extension({
    extnID: oid,
    critical,
    extnValue: value.toSchema().toBER(false)
  });
}

function bitMask(value: number, byte: number): BitString {
  const bytes = new Uint8Array(byte + 1);
  bytes[byte] = value;
  return new BitString({ valueHex: bytes.buffer });
}

async function generateKeys(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
}

async function createCertificate(
  options: CertificateOptions,
  keys: CryptoKeyPair,
  issuer?: SyntheticCertificate
): Promise<SyntheticCertificate> {
  const subject = distinguishedName(options.commonName);
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new Integer({
    valueHex: new Uint8Array(options.serial ?? [nextSerial++]).buffer
  });
  certificate.issuer = issuer ? issuer.subject : subject;
  certificate.subject = subject;
  certificate.notBefore = new Time({
    type: 0,
    value: options.notBefore ?? new Date("2026-01-01T00:00:00Z")
  });
  certificate.notAfter = new Time({
    type: 0,
    value: options.notAfter ?? new Date("2030-01-01T00:00:00Z")
  });
  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);

  const extensions: Extension[] = [];
  const usage = options.keyUsageBits ?? (options.ca === true ? [0x06] : [0x80]);
  extensions.push(
    new Extension({
      extnID: id_KeyUsage,
      critical: true,
      extnValue: bitMask(usage[0], 0).toBER(false)
    })
  );
  if (options.ca === true) {
    extensions.push(
      extension(
        id_BasicConstraints,
        new BasicConstraints({
          cA: true,
          ...(options.pathLenConstraint === undefined
            ? {}
            : { pathLenConstraint: options.pathLenConstraint })
        }),
        true
      )
    );
  }
  if (options.crlUrls?.length) {
    extensions.push(
      extension(
        id_CRLDistributionPoints,
        new CRLDistributionPoints({
          distributionPoints: [
            new DistributionPoint({
              distributionPoint: options.crlUrls.map(
                (value) => new GeneralName({ type: 6, value })
              )
            })
          ]
        })
      )
    );
  }
  if (options.ocspUrls?.length) {
    extensions.push(
      extension(
        "1.3.6.1.5.5.7.1.1",
        new InfoAccess({
          accessDescriptions: options.ocspUrls.map(
            (url) =>
              new AccessDescription({
                accessMethod: id_ad_ocsp,
                accessLocation: new GeneralName({ type: 6, value: url })
              })
          )
        })
      )
    );
  }
  if (options.uriSubjectAlternativeNames?.length) {
    extensions.push(
      extension(
        id_SubjectAltName,
        new AltName({
          altNames: options.uriSubjectAlternativeNames.map(
            (value) => new GeneralName({ type: 6, value })
          )
        })
      )
    );
  }
  if (options.extendedKeyUsageOids?.length) {
    extensions.push(
      extension(
        id_ExtKeyUsage,
        new ExtKeyUsage({ keyPurposes: options.extendedKeyUsageOids })
      )
    );
  }
  if (options.certificatePolicyOids?.length) {
    extensions.push(
      extension(
        id_CertificatePolicies,
        new CertificatePolicies({
          certificatePolicies: options.certificatePolicyOids.map(
            (policyIdentifier) => new PolicyInformation({ policyIdentifier })
          )
        })
      )
    );
  }
  certificate.extensions = extensions;
  await certificate.sign(
    issuer ? issuer.privateKey : keys.privateKey,
    "SHA-256"
  );
  return {
    certificate,
    der: new Uint8Array(certificate.toSchema(true).toBER(false)),
    privateKey: keys.privateKey,
    subject
  };
}

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
