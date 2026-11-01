import { BitString } from "asn1js";
import {
  AccessDescription,
  AltName,
  BasicConstraints,
  CertificatePolicies,
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
  id_SubjectAltName,
  PolicyInformation
} from "pkijs";
import type { CertificateOptions } from "./synthetic-certificate.ts";

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

export function createCertificateExtensions(
  options: CertificateOptions
): Extension[] {
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
  return extensions;
}
