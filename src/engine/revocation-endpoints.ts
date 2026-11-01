// Extracts CRL and OCSP URLs from certificate extensions.
import {
  type Certificate,
  CRLDistributionPoints,
  InfoAccess,
  id_AuthorityInfoAccess,
  id_ad_ocsp,
  id_CRLDistributionPoints
} from "pkijs";

const URI_GENERAL_NAME = 6;

export function getRevocationEndpoints(certificate: Certificate): {
  crlUrls: string[];
  ocspUrls: string[];
} {
  const crlUrls: string[] = [];
  const ocspUrls: string[] = [];

  for (const extension of certificate.extensions ?? []) {
    if (extension.extnID === id_CRLDistributionPoints) {
      const points = extension.parsedValue;
      if (
        !(points instanceof CRLDistributionPoints) ||
        "parsingError" in points
      ) {
        throw new TypeError("Invalid CRL distribution points extension");
      }

      for (const point of points.distributionPoints) {
        if (!Array.isArray(point.distributionPoint)) continue;
        for (const name of point.distributionPoint) {
          if (
            name.type === URI_GENERAL_NAME &&
            typeof name.value === "string"
          ) {
            crlUrls.push(name.value);
          }
        }
      }
    }

    if (extension.extnID === id_AuthorityInfoAccess) {
      const access = extension.parsedValue;
      if (!(access instanceof InfoAccess) || "parsingError" in access) {
        throw new TypeError("Invalid authority information access extension");
      }

      for (const {
        accessMethod,
        accessLocation
      } of access.accessDescriptions) {
        if (
          accessMethod === id_ad_ocsp &&
          accessLocation.type === URI_GENERAL_NAME &&
          typeof accessLocation.value === "string"
        ) {
          ocspUrls.push(accessLocation.value);
        }
      }
    }
  }

  return { crlUrls, ocspUrls };
}
