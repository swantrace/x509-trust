// Defines PKI engine contracts and prepared certificate-path data.
import type { CertificateInput } from "./certificate-path.ts";
import type { validateCrl } from "./crl.ts";
import type {
  CertificateFacts,
  ValidatedLeafCertificate
} from "./leaf-certificate.ts";
import type { validateOcsp } from "./ocsp.ts";
export interface PreparedCertificate {
  index: number;
  der: Uint8Array;
  issuerDer?: Uint8Array;
  crlUrls: string[];
  ocspUrls: string[];
  ocspRequestDer?: Uint8Array;
  facts: CertificateFacts;
}

export type PreparedPathResult =
  | {
      pathValid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      certificates: PreparedCertificate[];
      leafCertificate: ValidatedLeafCertificate;
    }
  | {
      pathValid: false;
      code: "INVALID_CERTIFICATE" | "INVALID_CERTIFICATE_PATH";
      message: string;
    };

export interface PkiEngine {
  preparePath(options: {
    certificateChain: readonly CertificateInput[];
    trustAnchors: readonly Uint8Array[];
    checkDateMs: number;
    signal?: AbortSignal;
  }): Promise<PreparedPathResult>;
  validateCrl: typeof validateCrl;
  validateOcsp: typeof validateOcsp;
}
