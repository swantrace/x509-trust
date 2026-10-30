import type { CrlValidationResult } from "./crl.ts";
import type { OcspValidationResult } from "./ocsp.ts";
import type { PreparedPathResult } from "./pki-engine.ts";

export type PkiWorkerTask =
  | {
      op: "preparePath";
      certificateChain: Uint8Array[];
      trustAnchors: Uint8Array[];
      checkDateMs: number;
    }
  | {
      op: "validateCrl";
      certificateDer: Uint8Array;
      issuerDer: Uint8Array;
      crl: Uint8Array;
      checkDateMs?: number;
    }
  | {
      op: "validateOcsp";
      certificateDer: Uint8Array;
      issuerDer: Uint8Array;
      response: Uint8Array;
      checkDateMs?: number;
    };

export type PkiWorkerResult =
  | PreparedPathResult
  | CrlValidationResult
  | OcspValidationResult;
