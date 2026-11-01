// Defines the task and result messages exchanged with PKI worker threads.
import type { CrlValidationResult } from "../engine/crl.ts";
import type { OcspValidationResult } from "../engine/ocsp.ts";
import type { PreparedPathResult } from "../engine/pki-engine.ts";

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
