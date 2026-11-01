// Dispatches worker-thread PKI tasks to the inline engine.
import { inlinePkiEngine } from "../engine/pki-engine.ts";
import type { PkiWorkerResult, PkiWorkerTask } from "./pki-worker-protocol.ts";

export default async function runPkiTask(
  task: PkiWorkerTask
): Promise<PkiWorkerResult> {
  switch (task.op) {
    case "preparePath":
      return inlinePkiEngine.preparePath({
        certificateChain: task.certificateChain,
        trustAnchors: task.trustAnchors,
        checkDateMs: task.checkDateMs
      });
    case "validateCrl":
      return inlinePkiEngine.validateCrl({
        certificateDer: task.certificateDer,
        issuerDer: task.issuerDer,
        crl: task.crl,
        checkDateMs: task.checkDateMs
      });
    case "validateOcsp":
      return inlinePkiEngine.validateOcsp({
        certificateDer: task.certificateDer,
        issuerDer: task.issuerDer,
        response: task.response,
        checkDateMs: task.checkDateMs
      });
  }
}
