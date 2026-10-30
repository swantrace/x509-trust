import { createInlinePkiEngine } from "../engine/pki-engine.ts";
import type { PkiWorkerResult, PkiWorkerTask } from "./pki-worker-protocol.ts";

const engine = createInlinePkiEngine();

export default async function runPkiTask(
  task: PkiWorkerTask
): Promise<PkiWorkerResult> {
  switch (task.op) {
    case "preparePath":
      return engine.preparePath({
        certificateChain: task.certificateChain,
        trustAnchors: task.trustAnchors,
        checkDateMs: task.checkDateMs
      });
    case "validateCrl":
      return engine.validateCrl({
        certificateDer: task.certificateDer,
        issuerDer: task.issuerDer,
        crl: task.crl,
        checkDateMs: task.checkDateMs
      });
    case "validateOcsp":
      return engine.validateOcsp({
        certificateDer: task.certificateDer,
        issuerDer: task.issuerDer,
        response: task.response,
        checkDateMs: task.checkDateMs
      });
  }
}
