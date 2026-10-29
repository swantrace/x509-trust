import type { RevocationStatus } from "../native/index.js";

export interface DiagnosticEvent {
  event:
    | "cache_hit"
    | "cache_miss"
    | "cache_discarded"
    | "cache_error"
    | "revocation_result"
    | "revocation_error";
  mechanism: "crl" | "ocsp";
  certificateIndex?: number;
  code?: string;
  status?: `${RevocationStatus}`;
  message: string;
}

export type DiagnosticCallback = (
  event: DiagnosticEvent
) => void | Promise<void>;

export type RevocationReport = (
  event: Pick<DiagnosticEvent, "event" | "message" | "code" | "status">
) => void;

export function createDiagnosticReporter(onDiagnostic?: DiagnosticCallback) {
  return (event: DiagnosticEvent): void => {
    if (!onDiagnostic) return;
    try {
      Promise.resolve(onDiagnostic(event)).catch(() => {});
    } catch {
      // Diagnostics must not affect certificate validation.
    }
  };
}
