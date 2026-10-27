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
  status?: "good" | "revoked" | "unknown";
  message: string;
}

export type DiagnosticCallback = (
  event: DiagnosticEvent
) => void | Promise<void>;

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
