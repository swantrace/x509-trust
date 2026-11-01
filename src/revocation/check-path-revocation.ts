// Coordinates concurrent revocation checks with cancellation, deadlines, and early revoked results.
import type { PreparedCertificate } from "../engine/pki-engine.ts";
import { abortError, ResourceLimitError } from "../errors.ts";
import type { ValidationResult } from "../validation-types.ts";
import type {
  CertificateFindings,
  CertificateRevocation,
  RevocationSummary
} from "./revocation.ts";
import type { CertificateRevocationChecker } from "./revocation-checker.ts";
import { markDeadlineExceeded } from "./revocation-findings.ts";

type RevocationCheckResult =
  | {
      valid: true;
      evidence: RevocationSummary[];
      findings: CertificateFindings[];
    }
  | Extract<ValidationResult, { valid: false }>;

type RevokedCertificate = {
  certificateIndex: number;
  evidence: RevocationSummary;
  findings: CertificateFindings;
};

type PipelineResult =
  | { index: number; result: CertificateRevocation }
  | { index: number; error: unknown };

export async function checkPathRevocation({
  certificates,
  checkRevocation,
  checkDateMs,
  signal,
  deadlineMs
}: {
  certificates: PreparedCertificate[];
  checkRevocation: CertificateRevocationChecker;
  checkDateMs?: number;
  signal?: AbortSignal;
  deadlineMs: number;
}): Promise<RevocationCheckResult> {
  if (signal?.aborted) throw abortError();
  const controller = new AbortController();
  const progress = new Map<number, CertificateFindings>();
  let collecting = true;
  const aborted = Promise.withResolvers<void>();
  const revoked = Promise.withResolvers<RevokedCertificate>();
  const deadline = Promise.withResolvers<void>();
  const onAbort = () => {
    controller.abort();
    aborted.resolve();
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  const deadlineTimer = setTimeout(() => {
    controller.abort();
    deadline.resolve();
  }, deadlineMs);
  deadlineTimer.unref();

  try {
    // Start certificate checks together; each follows the profile source order.
    const allCompleted = Promise.all(
      certificates.map(async (prepared, index) => {
        try {
          const result = await checkRevocation({
            prepared,
            certificateIndex: index,
            checkDateMs,
            signal: controller.signal,
            onProgress(findings) {
              if (collecting) progress.set(index, findings);
            }
          });
          if (result.status === "revoked") {
            revoked.resolve({
              certificateIndex: index,
              evidence: result.evidence,
              findings: result.findings
            });
          }
          return { index, result } satisfies PipelineResult;
        } catch (error) {
          return { index, error } satisfies PipelineResult;
        }
      })
    );

    const outcome = await Promise.race([
      allCompleted.then((results) => ({ kind: "completed" as const, results })),
      revoked.promise.then((value) => ({ kind: "revoked" as const, value })),
      aborted.promise.then(() => ({ kind: "aborted" as const })),
      deadline.promise.then(() => ({ kind: "deadline" as const }))
    ]);
    collecting = false;
    const partialFindings = [...progress.values()].sort(
      (a, b) => a.certificateIndex - b.certificateIndex
    );
    switch (outcome.kind) {
      case "aborted":
        controller.abort();
        throw abortError();
      case "deadline":
        controller.abort();
        return {
          valid: false,
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "The verification deadline was exceeded",
          findings: markDeadlineExceeded(partialFindings)
        };
      case "revoked":
        controller.abort();
        return {
          valid: false,
          code: "CERTIFICATE_REVOKED",
          message: "Certificate has been revoked",
          certificateIndex: outcome.value.certificateIndex,
          evidence: [outcome.value.evidence],
          findings: [outcome.value.findings]
        };
      case "completed":
        break;
    }
    if (signal?.aborted) throw abortError();

    const evidence: RevocationSummary[] = [];
    const findings: CertificateFindings[] = [];
    for (const entry of outcome.results) {
      if ("error" in entry) {
        const resourceError =
          entry.error instanceof ResourceLimitError ? entry.error : undefined;
        return {
          valid: false,
          code: resourceError
            ? "RESOURCE_LIMIT_EXCEEDED"
            : "REVOCATION_STATUS_UNKNOWN",
          message: resourceError?.message ?? "Revocation validation failed",
          certificateIndex: entry.index,
          findings: partialFindings
        };
      }
      if (entry.result.status === "unknown") {
        return {
          valid: false,
          code: "REVOCATION_STATUS_UNKNOWN",
          message: entry.result.message,
          certificateIndex: entry.index,
          findings: partialFindings
        };
      }
      if (entry.result.status !== "good") continue;
      evidence.push(...entry.result.evidence);
      findings.push(entry.result.findings);
    }
    return { valid: true, evidence, findings };
  } finally {
    collecting = false;
    signal?.removeEventListener("abort", onAbort);
    clearTimeout(deadlineTimer);
  }
}
