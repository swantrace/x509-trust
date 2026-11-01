// Converts revocation attempts into authenticated summaries and per-certificate progress findings.
import type { CrlValidationResult } from "../engine/crl.ts";
import type { OcspValidationResult } from "../engine/ocsp.ts";
import type {
  CertificateFindings,
  RevocationAttempt,
  RevocationFinding,
  RevocationSummary
} from "./revocation.ts";
export function recordResult(
  attempt: RevocationAttempt,
  result: CrlValidationResult | OcspValidationResult
): RevocationSummary | undefined {
  attempt.status = result.status;
  attempt.code = result.status === "unknown" ? result.code : undefined;
  if (result.status === "unknown") {
    attempt.message = result.message;
    return undefined;
  }
  const summary: RevocationSummary = {
    certificateIndex: attempt.certificateIndex,
    mechanism: attempt.mechanism,
    status: result.status,
    authenticated: true,
    fresh: true,
    thisUpdateMs: result.thisUpdate.getTime(),
    nextUpdateMs: result.nextUpdate.getTime(),
    checkedAtMs: result.checkedAt.getTime()
  };
  attempt.evidence = summary;
  attempt.message =
    result.status === "revoked"
      ? "Authenticated evidence reports revocation"
      : "Authenticated evidence reports good status";
  return summary;
}

function findingFor(attempt: RevocationAttempt): RevocationFinding {
  return {
    certificateIndex: attempt.certificateIndex,
    mechanism: attempt.mechanism,
    status: attempt.status,
    authenticated:
      attempt.status !== "unknown" && attempt.evidence?.authenticated === true,
    fresh: attempt.status !== "unknown" && attempt.evidence?.fresh === true,
    ...(attempt.code === undefined ? {} : { code: attempt.code }),
    message: attempt.message,
    source: attempt.source,
    durationMs: attempt.durationMs,
    ...(attempt.evidence
      ? {
          thisUpdateMs: attempt.evidence.thisUpdateMs,
          nextUpdateMs: attempt.evidence.nextUpdateMs,
          checkedAtMs: attempt.evidence.checkedAtMs
        }
      : {})
  };
}

export function findingsFor(
  certificateIndex: number,
  attempts: RevocationAttempt[]
): CertificateFindings {
  const findings = attempts.map(findingFor);
  return {
    certificateIndex,
    pathValid: true,
    revocation: {
      crl: findings.filter((finding) => finding.mechanism === "crl"),
      ocsp: findings.filter((finding) => finding.mechanism === "ocsp")
    }
  };
}

export function markDeadlineExceeded(
  findings: CertificateFindings[]
): CertificateFindings[] {
  const interrupted = (finding: RevocationFinding): RevocationFinding =>
    finding.code === "EVIDENCE_PENDING" || finding.code === "EVIDENCE_ABORTED"
      ? {
          ...finding,
          code: "EVIDENCE_DEADLINE_EXCEEDED",
          message: "The evidence deadline expired before this attempt completed"
        }
      : finding;
  return findings.map((entry) => ({
    ...entry,
    revocation: {
      crl: entry.revocation.crl.map(interrupted),
      ocsp: entry.revocation.ocsp.map(interrupted)
    }
  }));
}
