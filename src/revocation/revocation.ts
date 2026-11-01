// Defines revocation data types and decides status from the profile's evidence requirements.
import type {
  RequiredEvidence,
  RevocationMechanism
} from "../profile/profile.ts";

export interface SourceCheckOptions {
  mechanism: "crl" | "ocsp";
  certificateDer: Uint8Array;
  issuerDer: Uint8Array;
  source: string;
  signal?: AbortSignal;
  checkDateMs?: number;
  certificateIndex?: number;
  ocspRequestDer?: Uint8Array;
}

export interface RevocationSummary {
  certificateIndex: number;
  mechanism: RevocationMechanism;
  status: "good" | "revoked";
  authenticated: true;
  fresh: true;
  thisUpdateMs: number;
  nextUpdateMs: number;
  checkedAtMs: number;
}

export interface RevocationAttempt {
  certificateIndex: number;
  mechanism: RevocationMechanism;
  status: "good" | "revoked" | "unknown";
  evidence?: RevocationSummary;
  code?: string;
  message: string;
  source?: string;
  durationMs?: number;
}

export interface RevocationFinding {
  certificateIndex: number;
  mechanism: RevocationMechanism;
  status: "good" | "revoked" | "unknown";
  authenticated: boolean;
  fresh: boolean;
  code?: string;
  message: string;
  source?: string;
  durationMs?: number;
  thisUpdateMs?: number;
  nextUpdateMs?: number;
  checkedAtMs?: number;
}

export interface CertificateFindings {
  certificateIndex: number;
  pathValid: true;
  revocation: {
    crl: RevocationFinding[];
    ocsp: RevocationFinding[];
  };
}

export type RevocationDecision =
  | { status: "good"; evidence: RevocationSummary[] }
  | { status: "revoked"; evidence: RevocationSummary }
  | { status: "unknown"; message: string };

export type CertificateRevocation = RevocationDecision & {
  findings: CertificateFindings;
};

export function requiredMechanisms(
  requiredEvidence: RequiredEvidence
): readonly RevocationMechanism[] {
  switch (requiredEvidence) {
    case "any":
      return ["crl", "ocsp"];
    case "both":
      return ["crl", "ocsp"];
    default:
      return [requiredEvidence];
  }
}

export function decideRevocation(
  requiredEvidence: RequiredEvidence,
  attempts: readonly RevocationAttempt[],
  unavailableSourceMessage = "No usable revocation evidence established certificate status"
): RevocationDecision {
  const revoked = attempts.find(
    (attempt) =>
      attempt.status === "revoked" && attempt.evidence?.authenticated === true
  );
  if (revoked?.evidence) {
    return { status: "revoked", evidence: revoked.evidence };
  }

  const usableGood = (mechanism?: RevocationMechanism) =>
    attempts.find(
      (attempt) =>
        attempt.status === "good" &&
        attempt.evidence?.authenticated === true &&
        attempt.evidence.fresh === true &&
        (mechanism === undefined || attempt.mechanism === mechanism)
    )?.evidence;

  if (requiredEvidence === "any") {
    const good = usableGood();
    if (good) return { status: "good", evidence: [good] };
  } else if (requiredEvidence === "crl" || requiredEvidence === "ocsp") {
    const good = usableGood(requiredEvidence);
    if (good) return { status: "good", evidence: [good] };
  } else {
    const seen = new Set<RevocationMechanism>();
    const evidence: RevocationSummary[] = [];
    for (const attempt of attempts) {
      if (
        attempt.status !== "good" ||
        attempt.evidence?.authenticated !== true ||
        attempt.evidence.fresh !== true ||
        seen.has(attempt.mechanism)
      ) {
        continue;
      }
      seen.add(attempt.mechanism);
      evidence.push(attempt.evidence);
    }
    if (seen.has("crl") && seen.has("ocsp")) {
      return { status: "good", evidence };
    }
  }

  const lastUnknown = [...attempts]
    .reverse()
    .find((attempt) => attempt.status === "unknown");
  return {
    status: "unknown",
    message: lastUnknown?.message ?? unavailableSourceMessage
  };
}
