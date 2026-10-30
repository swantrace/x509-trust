import type {
  RequiredEvidence,
  RevocationMechanism
} from "../policy/policy.ts";

export interface EvidenceSummary {
  certificateIndex: number;
  mechanism: RevocationMechanism;
  status: "good" | "revoked";
  authenticated: true;
  fresh: true;
  thisUpdateMs: number;
  nextUpdateMs: number;
  checkedAtMs: number;
}

export interface EvidenceAttempt {
  certificateIndex: number;
  mechanism: RevocationMechanism;
  status: "good" | "revoked" | "unknown";
  evidence?: EvidenceSummary;
  code?: string;
  message: string;
}

export interface EvidenceFinding {
  certificateIndex: number;
  mechanism: RevocationMechanism;
  status: "good" | "revoked" | "unknown";
  authenticated: boolean;
  fresh: boolean;
  code?: string;
  message: string;
  thisUpdateMs?: number;
  nextUpdateMs?: number;
  checkedAtMs?: number;
}

export interface CertificateFindings {
  certificateIndex: number;
  pathValid: true;
  revocation: {
    crl: EvidenceFinding[];
    ocsp: EvidenceFinding[];
  };
}

export type EvidenceDecision =
  | { status: "good"; evidence: EvidenceSummary[] }
  | { status: "revoked"; evidence: EvidenceSummary }
  | { status: "unknown"; message: string };

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

export function decideRevocationEvidence(
  requiredEvidence: RequiredEvidence,
  attempts: readonly EvidenceAttempt[]
): EvidenceDecision {
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
    const evidence: EvidenceSummary[] = [];
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
    message:
      lastUnknown?.message ??
      "No usable revocation evidence established certificate status"
  };
}
