import type { CrlValidationResult } from "../engine/crl.ts";
import type { OcspValidationResult } from "../engine/ocsp.ts";
import type { PreparedCertificate } from "../engine/pki-engine.ts";
import { ResourceLimitError } from "../errors.ts";
import type { CompiledTrustPolicy } from "../policy/policy.ts";
import {
  type CertificateFindings,
  decideRevocationEvidence,
  type EvidenceAttempt,
  type EvidenceFinding,
  type EvidenceSummary,
  requiredMechanisms
} from "./evidence.ts";
import type { CrlLoadOptions, OcspLoadOptions } from "./http-loaders.ts";
import type { createRevocationChecker } from "./revocation-checker.ts";

type RevocationChecker = ReturnType<typeof createRevocationChecker>;
type CrlLoader = (url: string, options?: CrlLoadOptions) => Promise<Uint8Array>;
type OcspLoader = (options: OcspLoadOptions) => Promise<Uint8Array>;

export type CertificateRevocation =
  | {
      status: "good";
      evidence: EvidenceSummary[];
      findings: CertificateFindings;
    }
  | {
      status: "revoked";
      evidence: EvidenceSummary;
      findings: CertificateFindings;
    }
  | {
      status: "unknown";
      message: string;
      findings: CertificateFindings;
    };

interface EvidenceCollectorOptions {
  policy: CompiledTrustPolicy;
  checker: RevocationChecker;
  prepared: PreparedCertificate;
  certificateIndex: number;
  checkDateMs?: number;
  signal?: AbortSignal;
  crlLoader?: CrlLoader;
  ocspLoader?: OcspLoader;
}

function summaryFor(
  certificateIndex: number,
  mechanism: "crl" | "ocsp",
  result: { thisUpdate: Date; nextUpdate: Date; checkedAt: Date }
): EvidenceSummary {
  return {
    certificateIndex,
    mechanism,
    status: "good",
    authenticated: true,
    fresh: true,
    thisUpdateMs: result.thisUpdate.getTime(),
    nextUpdateMs: result.nextUpdate.getTime(),
    checkedAtMs: result.checkedAt.getTime()
  };
}

function acceptedEvidence(
  policy: CompiledTrustPolicy,
  goodByMechanism: Map<"crl" | "ocsp", EvidenceSummary>,
  single?: EvidenceSummary
): EvidenceSummary[] {
  if (single) return [single];
  const required = requiredMechanisms(policy.revocation.requiredEvidence);
  return policy.revocation.sourceOrder
    .filter(
      (mechanism) =>
        required.includes(mechanism) && goodByMechanism.has(mechanism)
    )
    .map((mechanism) => goodByMechanism.get(mechanism)!);
}

function recordResult(
  attempts: EvidenceAttempt[],
  certificateIndex: number,
  mechanism: "crl" | "ocsp",
  result: CrlValidationResult | OcspValidationResult
): EvidenceSummary | undefined {
  if (result.status === "unknown") {
    attempts.push({
      certificateIndex,
      mechanism,
      status: "unknown",
      code: result.code,
      message: result.message
    });
    return undefined;
  }
  const summary: EvidenceSummary = {
    ...summaryFor(certificateIndex, mechanism, result),
    status: result.status
  };
  attempts.push({
    certificateIndex,
    mechanism,
    status: result.status,
    evidence: summary,
    message:
      result.status === "revoked"
        ? "Authenticated evidence reports revocation"
        : "Authenticated evidence reports good status"
  });
  return summary;
}

function findingFor(attempt: EvidenceAttempt): EvidenceFinding {
  return {
    certificateIndex: attempt.certificateIndex,
    mechanism: attempt.mechanism,
    status: attempt.status,
    authenticated:
      attempt.status !== "unknown" && attempt.evidence?.authenticated === true,
    fresh: attempt.status !== "unknown" && attempt.evidence?.fresh === true,
    ...(attempt.code === undefined ? {} : { code: attempt.code }),
    message: attempt.message,
    ...(attempt.evidence
      ? {
          thisUpdateMs: attempt.evidence.thisUpdateMs,
          nextUpdateMs: attempt.evidence.nextUpdateMs,
          checkedAtMs: attempt.evidence.checkedAtMs
        }
      : {})
  };
}

function findingsFor(
  certificateIndex: number,
  attempts: EvidenceAttempt[]
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

export async function collectCertificateEvidence({
  policy,
  checker,
  prepared,
  certificateIndex,
  checkDateMs,
  signal,
  crlLoader,
  ocspLoader
}: EvidenceCollectorOptions): Promise<CertificateRevocation> {
  const attempts: EvidenceAttempt[] = [];
  const goodByMechanism = new Map<"crl" | "ocsp", EvidenceSummary>();
  const required = requiredMechanisms(policy.revocation.requiredEvidence);
  let message =
    "No usable CRL or OCSP source is configured for this certificate";

  for (const mechanism of policy.revocation.sourceOrder) {
    signal?.throwIfAborted();
    const urls = mechanism === "crl" ? prepared.crlUrls : prepared.ocspUrls;
    const loader = mechanism === "crl" ? crlLoader : ocspLoader;
    if (!loader) continue;
    if (urls.length === 0) {
      message = `No ${mechanism.toUpperCase()} source is advertised for this certificate`;
      continue;
    }

    for (const url of urls) {
      try {
        const result =
          mechanism === "crl"
            ? await checker.checkCrl({
                certificateDer: prepared.der,
                issuerDer: prepared.issuerDer!,
                source: url,
                certificateIndex,
                checkDateMs,
                signal,
                load: (loadSignal) =>
                  (loader as CrlLoader)(url, {
                    signal: loadSignal,
                    issuerCertificate: prepared.issuerDer!
                  })
              })
            : await checker.checkOcsp({
                certificateDer: prepared.der,
                issuerDer: prepared.issuerDer!,
                source: url,
                certificateIndex,
                checkDateMs,
                signal,
                ocspRequestDer: prepared.ocspRequestDer!,
                load: (loadSignal) =>
                  (loader as OcspLoader)({
                    url,
                    certificate: Uint8Array.from(prepared.der),
                    issuerCertificate: Uint8Array.from(prepared.issuerDer!),
                    signal: loadSignal,
                    requestDer: prepared.ocspRequestDer
                  })
              });
        const summary = recordResult(
          attempts,
          certificateIndex,
          mechanism,
          result
        );
        if (!summary) {
          const last = attempts.at(-1);
          if (last) message = last.message;
          continue;
        }
        if (summary.status === "revoked") {
          return {
            status: "revoked",
            evidence: summary,
            findings: findingsFor(certificateIndex, attempts)
          };
        }

        goodByMechanism.set(mechanism, summary);
        const allRequiredGood = required.every((entry) =>
          goodByMechanism.has(entry)
        );
        if (policy.revocation.requiredEvidence === "any" || allRequiredGood) {
          return {
            status: "good",
            evidence: acceptedEvidence(
              policy,
              goodByMechanism,
              policy.revocation.requiredEvidence === "any" ? summary : undefined
            ),
            findings: findingsFor(certificateIndex, attempts)
          };
        }
        // This mechanism is satisfied; continue with the next required one.
        break;
      } catch (error) {
        if (signal?.aborted || error instanceof ResourceLimitError) throw error;
        attempts.push({
          certificateIndex,
          mechanism,
          status: "unknown",
          message: "Unable to load or validate certificate revocation data"
        });
        message = "Unable to load or validate certificate revocation data";
      }
    }
  }

  const decision = decideRevocationEvidence(
    policy.revocation.requiredEvidence,
    attempts
  );
  const findings = findingsFor(certificateIndex, attempts);
  if (decision.status === "revoked") {
    return { status: "revoked", evidence: decision.evidence, findings };
  }
  if (decision.status === "good") {
    return { status: "good", evidence: decision.evidence, findings };
  }
  return {
    status: "unknown",
    message: decision.message || message,
    findings
  };
}
