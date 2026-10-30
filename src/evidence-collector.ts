import type { CrlValidationResult } from "./crl.ts";
import {
  decideRevocationEvidence,
  type EvidenceAttempt,
  type EvidenceSummary,
  requiredMechanisms
} from "./evidence.ts";
import type { OcspLoadOptions } from "./http-loaders.ts";
import type { OcspValidationResult } from "./ocsp.ts";
import type { PreparedCertificate } from "./pki-engine.ts";
import type { CompiledTrustPolicy } from "./policy.ts";
import type { createRevocationChecker } from "./revocation-checker.ts";

type RevocationChecker = ReturnType<typeof createRevocationChecker>;
type CrlLoader = (url: string) => Promise<Uint8Array>;
type OcspLoader = (options: OcspLoadOptions) => Promise<Uint8Array>;

export type CertificateRevocation =
  | { status: "good"; evidence: EvidenceSummary[] }
  | { status: "revoked"; evidence: EvidenceSummary }
  | { status: "unknown"; message: string };

interface EvidenceCollectorOptions {
  policy: CompiledTrustPolicy;
  checker: RevocationChecker;
  prepared: PreparedCertificate;
  certificateIndex: number;
  checkDateMs?: number;
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

export async function collectCertificateEvidence({
  policy,
  checker,
  prepared,
  certificateIndex,
  checkDateMs,
  crlLoader,
  ocspLoader
}: EvidenceCollectorOptions): Promise<CertificateRevocation> {
  const attempts: EvidenceAttempt[] = [];
  const goodByMechanism = new Map<"crl" | "ocsp", EvidenceSummary>();
  const required = requiredMechanisms(policy.revocation.requiredEvidence);
  let message =
    "No usable CRL or OCSP source is configured for this certificate";

  for (const mechanism of policy.revocation.sourceOrder) {
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
                load: () => (loader as CrlLoader)(url)
              })
            : await checker.checkOcsp({
                certificateDer: prepared.der,
                issuerDer: prepared.issuerDer!,
                source: url,
                certificateIndex,
                checkDateMs,
                ocspRequestDer: prepared.ocspRequestDer!,
                load: () =>
                  (loader as OcspLoader)({
                    url,
                    certificate: Uint8Array.from(prepared.der),
                    issuerCertificate: Uint8Array.from(prepared.issuerDer!)
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
          return { status: "revoked", evidence: summary };
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
            )
          };
        }
        // This mechanism is satisfied; continue with the next required one.
        break;
      } catch {
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
  if (decision.status === "revoked") {
    return { status: "revoked", evidence: decision.evidence };
  }
  if (decision.status === "good") {
    return { status: "good", evidence: decision.evidence };
  }
  return { status: "unknown", message: decision.message || message };
}
