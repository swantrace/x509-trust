// Coordinates certificate path validation, revocation checks, and profile rules.
import { inlinePkiEngine } from "./engine/pki-engine.ts";
import { abortError, invalidProfile } from "./errors.ts";
import { applyTrustRules } from "./profile/rules.ts";
import {
  type PreparedValidatorConfig,
  prepareValidatorConfig
} from "./profile/validator-config.ts";
import { checkPathRevocation } from "./revocation/check-path-revocation.ts";
import { requiredMechanisms } from "./revocation/revocation.ts";
import { createRevocationChecker } from "./revocation/revocation-checker.ts";
import { createRevocationProvider } from "./revocation/revocation-provider.ts";
import type {
  TrustValidator,
  TrustValidatorOptions,
  ValidationResult,
  VerifyOptions
} from "./validation-types.ts";

export type {
  TrustValidator,
  TrustValidatorOptions,
  ValidationFailureCode,
  ValidationResult,
  VerifyOptions
} from "./validation-types.ts";
export function createTrustValidator(
  options: TrustValidatorOptions
): TrustValidator {
  return createPreparedTrustValidator({
    ...options,
    ...prepareValidatorConfig(options)
  });
}

export function createPreparedTrustValidator({
  trustAnchors,
  profile,
  rules,
  crlLoader: providedCrlLoader,
  ocspLoader: providedOcspLoader,
  provider,
  engine: providedEngine,
  http,
  deadlineMs = 60_000,
  cache,
  maxCacheAgeMs,
  cacheKeyPrefix,
  now = Date.now,
  onDiagnostic
}: Omit<TrustValidatorOptions, "trustAnchors" | "profile" | "rules"> &
  PreparedValidatorConfig): TrustValidator {
  const profileMetadata = {
    profileId: profile.id,
    profileVersion: profile.version
  };
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) {
    throw new TypeError("deadlineMs must be a positive integer");
  }
  if (
    provider &&
    (providedCrlLoader !== undefined || providedOcspLoader !== undefined)
  ) {
    throw invalidProfile(
      "provider cannot be combined with crlLoader or ocspLoader"
    );
  }
  const revocationProvider =
    provider ??
    createRevocationProvider({
      crlLoader: providedCrlLoader,
      ocspLoader: providedOcspLoader,
      http
    });
  const engine = providedEngine ?? inlinePkiEngine;
  const mandatory =
    profile.revocation.requiredEvidence === "any"
      ? []
      : requiredMechanisms(profile.revocation.requiredEvidence);
  if (mandatory.includes("crl") && !revocationProvider.loadCrl) {
    throw invalidProfile(
      "The profile requires CRL evidence but the CRL loader is disabled"
    );
  }
  if (mandatory.includes("ocsp") && !revocationProvider.loadOcsp) {
    throw invalidProfile(
      "The profile requires OCSP evidence but the OCSP loader is disabled"
    );
  }
  const checkRevocation = createRevocationChecker({
    profile,
    provider: revocationProvider,
    engine,
    cache,
    maxCacheAgeMs,
    cacheKeyPrefix,
    now,
    onDiagnostic
  });

  return {
    async verify({
      certificateChain,
      checkDate,
      signal
    }: VerifyOptions): Promise<ValidationResult> {
      if (signal?.aborted) throw abortError();
      const explicitCheckDateMs = checkDate?.getTime();
      if (
        explicitCheckDateMs !== undefined &&
        Number.isNaN(explicitCheckDateMs)
      ) {
        throw new TypeError("checkDate must be a valid date");
      }
      const path = await engine.preparePath({
        certificateChain,
        trustAnchors,
        checkDateMs: explicitCheckDateMs ?? now(),
        signal
      });
      if (!path.pathValid) {
        return {
          valid: false,
          code: path.code,
          message: path.message,
          ...profileMetadata
        };
      }

      const revocation = await checkPathRevocation({
        // The last path entry is the configured trust anchor.
        certificates: path.certificates.slice(0, -1),
        checkRevocation,
        checkDateMs: explicitCheckDateMs,
        signal,
        deadlineMs
      });
      if (!revocation.valid) return { ...revocation, ...profileMetadata };
      const { evidence, findings } = revocation;

      const ruleFailure = await applyTrustRules({
        profile,
        leaf: path.leafCertificate,
        certificatePath: path.certificates.map((entry) => entry.facts),
        profileId: profile.id,
        rules
      });
      if (ruleFailure) {
        return {
          valid: false,
          code: "PROFILE_REJECTED",
          message: ruleFailure,
          evidence,
          findings,
          ...profileMetadata
        };
      }

      return {
        valid: true,
        certificatePath: path.certificatePath,
        trustAnchorFingerprint256: path.trustAnchorFingerprint256,
        leafCertificate: path.leafCertificate,
        evidence,
        findings,
        ...profileMetadata
      };
    }
  };
}
